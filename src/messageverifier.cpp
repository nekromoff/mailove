// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "messageverifier.h"
#include "mimeutils.h"

#include "mailstore.h"
#include "messagecontext.h"
#include "messagelistmodel.h"
#include "messagepresenter.h"
#include "pgpmime.h"

#include <QLoggingCategory>
#include <QThread>
#include <QTimer>

#include <kmime/content.h>
#include <kmime/message.h>
#include <kmime/util.h>

#include <utility>

Q_DECLARE_LOGGING_CATEGORY(logTrace)

MessageVerifier::MessageVerifier(MailStore &store, MessagePresenter *presenter,
                                 std::function<QString(KMime::Message *)> indexText,
                                 QObject *parent)
    : QObject(parent)
    , m_store(store)
    , m_presenter(presenter)
    , m_indexText(std::move(indexText))
{
    // DKIM verification is a DNS round trip plus SHA-256 over the whole
    // message and a public-key operation — none of it may run on the GUI
    // thread.
    m_dkimThread = new QThread(this);
    m_dkimVerifier = new DkimVerifier;
    m_dkimVerifier->moveToThread(m_dkimThread);
    connect(m_dkimThread, &QThread::finished, m_dkimVerifier, &QObject::deleteLater);
    connect(m_dkimVerifier, &DkimVerifier::finished, this,
            &MessageVerifier::applyDkimResult);
    m_dkimThread->start();
}

MessageVerifier::~MessageVerifier()
{
    if (!m_dkimThread)
        return;
    m_dkimThread->quit();
    // A verification in flight may be inside a DNS wait; that wait is capped
    // at 10s, so this join is bounded.
    m_dkimThread->wait();
}

void MessageVerifier::trackDecryptJob(quint64 jobId, MessageContext *ctx)
{
    m_pendingDecrypt[jobId].append(ctx);
}

void MessageVerifier::adoptJobs(MessageContext *ctx, quint64 decryptJob, quint64 verifyJob)
{
    // One check, two contexts — never a second gpg run (and a second
    // passphrase prompt) for the same message.
    if (verifyJob)
        m_pendingVerify[verifyJob].append(ctx);
    if (decryptJob)
        m_pendingDecrypt[decryptJob].append(ctx);
}

void MessageVerifier::startDkimVerification(MessageContext *ctx)
{
    ctx->m_dkimStatus.clear();
    ctx->m_dkimDetail.clear();
    ctx->m_arcStatus.clear();
    ctx->m_arcSealer.clear();
    ctx->m_arcDetail.clear();
    ctx->m_dkimTrusted = false;
    ctx->m_dkimChecking = false;
    ctx->m_dkimAttempt = 0;
    ctx->m_dkimFromCache = false;
    // No verification for imported archive mail: the DNS keys its signatures
    // were made against are long gone, so every check would report a failure
    // that says nothing about the message. Nor when the user turned sender
    // authentication off — that must emit no DNS query at all, not merely
    // hide the answer.
    if (m_local || !m_authVerification || !m_dkimVerifier || ctx->m_raw.isEmpty()) {
        Q_EMIT ctx->dkimChanged();
        return;
    }

    // Verified once, not once per open. Re-checking would cost a DNS query
    // every time the message is opened, and for a message whose attachments
    // have since been lifted out of the body there is no byte-exact copy left
    // to re-check against — the verdict from when there was one is the honest
    // answer, not the mismatch the reassembled stub would produce.
    if (ctx->m_uid >= 0 && !ctx->m_folder.isEmpty()) {
        const MailStore::AuthVerdict v = m_store.authVerdict(ctx->m_folder, ctx->m_uid);
        if (!v.isEmpty()) {
            ctx->m_dkimStatus = v.dkimStatus;
            ctx->m_dkimDetail = v.dkimDetail;
            ctx->m_dkimTrusted = v.dkimTrusted;
            ctx->m_arcStatus = v.arcStatus;
            ctx->m_arcSealer = v.arcSealer;
            ctx->m_arcDetail = v.arcDetail;
            qCDebug(logTrace) << "dkim: uid" << ctx->m_uid << "verdict from cache"
                              << ctx->m_dkimStatus;
            Q_EMIT ctx->dkimChanged();
            return;
        }
    }
    // Snapshot the origin of these bytes now, while the presentation flag
    // still describes them. Retries reuse the snapshot; how a mismatch must
    // be reported depends on where *these* bytes came from, not on whatever
    // the user happens to be reading when a retry fires.
    ctx->m_dkimFromCache = m_presentingFromCache;
    submitDkimVerification(ctx);
}

void MessageVerifier::submitDkimVerification(MessageContext *ctx)
{
    if (!m_authVerification || !m_dkimVerifier || ctx->m_raw.isEmpty())
        return;

    // The signature covers the octets as they travelled. KMime holds the
    // message in LF form, and LFtoCRLF restores the wire form byte for byte
    // as long as nothing re-assembled the MIME tree — which is why the raw
    // bytes are kept rather than rebuilt from the parsed parts.
    const QByteArray wire = KMime::LFtoCRLF(ctx->m_raw);

    // Alignment is judged against the From: header's domain.
    QString fromDomain;
    if (ctx->m_message) {
        if (const auto *from = std::as_const(*ctx->m_message).from();
            from && !from->mailboxes().isEmpty()) {
            const QString addr = QString::fromLatin1(from->mailboxes().first().address());
            fromDomain = addr.section(QLatin1Char('@'), 1).toLower();
        }
    }

    // Which path produced these bytes is the single most useful fact when a
    // body hash fails: a message straight off the wire and the same message
    // rebuilt from the cache are not the same byte sequence.
    //
    // The origin is the context's own m_dkimFromCache, set by whoever brought
    // the bytes: startDkimVerification snapshots the presentation flag, and
    // the heal path stamps false over a refetch. Deliberately NOT read from
    // m_presentingFromCache here — that flag describes whatever message is
    // being presented *now*, and a temperror retry fires minutes later, when
    // the user may be reading something else entirely. ctx->m_raw has not
    // changed since the first submission, so neither has its origin.
    qCDebug(logTrace) << "dkim: verifying uid" << ctx->m_uid
                      << "source" << (ctx->m_dkimFromCache ? "cache" : "network")
                      << "bytes" << wire.size();

    const quint64 requestId = ++m_dkimNextRequest;
    m_dkimPending.insert(requestId, ctx);
    ctx->m_dkimChecking = true;
    Q_EMIT ctx->dkimChanged();

    QMetaObject::invokeMethod(m_dkimVerifier, "verify", Qt::QueuedConnection,
                              Q_ARG(quint64, requestId), Q_ARG(QByteArray, wire),
                              Q_ARG(QString, fromDomain));
}

bool MessageVerifier::scheduleDkimRetry(MessageContext *ctx)
{
    static constexpr int delaysMs[] = {15000, 60000, 180000};
    static constexpr int maxAttempts = int(std::size(delaysMs));
    if (ctx->m_dkimAttempt >= maxAttempts)
        return false;
    const int delay = delaysMs[ctx->m_dkimAttempt];
    ++ctx->m_dkimAttempt;

    // Pin the message this retry belongs to. The user may open something else
    // in the meantime, and a verdict for the old message must never be
    // attached to the new one.
    const QPointer<MessageContext> guard(ctx);
    const qint64 uid = ctx->m_uid;
    QTimer::singleShot(delay, this, [this, guard, uid] {
        if (!guard || !guard->m_hasMessage || guard->m_uid != uid)
            return;
        submitDkimVerification(guard);
    });
    return true;
}

bool MessageVerifier::healCachedBody(MessageContext *ctx, HealReason reason)
{
    if (ctx->m_uid < 0 || ctx->m_folder.isEmpty())
        return false;

    const QString key = ctx->m_folder + QLatin1Char('\n') + QString::number(ctx->m_uid);
    if (m_dkimHealed.contains(key))
        return false; // already refetched once; the mismatch is the message's

    const QString folder = ctx->m_folder;
    const qint64 uid = ctx->m_uid;
    // The backend names messages its own way, and this path holds a message
    // rather than a visible row — so the id comes from the cache, not the list
    // model. A message that is not cached cannot be the one whose cached body
    // failed to verify.
    const QString remoteId = m_store.remoteIdFor(folder, uid);
    if (remoteId.isEmpty())
        return false;

    // A message whose attachments were lifted into the file store is cached as
    // a stub and put back together on open, and that reassembly re-encodes the
    // MIME parts — so the refetched octets must not be written back, or the
    // next open would mismatch again. The verdict is what gets kept instead.
    const bool externalized = !m_store.partsFor(folder, uid).isEmpty();

    qCDebug(logTrace) << "dkim: body mismatch from cache, refetching uid" << uid
                      << "in" << folder;

    // Could not get a second opinion, so do not offer one — and do not mark
    // the message healed either: a refetch that never happened must not stop
    // the next open from trying again.
    const auto giveUp = [reason](MessageContext *m) {
        if (reason == HealReason::OpenPgpSignature) {
            m->m_signatureStatus = QStringLiteral("unverified");
            m->m_cryptoChecking = false;
            Q_EMIT m->cryptoChanged();
        } else {
            m->m_dkimStatus = QStringLiteral("unverified");
            m->m_dkimChecking = false;
            Q_EMIT m->dkimChanged();
        }
    };

    // Whoever owns the connection fetches it; a backend that declines the
    // request is its problem to retry, not ours.
    const QPointer<MessageContext> guard(ctx);
    const QString healKey = key;
    const bool asked = m_refetch && m_refetch(folder, uid,
        [this, guard, folder, uid, healKey, externalized, reason, giveUp](
            const std::shared_ptr<KMime::Message> &message) {
            if (!guard || !guard->m_hasMessage || guard->m_uid != uid)
                return; // the user moved on; a verdict now would land on the wrong message
            if (!message) {
                giveUp(guard);
                return;
            }
            // Marked only now, on a refetch that actually delivered — an
            // aborted one would otherwise burn the single attempt this message
            // gets.
            m_dkimHealed.insert(healKey);
            KMime::Message *msg = message.get();
            MimeUtils::parseIfNeeded(msg);
            // Judge the signature against what the server actually holds. The
            // parsed message on screen is left alone: the rendered body is
            // unchanged, and re-presenting it would flicker for no gain.
            guard->m_raw = msg->encodedContent();
            if (!externalized) {
                // Heal the cache too, so this message is right from now on.
                m_store.storeBody(folder, uid, guard->m_raw, m_indexText(msg));
            }
            if (reason == HealReason::OpenPgpSignature) {
                // The signature has to be re-checked against the tree these
                // bytes parse into, not the one on screen: the octets are
                // sliced out of the message the boundary belongs to.
                guard->m_message = message;
                // Network-origin by construction — just refetched.
                if (!startPgpVerification(guard, msg, /*bytesFromCache=*/false))
                    giveUp(guard);
                return;
            }
            // Network-origin by construction — these bytes were fetched from
            // the server a moment ago. That is what lets a second mismatch be
            // reported as a real failure, and what makes the resulting
            // verdict worth storing.
            guard->m_dkimFromCache = false;
            submitDkimVerification(guard);
        });
    if (!asked)
        return false;

    // The badge stays in its "checking" state across the refetch — the check
    // has not finished, it has been handed a better copy to work from.
    if (reason == HealReason::OpenPgpSignature) {
        ctx->m_cryptoChecking = true;
        Q_EMIT ctx->cryptoChanged();
    } else {
        ctx->m_dkimChecking = true;
        Q_EMIT ctx->dkimChanged();
    }
    return true;
}

void MessageVerifier::applyDkimResult(quint64 requestId, const DkimResult &result)
{
    const QPointer<MessageContext> ctx = m_dkimPending.take(requestId);
    if (!ctx)
        return; // the window closed while the check was in flight

    bool retrying = false;
    switch (result.status) {
    case DkimResult::None:
        // No signature at all. Plenty of legitimate mail is unsigned, so this
        // stays distinct from a failure and shows nothing.
        ctx->m_dkimStatus = QStringLiteral("none");
        break;
    case DkimResult::Pass:
        // A signature that covered only the first l= bytes of the body is not
        // the same claim as one that covered the message, and must not be
        // reported with the same word — the rest of what is on screen came
        // with no signature at all.
        ctx->m_dkimStatus = result.bodyTruncated ? QStringLiteral("partial")
                                                 : QStringLiteral("pass");
        break;
    case DkimResult::Fail:
        // The one case that earns an accusation: we fetched the key the
        // signature names and the signature does not match it.
        ctx->m_dkimStatus = QStringLiteral("fail");
        break;
    case DkimResult::PermError:
        // A signature we cannot evaluate — most often "no public key published
        // for <selector>", which simply means the signer has rotated the key
        // out of DNS since the message arrived. That is the normal fate of any
        // archived mail, and it is why a receiving server's dkim=pass from
        // months ago can sit next to our own inability to check it today.
        // Also covers a revoked or unusable key and a malformed signature; the
        // tooltip carries which. Not an accusation either way: we did not
        // establish that the signature is bad, only that we cannot tell.
        ctx->m_dkimStatus = QStringLiteral("permerror");
        break;
    case DkimResult::TempError:
        ctx->m_dkimStatus = QStringLiteral("temperror");
        retrying = scheduleDkimRetry(ctx);
        break;
    case DkimResult::BodyMismatch:
        // The body hash did not match. What that means depends entirely on
        // whether the bytes we hashed are the bytes that arrived.
        if (ctx->m_dkimFromCache) {
            // They came out of the offline cache, which for bodies written by
            // older builds is not the original octets. Refetch and re-verify
            // before saying anything; healCachedBody() leaves the check
            // running when it takes over.
            if (healCachedBody(ctx, HealReason::DkimBodyHash))
                return;
            // Nothing to heal with (offline, or already tried) — say only what
            // we know, which is that we could not verify it.
            ctx->m_dkimStatus = QStringLiteral("unverified");
        } else {
            // These bytes came straight off the wire, and the fetch path is
            // known to preserve them (doc/roadmap.md), so the body really is
            // not the one that was signed. That is emphatically NOT a failed
            // signature: it is the everyday outcome of a mailing list or a
            // forwarder appending a footer or rewriting the subject, and it is
            // the exact situation ARC exists to describe. Calling it "invalid"
            // would cry wolf on most list mail — the same mistake the SPF/DKIM
            // column already makes (doc/roadmap.md). Its own status, so the
            // viewer can say what happened instead of accusing.
            ctx->m_dkimStatus = QStringLiteral("modified");
        }
        break;
    case DkimResult::Unsupported:
        // An obsolete algorithm is not a broken signature — it is one we
        // declined to give an opinion on. Saying "invalid" would be a claim we
        // did not earn.
        ctx->m_dkimStatus = QStringLiteral("unsupported");
        break;
    }
    qCDebug(logTrace) << "dkim: uid" << ctx->m_uid << "verdict" << ctx->m_dkimStatus
                      << "d=" << result.domain << "aligned" << result.aligned
                      << "-" << result.detail;
    ctx->m_dkimDetail = result.detail;

    // ARC is only run when DKIM could not settle the question, so an empty
    // status here means "not asked", not "no chain".
    switch (result.arc.status) {
    case ArcResult::None:
        ctx->m_arcStatus = QStringLiteral("none");
        break;
    case ArcResult::Pass:
        ctx->m_arcStatus = QStringLiteral("pass");
        break;
    case ArcResult::SealsOnly:
        ctx->m_arcStatus = QStringLiteral("sealsonly");
        break;
    case ArcResult::Fail:
        ctx->m_arcStatus = QStringLiteral("fail");
        break;
    case ArcResult::TempError:
    case ArcResult::PermError:
        // Nothing was established either way; the reason is in the tooltip.
        ctx->m_arcStatus = QStringLiteral("error");
        break;
    }
    ctx->m_arcSealer = result.arc.sealer;
    ctx->m_arcDetail = result.arc.detail;
    if (result.arc.status != ArcResult::None) {
        qCDebug(logTrace) << "arc: uid" << ctx->m_uid << "status" << ctx->m_arcStatus << "sealer"
                          << result.arc.sealer << "hops" << result.arc.sets;
    }
    ctx->m_dkimTrusted = result.trustworthy();
    // Still "checking" while a retry is pending — we have not given up yet.
    ctx->m_dkimChecking = retrying;
    Q_EMIT ctx->dkimChanged();

    // Record it, so the message is never re-verified — but only a verdict that
    // is both settled and earned. "temperror" is unsettled by definition, and
    // "unverified" says our copy was doubtful, which is not a fact about the
    // message. A verdict read off cached bytes is only trusted when it passed:
    // corruption produces a mismatch, never a valid signature, so a pass
    // cannot be an artefact of a stale copy the way a failure can.
    const bool settled = !retrying && ctx->m_dkimStatus != QLatin1String("temperror")
        && ctx->m_dkimStatus != QLatin1String("unverified")
        && !ctx->m_dkimStatus.isEmpty();
    // "permerror" is recorded even off cached bytes: "no key published" is a
    // fact about DNS, not about our copy of the message, and it is not an
    // accusation — which is what this rule exists to guard against. Without it
    // every open of an archived message whose key has rotated away would spend
    // another DNS query to reach the same answer.
    const bool earned = !ctx->m_dkimFromCache || ctx->m_dkimStatus == QLatin1String("pass")
        || ctx->m_dkimStatus == QLatin1String("permerror");
    if (settled && earned && ctx->m_uid >= 0 && !ctx->m_folder.isEmpty()) {
        m_store.storeAuthVerdict(ctx->m_folder, ctx->m_uid,
                                 {ctx->m_dkimStatus, ctx->m_dkimDetail, ctx->m_dkimTrusted,
                                  ctx->m_arcStatus, ctx->m_arcSealer, ctx->m_arcDetail});
    }
}

void MessageVerifier::setPgpEngine(PgpEngine *engine)
{
    m_pgp = engine;
    if (!engine)
        return;
    connect(engine, &PgpEngine::decryptFinished, this, &MessageVerifier::applyDecryption);
    connect(engine, &PgpEngine::verifyFinished, this, &MessageVerifier::applyVerification);
    connect(engine, &PgpEngine::decryptRecipient, this,
            [this](quint64 jobId, const QString &keyId) {
                const auto it = m_pendingDecrypt.constFind(jobId);
                if (it == m_pendingDecrypt.cend())
                    return;
                // gpg names the encryption *subkey* here. Resolved to the
                // primary fingerprint, because that is the identity everything
                // else (key manager, keyInfo) speaks; the raw subkey ID kept
                // as the fallback when the keyring cannot resolve it.
                const QString primary = m_pgp->primaryFingerprintFor(keyId);
                for (const QPointer<MessageContext> &ctx : it.value()) {
                    if (ctx)
                        ctx->m_decryptionKeyId = primary.isEmpty() ? keyId : primary;
                }
            });
}

bool MessageVerifier::startPgpVerification(MessageContext *ctx, KMime::Message *root,
                                           bool bytesFromCache)
{
    if (!m_pgp || !m_pgp->available() || !root)
        return false;
    const PgpMime::Structure s = PgpMime::classify(root);
    if (s.kind != PgpMime::Kind::Signed)
        return false;

    // The signed part is sliced out of the bytes the tree was parsed from,
    // never rebuilt from the tree itself: rebuilding can refold headers, and a
    // signature checked against rebuilt octets says nothing when it fails.
    //
    // Both trees have such bytes. For the message as it arrived that is m_raw;
    // for a decrypted one it is the plaintext gpg handed back, which is just as
    // original — it is what the sender signed before encrypting it. Getting
    // this wrong is not harmless: verifying a signed-and-encrypted message
    // against rebuilt octets, and calling them exact, reports every good
    // signature as "modified after signing".
    const bool fromArrived = root == ctx->m_message.get();
    const QByteArray raw = fromArrived ? ctx->m_raw
        : (root == ctx->m_decrypted.get() ? ctx->m_decryptedRaw : QByteArray());
    // Remembered per submission, like m_dkimFromCache: by the time the verdict
    // lands the user may have opened something else, and whether a mismatch
    // means anything depends on where *these* bytes came from — which is why
    // the caller states it rather than this reading a presentation flag that
    // may already describe some other message. Only the arrived copy can be
    // stale: a decryption happened just now, in this session.
    ctx->m_pgpFromCache = bytesFromCache && fromArrived;
    bool exact = false;
    const QByteArray octets = raw.isEmpty() ? PgpMime::signedOctets(s)
                                            : PgpMime::signedOctets(raw, s, &exact);
    ctx->m_pgpOctetsExact = exact;

    const quint64 job = m_pgp->verifyDetached(octets, PgpMime::signature(s));
    if (!job)
        return false;
    ctx->m_verifyJob = job;
    m_pendingVerify[job].append(ctx);
    return true;
}

/// Records one signature verdict on the message it belongs to.
///
/// Reached two ways: a detached RFC 3156 signature we asked about, and a
/// signature gpg found inside a message it was decrypting — the latter arrives
/// under the decrypt job's own token, which is why both maps are consulted.
void MessageVerifier::applyVerification(quint64 jobId, const PgpSignatureInfo &signature)
{
    QList<QPointer<MessageContext>> waiting = m_pendingVerify.take(jobId);
    // A signature inside an encrypted message: the contexts waiting on that
    // decryption are the ones this verdict is about.
    const auto pending = m_pendingDecrypt.constFind(jobId);
    if (pending != m_pendingDecrypt.cend())
        waiting += pending.value();
    if (waiting.isEmpty())
        return;

    for (const QPointer<MessageContext> &ptr : std::as_const(waiting)) {
        MessageContext *ctx = ptr;
        if (!ctx || !ctx->m_hasMessage)
            continue;

        ctx->m_verifyJob = 0;
        switch (signature.status) {
        case PgpSignatureInfo::Valid:
            ctx->m_signatureStatus = QStringLiteral("valid");
            break;
        case PgpSignatureInfo::NotVerified:
            // The same question DKIM asks of a body-hash mismatch, for the same
            // reason (doc/roadmap.md): are these the bytes that were signed?
            if (ctx->m_pgpFromCache) {
                // They came out of the cache, so no. Either the body predates
                // the fetch path that preserves octets, or it was reassembled
                // from externalised attachments — which is also the case where
                // the octets could not be sliced exactly, and so the case a
                // refetch helps most. Refetch once and ask again before saying
                // anything; healing leaves the check running when it takes
                // over.
                if (healCachedBody(ctx, HealReason::OpenPgpSignature))
                    continue;
                // Offline, or already refetched once. Say only what we know.
                ctx->m_signatureStatus = QStringLiteral("unverified");
            } else if (!ctx->m_pgpOctetsExact) {
                // Off the wire, but the signed part could not be sliced out of
                // it — a malformed boundary, or a tree gpg produced itself.
                // Nothing about the message follows from a mismatch here.
                ctx->m_signatureStatus = QStringLiteral("unverified");
            } else {
                // Exact octets, straight off the wire. The part that was
                // signed is genuinely not the part that arrived — which is the
                // everyday result of a mailing list rewriting a message, not
                // an accusation. Its own status, so the badge can say what
                // happened rather than imply forgery.
                ctx->m_signatureStatus = QStringLiteral("modified");
            }
            break;
        case PgpSignatureInfo::UnknownKey:
            ctx->m_signatureStatus = QStringLiteral("unknownKey");
            break;
        case PgpSignatureInfo::Expired:
            ctx->m_signatureStatus = QStringLiteral("expired");
            break;
        case PgpSignatureInfo::Revoked:
            ctx->m_signatureStatus = QStringLiteral("revoked");
            break;
        case PgpSignatureInfo::Error:
            ctx->m_signatureStatus = QStringLiteral("error");
            break;
        case PgpSignatureInfo::None:
            ctx->m_signatureStatus.clear();
            break;
        }
        ctx->m_signerName = signature.signerName;
        ctx->m_signerEmail = signature.signerEmail;
        ctx->m_signerFingerprint = signature.fingerprint;
        // Alignment, not just validity: a good signature from a key that has
        // nothing to do with the From address is precisely what a forger's own
        // key produces. Only the two together earn a name on the badge.
        ctx->m_signerTrusted = signature.status == PgpSignatureInfo::Valid
            && !signature.signerEmail.isEmpty()
            && signature.signerEmail.compare(ctx->m_senderAddress, Qt::CaseInsensitive) == 0;
        if (!signature.detail.isEmpty())
            ctx->m_cryptoDetail = signature.detail;
        if (ctx->m_signerTrusted) {
            // Nothing else here says the sender is who they claim, so say it
            // once, plainly, where the reader is already looking.
            ctx->m_cryptoDetail =
                tr("Signed by %1, whose key matches the From address.")
                    .arg(signature.signerEmail);
        } else if (signature.status == PgpSignatureInfo::Valid) {
            ctx->m_cryptoDetail =
                tr("Good signature, but the signing key belongs to %1 rather "
                   "than the sender. That is what a forged message signed with "
                   "the forger's own key looks like.")
                    .arg(signature.signerEmail.isEmpty() ? tr("an unknown address")
                                                         : signature.signerEmail);
        }

        // "signed and encrypted" is a stronger statement than either alone, so
        // it gets its own state rather than overwriting one with the other.
        if (ctx->m_cryptoState == QLatin1String("encrypted"))
            ctx->m_cryptoState = QStringLiteral("signedEncrypted");
        else if (ctx->m_cryptoState.isEmpty()
                 || ctx->m_cryptoState == QLatin1String("signed"))
            ctx->m_cryptoState = QStringLiteral("signed");
        ctx->m_cryptoChecking = ctx->m_decryptJob != 0;

        // The list's mark can be refined now: the head only shows the outer
        // type, so an encrypted message that turns out to be signed as well
        // only becomes "both" here.
        //
        // The model only, never the store. That a message is *also* signed was
        // learned by decrypting it, and nothing learned that way goes into the
        // plaintext cache — not the body, not the index, and not a metadata
        // bit about what was inside (doc/openpgp.md §4). It is a mark on
        // screen for as long as the message is open, and it is gone on the
        // next start, which is the correct trade.
        if (ctx->m_uid >= 0 && ctx->m_cryptoState == QLatin1String("signedEncrypted"))
            Q_EMIT cryptoMarkRefined(ctx->m_folder, ctx->m_uid, PgpMime::StoredBoth);
        Q_EMIT ctx->cryptoChanged();
    }
}

/// Takes the result of one decrypt job and, if the message it was for is still
/// open, re-renders that message from the decrypted tree.
///
/// The plaintext stops here: it goes into the context's own m_decrypted and
/// nowhere else. Nothing on this path writes to the cache, the search index or
/// the attachment store — those all read m_raw and m_message, which are still
/// the ciphertext exactly as it arrived (doc/openpgp.md §4).
void MessageVerifier::applyDecryption(quint64 jobId, const QByteArray &plainText,
                                 const QString &error, bool noSecretKey)
{
    const QList<QPointer<MessageContext>> waiting = m_pendingDecrypt.take(jobId);
    if (waiting.isEmpty())
        return;

    // Parsed once and shared: the reading pane and any window detached from it
    // are showing the same message, and a second parse would be a second copy
    // of the plaintext in memory.
    std::shared_ptr<KMime::Message> inner;
    if (error.isEmpty() && !plainText.isEmpty()) {
        inner = std::make_shared<KMime::Message>();
        // Inline PGP encrypts the sender's text, not a MIME entity, so what
        // comes back is a paragraph rather than a message. Parsed as one it
        // yields an entity whose first line was taken for a header and whose
        // body is empty — a good decryption that displays nothing. Give it the
        // one header it needs instead.
        if (PgpMime::looksLikeMimeEntity(plainText)) {
            inner->setContent(KMime::CRLFtoLF(plainText));
        } else {
            inner->setContent(QByteArrayLiteral("Content-Type: text/plain; "
                                                "charset=\"utf-8\"\n\n")
                              + KMime::CRLFtoLF(plainText));
        }
        inner->parse();
    }

    for (const QPointer<MessageContext> &ptr : waiting) {
        MessageContext *ctx = ptr;
        // The context is gone (a detached window closed), or the reader moved
        // on and this answer is for a message no longer on screen.
        if (!ctx || ctx->m_decryptJob != jobId)
            continue;

        ctx->m_decryptJob = 0;
        ctx->m_cryptoChecking = false;

        if (!inner) {
            ctx->m_cryptoState = QStringLiteral("failed");
            // "No key of yours" is the ordinary case — mail encrypted to an
            // address on another of the user's devices, or to a key they have
            // since retired. It is not a fault to report as a broken message.
            ctx->m_cryptoDetail = noSecretKey
                ? tr("This message is encrypted to a key you do not have.")
                : (error.isEmpty() ? tr("This message could not be decrypted.") : error);
            m_presenter->applyBodyParts(ctx, ctx->m_message.get(), ctx->m_junk);
        } else {
            ctx->m_decrypted = inner;
            // Kept so a signature inside can be checked against these octets
            // rather than against a re-serialisation of the tree they parse to.
            ctx->m_decryptedRaw = plainText;
            // From here until the message is closed there is plaintext in this
            // process, and it must not reach a core file.
            ctx->markPlaintextHeld(true);
            ctx->m_cryptoState = QStringLiteral("encrypted");
            // Which of the reader's keys opened it belongs here, in the
            // tooltip, and not in the badge's click target — that one is about
            // the sender. decryptRecipient() lands during the decryption, so
            // the id is already known by the time the job reports back.
            ctx->m_cryptoDetail = ctx->m_decryptionKeyId.isEmpty()
                ? tr("Decrypted with one of your OpenPGP keys. "
                     "The subject line was never encrypted.")
                : tr("Decrypted with your key %1. "
                     "The subject line was never encrypted.")
                      .arg(ctx->m_decryptionKeyId);
            m_presenter->applyBodyParts(ctx, inner.get(), ctx->m_junk);

            // Until it was decrypted there was no way to know whether this
            // message carried attachments — the head only says
            // multipart/encrypted, and the parts are inside the ciphertext. Now
            // there is, so the list can show the paperclip beside the lock.
            //
            // The model only, never the store: "this encrypted message has
            // attachments" is a fact derived from plaintext, and the cache is
            // the one place §4 keeps plaintext-derived data out of. It costs a
            // paperclip that reappears per session instead of persisting, which
            // is the right side of that trade.
            if (ctx->m_uid >= 0 && !inner->attachments().isEmpty())
                Q_EMIT attachmentsDiscovered(ctx->m_folder, ctx->m_uid);

            // The usual shape of signed-and-encrypted mail is a multipart/signed
            // *inside* the ciphertext, which only becomes visible now. (A
            // message signed in the same OpenPGP operation instead reports its
            // signature through the decrypt job's own token — see
            // applyVerification.)
            if (startPgpVerification(ctx, inner.get(), /*bytesFromCache=*/false))
                ctx->m_cryptoChecking = true;
        }
        Q_EMIT ctx->messageChanged();
        Q_EMIT ctx->cryptoChanged();
    }
}

/// Notices a public key attached to a message and offers it to the reader —
/// the fourth of the key sources in doc/openpgp.md §7, and the only one that
/// arrives unasked.
///
/// Nothing is imported here. A key attached to a message is a claim about an
/// identity made by whoever sent the message, which is exactly the claim a
/// forger would make; the reader gets a button, not a fait accompli.
