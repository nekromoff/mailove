// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "dkimverifier.h"

#include "advancedconfig.h"

#include "publicsuffixlist.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDnsLookup>
#include <QEventLoop>
#include <QList>
#include <QMap>
#include <QRegularExpression>
#include <QTimer>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <chrono>
#include <memory>

namespace
{

// --- RFC 6376 §3.5: one parsed DKIM-Signature header ----------------------

struct Tag {
    QByteArray name;
    QByteArray value;
};

QList<Tag> parseTagList(const QByteArray &value)
{
    QList<Tag> tags;
    for (const QByteArray &part : value.split(';')) {
        const int eq = part.indexOf('=');
        if (eq < 0)
            continue;
        Tag t;
        t.name = part.left(eq).trimmed();
        t.value = part.mid(eq + 1).trimmed();
        if (!t.name.isEmpty())
            tags.append(t);
    }
    return tags;
}

QByteArray tagValue(const QList<Tag> &tags, const char *name)
{
    for (const Tag &t : tags) {
        if (t.name == name)
            return t.value;
    }
    return {};
}

/// Whitespace, including the CRLF of a folded continuation, removed entirely.
/// Used for base64 and hash tag values, which may be folded anywhere.
QByteArray stripWsp(const QByteArray &in)
{
    QByteArray out;
    out.reserve(in.size());
    for (const char c : in) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            out.append(c);
    }
    return out;
}

// --- Canonicalization (RFC 6376 §3.4) -------------------------------------

/// Collapses WSP runs to one space and drops trailing WSP on the line.
/// A *leading* run collapses to one space and is kept: §3.4.4 reduces it, it
/// does not delete it, and the RFC's own example canonicalizes "<SP>C<SP>" to
/// "<SP>C". Header canonicalization strips what remains before the colon
/// separately, because there the RFC does say to delete it.
QByteArray relaxWhitespace(const QByteArray &in)
{
    QByteArray out;
    out.reserve(in.size());
    bool pendingSpace = false;
    for (const char c : in) {
        if (c == ' ' || c == '\t') {
            pendingSpace = true;
            continue;
        }
        if (pendingSpace)
            out.append(' ');
        pendingSpace = false;
        out.append(c);
    }
    return out; // a trailing run never flushes, so trailing WSP is dropped
}

} // namespace

namespace DkimCanon
{

/// §3.4.2 relaxed: lowercased name, unfolded value, collapsed WSP, no WSP
/// around the colon, one trailing CRLF.
QByteArray headerRelaxed(const QByteArray &name, const QByteArray &value)
{
    QByteArray unfolded;
    unfolded.reserve(value.size());
    for (int i = 0; i < value.size(); ++i) {
        const char c = value.at(i);
        if (c == '\r' && i + 1 < value.size() && value.at(i + 1) == '\n') {
            ++i; // the folding CRLF disappears; its following WSP stays as WSP
            continue;
        }
        if (c == '\n')
            continue;
        unfolded.append(c);
    }
    QByteArray v = relaxWhitespace(unfolded);
    while (v.endsWith(' '))
        v.chop(1);
    while (v.startsWith(' '))
        v.remove(0, 1);
    return name.toLower() + ':' + v + "\r\n";
}

/// §3.4.1 simple: the field exactly as it appeared, one trailing CRLF.
/// Takes the field's original bytes rather than a name/value pair — rebuilding
/// it as name + ':' + value would normalize away anything unusual around the
/// colon, and "exactly as they are in the message" is the whole contract here.
QByteArray headerSimple(const QByteArray &rawField)
{
    QByteArray out = rawField;
    while (out.endsWith('\n') || out.endsWith('\r'))
        out.chop(1);
    return out + "\r\n";
}

QByteArray bodySimple(const QByteArray &body)
{
    QByteArray b = body;
    // "Ignores all empty lines at the end of the message body."
    while (b.endsWith("\r\n\r\n"))
        b.chop(2);
    if (b.isEmpty())
        return QByteArrayLiteral("\r\n"); // an empty body canonicalizes to CRLF
    if (!b.endsWith("\r\n"))
        b += "\r\n";
    return b;
}

QByteArray bodyRelaxed(const QByteArray &body)
{
    QByteArray out;
    out.reserve(body.size());
    // Per-line: collapse WSP runs, drop trailing WSP.
    int pos = 0;
    while (pos < body.size()) {
        int eol = body.indexOf("\r\n", pos);
        const bool last = eol < 0;
        const QByteArray line = last ? body.mid(pos) : body.mid(pos, eol - pos);
        QByteArray v = relaxWhitespace(line);
        while (v.endsWith(' '))
            v.chop(1);
        out += v;
        out += "\r\n";
        if (last)
            break;
        pos = eol + 2;
    }
    // "Ignores all empty lines at the end of the message body."
    while (out.endsWith("\r\n\r\n"))
        out.chop(2);
    if (out == "\r\n")
        return {}; // a body that is entirely empty canonicalizes to nothing
    return out;
}

} // namespace DkimCanon

namespace
{

// --- Header block splitting ------------------------------------------------

struct Field {
    QByteArray name;
    QByteArray value; ///< everything after the colon, folding intact
    QByteArray raw;   ///< the field exactly as it appeared, no trailing CRLF
    bool used = false;
};

/// Splits a header block into fields, keeping each field's original bytes.
QList<Field> splitFields(const QByteArray &head)
{
    QList<Field> fields;
    int pos = 0;
    while (pos < head.size()) {
        int eol = head.indexOf("\r\n", pos);
        if (eol < 0)
            eol = head.size();
        // Absorb continuation lines (a following line starting with WSP).
        int end = eol;
        while (end + 2 < head.size() && (head.at(end + 2) == ' ' || head.at(end + 2) == '\t')) {
            int next = head.indexOf("\r\n", end + 2);
            if (next < 0) {
                end = head.size();
                break;
            }
            end = next;
        }
        const QByteArray raw = head.mid(pos, end - pos);
        const int colon = raw.indexOf(':');
        if (colon > 0) {
            Field f;
            f.name = raw.left(colon).trimmed();
            f.value = raw.mid(colon + 1);
            f.raw = raw;
            fields.append(f);
        }
        pos = end + 2;
    }
    return fields;
}

// --- DNS -------------------------------------------------------------------

/// Blocking TXT lookup. Safe here and only here: this runs on the verifier's
/// own thread, never the GUI thread. \a ttlSecs receives the record's DNS TTL
/// (0 when the answer is not cacheable).
QByteArray lookupDkimKey(const QString &name, bool *tempError, qint64 *ttlSecs)
{
    *tempError = false;
    *ttlSecs = 0;
    QDnsLookup lookup(QDnsLookup::TXT, name);
    QEventLoop loop;
    QObject::connect(&lookup, &QDnsLookup::finished, &loop, &QEventLoop::quit);
    QTimer guard;
    guard.setSingleShot(true);
    QObject::connect(&guard, &QTimer::timeout, &loop, &QEventLoop::quit);
    guard.start(std::chrono::seconds(10));
    lookup.lookup();
    loop.exec();

    if (!guard.isActive()) { // the timer fired first
        lookup.abort();
        *tempError = true;
        return {};
    }
    if (lookup.error() != QDnsLookup::NoError) {
        // NotFound is a permanent answer; anything else may succeed later.
        *tempError = lookup.error() != QDnsLookup::NotFoundError;
        return {};
    }
    const auto records = lookup.textRecords();
    if (records.isEmpty())
        return {};
    *ttlSecs = records.first().timeToLive();
    // A TXT record is a sequence of strings that must be concatenated.
    QByteArray joined;
    for (const QByteArray &chunk : records.first().values())
        joined += chunk;
    return joined;
}

// --- Crypto ----------------------------------------------------------------

struct PkeyDeleter {
    void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX *c) const { EVP_MD_CTX_free(c); }
};
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

/// \a keyType is the k= tag: "rsa" (SubjectPublicKeyInfo DER) or "ed25519"
/// (raw 32-byte key).
PkeyPtr loadPublicKey(const QByteArray &der, const QByteArray &keyType)
{
    if (keyType == "ed25519") {
        if (der.size() != 32)
            return {};
        return PkeyPtr(EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(der.constData()),
            32));
    }
    const unsigned char *p = reinterpret_cast<const unsigned char *>(der.constData());
    return PkeyPtr(d2i_PUBKEY(nullptr, &p, der.size()));
}

bool verifySignature(EVP_PKEY *key, const QByteArray &keyType, const QByteArray &signedData,
                     const QByteArray &signature)
{
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return false;
    const auto *sig = reinterpret_cast<const unsigned char *>(signature.constData());

    if (keyType == "ed25519") {
        // RFC 8463: Ed25519 signs the SHA-256 digest of the header data, not
        // the data itself.
        const QByteArray digest =
            QCryptographicHash::hash(signedData, QCryptographicHash::Sha256);
        if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1)
            return false;
        return EVP_DigestVerify(ctx.get(), sig, signature.size(),
                                reinterpret_cast<const unsigned char *>(digest.constData()),
                                digest.size())
            == 1;
    }
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1)
        return false;
    if (EVP_DigestVerifyUpdate(ctx.get(), signedData.constData(), signedData.size()) != 1)
        return false;
    return EVP_DigestVerifyFinal(ctx.get(), sig, signature.size()) == 1;
}

// --- Signature tag stripping -----------------------------------------------

/// Empties the b= tag, keeping the tag itself. Both DKIM (RFC 6376 §3.7) and
/// ARC (RFC 8617 §5.1.1) sign their own header field this way, since the value
/// being computed cannot be part of its own input. Anchored on a word boundary
/// so it does not eat bh=.
QByteArray stripBTag(const QByteArray &in)
{
    static const QRegularExpression bTagRe(QStringLiteral("(;?\\s*\\bb\\s*=)[^;]*"),
                                           QRegularExpression::CaseInsensitiveOption);
    QString s = QString::fromLatin1(in);
    s.replace(bTagRe, QStringLiteral("\\1"));
    return s.toLatin1();
}

// --- Alignment -------------------------------------------------------------

/// DMARC-style relaxed alignment: the two organizational domains must match.
///
/// Which domain is organizational is not computable — it comes from the Public
/// Suffix List, so when that has not loaded yet this falls back to accepting an
/// exact match or a parent/child relationship. The fallback is stricter than
/// DMARC relaxed in one direction (siblings under one org domain do not match)
/// and never looser, which is the safe way to be wrong.
bool domainsAligned(const QString &signing, const QString &from)
{
    const QString s = signing.toLower();
    const QString f = from.toLower();
    if (s.isEmpty() || f.isEmpty())
        return false;
    if (s == f)
        return true;

    const PublicSuffixList &psl = PublicSuffixList::instance();
    if (psl.isLoaded()) {
        const QString sOrg = psl.organizationalDomain(s);
        const QString fOrg = psl.organizationalDomain(f);
        // Empty means the name is itself a public suffix — "signed by .co.uk"
        // is not something to accept as alignment with anything.
        if (!sOrg.isEmpty() && !fOrg.isEmpty())
            return sOrg == fOrg;
        return false;
    }
    return f.endsWith(QLatin1Char('.') + s) || s.endsWith(QLatin1Char('.') + f);
}

} // namespace

// --- DkimVerifier ----------------------------------------------------------

struct DkimVerifier::Signature {
    QList<Tag> tags;
    QByteArray rawName;  ///< the header name as it appeared
    QByteArray rawValue; ///< the header value as it appeared, folding intact
    QByteArray rawField; ///< the whole field as it appeared, for simple canon
    QByteArray headerCanon = "simple";
    QByteArray bodyCanon = "simple";
};

bool DkimVerifier::prepare(const QByteArray &head, const QByteArray &body, const Signature &sig,
                           QByteArray *signedData, DkimResult *out) const
{
    const QByteArray algorithm = tagValue(sig.tags, "a").toLower();
    if (algorithm != "rsa-sha256" && algorithm != "ed25519-sha256") {
        out->status = DkimResult::Unsupported;
        // rsa-sha1 is the common case here, and RFC 8301 forbids it.
        out->detail = QObject::tr("signed with %1, which is obsolete — SHA-1 signatures can be "
                                  "forged, so verifying one would not tell you anything")
                          .arg(QString::fromLatin1(algorithm));
        return false;
    }

    // --- body hash ---
    QByteArray canonBody = sig.bodyCanon == "relaxed" ? DkimCanon::bodyRelaxed(body)
                                                      : DkimCanon::bodySimple(body);
    // l= limits how much of the body is signed. It is a weakness (anything
    // past the limit is unsigned and can be appended freely), so it is honored
    // but noted.
    const QByteArray lengthTag = tagValue(sig.tags, "l");
    bool truncated = false;
    if (!lengthTag.isEmpty()) {
        bool ok = false;
        const qsizetype limit = lengthTag.toLongLong(&ok);
        if (ok && limit >= 0 && limit < canonBody.size()) {
            canonBody = canonBody.left(limit);
            truncated = true;
        }
    }
    const QByteArray bodyHash =
        QCryptographicHash::hash(canonBody, QCryptographicHash::Sha256).toBase64();
    if (bodyHash != stripWsp(tagValue(sig.tags, "bh"))) {
        out->status = DkimResult::BodyMismatch;
        out->detail = QObject::tr("body hash does not match — the message was changed in "
                                  "transit, or our cached copy is not byte-identical to it");
        return false;
    }

    // --- the signed header set ---
    // h= is order-significant, and for a repeated field name each entry takes
    // the last not-yet-used instance, scanning upward (RFC 6376 §5.4.2).
    QList<Field> fields = splitFields(head);
    QByteArray data;
    const QByteArrayList wanted = tagValue(sig.tags, "h").split(':');
    // From MUST be among them (RFC 6376 §5.4), and a verifier that does not
    // insist is not verifying the thing the reader is being shown. A signature
    // that leaves From out says only that *some* header set was signed by the
    // d= domain: anyone holding such a message can rewrite From to any address
    // at that domain and still show an aligned, valid signature.
    bool signsFrom = false;
    for (const QByteArray &rawName : wanted) {
        if (rawName.trimmed().toLower() == "from") {
            signsFrom = true;
            break;
        }
    }
    if (!signsFrom) {
        out->status = DkimResult::PermError;
        out->detail = QObject::tr("the signature does not cover the From header, so it says "
                                  "nothing about who sent this");
        return false;
    }
    for (const QByteArray &rawName : wanted) {
        const QByteArray name = rawName.trimmed().toLower();
        if (name.isEmpty())
            continue;
        for (int i = fields.size() - 1; i >= 0; --i) {
            Field &f = fields[i];
            if (f.used || f.name.toLower() != name)
                continue;
            data += sig.headerCanon == "relaxed" ? DkimCanon::headerRelaxed(f.name, f.value)
                                                 : DkimCanon::headerSimple(f.raw);
            f.used = true;
            break;
        }
        // A name in h= with no matching field contributes nothing, which is
        // how a signer commits to a header being absent.
    }

    // The DKIM-Signature field itself goes in last, with b= emptied and no
    // trailing CRLF (RFC 6376 §3.7).
    QByteArray sigCanon = sig.headerCanon == "relaxed"
        ? DkimCanon::headerRelaxed(sig.rawName, stripBTag(sig.rawValue))
        : DkimCanon::headerSimple(stripBTag(sig.rawField));
    if (sigCanon.endsWith("\r\n"))
        sigCanon.chop(2);
    data += sigCanon;

    *signedData = data;
    if (truncated) {
        // Recorded, not just described: trustworthy() has to know, or a
        // message with unsigned text appended below the signed prefix reads as
        // verified — which is exactly what l= is abused for.
        out->bodyTruncated = true;
        out->detail = QObject::tr("only the first %1 bytes of the body are signed")
                          .arg(QString::fromLatin1(lengthTag));
    }
    return true;
}

QByteArray DkimVerifier::publicKeyRecord(const QString &dnsName, bool *tempError,
                                         QHash<QString, QByteArray> *cache)
{
    *tempError = false;
    if (!m_testKeyRecord.isEmpty())
        return m_testKeyRecord;
    if (cache) {
        const auto it = cache->constFind(dnsName);
        if (it != cache->constEnd())
            return *it; // including a remembered "no such key"
    }

    // The cross-message layer: keyed by DNS name, honouring the record's own
    // TTL. Without it, reopening a message re-asks the resolver for a key that
    // was fetched seconds ago — and mail from one sender tends to arrive in
    // runs signed by one selector. No locking: everything here runs on the
    // verifier's thread. Expired entries are dropped on contact rather than
    // swept; the map only ever holds selectors of mail actually opened.
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const auto cached = m_dnsCache.constFind(dnsName);
    if (cached != m_dnsCache.constEnd()) {
        if (cached->expiry > now) {
            if (cache)
                cache->insert(dnsName, cached->record);
            return cached->record;
        }
        m_dnsCache.erase(cached);
    }

    qint64 ttl = 0;
    const QByteArray record = lookupDkimKey(dnsName, tempError, &ttl);
    // A temporary failure must not be cached: the whole point is that it may
    // succeed next time.
    if (!*tempError) {
        if (cache)
            cache->insert(dnsName, record);
        // "No such key" is an answer too (NXDOMAIN), and the one senders with
        // no DKIM produce on every message — cache it briefly rather than
        // hammering the resolver with known misses. Positive answers keep the
        // record's TTL, clamped: the floor outlives the short TTLs key records
        // usually publish, which is where the repeat lookups come from, and
        // hours past a day defeats key rotation. Rotation is what the ceiling
        // protects — it publishes a new selector, so a stale record for the
        // old one is simply never asked for again. Revocation reuses the
        // selector, which is what the floor is kept to half an hour for.
        const qint64 keep = record.isEmpty()
            ? qint64(AdvancedConfig::i("dkim/dnsNegativeTtl"))
            : qBound(qint64(AdvancedConfig::i("dkim/dnsCacheMinTtl")), ttl,
                     qint64(AdvancedConfig::i("dkim/dnsCacheMaxTtl")));
        m_dnsCache.insert(dnsName, {record, now + keep});
    }
    return record;
}

ArcResult DkimVerifier::verifyArcChain(const QByteArray &head, const QByteArray &body,
                                       QHash<QString, QByteArray> *keyCache)
{
    // One hop's three headers. Every hop must supply all three; a set missing
    // one is not a set the chain can be walked through.
    struct ArcSet {
        Field aar;
        Field ams;
        Field seal;
        QList<Tag> sealTags;
        bool haveAar = false;
        bool haveAms = false;
        bool haveSeal = false;
    };

    ArcResult out;
    QMap<int, ArcSet> sets; // keyed by i=, so iteration is oldest hop first

    for (const Field &f : splitFields(head)) {
        const QByteArray name = f.name.toLower();
        const bool isAar = name == "arc-authentication-results";
        const bool isAms = name == "arc-message-signature";
        const bool isSeal = name == "arc-seal";
        if (!isAar && !isAms && !isSeal)
            continue;

        const QList<Tag> tags = parseTagList(f.value);
        bool ok = false;
        const int instance = tagValue(tags, "i").toInt(&ok);
        // §4.1.1 caps a chain at 50 sets; beyond that a message is trying to
        // make us do work, not make a claim.
        if (!ok || instance < 1 || instance > 50) {
            out.status = ArcResult::PermError;
            out.detail = QObject::tr("an ARC header has no usable instance number");
            return out;
        }

        ArcSet &s = sets[instance];
        bool *have = isAar ? &s.haveAar : (isAms ? &s.haveAms : &s.haveSeal);
        if (*have) {
            // Two of the same header in one set: which one a verifier picks
            // decides the outcome, so there is no safe way to guess.
            out.status = ArcResult::PermError;
            out.detail = QObject::tr("ARC set %1 has a duplicate header").arg(instance);
            return out;
        }
        *have = true;
        (isAar ? s.aar : (isAms ? s.ams : s.seal)) = f;
        if (isSeal)
            s.sealTags = tags;
    }

    if (sets.isEmpty())
        return out; // None: the overwhelmingly common case

    const int newest = sets.lastKey();
    out.sets = newest;
    for (int i = 1; i <= newest; ++i) {
        const auto it = sets.constFind(i);
        if (it == sets.constEnd() || !it->haveAar || !it->haveAms || !it->haveSeal) {
            out.status = ArcResult::PermError;
            out.detail = QObject::tr("the ARC chain is incomplete at hop %1").arg(i);
            return out;
        }
    }
    out.sealer = QString::fromLatin1(tagValue(sets[newest].sealTags, "d")).toLower();

    // §5.2: the oldest hop must record that it found no chain, and every later
    // hop must record that the chain was still good when it arrived. A single
    // cv=fail anywhere is a hop telling us outright that the chain was already
    // broken — believe it and stop.
    for (int i = 1; i <= newest; ++i) {
        const QByteArray cv = tagValue(sets[i].sealTags, "cv").toLower();
        if (cv == "fail") {
            out.status = ArcResult::Fail;
            out.detail = QObject::tr("hop %1 recorded the chain as already broken").arg(i);
            return out;
        }
        const QByteArray expected = i == 1 ? QByteArrayLiteral("none") : QByteArrayLiteral("pass");
        if (cv != expected) {
            out.status = ArcResult::PermError;
            out.detail = QObject::tr("ARC set %1 has an out-of-place chain state (cv=%2)")
                             .arg(i)
                             .arg(QString::fromLatin1(cv));
            return out;
        }
    }

    // Shared by the seals and the newest message signature.
    auto fetchKey = [&](const QList<Tag> &tags, QByteArray *keyType, QByteArray *keyData,
                        ArcResult *err) {
        const QString domain = QString::fromLatin1(tagValue(tags, "d")).toLower();
        const QString selector = QString::fromLatin1(tagValue(tags, "s"));
        if (domain.isEmpty() || selector.isEmpty()) {
            err->status = ArcResult::PermError;
            err->detail = QObject::tr("an ARC header is missing its domain or selector");
            return false;
        }
        bool tempError = false;
        const QByteArray record = publicKeyRecord(
            selector + QStringLiteral("._domainkey.") + domain, &tempError, keyCache);
        if (record.isEmpty()) {
            err->status = tempError ? ArcResult::TempError : ArcResult::PermError;
            err->detail = tempError
                ? QObject::tr("could not reach DNS to fetch an ARC signing key")
                : QObject::tr("no ARC key published for %1").arg(domain);
            return false;
        }
        const QList<Tag> keyTags = parseTagList(record);
        *keyType = tagValue(keyTags, "k").isEmpty() ? QByteArrayLiteral("rsa")
                                                    : tagValue(keyTags, "k").toLower();
        *keyData = stripWsp(tagValue(keyTags, "p"));
        if (keyData->isEmpty()) {
            err->status = ArcResult::PermError;
            err->detail = QObject::tr("an ARC signing key has been revoked");
            return false;
        }
        return true;
    };

    // §5.1.1: a seal covers every ARC header of every hop up to and including
    // its own, oldest first, each set in the order results / signature / seal.
    // Relaxed canonicalization always — a seal carries no c= tag to choose.
    // Its own seal goes in last with b= emptied and no trailing CRLF, the same
    // shape a DKIM signature signs itself in.
    auto sealedData = [&](int upTo) {
        QByteArray data;
        for (int i = 1; i <= upTo; ++i) {
            const ArcSet &s = sets[i];
            data += DkimCanon::headerRelaxed(s.aar.name, s.aar.value);
            data += DkimCanon::headerRelaxed(s.ams.name, s.ams.value);
            if (i < upTo) {
                data += DkimCanon::headerRelaxed(s.seal.name, s.seal.value);
                continue;
            }
            QByteArray own = DkimCanon::headerRelaxed(s.seal.name, stripBTag(s.seal.value));
            if (own.endsWith("\r\n"))
                own.chop(2);
            data += own;
        }
        return data;
    };

    for (int i = 1; i <= newest; ++i) {
        const ArcSet &s = sets[i];
        const QByteArray algorithm = tagValue(s.sealTags, "a").toLower();
        if (algorithm != "rsa-sha256" && algorithm != "ed25519-sha256") {
            out.status = ArcResult::PermError;
            out.detail = QObject::tr("ARC seal %1 uses an unsupported algorithm (%2)")
                             .arg(i)
                             .arg(QString::fromLatin1(algorithm));
            return out;
        }
        QByteArray keyType;
        QByteArray keyData;
        if (!fetchKey(s.sealTags, &keyType, &keyData, &out))
            return out;
        PkeyPtr key = loadPublicKey(QByteArray::fromBase64(keyData), keyType);
        if (!key) {
            out.status = ArcResult::PermError;
            out.detail = QObject::tr("an ARC signing key is unusable");
            return out;
        }
        const QByteArray signature = QByteArray::fromBase64(stripWsp(tagValue(s.sealTags, "b")));
        if (!verifySignature(key.get(), keyType, sealedData(i), signature)) {
            out.status = ArcResult::Fail;
            // The seal is over ARC headers only, so this is not our copy of the
            // body being off — something really did rewrite the chain.
            out.detail = QObject::tr("the seal from hop %1 does not verify — the chain of "
                                     "custody has been altered")
                             .arg(i);
            return out;
        }
    }

    // The newest message signature is the one that describes the message as we
    // received it; older ones describe versions we never saw.
    Signature ams;
    ams.rawName = sets[newest].ams.name;
    ams.rawValue = sets[newest].ams.value;
    ams.rawField = sets[newest].ams.raw;
    ams.tags = parseTagList(sets[newest].ams.value);
    const QByteArray canon = tagValue(ams.tags, "c").toLower();
    if (!canon.isEmpty()) {
        const int slash = canon.indexOf('/');
        ams.headerCanon = slash < 0 ? canon : canon.left(slash);
        ams.bodyCanon = slash < 0 ? QByteArrayLiteral("simple") : canon.mid(slash + 1);
    }

    QByteArray amsData;
    DkimResult amsOut;
    if (!prepare(head, body, ams, &amsData, &amsOut)) {
        if (amsOut.status == DkimResult::BodyMismatch) {
            // Every seal held, so the chain itself is intact; we simply cannot
            // confirm the body it vouches for against the copy we hold.
            out.status = ArcResult::SealsOnly;
            out.detail = QObject::tr("the chain of custody is intact, but the body does not "
                                     "match what %1 signed — as with DKIM, our stored copy "
                                     "is the more likely explanation")
                             .arg(out.sealer);
            return out;
        }
        out.status = ArcResult::PermError;
        out.detail = amsOut.detail;
        return out;
    }

    QByteArray keyType;
    QByteArray keyData;
    if (!fetchKey(ams.tags, &keyType, &keyData, &out))
        return out;
    PkeyPtr key = loadPublicKey(QByteArray::fromBase64(keyData), keyType);
    if (!key) {
        out.status = ArcResult::PermError;
        out.detail = QObject::tr("an ARC signing key is unusable");
        return out;
    }
    const QByteArray signature = QByteArray::fromBase64(stripWsp(tagValue(ams.tags, "b")));
    if (!verifySignature(key.get(), keyType, amsData, signature)) {
        out.status = ArcResult::Fail;
        out.detail = QObject::tr("the message signature from %1 does not verify").arg(out.sealer);
        return out;
    }

    out.status = ArcResult::Pass;
    out.detail = QObject::tr("chain of %n hop(s) intact, sealed by %1", nullptr, out.sets)
                     .arg(out.sealer);
    return out;
}

void DkimVerifier::verify(quint64 requestId, const QByteArray &rawMessageCrlf,
                          const QString &fromDomain)
{
    DkimResult result;

    const int split = rawMessageCrlf.indexOf("\r\n\r\n");
    if (split < 0) {
        result.status = DkimResult::PermError;
        result.detail = tr("message has no header/body separator");
        Q_EMIT finished(requestId, result);
        return;
    }
    const QByteArray head = rawMessageCrlf.left(split + 2); // keep the final CRLF
    const QByteArray body = rawMessageCrlf.mid(split + 4);

    // Collect every DKIM-Signature header; a message may carry several and
    // only one needs to verify.
    QList<Signature> signatures;
    for (const Field &f : splitFields(head)) {
        if (f.name.toLower() != "dkim-signature")
            continue;
        Signature s;
        s.rawName = f.name;
        s.rawValue = f.value;
        s.rawField = f.raw;
        s.tags = parseTagList(f.value);
        const QByteArray canon = tagValue(s.tags, "c").toLower();
        if (!canon.isEmpty()) {
            const int slash = canon.indexOf('/');
            s.headerCanon = slash < 0 ? canon : canon.left(slash);
            s.bodyCanon = slash < 0 ? QByteArrayLiteral("simple") : canon.mid(slash + 1);
        }
        signatures.append(s);
    }
    // Shared by every signature and the ARC pass: one message, one set of keys.
    QHash<QString, QByteArray> keyCache;

    if (signatures.isEmpty()) {
        result.status = DkimResult::None;
        // A mailing list that strips the author's signature and seals what it
        // forwards leaves ARC as the only evidence there ever was one.
        result.arc = verifyArcChain(head, body, &keyCache);
        Q_EMIT finished(requestId, result);
        return;
    }

    // Try each signature; the first Pass that is also aligned wins outright.
    DkimResult best;
    best.status = DkimResult::PermError;
    for (const Signature &sig : signatures) {
        DkimResult r;
        r.domain = QString::fromLatin1(tagValue(sig.tags, "d")).toLower();
        r.selector = QString::fromLatin1(tagValue(sig.tags, "s"));
        r.aligned = domainsAligned(r.domain, fromDomain);
        if (r.domain.isEmpty() || r.selector.isEmpty()) {
            r.status = DkimResult::PermError;
            r.detail = tr("signature is missing its domain or selector");
            best = r;
            continue;
        }

        QByteArray signedData;
        if (!prepare(head, body, sig, &signedData, &r)) {
            best = r;
            continue;
        }

        bool tempError = false;
        const QByteArray record = publicKeyRecord(
            r.selector + QStringLiteral("._domainkey.") + r.domain, &tempError, &keyCache);
        if (record.isEmpty()) {
            r.status = tempError ? DkimResult::TempError : DkimResult::PermError;
            r.detail = tempError ? tr("could not reach DNS to fetch the signing key")
                                 : tr("no public key published for %1").arg(r.selector);
            best = r;
            continue;
        }

        const QList<Tag> keyTags = parseTagList(record);
        const QByteArray keyType =
            tagValue(keyTags, "k").isEmpty() ? QByteArrayLiteral("rsa")
                                             : tagValue(keyTags, "k").toLower();
        const QByteArray keyData = stripWsp(tagValue(keyTags, "p"));
        if (keyData.isEmpty()) {
            r.status = DkimResult::PermError;
            r.detail = tr("the signing key has been revoked");
            best = r;
            continue;
        }
        PkeyPtr key = loadPublicKey(QByteArray::fromBase64(keyData), keyType);
        if (!key) {
            r.status = DkimResult::PermError;
            r.detail = tr("published key is unusable");
            best = r;
            continue;
        }

        const QByteArray signature = QByteArray::fromBase64(stripWsp(tagValue(sig.tags, "b")));
        if (verifySignature(key.get(), keyType, signedData, signature)) {
            r.status = DkimResult::Pass;
            if (r.detail.isEmpty()) {
                r.detail = r.aligned
                    ? tr("signed by %1").arg(r.domain)
                    // Valid but unaligned: the signer is not the From: domain,
                    // which is exactly what a forger's own valid signature
                    // looks like. Both domains are named so the mismatch can
                    // be seen, not taken on faith.
                    : tr("signed by %1, which does not match the sender %2")
                          .arg(r.domain, fromDomain);
            }
            if (r.aligned) {
                Q_EMIT finished(requestId, r);
                return;
            }
            best = r;
            continue;
        }
        r.status = DkimResult::Fail;
        r.detail = tr("signature does not match the published key");
        best = r;
    }

    // Only now, having failed to produce a signature the reader can rely on:
    // ARC is what explains a message that was legitimate before a list touched
    // it, and it costs DNS queries that a trustworthy signature makes pointless.
    best.arc = verifyArcChain(head, body, &keyCache);
    Q_EMIT finished(requestId, best);
}
