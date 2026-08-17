// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "mailclient.h"

#include "advancedconfig.h"
#include "documenthandler.h"
#include "mimeutils.h"
#include "attachmentstore.h"
#include "oauthhelper.h"
#include "pgpengine.h"
#include "pgpmime.h"
#include "imapbackend.h"
#include "jmapbackend.h"
#include "spamheuristics.h"
#include "publicsuffixlist.h"

#include <QClipboard>
#include <QMimeData>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QGuiApplication>
#include <QDir>
#include <QFile>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QStandardPaths>
#include <QLocale>
#include <QRandomGenerator>
#include <QSettings>
#include <QSqlQuery>
#include <QLoggingCategory>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>

#include <kmime/content.h>
#include <kmime/headerparsing.h>
#include <kmime/message.h>
#include <kmime/types.h>
#include <kmime/util.h>

#include <qt6keychain/keychain.h>


#include <QMimeDatabase>

#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextDocumentFragment>
#include <QTextFrame>
#include <QTextImageFormat>
#include <QTextTable>

#include "viewersecurity.h"

#include <algorithm>

static QSettings appSettings()
{
    return AccountStore::settings();
}

/// The keyring "service" every entry of ours is filed under. The keys within
/// it are AccountStore's to name — see walletKeyFor()/oauthWalletKeyFor().
static const auto kWalletService = QStringLiteral("mailove");

// Background-sync pacing and the throttle backoff used to be duplicated here
// as well; both now live in SyncEngine, which is the only thing that ever read
// them, and their numbers come from the advanced-settings schema
// (kSchema in advancedconfig.cpp) rather than from a constant.

/// True when the IMAP error text carries a throttling response code such as
/// Gmail's [THROTTLED] or [TOO-MANY-SIMULTANEOUS-CONNECTIONS]. Case-folded so
/// server casing differences don't matter.
static bool isThrottleError(const QString &err)
{
    const QString e = err.toUpper();
    return e.contains(QStringLiteral("THROTTL"))
        || e.contains(QStringLiteral("TOO-MANY-SIMULTANEOUS-CONNECTIONS"))
        || e.contains(QStringLiteral("TOO MANY SIMULTANEOUS CONNECTIONS"));
}

/// True when \a authservId is exactly one of \a trustedDomains or a host under
/// one. Must not be a substring test: "contains" would accept an authserv-id
/// of "gmail.com.attacker.example", which any sender can stamp on their own
/// message, turning the SPF/DKIM badge into attacker-controlled text.
static bool authservIdTrusted(const QString &authservId, const QStringList &trustedDomains)
{
    for (const QString &domain : trustedDomains) {
        if (authservId == domain || authservId.endsWith(QLatin1Char('.') + domain))
            return true;
    }
    return false;
}

/// First Authentication-Results header stamped by our own receiving server
/// (senders can forge their own AR headers, so foreign authserv-ids are
/// ignored). Empty when the message carries no trusted verdict.
static QString trustedAuthResults(const KMime::Message *msg,
                                  const QStringList &trustedAuthDomains)
{
    if (trustedAuthDomains.isEmpty())
        return {}; // nobody to trust — show nothing rather than a forgery
    const auto arHeaders = msg->headersByType("Authentication-Results");
    for (const KMime::Headers::Base *ar : arHeaders) {
        const QString value = ar->asUnicodeString();
        // authserv-id is the first field, optionally followed by a version
        // number: "purelymail.com 1; spf=pass …".
        const QString authservId = SpamHeuristics::stripAuthCommentsAndQuotes(value)
                                       .section(QLatin1Char(';'), 0, 0)
                                       .simplified()
                                       .section(QLatin1Char(' '), 0, 0)
                                       .toLower();
        if (!authservIdTrusted(authservId, trustedAuthDomains))
            continue; // forged or foreign AR header — ignore
        return value; // first trusted header wins (newest — servers prepend)
    }
    return {};
}

/// Builds a list header from a backend delivery, including the sender-
/// authentication verdict our receiving server stamped into the message.
static MessageListModel::Header headerFromBackend(const MailBackend::HeaderInfo &info,
                                                  const QStringList &trustedAuthDomains)
{
    MessageListModel::Header h;
    h.uid = info.uid;
    // Whatever the backend calls this message, recorded so the cache keys it
    // the same way regardless of which protocol fetched it (Header::remoteId).
    h.remoteId = info.remoteId;
    // Already parsed by the backend — never re-parsed here.
    const KMime::Message *msg = info.message.get();
    if (const auto *subject = msg->subject())
        h.subject = subject->asUnicodeString();
    if (const auto *from = msg->from())
        h.from = from->asUnicodeString();
    if (const auto *date = msg->date())
        h.date = date->dateTime();
    if (const auto *mid = msg->messageID(); mid && !mid->isEmpty())
        h.msgid = QString::fromLatin1(mid->identifier());
    h.seen = info.flags.contains(QStringLiteral("seen"));
    // Header-only heuristic: real attachments arrive as multipart/mixed.
    // Must inspect the raw head — KMime's parsed Content-Type reports
    // text/plain for a multipart message that has no body parts yet.
    h.attachKind = MailStore::headIndicatesAttachment(msg->head())
        ? MessageListModel::GenericAttachment
        : MessageListModel::NoAttachment;
    // Same trick for the lock glyph: the outer content type is in the head, so
    // the list knows an encrypted message without waiting for its body.
    h.crypto = PgpMime::storedKind(PgpMime::kindFromHead(msg->head()));
    h.authInfo = trustedAuthResults(msg, trustedAuthDomains);
    // Parsed by the same functions the spam scorer's context is built from, so
    // the "!" marker and the score can never disagree about the same header.
    // The marker does not grade: soft or hard, something failed to check out.
    if (SpamHeuristics::authResultsFailed(h.authInfo)
        || SpamHeuristics::authResultsSoftFailed(h.authInfo))
        h.suspicious = true;
    return h;
}

/// The authserv-id domains whose Authentication-Results headers we trust for a
/// given IMAP host. Providers rarely stamp the domain you connect to — Gmail is
/// reached at imap.gmail.com but stamps "mx.google.com" — so deriving the
/// registrable domain of the host alone would discard every genuine header and
/// leave only forged ones able to match.
static QStringList trustedAuthDomainsForHost(const QString &host)
{
    const QString h = host.toLower();
    struct Provider {
        const char *hostSuffix;
        const char *authDomains; // space-separated
    };
    static const Provider providers[] = {
        {"gmail.com", "mx.google.com google.com"},
        {"googlemail.com", "mx.google.com google.com"},
        {"google.com", "mx.google.com google.com"},
        {"outlook.com", "outlook.com protection.outlook.com"},
        {"office365.com", "outlook.com protection.outlook.com"},
        {"hotmail.com", "outlook.com protection.outlook.com"},
        {"live.com", "outlook.com protection.outlook.com"},
        {"yahoo.com", "yahoo.com"},
        {"fastmail.com", "messagingengine.com fastmail.com"},
        {"messagingengine.com", "messagingengine.com fastmail.com"},
        {"icloud.com", "icloud.com me.com"},
        {"me.com", "icloud.com me.com"},
        {"zoho.com", "zoho.com zohomail.com"},
        {"zohomail.com", "zoho.com zohomail.com"},
        {"proton.me", "proton.me protonmail.ch"},
        {"protonmail.ch", "proton.me protonmail.ch"},
        {"yandex.ru", "yandex.ru"},
        {"gmx.net", "gmx.net"},
        {"web.de", "web.de"},
        {"mail.ru", "mail.ru"},
    };
    for (const Provider &p : providers) {
        const QString suffix = QLatin1String(p.hostSuffix);
        if (h == suffix || h.endsWith(QLatin1Char('.') + suffix))
            return QString::fromLatin1(p.authDomains).split(QLatin1Char(' '), Qt::SkipEmptyParts);
    }
    // Unknown provider: the host itself and its registrable domain, which is
    // what a self-hosted or small-provider server stamps.
    QStringList out{h};
    const QStringList labels = h.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (labels.size() >= 3)
        out.append(labels.mid(1).join(QLatin1Char('.')));
    return out;
}

QStringList MailClient::trustedAuthDomains() const
{
    // Trusting nobody is exactly the "off" behaviour: trustedAuthResults()
    // returns nothing for an empty list, so no verdict is read off a message,
    // none is stored on a header, and the list marker never appears.
    if (!m_authVerification)
        return {};
    return trustedAuthDomainsForHost(m_acct.host);
}

/// "1 message" / "42 messages". Qt only picks plural forms for %n when a
/// translator is installed — without one, "(s)"-style source strings leak
/// into the UI verbatim.
static QString countNoun(qint64 n, const char *singular, const char *plural)
{
    return QStringLiteral("%1 %2").arg(n).arg(
        QLatin1String(n == 1 ? singular : plural));
}

/// Opt-in diagnostics (Settings -> General -> "Log activity to console"). Off
/// by default so a normal run stays quiet; toggling needs no restart.
Q_LOGGING_CATEGORY(logTrace, "mailove.trace")

/// Condense a verbose/multi-line error (often a raw server or KJob string)
/// into a terse status crumb: first line only, trailing punctuation trimmed,
/// and clipped so it never bloats the status line.
static QString shortenError(const QString &err)
{
    QString s = err.section(QLatin1Char('\n'), 0, 0).simplified();
    while (!s.isEmpty() && (s.endsWith(QLatin1Char('.')) || s.endsWith(QLatin1Char(':'))))
        s.chop(1);
    constexpr int kMaxLen = 60;
    if (s.size() > kMaxLen)
        s = s.left(kMaxLen - 1).trimmed() + QStringLiteral("…");
    return s;
}

/// The persisted `protocol` value as the enumerator it stands for. Anything
/// unrecognised is IMAP: that is what every account written before the key
/// existed means by its absence, and the safe reading of a value from a
/// newer version.
static MailBackend::Protocol protocolFromSetting(int value)
{
    return value == static_cast<int>(MailBackend::Protocol::Jmap)
        ? MailBackend::Protocol::Jmap
        : MailBackend::Protocol::Imap;
}

/// A backend speaking \a protocol. The only place either concrete class is
/// named — everything downstream holds a MailBackend and cannot tell which.
static MailBackend *makeBackend(MailBackend::Protocol protocol, QObject *parent)
{
    if (protocol == MailBackend::Protocol::Jmap)
        return new JmapBackend(parent);
    return new ImapBackend(parent);
}

/// Replaces the backend with one speaking \a protocol. Called before every
/// connect, so an account switch to the other protocol is simply the next
/// connect: nothing outside this function names a concrete backend, and
/// nothing that survives it (models, cache, selected folder) belongs to one.
void MailClient::setBackendProtocol(MailBackend::Protocol protocol)
{
    if (m_backend && m_backend->protocol() == protocol)
        return;
    if (m_backend) {
        m_backend->disconnectAccount();
        m_backend->deleteLater();
    }
    m_backend = makeBackend(protocol, this);
    connectBackend(m_backend);
}

void MailClient::connectBackend(MailBackend *backend)
{
    m_sync->setBackend(backend);
    // The protocol side reports what happened on the wire; deciding what it
    // means for the UI, the models and the cache stays here.
    connect(backend, &MailBackend::connectedChanged, this, [this](bool up) {
        Q_EMIT connectedChanged();
        if (!up)
            return;
        // A "mark all read" made before the connection was up is sent now,
        // before the header sync that would otherwise read the old flags back.
        flushPendingSeen();
        // No "loading folders" crumb — the busy spinner shows the activity.
        listFolders();
    });
    connect(backend, &MailBackend::connectionLost, this,
            &MailClient::handleConnectionLost);
    connect(backend, &MailBackend::errorOccurred, this,
            [this](MailBackend::Error error, const QString &message) {
                setBusy(false);
                switch (error) {
                case MailBackend::Error::Auth:
                case MailBackend::Error::Connection:
                    // The backend has closed its connections; this clears the
                    // sync bookkeeping that went with them (backfill cursor,
                    // prefetch queue, body pool) so a reconnect starts clean.
                    teardownSession();
                    setStatus(error == MailBackend::Error::Auth ? tr("Login failed")
                                                                : tr("Connection failed"));
                    break;
                default:
                    // The background pass asked to open a folder and was
                    // refused. Nobody is looking at that folder, so this is not
                    // the user's problem to read about — but it *is* the pass's
                    // to survive: leaving m_backfillFolder set would re-issue
                    // the same doomed open forever and never reach the folders
                    // queued behind it.
                    if (m_sync->handleBackgroundOpenFailure(message))
                        return;
                    // The connection is healthy and one request was refused —
                    // tearing the session down here would turn a failed folder
                    // listing into a disconnect. The server's own words go to
                    // the dialog below, which is where the detail is of use.
                    setStatus(tr("Server refused the request"));
                    break;
                }
                Q_EMIT errorOccurred(message);
            });
    connect(backend, &MailBackend::foldersListed, this, &MailClient::applyFolderListing);
    connect(backend, &MailBackend::folderOpened, this, &MailClient::applyFolderOpened);
    connect(backend, &MailBackend::folderInvalidated, this,
            &MailClient::applyFolderInvalidated);
    connect(backend, &MailBackend::messagesVanished, this,
            &MailClient::applyMessagesVanished);
    connect(backend, &MailBackend::searchResults, this,
            [this](const QString &, const QStringList &ids) { m_pendingSearchIds = ids; });
    connect(backend, &MailBackend::bodyFetched, this,
            [this](const QString &folder, const QString &remoteId,
                   const std::shared_ptr<KMime::Message> &message) {
                // Never toLongLong(): a JMAP remote id is an opaque string and
                // parsing one yields 0, which would file every body on the
                // same cache row.
                storeFetchedBody(folder, m_backend->localKeyFor(remoteId), message);
            });
    // Headers stream in batches; the request's own callback says when a window
    // is complete, and that is where the buffer below is drained.
    connect(backend, &MailBackend::headersFetched, this,
            [this](const QString &folder, const QList<MailBackend::HeaderInfo> &infos) {
                QList<MessageListModel::Header> rows;
                appendScoredHeaders(rows, folder, infos, trustedAuthDomains());
                m_sync->addPendingHeaders(folder, rows);
            });
    // The background connection dropping mid-fetch is the server pushing back;
    // the backfill's own backoff is what answers it.
    connect(backend, &MailBackend::throttled, this, [this] {
        m_sync->handleThrottled();
    });
    // Push says only "something changed there" — what changed is then fetched
    // the ordinary way, which is what keeps IDLE and JMAP's EventSource
    // interchangeable.
    connect(backend, &MailBackend::folderChanged, this, [this](const QString &folder) {
        if (folder == m_selectedFolder)
            refreshCurrentFolder();
    });
    // Only a protocol whose push covers the whole account raises this, so this
    // is where a JMAP account's *other* folders get their counts between polls
    // — the thing IMAP IDLE, watching one selected mailbox, can never report.
    connect(backend, &MailBackend::accountChanged, this,
            &MailClient::scheduleAccountCountRefresh);
}

/// Defined with the viewer code below; the scheduler and the importer both
/// reuse it so every path indexes a message the same way.
static QString indexTextFor(KMime::Message *msg);

MailClient::MailClient(QObject *parent)
    : QObject(parent)
{
    // Before anything can queue a body write or ask about the cache.
    setUpMaintenance();

    // The wallet read is asynchronous, so a connect requested before the
    // secret lands is deferred with m_connectWhenReady and resumed here. Wired
    // before loadAccount() below, which is what starts that read.
    connect(&m_accounts, &AccountStore::secretsReady, this, [this] {
        if (!m_connectWhenReady)
            return;
        m_connectWhenReady = false;
        connectAccount();
    });
    connect(&m_accounts, &AccountStore::errorOccurred, this, &MailClient::errorOccurred);

    m_sync = new SyncEngine(m_store, m_messageModel, m_folderModel, this);
    m_sync->setBusyProvider([this] { return m_busy; });
    connect(m_sync, &SyncEngine::statusMessage, this, &MailClient::setStatus);
    connect(m_sync, &SyncEngine::errorOccurred, this, &MailClient::errorOccurred);
    connect(m_sync, &SyncEngine::busyRequested, this, &MailClient::setBusy);
    connect(m_sync, &SyncEngine::folderRefreshed, this, &MailClient::folderRefreshed);
    connect(m_sync, &SyncEngine::unreadRecountNeeded, this,
            &MailClient::scheduleUnreadRecount);

    m_presenter = new MessagePresenter(this);
    m_verifier = new MessageVerifier(m_store, m_presenter,
                                     [](KMime::Message *msg) { return indexTextFor(msg); },
                                     this);
    // The list marks a decryption revealed. Model only, never the store — what
    // was learned from plaintext does not go in the cache (doc/openpgp.md §4).
    connect(m_verifier, &MessageVerifier::cryptoMarkRefined, this,
            [this](const QString &folder, qint64 uid, int storedKind) {
        if (folder == m_selectedFolder)
            m_messageModel.setCrypto(uid, storedKind);
    });
    connect(m_verifier, &MessageVerifier::attachmentsDiscovered, this,
            [this](const QString &folder, qint64 uid) {
        if (folder == m_selectedFolder)
            m_messageModel.setAttachKind(uid, MessageListModel::GenericAttachment);
    });
    // How the verifier gets the server's copy when a cached body fails its
    // hash. The single retry is here because declining a bulk transfer is the
    // backend's answer, not the verdict's.
    m_verifier->setRefetchBody([this](const QString &folder, qint64 uid,
                                      MessageVerifier::BodyReady done) {
        return refetchBodyForVerification(folder, uid, false, std::move(done));
    });

    connect(m_presenter, &MessagePresenter::statusMessage, this, &MailClient::setStatus);
    connect(m_presenter, &MessagePresenter::errorOccurred, this, &MailClient::errorOccurred);
    connect(m_presenter, &MessagePresenter::previewTextChanged, this,
            [this](const QString &text) {
        m_textPreview = text;
        Q_EMIT textPreviewChanged();
    });

    // IMAP until the account settings say otherwise, which loadAccount() below
    // is what decides. A backend always exists, so nothing has to null-check it.
    setBackendProtocol(MailBackend::Protocol::Imap);

    // The reading pane's message context. Detached windows clone it; this one
    // lives as long as the client. The legacy Mail.* message properties
    // delegate to it, so its change signals feed theirs.
    m_reading = new MessageContext(this);
    connect(m_reading, &MessageContext::messageChanged,
            this, &MailClient::attachmentsChanged);
    connect(m_reading, &MessageContext::messageChanged,
            this, &MailClient::junkTextOnlyChanged);
    connect(m_reading, &MessageContext::remoteContentAllowedChanged,
            this, &MailClient::remoteContentAllowedChanged);

    // Before the verifier thread exists, so the list's networking belongs to
    // the GUI thread: alignment reads it from the verifier thread, and whoever
    // touches the singleton first decides where it lives.
    PublicSuffixList::instance().start();

    // DKIM verification lives on its own thread for its whole life (inside
    // MessageVerifier): the DNS round trip alone would stall the GUI for as
    // long as a resolver takes.
    qRegisterMetaType<DkimResult>();

    // One-time Message-ID backfill for rows cached before the column existed.
    // 100 rows a tick reads roughly 1.5 MB of message heads — well inside a
    // frame — and the timer stops itself the moment there is nothing left.
    m_msgidBackfillTimer.setInterval(2000);
    connect(&m_msgidBackfillTimer, &QTimer::timeout, this, [this] {
        if (m_store.backfillMessageIds(100) == 0) {
            m_msgidBackfillTimer.stop();
            qCDebug(logTrace, "message-id backfill complete");
        }
    });
    QTimer::singleShot(10000, this, [this] { m_msgidBackfillTimer.start(); });

    // Errors go into the status breadcrumb (short), not passive popups.
    connect(this, &MailClient::errorOccurred, this, [this](const QString &msg) {
        setStatus(shortenError(msg));
    });
    loadAccount();
    m_folderModel.setAccountKey(accountKey());
    // Before the store is read from anywhere, including the sort worker: the
    // cache marks what it finds in a junk folder, and only this class can say
    // which folders those are. Captures `this`, which outlives the store.
    MailStore::setJunkFolderTest([this](const QString &scopedFolder) {
        // Passed the whole key, not the leaf: the cache holds every account's
        // rows and the answer depends on whose they are. An imported archive's
        // "Junk" folder is a record of what some other mail system once
        // decided, not a verdict this client should be restating.
        if (isLocalAccountKey(scopedFolder.section(QChar(0x1f), 0, 0)))
            return false;
        return isJunkFolder(scopedFolder.section(QChar(0x1f), -1));
    });
    m_store.open();
    // Claim any pre-multi-account cache rows for the account they were
    // written by (the one active at upgrade time), then scope everything.
    // Never for a local archive: its key was born after the migration and
    // must not adopt another account's leftovers.
    if (!m_acct.local)
        m_store.adoptLegacyCache(accountKey());
    m_store.setAccountKey(accountKey());

    // Instant startup from cache: folders and INBOX appear before (and
    // without) any network connection.
    loadCachedFolderModel();
    setSelectedFolder(QStringLiteral("INBOX"));
    const auto cachedInbox = m_store.cachedHeaders(m_selectedFolder);
    updatePageAnchor(cachedInbox);
    if (!cachedInbox.isEmpty()) {
        m_messageModel.setHeaders(cachedInbox);
        // Real cache size from SQL — cachedInbox is one page (max 1000 rows).
        setStatus(tr("INBOX — %1 cached")
                      .arg(m_store.cachedHeaderCount(m_selectedFolder)));
    }


    // Fallback poll of the open folder for servers where IDLE push is not
    // running; a no-op whenever the IDLE job is alive.
    m_refreshMinutes = qBound(
        0, appSettings().value(QStringLiteral("ui/refreshMinutes"), 5).toInt(), 24 * 60);
    m_maxBodyMB =
        qBound(0, appSettings().value(QStringLiteral("ui/maxBodyMB"), 5).toInt(), 1024);
    m_spamRetentionDays = qBound(
        0, appSettings().value(QStringLiteral("ui/spamRetentionDays"), 30).toInt(), 3650);
    m_spamSkipTrash =
        appSettings().value(QStringLiteral("ui/spamSkipTrash"), true).toBool();
    m_authVerification =
        appSettings().value(QStringLiteral("ui/authVerification"), true).toBool();
    m_verifier->setAuthVerification(m_authVerification);
    setDebugLogging(appSettings().value(QStringLiteral("ui/debugLogging"), false).toBool());
    connect(&m_pollTimer, &QTimer::timeout, this, [this] {
        if (connected() && !m_backend->pushActive())
            refreshCurrentFolder();
        // The open folder is covered by IDLE or the line above — but nothing
        // else on the open account is. IMAP IDLE watches the one selected
        // mailbox, and refreshAccountUnreadCounts() hangs off a signal only
        // JMAP raises, so without this the account being *read* is the one
        // whose other folders go stalest: a background account at least gets
        // the STATUS sweep in pollOtherAccounts() every tick.
        //
        // Skipped while something user-triggered is in flight: both of these
        // queue on the interactive session, and the interval has no deadline.
        if (connected() && !m_busy) {
            refreshAccountUnreadCounts(); // the pills, now
            // …and the mail behind them. The all-folders sync pass latches
            // itself done (once per connect), so re-arm it — mail arriving in
            // a folder nobody has open reaches the cache no other way. A pass
            // over folders that have not grown costs one open each and no
            // fetch: folderOpened() jumps straight to the body phase when the
            // cached header count already matches the server's.
            m_sync->restartFolderPass();
        }
        // Every other account has no connection at all, so this is the only
        // thing that ever moves their unread counts.
        pollOtherAccounts();
    });
    if (m_refreshMinutes > 0)
        m_pollTimer.start(m_refreshMinutes * 60 * 1000);

    // The open account syncs itself the moment it connects (listFolders, then
    // the all-folders pass). Every *other* account only ever moves on a poll
    // tick, so without this its unread counts are as old as the last session
    // until the first interval elapses. Launch is a refresh point of its own:
    // this runs even when the interval is disabled (refreshMinutes == 0), and
    // it starts at once rather than on a delay. Queued rather than called
    // directly only because the constructor has not returned yet; it is one
    // short-lived login at a time, on connections of its own, so it does not
    // queue behind the open account's first sync.
    QTimer::singleShot(0, this, [this] { pollOtherAccounts(); });

    m_dateFormat = appSettings()
                       .value(QStringLiteral("ui/dateFormat"), QStringLiteral("yyyy-MM-dd"))
                       .toString();
    m_messageModel.setDateFormat(m_dateFormat);

    m_jobs->startReindexTimer();

    // Old mail still has its attachments inside the message BLOBs; move them
    // out in the background. Deferred so it never competes with startup.
    if (m_store.attachmentMigrationPending())
        QTimer::singleShot(8000, this, [this] { m_jobs->startAttachmentMigration(); });

    // Same idea for the search index built before diacritic folding. Deferred
    // further than the attachment migration so the two do not fight over the
    // write lock in the first seconds.
    if (m_store.ftsNeedsRebuild())
        QTimer::singleShot(15000, this, [this] { m_jobs->startIndexRebuild(); });

    // The To column: mail cached before that column existed has none, which in
    // the Sent folder is every row. The header is still on disk inside the
    // cached message, so this reads it back rather than re-fetching anything.
    // Sooner than the other two because until it finishes the Sent folder is
    // visibly showing the wrong name, and it costs nothing after the first run.
    QTimer::singleShot(3000, this, [this] {
        // The static name test, not listsRecipients(): the worker walks every
        // account's folders, and the configured Sent/Drafts this object knows
        // about belong to the open account alone.
        m_jobs->startRecipientBackfill(&MailClient::folderNameIsOutgoing);
    });
}

/// Creates the cache-maintenance worker pool and wires what it reports back.
/// Split out of the constructor only because the wiring is a list of its own.
void MailClient::setUpMaintenance()
{
    m_jobs = new MaintenanceScheduler(
        m_store,
        [](KMime::Message *msg) { return indexTextFor(msg); },
        [this] {
            // Every account the pane can show a pill for, not just the open
            // one — one worker pass fills them all.
            QStringList keys;
            const int count = m_accounts.count();
            for (int i = 0; i < count; ++i) {
                const QString key = m_accounts.storedKeyAt(i);
                if (!key.isEmpty() && !keys.contains(key))
                    keys.append(key);
            }
            return keys;
        },
        this);

    connect(m_jobs, &MaintenanceScheduler::statusMessage, this, &MailClient::setStatus);
    connect(m_jobs, &MaintenanceScheduler::errorOccurred, this, &MailClient::errorOccurred);
    connect(m_jobs, &MaintenanceScheduler::reclaimingChanged, this,
            &MailClient::reclaimingChanged);
    connect(m_jobs, &MaintenanceScheduler::indexRebuildChanged, this,
            &MailClient::indexRebuildChanged);
    connect(m_jobs, &MaintenanceScheduler::migrationChanged, this, [this] {
        Q_EMIT migrationChanged();
        // A finished migration has changed rows the list is already showing.
        // Re-read them rather than leave the old values on screen until
        // something else happens to reload the folder.
        if (!m_jobs->migrationRunning() && !m_selectedFolder.isEmpty()
            && m_messageModel.totalCount() > 0 && !m_searchActive) {
            m_messageModel.setHeaders(m_store.cachedHeaders(m_selectedFolder));
        }
    });
    connect(m_jobs, &MaintenanceScheduler::indexRebuildFinished, this, [this] {
        if (m_quitAfterIndex)
            Q_EMIT closeRequested();
    });
    // A vacuum holds the exclusive lock; background syncing must not queue
    // behind it, and must resume on its own afterwards.
    connect(m_jobs, &MaintenanceScheduler::syncPauseRequested, this, [this] {
        m_sync->setSyncPaused(true);
    });
    connect(m_jobs, &MaintenanceScheduler::syncResumeRequested, this, [this] {
        m_sync->setSyncPaused(false);
        m_sync->scheduleBackfill(2000);
        // The archive purge is restartable and was cancelled for the vacuum.
        if (!m_allMailFolder.isEmpty())
            m_jobs->startAllMailPurge(m_store.scopedKey(m_allMailFolder));
    });
    connect(m_jobs, &MaintenanceScheduler::folderOpsFinished, this,
            &MailClient::invalidateMissingBodies);
    connect(m_jobs, &MaintenanceScheduler::sortPageReady, this,
            [this](const QString &scopedFolder, int column, bool descending, bool append,
                   const QList<MessageListModel::Header> &rows) {
        // The worker slot is free either way — even when the page below turns
        // out to be stale, the next ask may go out.
        m_sortPageInFlight = false;
        // Sorting the folder takes long enough that the user can have clicked
        // another column, or another folder, before the page lands. Either
        // makes it a page of something that is no longer showing.
        if (column != m_sortColumn || descending != m_sortDescending || m_searchActive
            || scopedFolder != m_store.scopedKey(m_selectedFolder)
            || !m_sync->sortedBrowse())
            return;
        applySortPage(append, rows);
    });
    connect(m_jobs, &MaintenanceScheduler::unreadCountsReady, this,
            [this](const QHash<QString, QHash<QString, int>> &counts) {
        m_unreadByAccount = counts;
        m_folderModel.setUnreadCounts(m_unreadByAccount.value(accountKey()));
        ++m_cachedFolderRevision;
        Q_EMIT cachedFoldersChanged(); // repaints the other accounts' trees
    });
}

/// The delimiter a stored mailbox path is built with. Servers use one or the
/// other and never mix them within a path; imported archives always use '/'.
static QChar folderSeparatorOf(const QString &mailBox)
{
    return mailBox.contains(QLatin1Char('/')) ? QLatin1Char('/') : QLatin1Char('.');
}

/// Gmail hangs its default folders — Sent Mail, Drafts, Trash, Spam, Starred,
/// Important — off a "[Gmail]" mailbox that is \Noselect: a namespace marker,
/// not a folder. The user's labels are plain top-level mailboxes beside it.
/// "[Google Mail]" is the same thing under Google's UK/DE branding.
static bool isGmailNamespace(const QString &component)
{
    return component.compare(QLatin1String("[Gmail]"), Qt::CaseInsensitive) == 0
        || component.compare(QLatin1String("[Google Mail]"), Qt::CaseInsensitive) == 0;
}

/// Sort rank of one path component: the inbox above its siblings at every
/// level, and — at the root only — Gmail's namespace above the user's labels.
/// Its contents are the default folders every other account shows directly
/// under the inbox, and flattenGmailNamespace() below moves them there; the
/// rank is what keeps the group in that spot, rather than letting '[' decide
/// where it lands among the label names.
static int componentRank(const QString &component, int depth)
{
    if (component.compare(QLatin1String("inbox"), Qt::CaseInsensitive) == 0)
        return 0;
    if (depth == 0 && isGmailNamespace(component))
        return 1;
    return 2;
}

/// Depth-first order with parents directly above their children — the order
/// the sidebar's tree rendering depends on (a plain string sort could wedge
/// "Inbox-old" between "Inbox" and "Inbox/Work").
///
/// The inbox sorts above its siblings at every level, the same rule the
/// server's folder listing is sorted by. An archive has no special-use flags
/// to go on, so it is recognised by name — which is all Thunderbird's on-disk
/// layout, where these paths come from, ever had either.
static bool mailBoxPathLess(const QString &a, const QString &b, QChar sep)
{
    const QStringList pa = a.split(sep);
    const QStringList pb = b.split(sep);
    for (int i = 0; i < pa.size() && i < pb.size(); ++i) {
        const int ra = componentRank(pa.at(i), i);
        const int rb = componentRank(pb.at(i), i);
        if (ra != rb)
            return ra < rb;
        const int c = QString::compare(pa.at(i), pb.at(i), Qt::CaseInsensitive);
        if (c != 0)
            return c < 0;
    }
    return pa.size() < pb.size();
}

/// The delimiter a whole stored list is built with — see folderSeparatorOf().
static QChar separatorOfPaths(const QStringList &boxes)
{
    for (const QString &box : boxes) {
        if (box.contains(QLatin1Char('/')))
            return QLatin1Char('/');
    }
    return QLatin1Char('.');
}

static void sortMailBoxPaths(QStringList *boxes, QChar sep)
{
    std::sort(boxes->begin(), boxes->end(), [sep](const QString &a, const QString &b) {
        return mailBoxPathLess(a, b, sep);
    });
}

/// An archive's folder list in sidebar order. A connected account gets its
/// order from the server's LIST on every refresh; an archive has no server, so
/// the stored row order is all it has — and archives imported before a change
/// to the ordering rule keep whatever order they were written with. Sorting on
/// read repairs those without a re-import.
static QStringList sortedLocalFolders(const QStringList &boxes)
{
    QStringList sorted = boxes;
    sortMailBoxPaths(&sorted, separatorOfPaths(boxes));
    return sorted;
}

/// How every path in \a boxes draws in the tree: its indent depth, and the
/// part of the path that is its own name.
///
/// Both are read from the ancestors that are really in the list, not from the
/// separators in the string. An imported Thunderbird profile keeps its mail
/// under the server directory it came from ("mail.example.com/Inbox") without
/// that directory being a mailbox of its own, and a plain IMAP folder is
/// allowed a dot in its name ("phish.id") on a server whose delimiter is a
/// dot — counting separators indented both of those a step past the account
/// name they hang under, with nothing drawn at the step above.
struct PathRow {
    int level = 0;
    QString name;
};

/// \a knownSep is the delimiter the server reported, when there is one to ask;
/// a null QChar falls back to guessing it per path (all a cached list of some
/// other account has to go on).
static QList<PathRow> pathRows(const QStringList &boxes, QChar knownSep = {})
{
    const QSet<QString> known(boxes.cbegin(), boxes.cend());
    QList<PathRow> rows;
    rows.reserve(boxes.size());
    for (const QString &mailBox : boxes) {
        const QChar sep = knownSep.isNull() ? folderSeparatorOf(mailBox) : knownSep;
        const QStringList parts = mailBox.split(sep);
        PathRow row;
        int shown = 0; // characters covered by the deepest ancestor on screen
        QString prefix;
        for (int i = 0; i + 1 < parts.size(); ++i) {
            prefix += (i == 0 ? QString() : QString(sep)) + parts.at(i);
            if (known.contains(prefix)) {
                ++row.level;
                shown = int(prefix.size()) + 1; // + the separator after it
            }
        }
        row.name = mailBox.mid(shown);
        rows.append(row);
    }
    return rows;
}

/// Draws Gmail's namespace the way Gmail's own web UI and Thunderbird do:
/// the "[Gmail]" container row goes, and the default folders behind it move up
/// beside the inbox. Left literal, the sidebar showed one unopenable row with
/// Sent, Drafts and Trash indented under it — and collapsed, which is the
/// state it is usually in, the account's default folders were not on screen at
/// all. Labels are unaffected: they are top-level mailboxes already.
///
/// Presentation only. mailBox keeps the real IMAP path, which is what SELECT,
/// the message cache, the special-folder bookkeeping and every rename use.
static void flattenGmailNamespace(QList<FolderModel::Folder> *folders)
{
    // Whether the server listed the container itself is what decides the
    // indent: its presence is what put its children a step in (pathRows()
    // counts only the ancestors that are really mailboxes), and its absence is
    // what leaves the namespace sitting in their display names.
    int container = -1;
    for (int i = 0; i < folders->size(); ++i) {
        if (isGmailNamespace(folders->at(i).mailBox)) {
            container = i;
            break;
        }
    }

    for (int i = folders->size() - 1; i >= 0; --i) {
        if (i == container) {
            folders->removeAt(i);
            continue;
        }
        FolderModel::Folder &f = (*folders)[i];
        const int cut = f.mailBox.indexOf(folderSeparatorOf(f.mailBox));
        if (cut < 0 || !isGmailNamespace(f.mailBox.left(cut)))
            continue;
        if (container >= 0)
            f.level = qMax(0, f.level - 1);
        else if (f.displayName == f.mailBox)
            f.displayName = f.mailBox.mid(cut + 1);
    }
}

QList<FolderModel::Folder> MailClient::foldersFromPaths(const QStringList &paths)
{
    const QList<PathRow> rows = pathRows(paths);
    QList<FolderModel::Folder> folders;
    folders.reserve(paths.size());
    for (int i = 0; i < paths.size(); ++i) {
        FolderModel::Folder f;
        f.mailBox = paths.at(i);
        f.level = rows.at(i).level;
        f.displayName = rows.at(i).name;
        folders.append(f);
    }
    flattenGmailNamespace(&folders);
    return folders;
}

void MailClient::loadCachedFolderModel()
{
    QStringList boxes = m_store.cachedFolders(accountKey());
    if (m_acct.local) {
        const QStringList sorted = sortedLocalFolders(boxes);
        if (sorted != boxes) {
            m_store.storeFolders(accountKey(), sorted); // repair it once, not on every switch
            boxes = sorted;
        }
    }
    const QList<FolderModel::Folder> folders = foldersFromPaths(boxes);
    if (!folders.isEmpty())
        m_folderModel.setFolders(folders);
    // setFolders() cleared nothing, but the pills belong to this account —
    // hand over what the last pass found and ask for a fresh one.
    m_folderModel.setUnreadCounts(m_unreadByAccount.value(accountKey()));
    scheduleUnreadRecount();
}

void MailClient::setSpamRetentionDays(int days)
{
    days = qBound(0, days, 3650);
    if (m_spamRetentionDays == days)
        return;
    m_spamRetentionDays = days;
    appSettings().setValue(QStringLiteral("ui/spamRetentionDays"), days);
    // A shortened window should bite now, not at the next connection.
    m_spamSwept = false;
    Q_EMIT spamRetentionDaysChanged();
    if (connected())
        sweepOldSpam();
}

void MailClient::setSpamSkipTrash(bool skip)
{
    if (m_spamSkipTrash == skip)
        return;
    m_spamSkipTrash = skip;
    appSettings().setValue(QStringLiteral("ui/spamSkipTrash"), skip);
    Q_EMIT spamSkipTrashChanged();
}

bool MailClient::deleteIsPermanent() const
{
    return isTrashFolder() || (m_spamSkipTrash && isJunkFolder(m_selectedFolder));
}

void MailClient::setRefreshMinutes(int minutes)
{
    minutes = qBound(0, minutes, 24 * 60);
    if (m_refreshMinutes == minutes)
        return;
    m_refreshMinutes = minutes;
    appSettings().setValue(QStringLiteral("ui/refreshMinutes"), minutes);
    if (minutes > 0)
        m_pollTimer.start(minutes * 60 * 1000);
    else
        m_pollTimer.stop();
    Q_EMIT refreshMinutesChanged();
}

void MailClient::setDebugLogging(bool on)
{
    m_debugLogging = on;
    appSettings().setValue(QStringLiteral("ui/debugLogging"), on);
    applyLogFilterRules(on);
    Q_EMIT debugLoggingChanged();
}

void MailClient::applyLogFilterRules(bool on)
{
    // Rules, not a boolean check at each call site: disabled categories cost
    // nothing, and QT_LOGGING_RULES in the environment still wins for a
    // developer who wants the trace without touching the setting. Static, and
    // called at the top of main() as well: the PSL cache loads (and logs)
    // during construction, before the settings-driven call here could quiet
    // it.
    //
    // Quiet means quiet — for everyone. mailove's own categories were gated one
    // by one until the console showed it was a losing game: KIMAP warns about
    // sessions mailove itself closes and about keepalive lines no job owns, the
    // viewer's page chats through "js" (its CSP blocks arrive at *error*
    // severity, hence js.critical below), the PSL loader and wipe breadcrumbs
    // debug by default. So logging off blankets every category's debug, info
    // and warning. Critical stays: something exceptional enough to be
    // critical should print even in quiet mode — except "js", where the
    // severity is chosen by the sender's HTML, not by anything being wrong
    // with mailove. Logging on lifts the blanket and turns the trace on.
    QLoggingCategory::setFilterRules(on ? QStringLiteral("mailove.trace.debug=true\n"
                                                         "mailove.psl.debug=true\n"
                                                         "mailove.wipe.debug=true\n"
                                                         "js.debug=true\n"
                                                         "js.info=true\n"
                                                         "js.warning=true\n"
                                                         "js.critical=true")
                                        : QStringLiteral("*.debug=false\n"
                                                         "*.info=false\n"
                                                         "*.warning=false\n"
                                                         "js.critical=false"));
}

void MailClient::setMaxBodyMB(int mb)
{
    mb = qBound(0, mb, 1024);
    if (m_maxBodyMB == mb)
        return;
    const bool raised = mb == 0 || mb > m_maxBodyMB;
    m_maxBodyMB = mb;
    appSettings().setValue(QStringLiteral("ui/maxBodyMB"), mb);
    if (raised) {
        // Messages refused under the old, smaller limit become eligible again.
        const int freed = m_store.unskipBodiesUpTo(qint64(mb) * 1024 * 1024);
        if (freed > 0) {
            invalidateMissingBodies();
            scheduleBackfill(1000);
        }
    }
    Q_EMIT maxBodyMBChanged();
}

void MailClient::setAuthVerification(bool on)
{
    if (m_authVerification == on)
        return;
    m_authVerification = on;
    m_verifier->setAuthVerification(on);
    appSettings().setValue(QStringLiteral("ui/authVerification"), on);

    // Take effect on what is already on screen rather than only on the next
    // message: switching this off is a privacy choice, and leaving a stale
    // verdict visible would misrepresent it as still being checked.
    if (m_reading) {
        m_reading->m_dkimStatus.clear();
        m_reading->m_dkimDetail.clear();
        m_reading->m_arcStatus.clear();
        m_reading->m_arcSealer.clear();
        m_reading->m_arcDetail.clear();
        m_reading->m_dkimTrusted = false;
        m_reading->m_dkimChecking = false;
        m_reading->m_authInfo.clear();
        Q_EMIT m_reading->dkimChanged();
        Q_EMIT m_reading->messageChanged();
        // Re-check the open message when switching back on; the header-derived
        // verdicts in the list heal on the next sync of each folder.
        if (on && m_reading->m_hasMessage)
            startDkimVerification(m_reading);
    }
    Q_EMIT authVerificationChanged();
}

void MailClient::setDateFormat(const QString &format)
{
    if (m_dateFormat == format || format.isEmpty())
        return;
    m_dateFormat = format;
    appSettings().setValue(QStringLiteral("ui/dateFormat"), format);
    m_messageModel.setDateFormat(format);
    Q_EMIT dateFormatChanged();
}

QVariantList MailClient::cachedFolderList(int index)
{
    bool local = false;
    const QString key = m_accounts.storedKeyAt(index, &local);
    if (key.isEmpty())
        return {};

    QVariantList out;
    const QSet<QString> collapsed = FolderModel::savedCollapsed(key);
    const QHash<QString, int> unread = m_unreadByAccount.value(key);
    QStringList boxes = m_store.cachedFolders(key);
    // Same repair as loadCachedFolderModel(), for an archive that is shown in
    // the pane but has not been switched to yet. Read-only here: the account
    // this is rendering is not the one the store is keyed to.
    if (local)
        boxes = sortedLocalFolders(boxes);
    // Rows of the WHOLE list up front: hasChildren must see the next row even
    // when a collapsed ancestor hides it from the output. Built the same way
    // the connected account's tree is — Gmail's namespace flattened included,
    // so an account draws the same whether or not it is the current one.
    const QList<FolderModel::Folder> rows = foldersFromPaths(boxes);

    // Which rows the collapse state hides, and — for the rows that stay — how
    // much unread is folded away underneath them. Same rule as
    // FolderModel::recomputeHiddenUnread(): a folded subfolder must not be
    // able to hide new mail from the parent that stands in for it.
    QList<bool> hidden(rows.size(), false);
    {
        int skip = -1;
        for (int i = 0; i < rows.size(); ++i) {
            const int level = rows.at(i).level;
            if (skip >= 0 && level > skip) {
                hidden[i] = true;
                continue;
            }
            skip = collapsed.contains(rows.at(i).mailBox) ? level : -1;
        }
    }
    QList<int> hiddenUnread(rows.size(), 0);
    for (int i = 0; i < rows.size(); ++i) {
        if (!hidden.at(i))
            continue;
        const int count = unread.value(rows.at(i).mailBox, 0);
        if (count == 0)
            continue;
        for (int j = i - 1, level = rows.at(i).level; j >= 0 && level > 0; --j) {
            if (rows.at(j).level < level) {
                level = rows.at(j).level;
                hiddenUnread[j] += count;
            }
        }
    }

    int skipDeeperThan = -1; // hide rows below a collapsed ancestor
    for (int i = 0; i < rows.size(); ++i) {
        const QString &mailBox = rows.at(i).mailBox;
        const int level = rows.at(i).level;
        if (skipDeeperThan >= 0 && level > skipDeeperThan)
            continue;
        const bool isCollapsed = collapsed.contains(mailBox);
        skipDeeperThan = isCollapsed ? level : -1;
        out.append(QVariantMap{
            {QStringLiteral("name"), rows.at(i).displayName},
            {QStringLiteral("mailBox"), mailBox},
            {QStringLiteral("level"), level},
            {QStringLiteral("hasChildren"),
             i + 1 < rows.size() && rows.at(i + 1).level > level},
            {QStringLiteral("expanded"), !isCollapsed},
            {QStringLiteral("unread"), unread.value(mailBox, 0)},
            {QStringLiteral("hiddenUnread"), hiddenUnread.at(i)},
        });
    }
    return out;
}

void MailClient::toggleCachedCollapsed(int index, const QString &mailBox)
{
    const QString key = m_accounts.storedKeyAt(index);
    if (key.isEmpty())
        return;
    FolderModel::toggleSavedCollapsed(key, mailBox);
    ++m_cachedFolderRevision;
    Q_EMIT cachedFoldersChanged();
}

void MailClient::openFolderInAccount(int index, const QString &mailBox)
{
    qCDebug(logTrace, "openFolderInAccount(%d, %s)  current=%d",
            index, qUtf8Printable(mailBox), currentAccount());
    if (index == currentAccount()) {
        openFolder(mailBox);
        return;
    }
    // The switch itself shows this folder's cache and opens it once the new
    // account's connection has listed its folders.
    switchAccountInternal(index, QString(), mailBox);
}

bool MailClient::hasAccount() const
{
    return m_acct.valid();
}

void MailClient::setSelectedFolder(const QString &folder)
{
    const bool changed = m_selectedFolder != folder;
    m_selectedFolder = folder;
    // The junk answer belongs to the folder being opened, so it is worked out
    // here — once, as the folder loads — rather than every time a menu asks.
    // Set from the new folder outright: a change must never leave the previous
    // folder's answer standing, so anything not known to be junk is not.
    m_selectedIsJunk = !folder.isEmpty() && isJunkFolderKey(folder);
    // A message left behind by a folder change was not read: its pending mark
    // goes with it.
    if (changed && m_markReadTimer)
        m_markReadTimer->stop();
    m_sync->setOpenFolder(folder);
    // The one place the open folder changes, so the one place that can say so.
    // Without this the properties bound to selectedFolderChanged — the "To"
    // column heading, the search scope, viewingDrafts — only refreshed when
    // something else happened to emit it later, which is why they changed a
    // moment after the folder did rather than with it. Emitted only on a real
    // change: the callers that already emit it do so after work this one has
    // no part in, and both firing on the same value is a re-evaluation for
    // nothing.
    if (changed)
        Q_EMIT selectedFolderChanged();
}

void MailClient::setSearchActive(bool active)
{
    m_searchActive = active;
    m_sync->setSearchActive(active);
}

void MailClient::loadAccount()
{
    m_accounts.migrate();
    loadAccountFields();

    // A local archive owns no secret — don't touch the keyring for it.
    if (m_acct.local) {
        m_accounts.markSecretReady();
        return;
    }

    // Pre-wallet builds kept the password base64-encoded in the config file.
    // Moving it into the wallet is what wipes it.
    QString legacy;
    if (m_accounts.takeLegacySecret(&legacy)) {
        m_accounts.setPassword(legacy);
        m_accounts.markSecretReady();
        m_accounts.writeSecretToWallet(m_acct);
        return;
    }
    m_accounts.readSecret(m_acct);
}

/// Reads the active account's config fields (no password) from the store.
void MailClient::loadAccountFields()
{
    m_acct = m_accounts.loadFields();
    // Imported archive mail is never verified: the DNS keys its signatures
    // were made against are long gone.
    m_verifier->setArchiveAccount(m_acct.local);
    // Per-account, and only the account's own LIST may set it. Carrying the
    // previous account's delimiter over meant every path split the wrong way —
    // a '.' server followed by an archive turned "mail.example.com/Inbox" into
    // a leaf of "com/Inbox", and a rename then wrote that to disk.
    m_folderSeparator = {};
}

QString MailClient::oauthWalletKey() const
{
    return AccountStore::oauthWalletKeyFor(m_acct.user, m_acct.host);
}

QStringList MailClient::accountNames() const
{
    return m_accounts.names();
}

QVariantMap MailClient::accountDetails(int index) const
{
    return m_accounts.details(index);
}

void MailClient::saveAccountDetails(int index, const QVariantMap &d)
{
    const AccountStore::SaveResult saved = m_accounts.saveDetails(index, d);

    // Reconnecting is the right answer to a changed server, a new password or
    // a different account — and the wrong one to a changed signature, which
    // used to cost a full teardown and dial (and, on Gmail, a connection out
    // of a small budget) for a settings write that no session depends on.
    // A save while nothing is connected still dials: that is how a failed
    // connection is retried.
    const bool needsSession = !saved.existed || saved.index != currentAccount()
        || !connected() || saved.sessionChanged
        || (saved.authType == 0 && !saved.password.isEmpty());
    if (needsSession) {
        switchAccountInternal(saved.index,
                              saved.authType == 0 ? saved.password : QString());
        return;
    }
    // Same session, new preferences: take the fields the composer reads from
    // the settings just written. Deliberately not loadAccountFields(), which
    // drops the OAuth tokens this still-live session is using.
    m_acct.displayName = saved.displayName;
    m_acct.organization = saved.organization;
    m_acct.signature = saved.signature;
    m_acct.htmlMail = saved.htmlMail;
    Q_EMIT accountChanged();
    Q_EMIT accountsChanged();
}

void MailClient::saveAccountPrefs(int index, const QVariantMap &d)
{
    const QVariantMap account = m_accounts.savePrefs(index, d);
    if (account.isEmpty())
        return; // unknown index, or nothing actually changed

    // The OpenPGP settings are read from QSettings at send time, so they are
    // already live; these four are cached and have to be told.
    if (index == currentAccount()) {
        m_acct.displayName = account.value(QStringLiteral("displayName")).toString();
        m_acct.organization = account.value(QStringLiteral("organization")).toString();
        m_acct.signature = account.value(QStringLiteral("signature")).toString();
        m_acct.htmlMail = account.value(QStringLiteral("htmlMail"), true).toBool();
        Q_EMIT accountChanged();
    }
    Q_EMIT accountsChanged();
}

void MailClient::removeAccount(int index)
{
    const int left = m_accounts.remove(index);
    if (left < 0)
        return;

    if (left == 0) {
        teardownSession();
        m_folderModel.setFolders({});
        m_messageModel.clear();
        m_acct = AccountConfig();
        Q_EMIT accountChanged();
        Q_EMIT accountsChanged();
        return;
    }
    switchAccountInternal(qMin(currentAccount(), left - 1), QString());
}

void MailClient::moveAccount(int from, int to)
{
    if (!m_accounts.move(from, to))
        return;

    // Order is presentation only: nothing keyed on an account (wallet entry,
    // message cache) uses its position, so no session teardown is needed. The
    // stored current-account index does, though — it has to follow the account
    // it pointed at, or a reorder would silently switch accounts.
    int current = m_accounts.currentIndex();
    if (current == from)
        current = to;
    else if (from < current && current <= to)
        --current;
    else if (to <= current && current < from)
        ++current;
    m_accounts.setCurrentIndex(current);
    Q_EMIT accountsChanged();
}

// --- Thunderbird import ---------------------------------------------------

// The body-text extractor lives with the viewer code below; the importer
// reuses it so imported mail is searchable exactly like fetched mail.
static QString indexTextFor(KMime::Message *msg);

/// One mbox file found under the import root, and the mailbox it becomes.
struct MboxSource {
    QString filePath;
    QString mailBox;
};

/// True for a file that holds Thunderbird mbox mail. The ".msf" index next to
/// it is the strong signal; without one, accept a file that begins like an
/// mbox. Everything else Thunderbird keeps next to its mail — indexes, filter
/// rules, junk training data — is ruled out by suffix first.
static bool looksLikeMbox(const QFileInfo &info)
{
    static const QStringList kNoise = {
        QStringLiteral("msf"),    QStringLiteral("dat"),  QStringLiteral("html"),
        QStringLiteral("sqlite"), QStringLiteral("json")};
    if (!info.isFile() || kNoise.contains(info.suffix().toLower()))
        return false;
    if (QFileInfo::exists(info.filePath() + QLatin1String(".msf")))
        return true;
    QFile f(info.filePath());
    return f.open(QIODevice::ReadOnly) && f.read(5) == "From ";
}

/// Collects every mbox under \a dir, depth first. Thunderbird materialises
/// the folder hierarchy as "<name>" (the mail) plus "<name>.sbd/" (the
/// children), so stripping ".sbd" recovers the mailbox path.
static void collectMboxFiles(const QDir &dir, const QString &prefix, QList<MboxSource> *out)
{
    const auto entries =
        dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    for (const QFileInfo &info : entries) {
        if (info.isDir()) {
            QString name = info.fileName();
            if (name.endsWith(QLatin1String(".sbd")))
                name.chop(4);
            if (name.isEmpty())
                continue;
            collectMboxFiles(QDir(info.filePath()),
                             prefix.isEmpty() ? name : prefix + QLatin1Char('/') + name, out);
        } else if (looksLikeMbox(info)) {
            out->append({info.filePath(), prefix.isEmpty()
                                              ? info.fileName()
                                              : prefix + QLatin1Char('/') + info.fileName()});
        }
    }
}

/// Depth-first order with parents directly above their children — the sidebar
/// derives the tree from row order, so "Inbox" must sit immediately before
/// "Inbox/Work". Imported paths are always built with '/'.
static void sortMailboxTree(QList<MboxSource> *sources)
{
    std::sort(sources->begin(), sources->end(), [](const MboxSource &a, const MboxSource &b) {
        return mailBoxPathLess(a.mailBox, b.mailBox, QLatin1Char('/'));
    });
}

/// True for a real mbox From_ separator. Starting with "From " is not enough:
/// Thunderbird does not always quote body paragraphs that begin with "From ",
/// so the line must also end the way every writer's From_ line does — in a
/// ctime-style timestamp ("Thu Jan 01 10:00:00 2015", sender optional).
static bool isMboxSeparator(const QByteArray &line)
{
    if (!line.startsWith("From "))
        return false;
    static const QRegularExpression kFromLine(QStringLiteral(
        "^From (?:\\S+ )?\\w{3} \\w{3} [ \\d]?\\d \\d{1,2}:\\d\\d(?::\\d\\d)? \\d{4}"));
    return kFromLine.match(QString::fromLatin1(line)).hasMatch();
}

/// Streams \a path message by message: the classic mbox rule, a From_ line
/// right after a blank line (or at file start) begins a new message.
/// Returns false when the callback asked to stop.
static bool forEachMboxMessage(const QString &path, const std::function<bool(QByteArray &&)> &fn)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return true; // unreadable: nothing to deliver, but not a stop
    QByteArray current;
    bool prevBlank = true;
    while (!f.atEnd()) {
        const QByteArray line = f.readLine();
        if (prevBlank && isMboxSeparator(line)) {
            if (!current.isEmpty() && !fn(std::move(current)))
                return false;
            current = QByteArray(); // the separator line is not part of the message
        } else {
            current += line;
        }
        prevBlank = line == "\n" || line == "\r\n";
    }
    if (!current.isEmpty() && !fn(std::move(current)))
        return false;
    return true;
}

void MailClient::importThunderbird(const QUrl &dir)
{
    if (m_importThread) {
        Q_EMIT errorOccurred(tr("An import is already running."));
        return;
    }
    const QString path = dir.isLocalFile() ? dir.toLocalFile() : dir.toString();
    if (!QFileInfo(path).isDir()) {
        Q_EMIT importFinished(false, tr("Not a folder: %1").arg(path));
        return;
    }

    // The account appears in the pane right away, named after the profile
    // folder; its folder list fills in when the worker finishes. It is an
    // ordinary account in every visible way — the "local" flag that keeps it
    // from ever connecting stays out of sight.
    QString name = QDir(path).dirName();
    if (name.endsWith(QLatin1String(".sbd")))
        name.chop(4);
    if (name.isEmpty())
        name = tr("Imported mail");
    const QList<QVariantMap> accounts = m_accounts.all();
    // A second import of the same profile gets its own account and its own
    // storage key — never silently merged into the first one's cache.
    QStringList takenNames, takenKeys;
    for (const QVariantMap &a : std::as_const(accounts)) {
        takenNames << a.value(QStringLiteral("user")).toString();
        takenKeys << a.value(QStringLiteral("cacheKey")).toString();
    }
    QString unique = name;
    for (int n = 2; takenNames.contains(unique)
                    || takenKeys.contains(QStringLiteral("import:") + unique);
         ++n)
        unique = name + QStringLiteral(" (%1)").arg(n);
    const QString storeKey = QStringLiteral("import:") + unique;

    QVariantMap account;
    account.insert(QStringLiteral("user"), unique);
    account.insert(QStringLiteral("local"), true);
    account.insert(QStringLiteral("cacheKey"), storeKey);
    m_accounts.append(account);
    Q_EMIT accountsChanged();

    setStatus(tr("Importing %1").arg(unique));
    const bool fts = m_store.ftsAvailable();
    m_importStop.storeRelaxed(0);
    m_importThread = QThread::create([this, path, storeKey, unique, fts] {
        QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("mailstore-import"));
        QList<MboxSource> sources;
        if (db.isOpen()) {
            collectMboxFiles(QDir(path), QString(), &sources);
            sortMailboxTree(&sources);
        }
        QStringList folders;
        qint64 total = 0;
        bool stopped = false;
        for (const MboxSource &src : std::as_const(sources)) {
            if (m_importStop.loadRelaxed()) {
                stopped = true;
                break;
            }
            folders.append(src.mailBox);
            const QString scoped = storeKey + QChar(0x1f) + src.mailBox;
            // For the rare message without a Date header: the mbox's own
            // timestamp beats 1970 (and keeps the row out of ghost territory).
            const QDateTime fallbackDate = QFileInfo(src.filePath).lastModified();
            qint64 uid = 0;
            // An archive's Sent mailbox is mail that was sent, so its To/Cc
            // belong in the compose autocompletion exactly as a synced Sent
            // folder's do — recorded per message here, at import time, rather
            // than by a sweep over the folder afterwards.
            static const QStringList sentNames = {
                QStringLiteral("sent"), QStringLiteral("sent messages"),
                QStringLiteral("sent items"), QStringLiteral("sent mail")};
            const bool isSent =
                sentNames.contains(src.mailBox.section(QChar(u'/'), -1).toLower());
            QList<MessageListModel::Header> headers;
            QList<MailStore::BodyWrite> bodies;
            QList<MailStore::SentRecipient> recipients;
            auto flush = [&] {
                MailStore::storeHeadersOn(db, scoped, headers, fts);
                MailStore::writeBodiesOn(db, bodies);
                MailStore::addSentRecipientsOn(db, storeKey, scoped, recipients);
                headers.clear();
                bodies.clear();
                recipients.clear();
            };
            const bool completed = forEachMboxMessage(src.filePath, [&](QByteArray &&raw) {
                if (m_importStop.loadRelaxed())
                    return false;
                KMime::Message msg;
                msg.setContent(KMime::CRLFtoLF(raw));
                msg.parse();
                // Thunderbird's own flags travel inside the message: bit 0x1
                // is read, 0x8 is "deleted, not compacted yet" — not mail.
                const auto *status = msg.headerByType("X-Mozilla-Status");
                const uint flags =
                    status ? status->asUnicodeString().trimmed().toUInt(nullptr, 16) : 0;
                if (flags & 0x0008)
                    return true;
                MessageListModel::Header h;
                h.uid = ++uid;
                if (const auto *subject = std::as_const(msg).subject())
                    h.subject = subject->asUnicodeString();
                if (const auto *from = std::as_const(msg).from())
                    h.from = from->asUnicodeString();
                if (const auto *date = std::as_const(msg).date())
                    h.date = date->dateTime();
                if (!h.date.isValid())
                    h.date = fallbackDate;
                if (const auto *mid = std::as_const(msg).messageID(); mid && !mid->isEmpty())
                    h.msgid = QString::fromLatin1(mid->identifier());
                // Without Thunderbird flags everything counts as read — an
                // archive must not arrive as ten years of unread badges.
                h.seen = status ? (flags & 0x0001) : true;
                h.attachKind = MailStore::headIndicatesAttachment(msg.head())
                    ? MessageListModel::GenericAttachment
                    : MessageListModel::NoAttachment;
                h.crypto = PgpMime::storedKind(PgpMime::kindFromHead(msg.head()));
                // Deliberately no authInfo and no suspicious flag: imported
                // mail is never validated (SPF/DKIM verdicts from another
                // client's era would only produce noise).
                MailStore::BodyWrite w;
                w.scopedFolder = scoped;
                w.uid = h.uid;
                w.indexText = indexTextFor(&msg);
                w.parts = MimeUtils::stripAttachments(&msg);
                if (!w.parts.isEmpty()) {
                    msg.assemble();
                    w.raw = msg.encodedContent();
                } else {
                    w.raw = raw;
                }
                if (isSent) {
                    // Read before the parts are stripped above? No need: To/Cc
                    // are headers, and stripping only touches the body.
                    const auto note = [&](const auto *header) {
                        if (!header)
                            return;
                        const auto mailboxes = header->mailboxes();
                        for (const auto &mb : mailboxes) {
                            recipients.append({h.uid, QString::fromLatin1(mb.address()),
                                               mb.hasName() ? mb.name() : QString()});
                        }
                    };
                    note(std::as_const(msg).to());
                    note(std::as_const(msg).cc());
                }
                headers.append(h);
                bodies.append(std::move(w));
                ++total;
                if (headers.size() >= 50) {
                    flush();
                    QMetaObject::invokeMethod(
                        this,
                        [this, unique, total] {
                            setStatus(tr("Importing %1 — %2 messages").arg(unique).arg(total));
                        },
                        Qt::QueuedConnection);
                }
                return true;
            });
            flush();
            if (!completed) {
                stopped = true;
                break;
            }
        }
        if (db.isOpen())
            db.close();
        QSqlDatabase::removeDatabase(QStringLiteral("mailstore-import"));

        QMetaObject::invokeMethod(
            this,
            [this, storeKey, folders, total, unique, stopped] {
                if (folders.isEmpty()) {
                    // Nothing found: take the just-created account back out
                    // rather than leaving an empty shell in the pane.
                    m_accounts.removeByCacheKey(storeKey);
                    Q_EMIT accountsChanged();
                    setStatus({});
                    Q_EMIT importFinished(false, tr("No Thunderbird mail found in that folder."));
                    return;
                }
                m_store.storeFolders(storeKey, folders);
                ++m_cachedFolderRevision;
                Q_EMIT cachedFoldersChanged();
                Q_EMIT accountsChanged();
                // On a fresh install the pane is already "on" the imported
                // slot (currentAccount 0), but nothing ever loaded it — switch
                // for real so the archive appears without a restart.
                {
                    const int slot = m_accounts.indexOfCacheKey(storeKey);
                    if (slot >= 0 && slot == currentAccount())
                        switchAccountInternal(slot, QString(), folders.first());
                }
                if (stopped) {
                    setStatus(tr("Import interrupted"));
                    Q_EMIT importFinished(false,
                                          tr("Import of %1 was interrupted — what was already "
                                             "imported is browsable.")
                                              .arg(unique));
                    return;
                }
                setStatus(tr("Imported %1 — %2 in %3")
                              .arg(unique)
                              .arg(countNoun(total, "message", "messages"))
                              .arg(countNoun(folders.size(), "folder", "folders")));
                Q_EMIT importFinished(true,
                                      tr("Imported %1: %2 in %3.")
                                          .arg(unique)
                                          .arg(countNoun(total, "message", "messages"))
                                          .arg(countNoun(folders.size(), "folder", "folders")));
            },
            Qt::QueuedConnection);
    });
    connect(m_importThread, &QThread::finished, this, [this] {
        m_importThread->deleteLater();
        m_importThread = nullptr;
    });
    // Priority goes to start(); setPriority() before it only warns.
    m_importThread->start(QThread::LowPriority);
}

void MailClient::switchAccount(int index)
{
    switchAccountInternal(index, QString());
}

void MailClient::switchAccountInternal(int index, const QString &sessionPassword,
                                       const QString &targetFolder)
{
    qCDebug(logTrace, "switchAccountInternal(%d)  pendingWas=%s",
            index, qUtf8Printable(m_pendingFolder));
    m_accounts.setCurrentIndex(index);

    // Set the destination before anything is torn down, so no observer ever
    // sees a blank selection: the sidebar highlight binds to it, and a moment
    // of "" made it fall back to row 0 — INBOX — mid-switch.
    setSelectedFolder(targetFolder.isEmpty() ? QStringLiteral("INBOX") : targetFolder);
    m_pendingFolder = targetFolder;
    Q_EMIT selectedFolderChanged();

    // Special-use folders belong to the account that advertised them. They are
    // re-detected by the next listFolders(), but until then a stale path would
    // point "Save as draft" (or the Sent copy) at the previous account's
    // mailbox — which the new connection may not even have.
    m_sentFolder.clear();
    m_draftsFolder.clear();
    m_allMailFolder.clear();
    Q_EMIT draftsFolderChanged();

    teardownSession();
    m_folderModel.setFolders({});
    m_messageModel.clear();
    // And the reading pane with it — the same reason openFolder() does it, and
    // a stronger one: what is in the pane belongs to the account being left.
    // The list below auto-selects the switched-to account's top row, but its
    // body is often not cached and the session was just torn down, so the fetch
    // that follows bails out without presenting anything — leaving the previous
    // account's mail on screen under this account's selected row.
    m_reading->clear();
    setSearchActive(false);
    m_sync->resetFolderCursor();
    // Queued \Seen stores name messages of the account being left, and the
    // connection they were waiting for is the one just torn down.
    m_pendingSeen.clear();

    loadAccountFields();
    m_folderModel.setAccountKey(accountKey());
    m_store.setAccountKey(accountKey());
    // The switched-to account's sidebar and the target folder come straight
    // from cache; the network refresh merges into them once connected.
    loadCachedFolderModel();
    // Cached contents of the folder being opened — not INBOX's, which is what
    // made the message list show INBOX until the server's folder list arrived.
    const auto cached = m_store.cachedHeaders(m_selectedFolder);
    updatePageAnchor(cached);
    m_messageModel.setHeaders(cached);
    if (m_acct.local) {
        // A local archive has no server and no secret — don't touch the
        // keyring, and never try to connect. The cache shown above is all
        // there is, and that is the point.
        m_accounts.setSessionSecret(QString());
    } else if (!sessionPassword.isEmpty()) {
        m_accounts.setSessionSecret(sessionPassword);
    } else {
        m_accounts.readSecret(m_acct);
    }

    Q_EMIT accountChanged();
    Q_EMIT accountsChanged();

    if (m_acct.local) {
        setStatus(tr("%1 — %2 messages")
                      .arg(m_selectedFolder)
                      .arg(m_store.cachedHeaderCount(m_selectedFolder)));
        return;
    }
    if (!hasAccount())
        return;
    if (m_accounts.secretReady())
        connectAccount();
    else
        m_connectWhenReady = true;
}

/// The MIME construction shared by sendMail() and saveDraft(). \a strict is
/// what separates them: sending refuses a malformed recipient, while a draft
/// is saved from whatever is on screen — including an address halfway through
/// being typed — so it keeps the text as-is rather than throwing the draft away.
std::shared_ptr<KMime::Message> MailClient::composeMessage(
    const QString &to, const QString &cc, const QString &bcc, const QString &subject,
    const QString &html, const QList<QUrl> &attachments, bool strict,
    QStringList *toOut, QStringList *ccOut, QStringList *bccOut)
{
    // Defense against header/SMTP-command injection: no CR/LF survives into a
    // header. Everything past that is KMime's RFC 5322 address parser rather
    // than a pattern of our own — it splits the list on the commas that
    // actually separate addresses, keeps "Display Name <addr>" together
    // (including a comma inside a quoted display name), and rejects what is
    // not an address at all. \a hdr is filled with what was typed, display
    // names and their encoding included; the returned bare addresses are what
    // the SMTP envelope and the PGP key lookup want, since neither has any use
    // for a display name.
    static const QRegularExpression crlfRe(QStringLiteral("[\\r\\n]"));
    auto msg = std::make_shared<KMime::Message>();
    auto parseAddresses = [this, strict, &msg](QString raw,
                                               KMime::Headers::Generics::AddressList *hdr,
                                               const char *headerName, bool *ok) -> QStringList {
        raw.remove(crlfRe);
        raw = raw.trimmed();
        *ok = true;
        QStringList out;
        if (raw.isEmpty())
            return out;
        // Two steps because they answer two questions. parseAddressList says
        // whether the whole list is well-formed — it returns false on a
        // half-typed "john" where the header parse would just quietly drop it,
        // which is the difference between refusing to send and sending to
        // fewer people than the user typed.
        const QByteArray bytes = raw.toUtf8();
        const char *cursor = bytes.constData();
        QList<KMime::Types::Address> parsed;
        if (!KMime::HeaderParsing::parseAddressList(cursor, cursor + bytes.size(), parsed)) {
            if (strict) {
                Q_EMIT sendFailed(tr("Invalid recipient address: %1").arg(raw));
                *ok = false;
                return {};
            }
            // A draft is saved from whatever is on screen, an address halfway
            // through being typed included. An address header will not hold
            // text that is not an address, so the draft keeps it as an
            // unstructured one — losing what the user typed is the one thing a
            // draft must not do.
            auto literal = std::make_unique<KMime::Headers::Generic>(headerName);
            literal->fromUnicodeString(raw);
            msg->setHeader(std::move(literal));
            return out;
        }
        // The header parse is the one that gets used, because unlike the raw
        // byte parse above it knows the text is UTF-8 and encodes a non-ASCII
        // display name accordingly instead of mangling it into latin1.
        hdr->fromUnicodeString(raw);
        for (const KMime::Types::Mailbox &mb : hdr->mailboxes()) {
            if (mb.hasAddress())
                out.append(QString::fromUtf8(mb.address()));
        }
        return out;
    };

    bool ok = false;
    const QStringList toList = parseAddresses(to, msg->to(), "To", &ok);
    if (!ok)
        return {};
    const QStringList ccList = parseAddresses(cc, msg->cc(), "Cc", &ok);
    if (!ok)
        return {};
    // Bcc never rides along on a message being sent — hiding those recipients
    // is the whole point, and the envelope is what carries them. A draft is
    // the opposite case: it is not being delivered, and a Bcc left out of the
    // header would be gone when the draft is reopened.
    KMime::Headers::Bcc envelopeOnlyBcc;
    const QStringList bccList = parseAddresses(
        bcc, strict ? &envelopeOnlyBcc : msg->bcc(), "Bcc", &ok);
    if (!ok)
        return {};
    if (toOut)
        *toOut = toList;
    if (ccOut)
        *ccOut = ccList;
    if (bccOut)
        *bccOut = bccList;
    QString cleanSubject = subject;
    cleanSubject.remove(crlfRe);

    // --- Build the MIME message ---
    const QString fromAddr = ownAddress();

    // Built as a Mailbox rather than a "Name <addr>" string so KMime does the
    // quoting and RFC 2047 encoding — a display name may hold a comma, a
    // quote, or non-ASCII, none of which survive naive concatenation.
    KMime::Types::Mailbox fromMailbox;
    fromMailbox.setAddress(fromAddr.toUtf8());
    if (!m_acct.displayName.isEmpty())
        fromMailbox.setName(m_acct.displayName);
    msg->from()->addAddress(fromMailbox);
    // Organization is optional, and an empty one is not a header worth
    // sending — recipients would see a blank field rather than nothing.
    if (!m_acct.organization.isEmpty()) {
        auto org = std::make_unique<KMime::Headers::Generic>("Organization");
        org->fromUnicodeString(m_acct.organization);
        msg->setHeader(std::move(org));
    }
    msg->subject()->fromUnicodeString(cleanSubject);
    msg->date()->setDateTime(QDateTime::currentDateTime());
    // The SMTP host when there is one, the sender's own domain otherwise: a
    // JMAP account has no SMTP host, and an empty domain here would generate a
    // Message-ID that no receiver can attribute to anything.
    const QString idDomain = !m_acct.smtpHost.isEmpty()
        ? m_acct.smtpHost
        : fromAddr.section(QLatin1Char('@'), 1);
    msg->messageID()->generate(idDomain.toUtf8());
    msg->userAgent()->fromUnicodeString(
        QStringLiteral("mailove/" MAILOVE_VERSION " (https://github.com/nekromoff/mailove)"));

    // Images pasted into the body are local files while the composer is open —
    // that is the only kind of reference a QTextDocument renders. They travel
    // as parts of their own, referenced by cid:, so this happens before the
    // body parts are built: the HTML that goes into the message is the
    // rewritten one.
    QString bodyHtml = html;
    const QList<MimeUtils::InlineImage> inlineImages =
        MimeUtils::takeInlineImages(bodyHtml, fromAddr.section(QLatin1Char('@'), 1));
    struct ImagePart {
        QByteArray data;
        QByteArray mimeType;
        QString name;
        QByteArray cid;
    };
    QList<ImagePart> imageParts;
    {
        QMimeDatabase mimeDb;
        for (const MimeUtils::InlineImage &image : inlineImages) {
            QFile file(image.path);
            if (!file.open(QIODevice::ReadOnly)) {
                // Only reachable if the scratch file went out from under the
                // composer; sending the message without it would deliver a
                // broken-image icon and no way to tell what was lost.
                Q_EMIT sendFailed(tr("Could not read the pasted image %1.").arg(image.path));
                return {};
            }
            imageParts.append({file.readAll(),
                               mimeDb.mimeTypeForFile(image.path).name().toUtf8(),
                               QFileInfo(file).fileName(), image.contentId});
        }
    }

    // Link targets kept — a recipient reading the text alternative must not
    // lose where "click here" pointed; toPlainText() would drop every href.
    QString plain = MimeUtils::plainTextWithLinks(bodyHtml);
    // The object-replacement characters are where the images sat: a stand-in
    // the layout needs and the plain-text alternative has no use for.
    plain.remove(QChar::ObjectReplacementCharacter);
    // What a recipient's text-mode client shows — same blank-line cap as
    // every text rendering of ours.
    plain = MimeUtils::condenseBlankLines(plain);

    auto makeTextPart = [&plain]() {
        auto part = std::make_unique<KMime::Content>();
        part->contentType()->setMimeType("text/plain");
        part->contentType()->setCharset("utf-8");
        part->contentTransferEncoding()->setEncoding(KMime::Headers::CEquPr);
        part->fromUnicodeString(plain);
        return part;
    };
    auto makeHtmlPart = [&bodyHtml]() {
        auto part = std::make_unique<KMime::Content>();
        part->contentType()->setMimeType("text/html");
        part->contentType()->setCharset("utf-8");
        part->contentTransferEncoding()->setEncoding(KMime::Headers::CEquPr);
        part->fromUnicodeString(bodyHtml);
        return part;
    };
    // \a referenced tells the two jobs an image part can have apart: one the
    // body points at by cid: (inline, shown where it was pasted), and one that
    // is simply along for the ride because a plain-text message cannot point
    // at anything.
    auto makeImagePart = [](const ImagePart &image, bool referenced) {
        auto part = std::make_unique<KMime::Content>();
        part->contentType()->setMimeType(image.mimeType);
        part->contentType()->setName(image.name);
        if (referenced) {
            part->contentID()->setIdentifier(image.cid);
            part->contentDisposition()->setDisposition(KMime::Headers::CDinline);
        } else {
            part->contentDisposition()->setDisposition(KMime::Headers::CDattachment);
        }
        part->contentDisposition()->setFilename(image.name);
        part->contentTransferEncoding()->setEncoding(KMime::Headers::CEbase64);
        part->setBody(image.data);
        return part;
    };
    // Both fill a node rather than returning one, because the same structure
    // is built at the top level and one level down, and only the caller knows
    // which. text + html: receiving clients pick their format.
    auto fillAlternative = [&](KMime::Content *into) {
        into->contentType()->setMimeType("multipart/alternative");
        into->contentType()->setBoundary(KMime::multiPartBoundary());
        into->appendContent(makeTextPart());
        into->appendContent(makeHtmlPart());
    };
    // multipart/related is what makes a cid: reference resolvable: the body and
    // the images it points at, in one part that says they belong together.
    auto fillRelated = [&](KMime::Content *into) {
        into->contentType()->setMimeType("multipart/related");
        into->contentType()->setBoundary(KMime::multiPartBoundary());
        // RFC 2387: which of the parts inside is the document. Without it a
        // client has to guess, and some guess the first image.
        into->contentType()->setParameter("type", QStringLiteral("multipart/alternative"));
        auto alternative = std::make_unique<KMime::Content>();
        fillAlternative(alternative.get());
        into->appendContent(std::move(alternative));
        for (const ImagePart &image : imageParts)
            into->appendContent(makeImagePart(image, true));
    };

    // Only an HTML body can reference an image; a plain-text account sends
    // what was pasted as attachments instead — which is also why such a
    // message has something to mix in even with nothing formally attached.
    const bool related = m_acct.htmlMail && !imageParts.isEmpty();
    const bool imagesAsAttachments = !m_acct.htmlMail && !imageParts.isEmpty();

    // The outer type says what the message actually is. A multipart/mixed
    // wrapper around nothing but the body is what makes mail clients (this one
    // included — see MailStore::headIndicatesAttachment) show a paperclip on a
    // message that carries no attachment, so it is only built when there is
    // something to mix in.
    const bool mixed = !attachments.isEmpty() || imagesAsAttachments;
    if (mixed) {
        msg->contentType()->setMimeType("multipart/mixed");
        msg->contentType()->setBoundary(KMime::multiPartBoundary());
        if (related) {
            auto body = std::make_unique<KMime::Content>();
            fillRelated(body.get());
            msg->appendContent(std::move(body));
        } else if (m_acct.htmlMail) {
            auto alternative = std::make_unique<KMime::Content>();
            fillAlternative(alternative.get());
            msg->appendContent(std::move(alternative));
        } else {
            msg->appendContent(makeTextPart());
            for (const ImagePart &image : imageParts)
                msg->appendContent(makeImagePart(image, false));
        }
    } else if (related) {
        // Nothing attached: the body and its images are the whole message, so
        // they sit at the top level instead of inside a wrapper.
        fillRelated(msg.get());
    } else if (m_acct.htmlMail) {
        fillAlternative(msg.get());
    } else {
        // Plain-text-only account, nothing attached: a plain text/plain
        // message, no multipart machinery at all.
        msg->contentType()->setMimeType("text/plain");
        msg->contentType()->setCharset("utf-8");
        msg->contentTransferEncoding()->setEncoding(KMime::Headers::CEquPr);
        msg->fromUnicodeString(plain);
    }

    {
        QMimeDatabase mimeDb;
        for (const QUrl &url : attachments) {
            QFile file(url.toLocalFile());
            if (!file.open(QIODevice::ReadOnly)) {
                Q_EMIT sendFailed(tr("Could not read attachment %1.").arg(url.toLocalFile()));
                return {};
            }
            const QString name = QFileInfo(file).fileName();
            auto part = std::make_unique<KMime::Content>();
            part->contentType()->setMimeType(
                mimeDb.mimeTypeForFile(url.toLocalFile()).name().toUtf8());
            part->contentType()->setName(name);
            part->contentDisposition()->setDisposition(KMime::Headers::CDattachment);
            part->contentDisposition()->setFilename(name);
            part->contentTransferEncoding()->setEncoding(KMime::Headers::CEbase64);
            part->setBody(file.readAll());
            msg->appendContent(std::move(part));
        }
    }
    msg->assemble();

    return msg;
}

QString MailClient::accountPgpKey() const
{
    QSettings s = appSettings();
    QString fp;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (currentAccount() >= 0 && currentAccount() < count) {
        s.setArrayIndex(currentAccount());
        fp = s.value(QStringLiteral("pgpKeyFp")).toString();
    }
    s.endArray();
    return fp;
}

/// One of the active account's boolean OpenPGP settings. Read from QSettings
/// rather than cached: they change in the settings page, which rewrites the
/// array wholesale, and a stale copy here would sign mail the user just told
/// mailove not to sign.
static bool accountPgpFlag(int index, const char *key, bool fallback)
{
    QSettings s = appSettings();
    bool value = fallback;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (index >= 0 && index < count) {
        s.setArrayIndex(index);
        value = s.value(QString::fromLatin1(key), fallback).toBool();
    }
    s.endArray();
    return value;
}

bool MailClient::accountPgpSignByDefault() const
{
    return accountPgpFlag(currentAccount(), "pgpSignByDefault", false);
}

bool MailClient::accountPgpEncryptByDefault() const
{
    return accountPgpFlag(currentAccount(), "pgpEncryptByDefault", false);
}

bool MailClient::accountPgpAutoWkd() const
{
    return accountPgpFlag(currentAccount(), "pgpAutoWkd", true);
}

void MailClient::applyOutgoingCrypto(const std::shared_ptr<KMime::Message> &msg,
                                     const QStringList &recipients, bool sign, bool encrypt,
                                     std::function<void(const QByteArray &)> done)
{
    const QByteArray plain = msg->encodedContent(KMime::NewlineType::CRLF);
    if (!sign && !encrypt) {
        done(plain);
        return;
    }
    if (!m_pgp || !m_pgp->available()) {
        Q_EMIT sendFailed(m_pgp ? m_pgp->unavailableReason()
                                : tr("OpenPGP support is not available."));
        return;
    }
    const QString ownKey = accountPgpKey();
    if (ownKey.isEmpty()) {
        Q_EMIT sendFailed(tr("This account has no OpenPGP key. Choose one in "
                             "Settings before signing or encrypting."));
        return;
    }

    // Every recipient must have a key, and so must the sender — leaving the
    // sender out is how a Sent copy becomes unreadable to the person who sent
    // it (doc/openpgp.md §6).
    QStringList encryptTo;
    if (encrypt) {
        QStringList missing;
        const QVariantMap keys = m_pgp->encryptionKeysFor(recipients);
        for (auto it = keys.cbegin(); it != keys.cend(); ++it) {
            const QString fp = it.value().toString();
            if (fp.isEmpty())
                missing.append(it.key());
            else if (!encryptTo.contains(fp))
                encryptTo.append(fp);
        }
        if (!missing.isEmpty()) {
            // Never a silent downgrade: the compose window is expected to have
            // asked already, so reaching here means something changed under it.
            Q_EMIT sendFailed(tr("No OpenPGP key for %1. The message was not "
                                 "sent — encrypting to the others would leave "
                                 "them out, and sending in the clear is not "
                                 "something Mailove will do on its own.")
                                  .arg(missing.join(QStringLiteral(", "))));
            return;
        }
        if (!encryptTo.contains(ownKey))
            encryptTo.append(ownKey);
    }

    const PgpMime::OutgoingParts parts = PgpMime::splitForCrypto(plain);
    if (!parts.valid) {
        Q_EMIT sendFailed(tr("The message could not be prepared for encryption."));
        return;
    }

    // Encryption of an already-built body, shared by "encrypt only" and the
    // second half of "sign, then encrypt".
    auto encryptStep = [this, done, encryptTo](const PgpMime::OutgoingParts &p) {
        const quint64 job = m_pgp->encryptTo(p.contentPart, encryptTo);
        if (!job) {
            Q_EMIT sendFailed(tr("The message could not be encrypted."));
            return;
        }
        auto *conn = new QMetaObject::Connection;
        *conn = connect(m_pgp, &PgpEngine::encryptFinished, this,
                        [this, conn, job, p, done](quint64 id, const QByteArray &cipher,
                                                   const QString &error) {
                            if (id != job)
                                return;
                            disconnect(*conn);
                            delete conn;
                            if (!error.isEmpty() || cipher.isEmpty()) {
                                Q_EMIT sendFailed(
                                    error.isEmpty() ? tr("The message could not be "
                                                         "encrypted.")
                                                    : error);
                                return;
                            }
                            done(PgpMime::buildEncrypted(p, cipher));
                        });
    };

    if (!sign) {
        encryptStep(parts);
        return;
    }

    // Sign first, encrypt the resulting multipart/signed — the order RFC 3156
    // specifies, and the one that keeps the signature hidden from anyone who
    // cannot decrypt the message.
    const quint64 job = m_pgp->signDetached(parts.contentPart, ownKey);
    if (!job) {
        Q_EMIT sendFailed(tr("The message could not be signed."));
        return;
    }
    auto *conn = new QMetaObject::Connection;
    *conn = connect(m_pgp, &PgpEngine::signFinished, this,
                    [this, conn, job, parts, encrypt, encryptStep, done](
                        quint64 id, const QByteArray &signature, const QString &micalg,
                        const QString &error) {
                        if (id != job)
                            return;
                        disconnect(*conn);
                        delete conn;
                        if (!error.isEmpty() || signature.isEmpty()) {
                            Q_EMIT sendFailed(error.isEmpty()
                                                  ? tr("The message could not be signed.")
                                                  : error);
                            return;
                        }
                        const QByteArray signedMsg =
                            PgpMime::buildSigned(parts, signature, micalg);
                        if (signedMsg.isEmpty()) {
                            Q_EMIT sendFailed(tr("The signed message could not be built."));
                            return;
                        }
                        if (!encrypt) {
                            done(signedMsg);
                            return;
                        }
                        const PgpMime::OutgoingParts signedParts =
                            PgpMime::splitForCrypto(signedMsg);
                        if (!signedParts.valid) {
                            Q_EMIT sendFailed(tr("The message could not be prepared "
                                                 "for encryption."));
                            return;
                        }
                        encryptStep(signedParts);
                    });
}

/// Splices a deferred quote into the outgoing HTML, just before </body> so
/// it lands inside the document like the inline path would have put it. The
/// remote strip deferred at open time runs here — one parse at the send or
/// save click instead of a freeze at the open.
static QString appendQuoteHtml(QString html, QString quote, bool strip)
{
    if (quote.isEmpty())
        return html;
    QElapsedTimer timer;
    timer.start();
    if (strip)
        quote = DocumentHandler::stripRemoteContent(quote);
    const QString block =
        QStringLiteral("<blockquote>") + quote + QStringLiteral("</blockquote>");
    const qsizetype at = html.lastIndexOf(QLatin1String("</body>"), -1, Qt::CaseInsensitive);
    if (at >= 0)
        html.insert(at, block);
    else
        html += block;
    qCDebug(logTrace, "appendQuoteHtml: %lldms, strip=%d, quote=%lld chars",
            timer.elapsed(), int(strip), static_cast<qint64>(quote.size()));
    return html;
}

void MailClient::sendMail(const QString &to, const QString &cc, const QString &bcc,
                          const QString &subject, const QString &html,
                          const QList<QUrl> &attachments, bool sign, bool encrypt,
                          const QString &appendQuote, bool appendStrip)
{
    const bool haveCredential = m_acct.authType != 0
        ? !m_accounts.accessToken().isEmpty()
        : !m_accounts.password().isEmpty();
    if (m_acct.user.isEmpty() || !haveCredential) {
        Q_EMIT sendFailed(tr("The account is not configured (check account settings)."));
        return;
    }
    // An SMTP host is what IMAP needs to send and JMAP has no use for at all —
    // it submits over its own API. Gating both on it would leave a correctly
    // configured JMAP account unable to send, so the check follows the protocol
    // rather than the settings page.
    if (!m_backend || (m_backend->protocol() == MailBackend::Protocol::Imap
                       && m_acct.smtpHost.isEmpty())) {
        Q_EMIT sendFailed(tr("SMTP is not configured (check account settings)."));
        return;
    }
    QStringList toList, ccList, bccList;
    auto msg = composeMessage(to, cc, bcc, subject,
                              appendQuoteHtml(html, appendQuote, appendStrip),
                              attachments, true, &toList, &ccList, &bccList);
    if (!msg)
        return;
    if (toList.isEmpty()) {
        Q_EMIT sendFailed(tr("No recipient given."));
        return;
    }
    const QString fromAddr = ownAddress();

    // Build -> (optional crypto) -> send. The crypto step is asynchronous —
    // gpg-agent may be putting a passphrase prompt on screen — so everything
    // that touches SMTP moves into the continuation (doc/openpgp.md §6).
    applyOutgoingCrypto(
        msg, toList + ccList + bccList, sign, encrypt,
        [this, toList, ccList, bccList, fromAddr](const QByteArray &wire) {
    // --- Ship it ---
    // Sending is silent in the status log: success just closes the compose
    // window (mailSent), failure keeps it open with a dismissible dialog
    // (sendFailed). The busy spinner covers the in-progress state.
    setBusy(true);
    const QStringList envelope = toList + ccList + bccList;
    m_backend->sendMessage(wire, fromAddr, envelope,
                           [this, envelope, wire](MailBackend::Error error,
                                                  const QString &message) {
        setBusy(false);
        if (error != MailBackend::Error::None) {
            // Keep the compose window open and show the full error there.
            Q_EMIT sendFailed(message);
            return;
        }
        for (const QString &addr : envelope)
            m_store.addRecipient(addr);
        Q_EMIT mailSent(); // compose window closes on this
        // Whether a Sent copy has to be filed by hand is the protocol's
        // business: IMAP needs an APPEND, JMAP files it as part of the
        // submission. The copy is the encrypted one — encrypted to the
        // sender's own key too, so it stays readable.
        if (!m_backend->sentCopyIsAutomatic()) {
            appendToSentFolder(wire);
        } else if (!m_sentFolder.isEmpty() && m_selectedFolder == m_sentFolder) {
            // The server filed the copy, but nothing told the list about it:
            // that is push's job, and a server without it (or with push not yet
            // established) leaves the folder the user is looking at missing the
            // message they just sent until they refresh it by hand.
            refreshCurrentFolder();
        }
    });
        });
}

void MailClient::saveDraft(const QString &to, const QString &cc, const QString &bcc,
                           const QString &subject, const QString &html,
                           const QList<QUrl> &attachments, qint64 replacesUid,
                           bool sign, bool encrypt,
                           const QString &appendQuote, bool appendStrip)
{
    if (!connected()) {
        Q_EMIT sendFailed(tr("Cannot save a draft while offline."));
        return;
    }
    if (m_draftsFolder.isEmpty()) {
        Q_EMIT sendFailed(tr("No Drafts folder found on the server."));
        return;
    }
    // Bcc is a header here rather than an envelope field — a draft is not
    // being delivered, and dropping it would lose it when the draft is
    // reopened — which is what the non-strict composeMessage() does with it.
    // The deferred quote goes into the draft too — a draft missing the
    // content it promises to send would be silent data loss.
    auto msg = composeMessage(to, cc, bcc, subject,
                              appendQuoteHtml(html, appendQuote, appendStrip),
                              attachments, false);
    if (!msg)
        return;

    // A draft of an encrypted message is encrypted to the sender's own key
    // before it goes anywhere: the Drafts folder is on the server, and a draft
    // left in the clear there defeats the point of encrypting the message it
    // becomes (doc/openpgp.md §6). Only the sender's key — the recipients are
    // still being decided, and one of them may not even be a recipient yet.
    // Never signed: a signature over a half-written message would be a
    // statement the user has not made.
    const QString ownKey = accountPgpKey();
    const bool encryptDraft = encrypt && !ownKey.isEmpty();
    Q_UNUSED(sign)
    applyOutgoingCrypto(
        msg, {ownAddress()}, false, encryptDraft,
        [this, replacesUid](const QByteArray &wire) {
    setBusy(true);
    // "draft" is what makes other clients treat it as editable rather than as
    // received mail; "seen" keeps it from showing up as unread.
    m_backend->storeMessage(m_draftsFolder, wire,
                            {QStringLiteral("draft"), QStringLiteral("seen")},
                            [this, replacesUid](MailBackend::Error error, const QString &,
                                                const QString &message) {
        setBusy(false);
        if (error != MailBackend::Error::None) {
            Q_EMIT sendFailed(tr("Saving the draft failed: %1").arg(message));
            return;
        }
        setStatus(tr("Draft saved to %1").arg(m_draftsFolder));
        Q_EMIT draftSaved(); // the compose window closes on this
        // IMAP cannot replace a message in place, so re-saving is append-new
        // then delete-old. Both steps happen here, in that order, and the list
        // is refreshed once at the end — refreshing in between showed the old
        // and new copies side by side, and not refreshing at all left the new
        // one invisible until the next background sync.
        if (replacesUid > 0) {
            discardDraft(replacesUid); // refreshes once the expunge lands
        } else if (viewingDrafts()) {
            refreshCurrentFolder();
        }
    });
        });
}

void MailClient::appendToSentFolder(const QByteArray &rawMessage)
{
    if (!connected()) {
        setStatus(tr("Sent — not copied to the Sent folder (IMAP offline)"));
        return;
    }
    if (m_sentFolder.isEmpty()) {
        setStatus(tr("Sent — no Sent folder found on the server to copy into"));
        return;
    }
    m_backend->storeMessage(m_sentFolder, rawMessage, {QStringLiteral("seen")},
                            [this](MailBackend::Error error, const QString &,
                                   const QString &message) {
        // Success is silent — the closed compose window and the message showing
        // up in Sent are confirmation enough. Only a copy failure is logged.
        if (error != MailBackend::Error::None) {
            Q_EMIT errorOccurred(
                tr("Sent, but copying to %1 failed: %2").arg(m_sentFolder, message));
            return;
        }
        // "Showing up in Sent" is only automatic while push is delivering; with
        // the folder open in front of the user, ask for it rather than leaving
        // the copy invisible until the next sync.
        if (m_selectedFolder == m_sentFolder)
            refreshCurrentFolder();
    });
}

QString MailClient::ownAddress() const
{
    // What the account explicitly says it sends as, when it says so. The rest
    // is the pre-"email"-field fallback: it only ever guessed right when the
    // login happened to be the address, or the mail domain happened to match
    // the SMTP host's parent. Kept so accounts saved before the field existed
    // behave exactly as they did.
    if (!m_acct.email.isEmpty())
        return m_acct.email;
    return m_acct.user.contains(QLatin1Char('@'))
        ? m_acct.user
        : m_acct.user + QLatin1Char('@') + m_acct.smtpHost.section(QLatin1Char('.'), 1);
}

QString MailClient::signatureBlock() const
{
    // The signature editor hands us a full QTextDocument HTML page; splicing
    // <html>/<body> tags into another body string confuses the rich-text
    // parser, so cut the fragment out of the body element first.
    if (QTextDocumentFragment::fromHtml(m_acct.signature).toPlainText().trimmed().isEmpty())
        return {};
    QString fragment = m_acct.signature;
    static const QRegularExpression bodyRe(
        QStringLiteral("<body[^>]*>(.*)</body>"),
        QRegularExpression::DotMatchesEverythingOption
            | QRegularExpression::CaseInsensitiveOption);
    if (const auto m = bodyRe.match(fragment); m.hasMatch())
        fragment = m.captured(1);
    return fragment;
}

// Inner <body> content of an HTML mail, prepared for embedding into the
// compose editor: <style>/<script> blocks go (QTextDocument would render
// their text), and cid: images go (the editor cannot resolve them).
static QString quotableHtml(QString html)
{
    static const QRegularExpression bodyRe(
        QStringLiteral("<body[^>]*>(.*)</body>"),
        QRegularExpression::DotMatchesEverythingOption
            | QRegularExpression::CaseInsensitiveOption);
    if (const auto m = bodyRe.match(html); m.hasMatch())
        html = m.captured(1);
    static const QRegularExpression styleScriptRe(
        QStringLiteral("<(style|script)\\b[^>]*>.*?</\\1\\s*>"),
        QRegularExpression::DotMatchesEverythingOption
            | QRegularExpression::CaseInsensitiveOption);
    html.remove(styleScriptRe);
    static const QRegularExpression cidImgRe(
        QStringLiteral("<img\\b[^>]*\\bsrc\\s*=\\s*[\"']cid:[^>]*>"),
        QRegularExpression::CaseInsensitiveOption);
    html.remove(cidImgRe);
    return html;
}

// Chops a big HTML quote into structurally self-contained chunks the
// composer can insert one frame's budget at a time — see
// DocumentHandler::startQuoteStream. Cuts happen between top-level elements
// and after any table row: at a cut, every element still open (the
// newsletter's wrapper chain — centering table, row, cell, content table) is
// closed to finish the chunk and reopened, with its original attributes, at
// the head of the next, so each chunk parses standalone and the wrapper
// formatting carries across. When no safe cut exists the quote is one chunk.
static QStringList splitQuoteHtml(const QString &html, qsizetype budget)
{
    static const QRegularExpression tagRe(
        QStringLiteral("<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>"));
    // Elements that never close; treating them as opens would corrupt the
    // open-tag stack.
    static const QSet<QString> voidTags = {
        QStringLiteral("area"),  QStringLiteral("base"),  QStringLiteral("br"),
        QStringLiteral("col"),   QStringLiteral("embed"), QStringLiteral("hr"),
        QStringLiteral("img"),   QStringLiteral("input"), QStringLiteral("link"),
        QStringLiteral("meta"),  QStringLiteral("param"), QStringLiteral("source"),
        QStringLiteral("track"), QStringLiteral("wbr")};

    struct OpenTag { QString name; QString tag; };
    QList<OpenTag> stack;
    QStringList chunks;
    qsizetype chunkStart = 0;
    QString reopen; // open tags carried over from the previous chunk's cut

    auto emitChunk = [&](qsizetype end) {
        QString chunk = reopen + html.sliced(chunkStart, end - chunkStart);
        for (auto it = stack.crbegin(); it != stack.crend(); ++it)
            chunk += QStringLiteral("</") + it->name + QLatin1Char('>');
        chunks.append(chunk);
        chunkStart = end;
        reopen.clear();
        for (const OpenTag &open : std::as_const(stack))
            reopen += open.tag;
    };

    auto matches = tagRe.globalMatch(html);
    while (matches.hasNext()) {
        const auto match = matches.next();
        const QString name = match.captured(2).toLower();
        const bool closing = !match.captured(1).isEmpty();
        const bool selfClosing = match.captured(3).endsWith(QLatin1Char('/'));
        if (voidTags.contains(name) || selfClosing)
            continue;
        if (!closing) {
            stack.append({name, match.captured(0)});
            continue;
        }
        // Pop to the matching open, tolerating the misnesting real mail has.
        for (qsizetype i = stack.size() - 1; i >= 0; --i) {
            if (stack.at(i).name == name) {
                stack.remove(i, stack.size() - i);
                break;
            }
        }
        const qsizetype cut = match.capturedEnd();
        if (cut - chunkStart + reopen.size() < budget)
            continue;
        // Rows are the natural section boundary of table-built mail; between
        // top-level siblings (empty stack) anything may cut.
        if (name == QLatin1String("tr") || stack.isEmpty())
            emitChunk(cut);
    }
    if (chunkStart < html.size())
        chunks.append(reopen + html.sliced(chunkStart));
    return chunks;
}

namespace
{
/// cid → the part carrying it, for a whole MIME tree.
void indexContentIds(KMime::Content *node, QHash<QString, KMime::Content *> *out)
{
    if (const auto *cid = std::as_const(*node).contentID(); cid && !cid->identifier().isEmpty())
        out->insert(QString::fromLatin1(cid->identifier()), node);
    const auto children = node->contents();
    for (KMime::Content *child : children)
        indexContentIds(child, out);
}

/// Points a message's cid: images back at files the composer can render.
///
/// A pasted image in a saved draft — or an inline image in a message being
/// replied to or forwarded — is an ordinary cid: part, and the compose editor
/// cannot resolve a cid: — left alone they come back as empty boxes (or are
/// stripped by quotableHtml), and are gone for good on the next save or send.
/// Writing them back out gives the composer local-file references, which
/// composeMessage() turns into parts again on the way out.
QString restoreDraftImages(QString html, KMime::Content *root)
{
    static const QRegularExpression cidRe(
        QStringLiteral("(\\bsrc\\s*=\\s*)([\"'])cid:([^\"']+)\\2"),
        QRegularExpression::CaseInsensitiveOption);
    if (!root || !html.contains(QLatin1String("cid:"), Qt::CaseInsensitive))
        return html;

    QHash<QString, KMime::Content *> parts;
    indexContentIds(root, &parts);
    if (parts.isEmpty())
        return html;

    // Same reasoning as MessagePresenter::openAttachment: a private 0700
    // directory with an unpredictable name, living as long as the process, so
    // a draft left open all afternoon still has its images.
    static QTemporaryDir tempDir(QDir::tempPath() + QStringLiteral("/mailove-draft-images-XXXXXX"));
    if (!tempDir.isValid())
        return html;

    QMimeDatabase mimeDb;
    QHash<QString, QString> written; // cid → file URL, for an image used twice
    QString out;
    out.reserve(html.size());
    qsizetype copied = 0;
    auto matches = cidRe.globalMatch(html);
    while (matches.hasNext()) {
        const auto match = matches.next();
        const QString cid = match.captured(3);
        QString url = written.value(cid);
        if (url.isEmpty()) {
            KMime::Content *part = parts.value(cid);
            if (!part)
                continue;
            const auto *ct = std::as_const(*part).contentType();
            const QByteArray mimeType = ct ? ct->mimeType() : QByteArray();
            // Images only. Anything else a cid: may point at (a stylesheet, a
            // part of a calendar invitation) is not something the editor
            // renders, and writing it out would gain nothing.
            if (!mimeType.startsWith("image/"))
                continue;
            const QString suffix =
                mimeDb.mimeTypeForName(QString::fromLatin1(mimeType)).preferredSuffix();
            const QString path = tempDir.filePath(
                QStringLiteral("draft-%1.%2")
                    .arg(written.size() + 1)
                    .arg(suffix.isEmpty() ? QStringLiteral("png") : suffix));
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly))
                continue;
            file.write(part->decodedBody());
            file.close();
            url = QUrl::fromLocalFile(path).toString();
            written.insert(cid, url);
        }
        out += QStringView(html).sliced(copied, match.capturedStart() - copied);
        out += match.captured(1) + QLatin1Char('"') + url + QLatin1Char('"');
        copied = match.capturedEnd();
    }
    if (written.isEmpty())
        return html;
    out += QStringView(html).sliced(copied);
    return out;
}
} // namespace

/// The original message quoted for a reply or forward body — full HTML
/// fidelity either way, in one of two shapes:
///
/// Small quote: returned whole, remote content already stripped when not
/// allowed; the caller embeds it in the body and the composer lays it out in
/// one affordable pass.
///
/// Big quote (or one carrying remote images the user allowed): returns empty
/// and hands the prepared HTML back via \a appendQuote instead. It never
/// enters the editor — the composer shows a banner and the quote is appended
/// to the outgoing HTML at send/draft time (appendQuoteHtml), with
/// \a appendStrip saying whether the remote strip still has to run then.
/// doc/COMPOSER_ROADMAP.md records why the editor cannot afford these and
/// where this is headed.
QString MailClient::quotedBody(MessageContext *ctx, bool forward, QString *appendQuote,
                               bool *appendStrip, QStringList *chunks) const
{
    QElapsedTimer timer;
    timer.start();
    constexpr qsizetype maxInlineQuote = 64 * 1024;
    *appendStrip = false;

    // No HTML part — or the reader switched this message's view to plain
    // text, which the quote follows: quoting HTML the reader deliberately
    // chose not to look at would be quoting a message they did not read.
    // Plain text lays out for next to nothing, so it always goes inline.
    if (ctx->m_htmlBody.isEmpty() || ctx->m_quotePlain) {
        QString text = ctx->m_textBody.trimmed();
        if (text.isEmpty() && !ctx->m_htmlBody.isEmpty()) {
            // HTML-only message read as text: extract, capped like the
            // viewer's own text view, link targets kept.
            text = MimeUtils::plainTextWithLinks(ctx->m_htmlBody.left(500000)).trimmed();
        }
        text = MimeUtils::condenseBlankLines(text);
        const QString quoted = text.toHtmlEscaped()
            .replace(QLatin1Char('\n'), QLatin1String("<br>"));
        qCDebug(logTrace, "quotedBody: text quote%s, %lld chars",
                ctx->m_quotePlain ? " (viewer in text mode)" : "",
                static_cast<qint64>(quoted.size()));
        return quoted;
    }

    // cid: images become file: references the editor can render (and
    // composeMessage() re-embeds on send) — cheap, so done up front whole.
    QString html = restoreDraftImages(
        ctx->m_htmlBody, ctx->m_decrypted ? ctx->m_decrypted.get() : ctx->m_message.get());
    const qint64 restoreMs = timer.restart();
    html = quotableHtml(html);

    // Reply and forward part ways over remote images — a reply quotes for
    // context, a forward IS the content:
    //
    // Small reply quote: inline, remote references stripped no matter what
    // the viewer's remote toggle said. The strip is editor safety as much as
    // policy: an http: src reaching the editor is loaded by Qt Quick's
    // render thread, which blocks scene-graph sync for seconds and touches
    // the QML engine off-thread. Structure and text keep full fidelity.
    //
    // Small forward quote with remote images the user allowed: streamed into
    // the editor in chunks while the images download — each chunk rewritten
    // to local file: references before insertion
    // (DocumentHandler::resolveChunkImages), which composeMessage() embeds
    // as cid: parts on send. The recipient sees the pictures without
    // allowing remote content. With remote off, a forward strips like a
    // reply: the user declined this sender's remote content, and quoting is
    // not the moment to fetch it after all ("Forward as attachment" is the
    // full-fidelity route there).
    //
    // A big quote must not enter the editor at all (laying it out freezes
    // the GUI on open, and typing into a document sharing space with
    // hundreds of tables costs ~150ms a keystroke): it is stashed whole and
    // appended at send/draft time, with the composer showing a banner and a
    // plain-text preview meanwhile.
    const bool mayHoldRemoteImages =
        html.contains(QLatin1String("<img"), Qt::CaseInsensitive)
        && html.contains(QLatin1String("http"), Qt::CaseInsensitive);
    if (html.size() <= maxInlineQuote) {
        if (forward && ctx->m_remoteAllowed && mayHoldRemoteImages) {
            *chunks = splitQuoteHtml(html, 2 * 1024);
            qCDebug(logTrace,
                    "quotedBody: forward image stream, restoreImages=%lldms, "
                    "%lld chars -> %lld chunks",
                    restoreMs, static_cast<qint64>(html.size()),
                    static_cast<qint64>(chunks->size()));
            return QString();
        }
        if (!ctx->m_remoteAllowed || mayHoldRemoteImages)
            html = DocumentHandler::stripRemoteContent(html);
        qCDebug(logTrace,
                "quotedBody: inline quote, restoreImages=%lldms stripAndTotal=%lldms, %lld chars",
                restoreMs, timer.elapsed(), static_cast<qint64>(html.size()));
        return html;
    }

    *appendQuote = html;
    // Stripping a 400 KB quote parses it whole (~300ms) — deferred to the
    // send/save click rather than paid on the open.
    *appendStrip = !ctx->m_remoteAllowed;
    qCDebug(logTrace,
            "quotedBody: deferred quote, restoreImages=%lldms, %lld chars, strip=%d",
            restoreMs, static_cast<qint64>(html.size()), int(*appendStrip));
    return QString();
}

void MailClient::releaseQuotePreview(quint64 slot)
{
    m_presenter->releasePreviewSlot(slot);
}

void MailClient::clipboardSelectionToMarkdown(int)
{
    // Called right after a WebEngine Copy action is *triggered*. The
    // renderer writes the clipboard asynchronously, so the current content
    // is whatever was copied last — polling it raced the write and, when it
    // lost, converted stale content or left the plain copy (links gone).
    // Convert on the clipboard's next change instead: that change IS the
    // renderer's write landing, HTML flavour included.
    QClipboard *clipboard = QGuiApplication::clipboard();
    auto conn = std::make_shared<QMetaObject::Connection>();
    QElapsedTimer started;
    started.start();
    auto finish = [conn] { QObject::disconnect(*conn); };
    *conn = connect(clipboard, &QClipboard::dataChanged, this,
                    [this, clipboard, finish, started] {
        const QMimeData *mime = clipboard->mimeData();
        if (!mime || !mime->hasHtml())
            return; // an ownership-only change; the data write follows
        finish();
        QTextDocument doc;
        doc.setHtml(mime->html());
        // <br> parses to line-separator characters, which toMarkdown() emits
        // as bare newlines — soft breaks that renderers join into one line.
        // Promoted to real paragraph breaks, they survive as the separate
        // lines the reader saw. (The writer's own 80-column prose wrapping
        // also emits bare newlines, so this cannot be fixed after the fact —
        // only here, where the two are still distinguishable.)
        for (QTextCursor cursor(&doc);;) {
            cursor = doc.find(QString(QChar::LineSeparator), cursor);
            if (cursor.isNull())
                break;
            cursor.insertBlock();
        }
        // Layout-table furniture stripped (with blank runs capped) — the
        // paste target gets content, not a diagram of the newsletter's grid.
        const QString markdown = MimeUtils::flattenMarkdownTables(
            doc.toMarkdown(QTextDocument::MarkdownDialectGitHub)).trimmed();
        if (markdown.isEmpty())
            return; // leave the renderer's copy as it is
        // Our own setText fires dataChanged too — disconnected above.
        clipboard->setText(markdown);
        qCDebug(logTrace, "copy as markdown: %lld chars, %lldms after trigger",
                static_cast<qint64>(markdown.size()), started.elapsed());
    });
    // If the renderer's write never comes (nothing was selected after all),
    // stop listening — a later ordinary copy must not get converted.
    QTimer::singleShot(3000, this, finish);
}

QString MailClient::newMessageBody() const
{
    const QString sig = signatureBlock();
    return sig.isEmpty() ? QString() : QStringLiteral("<p><br></p>") + sig;
}

QString MailClient::loadHtmlFile(const QUrl &fileUrl)
{
    QFile file(fileUrl.toLocalFile());
    // A signature is a short snippet — reject anything that clearly isn't.
    constexpr qint64 maxSize = 1 * 1024 * 1024;
    if (!file.open(QIODevice::ReadOnly) || file.size() > maxSize) {
        Q_EMIT errorOccurred(file.size() > maxSize
                                 ? tr("%1 is too large for a signature (max 1 MB).")
                                       .arg(fileUrl.fileName())
                                 : tr("Could not read %1.").arg(fileUrl.toLocalFile()));
        return {};
    }
    return QString::fromUtf8(file.readAll());
}

QVariantMap MailClient::replyData(bool replyAll)
{
    return replyDataFor(m_reading, replyAll);
}

QVariantMap MailClient::replyDataFor(MessageContext *ctx, bool replyAll)
{
    if (!ctx->m_message)
        return {};
    const KMime::Message *msg = ctx->m_message.get();

    // Bare addr-specs only — that is the shape sendMail() accepts back.
    auto addressesOf = [](const auto *header) {
        QStringList out;
        if (!header)
            return out;
        const auto mailboxes = header->mailboxes();
        for (const auto &mb : mailboxes) {
            const QString addr = QString::fromLatin1(mb.address());
            if (addr.contains(QLatin1Char('@')))
                out.append(addr);
        }
        return out;
    };

    // Reply target: Reply-To when the sender set one, else From.
    QStringList to = addressesOf(msg->replyTo());
    if (to.isEmpty())
        to = addressesOf(msg->from());
    to.removeDuplicates();

    // Reply-all: everyone in the original To/Cc except us and the target.
    QStringList cc;
    if (replyAll) {
        QSet<QString> seen{ownAddress().toLower()};
        for (const QString &addr : std::as_const(to))
            seen.insert(addr.toLower());
        const QStringList others = addressesOf(msg->to()) + addressesOf(msg->cc());
        for (const QString &addr : others) {
            if (!seen.contains(addr.toLower())) {
                seen.insert(addr.toLower());
                cc.append(addr);
            }
        }
    }

    QString subject = msg->subject() ? msg->subject()->asUnicodeString() : QString();
    if (!subject.startsWith(QLatin1String("Re:"), Qt::CaseInsensitive))
        subject = QStringLiteral("Re: ") + subject;

    // Quote the HTML part when there is one so the reply keeps the original's
    // formatting; the plain-text part is the fallback. A big quote never
    // enters the editor — it comes back via appendQuote and is appended to
    // the outgoing message on send; the composer shows a banner meanwhile.
    QString appendQuote;
    bool appendStrip = false;
    QStringList quoteChunks; // stays empty: replies never image-stream
    const QString quoted =
        quotedBody(ctx, /*forward=*/false, &appendQuote, &appendStrip, &quoteChunks);
    const QString fromDisplay = msg->from() ? msg->from()->asUnicodeString() : QString();
    QString date;
    if (msg->date()) {
        date = msg->date()->dateTime().toLocalTime().toString(
            m_dateFormat + QStringLiteral(" hh:mm"));
    }
    // Signature goes above the quoted original, right under the cursor line.
    // A deferred quote leaves only the attribution line in the document; the
    // quote itself is appended at send time.
    const QString body = QStringLiteral("<p><br></p>") + signatureBlock()
        + QStringLiteral("<p>")
        + tr("On %1, %2 wrote:").arg(date, fromDisplay).toHtmlEscaped()
        + QStringLiteral("</p>")
        + (appendQuote.isEmpty()
               ? QStringLiteral("<blockquote>") + quoted + QStringLiteral("</blockquote>")
               : QString());

    // Full-fidelity read-only preview of a deferred quote, rendered by the
    // viewer's own sandboxed pipeline into a slot the composer owns.
    quint64 previewSlot = 0;
    const QString previewUrl = appendQuote.isEmpty()
        ? QString() : m_presenter->composePreviewUrl(ctx, &previewSlot);

    return {{QStringLiteral("to"), to.join(QStringLiteral(", "))},
            {QStringLiteral("cc"), cc.join(QStringLiteral(", "))},
            {QStringLiteral("subject"), subject},
            {QStringLiteral("body"), body},
            {QStringLiteral("appendQuote"), appendQuote},
            {QStringLiteral("appendStrip"), appendStrip},
            {QStringLiteral("quotePreviewUrl"), previewUrl},
            {QStringLiteral("quotePreviewSlot"), previewSlot}};
}

/// The message as it stands, for reopening a draft in the composer. Unlike
/// replyData/forwardData nothing is quoted or prefixed — a draft is resumed,
/// not responded to.
QVariantMap MailClient::draftData()
{
    MessageContext *ctx = m_reading;
    if (!ctx->m_message)
        return {};
    const KMime::Message *msg = ctx->m_message.get();

    auto addressesOf = [](const auto *header) {
        QStringList out;
        if (!header)
            return out;
        const auto mailboxes = header->mailboxes();
        for (const auto &mb : mailboxes) {
            const QString addr = QString::fromLatin1(mb.address());
            if (addr.contains(QLatin1Char('@')))
                out.append(addr);
        }
        return out;
    };

    // The HTML part when the draft has one, so formatting survives a
    // save/reopen round trip — pasted images included, which is what
    // restoreDraftImages() is for; the plain part is the fallback.
    QString body = !ctx->m_htmlBody.isEmpty()
        ? restoreDraftImages(ctx->m_htmlBody,
                             ctx->m_decrypted ? ctx->m_decrypted.get() : ctx->m_message.get())
        : ctx->m_textBody.toHtmlEscaped().replace(QLatin1Char('\n'), QLatin1String("<br>"));

    // A draft that carries a deferred quote (or any other huge HTML) gets the
    // same protection the reply/forward paths have: assigned whole it would
    // freeze the composer for seconds, so it is split and streamed in instead
    // (DocumentHandler::startQuoteStream — which also resolves any remote
    // images to local files, keeping http: srcs away from the render thread).
    // It stays fully editable; on this size, editing is simply slower.
    QStringList bodyChunks;
    constexpr qsizetype maxInlineDraft = 64 * 1024;
    // src="http, not just <img + http anywhere: a small draft with a pasted
    // (file:) image and a web link in its text is not carrying remote images.
    const bool remoteImages =
        body.contains(QLatin1String("src=\"http"), Qt::CaseInsensitive)
        || body.contains(QLatin1String("src='http"), Qt::CaseInsensitive);
    if (body.size() > maxInlineDraft || remoteImages) {
        bodyChunks = splitQuoteHtml(body, 2 * 1024);
        qCDebug(logTrace, "draftData: streaming %lld chars in %lld chunks",
                static_cast<qint64>(body.size()), static_cast<qint64>(bodyChunks.size()));
        body.clear();
        setStatus(tr("⏳ Large draft — its content loads progressively."));
    }

    return {{QStringLiteral("to"), addressesOf(msg->to()).join(QStringLiteral(", "))},
            {QStringLiteral("cc"), addressesOf(msg->cc()).join(QStringLiteral(", "))},
            {QStringLiteral("bcc"), addressesOf(msg->bcc()).join(QStringLiteral(", "))},
            {QStringLiteral("subject"),
             msg->subject() ? msg->subject()->asUnicodeString() : QString()},
            {QStringLiteral("body"), body},
            {QStringLiteral("bodyChunks"), bodyChunks},
            {QStringLiteral("uid"), ctx->m_uid}};
}

/// Removes the draft a composer was opened from, once its replacement has been
/// sent or re-saved — otherwise editing a draft would leave the old copy
/// beside the new one every time.
void MailClient::discardDraft(qint64 uid)
{
    if (uid <= 0 || m_draftsFolder.isEmpty() || !connected())
        return;
    m_backend->deleteMessages(m_draftsFolder, {QString::number(uid)},
                              [this, uid](MailBackend::Error error, const QString &) {
        if (error != MailBackend::Error::None)
            return;
        // Drop it from the open list too, when Drafts is on screen.
        if (viewingDrafts()) {
            m_messageModel.removeByUids({uid});
            m_store.removeMessages(m_draftsFolder, {uid});
            // The replacement was APPENDed just before this; show it in the
            // same breath as the old row disappearing.
            refreshCurrentFolder();
        }
    });
}

QVariantMap MailClient::forwardData()
{
    return forwardDataFor(m_reading);
}

QVariantMap MailClient::forwardDataFor(MessageContext *ctx)
{
    if (!ctx->m_message)
        return {};
    const KMime::Message *msg = ctx->m_message.get();

    QString subject = msg->subject() ? msg->subject()->asUnicodeString() : QString();
    if (!subject.startsWith(QLatin1String("Fwd:"), Qt::CaseInsensitive)
        && !subject.startsWith(QLatin1String("Fw:"), Qt::CaseInsensitive))
        subject = QStringLiteral("Fwd: ") + subject;

    // Inline cid: images are rewritten to temp files first — quotableHtml()
    // drops any cid: image left over (the editor cannot resolve them), which
    // would silently forward the mail without its pictures. As with a reopened
    // draft, composeMessage() turns the file references back into inline parts
    // on the way out. Remote content follows the viewer's decision — see
    // stripRemoteContent.
    QString appendQuote;
    bool appendStrip = false;
    QStringList quoteChunks;
    const QString quoted =
        quotedBody(ctx, /*forward=*/true, &appendQuote, &appendStrip, &quoteChunks);
    const QString from = msg->from() ? msg->from()->asUnicodeString() : QString();
    const QString origTo = msg->to() ? msg->to()->asUnicodeString() : QString();
    const QString origSubject =
        msg->subject() ? msg->subject()->asUnicodeString() : QString();
    QString date;
    if (msg->date()) {
        date = msg->date()->dateTime().toLocalTime().toString(
            m_dateFormat + QStringLiteral(" hh:mm"));
    }

    QString header = tr("---------- Forwarded message ----------");
    header += QStringLiteral("<br>") + tr("From: %1").arg(from.toHtmlEscaped());
    header += QStringLiteral("<br>") + tr("Date: %1").arg(date.toHtmlEscaped());
    header += QStringLiteral("<br>") + tr("Subject: %1").arg(origSubject.toHtmlEscaped());
    header += QStringLiteral("<br>") + tr("To: %1").arg(origTo.toHtmlEscaped());

    // Signature goes above the forwarded block, right under the cursor line.
    // A deferred quote leaves only the forwarded-message header block in the
    // document (content appended at send time); an image-streamed quote
    // arrives as chunks after the header instead of an inline blockquote.
    const QString body = QStringLiteral("<p><br></p>") + signatureBlock()
        + QStringLiteral("<p>") + header + QStringLiteral("</p>")
        + (!quoted.isEmpty()
               ? QStringLiteral("<blockquote>") + quoted + QStringLiteral("</blockquote>")
               : QString());

    // The original's attachments, exported as temp files the composer can
    // list and composeMessage() can read back — a forward without them sends
    // a mail that talks about an attachment it does not carry.
    QElapsedTimer timer;
    timer.start();
    QVariantList attachmentUrls;
    const QList<QUrl> exported = m_presenter->exportAttachments(ctx);
    for (const QUrl &url : exported)
        attachmentUrls.append(url);
    qCDebug(logTrace, "forwardData: exportAttachments=%lldms (%lld files)",
            timer.elapsed(), static_cast<qint64>(exported.size()));

    // Full-fidelity read-only preview of a deferred quote, rendered by the
    // viewer's own sandboxed pipeline into a slot the composer owns.
    quint64 previewSlot = 0;
    const QString previewUrl = appendQuote.isEmpty()
        ? QString() : m_presenter->composePreviewUrl(ctx, &previewSlot);

    return {{QStringLiteral("to"), QString()},
            {QStringLiteral("cc"), QString()},
            {QStringLiteral("subject"), subject},
            {QStringLiteral("body"), body},
            {QStringLiteral("attachments"), attachmentUrls},
            {QStringLiteral("appendQuote"), appendQuote},
            {QStringLiteral("appendStrip"), appendStrip},
            {QStringLiteral("quoteChunks"), quoteChunks},
            // A deferred forward with remote content allowed: its images are
            // fetched while the user writes, so the send can embed them —
            // the recipient sees the pictures without allowing anything.
            {QStringLiteral("prefetchImages"),
             !appendQuote.isEmpty() && ctx->m_remoteAllowed
                 && (appendQuote.contains(QLatin1String("src=\"http"), Qt::CaseInsensitive)
                     || appendQuote.contains(QLatin1String("src='http"), Qt::CaseInsensitive))},
            {QStringLiteral("quotePreviewUrl"), previewUrl},
            {QStringLiteral("quotePreviewSlot"), previewSlot}};
}

QVariantMap MailClient::forwardAsAttachmentData()
{
    return forwardAsAttachmentDataFor(m_reading);
}

QVariantMap MailClient::forwardAsAttachmentDataFor(MessageContext *ctx)
{
    if (!ctx->m_message)
        return {};
    const KMime::Message *msg = ctx->m_message.get();

    QString subject = msg->subject() ? msg->subject()->asUnicodeString() : QString();
    const QString origSubject = subject;
    if (!subject.startsWith(QLatin1String("Fwd:"), Qt::CaseInsensitive)
        && !subject.startsWith(QLatin1String("Fw:"), Qt::CaseInsensitive))
        subject = QStringLiteral("Fwd: ") + subject;

    // The message as it arrived, byte for byte — attachments, inline images,
    // headers and signatures intact and verifiable, which no inline forward
    // can fully match. A decrypted message forwards its decrypted form: the
    // ciphertext would be addressed to the wrong key to be of any use.
    const QByteArray &raw = ctx->m_decrypted && !ctx->m_decryptedRaw.isEmpty()
        ? ctx->m_decryptedRaw : ctx->m_raw;
    if (raw.isEmpty())
        return {};

    // Same reasoning as every other composer temp file: private 0700
    // directory, process lifetime — it must survive until the send reads it.
    static QTemporaryDir tempDir(QDir::tempPath() + QStringLiteral("/mailove-forward-eml-XXXXXX"));
    if (!tempDir.isValid())
        return {};
    static int count = 0;
    QString base;
    for (const QChar &c : origSubject) {
        base.append(c.isLetterOrNumber() || c == QLatin1Char(' ') || c == QLatin1Char('-')
                        ? c : QLatin1Char('_'));
    }
    base = base.trimmed().left(60);
    if (base.isEmpty())
        base = QStringLiteral("forwarded message");
    const QString path =
        tempDir.filePath(QStringLiteral("%1-%2.eml").arg(++count).arg(base));
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        Q_EMIT errorOccurred(tr("Could not write %1: %2").arg(path, file.errorString()));
        return {};
    }
    file.write(raw);
    file.close();
    qCDebug(logTrace, "forwardAsAttachment: %lld bytes -> %s",
            static_cast<qint64>(raw.size()), qUtf8Printable(path));

    return {{QStringLiteral("to"), QString()},
            {QStringLiteral("cc"), QString()},
            {QStringLiteral("subject"), subject},
            {QStringLiteral("body"), QStringLiteral("<p><br></p>") + signatureBlock()},
            {QStringLiteral("attachments"),
             QVariantList{QUrl::fromLocalFile(path)}}};
}

QStringList MailClient::recipientSuggestions(const QString &prefix)
{
    return m_store.recipientCompletions(prefix);
}

QString MailClient::avatarSource(const QString &from) const
{
    if (!AdvancedConfig::b("avatars/enabled"))
        return {};
    // "Name <addr>" as often as not, and Gravatar keys on the address alone,
    // lowercased and trimmed.
    QString address = from.trimmed();
    const qsizetype open = address.lastIndexOf(u'<');
    const qsizetype close = address.lastIndexOf(u'>');
    if (open >= 0 && close > open)
        address = address.mid(open + 1, close - open - 1);
    address = address.trimmed().toLower();
    if (address.isEmpty() || !address.contains(u'@'))
        return {};
    const QString hash = QString::fromLatin1(
        QCryptographicHash::hash(address.toUtf8(), QCryptographicHash::Sha256).toHex());
    // Fetched at twice the size it is shown at: avatarSize() is a logical
    // pixel size, and a 40-logical-px image displayed on a HiDPI screen is
    // drawn from 80 device pixels. Gravatar serves any size for the same
    // request, so the doubling costs a few KB once per address per year.
    return QStringLiteral("image://gravatar/%1/%2").arg(avatarSize() * 2).arg(hash);
}

int MailClient::avatarSize() const
{
    return AdvancedConfig::i("avatars/sizePixels");
}

QStringList MailClient::trustedAuthMethods() const
{
    QStringList out;
    for (const char *m : {"spf", "dkim", "dmarc", "arc", "compauth"}) {
        if (SpamHeuristics::authMethodTrusted(QLatin1String(m)))
            out.append(QLatin1String(m));
    }
    return out;
}

QStringList MailClient::ownAddresses() const
{
    // Every configured account, not just the active one: mail to a second
    // address of the user's routinely lands in this mailbox through forwarding,
    // and reading that as "addressed to a stranger" would be wrong.
    //
    // Aliases the client does not know about are the reason the rule that reads
    // this is weighted at 8 and not more — the list is necessarily incomplete,
    // and Delivered-To covers the common case that it misses.
    QStringList out;
    const QString own = SpamHeuristics::normalizeAddress(ownAddress());
    if (!own.isEmpty())
        out.append(own);
    const QList<QVariantMap> all = m_accounts.all();
    for (const QVariantMap &a : all) {
        const QString addr =
            SpamHeuristics::normalizeAddress(a.value(QStringLiteral("email")).toString());
        if (!addr.isEmpty() && !out.contains(addr))
            out.append(addr);
    }
    return out;
}

QSet<QString> MailClient::referencedMessageIds(const QByteArray &head)
{
    // Read off the raw head rather than a parsed message: this runs for every
    // header the sync delivers, and the two fields are simple enough that
    // parsing the whole message to reach them would be the expensive way.
    static const QRegularExpression fieldRe(
        QStringLiteral("^(in-reply-to|references):(.*(?:\\r?\\n[ \\t].*)*)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);
    static const QRegularExpression idRe(QStringLiteral("<([^<>\\s]+)>"));
    QSet<QString> out;
    const QString text = QString::fromUtf8(head);
    auto fields = fieldRe.globalMatch(text);
    while (fields.hasNext()) {
        auto ids = idRe.globalMatch(fields.next().captured(2));
        while (ids.hasNext())
            out.insert(ids.next().captured(1));
    }
    return out;
}

SpamHeuristics::Context
MailClient::spamContextFor(const QString &folder, const QString &fromValue,
                           const QByteArray &head,
                           const QSet<QString> &knownSenders,
                           const QHash<QString, MailStore::DomainHistory> &orgHistory,
                           const QSet<QString> &knownMsgIds,
                           const MailStore::SentTldProfile &tldProfile) const
{
    SpamHeuristics::Context ctx;
    ctx.inJunkFolder = isJunkFolderKey(folder);
    const QString fromAddr = SpamHeuristics::addressOf(fromValue);
    ctx.knownCorrespondent = knownSenders.contains(fromAddr);
    const auto hist = orgHistory.value(SpamHeuristics::organizationalDomainOf(fromAddr));
    ctx.seenFromOrg = hist.seen;
    ctx.daysKnownOrg = hist.days;
    ctx.familiarTlds = tldProfile.familiar;
    ctx.sentTldSample = tldProfile.sample;
    ctx.ownAddresses = ownAddresses();
    const QSet<QString> refs = referencedMessageIds(head);
    for (const QString &id : refs) {
        if (knownMsgIds.contains(id)) {
            ctx.inReplyToKnown = true;
            break;
        }
    }
    return ctx;
}

void MailClient::scoreHeader(MessageListModel::Header &h, const QString &folder,
                             const QByteArray &head,
                             const QSet<QString> &knownSenders,
                             const QHash<QString, MailStore::DomainHistory> &orgHistory,
                             const QSet<QString> &knownMsgIds,
                             const MailStore::SentTldProfile &tldProfile)
{
    SpamHeuristics::Context ctx = spamContextFor(folder, h.from, head, knownSenders,
                                                 orgHistory, knownMsgIds, tldProfile);
    ctx.authInfo = h.authInfo;
    // Re-derived rather than read off h.suspicious: the marker deliberately
    // does not grade (soft or hard, it shows), while the scorer must — only
    // an outright failure may revoke the known-correspondent exemption.
    ctx.authFailed = SpamHeuristics::authResultsFailed(h.authInfo);
    ctx.authSoftFailed = SpamHeuristics::authResultsSoftFailed(h.authInfo);
    ctx.authPassed = SpamHeuristics::authResultsPassed(h.authInfo);
    ctx.arcPassed = SpamHeuristics::authResultsArcPassed(h.authInfo);
    ctx.crypto = h.crypto;
    const SpamHeuristics::Score s = SpamHeuristics::score({head, {}, {}}, ctx);
    h.spamScore = s.total;
    h.spamState = s.exempt ? 3 : 1;
    h.spamDetail = s.exempt ? s.exemptReason : s.explanation();
}

void MailClient::rescoreWithBody(const QString &folder, qint64 uid, KMime::Message *msg)
{
    if (!msg || uid <= 0 || !scoresSpamIn(folder))
        return;
    // The user's own answer outranks anything a re-score can find. Only the
    // model knows it for a listed message; for one in another folder the store
    // is asked instead, so a prefetch cannot resurrect a cleared mark.
    const int state = folder == m_selectedFolder ? m_messageModel.spamStateOf(uid)
                                                 : m_store.spamStateOf(folder, uid);
    if (state == 3)
        return;

    SpamHeuristics::Message m;
    m.head = msg->head();
    MimeUtils::collectBodies(msg, &m.text, &m.html);
    MimeUtils::collectAttachments(msg, &m.attachmentNames);
    m.encryptedArchive = MimeUtils::hasEncryptedArchive(msg);

    const QString fromValue = msg->from() ? msg->from()->asUnicodeString() : QString();
    const QString fromAddr = SpamHeuristics::addressOf(fromValue);
    const QString org = SpamHeuristics::organizationalDomainOf(fromAddr);
    SpamHeuristics::Context ctx =
        spamContextFor(folder, fromValue, m.head, m_store.knownCorrespondents({fromAddr}),
                       m_store.senderDomainHistory(org.isEmpty() ? QSet<QString>()
                                                                 : QSet<QString>{org}),
                       m_store.knownMessageIds(referencedMessageIds(m.head)),
                       m_store.sentTldProfile());
    // The authentication verdict is the one thing the body cannot improve on,
    // and re-deriving it here would need the trusted-domain list all over
    // again — so it is carried over from the header pass where there is one.
    const QString authInfo = trustedAuthResults(msg, trustedAuthDomains());
    ctx.authInfo = authInfo;
    ctx.authPassed = SpamHeuristics::authResultsPassed(authInfo);
    ctx.arcPassed = SpamHeuristics::authResultsArcPassed(authInfo);
    if (SpamHeuristics::authResultsFailed(authInfo))
        ctx.authFailed = true;
    ctx.authSoftFailed = SpamHeuristics::authResultsSoftFailed(authInfo);
    ctx.crypto = PgpMime::storedKind(PgpMime::kindFromHead(m.head));

    const SpamHeuristics::Score s = SpamHeuristics::score(m, ctx);
    const int newState = s.exempt ? 3 : 2;
    const QString detail = s.exempt ? s.exemptReason : s.explanation();
    m_store.setSpamVerdict(folder, uid, s.total, newState, detail);
    if (folder == m_selectedFolder)
        m_messageModel.setSpamVerdict(uid, s.total, newState, detail);
}

bool MailClient::listsRecipients(const QString &folder) const
{
    const QString path = folder.section(QChar(0x1f), -1);
    if (path.isEmpty())
        return false;
    // What the account configuration says first, when it says anything. Only
    // the open account has one, which is why the name test below is the part
    // that has to stand on its own.
    if (!m_sentFolder.isEmpty() && path == m_sentFolder)
        return true;
    if (!m_draftsFolder.isEmpty() && path == m_draftsFolder)
        return true;
    return folderNameIsOutgoing(path);
}

bool MailClient::folderNameIsOutgoing(const QString &folder)
{
    const QString path = folder.section(QChar(0x1f), -1);
    if (path.isEmpty())
        return false;
    // Then the names, for the accounts whose server declares no special-use
    // and for the folders it has no attribute for at all (Templates, Outbox).
    // Matched on the leaf so that "[Gmail]/Sent Mail" and "INBOX.Sent" both
    // answer, and case-insensitively because servers disagree about that too.
    static const QStringList names = {
        QStringLiteral("sent"),          QStringLiteral("sent mail"),
        QStringLiteral("sent items"),    QStringLiteral("sent messages"),
        QStringLiteral("drafts"),        QStringLiteral("draft"),
        QStringLiteral("outbox"),        QStringLiteral("templates"),
        // Localised names the major web UIs create.
        QStringLiteral("odoslané"),      QStringLiteral("odoslaná pošta"),
        QStringLiteral("koncepty"),      QStringLiteral("rozpracované"),
        QStringLiteral("odeslaná pošta"), QStringLiteral("gesendet"),
        QStringLiteral("entwürfe"),      QStringLiteral("envoyés"),
        QStringLiteral("brouillons"),    QStringLiteral("enviados"),
        QStringLiteral("borradores"),
    };
    // Deliberately not folderLeaf(): that splits on the delimiter the server
    // reported, and on an account switch there is not one yet. m_folderSeparator
    // is cleared per account, so the fallback guesses from the folder model —
    // which still holds the *previous* account's folders — and guessed '.' for
    // Gmail, leaving "[Gmail]/Sent Mail" unsplit and unmatched until LIST
    // landed. The column heading and the search scope then changed a moment
    // after the folder opened, which is exactly the flicker this avoids.
    //
    // Both delimiters, always: no server uses a third, and a folder that is a
    // leaf under one reading is a leaf under the other.
    const int cut = qMax(path.lastIndexOf(QLatin1Char('/')), path.lastIndexOf(QLatin1Char('.')));
    return names.contains(path.mid(cut + 1).trimmed().toLower());
}

bool MailClient::isLocalAccountKey(const QString &accountKey) const
{
    if (accountKey.isEmpty())
        return false;
    // The open account is answered without touching settings, which is the
    // case this is asked about a few hundred times per folder load.
    if (accountKey == this->accountKey())
        return m_acct.local;
    QSettings s = AccountStore::settings();
    const int count = s.value(QStringLiteral("accounts/size")).toInt();
    for (int i = 0; i < count; ++i) {
        bool local = false;
        if (AccountStore::storedKeyAt(s, i, &local) == accountKey)
            return local;
    }
    return false;
}

bool MailClient::isJunkFolderKey(const QString &folder) const
{
    return isJunkFolder(folder.section(QChar(0x1f), -1));
}

bool MailClient::scoresSpamIn(const QString &folder) const
{
    // Never for an imported archive. Two reasons, and the second is the one
    // that matters: there is nothing to do with a verdict — no server to move
    // junk to, and the retention sweep already refuses to touch an archive
    // because imported mail is the only copy there is — and, worse, the rules
    // would be wrong. Archived mail routinely arrives without Received, Date
    // or Message-ID once it has been through an mbox export, and those three
    // together come to 53, over the threshold, on mail that is merely old.
    // It also never carries a trusted Authentication-Results, so none of the
    // ham credit that would offset them is available either.
    if (m_acct.local)
        return false;
    // The folder key may be scoped ("account\x1fINBOX") or a plain path, and
    // IMAP spells the inbox case-insensitively by RFC 3501. Sub-folders of the
    // inbox ("INBOX/Archive") are somewhere mail was filed on purpose and are
    // deliberately not included.
    const QString path = folder.section(QChar(0x1f), -1);
    if (path.compare(QLatin1String("INBOX"), Qt::CaseInsensitive) == 0)
        return true;
    return isJunkFolder(path);
}

void MailClient::appendScoredHeaders(QList<MessageListModel::Header> &out,
                                     const QString &folder,
                                     const QList<MailBackend::HeaderInfo> &infos,
                                     const QStringList &authDomains)
{
    // Only where the list will show it: everywhere else this is a string per
    // message the cache would carry and nothing would read.
    const bool wantsRecipients = listsRecipients(folder);
    const auto withRecipients = [wantsRecipients](MessageListModel::Header h,
                                                  const MailBackend::HeaderInfo &info) {
        if (wantsRecipients && info.message && info.message->to())
            h.to = info.message->to()->asUnicodeString();
        return h;
    };

    if (!scoresSpamIn(folder)) {
        // Still becomes rows — just unscored ones, settled at state 3 so
        // nothing downstream reads the untouched zero as a verdict.
        for (const auto &info : infos) {
            if (!info.message || info.uid <= 0)
                continue;
            MessageListModel::Header h =
                withRecipients(headerFromBackend(info, authDomains), info);
            h.spamState = 3;
            out.append(h);
        }
        return;
    }

    QList<MessageListModel::Header> batch;
    QList<QByteArray> heads;
    QSet<QString> senders;
    QSet<QString> orgs;
    QSet<QString> references;
    for (const auto &info : infos) {
        if (!info.message || info.uid <= 0)
            continue;
        batch.append(withRecipients(headerFromBackend(info, authDomains), info));
        heads.append(info.message->head());
        const QString addr = SpamHeuristics::addressOf(batch.constLast().from);
        senders.insert(addr);
        if (const QString org = SpamHeuristics::organizationalDomainOf(addr); !org.isEmpty())
            orgs.insert(org);
        references += referencedMessageIds(heads.constLast());
    }
    if (batch.isEmpty())
        return;
    // One allowlist query for the whole FETCH batch rather than one per
    // message: this runs on the GUI thread between deliveries, and a few
    // hundred round trips there would be felt in the list. The domain history
    // and the ancestor lookup are batched for exactly the same reason.
    const QSet<QString> known = m_store.knownCorrespondents(senders);
    const auto orgHistory = m_store.senderDomainHistory(orgs);
    const QSet<QString> knownMsgIds = m_store.knownMessageIds(references);
    const auto tldProfile = m_store.sentTldProfile();
    for (qsizetype i = 0; i < batch.size(); ++i)
        scoreHeader(batch[i], folder, heads.at(i), known, orgHistory, knownMsgIds, tldProfile);
    out += batch;
}

void MailClient::harvestRecipients(const KMime::Message *msg, const QString &folder,
                                   qint64 uid)
{
    auto add = [this, &folder, uid](const auto *header) {
        if (!header)
            return;
        const auto mailboxes = header->mailboxes();
        for (const auto &mb : mailboxes)
            m_store.addSentRecipient(folder, uid, QString::fromLatin1(mb.address()),
                                     mb.hasName() ? mb.name() : QString());
    };
    add(std::as_const(*msg).to());
    add(std::as_const(*msg).cc());
}

void MailClient::setBusy(bool busy)
{
    if (m_busy == busy)
        return;
    m_busy = busy;
    Q_EMIT busyChanged();
}

// Collapse key for the breadcrumb: statuses about the same subject replace
// each other in place instead of stacking. Folder statuses are formatted as
// "FOLDER — detail…", so the key is the part before the em-dash — every
// "INBOX — checking… / cached, refreshing… / N of M headers…" update becomes
// one INBOX crumb that updates in place. Statuses without an em-dash (errors,
// "Loaded from cache", "Message sent") each key on their own digit-stripped
// text, so distinct ones still accrue but repeats don't.
static QString statusStem(const QString &s)
{
    const int dash = s.indexOf(QStringLiteral(" — "));
    if (dash > 0)
        return s.left(dash).simplified();
    QString stem;
    stem.reserve(s.size());
    for (const QChar &c : s) {
        if (!c.isDigit())
            stem.append(c);
    }
    return stem.simplified();
}

void MailClient::setStatus(const QString &text)
{
    // Keep a short breadcrumb of recent statuses instead of overwriting, so the
    // user can see the recent history (e.g. "fetching older… · cached ·
    // connected"), newest first. Progress updates that only change their
    // numbers replace the head rather than piling up.
    // An empty status means "the transient op finished" — don't add or wipe
    // anything; the trail keeps showing the last real state (folder sync etc.).
    if (text.isEmpty())
        return;

    const int maxTrail = 6;
    // Collapse against the whole trail, not just its head. Two operations
    // reporting progress at once take turns at the head, so a head-only check
    // never matched and the trail filled with one alternating pair repeated
    // over and over — "Importing Mail — 43931 messages · Trash — caching 1
    // body · Importing Mail — 43581 messages · …". One crumb per subject is
    // what the collapse was always meant to give.
    int existing = -1;
    const QString stem = statusStem(text);
    for (int i = 0; i < m_statusTrail.size(); ++i) {
        if (statusStem(m_statusTrail.at(i)) == stem) {
            existing = i;
            break;
        }
    }
    if (existing >= 0) {
        if (m_statusTrail.at(existing) == text)
            return; // identical — nothing changed
        // Updated in place rather than moved to the front: with two operations
        // running, promoting every update would have them swapping positions
        // on each tick, which reads as flicker even though it is only ever two
        // crumbs. Their numbers change where they stand.
        m_statusTrail[existing] = text;
    } else {
        m_statusTrail.prepend(text);
        while (m_statusTrail.size() > maxTrail)
            m_statusTrail.removeLast();
    }

    const QString composed = m_statusTrail.join(QStringLiteral("  ·  "));
    if (m_statusText == composed)
        return;
    m_statusText = composed;
    Q_EMIT statusTextChanged();
}

void MailClient::copyToClipboard(const QString &text) const
{
    if (auto *cb = QGuiApplication::clipboard())
        cb->setText(text);
}

QString MailClient::aboutText() const
{
    // ABOUT.md is compiled into the binary as a Qt resource at build time.
    QFile f(QStringLiteral(":/ABOUT.md"));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    return QString::fromUtf8(f.readAll());
}

/// Cached "how many bodies are still missing here". The underlying query is a
/// LEFT JOIN over the whole folder — 200 ms on a large one — and the backfill
/// asked for it on every 600 ms tick purely to word a status crumb. It is
/// recomputed on folder change and when new headers arrive, and counted down
/// locally as bodies land.
int MailClient::missingBodiesIn(const QString &folder)
{
    return m_sync->missingBodiesIn(folder);
}

void MailClient::noteBodyStored(const QString &folder)
{
    m_sync->noteBodyStored(folder);
}

void MailClient::invalidateMissingBodies()
{
    m_sync->invalidateMissingBodies();
}

QString MailClient::openFolderSyncStatus(const QString &folder)
{
    return m_sync->openFolderSyncStatus(folder);
}

void MailClient::teardownSession()
{
    m_spamSwept = false; // the next connection sweeps again
    m_sync->teardown();
    // Closes every connection and reports the state change. Because this is a
    // deliberate teardown the backend stays quiet about it beyond that — no
    // connectionLost(), so nothing here tries to dial again, and in particular
    // m_pendingFolder keeps whatever folder an account switch just chose.
    m_backend->disconnectAccount();
    // m_selectedFolder deliberately survives a teardown. connectAccount() tears
    // the session down as its first step, so clearing here wiped the folder an
    // account switch had just chosen — leaving every consumer (the sidebar
    // highlight, openCurrent()'s "already open?" guard, and the keep-current
    // fallback when the folder list arrives) comparing against an empty string.
    // Everything that acts on it is already guarded by connected(), and the
    // paths that really mean "nothing is open" clear it themselves.
}

void MailClient::refreshCurrentFolder()
{
    if (!connected() || m_selectedFolder.isEmpty() || m_busy)
        return;
    // Same round trip as opening the folder — it is what re-reads the size —
    // but the folder is already on screen, so the answer only tops up the
    // newest headers. The intent is what tells the two apart when the reply
    // arrives.
    m_sync->refreshSelectedFolder(m_selectedFolder);
}

void MailClient::acquireTokenAndConnect()
{
    if (!m_oauth) {
        m_oauth = new OAuthHelper(this);
        connect(m_oauth, &OAuthHelper::tokensReady, this,
                [this](const QString &accessToken, const QString &refreshToken,
                       const QDateTime &expiry) {
                    m_accounts.setAccessToken(accessToken, expiry);
                    if (!refreshToken.isEmpty()
                        && refreshToken != m_accounts.refreshToken()) {
                        m_accounts.setRefreshToken(refreshToken);
                        auto *write = new QKeychain::WritePasswordJob(kWalletService, this);
                        write->setKey(oauthWalletKey());
                        write->setTextData(refreshToken);
                        write->start();
                    }
                    connectAccount();
                });
        connect(m_oauth, &OAuthHelper::failed, this, [this](const QString &message) {
            setBusy(false);
            // A dead refresh token would fail forever — drop it so the next
            // attempt goes through the browser again.
            if (!m_accounts.refreshToken().isEmpty()) {
                m_accounts.setRefreshToken(QString());
                auto *del = new QKeychain::DeletePasswordJob(kWalletService, this);
                del->setKey(oauthWalletKey());
                del->start();
            }
            setStatus(tr("Sign-in failed"));
            Q_EMIT errorOccurred(message);
        });
    }
    const auto provider = OAuthHelper::Provider(m_acct.authType);

    // Built-in desktop-client IDs so sign-in needs no manual setup (same
    // publicly-documented installed-app credentials Thunderbird ships; a
    // clientId in the account config overrides them).
    // Three places, most specific first: this account's own pair, then the
    // advanced-settings pair (one registration for every account), then the
    // built-ins. An own registration is the reason either override exists —
    // Google's and Microsoft's quotas are per client id, not per user.
    const bool gmail = provider == OAuthHelper::Gmail;
    QString clientId = m_acct.clientId;
    QString clientSecret = m_acct.clientSecret;
    // Whether the pair in force is the advanced-settings one, whose secret is
    // in the wallet rather than in advanced.conf and so has to be fetched.
    bool advancedPair = false;
    if (clientId.isEmpty()) {
        clientId = AdvancedConfig::s(gmail ? "oauth/googleClientId" : "oauth/microsoftClientId");
        clientSecret.clear();
        advancedPair = !clientId.isEmpty();
    }
    if (clientId.isEmpty()) {
        if (provider == OAuthHelper::Gmail) {
            clientId = QStringLiteral(
                "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com");
            clientSecret = QStringLiteral("kSmqreRr0qwBWJgbf5Y-PjSU");
        } else {
            clientId = QStringLiteral("9e5f94bc-e8a4-4e73-b8be-63364c29d753");
            clientSecret.clear();
        }
    }

    setBusy(true);
    const auto start = [this, provider](const QString &id, const QString &secret) {
        if (!m_accounts.refreshToken().isEmpty()) {
            setStatus(tr("Refreshing sign-in"));
            m_oauth->refresh(provider, id, secret, m_accounts.refreshToken());
        } else {
            setStatus(tr("Sign in in your browser"));
            m_oauth->authorize(provider, id, secret);
        }
    };

    if (advancedPair) {
        // advanced.conf holds the client id and a placeholder; the secret
        // itself is in the wallet, under the key AdvancedConfig named when it
        // put it there. Absent is normal — most installed-app registrations
        // have no secret — so a failed lookup carries on without one.
        setStatus(tr("Reading sign-in details"));
        auto *read = new QKeychain::ReadPasswordJob(kWalletService, this);
        read->setKey(AdvancedConfig::walletKeyFor(gmail
                                                      ? QStringLiteral("oauth/googleClientSecret")
                                                      : QStringLiteral("oauth/microsoftClientSecret")));
        connect(read, &QKeychain::Job::finished, this, [read, clientId, start] {
            start(clientId, read->error() ? QString() : read->textData());
        });
        read->start();
        return;
    }
    start(clientId, clientSecret);
}

void MailClient::connectAccount()
{
    // A local archive never connects — silently, so nothing in the UI ever
    // hints that this account is anything other than a quiet one.
    if (m_acct.local)
        return;
    if (!hasAccount()) {
        Q_EMIT errorOccurred(tr("No account configured yet."));
        return;
    }
    if (!m_accounts.secretReady()) {
        // Wallet lookup still in flight — connect as soon as it lands.
        m_connectWhenReady = true;
        setStatus(tr("Waiting for wallet"));
        return;
    }
    if (m_acct.authType != 0) {
        // OAuth: make sure we hold a live access token first.
        if (m_accounts.accessToken().isEmpty()
            || m_accounts.accessTokenExpiry() <= QDateTime::currentDateTimeUtc()) {
            acquireTokenAndConnect();
            return;
        }
    } else if (m_accounts.password().isEmpty()) {
        Q_EMIT errorOccurred(m_acct.bearerAuth
                                 ? tr("No API token set for this account.")
                                 : tr("No password set for this account."));
        return;
    }

    // Deliberately do NOT clear the folder/message models here: the cached
    // view stays on screen until the fresh server data merges into it —
    // clearing caused seconds of blank panes on every (re)connect.
    teardownSession();

    setBusy(true);
    setStatus(tr("Connecting to %1:%2").arg(m_acct.host).arg(m_acct.port));
    // The account decides which protocol answers; teardownSession() above has
    // already closed whatever the previous one held.
    setBackendProtocol(protocolFromSetting(m_acct.protocol));
    // Everything from here is the backend's: the outcome comes back through
    // connectedChanged / connectionLost / errorOccurred, wired up in
    // connectBackend().
    m_backend->connectAccount(backendCredentials());
}

MailBackend::Credentials MailClient::backendCredentials() const
{
    MailBackend::Credentials c;
    c.host = m_acct.host;
    c.port = m_acct.port;
    c.security = m_acct.security;
    c.user = m_acct.user;
    c.password = m_accounts.password();
    c.accessToken = m_accounts.accessToken();
    // A token account keeps its secret in the same place a password lives (the
    // wallet, under the same key), and it is the header it goes into that
    // differs — so hand it over as the access token, which is what every
    // backend already reads for "put this in Authorization".
    if (m_acct.bearerAuth && m_acct.authType == 0
        && protocolFromSetting(m_acct.protocol) == MailBackend::Protocol::Jmap) {
        c.accessToken = m_accounts.password();
        c.password.clear();
    }
    c.authType = m_acct.authType;
    c.smtpHost = m_acct.smtpHost;
    c.smtpPort = m_acct.smtpPort;
    c.smtpSecurity = m_acct.smtpSecurity;
    return c;
}

void MailClient::handleConnectionLost()
{
    setBusy(false);
    m_pendingFolder = m_selectedFolder; // restore it after reconnect
    teardownSession();
    setStatus(tr("Reconnecting"));
    QTimer::singleShot(2000, this, [this] {
        if (!connected() && hasAccount())
            connectAccount();
    });
}

MailClient::~MailClient()
{
    // Shutdown joins the workers this object owns directly; the cache workers
    // are MaintenanceScheduler's, and its destructor joins those. If quitting
    // ever hangs, these say which join it is sitting in rather than leaving a
    // silent process behind.
    abandonLocalSearch(); // a search worker must not outlive the model it fills
    qCDebug(logTrace, "shutdown: stopping DKIM verifier");
    delete m_verifier;
    m_verifier = nullptr;
    // The importer checks the stop flag per message, so this join is short; a
    // partial import stays browsable and a re-import gets its own account.
    qCDebug(logTrace, "shutdown: stopping import");
    m_importStop.storeRelaxed(1);
    if (m_importThread)
        m_importThread->wait();
    qCDebug(logTrace, "shutdown: stopping cache workers");
    delete m_jobs;
    m_jobs = nullptr;
    qCDebug(logTrace, "shutdown: workers joined");
}

bool MailClient::reclaiming() const
{
    return m_jobs->reclaiming();
}

bool MailClient::indexRebuilding() const
{
    return m_jobs->indexRebuilding();
}

int MailClient::indexRebuildPercent() const
{
    return m_jobs->indexRebuildPercent();
}

bool MailClient::migrationRunning() const
{
    return m_jobs->migrationRunning();
}

QString MailClient::migrationLabel() const
{
    return m_jobs->migrationLabel();
}

int MailClient::migrationPercent() const
{
    return m_jobs->migrationPercent();
}

bool MailClient::reclaimWorthwhile()
{
    return m_jobs->reclaimWorthwhile();
}

QString MailClient::cacheSizeText()
{
    return m_jobs->cacheSizeText();
}

void MailClient::reclaimDiskSpace()
{
    m_jobs->reclaimDiskSpace();
}

/// Name fallback for servers that do not advertise RFC 6154 \All. Gmail always
/// does, so this only catches an odd proxy — deliberately narrow, because a
/// false positive would hide a folder the user actually wants.
bool MailClient::isAllMailName(const QString &mailBox)
{
    return mailBox.compare(QLatin1String("[Gmail]/All Mail"), Qt::CaseInsensitive) == 0
        || mailBox.compare(QLatin1String("[Google Mail]/All Mail"), Qt::CaseInsensitive) == 0;
}

void MailClient::listFolders()
{
    m_backend->listFolders();
}

/// What a folder listing means to the application: which mailboxes exist, how
/// the tree is drawn, which of them are special, and which one to open. None of
/// it is protocol-specific, which is why only the LIST itself moved out.
void MailClient::applyFolderListing(const QList<MailBackend::FolderInfo> &listed,
                                    QChar separator)
{
    setBusy(false);
    // The delimiter every folder path is built with; needed to form destination
    // paths when a folder is reparented.
    if (!separator.isNull())
        m_folderSeparator = separator;

    // A listing is the whole truth about the account it describes, so the
    // special folders start empty: without this an account switch keeps the
    // previous account's Sent (or Trash, or Junk) whenever the new server
    // neither states a role nor has a folder whose name gives it away — and
    // mail would then be filed into a mailbox on another account entirely.
    m_sentFolder.clear();
    m_draftsFolder.clear();
    m_trashFolder.clear();
    m_junkFolder.clear();
    m_allMailFolder.clear();

    QList<FolderModel::Folder> folders;
    for (const auto &info : listed) {
        // A role the server stated outright — RFC 6154 special-use over IMAP,
        // the mandatory `role` property over JMAP. The name guesses further
        // down are only for servers that say nothing.
        switch (info.role) {
        case MailBackend::FolderRole::Sent:
            m_sentFolder = info.path;
            break;
        case MailBackend::FolderRole::Drafts:
            m_draftsFolder = info.path;
            break;
        case MailBackend::FolderRole::Trash:
            m_trashFolder = info.path;
            break;
        case MailBackend::FolderRole::Junk:
            m_junkFolder = info.path;
            break;
        default:
            break;
        }
        // Gmail's All Mail duplicates every message that is already in INBOX
        // and in each label, so caching it stores the same bytes two to four
        // times over. Skipping it here keeps it out of the folder list, out of
        // storeFolders() and out of the backfill queue in one go.
        if (info.role == MailBackend::FolderRole::All || isAllMailName(info.path)) {
            m_allMailFolder = info.path;
            continue;
        }
        FolderModel::Folder f;
        f.mailBox = info.path;
        f.selectable = info.selectable;
        // Level and display name are filled in once the whole list is in, by
        // pathRows() — they depend on which ancestors are really mailboxes,
        // which a single descriptor cannot say.
        folders.append(f);
    }

    // The roles above are what isJunkFolderKey() answers from, and this
    // listing is where they arrive — usually after a folder is already open.
    // Re-deciding here is what makes the cached answer right for an account
    // whose server names its junk folder rather than spelling it "Spam".
    {
        const bool wasJunk = m_selectedIsJunk;
        m_selectedIsJunk = !m_selectedFolder.isEmpty() && isJunkFolderKey(m_selectedFolder);
        if (wasJunk != m_selectedIsJunk)
            Q_EMIT selectedFolderChanged();
    }

    // The same order the rest of the app builds trees in: inbox first,
    // then depth first with every parent directly above its children.
    //
    // The old rule compared whole paths as strings, which put "INBOX-old"
    // between "INBOX" and "INBOX/Work" ('-' sorts below '/') — and the
    // sidebar reads the tree off row order, so the child was orphaned from
    // its parent and the parent lost its expander. It also matched the
    // inbox with startsWith(), so "INBOX-old" was hoisted to the top as if
    // it were the inbox itself.
    const QChar sep = folderSeparator();
    std::sort(folders.begin(), folders.end(),
              [sep](const FolderModel::Folder &a, const FolderModel::Folder &b) {
                  return mailBoxPathLess(a.mailBox, b.mailBox, sep);
              });
    // Indent and display name, once the whole set is known — see pathRows().
    {
        QStringList paths;
        paths.reserve(folders.size());
        for (const auto &f : std::as_const(folders))
            paths.append(f.mailBox);
        const QList<PathRow> rows = pathRows(paths, sep);
        for (int i = 0; i < folders.size(); ++i) {
            folders[i].level = rows.at(i).level;
            folders[i].displayName = rows.at(i).name;
        }
    }
    // Fallback when the server doesn't advertise \Sent special-use.
    if (m_sentFolder.isEmpty()) {
        static const QStringList sentNames = {
            QStringLiteral("sent"), QStringLiteral("sent messages"),
            QStringLiteral("sent items"), QStringLiteral("sent mail")};
        for (const auto &f : std::as_const(folders)) {
            if (sentNames.contains(f.displayName.toLower())) {
                m_sentFolder = f.mailBox;
                break;
            }
        }
    }
    // Fallback when the server doesn't advertise \\Drafts special-use.
    if (m_draftsFolder.isEmpty()) {
        static const QStringList draftNames = {
            QStringLiteral("drafts"), QStringLiteral("draft"),
            QStringLiteral("draft messages")};
        for (const auto &f : std::as_const(folders)) {
            if (draftNames.contains(f.displayName.toLower())) {
                m_draftsFolder = f.mailBox;
                break;
            }
        }
    }
    Q_EMIT draftsFolderChanged();
    // Everything the server listed, before the sidebar drops what it does not
    // draw: the cache is this account's record of which mailboxes exist, and
    // the tree is rebuilt from it (with the same flattening applied) whenever
    // the account is shown without being connected.
    QStringList names;
    names.reserve(folders.size());
    for (const auto &f : std::as_const(folders))
        names.append(f.mailBox);

    flattenGmailNamespace(&folders);
    m_folderModel.setFolders(folders);
    // A fresh folder list restarts the all-folders background sync pass.
    m_sync->restartFolderQueue();
    m_store.storeFolders(accountKey(), names);
    scheduleUnreadRecount(); // the tree just changed; so did which pills exist
    sweepOldSpam(); // needs junkFolderName(), which the listing just settled
    setStatus(countNoun(folders.size(), "folder", "folders"));
    // Drop whatever an earlier version cached for the now-excluded archive.
    // Detection repeats on every connect, so an interrupted purge simply
    // resumes next session instead of leaving rows stranded.
    if (!m_allMailFolder.isEmpty())
        m_jobs->startAllMailPurge(m_store.scopedKey(m_allMailFolder));
    QString target = m_pendingFolder;
    qCDebug(logTrace, "listFolders done: pending=%s selected=%s folders=%d",
            qUtf8Printable(m_pendingFolder), qUtf8Printable(m_selectedFolder),
            int(names.size()));
    m_pendingFolder.clear();
    if (target.isEmpty()) {
        // Whatever is already open wins. Listing folders is a background
        // step that also runs on every reconnect, and forcing INBOX here
        // yanked the user out of the folder they had just opened — the
        // account switch opens the clicked folder from cache first, and
        // this landed a moment later and overrode it.
        target = (!m_selectedFolder.isEmpty() && names.contains(m_selectedFolder))
            ? m_selectedFolder
            : QStringLiteral("INBOX");
    }
    if (!m_allMailFolder.isEmpty() && target == m_allMailFolder)
        target = QStringLiteral("INBOX"); // it is no longer in the list
    // The user is searching this folder right now. This reopen is a
    // background step (connect, reconnect), and openFolder() starts by
    // cancelling the search and refilling the list with fresh folder rows —
    // the GUI serves the user before any worker, so the results stay until
    // the user leaves them. Nothing is lost: the folder tree above is
    // already updated, and clearSearch() reopens the folder itself (which
    // also re-arms the refresh and the IDLE watch).
    if (m_searchActive && target == m_selectedFolder) {
        qCDebug(logTrace, "listFolders done: search active, not reopening %s",
                qUtf8Printable(target));
        return;
    }
    openFolder(target);
}

bool MailClient::isJunkFolder(const QString &mailBox) const
{
    // The server's own answer first: RFC 6154 \Junk over IMAP, the `junk` role
    // over JMAP. It settles *which* mailbox is the junk one — but not that no
    // other holds spam, so the name heuristic below still runs. This drives
    // the hostile-content defaults (plain text, no remote content), where a
    // miss silently downgrades protection and a false positive costs one
    // click, which is why the guessing is generous and stays that way.
    if (!m_junkFolder.isEmpty() && mailBox == m_junkFolder)
        return true;

    static const QStringList junkNames = {
        QStringLiteral("spam"),         QStringLiteral("junk"),
        QStringLiteral("junk e-mail"),  QStringLiteral("junk email"),
        QStringLiteral("junk mail"),    QStringLiteral("bulk mail"),
        QStringLiteral("bulk"),         QStringLiteral("quarantine"),
        // Localized names used by the major providers' web UIs
        QStringLiteral("correo no deseado"), QStringLiteral("no deseado"),
        QStringLiteral("courrier indésirable"), QStringLiteral("indésirables"),
        QStringLiteral("pourriel"),     QStringLiteral("unerwünscht"),
        QStringLiteral("posta indesiderata"), QStringLiteral("indesiderata"),
        QStringLiteral("lixo eletrônico"), QStringLiteral("lixo eletronico"),
        QStringLiteral("ongewenst"),    QStringLiteral("ongewenste e-mail"),
        QStringLiteral("uønsket e-post"), QStringLiteral("skräppost"),
        QStringLiteral("roskaposti"),   QStringLiteral("uønsket post"),
        QStringLiteral("wiadomości-śmieci"), QStringLiteral("niechciane"),
        QStringLiteral("nevyžádaná pošta"), QStringLiteral("nevyžiadaná pošta"),
        QStringLiteral("levélszemét"),  QStringLiteral("спам"),
        QStringLiteral("нежелательная почта"), QStringLiteral("垃圾邮件"),
        QStringLiteral("垃圾郵件"),      QStringLiteral("迷惑メール"),
        QStringLiteral("스팸")};
    const QChar sep = mailBox.contains(QLatin1Char('/')) ? QLatin1Char('/')
                                                         : QLatin1Char('.');
    const QString leaf = mailBox.section(sep, -1).toLower();
    if (junkNames.contains(leaf))
        return true;
    // Providers decorate the leaf ("Spam (2)", "Junk-E-Mail"); a substring test
    // on these two roots costs nothing and catches the decorated variants.
    return leaf.contains(QLatin1String("spam")) || leaf.contains(QLatin1String("junk"));
}

QString MailClient::trashFolderName() const
{
    // Stated by the server (\Trash / the `trash` role) if it said anything.
    if (!m_trashFolder.isEmpty())
        return m_trashFolder;

    static const QStringList trashNames = {
        QStringLiteral("trash"), QStringLiteral("deleted items"),
        QStringLiteral("deleted messages"), QStringLiteral("deleted"),
        QStringLiteral("bin")};
    const QStringList boxes = m_folderModel.allMailBoxes();
    for (const QString &mailBox : boxes) {
        const QChar sep = mailBox.contains(QLatin1Char('/')) ? QLatin1Char('/')
                                                             : QLatin1Char('.');
        if (trashNames.contains(mailBox.section(sep, -1).toLower()))
            return mailBox;
    }
    return {};
}

QString MailClient::junkFolderName() const
{
    if (!m_junkFolder.isEmpty())
        return m_junkFolder;
    const QStringList boxes = m_folderModel.allMailBoxes();
    for (const QString &mailBox : boxes) {
        if (isJunkFolder(mailBox))
            return mailBox;
    }
    return {};
}

bool MailClient::isTrashFolder() const
{
    return !m_selectedFolder.isEmpty() && m_selectedFolder == trashFolderName();
}

/// Removes the uids from the visible list and the on-disk cache.
void MailClient::purgeDeleted(const QList<qint64> &uids)
{
    m_messageModel.removeByUids(uids);
    m_store.removeMessages(m_selectedFolder, uids);
    invalidateMissingBodies();
}

void MailClient::deleteMessages(const QVariantList &rows)
{
    if (!connected()) {
        Q_EMIT errorOccurred(tr("Not connected — cannot delete messages."));
        return;
    }
    // ids for the backend (it names messages the protocol's way), uids for the
    // model and cache updates that follow a success.
    QStringList ids;
    auto uids = std::make_shared<QList<qint64>>();
    for (const QVariant &v : rows) {
        const qint64 uid = m_messageModel.uidAt(v.toInt());
        if (uid > 0) {
            ids.append(QString::number(uid));
            uids->append(uid);
        }
    }
    if (uids->isEmpty())
        return;

    // Spam skips the trash when the setting says so — filing junk under
    // "deleted" only means clearing it out twice.
    const bool permanent = deleteIsPermanent();
    const QString trash = trashFolderName();
    if (!permanent && trash.isEmpty()) {
        Q_EMIT errorOccurred(tr("No trash folder found on the server."));
        return;
    }

    setBusy(true);
    // No in-progress crumb — the busy spinner covers it; only the result shows.

    // Cache and model are updated only once the server has confirmed, so a
    // failure never leaves mail on the server that mailove has forgotten.
    const auto done = [this, uids](const QString &crumb) {
        return [this, uids, crumb](MailBackend::Error error, const QString &message) {
            setBusy(false);
            if (error != MailBackend::Error::None) {
                Q_EMIT errorOccurred(message);
                return;
            }
            purgeDeleted(*uids);
            setStatus(crumb.arg(uids->size()));
        };
    };
    if (permanent)
        m_backend->deleteMessages(m_selectedFolder, ids, done(tr("%1 deleted permanently")));
    else
        m_backend->moveMessages(m_selectedFolder, ids, trash, done(tr("%1 moved to trash")));
}

void MailClient::markAsNotSpam(const QVariantList &rows)
{
    // In the junk folder this *is* the manual move out, reached by a different
    // gesture — so it goes through the same path rather than a second copy of
    // it. moveMessagesTo() already treats leaving the junk folder as the
    // reversal it is: it allowlists the senders, moves the mail, drops the
    // cached rows and says so. A rescue that behaved differently depending on
    // which button triggered it would be a bug waiting to happen.
    if (isJunkFolderKey(m_selectedFolder)) {
        moveMessagesTo(rows, QStringLiteral("INBOX"));
        return;
    }

    // Outside the junk folder there is nothing to move: the message is already
    // where the user wants it and only the mark is wrong.
    int cleared = 0;
    for (const QVariant &v : rows) {
        const int row = v.toInt();
        const qint64 uid = m_messageModel.uidAt(row);
        if (uid < 0)
            continue;
        // Allowlist the sender, not just this message. A false positive means
        // the rule was wrong about the person; correcting only the one message
        // would let the next one from them be marked all over again.
        const QString sender = SpamHeuristics::addressOf(m_messageModel.fromAt(row));
        if (!sender.isEmpty())
            m_store.addRecipient(sender);
        m_messageModel.clearSpam(uid);
        m_store.setSpamVerdict(m_selectedFolder, uid, 0, 3, QString());
        ++cleared;
    }
    if (cleared > 0)
        setStatus(tr("Not spam — sender added to your known contacts"));
}

void MailClient::markAsJunk(const QVariantList &rows)
{
    if (!connected()) {
        Q_EMIT errorOccurred(tr("Not connected — cannot move messages to spam."));
        return;
    }
    const QString junk = junkFolderName();
    if (junk.isEmpty()) {
        Q_EMIT errorOccurred(tr("No spam folder found on the server."));
        return;
    }
    if (m_selectedFolder == junk)
        return;

    // ids for the backend (it names messages the protocol's way), uids for the
    // model and cache updates that follow a success.
    QStringList ids;
    auto uids = std::make_shared<QList<qint64>>();
    for (const QVariant &v : rows) {
        const qint64 uid = m_messageModel.uidAt(v.toInt());
        if (uid > 0) {
            ids.append(QString::number(uid));
            uids->append(uid);
        }
    }
    if (uids->isEmpty())
        return;

    setBusy(true);
    // No in-progress crumb — the busy spinner covers it; only the result shows.
    m_backend->moveMessages(m_selectedFolder, ids, junk,
                            [this, uids](MailBackend::Error error, const QString &message) {
        setBusy(false);
        if (error != MailBackend::Error::None) {
            Q_EMIT errorOccurred(message);
            return;
        }
        purgeDeleted(*uids);
        setStatus(tr("%1 moved to spam").arg(uids->size()));
    });
}

void MailClient::moveMessagesTo(const QVariantList &rows, const QString &targetFolder)
{
    if (!connected()) {
        Q_EMIT errorOccurred(tr("Not connected — cannot move messages."));
        return;
    }
    if (targetFolder.isEmpty() || targetFolder == m_selectedFolder)
        return;

    // ids for the backend (it names messages the protocol's way), uids for the
    // model and cache updates that follow a success.
    QStringList ids;
    auto uids = std::make_shared<QList<qint64>>();
    // Taking a message *out* of the junk folder is the same statement as
    // pressing "Not spam", made with a different gesture, and it has to be
    // recorded the same way. Without this the message keeps its old score, is
    // re-scored from scratch when it lands, and can be marked all over again in
    // its new folder — and the next message from that sender certainly will be.
    //
    // The sender is what gets remembered, not the message: a false positive
    // means the rules were wrong about a person, and correcting one message
    // would leave the next one from them to be marked again.
    //
    // Only a rescue counts. Moving junk on to the trash, or filing it in
    // another junk folder, is agreement with the verdict rather than a reversal
    // of it, and must not allowlist anybody.
    const bool rescuedFromJunk = isJunkFolderKey(m_selectedFolder)
        && !isJunkFolderKey(targetFolder)
        && targetFolder != trashFolderName();
    auto rescuedSenders = std::make_shared<QStringList>();
    for (const QVariant &v : rows) {
        const int row = v.toInt();
        const qint64 uid = m_messageModel.uidAt(row);
        if (uid > 0) {
            ids.append(QString::number(uid));
            uids->append(uid);
            if (rescuedFromJunk) {
                const QString sender = SpamHeuristics::addressOf(m_messageModel.fromAt(row));
                if (!sender.isEmpty())
                    rescuedSenders->append(sender);
            }
        }
    }
    if (uids->isEmpty())
        return;

    setBusy(true);
    m_backend->moveMessages(m_selectedFolder, ids, targetFolder,
                            [this, uids, targetFolder, rescuedSenders](
                                MailBackend::Error error, const QString &message) {
        setBusy(false);
        if (error != MailBackend::Error::None) {
            Q_EMIT errorOccurred(message);
            return;
        }
        // After the move, so a failed move records nothing.
        for (const QString &sender : std::as_const(*rescuedSenders))
            m_store.addRecipient(sender);
        purgeDeleted(*uids);
        // The destination's cached header list no longer matches what the
        // server holds; its next open re-syncs it anyway, but the missing
        // -bodies estimate is shared and would be stale immediately.
        invalidateMissingBodies();
        if (!rescuedSenders->isEmpty()) {
            setStatus(tr("%1 moved to %2 — sender added to your known contacts")
                          .arg(uids->size())
                          .arg(folderLeaf(targetFolder)));
        } else {
            setStatus(tr("%1 moved to %2").arg(uids->size()).arg(folderLeaf(targetFolder)));
        }
    });
}

QChar MailClient::folderSeparator() const
{
    // An archive is built by the importer, which always joins with '/'. Asking
    // it to guess is what let a previously-connected IMAP account's '.' leak in
    // and turn "mail.example.com/Inbox" into a leaf of "com/Inbox".
    if (m_acct.local)
        return QLatin1Char('/');
    if (!m_folderSeparator.isNull())
        return m_folderSeparator;
    // Before the first LIST lands, infer it the way the special-folder
    // lookups do: '/' when any path uses it, '.' otherwise.
    const QStringList boxes = m_folderModel.allMailBoxes();
    for (const QString &box : boxes) {
        if (box.contains(QLatin1Char('/')))
            return QLatin1Char('/');
    }
    return QLatin1Char('.');
}

QString MailClient::folderLeaf(const QString &mailBox) const
{
    return mailBox.section(folderSeparator(), -1);
}

QString MailClient::folderParent(const QString &mailBox) const
{
    const QChar sep = folderSeparator();
    const int cut = mailBox.lastIndexOf(sep);
    return cut < 0 ? QString() : mailBox.left(cut);
}

QString MailClient::folderDisplayParent(const QString &mailBox) const
{
    // Read from the ancestors that really are mailboxes, exactly as pathRows()
    // draws the tree. An imported archive keeps its mail under the server
    // directory it came from ("mail.example.com/Inbox") without that directory
    // being a mailbox, so the string prefix is not the parent on screen — and
    // a drop has to mean what the user sees.
    const QChar sep = folderSeparator(); // the account's real delimiter, not a guess
    const QStringList boxes = m_folderModel.allMailBoxes();
    const QSet<QString> known(boxes.cbegin(), boxes.cend());
    const QStringList parts = mailBox.split(sep);
    QString parent;
    QString prefix;
    for (int i = 0; i + 1 < parts.size(); ++i) {
        prefix += (i == 0 ? QString() : QString(sep)) + parts.at(i);
        if (known.contains(prefix))
            parent = prefix;
    }
    return parent;
}

QString MailClient::folderDisplayLeaf(const QString &mailBox) const
{
    const QString parent = folderDisplayParent(mailBox);
    return parent.isEmpty() ? mailBox : mailBox.mid(parent.size() + 1);
}

QString MailClient::freeChildPath(const QString &parent, const QString &leaf) const
{
    const QChar sep = folderSeparator();
    const QStringList boxes = m_folderModel.allMailBoxes();
    const auto pathOf = [&](const QString &name) {
        return parent.isEmpty() ? name : parent + sep + name;
    };
    QString candidate = pathOf(leaf);
    for (int n = 2; boxes.contains(candidate); ++n)
        candidate = pathOf(QStringLiteral("%1 (%2)").arg(leaf).arg(n));
    return candidate;
}

QStringList MailClient::folderSubtree(const QString &mailBox) const
{
    const QString prefix = mailBox + folderSeparator();
    QStringList out;
    const QStringList boxes = m_folderModel.allMailBoxes();
    for (const QString &box : boxes) {
        if (box == mailBox || box.startsWith(prefix))
            out.append(box);
    }
    // Deepest first: a server may refuse to DELETE a mailbox that still has
    // children, and never the other way round.
    std::sort(out.begin(), out.end(), [](const QString &a, const QString &b) {
        return a.size() > b.size();
    });
    return out;
}

bool MailClient::folderProtected(const QString &mailBox) const
{
    if (mailBox.isEmpty())
        return true;
    // A local archive is plain storage: no folder has server-side meaning, so
    // even INBOX, Trash or Sent may be renamed, moved or deleted.
    if (m_acct.local)
        return false;
    if (mailBox.compare(QLatin1String("INBOX"), Qt::CaseInsensitive) == 0)
        return true;
    // Drafts belongs here with the others: it is a RFC 6154 special-use
    // mailbox, and a server that requires one recreates it the moment it is
    // renamed away — which looks exactly like the move left a copy behind,
    // because the folder is now in both places.
    return mailBox == trashFolderName() || mailBox == junkFolderName()
        || mailBox == m_sentFolder || mailBox == m_draftsFolder
        || mailBox == m_allMailFolder;
}

bool MailClient::canMoveFolder(const QString &mailBox, const QString &newParent) const
{
    // A local archive edits its cache directly, so being offline is its
    // normal, fully-capable state.
    if ((!connected() && !m_acct.local) || mailBox.isEmpty() || mailBox == newParent)
        return false;
    if (folderProtected(mailBox))
        return false;
    const QChar sep = folderSeparator();
    if (folderDisplayParent(mailBox) == newParent)
        return false; // already sits there
    if (newParent.startsWith(mailBox + sep))
        return false; // a folder cannot become its own descendant
    const QStringList boxes = m_folderModel.allMailBoxes();
    if (!newParent.isEmpty() && !boxes.contains(newParent))
        return false;
    // Occupied destination: the server would reject the RENAME, and merging
    // two mailboxes is not something a drop should be able to mean.
    const QString leaf = folderDisplayLeaf(mailBox);
    return !boxes.contains(newParent.isEmpty() ? leaf : newParent + sep + leaf);
}

void MailClient::moveFolder(const QString &mailBox, const QString &newParent)
{
    if (!m_acct.local && (!connected())) {
        Q_EMIT errorOccurred(tr("Not connected — cannot move folders."));
        return;
    }
    if (!canMoveFolder(mailBox, newParent))
        return;
    const QChar sep = folderSeparator();
    const QString leaf = folderDisplayLeaf(mailBox);
    const QString dest = newParent.isEmpty() ? leaf : newParent + sep + leaf;
    renameFolderOnServer(mailBox, dest,
                         newParent.isEmpty()
                             ? tr("%1 moved to the top level").arg(leaf)
                             : tr("%1 moved into %2").arg(leaf, folderLeaf(newParent)));
}

QString MailClient::folderRenameBlockedReason(const QString &mailBox) const
{
    if (mailBox.isEmpty())
        return tr("No folder selected");
    if (m_acct.local)
        return {}; // plain storage: no folder here means anything to a server
    if (!connected())
        return tr("Renaming needs a connection");
    // Named after the folder, so the menu says which one it is talking about.
    // RFC 3501 §6.3.5: renaming INBOX moves its messages out and leaves INBOX
    // in place, so it is not a rename at all. RFC 6154 special-use: a server
    // that requires one recreates it under the old name straight away.
    if (mailBox.compare(QLatin1String("INBOX"), Qt::CaseInsensitive) == 0)
        return tr("INBOX cannot be renamed (RFC 3501)");
    if (mailBox == m_sentFolder || mailBox == m_draftsFolder
        || mailBox == trashFolderName() || mailBox == junkFolderName()
        || mailBox == m_allMailFolder) {
        return tr("%1 cannot be renamed (RFC 6154)").arg(folderDisplayLeaf(mailBox));
    }
    return {};
}

void MailClient::renameFolder(const QString &mailBox, const QString &newName)
{
    const QString leaf = newName.trimmed();
    if (leaf.isEmpty() || !folderRenameBlockedReason(mailBox).isEmpty())
        return;
    const QChar sep = folderSeparator();
    if (leaf.contains(sep)) {
        // A separator in the name would reparent the folder, which is what
        // dragging it is for. Renaming only ever changes the last step.
        Q_EMIT errorOccurred(tr("A folder name cannot contain %1.").arg(sep));
        return;
    }
    if (leaf == folderDisplayLeaf(mailBox))
        return; // unchanged
    const QString parent = folderDisplayParent(mailBox);
    const QString dest = parent.isEmpty() ? leaf : parent + sep + leaf;
    if (m_folderModel.allMailBoxes().contains(dest)) {
        Q_EMIT errorOccurred(tr("A folder named %1 is already there.").arg(leaf));
        return;
    }
    if (!m_acct.local && (!connected())) {
        Q_EMIT errorOccurred(tr("Not connected — cannot rename folders."));
        return;
    }
    renameFolderOnServer(mailBox, dest, tr("Renamed to %1").arg(leaf));
}

bool MailClient::folderDeleteIsPermanent(const QString &mailBox) const
{
    const QString trash = trashFolderName();
    if (trash.isEmpty())
        return true; // nowhere to move it to
    return mailBox == trash || mailBox.startsWith(trash + folderSeparator());
}

void MailClient::deleteFolder(const QString &mailBox)
{
    if (!m_acct.local && (!connected())) {
        Q_EMIT errorOccurred(tr("Not connected — cannot delete folders."));
        return;
    }
    if (mailBox.isEmpty() || folderProtected(mailBox))
        return;

    const QString leaf = folderLeaf(mailBox);
    if (!folderDeleteIsPermanent(mailBox)) {
        renameFolderOnServer(mailBox, freeChildPath(trashFolderName(), leaf),
                             tr("%1 moved to trash").arg(leaf));
        return;
    }

    if (m_acct.local) {
        // No server holds a copy: dropping the subtree from the folder list
        // and purging its cached mail IS the deletion. The purge itself runs
        // chunked on the worker; the tree and the open folder update now.
        const QStringList doomed = folderSubtree(mailBox);
        QStringList remaining = m_folderModel.allMailBoxes();
        for (const QString &box : doomed)
            remaining.removeAll(box);
        m_store.storeFolders(accountKey(), remaining);
        m_folderModel.setFolders(foldersFromPaths(remaining));
        purgeCachedFolders(doomed);
        if (doomed.contains(m_selectedFolder)) {
            // Even INBOX may be gone here — land on whatever still exists.
            if (remaining.contains(QStringLiteral("INBOX")))
                openFolder(QStringLiteral("INBOX"));
            else if (!remaining.isEmpty())
                openFolder(remaining.first());
            else {
                m_selectedFolder.clear();
                Q_EMIT selectedFolderChanged();
                m_messageModel.clear();
            }
        }
        setStatus(tr("%1 deleted").arg(leaf));
        return;
    }

    // Already in the trash: this really removes it. Subfolders go first —
    // deepest first, one job at a time, since a server may refuse to delete a
    // mailbox that still has children.
    auto remaining = std::make_shared<QStringList>(folderSubtree(mailBox));
    if (remaining->isEmpty())
        return;
    const auto deleted = std::make_shared<QStringList>();

    setBusy(true);
    // Chained rather than fired together, so the first failure stops the rest
    // — and a backend that serializes its requests gains nothing from the
    // parallel version anyway.
    auto step = std::make_shared<std::function<void()>>();
    *step = [this, remaining, deleted, step, leaf] {
        if (remaining->isEmpty()) {
            purgeCachedFolders(*deleted);
            // Whatever was open inside the deleted subtree is gone; land on
            // INBOX rather than on a mailbox the server no longer has.
            if (deleted->contains(m_selectedFolder))
                m_pendingFolder = QStringLiteral("INBOX");
            setStatus(tr("%1 deleted").arg(leaf));
            listFolders(); // clears busy when the new tree arrives
            return;
        }
        const QString box = remaining->takeFirst();
        m_backend->deleteFolder(box, [this, box, deleted, step](MailBackend::Error error,
                                                                const QString &message) {
            if (error != MailBackend::Error::None) {
                setBusy(false);
                setStatus(tr("Deleting folder failed"));
                Q_EMIT errorOccurred(message);
                if (!deleted->isEmpty()) {
                    purgeCachedFolders(*deleted); // whatever did go, goes from the cache too
                    setBusy(true);
                    listFolders();
                }
                return;
            }
            deleted->append(box);
            (*step)();
        });
    };
    (*step)();
}

void MailClient::renameFolderOnServer(const QString &from, const QString &to,
                                      const QString &doneStatus)
{
    setBusy(true);
    if (m_acct.local) {
        // No server to ask — the cache re-key IS the rename, and it also
        // rewrites the stored folder list (see MailStore::renameFolderOn).
        // Unlike the connected path, the tree refresh and the selection
        // follow-up wait for the worker: reopening a folder whose rows are
        // still being re-keyed would show it half-empty.
        renameCachedFolder(from, to, [this, from, to, doneStatus] {
            const QString prefix = from + folderSeparator();
            if (m_selectedFolder == from || m_selectedFolder.startsWith(prefix)) {
                setSelectedFolder(to + m_selectedFolder.mid(from.size()));
                Q_EMIT selectedFolderChanged();
            }
            // The re-key rewrites each path in place but leaves the stored row
            // order alone, and the tree is drawn from that order — a folder
            // moved under a parent further down the list would render as an
            // indented orphan. A connected account gets a freshly sorted list
            // back from the server's LIST; here nobody else will sort it.
            QStringList boxes = m_store.cachedFolders(accountKey());
            sortMailBoxPaths(&boxes, folderSeparator());
            m_store.storeFolders(accountKey(), boxes);
            m_folderModel.setFolders(foldersFromPaths(boxes));
            setBusy(false);
            if (!m_selectedFolder.isEmpty())
                openFolder(m_selectedFolder);
            setStatus(doneStatus);
        });
        return;
    }
    m_backend->renameFolder(from, to, [this, from, to, doneStatus](
                                          MailBackend::Error error, const QString &message) {
        if (error != MailBackend::Error::None) {
            setBusy(false);
            setStatus(tr("Moving folder failed"));
            Q_EMIT errorOccurred(message);
            return;
        }
        // The mail did not change, only the path it is filed under — re-key
        // the cache instead of making the user sync the folder again. It runs
        // in the background: a header sync that lands on the new path while it
        // is still going may lose a row or two to the re-key, which the next
        // refresh puts back. Blocking the UI for a subtree rewrite would be a
        // far worse trade.
        renameCachedFolder(from, to);
        // RENAME takes the subtree with it, so the open folder may be sitting
        // at a path that no longer exists. Follow it to the new one.
        const QString prefix = from + folderSeparator();
        if (m_selectedFolder == from || m_selectedFolder.startsWith(prefix))
            m_pendingFolder = to + m_selectedFolder.mid(from.size());
        setStatus(doneStatus);
        listFolders(); // clears busy when the new tree arrives
    });
}

void MailClient::renameCachedFolder(const QString &from, const QString &to,
                                    std::function<void()> done)
{
    m_jobs->renameCachedFolder(accountKey(), from, to, folderSeparator(),
                               std::move(done));
}

void MailClient::pollOtherAccounts()
{
    if (m_accountPollBusy)
        return; // the previous round is still going; skip this tick
    const QList<QVariantMap> accounts = m_accounts.all();
    auto queue = std::make_shared<QList<QVariantMap>>();
    for (int i = 0; i < accounts.size(); ++i) {
        if (i == currentAccount())
            continue; // it has a live session and IDLE of its own
        const QVariantMap &a = accounts.at(i);
        if (a.value(QStringLiteral("local"), false).toBool())
            continue; // an archive has no server to ask
        if (a.value(QStringLiteral("host")).toString().isEmpty()
            || a.value(QStringLiteral("user")).toString().isEmpty())
            continue;
        queue->append(a);
    }
    if (queue->isEmpty())
        return;

    m_accountPollBusy = true;
    // One at a time. Firing every account at once would open as many
    // simultaneous logins as there are accounts, which is exactly what servers
    // that count connections per IP object to.
    auto step = std::make_shared<std::function<void()>>();
    *step = [this, queue, step] {
        if (queue->isEmpty()) {
            m_accountPollBusy = false;
            scheduleUnreadRecount(); // fold the new counts into the sidebar
            return;
        }
        const QVariantMap account = queue->takeFirst();
        pollAccount(account, [step] { (*step)(); });
    };
    (*step)();
}

void MailClient::pollAccount(const QVariantMap &account, const std::function<void()> &done)
{
    const QString host = account.value(QStringLiteral("host")).toString();
    const QString user = account.value(QStringLiteral("user")).toString();
    const int port = account.value(QStringLiteral("port"), 993).toInt();
    const int security = account.value(QStringLiteral("security"), int(SslTls)).toInt();
    const int authType = account.value(QStringLiteral("authType"), 0).toInt();
    const bool bearerAuth = account.value(QStringLiteral("bearerAuth"), false).toBool();
    const MailBackend::Protocol protocol = protocolFromSetting(
        account.value(QStringLiteral("protocol"),
                      static_cast<int>(MailBackend::Protocol::Imap)).toInt());
    QString key = account.value(QStringLiteral("cacheKey")).toString();
    if (key.isEmpty())
        key = user + QLatin1Char('@') + host;

    // A backend instance is one account, so an account that is not the open one
    // gets a short-lived backend of its own. That also means a JMAP account
    // polls correctly without this code knowing anything about either protocol.
    auto connectWith = [this, host, port, security, user, authType, bearerAuth, protocol,
                        key, done]
                       (const QString &secret) {
        if (secret.isEmpty()) {
            done();
            return;
        }
        MailBackend::Credentials creds;
        creds.host = host;
        creds.port = port;
        creds.security = security;
        creds.user = user;
        creds.authType = authType;
        if (authType != 0 || (bearerAuth && protocol == MailBackend::Protocol::Jmap))
            creds.accessToken = secret;
        else
            creds.password = secret;

        MailBackend *backend = makeBackend(protocol, this);
        // done() must run exactly once however this ends — the queue of
        // accounts stops moving otherwise, and an unreachable server is the
        // normal case here, not an exceptional one.
        auto finished = std::make_shared<bool>(false);
        const auto finish = [backend, done, finished] {
            if (*finished)
                return;
            *finished = true;
            backend->disconnectAccount();
            backend->deleteLater();
            done();
        };
        connect(backend, &MailBackend::errorOccurred, this,
                [finish](MailBackend::Error, const QString &) { finish(); });
        connect(backend, &MailBackend::connectionLost, this, finish);
        connect(backend, &MailBackend::connectedChanged, this,
                [this, backend, key, host, finish](bool up) {
            if (!up)
                return;
            QStringList folders = m_store.cachedFolders(key);
            if (folders.isEmpty()) {
                // Never synced: INBOX is the one mailbox every server has.
                folders.append(QStringLiteral("INBOX"));
            }
            backend->folderUnreadCounts(folders, [this, backend, key, host, folders, finish](
                    MailBackend::Error, const QHash<QString, int> &counts, const QString &) {
                // Replace wholesale: a folder that has dropped to zero unread
                // must lose its pill, which merging would never do.
                m_unreadByAccount.insert(key, counts);
                ++m_cachedFolderRevision;
                Q_EMIT cachedFoldersChanged();
                // The counts are the news; this is the mail behind them. The
                // pill and the rows land in the same visit, so switching to
                // the account shows what the badge already promised instead of
                // having to sync it then.
                QStringList known = folders;
                for (auto it = counts.constBegin(); it != counts.constEnd(); ++it) {
                    if (!known.contains(it.key()))
                        known.append(it.key()); // a folder cached under another name
                }
                syncBackgroundFolders(backend, key, host, known, finish);
            });
        });
        backend->connectAccount(creds);
    };

    // OAuth accounts keep a refresh token rather than a password; renew it
    // silently, exactly as the foreground connection does.
    if (authType != 0) {
        auto *read = new QKeychain::ReadPasswordJob(kWalletService, this);
        // Must match oauthWalletKey(): the token is stored per user@host, not
        // under the cache key, which for an imported account differs.
        read->setKey(QStringLiteral("oauth-refresh:") + user + QLatin1Char('@') + host);
        connect(read, &QKeychain::Job::finished, this,
                [this, read, account, connectWith, done] {
            if (read->error() || read->textData().isEmpty()) {
                done();
                return;
            }
            auto *oauth = new OAuthHelper(this);
            // authType is the provider id (see the foreground path).
            const auto provider = OAuthHelper::Provider(
                account.value(QStringLiteral("authType"), 0).toInt());
            connect(oauth, &OAuthHelper::tokensReady, this,
                    [oauth, connectWith](const QString &accessToken, const QString &,
                                         const QDateTime &) {
                oauth->deleteLater();
                connectWith(accessToken);
            });
            connect(oauth, &OAuthHelper::failed, this, [oauth, done](const QString &) {
                oauth->deleteLater();
                done();
            });
            oauth->refresh(provider,
                           account.value(QStringLiteral("clientId")).toString(),
                           account.value(QStringLiteral("clientSecret")).toString(),
                           read->textData());
        });
        read->start();
        return;
    }

    auto *read = new QKeychain::ReadPasswordJob(kWalletService, this);
    read->setKey(AccountStore::walletKeyFor(user, host));
    connect(read, &QKeychain::Job::finished, this, [read, connectWith, done] {
        if (read->error()) {
            done();
            return;
        }
        connectWith(read->textData());
    });
    read->start();
}

/// \a folders with the inbox pulled to the front. Servers disagree on the
/// spelling ("INBOX" over IMAP, "Inbox" over JMAP) and the cache holds whichever
/// one this account reported, so match without case rather than assuming
/// either; an account with nothing cached yet gets the IMAP spelling, which is
/// the one mailbox every server has.
static QStringList inboxFirst(const QStringList &folders)
{
    QStringList ordered;
    ordered.reserve(folders.size() + 1);
    for (const QString &folder : folders) {
        if (folder.compare(QStringLiteral("INBOX"), Qt::CaseInsensitive) == 0)
            ordered.prepend(folder);
        else
            ordered.append(folder);
    }
    if (ordered.isEmpty()
        || ordered.constFirst().compare(QStringLiteral("INBOX"), Qt::CaseInsensitive) != 0) {
        ordered.prepend(QStringLiteral("INBOX"));
    }
    return ordered;
}

void MailClient::syncBackgroundFolders(MailBackend *backend, const QString &key,
                                       const QString &host, const QStringList &folders,
                                       const std::function<void()> &done)
{
    auto queue = std::make_shared<QStringList>(inboxFirst(folders));
    // Which folder the signals below belong to. A reply can arrive after this
    // pass has moved on, and the folder it names is the only way to tell.
    auto current = std::make_shared<QString>();
    // Headers arrive as a stream of batches and are collected here rather than
    // in SyncEngine: that engine holds the *open* account's cursors, and a
    // background account writing into them would corrupt the folder the user
    // is actually reading.
    auto rows = std::make_shared<QList<MessageListModel::Header>>();
    // A cache the server has voided (UIDVALIDITY changed) is not something a
    // background pass can put right: clearing a folder touches attachment
    // refcounts, the FTS rows and possibly the open list model, so it stays a
    // foreground job. Merging fresh uids into rows that no longer mean anything
    // would be worse than waiting, so that folder is skipped and left to the
    // next switch to this account.
    auto voided = std::make_shared<bool>(false);
    const QStringList authDomains =
        m_authVerification ? trustedAuthDomainsForHost(host) : QStringList();

    connect(backend, &MailBackend::headersFetched, this,
            [this, rows, current, authDomains](const QString &folder,
                                               const QList<MailBackend::HeaderInfo> &infos) {
                if (folder == *current)
                    appendScoredHeaders(*rows, folder, infos, authDomains);
            });
    connect(backend, &MailBackend::folderInvalidated, this,
            [voided, current](const QString &folder) {
                if (folder == *current)
                    *voided = true;
            });

    // One step per folder, in order. Strictly sequential: the folders of a
    // background account are worth keeping current, but not at the price of
    // firing a mailbox's worth of requests at a server nobody is waiting on.
    auto next = std::make_shared<std::function<void()>>();
    *next = [this, backend, key, queue, current, rows, voided, done] {
        if (queue->isEmpty()) {
            done();
            return;
        }
        rows->clear();
        *voided = false;
        *current = queue->takeFirst();
        backend->openFolder(*current, m_store.syncStateIn(key, *current));
    };

    connect(backend, &MailBackend::folderOpened, this,
            [this, backend, key, current, rows, voided, next](const QString &folder,
                                                              qint64 messageCount,
                                                              const QString &syncToken) {
        if (folder != *current)
            return;
        // JMAP resumes its delta from this; the UPDATE is a no-op for a folder
        // with nothing cached yet, which then simply pages the newest headers
        // below instead of asking for a delta.
        m_store.setSyncStateIn(key, folder, syncToken);
        if (*voided || messageCount <= 0) {
            (*next)();
            return;
        }
        const qint64 maxUid = m_store.maxCachedUidIn(key, folder);
        const int cached = m_store.cachedHeaderCountIn(key, folder);
        const auto stored = [this, key, folder, rows, next](MailBackend::Error error,
                                                            const QString &) {
            if (error == MailBackend::Error::None && !rows->isEmpty()) {
                m_store.storeHeadersIn(key, folder, *rows);
                // Per folder rather than once at the end, so the inbox's new
                // mail reaches the sidebar before the rest of the pass runs.
                // The sidebar re-reads the cached tree on this; the message
                // list of an account that is not open has nothing to update.
                ++m_cachedFolderRevision;
                Q_EMIT cachedFoldersChanged();
            }
            // A folder the server refused is one folder's loss, not the pass's:
            // carry on rather than leaving everything behind it unsynced.
            (*next)();
        };
        if (cached > 0 && maxUid > 0) {
            // Only what arrived since — the whole point of polling cheaply.
            // A folder that has not changed costs one open and an empty answer.
            backend->fetchHeadersSince(folder, QString::number(maxUid), stored);
        } else {
            // Never synced: the newest page, same as opening it would give.
            // Not marked background — this backend is this poll's alone, so
            // there is no interactive work for it to queue in front of.
            backend->fetchHeaderWindow(folder, 0, 100, /*background=*/false, stored);
        }
    });

    // A folder that cannot even be opened reaches finish() through the
    // errorOccurred wiring pollAccount() put on this backend, which ends the
    // whole account's round. That is the pre-existing behaviour for a poll that
    // hits a bad reply, and the next tick starts it over.
    (*next)();
}

void MailClient::sweepOldSpam()
{
    // A local archive is an archive: imported mail is the only copy there is,
    // and quietly eating part of it is not something an import should do.
    qCDebug(logTrace, "spam sweep: days=%d local=%d swept=%d connected=%d",
            m_spamRetentionDays, int(m_acct.local), int(m_spamSwept), int(connected()));
    if (m_spamRetentionDays <= 0 || m_acct.local || m_spamSwept || !connected())
        return;
    const QString junk = junkFolderName();
    if (junk.isEmpty()) {
        qCWarning(logTrace, "spam sweep: no spam folder among %lld mailboxes",
                  qint64(m_folderModel.allMailBoxes().size()));
        return;
    }
    m_spamSwept = true;
    qCDebug(logTrace, "spam sweep: folder=%s older than %d days",
            qUtf8Printable(junk), m_spamRetentionDays);

    // Which messages are old is decided from the dates mailove already holds,
    // not from a server-side search.
    //
    // Both IMAP criteria were tried and both matched nothing. BEFORE is
    // INTERNALDATE — when this mailbox received the message — so a recently
    // synced account stamps every message as arriving now and none is ever
    // old. SENTBEFORE should have worked and did not, which leaves the
    // criterion unexplained; the cache needs no explanation, because it holds
    // the very dates the list shows. It is also the only formulation that
    // survives the move off IMAP: JMAP has its own query language, and the
    // sweep's rule is not a protocol matter.
    //
    // So what gets deleted is exactly what you can see is old, and a message
    // with no usable date (the 1970 rows) counts as old rather than being
    // allowed to sit in spam forever by saying nothing.
    //
    // Bounded by what has been synced: mail not yet in the cache is not
    // touched, and the next pass picks it up.
    const qint64 cutoff =
        QDateTime::currentDateTimeUtc().addDays(-m_spamRetentionDays).toSecsSinceEpoch();
    const QList<MailStore::AgedMessage> aged = m_store.messagesOlderThan(junk, cutoff);
    qCDebug(logTrace, "spam sweep: %lld cached messages older than %d days",
            qint64(aged.size()), m_spamRetentionDays);
    if (aged.isEmpty())
        return;

    QList<qint64> uids;
    QStringList remoteIds;
    uids.reserve(aged.size());
    remoteIds.reserve(aged.size());
    for (const MailStore::AgedMessage &m : aged) {
        uids.append(m.uid);
        remoteIds.append(m.remoteId);
    }

    // Cache rows go only once the server has confirmed, so a failure never
    // leaves mail on the server that mailove has forgotten.
    const auto settle = [this, junk, uids](const QString &crumb) {
        m_store.removeMessages(junk, uids);
        if (m_selectedFolder == junk)
            m_messageModel.removeByUids(uids);
        scheduleUnreadRecount();
        setStatus(crumb);
    };

    // Both of these used to run on a connection opened here just for the
    // sweep, because STORE and EXPUNGE act on whatever mailbox the connection
    // has selected and one that anything else can re-aim would expunge the
    // wrong folder. That is now handled where it belongs: ImapBackend
    // re-asserts the selection between the two, so no caller has to own a
    // connection to delete mail safely. What is left — wanting a connection
    // that is not queued behind the backfill — is a scheduling preference, and
    // scheduling is the backend's business, not this function's.
    const QString trash = trashFolderName();
    if (!m_spamSkipTrash && !trash.isEmpty()) {
        m_backend->moveMessages(junk, remoteIds, trash,
                                [uids, settle](MailBackend::Error error,
                                               const QString &message) {
            if (error != MailBackend::Error::None) {
                qCWarning(logTrace, "spam sweep: move failed: %s", qUtf8Printable(message));
                return;
            }
            settle(tr("Moved %1 from spam to trash")
                       .arg(countNoun(uids.size(), "old message", "old messages")));
        });
        return;
    }

    m_backend->deleteMessages(junk, remoteIds,
                              [uids, settle](MailBackend::Error error,
                                             const QString &message) {
        if (error != MailBackend::Error::None) {
            qCWarning(logTrace, "spam sweep: delete failed: %s", qUtf8Printable(message));
            return;
        }
        settle(tr("Deleted %1 from spam")
                   .arg(countNoun(uids.size(), "old message", "old messages")));
    });
}

/// Asks the server for this account's unread counts, debounced. A push can
/// arrive per message during a delivery run, and each one would otherwise cost
/// a round trip to be told much the same thing.
void MailClient::scheduleAccountCountRefresh()
{
    if (!m_accountCountDebounce.isSingleShot()) {
        m_accountCountDebounce.setSingleShot(true);
        // Longer than the unread debounce: this one leaves the machine, and
        // nothing is waiting on it — the pills are already right for the folder
        // being read, which folderChanged() refreshed.
        m_accountCountDebounce.setInterval(2000);
        connect(&m_accountCountDebounce, &QTimer::timeout, this,
                &MailClient::refreshAccountUnreadCounts);
    }
    m_accountCountDebounce.start();
}

void MailClient::refreshAccountUnreadCounts()
{
    if (!connected())
        return;
    const QString key = accountKey();
    QStringList folders = m_store.cachedFolders(key);
    if (folders.isEmpty())
        folders.append(QStringLiteral("INBOX"));

    // One call for every folder at once over JMAP, where IMAP would need a
    // STATUS each — which is why this hangs off a signal only JMAP raises.
    m_backend->folderUnreadCounts(folders, [this, key](MailBackend::Error error,
                                                       const QHash<QString, int> &counts,
                                                       const QString &) {
        if (error != MailBackend::Error::None)
            return; // best-effort: the poll timer and the backfill still run
        // Replace wholesale, as the other-accounts poll does: a folder that has
        // dropped to zero unread must lose its pill, which merging never does.
        m_unreadByAccount.insert(key, counts);
        if (key == accountKey())
            m_folderModel.setUnreadCounts(counts);
        ++m_cachedFolderRevision;
        Q_EMIT cachedFoldersChanged();
    });
}

void MailClient::scheduleUnreadRecount()
{
    m_jobs->scheduleUnreadRecount();
}

void MailClient::purgeCachedFolders(const QStringList &folders)
{
    QStringList keys;
    keys.reserve(folders.size());
    for (const QString &folder : folders)
        keys.append(m_store.scopedKey(folder));
    m_jobs->purgeCachedFolders(keys);
}

void MailClient::openFolder(const QString &mailBox)
{
    qCDebug(logTrace, "openFolder(%s)  selected=%s pending=%s",
            qUtf8Printable(mailBox), qUtf8Printable(m_selectedFolder),
            qUtf8Printable(m_pendingFolder));
    setSearchActive(false);
    m_sync->resetForFolderChange();
    // Whatever an account switch or a reconnect meant to reopen, this call
    // supersedes it. Leaving it set let listFolders() land a moment later and
    // yank the user back to the folder they had switched accounts with —
    // click a folder in account A, a non-INBOX folder in account B, then
    // INBOX, and INBOX opened and was immediately replaced by the second one.
    m_pendingFolder.clear();
    // Reopening the folder already on screen — which listFolders() does after
    // every reconnect — used to empty the list and refill it from cache. That
    // churn is what the view has to defend its selection against, and it buys
    // nothing: the rows are already the right ones and the network refresh
    // below merges into them either way. Only a real folder change rebuilds.
    const bool reopening = mailBox == m_selectedFolder && m_messageModel.rowCount() > 0;
    setSelectedFolder(mailBox);
    Q_EMIT selectedFolderChanged();

    QList<MessageListModel::Header> cached;
    if (!reopening) {
        m_messageModel.clear();
        // And the reading pane with it. A folder change deselects the row the
        // shown message came from, and in a folder with mail the next click
        // fills the pane again — but an empty folder has no next click, so the
        // previous folder's message sat there being read under the wrong
        // folder's name.
        m_reading->clear();
        // Show the cache instantly; the network refresh merges into it.
        cached = m_store.cachedHeaders(mailBox);
        updatePageAnchor(cached);
        if (!cached.isEmpty())
            m_messageModel.setHeaders(cached);
        // The new folder's window is newest-first like every other one, so a
        // list sorted by anything else restarts its paging from the folder's
        // real first page under that sort.
        requestSortSeed();
    }

    if (!connected()) {
        // Not cached.size(): that is one page (max 1000 rows), not the folder.
        // A local archive is not "offline" — the cache is the whole account.
        setStatus(m_acct.local ? tr("%1 — %2 messages")
                                .arg(mailBox)
                                .arg(m_store.cachedHeaderCount(mailBox))
                          : tr("%1 — offline, %2 cached")
                                .arg(mailBox)
                                .arg(m_store.cachedHeaderCount(mailBox)));
        return;
    }
    setBusy(true);
    // Reopening always means refreshing: the rows are already on screen.
    if (reopening || !cached.isEmpty())
        setStatus(tr("%1 refreshing").arg(mailBox));
    else
        setStatus(tr("Opening %1").arg(mailBox));

    // The folder's size and sync position come back on folderOpened(); what
    // the open makes of them is applySelectedFolderOpened(), which is where the
    // reply lands however long the round trip takes.
    m_sync->openSelectedFolder(mailBox);
}

void MailClient::scheduleBackfill(int delayMs)
{
    m_sync->scheduleBackfill(delayMs);
}

void MailClient::backoffBackfill()
{
    m_sync->backoffBackfill();
}

void MailClient::resetBackfillBackoff()
{
    m_sync->resetBackfillBackoff();
}

void MailClient::applySyncToken(const QString &folder, const QString &syncToken)
{
    m_sync->applySyncToken(folder, syncToken);
}

void MailClient::applyFolderInvalidated(const QString &folder)
{
    m_sync->applyFolderInvalidated(folder);
}

void MailClient::applyMessagesVanished(const QString &folder, const QStringList &remoteIds)
{
    m_sync->applyMessagesVanished(folder, remoteIds);
}

void MailClient::applyFolderOpened(const QString &folder, qint64 messageCount,
                                   const QString &syncToken)
{
    m_sync->applyFolderOpened(folder, messageCount, syncToken);
}

void MailClient::updatePageAnchor(const QList<MessageListModel::Header> &page)
{
    m_sync->updatePageAnchor(page);
}

void MailClient::loadMoreMessages()
{
    QElapsedTimer timer;
    timer.start();
    // A sorted browse pages in its own order — the next keyset page under the
    // sort, appended at the end, exactly like the default walk but along a
    // different axis.
    if (m_sync->sortedBrowse())
        requestSortPage(/*append=*/true);
    else
        m_sync->loadMoreMessages();
    // Only calls that did something are interesting; the prefetch zone makes
    // many that no-op out on the in-flight or exhausted guards.
    const qint64 ms = timer.elapsed();
    if (ms > 0) {
        qCDebug(logTrace, "loadMoreMessages: %lld ms (%d rows shown)", ms,
                m_messageModel.rowCount());
    }
}

bool MailClient::loadAllCachedMessages()
{
    return m_sync->loadAllCachedMessages();
}

void MailClient::seedSortOrder(int column, bool descending)
{
    if (m_sortColumn == column && m_sortDescending == descending)
        return;
    m_sortColumn = column;
    m_sortDescending = descending;
    m_sync->setSortOrder(column, descending);
    m_sortAnchorValid = false;
    m_sortExhausted = false;
    if (!m_sync->sortedBrowse()) {
        // Back to the default: the sorted pages on screen are some other slice
        // of the folder — put the newest-first window back.
        m_sync->reloadWindow();
        return;
    }
    requestSortSeed();
}

bool MailClient::sortPagesInline() const
{
    return m_sortColumn == int(MessageListModel::SortColumn::Date);
}

void MailClient::requestSortSeed()
{
    // Newest-first by date is the order the page window is already in: its
    // first row is the folder's first row, so there is nothing to fetch.
    if (!m_sync->sortedBrowse() || m_selectedFolder.isEmpty() || m_searchActive)
        return;
    m_sortAnchorValid = false;
    m_sortExhausted = false;
    requestSortPage(/*append=*/false);
}

void MailClient::requestSortPage(bool append)
{
    if (append) {
        // No anchor yet means the first page is still on its way; the prefetch
        // zone will ask again once it is showing. Exhausted means the last
        // page came back empty — there is nothing further in the cache. In
        // flight means the answer to this exact ask is already coming.
        if (!m_sortAnchorValid || m_sortExhausted || m_sortPageInFlight)
            return;
    }
    const MessageListModel::Header *anchor = append ? &m_sortAnchor : nullptr;
    if (sortPagesInline()) {
        // Indexed: milliseconds, and having the rows before this returns is
        // what keeps a held PageDown from ever reaching a bottom edge — the
        // worker round trip (thread start, its own connection to the cache,
        // scheduling under a scroll-busy GUI) cost more than the query.
        applySortPage(append, m_store.sortedHeaders(m_selectedFolder, m_sortColumn,
                                                    m_sortDescending, 500, anchor));
        return;
    }
    m_sortPageInFlight = true;
    // 2000 rows, not 500: these pages sort the folder whatever the LIMIT, so
    // nearly all of a page's cost is per-page, not per-row — fewer, bigger
    // pages put the next boundary four times further away for almost nothing.
    m_jobs->startSortPage(m_store.scopedKey(m_selectedFolder), m_sortColumn, m_sortDescending,
                          anchor, 2000);
}

void MailClient::applySortPage(bool append, const QList<MessageListModel::Header> &rows)
{
    if (rows.isEmpty()) {
        // A follow-on page of nothing is the end of the cache; a first page of
        // nothing is an empty folder. Either way, stop asking.
        m_sortExhausted = true;
        return;
    }
    m_sortAnchor = rows.last();
    m_sortAnchorValid = true;
    m_sync->applySortedPage(rows, /*replace=*/!append);
}

void MailClient::searchMessages(const QString &query, int field)
{
    const QString trimmed = query.trimmed();
    if (trimmed.isEmpty()) {
        clearSearch();
        return;
    }
    // While results are shown, end-of-list scrolling must not page unrelated
    // cached folder rows into the result list.
    setSearchActive(true);

    // /pattern/ → client-side regex filter over the already-loaded list
    if (trimmed.size() > 2 && trimmed.startsWith(QLatin1Char('/')) && trimmed.endsWith(QLatin1Char('/'))) {
        const QRegularExpression re(trimmed.mid(1, trimmed.size() - 2),
                                    QRegularExpression::CaseInsensitiveOption);
        if (!re.isValid()) {
            Q_EMIT errorOccurred(tr("Invalid regular expression: %1").arg(re.errorString()));
            return;
        }
        m_messageModel.applyFilter(re);
        return;
    }

    if (m_selectedFolder.isEmpty()) {
        Q_EMIT errorOccurred(tr("Select a folder to search."));
        return;
    }

    // A previous query that found nothing left a regex filter on the model (see
    // the tail of localKeywordFilter) — and a filter hides every row the NEXT
    // query appends, so one fruitless search made the search box look broken
    // until the field was cleared. The filter belongs to the query that set it.
    m_messageModel.applyFilter(QRegularExpression());

    // A local archive has no server to ask, and an offline account has none it
    // can reach — either way the cache is what there is to search, and the
    // local index pass IS the search. Refusing here with "Not connected" was
    // the whole complaint: the mail is sitting in the index, unsearchable.
    if (m_acct.local || !connected()) {
        m_searchSeen.clear();
        m_searching = true;
        m_searchFound = 0;
        Q_EMIT searchingChanged();
        localKeywordFilter(trimmed, tr("Search results"), /*append=*/false, field == 0);
        return;
    }

    setBusy(true);
    // Progress lives in the list itself (Mail.searching drives an overlay
    // there), not in the status breadcrumb. The previous results are NOT
    // cleared here: the search field re-fires on every keystroke, and a clear
    // per letter flashes the list blank. New hits merge into what is showing,
    // and rows the new query does not confirm are pruned when it completes.
    m_searchSeen.clear();
    m_searching = true;
    m_searchFound = 0;
    Q_EMIT searchingChanged();

    // 0 = from + subject, the default: body search drags in every newsletter
    // that ever mentioned the word. "Everything" (1) is the opt-in.
    const bool headersOnly = field == 0;
    m_pendingSearchIds.clear();
    // In the user's own outgoing folders the header pass looks at To: every
    // message there is from them, so a From search is either the whole folder
    // or nothing, and the name a person types is the one they wrote to.
    const bool byRecipient = listsRecipients(m_selectedFolder);
    m_backend->search(m_selectedFolder, trimmed, headersOnly, byRecipient,
                      [this, trimmed, headersOnly](MailBackend::Error error,
                                                   const QString &message) {
        QStringList ids = m_pendingSearchIds;
        m_pendingSearchIds.clear();
        if (error != MailBackend::Error::None) {
            // Some servers reject SEARCH variants; fall back to local matching.
            setBusy(false);
            localKeywordFilter(trimmed, tr("Server search failed (%1)").arg(message),
                               /*append=*/false, headersOnly);
            return;
        }
        if (ids.isEmpty()) {
            setBusy(false);
            localKeywordFilter(trimmed, tr("No server matches"), /*append=*/false,
                               headersOnly);
            return;
        }
        // Newest 200 hits are plenty for a result list.
        if (ids.size() > 200)
            ids = ids.mid(ids.size() - 200);
        QList<qint64> uids;
        uids.reserve(ids.size());
        for (const QString &id : std::as_const(ids))
            uids.append(m_backend->localKeyFor(id));
        // Merge in local partial-word hits — many servers (Gmail…) match whole
        // words only, so "hung" would otherwise miss "hungarian".
        fetchHeadersByUids(uids, trimmed, headersOnly);
    });
}

void MailClient::localKeywordFilter(const QString &keyword, const QString &reason, bool append,
                                    bool headersOnly)
{
    // The substring pass walks the folder's whole date index, which on a large
    // mailbox is far past a frame's worth of work — so it runs on a worker and
    // hands rows over in batches. The list fills in while it goes rather than
    // staying frozen and then appearing all at once.
    const quint64 seq = m_searchSeq.fetchAndAddOrdered(1) + 1;
    const QString scopedFolder = m_store.scopedKey(m_selectedFolder);
    const bool fts = m_store.ftsAvailable();
    const QString connection = QStringLiteral("mailstore-search-%1").arg(seq);

    // Shared with the worker: what it has delivered so far, so the finish
    // handler can tell "no matches" from "matches already on screen" without
    // asking the model (which may hold server hits too).
    auto delivered = std::make_shared<QAtomicInt>(0);
    if (!m_searching) {
        m_searching = true;
        m_searchFound = append ? m_messageModel.rowCount() : 0;
        Q_EMIT searchingChanged();
    }

    const bool byRecipient = listsRecipients(m_selectedFolder);
    auto *thread = QThread::create([this, seq, scopedFolder, keyword, fts, connection, delivered,
                                    headersOnly, byRecipient] {
        // Scoped so the handle is gone before removeDatabase — a live handle
        // is "still in use" to Qt and the removal only warns.
        {
        QSqlDatabase db = MailStore::openWorkerConnection(connection);
        if (db.isOpen()) {
            MailStore::searchOn(
                db, scopedFolder, keyword, fts,
                [this, seq, delivered](const QList<MessageListModel::Header> &batch) -> bool {
                    if (m_searchSeq.loadAcquire() != seq)
                        return false; // nobody is waiting for this any more
                    delivered->fetchAndAddOrdered(batch.size());
                    // Queued, never blocking: both passes are capped at 200
                    // rows, so this is a handful of posts and there is nothing
                    // to throttle — while a worker blocking on the GUI thread
                    // would be a deadlock waiting for a shutdown to happen.
                    // Append-only: the list was cleared once when the search
                    // started, and every batch after that inserts sorted rows
                    // in place. Never a reset mid-search — a reset blanks the
                    // view for a frame and reads as flashing.
                    QMetaObject::invokeMethod(
                        this,
                        [this, seq, batch] {
                            if (m_searchSeq.loadAcquire() != seq)
                                return;
                            // results are not a page of the folder
                            m_sync->markFullySynced();
                            m_messageModel.appendHeaders(batch);
                            for (const auto &h : batch)
                                m_searchSeen.insert(h.uid);
                            m_searchFound = int(m_searchSeen.size());
                            Q_EMIT searchingChanged();
                        },
                        Qt::QueuedConnection);
                    return m_searchSeq.loadAcquire() == seq;
                },
                headersOnly, byRecipient);
            db.close();
        }
        }
        QSqlDatabase::removeDatabase(connection);
    });
    connect(thread, &QThread::finished, this,
            [this, thread, seq, keyword, reason, delivered, append] {
                thread->deleteLater();
                if (m_searchSeq.loadAcquire() != seq)
                    return; // superseded; whoever replaced us owns the status line
                setBusy(false);
                m_searching = false;
                pruneSearchResults();
                m_searchFound = m_messageModel.rowCount();
                Q_EMIT searchingChanged();
                if (delivered->loadAcquire() > 0)
                    return;
                if (append)
                    return; // server hits stand on their own
                // Nothing in the index: fall back to filtering what is loaded.
                const QRegularExpression re(QRegularExpression::escape(keyword),
                                            QRegularExpression::CaseInsensitiveOption);
                m_messageModel.applyFilter(re);
            });
    // Below the UI's own work: typing the next letter must not wait for this.
    thread->start(QThread::LowPriority);
}

/// Drops rows the just-finished search did not deliver. Runs only at
/// completion: mid-search the old rows are still being confirmed one batch at
/// a time, and pruning early would re-introduce the per-keystroke blanking
/// this exists to avoid.
void MailClient::pruneSearchResults()
{
    if (!m_searchActive)
        return;
    QList<qint64> stale;
    const QList<qint64> uids = m_messageModel.allUids();
    for (qint64 uid : uids) {
        if (!m_searchSeen.contains(uid))
            stale.append(uid);
    }
    if (!stale.isEmpty())
        m_messageModel.removeByUids(stale);
}

void MailClient::clearSearch()
{
    setSearchActive(false);
    abandonLocalSearch(); // its rows would land in the folder we are restoring
    if (m_searching) {
        m_searching = false;
        Q_EMIT searchingChanged();
    }
    m_messageModel.applyFilter(QRegularExpression());
    if (m_selectedFolder.isEmpty())
        return;
    // Offline (and every local archive): no server refresh is coming to replace
    // the result rows, and openFolder() treats a folder that still has rows as
    // a reopen and leaves them standing — so drop them and let it refill from
    // the cache. Otherwise clearing the search left the hits on screen.
    if (!connected())
        m_messageModel.clear();
    openFolder(m_selectedFolder);
}

void MailClient::fetchHeadersByUids(const QList<qint64> &uids, const QString &localMergeKeyword,
                                    bool headersOnly)
{

    const QString folder = m_selectedFolder;
    QStringList ids;
    ids.reserve(uids.size());
    for (qint64 uid : uids)
        ids.append(QString::number(uid));

    m_backend->fetchHeadersById(folder, ids,
            [this, folder, localMergeKeyword, headersOnly](MailBackend::Error error,
                                                           const QString &message) {
        const QList<MessageListModel::Header> fetched = m_sync->takePendingHeaders(folder);
        setBusy(false);
        if (error != MailBackend::Error::None) {
            setStatus(tr("Fetching results failed"));
            m_searching = false;
            Q_EMIT searchingChanged();
            Q_EMIT errorOccurred(message);
            return;
        }
        // disable load-more while showing results
        m_sync->markFullySynced();
        // Append, not set: a reset would blank the rows already showing.
        m_messageModel.appendHeaders(fetched);
        for (const auto &h : fetched)
            m_searchSeen.insert(h.uid);
        m_searchFound = int(m_searchSeen.size());
        // Local partial-word hits are topped up afterwards, on a worker: the
        // server's answer is already on screen and must not wait for ours.
        // Only that top-up ends the searching state; without one it ends here.
        if (!localMergeKeyword.isEmpty()) {
            localKeywordFilter(localMergeKeyword, tr("Search results"), /*append=*/true,
                               headersOnly);
        } else {
            m_searching = false;
            pruneSearchResults();
        }
        Q_EMIT searchingChanged();
    });
}

/// True for MIME parts that carry an iCalendar invite (.ics).
static bool partIsCalendar(KMime::Content *part)
{
    if (const auto *ct = std::as_const(*part).contentType()) {
        const QByteArray mime = ct->mimeType().toLower();
        if (mime == "text/calendar" || mime == "application/ics")
            return true;
    }
    QString name;
    if (const auto *cd = std::as_const(*part).contentDisposition())
        name = cd->filename();
    if (name.isEmpty()) {
        if (const auto *ct = std::as_const(*part).contentType())
            name = ct->name();
    }
    return name.toLower().endsWith(QLatin1String(".ics"));
}

void MailClient::refineAttachKind(const QString &folder, qint64 uid, KMime::Message *msg)
{
    if (uid < 0)
        return;
    // The head can only say "multipart/mixed", which is a guess: plenty of
    // messages — the ones Mailove itself sent before it stopped wrapping a bare
    // body in a mixed part — declare it and carry no attachment at all. The
    // body settles it, and the answer here is exactly the list the reading
    // pane shows (collectAttachments walks the same parts).
    const auto parts = msg->attachments();
    int kind = MessageListModel::ConfirmedNoAttachment;
    if (!parts.isEmpty()) {
        // Refined (calendar icon in the list) only when every attachment is an
        // .ics; a mixed set keeps the head-derived generic flag.
        kind = MessageListModel::CalendarAttachment;
        for (KMime::Content *part : parts) {
            if (!partIsCalendar(part)) {
                kind = MessageListModel::GenericAttachment;
                break;
            }
        }
        if (kind == MessageListModel::GenericAttachment)
            return; // a mixed set: leave the head's generic flag alone
    }
    m_store.setAttachKind(folder, uid, kind);
    if (folder == m_selectedFolder)
        m_messageModel.setAttachKind(uid, kind);
}

/// Corrects the list's OpenPGP mark once the body is here. The head can only
/// show the outer content type: inline PGP is invisible to it, and so is a
/// message whose declared type promised a structure it does not have.
void MailClient::refineCrypto(const QString &folder, qint64 uid, KMime::Message *msg)
{
    if (uid < 0)
        return;
    const int kind = PgpMime::storedKind(PgpMime::classify(msg).kind);
    if (kind == PgpMime::storedKind(PgpMime::kindFromHead(msg->head())))
        return; // the head already had it right, which is the common case
    m_store.setCrypto(folder, uid, kind);
    if (folder == m_selectedFolder)
        m_messageModel.setCrypto(uid, kind);
}

QString MailClient::htmlViewUrl()
{
    return htmlViewUrlFor(m_reading);
}

QString MailClient::htmlViewUrlFor(MessageContext *ctx)
{
    return m_presenter->htmlViewUrl(ctx);
}

QString MailClient::textViewUrl()
{
    return textViewUrlFor(m_reading);
}

QString MailClient::textViewUrlFor(MessageContext *ctx)
{
    return m_presenter->textViewUrl(ctx);
}

QString MailClient::sourceViewUrl()
{
    return sourceViewUrlFor(m_reading);
}

QString MailClient::sourceViewUrlFor(MessageContext *ctx)
{
    return m_presenter->sourceViewUrl(ctx);
}

void MailClient::saveAttachment(int index, const QUrl &fileUrl)
{
    saveAttachmentFor(m_reading, index, fileUrl);
}

void MailClient::saveAttachmentFor(MessageContext *ctx, int index, const QUrl &fileUrl)
{
    m_presenter->saveAttachment(ctx, index, fileUrl);
}

bool MailClient::attachmentRisky(int index) const
{
    return attachmentRiskyFor(m_reading, index);
}

bool MailClient::attachmentRiskyFor(const MessageContext *ctx, int index) const
{
    return m_presenter->attachmentRisky(ctx, index);
}

void MailClient::openAttachment(int index)
{
    openAttachmentFor(m_reading, index);
}

void MailClient::openAttachmentFor(MessageContext *ctx, int index)
{
    m_presenter->openAttachment(ctx, index);
}

void MailClient::saveAttachmentToDownloads(int index)
{
    saveAttachmentToDownloadsFor(m_reading, index);
}

void MailClient::saveAttachmentToDownloadsFor(MessageContext *ctx, int index)
{
    m_presenter->saveAttachmentToDownloads(ctx, index);
}

void MailClient::markMessageColor(const QVariantList &rows, int color)
{
    if (color < 0 || color > 5)
        return;
    for (const QVariant &v : rows) {
        const int row = v.toInt();
        const qint64 uid = m_messageModel.uidAt(row);
        if (uid < 0)
            continue;
        const int newColor = m_messageModel.colorLabelAt(row) == color ? 0 : color;
        m_messageModel.setColorLabel(uid, newColor);
        m_store.setColorLabel(m_selectedFolder, uid, newColor);
    }
}

void MailClient::filterByColor(int color)
{
    m_messageModel.setColorFilter(color);
    if (color <= 0)
        return;
    // The loaded page holds only the newest rows — pull every cached mark of
    // this color from disk so older marks show as well (indexed query).
    m_messageModel.appendHeaders(m_store.headersByColor(m_selectedFolder, color));
}

void MailClient::markMessagesUnread(const QVariantList &rows)
{
    QList<qint64> uids;
    for (const QVariant &v : rows) {
        const int row = v.toInt();
        const qint64 uid = m_messageModel.uidAt(row);
        if (uid < 0 || !m_messageModel.seenAt(row))
            continue; // already unread: nothing to undo
        m_messageModel.markUnseen(row);
        m_store.setUnseen(m_selectedFolder, uid);
        uids.append(uid);
    }
    if (uids.isEmpty())
        return;
    scheduleUnreadRecount();

    // Nothing here reopens the message. Marking the open one unread leaves it
    // on screen and leaves it unread — the ordinary rule then applies again,
    // and it is only marked read the next time it is actually opened.
    if (!connected())
        return;
    // Clear \Seen server-side so other clients and the next header sync agree,
    // exactly as markMessageRead() sets it. Best effort, same as there.
    QStringList ids;
    for (qint64 uid : std::as_const(uids))
        ids.append(QString::number(uid));
    m_backend->setFlags(m_selectedFolder, ids, {}, {QStringLiteral("seen")},
                        [this](MailBackend::Error error, const QString &) {
        if (error != MailBackend::Error::None)
            setStatus(tr("Marking unread failed on the server"));
    });
}

void MailClient::markMessagesRead(const QVariantList &rows)
{
    QList<qint64> uids;
    for (const QVariant &v : rows) {
        const int row = v.toInt();
        const qint64 uid = m_messageModel.uidAt(row);
        if (uid < 0 || m_messageModel.seenAt(row))
            continue; // already read: nothing to do
        m_messageModel.markSeen(row);
        m_store.setSeen(m_selectedFolder, uid);
        uids.append(uid);
    }
    if (uids.isEmpty())
        return;
    scheduleUnreadRecount();

    if (!connected())
        return;
    // Set \Seen server-side so other clients and the next header sync agree,
    // exactly as markMessagesUnread() clears it. Best effort, same as there.
    QStringList ids;
    for (qint64 uid : std::as_const(uids))
        ids.append(QString::number(uid));
    m_backend->setFlags(m_selectedFolder, ids, {QStringLiteral("seen")}, {},
                        [this](MailBackend::Error error, const QString &) {
        if (error != MailBackend::Error::None)
            setStatus(tr("Marking read failed on the server"));
    });
}

bool MailClient::folderHasUnread(const QString &mailBox)
{
    // The sidebar's own figure, already in memory — asking the cache here
    // would put a query on the GUI thread just to decide whether a menu entry
    // is greyed out.
    return m_unreadByAccount.value(accountKey()).value(mailBox) > 0;
}

void MailClient::markFolderRead(const QString &mailBox)
{
    if (mailBox.isEmpty())
        return;

    // The cached messages are the whole scope: a folder still backfilling has
    // unread mail we have never seen a header for, and there is no id to name
    // it by. Those are marked read the next time this is asked, once they are
    // cached — which is also what the pill counts, so the two agree.
    //
    // The server is told about the messages that were unread before the cache
    // is updated, so the two cannot disagree about which ones those were.
    const QList<MailStore::AgedMessage> unseen = m_store.unseenMessages(mailBox);
    m_store.setFolderSeen(mailBox);
    if (mailBox == m_selectedFolder)
        m_messageModel.markAllSeen();
    scheduleUnreadRecount();

    if (unseen.isEmpty())
        return;
    QStringList ids;
    ids.reserve(unseen.size());
    for (const MailStore::AgedMessage &m : unseen)
        ids.append(m.remoteId);
    // Offline — including the moment right after a right-click switched to
    // this account — the store waits for the connection rather than being
    // dropped: the cache alone would lose the argument with the next header
    // sync, which reads the server's untouched flags back.
    if (!connected()) {
        m_pendingSeen[mailBox] += ids;
        return;
    }
    sendSeenStore(mailBox, ids);
}

void MailClient::sendSeenStore(const QString &mailBox, const QStringList &ids)
{
    m_backend->setFlags(mailBox, ids, {QStringLiteral("seen")}, {},
                        [this](MailBackend::Error error, const QString &) {
        if (error != MailBackend::Error::None)
            setStatus(tr("Marking the folder read failed on the server"));
    });
}

void MailClient::flushPendingSeen()
{
    if (m_pendingSeen.isEmpty() || !connected())
        return;
    // Taken before the first send: a failing store reports through setStatus()
    // and must not be handed back to a queue we are still walking.
    const QHash<QString, QStringList> pending = m_pendingSeen;
    m_pendingSeen.clear();
    for (auto it = pending.cbegin(); it != pending.cend(); ++it)
        sendSeenStore(it.key(), it.value());
}

void MailClient::markMessageRead(int row)
{
    // Opening a message is what marks it read, after it has been open for
    // view/markReadSeconds. 0 turns that off entirely, for anyone who keeps
    // unread as a to-do list and marks read by hand; a long value means only
    // a message actually read counts, not one glanced at while moving through
    // the list. Only this path is affected — marking read explicitly still
    // works.
    const double seconds = AdvancedConfig::d("view/markReadSeconds");
    if (seconds <= 0.0)
        return;
    const qint64 uid = m_messageModel.uidAt(row);
    if (uid < 0 || m_messageModel.seenAt(row))
        return;
    // One pending mark at a time: opening another message replaces it, so the
    // one left behind stays unread — which is the whole point of the delay.
    m_pendingReadUid = uid;
    if (!m_markReadTimer) {
        m_markReadTimer = new QTimer(this);
        m_markReadTimer->setSingleShot(true);
        connect(m_markReadTimer, &QTimer::timeout, this, [this] {
            // By the row it is on now: a sync or a re-sort may have moved it,
            // and it may have left the folder altogether.
            const int at = m_messageModel.rowForUid(m_pendingReadUid);
            if (at >= 0)
                applyReadMark(at);
        });
    }
    // Never below a millisecond: the default is a tenth of a second, which is
    // there to let a keypress move on before the mark lands, not to delay it.
    m_markReadTimer->start(qMax(1, qRound(seconds * 1000.0)));
}

void MailClient::applyReadMark(int row)
{
    const qint64 uid = m_messageModel.uidAt(row);
    if (uid < 0)
        return;
    const bool alreadySeen = m_messageModel.seenAt(row);
    m_messageModel.markSeen(row);
    m_store.setSeen(m_selectedFolder, uid);
    if (!alreadySeen)
        scheduleUnreadRecount();
    if (alreadySeen || !connected())
        return;

    // Push the read state to the server so other clients (and our next header
    // sync) agree. Best effort: the cache row above already carries it, and
    // reading a message never sets the flag as a side effect — a backend
    // fetches bodies without disturbing them — so without this the server
    // would never learn the message was read.
    // The backend re-SELECTs only when the mailbox it holds will not do, so
    // this costs a round trip on the first read in a folder and nothing after.
    m_backend->setFlags(m_selectedFolder, {QString::number(uid)},
                        {QStringLiteral("seen")}, {},
                        [](MailBackend::Error error, const QString &message) {
        if (error != MailBackend::Error::None)
            qWarning() << "mailove: storing \\Seen failed:" << message;
    });
}

void MailClient::fetchMessage(int row)
{
    const qint64 uid = m_messageModel.uidAt(row);
    if (uid < 0) {
        m_detachPending = false;
        return;
    }
    // Remembered so draftData() can name the message it came from.
    m_reading->m_uid = uid;

    // Previously read message → serve from cache, no network needed.
    const QByteArray cachedRaw = m_store.cachedBody(m_selectedFolder, uid);
    if (!cachedRaw.isEmpty()) {
        auto msg = std::make_shared<KMime::Message>();
        msg->setContent(KMime::CRLFtoLF(cachedRaw));
        // The cached form is a stub: attachment payloads live in the file
        // store. Put them back before anything looks at the message. If a
        // payload has gone missing the cache entry is incomplete, so fall
        // through and re-fetch rather than showing an empty attachment.
        msg->parse();
        if (!MimeUtils::restoreAttachments(msg.get(), m_store.partsFor(m_selectedFolder, uid))
            && connected()) {
            m_store.removeBodyOnly(m_selectedFolder, uid);
        } else {
        // The verifier keeps its own copy, so it is told at BOTH edges — not
        // just when a check starts. The heal path re-submits from inside the
        // verifier after this scope has closed, and it must read false there:
        // the refetched bytes are network-origin, which is what lets a second
        // mismatch be reported as a real failure instead of "unverified".
        m_presentingFromCache = true;
        m_verifier->setPresentingFromCache(true);
        presentMessage(msg);
        m_presentingFromCache = false;
        m_verifier->setPresentingFromCache(false);
        refineAttachKind(m_selectedFolder, uid, msg.get());
        rescoreWithBody(m_selectedFolder, uid, msg.get());
        markMessageRead(row);
        // No status crumb for opening a cached message — it's silent, the
        // message simply appears.
        // Read-ahead: sequential reading should never wait on the network.
        prefetchMessage(row + 1);
        prefetchMessage(row + 2);
        return;
        }
    }

    // Neither path below presents anything, so the pane keeps whatever it was
    // showing — a message from a different row, folder or account — while
    // m_uid above already names the row that failed to load. That pairing is
    // what openMessageInWindow() reads to skip the fetch, so a double-click
    // would then detach the *previous* message into a window. Clearing puts
    // both back in agreement: nothing is being read.
    if (!connected()) {
        m_detachPending = false;
        m_reading->clear();
        setStatus(tr("Not cached — connect to load"));
        return;
    }

    const QString remoteId = m_messageModel.remoteIdAt(row);
    if (remoteId.isEmpty()) {
        m_detachPending = false;
        m_reading->clear();
        setStatus(tr("Message load failed"));
        return;
    }

    setBusy(true);
    // No "loading…" crumb — the busy spinner already shows activity; only a
    // failure is worth a status.
    requestMessageBody(row, remoteId, false);
}

void MailClient::requestMessageBody(int row, const QString &remoteId, bool isRetry)
{
    // The message arrives on bodyFetched(), which is a signal rather than a
    // callback because several bodies can answer one request. This is a
    // single-message read, so the connection is made single-shot against the
    // id asked for and torn down whichever way the request ends — a stray
    // connection here would re-present an old message under a later one.
    auto connection = std::make_shared<QMetaObject::Connection>();
    auto answered = std::make_shared<bool>(false);

    *connection = connect(
        m_backend, &MailBackend::bodyFetched, this,
        [this, row, remoteId, connection, answered](
            const QString &folder, const QString &id,
            const std::shared_ptr<KMime::Message> &message) {
            if (id != remoteId || folder != m_selectedFolder || *answered)
                return;
            *answered = true;
            disconnect(*connection);

            setBusy(false);
            presentMessage(message);
            // Index text: prefer the plain part, else strip the HTML.
            const QString indexText = !m_reading->m_textBody.isEmpty()
                ? m_reading->m_textBody
                : QTextDocumentFragment::fromHtml(m_reading->m_htmlBody).toPlainText();
            m_store.storeBody(m_selectedFolder, m_messageModel.uidAt(row), m_reading->m_raw,
                              indexText);
            refineAttachKind(m_selectedFolder, m_messageModel.uidAt(row), message.get());
            rescoreWithBody(m_selectedFolder, m_messageModel.uidAt(row), message.get());
            setStatus({});
            markMessageRead(row);
            // Read-ahead: sequential reading should never wait on the network.
            prefetchMessage(row + 1);
            prefetchMessage(row + 2);
        });

    m_backend->fetchBodies(
        m_selectedFolder, {remoteId},
        [this, row, remoteId, isRetry, connection, answered](MailBackend::Error error,
                                                            const QString &message) {
            // The request finished. If bodyFetched() never came, nothing was
            // delivered — the callback is the only place that can tell, since
            // a body that never arrives emits no signal at all.
            if (*answered)
                return;
            *answered = true;
            disconnect(*connection);

            // A backend may decline a body request outright when its bulk
            // transfers are all busy, reporting success because for the
            // backfill that is true: the id comes back round on a later pass.
            // Nothing comes back round for a message the user just clicked, so
            // the one caller with a person waiting on it asks again.
            if (error == MailBackend::Error::None && !isRetry) {
                QTimer::singleShot(250, this, [this, row, remoteId] {
                    if (m_messageModel.remoteIdAt(row) == remoteId)
                        requestMessageBody(row, remoteId, true);
                    else
                        setBusy(false); // the user moved on
                });
                return;
            }

            setBusy(false);
            m_detachPending = false;
            // Same as the bail-outs in fetchMessage(): the request is over and
            // nothing was presented, so the pane must not go on showing the
            // previously read message under the selected row.
            m_reading->clear();
            setStatus(tr("Message load failed"));
            if (error != MailBackend::Error::None && !message.isEmpty())
                Q_EMIT errorOccurred(message);
        });
}

bool MailClient::refetchBodyForVerification(const QString &folder, qint64 uid,
                                            bool isRetry, MessageVerifier::BodyReady done)
{
    if (!connected())
        return false;
    // The backend names messages its own way, and this path holds a message
    // rather than a visible row — so the id comes from the cache, not the list
    // model. A message that is not cached cannot be the one whose cached body
    // failed to verify.
    const QString remoteId = m_store.remoteIdFor(folder, uid);
    if (remoteId.isEmpty())
        return false;

    // The body arrives on bodyFetched(), which is a signal rather than a
    // callback because one request can answer with several messages. This asks
    // for exactly one, so the connection is single-shot against the id asked
    // for and is torn down whichever way the request ends — a stray one here
    // would judge a later message against these octets.
    auto connection = std::make_shared<QMetaObject::Connection>();
    auto answered = std::make_shared<bool>(false);

    *connection = connect(
        m_backend, &MailBackend::bodyFetched, this,
        [this, folder, remoteId, done, connection, answered](
            const QString &f, const QString &id,
            const std::shared_ptr<KMime::Message> &message) {
            if (*answered || id != remoteId || f != folder)
                return;
            *answered = true;
            disconnect(*connection);
            done(message);
        });

    m_backend->fetchBodies(
        folder, {remoteId},
        [this, folder, uid, isRetry, done, connection, answered](MailBackend::Error error,
                                                                const QString &) {
            // The request finished. If bodyFetched() never came, nothing was
            // delivered — the callback is the only place that can tell, since a
            // body that never arrives emits no signal at all.
            if (*answered)
                return;
            *answered = true;
            disconnect(*connection);

            // A backend may decline a body request outright when its bulk
            // transfers are all busy, reporting success because for the
            // backfill that is true: the id comes back round on a later pass.
            // Nothing comes back round here, so the one attempt this message
            // gets is asked for again rather than spent on a refusal.
            if (error == MailBackend::Error::None && !isRetry) {
                QTimer::singleShot(250, this, [this, folder, uid, done] {
                    if (!refetchBodyForVerification(folder, uid, true, done))
                        done({});
                });
                return;
            }
            done({});
        });
    return true;
}

void MailClient::openExternalUrl(const QUrl &url)
{
    const QString scheme = url.scheme();
    if (scheme != QLatin1String("http") && scheme != QLatin1String("https")
        && scheme != QLatin1String("mailto")) {
        Q_EMIT errorOccurred(tr("Refusing to open %1 link externally.").arg(scheme));
        return;
    }
    // No breadcrumb on success: the browser coming up is the feedback, and a
    // status line repeating it just pushes something useful out of the trail.
    // Failure still speaks up, because nothing else would.
    if (QDesktopServices::openUrl(url))
        qCDebug(logTrace, "opened %s externally", qUtf8Printable(url.host()));
    else
        Q_EMIT errorOccurred(tr("Could not open %1.").arg(url.toString()));
}

void MailClient::setRemoteContentAllowed(bool allow)
{
    m_reading->setRemoteContentAllowed(allow);
}

void MailClient::rememberRemoteContent(const QString &senderAddress, bool allow)
{
    // User toggle: remember the choice for this sender.
    qCDebug(logTrace) << "remote content toggle" << allow << "for sender" << senderAddress;
    m_store.setRemoteContentAllowedFor(senderAddress, allow);
}

static QString indexTextFor(KMime::Message *msg)
{
    // Encrypted mail is not full-text searchable, and this is the one line
    // that makes that true. The index is a plaintext SQLite table; putting a
    // decrypted body in it would undo the encryption for anyone who reads the
    // file, permanently and invisibly (doc/openpgp.md §4). Subject and headers
    // travel in the clear on the wire and stay indexed by the header path.
    //
    // Note this runs on the ciphertext even for a message the reader has open
    // and decrypted: the cache and the viewer never share a tree.
    if (PgpMime::classify(msg).isEncrypted())
        return {};
    KMime::Content *textPart = msg->mainBodyPart("text/plain");
    if (!textPart)
        textPart = MimeUtils::findPartByType(msg, "text/plain");
    if (textPart)
        return textPart->decodedText();
    KMime::Content *htmlPart = msg->mainBodyPart("text/html");
    if (!htmlPart)
        htmlPart = MimeUtils::findPartByType(msg, "text/html");
    if (htmlPart)
        return QTextDocumentFragment::fromHtml(htmlPart->decodedText().left(100000))
            .toPlainText();
    return {};
}

/// Extracts the searchable text of a batch of cached bodies on a worker thread
/// and writes it back to the index. A full MIME parse plus an HTML-to-text
/// conversion of up to 100 KB is far past the 20 ms budget, and open() seeds
/// the queue with every cached body — on a large cache that was hours of
/// GUI-thread CPU. None of it touches the UI, so none of it belongs there.
void MailClient::prefetchMessage(int row)
{
    m_sync->prefetchBody(m_selectedFolder, m_messageModel.uidAt(row));
}

void MailClient::processPrefetchQueue()
{
    m_sync->processPrefetchQueue();
}

void MailClient::storeFetchedBody(const QString &folder, qint64 uid,
                                  const std::shared_ptr<KMime::Message> &message)
{
    KMime::Message *msg = message.get();
    if (msg->contents().isEmpty())
        msg->parse();
    const QByteArray raw = msg->encodedContent();
    const qint64 cap = qint64(m_maxBodyMB) * 1024 * 1024;
    if (cap > 0 && raw.size() > cap) {
        // A single mail with a big attachment can outweigh thousands of normal
        // ones. Remember the refusal (so the backfill drops it) and move on —
        // opening the message still fetches it on demand.
        m_store.skipBody(folder, uid, raw.size());
        refineAttachKind(folder, uid, msg);
        refineCrypto(folder, uid, msg);
        // Scored even though the body was refused: the head is all the
        // attachment-name rules need once the MIME tree has been parsed, and a
        // message too big to cache is not a message too big to judge.
        rescoreWithBody(folder, uid, msg);
        noteBodyStored(folder);
        return;
    }
    m_jobs->queueBodyWrite({m_store.scopedKey(folder), uid, raw, indexTextFor(msg)});
    noteBodyStored(folder);
    refineAttachKind(folder, uid, msg);
    refineCrypto(folder, uid, msg);
    rescoreWithBody(folder, uid, msg);
    if (!m_sentFolder.isEmpty() && folder == m_sentFolder)
        harvestRecipients(msg, folder, uid);
}

void MailClient::startDkimVerification(MessageContext *ctx)
{
    m_verifier->setPresentingFromCache(m_presentingFromCache);
    m_verifier->startDkimVerification(ctx);
}

void MailClient::setViewerHandler(ViewerSchemeHandler *handler)
{
    m_viewerHandler = handler;
    m_presenter->setViewerHandler(handler);
}

void MailClient::setPgpEngine(PgpEngine *engine)
{
    m_pgp = engine;
    m_verifier->setPgpEngine(engine);
}

bool MailClient::startPgpVerification(MessageContext *ctx, KMime::Message *root)
{
    return m_verifier->startPgpVerification(ctx, root, m_presentingFromCache);
}

void MailClient::findAttachedKey(MessageContext *ctx, KMime::Content *root)
{
    m_presenter->findAttachedKey(ctx, root);
}

void MailClient::applyBodyParts(MessageContext *ctx, KMime::Message *root, bool junk)
{
    m_presenter->applyBodyParts(ctx, root, junk);
}

void MailClient::presentMessage(const std::shared_ptr<KMime::Message> &message)
{
    KMime::Message *msg = message.get();
    // The backend delivers the message already parsed. Calling parse() on a
    // parsed multipart message DESTROYS it: the body was consumed into the
    // child parts, so a re-parse from the now-empty body drops every part
    // and leaves a headers-only shell. Parse only if it hasn't happened yet.
    if (msg->contents().isEmpty())
        msg->parse();

    MessageContext *ctx = m_reading;
    ctx->m_handler = m_viewerHandler;

    // What shape of OpenPGP this is, before anything else looks at the tree:
    // both the remote-content decision below and the part search further down
    // depend on the answer.
    const PgpMime::Structure pgp = PgpMime::classify(msg);

    // Privacy default: remote content blocked, unless the user previously
    // chose "load remote content" for this exact sender address. Must run
    // AFTER the parse guard — cache-served messages have no headers before it.
    ctx->m_senderAddress.clear();
    if (const auto *from = std::as_const(*msg).from(); from && !from->mailboxes().isEmpty())
        ctx->m_senderAddress =
            QString::fromLatin1(from->mailboxes().first().address()).toLower();
    const bool remembered = m_store.remoteContentAllowedFor(ctx->m_senderAddress);
    qCDebug(logTrace) << "presenting message from" << ctx->m_senderAddress
                      << "remembered remote-content" << remembered;
    // Junk gets hostile-content handling: no remembered remote-content
    // allowance either — the user can still toggle it per view.
    const bool junk = isJunkFolder(m_selectedFolder);
    // Nor does an encrypted message inherit one. A remote request made from
    // decrypted mail can carry the plaintext to whoever chose the URL, and a
    // per-sender allowance granted for their ordinary mail was never a
    // decision about that (doc/openpgp.md §5). The toggle still works; it just
    // has to be a fresh, deliberate choice, and the viewer says why.
    ctx->applyRemoteAllowed(remembered && !junk && !pgp.isEncrypted());
    ctx->m_junk = junk;
    ctx->m_folder = m_selectedFolder;
    // A message in the Sent folder means its To/Cc were once our recipients —
    // feed them to the compose autocompletion.
    if (!m_sentFolder.isEmpty() && m_selectedFolder == m_sentFolder)
        harvestRecipients(msg, m_selectedFolder, ctx->m_uid);
    ctx->m_message = message; // keeps all parts alive
    ctx->m_raw = msg->encodedContent();
    ctx->m_decrypted.reset();
    ctx->m_decryptJob = 0;
    ctx->m_cryptoState.clear();
    ctx->m_cryptoDetail.clear();
    ctx->m_cryptoChecking = false;

    // For an encrypted message the parts worth showing are not in this tree at
    // all, so this has to settle before the part search below.
    if (pgp.kind == PgpMime::Kind::Partial) {
        ctx->m_cryptoState = QStringLiteral("partial");
        ctx->m_cryptoDetail =
            tr("Part of this message is encrypted. Mailove does not decrypt a "
               "fragment of a message: shown together with the parts that were "
               "never encrypted, there would be no way to tell which was which.");
    } else if (pgp.isEncrypted()) {
        // Remote content is not inherited for these: see the applyRemoteAllowed
        // call above and doc/openpgp.md §5.
        ctx->m_cryptoState = QStringLiteral("failed"); // until a job starts
        if (!m_pgp || !m_pgp->available()) {
            ctx->m_cryptoDetail = m_pgp ? m_pgp->unavailableReason()
                                        : tr("OpenPGP support is not available.");
        } else if (const quint64 job = m_pgp->decrypt(PgpMime::ciphertext(pgp))) {
            ctx->m_cryptoState = QStringLiteral("decrypting");
            ctx->m_decryptJob = job;
            ctx->m_cryptoChecking = true;
            ctx->m_cryptoDetail = tr("Decrypting…");
            m_verifier->trackDecryptJob(job, ctx);
        } else {
            ctx->m_cryptoDetail = tr("This message could not be decrypted.");
        }
    } else if (pgp.kind == PgpMime::Kind::Signed) {
        // Nothing is hidden here — the message reads either way — so it is
        // presented at once and the verdict lands on the badge when it lands.
        ctx->m_cryptoState = QStringLiteral("signed");
        if (startPgpVerification(ctx, msg)) {
            ctx->m_cryptoChecking = true;
            ctx->m_cryptoDetail = tr("Checking the signature…");
        } else {
            ctx->m_signatureStatus = QStringLiteral("error");
            ctx->m_cryptoDetail = m_pgp && !m_pgp->available()
                ? m_pgp->unavailableReason()
                : tr("The signature could not be checked.");
        }
    }

    // Body, preview, inline parts and attachments — and the view URL, which
    // applyBodyParts picks (junk folders open as plain text, always).
    applyBodyParts(ctx, msg, junk);
    const QString bodyUrl = ctx->m_bodyUrl;

    const KMime::Message *cmsg = msg;
    const QString subject = cmsg->subject() ? cmsg->subject()->asUnicodeString() : QString();
    const QString from = cmsg->from() ? cmsg->from()->asUnicodeString() : QString();
    const QString to = cmsg->to() ? cmsg->to()->asUnicodeString() : QString();
    const QString cc = cmsg->cc() ? cmsg->cc()->asUnicodeString() : QString();
    QString date;
    if (cmsg->date()) {
        const QDateTime local = cmsg->date()->dateTime().toLocalTime();
        date = local.date() == QDate::currentDate()
            ? local.toString(QStringLiteral("hh:mm"))
            : local.toString(m_dateFormat + QStringLiteral(" hh:mm"));
    }
    // Imported archive mail gets no authentication verdicts at all: there is
    // no receiving server whose Authentication-Results could be trusted, and
    // years-old DKIM keys are long rotated — every check would just fail.
    const QString authInfo =
        m_acct.local ? QString() : trustedAuthResults(cmsg, trustedAuthDomains());

    ctx->m_subject = subject;
    ctx->m_from = from;
    ctx->m_to = to;
    ctx->m_cc = cc;
    ctx->m_date = date;
    ctx->m_authInfo = authInfo;
    ctx->m_bodyUrl = bodyUrl;
    ctx->m_hasMessage = true;
    Q_EMIT ctx->messageChanged();
    Q_EMIT ctx->cryptoChanged();
    Q_EMIT messageLoaded(subject, from, to, cc, date, bodyUrl, authInfo);

    // Verify the signature ourselves. This is the one place it is started:
    // opening a message, not listing or prefetching one.
    startDkimVerification(ctx);

    // A double-click asked for this message in its own window; now that it is
    // presentable, hand a standalone copy to QML. The uid guard drops stale
    // requests — e.g. the user moved on to another message before the fetch
    // for the double-clicked one came back.
    if (m_detachPending) {
        m_detachPending = false;
        if (ctx->m_uid == m_detachUid)
            Q_EMIT messageWindowReady(detachReading());
    }
}

MessageContext *MailClient::detachReading()
{
    MessageContext *src = m_reading;
    auto *ctx = new MessageContext(this);
    ctx->m_handler = m_viewerHandler;
    ctx->m_message = src->m_message; // shared — parts stay alive for both
    ctx->m_attachmentParts = src->m_attachmentParts;
    ctx->m_attachments = src->m_attachments;
    ctx->m_htmlBody = src->m_htmlBody;
    ctx->m_textBody = src->m_textBody;
    ctx->m_raw = src->m_raw;
    ctx->m_uid = src->m_uid;
    // What makes this message *this* message: a uid is only unique within a
    // folder, and a folder name only within an account.
    ctx->m_sourceKey = accountKey() + QLatin1Char('\n') + m_selectedFolder
        + QLatin1Char('\n') + QString::number(src->m_uid);
    ctx->m_senderAddress = src->m_senderAddress;
    ctx->m_junk = src->m_junk;
    ctx->m_folder = src->m_folder;
    ctx->m_remoteAllowed = src->m_remoteAllowed;
    ctx->m_subject = src->m_subject;
    ctx->m_from = src->m_from;
    ctx->m_to = src->m_to;
    ctx->m_cc = src->m_cc;
    ctx->m_date = src->m_date;
    ctx->m_authInfo = src->m_authInfo;
    ctx->m_hasMessage = src->m_hasMessage;
    // Whatever we already know about the signature, so the window opens with
    // the badge the reading pane was showing rather than a blank space.
    ctx->m_dkimStatus = src->m_dkimStatus;
    ctx->m_dkimDetail = src->m_dkimDetail;
    ctx->m_dkimTrusted = src->m_dkimTrusted;
    ctx->m_arcStatus = src->m_arcStatus;
    ctx->m_arcSealer = src->m_arcSealer;
    ctx->m_arcDetail = src->m_arcDetail;
    ctx->m_dkimFromCache = src->m_dkimFromCache;
    // The decrypted tree is shared, not decrypted again: a second decryption
    // would mean a second passphrase prompt for a message already open.
    ctx->m_decrypted = src->m_decrypted;
    ctx->m_decryptedRaw = src->m_decryptedRaw;
    if (ctx->m_decrypted)
        ctx->markPlaintextHeld(true);
    ctx->m_decryptionKeyId = src->m_decryptionKeyId;
    ctx->m_cryptoState = src->m_cryptoState;
    ctx->m_cryptoDetail = src->m_cryptoDetail;
    ctx->m_cryptoChecking = src->m_cryptoChecking;
    ctx->m_decryptJob = src->m_decryptJob;
    ctx->m_signatureStatus = src->m_signatureStatus;
    ctx->m_signerName = src->m_signerName;
    ctx->m_signerEmail = src->m_signerEmail;
    ctx->m_signerFingerprint = src->m_signerFingerprint;
    ctx->m_signerTrusted = src->m_signerTrusted;
    ctx->m_verifyJob = src->m_verifyJob;
    ctx->m_pgpOctetsExact = src->m_pgpOctetsExact;
    ctx->m_pgpFromCache = src->m_pgpFromCache;
    // Own scheme-handler slot: the window keeps its body and inline images
    // however the reading pane moves on.
    if (m_viewerHandler && ctx->m_message)
        m_presenter->collectInlineParts(ctx, ctx->m_decrypted ? ctx->m_decrypted.get()
                                                              : ctx->m_message.get());
    // No HTML part to show — an encrypted message still being decrypted, among
    // others — means the HTML view would open blank.
    ctx->m_bodyUrl = (ctx->m_junk || ctx->m_htmlBody.isEmpty()) ? textViewUrlFor(ctx)
                                                                : htmlViewUrlFor(ctx);
    // A window detached mid-check is addressed by the same job ids as the pane
    // it came from, so it joins those jobs rather than starting ones of its own
    // (unlike DKIM below — re-running gpg would prompt again).
    m_verifier->adoptJobs(ctx, ctx->m_decryptJob, ctx->m_verifyJob);
    // A detach almost always happens while the reading pane's check is still in
    // flight — the verdict is addressed to that context by request id, so this
    // copy would sit at "checking" forever and show nothing but the server's
    // say-so. Run its own instead: once a verdict has been recorded this is a
    // primary-key lookup, and while one is still being established the second
    // verification reuses the worker's DNS cache, so it costs no query.
    if (src->m_dkimChecking)
        startDkimVerification(ctx);
    return ctx;
}

void MailClient::openMessageInWindow(int row)
{
    const qint64 uid = m_messageModel.uidAt(row);
    if (uid < 0)
        return;
    // The usual case: the first click of the double-click already loaded the
    // message into the reading pane — copy it straight into a window.
    if (m_reading->m_hasMessage && m_reading->m_uid == uid) {
        Q_EMIT messageWindowReady(detachReading());
        return;
    }
    // Still loading (or the click never fetched): ask for the message and
    // open the window when it arrives — see presentMessage().
    m_detachPending = true;
    m_detachUid = uid;
    fetchMessage(row);
}

/// Copies the FTS index into one whose tokenizer folds diacritics, so "ave"
/// finds "ávé". A tokenizer cannot be changed in place, and the copy is as big
/// as the mail behind it, so it runs in slices on a worker with the cursor
/// persisted after every slice: quitting resumes rather than restarts. The
/// window refuses to close while it runs, because the swap at the end is what
/// makes the work count.
void MailClient::startIndexRebuild()
{
    m_jobs->startIndexRebuild();
}
