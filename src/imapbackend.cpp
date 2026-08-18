// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "imapbackend.h"

#include "advancedconfig.h"

#include <QDebug>
#include <QDateTime>
#include <QLoggingCategory>
#include <QHash>
#include <QTimer>

#include <kmime/content.h>
#include <kmime/message.h>
#include <kmime/util.h>

/// Defined in mailclient.cpp — the verbose trail, off unless asked for.
Q_DECLARE_LOGGING_CATEGORY(logTrace)

#include <kimap/capabilitiesjob.h>
#include <kimap/appendjob.h>
#include <kimap/createjob.h>
#include <kimap/deletejob.h>
#include <kimap/expungejob.h>
#include <kimap/fetchjob.h>
#include <kimap/imapset.h>
#include <kimap/idlejob.h>
#include <kimap/listjob.h>
#include <kimap/loginjob.h>
#include <kimap/movejob.h>
#include <kimap/renamejob.h>
#include <kimap/searchjob.h>
#include <kimap/selectjob.h>
#include <kimap/session.h>
#include <kimap/statusjob.h>
#include <kimap/storejob.h>

#include <ksmtp/loginjob.h>
#include <ksmtp/sendjob.h>
#include <ksmtp/session.h>

namespace
{
/// True specifically for the concurrent-connection cap, which is answered by
/// using fewer connections, not just by waiting.
bool isTooManyConnections(const QString &err)
{
    const QString up = err.toUpper();
    return up.contains(QStringLiteral("SIMULTANEOUS-CONNECTIONS"))
        || up.contains(QStringLiteral("SIMULTANEOUS CONNECTIONS"));
}

/// The two halves of a message as the server sent them, before KMime has been
/// allowed near either.
///
/// BODY.PEEK[] is the obvious way to ask for a message and the wrong one:
/// KIMAP answers it with Message::setContent() followed by parse(), and a
/// parsed KMime tree can no longer reproduce its own source. Where a nested
/// multipart's closing delimiter sits tight against the parent boundary — no
/// blank line between `--INNER--` and `--OUTER`, which is what Gmail emits for
/// a reply with attachments — re-assembly inserts a blank line the wire did
/// not have ([KDE bug 523826](https://bugs.kde.org/show_bug.cgi?id=523826)).
/// The body hash then fails and mailove calls a perfectly good message
/// "modified after signing".
///
/// The section fetches take a different path through KIMAP: BODY[HEADER]
/// reaches KMime as setHead() and BODY[TEXT] as setBody(), neither of which
/// re-encodes anything, and a Content with no head of its own parses as
/// text/plain so its body is never split. Both halves come back octet-exact,
/// and joining them is the message as it travelled.
struct RawMessage {
    QByteArray head; ///< BODY[HEADER], including its terminating blank line
    QByteArray body; ///< BODY[TEXT]
    bool haveHead = false;
    bool haveBody = false;
    /// Both halves arrived. They may come in one delivery or several.
    bool complete() const { return haveHead && haveBody; }
};

/// Takes whichever halves this delivery carried. First one wins: a server that
/// repeats a section in a later untagged response is describing the same
/// octets, and re-taking them would only risk a partial overwrite.
///
/// The two halves arrive through different doors, from different jobs. The
/// head comes from the FullHeaders job as m.message->head() — that mode is one
/// of the three whose responses assign msg.message at all; asking for HEADER
/// as a Content part instead gets parsed into a message KIMAP never delivers.
/// The body comes from the Content job's parts map, where TEXT lands via
/// setBody(). The parts fallback for HEADER costs nothing and keeps this
/// working if KIMAP ever routes it there.
void mergeRawParts(const KIMAP::Message &m, RawMessage &raw)
{
    if (!raw.haveHead) {
        if (m.message && !m.message->head().isEmpty()) {
            raw.head = m.message->head();
            raw.haveHead = true;
        } else if (const auto part = m.parts.value(QByteArrayLiteral("HEADER"))) {
            raw.head = part->head();
            raw.haveHead = true;
        }
    }
    if (!raw.haveBody) {
        if (const auto part = m.parts.value(QByteArrayLiteral("TEXT"))) {
            raw.body = part->body();
            raw.haveBody = true;
        }
    }
}

/// Header section and body section back into one RFC 5322 message.
///
/// RFC 9051 §7.5.2 says BODY[HEADER] ends with the blank line that closes the
/// header, so the two normally concatenate untouched. The fallbacks are for
/// servers that trim it: the separator is rebuilt in whatever line ending the
/// header itself used, because guessing CRLF for an LF message would put a
/// stray byte into the very octets this whole path exists to preserve.
QByteArray joinRawWire(const QByteArray &head, const QByteArray &body)
{
    if (head.isEmpty())
        return body;
    if (head.endsWith("\r\n\r\n") || head.endsWith("\n\n"))
        return head + body;
    if (head.endsWith("\r\n"))
        return head + "\r\n" + body;
    if (head.endsWith('\n'))
        return head + "\n" + body;
    return head + "\r\n\r\n" + body;
}

/// Parses the joined wire into the message the rest of mailove reads.
///
/// setFrozen() before parse() is the load-bearing line. Frozen, KMime answers
/// encodedContent() with the octets it was given instead of re-assembling them
/// from the parsed tree, which is what keeps ctx->m_raw — and so the DKIM body
/// hash, and the OpenPGP signed part, which is frozen along with its parent —
/// equal to what the sender signed. It must come before parse(): afterwards
/// the original body is already gone and freezing then truncates the message
/// to its headers. The message is consequently immutable — assemble() will not
/// write changes back — which is correct for everything on the read path and
/// the reason composing builds its own messages.
std::shared_ptr<KMime::Message> buildMessage(const RawMessage &raw)
{
    auto message = std::make_shared<KMime::Message>();
    // CRLFtoLF because setContent() takes LF: handed CRLF, the head parses but
    // no boundary line ever matches and the message comes out with no parts.
    message->setContent(KMime::CRLFtoLF(joinRawWire(raw.head, raw.body)));
    message->setFrozen(true);
    message->parse();
    return message;
}

/// Mirrors MailClient::Security, which is the enum the account settings and
/// the QML combo box are written in. Not shared as a type because that enum is
/// registered with QML and moving it would change the singleton's API for no
/// gain here.
enum Security { SslTls = 0, StartTls = 1, None = 2 };
}

ImapBackend::ImapBackend(QObject *parent)
    : MailBackend(parent)
{
    // A quiet connection gets closed by most servers within some minutes; a
    // periodic CAPABILITY is the cheapest thing that counts as traffic.
    m_keepAlive.setInterval(AdvancedConfig::i("imap/keepAliveSeconds") * 1000);
    connect(&m_keepAlive, &QTimer::timeout, this, [this] {
        if (m_connected && m_session)
            (new KIMAP::CapabilitiesJob(m_session))->start();
    });
    // One retry, owned here rather than posted as a loose singleShot each
    // time — see m_pushRetry.
    m_pushRetry.setSingleShot(true);
    connect(&m_pushRetry, &QTimer::timeout, this, [this] { startPush(m_pushFolder); });
}

ImapBackend::~ImapBackend()
{
    closeSessions();
}

KIMAP::Session *ImapBackend::mainSession() const
{
    return m_session.data();
}

KIMAP::Session *ImapBackend::syncSession() const
{
    return m_syncSession.data();
}

void ImapBackend::configureLogin(KIMAP::LoginJob *login) const
{
    login->setUserName(m_credentials.user);
    if (m_credentials.authType != 0) {
        login->setAuthenticationMode(KIMAP::LoginJob::XOAuth2);
        login->setPassword(m_credentials.accessToken);
    } else {
        login->setAuthenticationMode(KIMAP::LoginJob::Plain);
        login->setPassword(m_credentials.password);
    }
    switch (m_credentials.security) {
    case StartTls:
        login->setEncryptionMode(KIMAP::LoginJob::STARTTLS);
        break;
    case None:
        login->setEncryptionMode(KIMAP::LoginJob::Unencrypted);
        break;
    default:
        login->setEncryptionMode(KIMAP::LoginJob::SSLorTLS);
        break;
    }
}

void ImapBackend::setConnected(bool connected)
{
    if (m_connected == connected)
        return;
    m_connected = connected;
    Q_EMIT connectedChanged(connected);
}

void ImapBackend::closeSessions()
{
    m_keepAlive.stop();
    stopPush();
    m_syncReady = false;
    m_syncFolder.clear();
    m_syncQueuedFolder.clear();
    m_selectedFolder.clear();
    m_selectedReadWrite = false;
    m_queuedFolder.clear();
    m_queuedReadWrite = false;
    m_messageCounts.clear();
    for (const auto &conn : std::as_const(m_bodyPool)) {
        if (conn->session)
            conn->session->deleteLater();
    }
    m_bodyPool.clear();
    m_bodyPoolBroken = false;
    m_bodyFallbackBusy = false;
    if (m_syncSession) {
        m_syncSession->disconnect(this); // same reason as the main session below
        m_syncSession->deleteLater();
        m_syncSession.clear();
    }
    if (m_session) {
        // Drop our handlers before closing. close() makes the socket emit
        // connectionLost, which is meant for an *unexpected* drop and would
        // otherwise arrive asynchronously — after the caller has already acted
        // on the deliberate teardown — and be taken for a dropped connection
        // to reconnect from.
        m_session->disconnect(this);
        m_session->close();
        m_session->deleteLater();
        m_session.clear();
    }
}

void ImapBackend::disconnectAccount()
{
    closeSessions();
    setConnected(false);
}

void ImapBackend::connectAccount(const Credentials &credentials)
{
    m_credentials = credentials;
    closeSessions();
    setConnected(false);

    m_session = new KIMAP::Session(m_credentials.host, quint16(m_credentials.port), this);
    // No SessionUiProxy is installed on purpose: KIMAP then rejects invalid TLS
    // certificates instead of asking. Surfaced explicitly below.
    connect(m_session, &KIMAP::Session::connectionFailed, this, [this] {
        const QString host = m_credentials.host;
        const int port = m_credentials.port;
        closeSessions();
        setConnected(false);
        Q_EMIT errorOccurred(
            Error::Connection,
            tr("Could not establish a secure connection to %1:%2 — wrong host/port, "
               "or the server's TLS certificate was rejected.")
                .arg(host)
                .arg(port));
    });
    connect(m_session, &KIMAP::Session::connectionLost, this, [this] {
        closeSessions();
        setConnected(false);
        // Reported after the state change so a handler that reconnects sees
        // isConnected() == false rather than racing it.
        Q_EMIT connectionLost();
    });

    auto *login = new KIMAP::LoginJob(m_session);
    configureLogin(login);
    connect(login, &KJob::result, this, [this](KJob *job) {
        if (job->error()) {
            const QString message = job->errorString();
            closeSessions();
            setConnected(false);
            Q_EMIT errorOccurred(Error::Auth, message);
            return;
        }
        // The flag is set before the signal so the background connection can be
        // opened first (startSyncSession() checks it), preserving the order the
        // single-function version ran in: sync login is in flight by the time a
        // handler starts listing folders on the interactive connection.
        m_connected = true;
        m_keepAlive.start();
        startSyncSession();
        Q_EMIT connectedChanged(true);
    });
    login->start();
}

/// Third connection, dedicated to background transfers. Best-effort: if the
/// server refuses it, callers fall back to the interactive session.
void ImapBackend::startSyncSession()
{
    if (m_syncSession || !m_connected)
        return;
    m_syncSession = new KIMAP::Session(m_credentials.host, quint16(m_credentials.port), this);
    const auto drop = [this] {
        // A connection dropped while a background fetch was in flight is the
        // server pushing back on heavy fetching (Gmail does this rather than
        // failing the job cleanly). Reported as throttling so the caller grows
        // its backoff instead of reconnecting and hammering at full speed.
        m_syncReady = false;
        m_syncFolder.clear();
    m_syncQueuedFolder.clear();
        if (m_syncSession) {
            m_syncSession->deleteLater();
            m_syncSession.clear();
        }
        Q_EMIT throttled();
    };
    connect(m_syncSession, &KIMAP::Session::connectionFailed, this, drop);
    connect(m_syncSession, &KIMAP::Session::connectionLost, this, drop);
    auto *login = new KIMAP::LoginJob(m_syncSession);
    configureLogin(login);
    connect(login, &KJob::result, this, [this, drop](KJob *job) {
        if (job->error() || !m_syncSession) {
            qWarning() << "mailove: sync-session login failed:" << job->errorString();
            drop();
            return;
        }
        m_syncReady = true;
    });
    login->start();
}

void ImapBackend::withSyncSession(const QString &folder,
                                  const std::function<void(KIMAP::Session *)> &fn)
{
    if (!m_syncSession || !m_syncReady) {
        fn(nullptr);
        return;
    }
    // The queued folder, not the selected one — and the caller's job is queued
    // immediately behind the SELECT rather than when it completes.
    //
    // Waiting cost this connection the same bug the write path had. Two reads
    // of different folders overlap constantly here (the folder pass, the
    // background poll, an unread reconcile): each saw the *other* folder still
    // selected, each queued its own SELECT, and both then queued their FETCH
    // or SEARCH when their SELECT came back — by which time the other SELECT
    // was already ahead of it. Both commands then ran against whichever
    // mailbox was selected last. It was two searches for INBOX and Junk coming
    // back with an identical answer that made it visible; a header fetch
    // reading the wrong folder is the same fault and says nothing at all.
    if (m_syncQueuedFolder != folder) {
        auto *select = new KIMAP::SelectJob(m_syncSession);
        select->setMailBox(folder);
        select->setOpenReadOnly(true);
        m_syncQueuedFolder = folder;
        connect(select, &KJob::result, this, [this, folder](KJob *job) {
            if (job->error() || !m_syncSession) {
                // Nothing reliable is selected now; make the next caller ask
                // for its own SELECT rather than trust this one.
                if (m_syncQueuedFolder == folder)
                    m_syncQueuedFolder.clear();
                m_syncFolder.clear();
    m_syncQueuedFolder.clear();
                return;
            }
            m_syncFolder = folder;
            m_messageCounts[folder] = static_cast<KIMAP::SelectJob *>(job)->messageCount();
        });
        select->start();
    }
    fn(m_syncSession.data());
}

bool ImapBackend::pushActive() const
{
    return !m_idleJob.isNull();
}

void ImapBackend::stopPush()
{
    if (m_idleSession) {
        qCDebug(logTrace, "push: dropping the idle connection on %s (idle job %s)",
                qUtf8Printable(m_pushFolder), m_idleJob.isNull() ? "gone" : "still live");
    }
    m_pushRetry.stop();
    m_idleJob.clear(); // owned by the session; dies with it
    if (m_idleSession) {
        m_idleSession->deleteLater();
        m_idleSession.clear();
    }
}

void ImapBackend::schedulePushRetry()
{
    // The session first, always: a half-built one (logged in but not selected,
    // or selected but never idled) still holds an open socket the server will
    // talk to, and nothing is left to answer.
    const QString folder = m_pushFolder;
    stopPush();
    if (!m_connected || folder.isEmpty())
        return;
    m_pushFolder = folder; // stopPush() does not clear it, but be explicit
    qCDebug(logTrace, "push: retrying %s in %d ms", qUtf8Printable(folder), m_pushBackoffMs);
    m_pushRetry.start(m_pushBackoffMs);
    m_pushBackoffMs = qMin(m_pushBackoffMs * 2, kPushBackoffMaxMs);
}

/// IMAP IDLE on a dedicated connection: the server reports new mail in the
/// watched folder instantly instead of waiting for a poll. Best-effort — any
/// failure just means the caller's refresh timer stays the only source.
void ImapBackend::startPush(const QString &folder)
{
    stopPush();
    if (!m_connected || folder.isEmpty())
        return;
    m_pushFolder = folder;

    m_idleSession = new KIMAP::Session(m_credentials.host, quint16(m_credentials.port), this);
    // The session this attempt belongs to. Every stage below checks that it is
    // still the current one before reacting, for the same reason the IdleJob
    // result does: opening a folder (or switching account) tears the push
    // connection down, and the login or select already in flight on it then
    // fails with the server-sounding "Connection to server lost" that we
    // caused. Acting on that killed the replacement connection and booked a
    // retry against a backoff that kept doubling — two lines per switch, and
    // push effectively off.
    QPointer<KIMAP::Session> attempt = m_idleSession;
    qCDebug(logTrace, "push: opening an idle connection for %s", qUtf8Printable(folder));
    auto *login = new KIMAP::LoginJob(m_idleSession);
    configureLogin(login);
    connect(login, &KJob::result, this, [this, folder, attempt](KJob *job) {
        if (m_idleSession.isNull() || m_idleSession != attempt)
            return; // ours was replaced or dropped; not this attempt's business
        if (job->error()) {
            qWarning() << "mailove: idle login failed:" << job->errorString();
            schedulePushRetry();
            return;
        }
        auto *select = new KIMAP::SelectJob(m_idleSession);
        select->setMailBox(folder);
        select->setOpenReadOnly(true);
        connect(select, &KJob::result, this, [this, folder, attempt](KJob *job) {
            if (m_idleSession.isNull() || m_idleSession != attempt)
                return;
            if (job->error()) {
                qWarning() << "mailove: idle select failed:" << job->errorString();
                schedulePushRetry();
                return;
            }
            // The connection works; the next failure starts counting again
            // from the short interval rather than from wherever an earlier
            // outage left the backoff.
            m_pushBackoffMs = kPushBackoffMinMs;
            auto *idle = new KIMAP::IdleJob(m_idleSession);
            m_idleJob = idle;
            // The window in which the server's keepalives have a job to land
            // in. KIMAP warns "a message was received from the server with no
            // job to handle it" for anything arriving outside it, and that
            // warning names no connection — so the pair of lines here is what
            // says whether IDLE was live at the time.
            qCDebug(logTrace, "push: IDLE started on %s", qUtf8Printable(folder));
            connect(idle, &KIMAP::IdleJob::mailBoxStats, this,
                    [this, folder](KIMAP::IdleJob *, const QString &mailBox, int, int) {
                        if (mailBox == folder)
                            Q_EMIT folderChanged(mailBox);
                    });
            connect(idle, &KJob::result, this, [this](KJob *job) {
                // Only the job we are actually watching. Reopening a folder
                // calls startPush(), which stops the old session before
                // building the new one — and the old IdleJob's result lands
                // *after* that, reporting the "Connection to server lost" we
                // caused by deleting its session. Acting on it tore down the
                // healthy new session and booked a retry 30 seconds out, so
                // every folder click cost push for half a minute and left a
                // warning implying the server had dropped us. m_idleJob is a
                // QPointer cleared by stopPush(), so a stale result never
                // matches.
                if (m_idleJob.isNull() || m_idleJob.data() != job)
                    return;
                // Server ended IDLE (timeout, capability missing, a dropped
                // socket) — come back later. The teardown is unconditional:
                // it used to be skipped while disconnected, which left the
                // dead session (and, when the drop was one-sided, its open
                // socket) standing until something else called startPush.
                // Jobless but connected is the state that makes KIMAP warn
                // about the server's keepalives having no job to handle them.
                qCDebug(logTrace, "push: IDLE ended on %s (%s)",
                        qUtf8Printable(m_pushFolder),
                        job->error() ? qUtf8Printable(job->errorString()) : "no error");
                if (job->error())
                    qWarning() << "mailove: idle ended:" << job->errorString();
                schedulePushRetry();
            });
            idle->start();
        });
        select->start();
    });
    login->start();
}

// --- Folders ---------------------------------------------------------------

/// True when \a flags contains \a flag, compared the case-insensitive way RFC
/// 3501 requires of mailbox attributes.
static bool hasFlag(const QList<QByteArray> &flags, const char *flag)
{
    for (const QByteArray &f : flags) {
        if (f.compare(flag, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

/// The RFC 6154 special-use attribute of a mailbox, as a role. Servers that do
/// not implement the extension report nothing here, and the caller falls back
/// to recognising folders by name — which is exactly the guesswork JMAP's
/// mandatory `role` property removes.
static MailBackend::FolderRole roleFromFlags(const QList<QByteArray> &flags)
{
    using Role = MailBackend::FolderRole;
    if (hasFlag(flags, "\\Sent"))
        return Role::Sent;
    if (hasFlag(flags, "\\Drafts"))
        return Role::Drafts;
    if (hasFlag(flags, "\\Trash"))
        return Role::Trash;
    if (hasFlag(flags, "\\Junk"))
        return Role::Junk;
    if (hasFlag(flags, "\\Archive"))
        return Role::Archive;
    // Gmail's "everything" mailbox, which re-lists every message already held
    // under the inbox and each label.
    if (hasFlag(flags, "\\All"))
        return Role::All;
    return Role::None;
}

void ImapBackend::listFolders()
{
    if (!m_session) {
        Q_EMIT errorOccurred(Error::Connection, tr("Not connected."));
        return;
    }
    auto *list = new KIMAP::ListJob(m_session);
    list->setOption(KIMAP::ListJob::IncludeUnsubscribed);

    // Shared with the result handler: LIST answers in several deliveries and
    // only the last one means the set is complete.
    auto folders = std::make_shared<QList<FolderInfo>>();
    auto separator = std::make_shared<QChar>();
    connect(list, &KIMAP::ListJob::mailBoxesReceived, this,
            [folders, separator](const QList<KIMAP::MailBoxDescriptor> &descriptors,
                                 const QList<QList<QByteArray>> &flagList) {
                for (int i = 0; i < descriptors.size(); ++i) {
                    const auto &d = descriptors.at(i);
                    FolderInfo f;
                    f.path = d.name;
                    f.separator = d.separator;
                    if (!d.separator.isNull())
                        *separator = d.separator;
                    if (i < flagList.size()) {
                        f.selectable = !hasFlag(flagList.at(i), "\\Noselect");
                        f.role = roleFromFlags(flagList.at(i));
                    }
                    // RFC 3501 fixes the inbox's name, so this one role can be
                    // stated even by a server without the special-use extension.
                    if (f.role == FolderRole::None
                        && f.path.compare(QLatin1String("INBOX"), Qt::CaseInsensitive) == 0)
                        f.role = FolderRole::Inbox;
                    folders->append(f);
                }
            });
    connect(list, &KJob::result, this, [this, folders, separator](KJob *job) {
        if (job->error()) {
            Q_EMIT errorOccurred(Error::Protocol, job->errorString());
            return;
        }
        Q_EMIT foldersListed(*folders, *separator);
    });
    list->start();
}

/// Shared tail of the three folder writes: report the job's outcome once.
void ImapBackend::finishFolderOp(KJob *job, const OpCallback &done)
{
    if (!done)
        return;
    if (job->error())
        done(Error::Protocol, job->errorString());
    else
        done(Error::None, QString());
}

void ImapBackend::createFolder(const QString &path, const OpCallback &done)
{
    if (!m_session) {
        if (done)
            done(Error::Connection, tr("Not connected."));
        return;
    }
    auto *create = new KIMAP::CreateJob(m_session);
    create->setMailBox(path);
    connect(create, &KJob::result, this,
            [this, done](KJob *job) { finishFolderOp(job, done); });
    create->start();
}

void ImapBackend::renameFolder(const QString &from, const QString &to,
                               const OpCallback &done)
{
    if (!m_session) {
        if (done)
            done(Error::Connection, tr("Not connected."));
        return;
    }
    auto *rename = new KIMAP::RenameJob(m_session);
    rename->setSourceMailBox(from);
    rename->setDestinationMailBox(to);
    connect(rename, &KJob::result, this,
            [this, done](KJob *job) { finishFolderOp(job, done); });
    rename->start();
}

void ImapBackend::deleteFolder(const QString &path, const OpCallback &done)
{
    if (!m_session) {
        if (done)
            done(Error::Connection, tr("Not connected."));
        return;
    }
    auto *del = new KIMAP::DeleteJob(m_session);
    del->setMailBox(path);
    connect(del, &KJob::result, this,
            [this, done](KJob *job) { finishFolderOp(job, done); });
    del->start();
}

// --- Messages --------------------------------------------------------------

KIMAP::SelectJob *ImapBackend::issueSelect(const QString &folder, bool readWrite)
{
    auto *select = new KIMAP::SelectJob(m_session);
    select->setMailBox(folder);
    select->setOpenReadOnly(!readWrite);
    // Recorded now, not when the result arrives. Everything queued on this
    // session after this job runs against this mailbox, so this is what a
    // later "is it already selected?" has to be answered from.
    m_queuedFolder = folder;
    m_queuedReadWrite = readWrite;
    connect(select, &KJob::result, this, [this, folder, readWrite](KJob *job) {
        if (job->error()) {
            // Nothing is reliably selected now. Clearing both makes the next
            // caller issue its own SELECT rather than trust a mailbox the
            // server just refused to open.
            if (m_queuedFolder == folder) {
                m_queuedFolder.clear();
                m_queuedReadWrite = false;
            }
            m_selectedFolder.clear();
            m_selectedReadWrite = false;
            return;
        }
        auto *sel = static_cast<KIMAP::SelectJob *>(job);
        m_selectedFolder = folder;
        // What the server GRANTED, not what was asked: a SELECT can succeed
        // and still answer [READ-ONLY] (an ACL-restricted or otherwise
        // write-protected mailbox). Recording the request here marked such a
        // folder writable, and the STORE that followed was refused with the
        // server's "NO STORE attempt on READ-ONLY folder".
        m_selectedReadWrite = !sel->isOpenReadOnly();
        if (!m_selectedReadWrite && m_queuedFolder == folder)
            m_queuedReadWrite = false;
        // Asked-for versus granted, plus what the server says can be stored
        // permanently. A write refused on a mailbox that answered writable is
        // otherwise indistinguishable from a bug in our own bookkeeping, and
        // the difference decides where to look next.
        qCDebug(logTrace, "select %s: asked %s, granted %s, permanent flags %s",
                qUtf8Printable(folder), readWrite ? "read-write" : "read-only",
                m_selectedReadWrite ? "read-write" : "read-only",
                qUtf8Printable(QString::fromLatin1(
                    QByteArrayList(sel->permanentFlags().cbegin(),
                                   sel->permanentFlags().cend()).join(' '))));
        // EXISTS and UIDVALIDITY come free with every SELECT; positional
        // windows need the first, and the caller compares the second against
        // what it stored to notice a mailbox the server regenerated.
        m_messageCounts[folder] = sel->messageCount();
        m_lastUidValidity = sel->uidValidity();
    });
    select->start();
    return select;
}

void ImapBackend::selectThenQueue(const QString &folder,
                                  const std::function<void()> &queueWork)
{
    // Only when the session is already headed there read-write. Anything else
    // — a different mailbox, one opened read-only, or one whose SELECT is
    // still in flight — gets its own SELECT immediately in front of the work.
    if (m_queuedFolder != folder || !m_queuedReadWrite)
        issueSelect(folder, true);
    // No waiting, deliberately: the two jobs go into the session's queue back
    // to back, so nothing can be queued between them. See the header.
    queueWork();
}

void ImapBackend::withFolderSelected(
    const QString &folder, bool readWrite,
    const std::function<void(bool ok, const QString &error)> &then)
{
    if (!m_session) {
        then(false, tr("Not connected."));
        return;
    }
    if (m_queuedFolder == folder && (m_queuedReadWrite || !readWrite)) {
        then(true, QString());
        return;
    }
    auto *select = issueSelect(folder, readWrite);
    // After issueSelect's own handler, which Qt runs first because it was
    // connected first — so m_selectedReadWrite below is this SELECT's answer.
    connect(select, &KJob::result, this, [this, folder, readWrite, then](KJob *job) {
        if (job->error()) {
            then(false, job->errorString());
            return;
        }
        if (readWrite && !m_selectedReadWrite) {
            // Failing here spares the round trip a doomed write costs and
            // turns the server's cryptic refusal into a statement of fact.
            then(false, tr("%1 is read-only on the server").arg(folder));
            return;
        }
        then(true, QString());
    });
}

/// The protocol-neutral flag names of MailBackend::HeaderInfo, as IMAP spells
/// them. Anything unrecognised is passed through untouched, so a caller can
/// still name a server-specific keyword.
static QByteArray imapFlag(const QString &flag)
{
    static const QHash<QString, QByteArray> known = {
        {QStringLiteral("seen"), QByteArrayLiteral("\\Seen")},
        {QStringLiteral("deleted"), QByteArrayLiteral("\\Deleted")},
        {QStringLiteral("draft"), QByteArrayLiteral("\\Draft")},
        {QStringLiteral("flagged"), QByteArrayLiteral("\\Flagged")},
        {QStringLiteral("answered"), QByteArrayLiteral("\\Answered")},
    };
    const auto it = known.constFind(flag.toLower());
    return it != known.cend() ? it.value() : flag.toUtf8();
}

/// IMAP addresses messages by numeric uid, which is what remoteId holds for
/// this backend (see MessageListModel::Header::remoteId). Ids that are not
/// numbers cannot have come from here and are dropped rather than guessed at.
static KIMAP::ImapSet uidSet(const QStringList &remoteIds)
{
    KIMAP::ImapSet set;
    for (const QString &id : remoteIds) {
        bool ok = false;
        const qint64 uid = id.toLongLong(&ok);
        if (ok && uid > 0)
            set.add(uid);
    }
    return set;
}

void ImapBackend::setFlags(const QString &folder, const QStringList &remoteIds,
                           const QStringList &addFlags, const QStringList &removeFlags,
                           const OpCallback &done)
{
    const KIMAP::ImapSet set = uidSet(remoteIds);
    if (set.isEmpty()) {
        if (done)
            done(Error::None, QString());
        return;
    }
    if (!m_session) {
        if (done)
            done(Error::Connection, tr("Not connected."));
        return;
    }
    {
        // Two STOREs when both directions are asked for: IMAP has no single
        // command that adds some flags and removes others. Each is queued
        // behind its own SELECT — the second one is created in the first's
        // callback, which is another gap something else can queue into.
        const auto run = [this, folder, set](const QStringList &flags, bool add,
                                     const std::function<void(bool, QString)> &next) {
            if (flags.isEmpty()) {
                next(true, QString());
                return;
            }
            QList<QByteArray> imapFlags;
            for (const QString &f : flags)
                imapFlags.append(imapFlag(f));
            selectThenQueue(folder, [this, folder, set, add, imapFlags, next] {
                auto *store = new KIMAP::StoreJob(m_session);
                store->setUidBased(true);
                store->setSequenceSet(set);
                store->setMode(add ? KIMAP::StoreJob::AppendFlags
                                   : KIMAP::StoreJob::RemoveFlags);
                store->setFlags(imapFlags);
                connect(store, &KJob::result, this, [this, folder, next](KJob *job) {
                    if (job->error())
                        noteWriteRefusal(folder, job->errorString());
                    next(!job->error(), job->errorString());
                });
                store->start();
            });
        };
        run(addFlags, true, [run, removeFlags, done](bool ok, const QString &error) {
            if (!ok) {
                if (done)
                    done(Error::Protocol, error);
                return;
            }
            run(removeFlags, false, [done](bool ok, const QString &error) {
                if (done)
                    done(ok ? Error::None : Error::Protocol, ok ? QString() : error);
            });
        });
    }
}

void ImapBackend::moveMessages(const QString &folder, const QStringList &remoteIds,
                               const QString &targetFolder, const OpCallback &done)
{
    const KIMAP::ImapSet set = uidSet(remoteIds);
    if (set.isEmpty()) {
        if (done)
            done(Error::None, QString());
        return;
    }
    withFolderSelected(folder, true,
                       [this, set, targetFolder, done](bool ok, const QString &error) {
        if (!ok) {
            if (done)
                done(Error::Protocol, error);
            return;
        }
        auto *move = new KIMAP::MoveJob(m_session);
        move->setUidBased(true);
        move->setSequenceSet(set);
        move->setMailBox(targetFolder);
        connect(move, &KJob::result, this, [done](KJob *job) {
            if (done)
                done(job->error() ? Error::Protocol : Error::None, job->errorString());
        });
        move->start();
    });
}

void ImapBackend::noteWriteRefusal(const QString &folder, const QString &error)
{
    if (!error.contains(QLatin1String("READ-ONLY"), Qt::CaseInsensitive))
        return;
    // withFolderSelected() already refuses to write to a mailbox the server
    // answered [READ-ONLY] on. Reaching here means it was answered writable
    // and refused anyway — an ACL the SELECT did not reflect, a proxy, or a
    // mailbox that changed under us. Either way the cache of "Junk is open
    // read-write" is wrong, and left standing it makes every later attempt
    // skip the SELECT and repeat the same refusal.
    qWarning() << "mailove:" << folder
               << "refused a write although its SELECT reported it writable";
    if (m_selectedFolder == folder) {
        m_selectedReadWrite = false;
        // Cleared, not just marked: the next withFolderSelected() has to issue
        // a real SELECT to find out what the server says now.
        m_selectedFolder.clear();
    }
}

void ImapBackend::deleteMessages(const QString &folder, const QStringList &remoteIds,
                                 const OpCallback &done)
{
    const KIMAP::ImapSet set = uidSet(remoteIds);
    if (set.isEmpty()) {
        if (done)
            done(Error::None, QString());
        return;
    }
    // IMAP has no "destroy these": \Deleted marks them and EXPUNGE is what
    // actually removes them, so the two always travel together here.
    if (!m_session) {
        if (done)
            done(Error::Connection, tr("Not connected."));
        return;
    }
    selectThenQueue(folder, [this, folder, set, done] {
        auto *store = new KIMAP::StoreJob(m_session);
        store->setUidBased(true);
        store->setSequenceSet(set);
        store->setMode(KIMAP::StoreJob::AppendFlags);
        store->setFlags({QByteArrayLiteral("\\Deleted")});
        connect(store, &KJob::result, this, [this, folder, done](KJob *job) {
            if (job->error()) {
                noteWriteRefusal(folder, job->errorString());
                if (done)
                    done(Error::Protocol, job->errorString());
                return;
            }
            // Re-assert the selection before expunging, in front of the
            // EXPUNGE in the same queue. EXPUNGE acts on whatever mailbox the
            // connection has selected, and the event loop runs between the
            // STORE finishing and this job being created — so another
            // operation can SELECT a different mailbox in the gap, and the
            // expunge would then destroy *that* folder's \Deleted messages
            // instead.
            selectThenQueue(folder, [this, done] {
                auto *expunge = new KIMAP::ExpungeJob(m_session);
                connect(expunge, &KJob::result, this, [done](KJob *ejob) {
                    if (done)
                        done(ejob->error() ? Error::Protocol : Error::None,
                             ejob->errorString());
                });
                expunge->start();
            });
        });
        store->start();
    });
}

// --- Reading ---------------------------------------------------------------

qint64 ImapBackend::messageCount(const QString &folder) const
{
    return m_messageCounts.value(folder, 0);
}

void ImapBackend::openFolder(const QString &folder, const QString &syncToken)
{
    // EXAMINE, not SELECT: browsing must not clear \Recent or mark anything.
    // A write re-SELECTs read-write when it needs to (withFolderSelected).
    withFolderSelected(folder, false, [this, folder, syncToken](bool ok, const QString &error) {
        if (!ok) {
            Q_EMIT errorOccurred(Error::Protocol, error);
            return;
        }
        // UIDVALIDITY is IMAP's resume token, and for IMAP alone it is also the
        // validity marker: RFC 3501 §2.3.1.1 says a different one means every
        // uid the caller cached now names a different message, or nothing. That
        // reading is made here rather than by the caller because it is true of
        // IMAP and false of JMAP, whose token changes whenever anything does.
        const QString current = m_lastUidValidity > 0 ? QString::number(m_lastUidValidity)
                                                      : QString();
        if (!syncToken.isEmpty() && !current.isEmpty() && current != syncToken) {
            qWarning() << "mailove: UIDVALIDITY of" << folder << "changed" << syncToken << "->"
                       << current << "- the cached messages are void";
            Q_EMIT folderInvalidated(folder);
        }
        Q_EMIT folderOpened(folder, m_messageCounts.value(folder, 0), current);
    });
}

void ImapBackend::withReadSession(const QString &folder, bool background,
                                  const std::function<void(KIMAP::Session *)> &fn)
{
    if (!background) {
        // Interactive work goes on the connection the folder is already open
        // on; anything else would cost a SELECT the user waits for. Queued in
        // front of the caller's job rather than awaited, for the reason spelled
        // out in withSyncSession(): waiting hands the mailbox to whoever
        // queued a SELECT in the meantime.
        if (!m_session) {
            fn(nullptr);
            return;
        }
        if (m_queuedFolder != folder)
            issueSelect(folder, false);
        fn(m_session.data());
        return;
    }
    // Background work gets its own connection so a folder click never queues
    // behind a multi-second FETCH. If there is none, fall back to the
    // interactive one only when it already has the folder open — never by
    // re-SELECTing it, which would yank the mailbox out from under the user.
    if (m_syncSession && m_syncReady) {
        withSyncSession(folder, fn);
        return;
    }
    // The queued selection again: m_selectedFolder is what the connection has
    // finished selecting, which during any overlap names the folder it is
    // about to leave.
    fn(m_queuedFolder == folder ? m_session.data() : nullptr);
}

void ImapBackend::runHeaderFetch(KIMAP::Session *session, const QString &folder,
                                 const KIMAP::ImapSet &set, bool uidBased, qint64 minUid,
                                 const OpCallback &done)
{
    auto *fetch = new KIMAP::FetchJob(session);
    fetch->setSequenceSet(set);
    fetch->setUidBased(uidBased);
    KIMAP::FetchJob::FetchScope scope;
    // FullHeaders, not Headers: Authentication-Results is needed for the
    // SPF/DKIM/DMARC verdict and the minimal set does not include it.
    scope.mode = KIMAP::FetchJob::FetchScope::FullHeaders;
    fetch->setScope(scope);

    connect(fetch, &KIMAP::FetchJob::messagesAvailable, this,
            [this, folder, minUid](const QMap<qint64, KIMAP::Message> &messages) {
                QList<HeaderInfo> out;
                out.reserve(messages.size());
                for (auto it = messages.cbegin(); it != messages.cend(); ++it) {
                    const KIMAP::Message &m = it.value();
                    if (!m.message || m.uid <= 0 || m.uid <= minUid)
                        continue;
                    HeaderInfo h;
                    h.uid = m.uid;
                    h.remoteId = QString::number(m.uid);
                    // KIMAP's own parsed message, passed through rather than
                    // re-parsed: re-parsing one loses fidelity, and everything
                    // derived from a header is the same work whichever protocol
                    // delivered it.
                    h.message = m.message;
                    h.size = m.size;
                    for (const QByteArray &flag : m.flags) {
                        if (flag.compare("\\Seen", Qt::CaseInsensitive) == 0)
                            h.flags.append(QStringLiteral("seen"));
                        else if (flag.compare("\\Deleted", Qt::CaseInsensitive) == 0)
                            h.flags.append(QStringLiteral("deleted"));
                        else if (flag.compare("\\Draft", Qt::CaseInsensitive) == 0)
                            h.flags.append(QStringLiteral("draft"));
                        else if (flag.compare("\\Flagged", Qt::CaseInsensitive) == 0)
                            h.flags.append(QStringLiteral("flagged"));
                        else if (flag.compare("\\Answered", Qt::CaseInsensitive) == 0)
                            h.flags.append(QStringLiteral("answered"));
                    }
                    out.append(h);
                }
                if (!out.isEmpty())
                    Q_EMIT headersFetched(folder, out);
            });
    connect(fetch, &KJob::result, this, [this, done](KJob *job) {
        if (job->error() && isTooManyConnections(job->errorString())) {
            // Answered by using fewer connections, not only by waiting.
            shrinkBodyPool();
        }
        if (!done)
            return;
        done(job->error() ? Error::Protocol : Error::None, job->errorString());
    });
    fetch->start();
}

void ImapBackend::fetchHeaderWindow(const QString &folder, int fromNewest, int count,
                                    bool background, const OpCallback &done)
{
    const qint64 total = m_messageCounts.value(folder, 0);
    if (total <= 0 || count <= 0 || fromNewest >= total) {
        if (done)
            done(Error::None, QString());
        return;
    }
    // Positional window → sequence range. This is the one place sequence
    // numbers exist, and the only reason the mailbox size is tracked at all:
    // "the newest N" cannot be expressed by uid, which is sparse.
    const qint64 to = total - fromNewest;
    const qint64 from = qMax(qint64(1), to - count + 1);
    withReadSession(folder, background, [this, folder, from, to, done](KIMAP::Session *s) {
        if (!s) {
            if (done)
                done(Error::Connection, tr("No connection available for %1.").arg(folder));
            return;
        }
        runHeaderFetch(s, folder, KIMAP::ImapSet(from, to), false, 0, done);
    });
}

void ImapBackend::fetchHeadersSince(const QString &folder, const QString &sinceRemoteId,
                                    const OpCallback &done)
{
    bool ok = false;
    const qint64 sinceUid = sinceRemoteId.toLongLong(&ok);
    KIMAP::ImapSet set;
    // Open-ended "uid:*". Deliberately not a positional window: after a
    // reconnect the point is to catch up on whatever arrived, and how many
    // that is, is exactly what is not known yet.
    set.add(KIMAP::ImapInterval((ok && sinceUid > 0) ? sinceUid + 1 : 1));
    withReadSession(folder, false, [this, folder, set, sinceUid, ok, done](KIMAP::Session *s) {
        if (!s) {
            if (done)
                done(Error::Connection, tr("No connection available for %1.").arg(folder));
            return;
        }
        // "uid:*" always returns the mailbox's newest message even when its uid
        // is below the range asked for, hence the cutoff rather than trusting
        // the server to have honoured the interval.
        runHeaderFetch(s, folder, set, true, ok ? sinceUid : 0, done);
    });
}

void ImapBackend::fetchHeadersById(const QString &folder, const QStringList &remoteIds,
                                   const OpCallback &done)
{
    const KIMAP::ImapSet set = uidSet(remoteIds);
    if (set.isEmpty()) {
        if (done)
            done(Error::None, QString());
        return;
    }
    withReadSession(folder, false, [this, folder, set, done](KIMAP::Session *s) {
        if (!s) {
            if (done)
                done(Error::Connection, tr("No connection available for %1.").arg(folder));
            return;
        }
        runHeaderFetch(s, folder, set, true, 0, done);
    });
}

// --- Bodies ----------------------------------------------------------------

bool ImapBackend::bodyFetchActive() const
{
    if (m_bodyFallbackBusy)
        return true;
    for (const auto &conn : m_bodyPool) {
        if (conn->busy)
            return true;
    }
    return false;
}

bool ImapBackend::ensureBackgroundReady()
{
    if (m_syncSession && m_syncReady)
        return true;
    // The background connection can be dropped on its own — Gmail throttling
    // the backfill while leaving the interactive session up is the usual way.
    // Reopening is a no-op when one already exists (it is merely still logging
    // in), so this is safe to call on every tick.
    startSyncSession();
    return false;
}

int ImapBackend::freeBodySlots() const
{
    if (!m_connected)
        return 0;
    int free = 0;
    bool anyReady = false;
    for (const auto &conn : m_bodyPool) {
        if (!conn->session || !conn->ready)
            continue;
        anyReady = true;
        if (!conn->busy)
            ++free;
    }
    // While the pool is still logging in (or was refused outright), one batch
    // may still run on the background connection, so bodies flow either way.
    if (!anyReady && !m_bodyFallbackBusy && m_syncReady)
        return 1;
    return free;
}

void ImapBackend::shrinkBodyPool()
{
    // Stop growing the pool, and shed one idle connection so the concurrent
    // count actually drops. A busy one is left to finish and reused; the cap
    // flag keeps us from re-adding.
    m_bodyPoolBroken = true;
    for (int i = 0; i < m_bodyPool.size(); ++i) {
        if (!m_bodyPool.at(i)->busy) {
            auto conn = m_bodyPool.takeAt(i);
            if (conn->session)
                conn->session->deleteLater();
            break;
        }
    }
    qWarning() << "mailove: reduced body-fetch pool to" << m_bodyPool.size()
               << "after connection-cap refusal";
}

void ImapBackend::ensureBodyPool()
{
    // Extra connections only once the server has proven it grants us a second
    // one at all (the background session), and never after a refusal.
    if (!m_connected || !m_syncReady || m_bodyPoolBroken)
        return;
    // Keep the total concurrent connection count low (interactive + IDLE +
    // background + these) — well under the ~15 servers like Gmail cap, and near
    // the 2–3 recommended to avoid throttling. imap/bodyPoolSize is where a
    // server with a stricter (or looser) limit is accommodated; 0 turns the
    // pool off and leaves body fetches on the shared session.
    while (m_bodyPool.size() < AdvancedConfig::i("imap/bodyPoolSize")) {
        auto conn = std::make_shared<BodyConn>();
        conn->session = new KIMAP::Session(m_credentials.host,
                                           quint16(m_credentials.port), this);
        m_bodyPool.append(conn);
        const auto drop = [this, conn] {
            if (conn->session)
                conn->session->deleteLater();
            m_bodyPool.removeAll(conn);
        };
        connect(conn->session, &KIMAP::Session::connectionFailed, this, drop);
        connect(conn->session, &KIMAP::Session::connectionLost, this, drop);
        auto *login = new KIMAP::LoginJob(conn->session);
        configureLogin(login);
        connect(login, &KJob::result, this, [this, conn, drop](KJob *job) {
            if (job->error() || !conn->session) {
                qWarning() << "mailove: body-pool login failed:" << job->errorString();
                // The server likely caps concurrent connections — settle for
                // what we have until the next (re)connect.
                m_bodyPoolBroken = true;
                drop();
                return;
            }
            conn->ready = true;
        });
        login->start();
    }
}

void ImapBackend::fetchBodies(const QString &folder, const QStringList &remoteIds,
                              const OpCallback &done)
{
    const KIMAP::ImapSet set = uidSet(remoteIds);
    if (set.isEmpty()) {
        if (done)
            done(Error::None, QString());
        return;
    }
    ensureBodyPool();

    // Preferred path: a free pool connection, so bulk transfer never shares a
    // connection with anything the user is waiting on.
    for (const auto &conn : m_bodyPool) {
        if (!conn->session || !conn->ready || conn->busy)
            continue;
        conn->busy = true;
        const auto release = [conn] { conn->busy = false; };
        if (conn->folder == folder) {
            startBodyFetchJob(conn->session.data(), folder, set, done, release);
            return;
        }
        auto *select = new KIMAP::SelectJob(conn->session);
        select->setMailBox(folder);
        select->setOpenReadOnly(true);
        connect(select, &KJob::result, this,
                [this, conn, folder, set, done, release](KJob *job) {
                    if (job->error() || !conn->session) {
                        // Dropped ids come back round on a later pass.
                        release();
                        if (done)
                            done(Error::Protocol, job->errorString());
                        return;
                    }
                    conn->folder = folder;
                    startBodyFetchJob(conn->session.data(), folder, set, done, release);
                });
        select->start();
        return;
    }

    // Fallback while the pool is still logging in, or was refused.
    if (m_bodyFallbackBusy) {
        if (done)
            done(Error::None, QString());
        return;
    }
    m_bodyFallbackBusy = true;
    withSyncSession(folder, [this, folder, set, done](KIMAP::Session *s) {
        if (!s) {
            m_bodyFallbackBusy = false;
            if (done)
                done(Error::Connection, tr("No connection available for %1.").arg(folder));
            return;
        }
        startBodyFetchJob(s, folder, set, done, [this] { m_bodyFallbackBusy = false; });
    });
}

void ImapBackend::startBodyFetchJob(KIMAP::Session *session, const QString &folder,
                                    const KIMAP::ImapSet &set, const OpCallback &done,
                                    const std::function<void()> &release)
{
    // Two FETCHes per batch, not one. The halves have to be asked for
    // separately because of how KIMAP hands each back:
    //
    //  - FullHeaders answers BODY.PEEK[HEADER] and is one of the three modes
    //    whose end-of-response code assigns msg.message at all — Content mode
    //    parses the same header into a message it then never delivers. This is
    //    also where FLAGS and RFC822.SIZE ride along.
    //  - Content with parts={TEXT} answers BODY.PEEK[TEXT] into the parts map
    //    via setBody(), which is the one route through KIMAP that neither
    //    KMime-parses nor re-encodes the payload (setContent() does both, and
    //    is where KDE bug 523826 lives — see RawMessage above).
    //
    // Both jobs queue on the same session, so this is one extra round trip per
    // batch, not per message.
    auto *headers = new KIMAP::FetchJob(session);
    headers->setSequenceSet(set);
    headers->setUidBased(true);
    KIMAP::FetchJob::FetchScope headScope;
    headScope.mode = KIMAP::FetchJob::FetchScope::FullHeaders;
    headers->setScope(headScope);

    auto *content = new KIMAP::FetchJob(session);
    content->setSequenceSet(set);
    content->setUidBased(true);
    KIMAP::FetchJob::FetchScope textScope;
    textScope.mode = KIMAP::FetchJob::FetchScope::Content;
    textScope.parts = {QByteArrayLiteral("TEXT")};
    content->setScope(textScope);

    // Emit each body the moment its second half lands: memory stays flat
    // (roughly one body at a time) however big the batch is, and the parse and
    // indexing work downstream spreads across the socket events. `found`
    // stashes half-arrived messages — the two jobs stream independently.
    auto found = std::make_shared<QHash<qint64, RawMessage>>();
    auto sent = std::make_shared<QSet<qint64>>();
    const auto onMessages =
        [this, folder, found, sent](const QMap<qint64, KIMAP::Message> &messages) {
            for (const KIMAP::Message &m : messages) {
                if (m.uid <= 0 || sent->contains(m.uid))
                    continue;
                RawMessage &raw = (*found)[m.uid];
                mergeRawParts(m, raw);
                if (raw.complete()) {
                    sent->insert(m.uid);
                    // take(), not remove-then-use: raw is a reference into the
                    // hash and dies with the entry.
                    const RawMessage whole = found->take(m.uid);
                    Q_EMIT bodyFetched(folder, QString::number(m.uid),
                                       buildMessage(whole));
                }
            }
        };
    connect(headers, &KIMAP::FetchJob::messagesAvailable, this, onMessages);
    connect(content, &KIMAP::FetchJob::messagesAvailable, this, onMessages);

    // One shared completion: the batch is done when both jobs are, and a
    // failure of either reports once and silences the survivor.
    auto remaining = std::make_shared<int>(2);
    auto failed = std::make_shared<bool>(false);
    const QPointer<KIMAP::FetchJob> headersPtr(headers);
    const QPointer<KIMAP::FetchJob> contentPtr(content);
    const auto onResult = [this, found, folder, done, release, remaining, failed,
                           headersPtr, contentPtr](KJob *job) {
        if (job->error()) {
            if (*failed)
                return; // the other job already reported this batch
            *failed = true;
            if (headersPtr && headersPtr != job)
                headersPtr->kill(KJob::Quietly);
            if (contentPtr && contentPtr != job)
                contentPtr->kill(KJob::Quietly);
            release();
            // Server pushback. On the concurrent-connection cap specifically,
            // shed a pool connection too so a retry does not hit the same wall.
            if (isTooManyConnections(job->errorString()))
                shrinkBodyPool();
            Q_EMIT throttled();
            if (done)
                done(Error::Throttled, job->errorString());
            return;
        }
        if (--*remaining > 0 || *failed)
            return;
        // Leftovers with only one half (rare — the server answered one FETCH
        // and not the other) are dropped, not emitted. Emitting a half-message
        // put headerless bodies into the viewer, the cache and the spam scorer
        // at once; saying nothing costs one backfill retry. uidsWithoutBody
        // cannot tell "dropped" from "never fetched", so they come back round.
        for (auto it = found->cbegin(); it != found->cend(); ++it)
            qWarning() << "mailove: uid" << it.key() << "in" << folder
                       << "arrived" << (it.value().haveHead ? "head-only" : "body-only")
                       << "- dropped for refetch";
        release();
        if (done)
            done(Error::None, QString());
    };
    connect(headers, &KJob::result, this, onResult);
    connect(content, &KJob::result, this, onResult);
    headers->start();
    content->start();
}

void ImapBackend::folderUnreadCounts(
    const QStringList &folders,
    const std::function<void(Error, const QHash<QString, int> &, const QString &)> &done)
{
    if (!m_session || folders.isEmpty()) {
        if (done)
            done(m_session ? Error::None : Error::Connection, {}, QString());
        return;
    }
    auto pending = std::make_shared<QStringList>(folders);
    auto counts = std::make_shared<QHash<QString, int>>();
    auto step = std::make_shared<std::function<void()>>();
    *step = [this, pending, counts, step, done] {
        if (pending->isEmpty() || !m_session) {
            if (done)
                done(Error::None, *counts, QString());
            return;
        }
        const QString folder = pending->takeFirst();
        auto *status = new KIMAP::StatusJob(m_session);
        status->setMailBox(folder);
        // UNSEEN only, and STATUS rather than SELECT: this must not disturb the
        // mailbox state of a client idling on the same account elsewhere.
        status->setDataItems({QByteArrayLiteral("UNSEEN")});
        connect(status, &KJob::result, this, [folder, counts, step](KJob *job) {
            if (!job->error()) {
                const auto items = static_cast<KIMAP::StatusJob *>(job)->status();
                for (const auto &item : items) {
                    if (item.first == "UNSEEN" && item.second > 0)
                        counts->insert(folder, int(item.second));
                }
            }
            // A folder that fails is skipped, not fatal: one unreadable mailbox
            // must not cost the account its other counts.
            (*step)();
        });
        status->start();
    };
    (*step)();
}

// --- Search ----------------------------------------------------------------

void ImapBackend::fetchUnseenIds(
    const QString &folder,
    const std::function<void(Error, const QStringList &, const QString &)> &done)
{
    // Read-only select: this asks a question, it does not change a flag. The
    // background connection where one is free, so polling another account's
    // folders never re-aims the mailbox the user is reading.
    withReadSession(folder, /*background=*/true, [this, folder, done](KIMAP::Session *s) {
        if (!s) {
            done(Error::Connection, {}, tr("No connection available for %1.").arg(folder));
            return;
        }
        auto *search = new KIMAP::SearchJob(s);
        search->setUidBased(true);
        // NOT SEEN. One command, and the complete answer: every id it returns
        // is unread, and every cached row it does not is read.
        search->setTerm(KIMAP::Term(KIMAP::Term::Seen).setNegated(true));
        connect(search, &KJob::result, this, [folder, done](KJob *job) {
            if (job->error()) {
                done(Error::Protocol, {}, job->errorString());
                return;
            }
            const QList<qint64> uids = static_cast<KIMAP::SearchJob *>(job)->results();
            QStringList ids;
            ids.reserve(uids.size());
            for (qint64 uid : uids)
                ids.append(QString::number(uid));
            done(Error::None, ids, QString());
        });
        search->start();
    });
}

void ImapBackend::search(const QString &folder, const QString &query, bool headersOnly,
                         bool byRecipient, const OpCallback &done)
{
    // headersOnly is the default at the call site: a body search drags in every
    // newsletter that ever mentioned the word. Which header the name is looked
    // for in depends on the folder — searching From in Sent asks "which of my
    // messages are from me", which is all of them.
    const KIMAP::Term term = headersOnly
        ? KIMAP::Term(KIMAP::Term::Or,
                      {KIMAP::Term(byRecipient ? KIMAP::Term::To : KIMAP::Term::From, query),
                       KIMAP::Term(KIMAP::Term::Subject, query)})
        : KIMAP::Term(KIMAP::Term::Text, query);

    withFolderSelected(folder, false, [this, folder, term, done](bool ok,
                                                                 const QString &error) {
        if (!ok) {
            if (done)
                done(Error::Protocol, error);
            return;
        }
        auto *search = new KIMAP::SearchJob(m_session);
        search->setUidBased(true);
        search->setTerm(term);
        connect(search, &KJob::result, this, [this, folder, done](KJob *job) {
            if (job->error()) {
                // Some servers reject SEARCH variants outright; the caller
                // falls back to matching against its own index.
                qWarning() << "mailove: IMAP SEARCH failed:" << job->errorString();
                if (done)
                    done(Error::Protocol, job->errorString());
                return;
            }
            const QList<qint64> uids = static_cast<KIMAP::SearchJob *>(job)->results();
            QStringList ids;
            ids.reserve(uids.size());
            for (qint64 uid : uids)
                ids.append(QString::number(uid));
            Q_EMIT searchResults(folder, ids);
            if (done)
                done(Error::None, QString());
        });
        search->start();
    });
}

void ImapBackend::storeMessage(const QString &folder, const QByteArray &raw,
                               const QStringList &flags,
                               const std::function<void(Error, const QString &,
                                                        const QString &)> &done)
{
    if (!m_session) {
        if (done)
            done(Error::Connection, QString(), tr("Not connected."));
        return;
    }
    QList<QByteArray> imapFlags;
    for (const QString &f : flags)
        imapFlags.append(imapFlag(f));

    auto *append = new KIMAP::AppendJob(m_session);
    append->setMailBox(folder);
    append->setContent(raw);
    append->setFlags(imapFlags);
    append->setInternalDate(QDateTime::currentDateTime());
    connect(append, &KJob::result, this, [done](KJob *job) {
        if (!done)
            return;
        if (job->error()) {
            done(Error::Protocol, QString(), job->errorString());
            return;
        }
        // The uid the server filed it under, when it says so at all (UIDPLUS).
        // 0 means it did not, which the caller must tolerate: IMAP has no other
        // way to learn it short of re-listing the mailbox.
        const qint64 uid = static_cast<KIMAP::AppendJob *>(job)->uid();
        done(Error::None, uid > 0 ? QString::number(uid) : QString(), QString());
    });
    append->start();
}

// --- Sending ---------------------------------------------------------------

/// SMTP, which is not IMAP at all — it is simply the other half of what an IMAP
/// account needs to be usable. JMAP has no equivalent leg: it submits over its
/// own API and files the sent copy itself, which is what sentCopyIsAutomatic()
/// distinguishes.
void ImapBackend::sendMessage(const QByteArray &raw, const QString &from,
                              const QStringList &recipients, const OpCallback &done)
{
    auto *session = new KSmtp::Session(m_credentials.smtpHost,
                                       quint16(m_credentials.smtpPort), this);
    switch (m_credentials.smtpSecurity) {
    case 0:
        session->setEncryptionMode(KSmtp::Session::TLS);
        break;
    case 2:
        session->setEncryptionMode(KSmtp::Session::Unencrypted);
        break;
    default:
        session->setEncryptionMode(KSmtp::Session::STARTTLS);
        break;
    }

    // Called exactly once, however the attempt ends, and always closes the
    // session: an SMTP connection left open holds a socket for nothing.
    auto finish = std::make_shared<std::function<void(const QString &)>>();
    *finish = [session, done](const QString &error) {
        if (done)
            done(error.isEmpty() ? Error::None : Error::Protocol, error);
        session->quit();
        session->deleteLater();
    };

    connect(session, &KSmtp::Session::stateChanged, this,
            [this, session, raw, from, recipients, finish](KSmtp::Session::State state) {
                if (state != KSmtp::Session::NotAuthenticated)
                    return;
                auto *login = new KSmtp::LoginJob(session);
                login->setUserName(m_credentials.user);
                if (m_credentials.authType != 0) {
                    login->setPreferedAuthMode(KSmtp::LoginJob::XOAuth2);
                    login->setPassword(m_credentials.accessToken);
                } else {
                    login->setPassword(m_credentials.password);
                }
                connect(login, &KJob::result, this,
                        [session, raw, from, recipients, finish](KJob *job) {
                            if (job->error()) {
                                (*finish)(job->errorString());
                                return;
                            }
                            auto *send = new KSmtp::SendJob(session);
                            send->setFrom(from);
                            // One envelope list: RCPT TO makes no distinction,
                            // and Bcc must not reach a header.
                            send->setTo(recipients);
                            send->setData(raw);
                            connect(send, &KJob::result, session, [finish](KJob *job) {
                                (*finish)(job->error() ? job->errorString() : QString());
                            });
                            send->start();
                        });
                login->start();
            });
    session->open();
}


