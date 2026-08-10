// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "imapbackend.h"

#include <QDebug>
#include <QDateTime>
#include <QHash>
#include <QTimer>

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
    m_keepAlive.setInterval(3 * 60 * 1000);
    connect(&m_keepAlive, &QTimer::timeout, this, [this] {
        if (m_connected && m_session)
            (new KIMAP::CapabilitiesJob(m_session))->start();
    });
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
    m_selectedFolder.clear();
    m_selectedReadWrite = false;
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
            qWarning() << "mailo: sync-session login failed:" << job->errorString();
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
    if (m_syncFolder == folder) {
        fn(m_syncSession.data());
        return;
    }
    auto *select = new KIMAP::SelectJob(m_syncSession);
    select->setMailBox(folder);
    select->setOpenReadOnly(true);
    connect(select, &KJob::result, this, [this, folder, fn](KJob *job) {
        if (job->error() || !m_syncSession) {
            fn(nullptr);
            return;
        }
        m_syncFolder = folder;
        m_messageCounts[folder] = static_cast<KIMAP::SelectJob *>(job)->messageCount();
        fn(m_syncSession.data());
    });
    select->start();
}

bool ImapBackend::pushActive() const
{
    return !m_idleJob.isNull();
}

void ImapBackend::stopPush()
{
    m_idleJob.clear(); // owned by the session; dies with it
    if (m_idleSession) {
        m_idleSession->deleteLater();
        m_idleSession.clear();
    }
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
    auto *login = new KIMAP::LoginJob(m_idleSession);
    configureLogin(login);
    connect(login, &KJob::result, this, [this, folder](KJob *job) {
        if (job->error() || !m_idleSession) {
            qWarning() << "mailo: idle login failed:" << job->errorString();
            return;
        }
        auto *select = new KIMAP::SelectJob(m_idleSession);
        select->setMailBox(folder);
        select->setOpenReadOnly(true);
        connect(select, &KJob::result, this, [this, folder](KJob *job) {
            if (job->error() || !m_idleSession) {
                qWarning() << "mailo: idle select failed:" << job->errorString();
                return;
            }
            auto *idle = new KIMAP::IdleJob(m_idleSession);
            m_idleJob = idle;
            connect(idle, &KIMAP::IdleJob::mailBoxStats, this,
                    [this, folder](KIMAP::IdleJob *, const QString &mailBox, int, int) {
                        if (mailBox == folder)
                            Q_EMIT folderChanged(mailBox);
                    });
            connect(idle, &KJob::result, this, [this](KJob *job) {
                // Server ended IDLE (timeout, capability missing, …) — retry
                // later unless the session was torn down by us.
                if (job->error())
                    qWarning() << "mailo: idle ended:" << job->errorString();
                if (m_idleSession && m_connected) {
                    const QString folder = m_pushFolder;
                    QTimer::singleShot(30 * 1000, this, [this, folder] { startPush(folder); });
                }
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

void ImapBackend::withFolderSelected(
    const QString &folder, bool readWrite,
    const std::function<void(bool ok, const QString &error)> &then)
{
    if (!m_session) {
        then(false, tr("Not connected."));
        return;
    }
    if (m_selectedFolder == folder && (m_selectedReadWrite || !readWrite)) {
        then(true, QString());
        return;
    }
    auto *select = new KIMAP::SelectJob(m_session);
    select->setMailBox(folder);
    select->setOpenReadOnly(!readWrite);
    connect(select, &KJob::result, this, [this, folder, readWrite, then](KJob *job) {
        if (job->error()) {
            then(false, job->errorString());
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
        // EXISTS and UIDVALIDITY come free with every SELECT; positional
        // windows need the first, and the caller compares the second against
        // what it stored to notice a mailbox the server regenerated.
        m_messageCounts[folder] = sel->messageCount();
        m_lastUidValidity = sel->uidValidity();
        if (readWrite && !m_selectedReadWrite) {
            // Failing here spares the round trip a doomed write costs and
            // turns the server's cryptic refusal into a statement of fact.
            then(false, tr("%1 is read-only on the server").arg(folder));
            return;
        }
        then(true, QString());
    });
    select->start();
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
    withFolderSelected(folder, true, [this, set, addFlags, removeFlags, done](
                                         bool ok, const QString &error) {
        if (!ok) {
            if (done)
                done(Error::Protocol, error);
            return;
        }
        // Two STOREs when both directions are asked for: IMAP has no single
        // command that adds some flags and removes others.
        const auto run = [this, set](const QStringList &flags, bool add,
                                     const std::function<void(bool, QString)> &next) {
            if (flags.isEmpty()) {
                next(true, QString());
                return;
            }
            QList<QByteArray> imapFlags;
            for (const QString &f : flags)
                imapFlags.append(imapFlag(f));
            auto *store = new KIMAP::StoreJob(m_session);
            store->setUidBased(true);
            store->setSequenceSet(set);
            store->setMode(add ? KIMAP::StoreJob::AppendFlags
                               : KIMAP::StoreJob::RemoveFlags);
            store->setFlags(imapFlags);
            connect(store, &KJob::result, this, [next](KJob *job) {
                next(!job->error(), job->errorString());
            });
            store->start();
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
    });
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
    withFolderSelected(folder, true, [this, folder, set, done](bool ok,
                                                               const QString &error) {
        if (!ok) {
            if (done)
                done(Error::Protocol, error);
            return;
        }
        auto *store = new KIMAP::StoreJob(m_session);
        store->setUidBased(true);
        store->setSequenceSet(set);
        store->setMode(KIMAP::StoreJob::AppendFlags);
        store->setFlags({QByteArrayLiteral("\\Deleted")});
        connect(store, &KJob::result, this, [this, folder, done](KJob *job) {
            if (job->error()) {
                if (done)
                    done(Error::Protocol, job->errorString());
                return;
            }
            // Re-assert the selection before expunging. EXPUNGE acts on
            // whatever mailbox the connection has selected, and the event loop
            // runs between the STORE finishing and this job being created — so
            // another operation can SELECT a different mailbox in the gap, and
            // the expunge would then destroy *that* folder's \Deleted messages
            // instead. This is a no-op when nothing moved, and a re-SELECT when
            // something did.
            withFolderSelected(folder, true, [this, done](bool ok, const QString &error) {
                if (!ok) {
                    if (done)
                        done(Error::Protocol, error);
                    return;
                }
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
            qWarning() << "mailo: UIDVALIDITY of" << folder << "changed" << syncToken << "->"
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
        // on; anything else would cost a SELECT the user waits for.
        withFolderSelected(folder, false, [this, fn](bool ok, const QString &) {
            fn(ok ? m_session.data() : nullptr);
        });
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
    fn(m_selectedFolder == folder ? m_session.data() : nullptr);
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
    qWarning() << "mailo: reduced body-fetch pool to" << m_bodyPool.size()
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
    // the 2–3 recommended to avoid throttling.
    while (m_bodyPool.size() < 2) {
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
                qWarning() << "mailo: body-pool login failed:" << job->errorString();
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
    auto *fetch = new KIMAP::FetchJob(session);
    fetch->setSequenceSet(set);
    fetch->setUidBased(true);
    KIMAP::FetchJob::FetchScope scope;
    scope.mode = KIMAP::FetchJob::FetchScope::Full;
    fetch->setScope(scope);

    // Emit each body the moment its delivery streams in: memory stays flat
    // (roughly one body at a time) however big the batch is, and the parse and
    // indexing work downstream spreads across the socket events. `found` only
    // stashes content-less deliveries — a message's attributes may arrive split
    // across several emissions.
    auto found = std::make_shared<QHash<qint64, std::shared_ptr<KMime::Message>>>();
    auto sent = std::make_shared<QSet<qint64>>();
    connect(fetch, &KIMAP::FetchJob::messagesAvailable, this,
            [this, folder, found, sent](const QMap<qint64, KIMAP::Message> &messages) {
                for (const KIMAP::Message &m : messages) {
                    if (!m.message || m.uid <= 0 || sent->contains(m.uid))
                        continue;
                    if (!m.message->body().isEmpty() || !m.message->contents().isEmpty()) {
                        sent->insert(m.uid);
                        found->remove(m.uid);
                        Q_EMIT bodyFetched(folder, QString::number(m.uid), m.message);
                    } else if (!found->contains(m.uid)) {
                        (*found)[m.uid] = m.message;
                    }
                }
            });
    connect(fetch, &KJob::result, this,
            [this, found, folder, done, release](KJob *job) {
        if (job->error()) {
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
        // Leftovers whose deliveries never showed content (rare): emit what we
        // got, one per event-loop pass to keep the GUI thread fluid.
        auto drain = std::make_shared<std::function<void()>>();
        *drain = [this, found, folder, done, release, drain]() {
            if (!found->isEmpty()) {
                const qint64 uid = found->cbegin().key();
                Q_EMIT bodyFetched(folder, QString::number(uid), found->take(uid));
                if (!found->isEmpty()) {
                    QTimer::singleShot(0, this, *drain);
                    return;
                }
            }
            release();
            if (done)
                done(Error::None, QString());
        };
        (*drain)();
    });
    fetch->start();
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

void ImapBackend::search(const QString &folder, const QString &query, bool headersOnly,
                         const OpCallback &done)
{
    // headersOnly is the default at the call site: a body search drags in every
    // newsletter that ever mentioned the word.
    const KIMAP::Term term = headersOnly
        ? KIMAP::Term(KIMAP::Term::Or,
                      {KIMAP::Term(KIMAP::Term::From, query),
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
                qWarning() << "mailo: IMAP SEARCH failed:" << job->errorString();
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


