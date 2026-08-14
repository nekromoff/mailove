// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QHash>
#include <QPointer>
#include <QString>
#include <QTimer>

#include <functional>

#include "mailbackend.h"

class KJob;

namespace KIMAP
{
class IdleJob;
class ImapSet;
class LoginJob;
class Session;
}

/**
 * The IMAP side of MailBackend, over KIMAP.
 *
 * Owns the connections and nothing else. KIMAP runs the jobs of one connection
 * strictly in order, so three are opened rather than one: the interactive
 * session the user's clicks go through, a session parked in IDLE for push, and
 * a background session for the header backfill and body prefetch. Without the
 * split a folder click queues behind whatever multi-second FETCH the backfill
 * has in flight. Only the first is required — the other two are best-effort,
 * and a server that refuses extra connections costs responsiveness, not
 * function.
 *
 * Every MailBackend operation is implemented here. What remains in MailClient
 * (doc/JMAP_ROADMAP.md) is work the interface does not yet describe: the spam
 * sweep's isolated connection, polling *other* accounts, and two direct reads.
 * Those reach the connections through the transitional accessors below; when the
 * last of them goes, MailClient no longer names KIMAP at all.
 */
class ImapBackend : public MailBackend
{
    Q_OBJECT

public:
    explicit ImapBackend(QObject *parent = nullptr);
    ~ImapBackend() override;

    Protocol protocol() const override { return Protocol::Imap; }
    /// An IMAP remote id is the uid written as text, so the key is a parse.
    qint64 localKeyFor(const QString &remoteId) const override
    {
        return remoteId.toLongLong();
    }

    void connectAccount(const Credentials &credentials) override;
    void disconnectAccount() override;
    /// The interactive connection has to exist as well as the login having
    /// succeeded: callers read this as "there is something to talk to", and a
    /// socket that died between the two would otherwise answer yes.
    bool isConnected() const override { return m_connected && !m_session.isNull(); }

    void startPush(const QString &folder) override;
    void stopPush() override;
    bool pushActive() const override;

    /// IMAP has no notion of filing the sent copy for you — the message is
    /// handed to SMTP, and the copy is a separate APPEND.
    bool sentCopyIsAutomatic() const override { return false; }

    // --- Folders -----------------------------------------------------------

    void listFolders() override;
    void createFolder(const QString &path, const OpCallback &done) override;
    void renameFolder(const QString &from, const QString &to,
                      const OpCallback &done) override;
    void deleteFolder(const QString &path, const OpCallback &done) override;

    // --- Messages ----------------------------------------------------------

    void setFlags(const QString &folder, const QStringList &remoteIds,
                  const QStringList &addFlags, const QStringList &removeFlags,
                  const OpCallback &done) override;
    void moveMessages(const QString &folder, const QStringList &remoteIds,
                      const QString &targetFolder, const OpCallback &done) override;
    void deleteMessages(const QString &folder, const QStringList &remoteIds,
                        const OpCallback &done) override;

    // --- Reading -----------------------------------------------------------

    void openFolder(const QString &folder, const QString &syncToken) override;
    void fetchHeaderWindow(const QString &folder, int fromNewest, int count,
                           bool background, const OpCallback &done) override;
    void fetchHeadersSince(const QString &folder, const QString &sinceRemoteId,
                           const OpCallback &done) override;
    void fetchHeadersById(const QString &folder, const QStringList &remoteIds,
                          const OpCallback &done) override;

    /// How many messages the server reported in \a folder at its last SELECT,
    /// 0 when it has not been opened. Positional windows are counted back from
    /// this, and the caller needs it to know when the history is exhausted.
    qint64 messageCount(const QString &folder) const;

    void fetchBodies(const QString &folder, const QStringList &remoteIds,
                     const OpCallback &done) override;
    int freeBodySlots() const override;
    bool bodyFetchActive() const override;
    /// The dedicated background connection being up and logged in. When it is
    /// not, this reopens it (best-effort) and answers false — the caller comes
    /// back on a later tick rather than pushing background work onto the
    /// connection the user's clicks go through.
    bool ensureBackgroundReady() override;
    void folderUnreadCounts(
        const QStringList &folders,
        const std::function<void(Error, const QHash<QString, int> &,
                                 const QString &)> &done) override;
    void search(const QString &folder, const QString &query, bool headersOnly,
                bool byRecipient,
                const OpCallback &done) override;
    void storeMessage(const QString &folder, const QByteArray &raw,
                      const QStringList &flags,
                      const std::function<void(Error, const QString &,
                                               const QString &)> &done) override;
    void sendMessage(const QByteArray &raw, const QString &from,
                     const QStringList &recipients, const OpCallback &done) override;

private:
    // The connections. Private since the last KIMAP code left MailClient:
    // nothing outside this class has seen a KIMAP::Session for anything in
    // months of migration, and a new caller for one of these would be a
    // protocol detail escaping again. Public accessors lived here only to
    // serve the operations that had not moved in yet.

    /// The interactive connection — null when not connected.
    KIMAP::Session *mainSession() const;
    /// The background-sync connection; null when the server refused it or it
    /// has since dropped, in which case the caller falls back to the main one.
    KIMAP::Session *syncSession() const;
    /// Mailbox currently selected on the background connection.
    QString syncFolder() const { return m_syncFolder; }
    void setSyncFolder(const QString &folder) { m_syncFolder = folder; }
    /// (Re)opens the background connection if it is missing. Best-effort.
    void startSyncSession();
    /// Runs \a fn with the background connection once \a folder is selected on
    /// it, passing nullptr when there is no usable one. Deliberately does NOT
    /// fall back to the main session: background work that borrows the user's
    /// connection is the thing the extra connection exists to prevent.
    void withSyncSession(const QString &folder,
                         const std::function<void(KIMAP::Session *)> &fn);
    /// Applies the account's credentials and encryption mode to \a login — the
    /// extra connections (IDLE, background sync, the body-fetch pool) all log
    /// in the same way the interactive one does.
    void configureLogin(KIMAP::LoginJob *login) const;
    /// Host and port of the account in use, for those same connections.
    QString host() const { return m_credentials.host; }
    int port() const { return m_credentials.port; }

    /// One extra connection of the parallel body-transfer pool. KIMAP
    /// serializes jobs per connection, so bulk body downloads get their own —
    /// otherwise a folder click queues behind a multi-megabyte transfer.
    struct BodyConn {
        QPointer<KIMAP::Session> session;
        QString folder;    ///< mailbox currently selected on it
        bool ready = false;
        bool busy = false; ///< a body batch is streaming on it
    };
    QList<std::shared_ptr<BodyConn>> m_bodyPool;
    bool m_bodyPoolBroken = false; ///< server refused extra connections — stop trying
    bool m_bodyFallbackBusy = false; ///< a batch is running on the sync connection
    /// Opens the missing pool connections (best effort, once per connect).
    void ensureBodyPool();
    /// Drops one idle pool connection and stops growing the pool, after a
    /// [TOO-MANY-SIMULTANEOUS-CONNECTIONS] refusal.
    void shrinkBodyPool();
    /// The streaming multi-id body FETCH itself; \a release frees the issuing
    /// connection and is called exactly once.
    void startBodyFetchJob(KIMAP::Session *session, const QString &folder,
                           const KIMAP::ImapSet &set, const OpCallback &done,
                           const std::function<void()> &release);
    /// Reports one folder write's outcome through \a done, exactly once.
    void finishFolderOp(KJob *job, const OpCallback &done);
    /// Runs \a then once \a folder is selected on the interactive connection
    /// with at least the access \a readWrite asks for, SELECTing only when what
    /// is already selected will not do. Browsing uses EXAMINE, so a write always
    /// has to check: STORE, MOVE and EXPUNGE all act on the selected mailbox,
    /// and acting on the wrong one silently damages a different folder.
    void withFolderSelected(const QString &folder, bool readWrite,
                            const std::function<void(bool ok, const QString &error)> &then);
    /// Tears down every connection without touching m_connected — the shared
    /// part of disconnectAccount() and a failed connect.
    void closeSessions();
    void setConnected(bool connected);

    Credentials m_credentials;
    bool m_connected = false;

    QPointer<KIMAP::Session> m_session;     ///< interactive
    QPointer<KIMAP::Session> m_idleSession; ///< parked in IDLE for push
    QPointer<KIMAP::IdleJob> m_idleJob;
    QPointer<KIMAP::Session> m_syncSession; ///< header backfill + body prefetch
    bool m_syncReady = false;
    QString m_syncFolder;
    QString m_selectedFolder;         ///< mailbox selected on the interactive connection
    bool m_selectedReadWrite = false; ///< ...and whether SELECT, not EXAMINE, opened it
    /// EXISTS per mailbox, from the last SELECT/EXAMINE of it on any connection.
    /// A positional window is "the newest N", which in IMAP can only be turned
    /// into a sequence range once the mailbox's size is known.
    QHash<QString, qint64> m_messageCounts;
    qint64 m_lastUidValidity = 0; ///< from the most recent SELECT/EXAMINE

    /// Runs one header FETCH on \a session, decoding each batch into
    /// HeaderInfo and emitting it. \a minUid drops entries at or below it,
    /// which "uid:*" needs: it always returns the newest message even when its
    /// uid is below the requested range.
    void runHeaderFetch(KIMAP::Session *session, const QString &folder,
                        const KIMAP::ImapSet &set, bool uidBased, qint64 minUid,
                        const OpCallback &done);
    /// The connection a read of \a folder should use: the background one when
    /// it is available and has (or can take) the folder, else the interactive
    /// one when that folder is already open on it.
    void withReadSession(const QString &folder, bool background,
                         const std::function<void(KIMAP::Session *)> &fn);
    QString m_pushFolder; ///< folder push is watching, for the IDLE restart

    /// Keeps the interactive connection from being dropped as idle. Purely a
    /// protocol concern (a periodic CAPABILITY), so it lives here rather than
    /// with the application's own timers.
    QTimer m_keepAlive;
};
