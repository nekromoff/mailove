// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QHash>
#include <QJsonObject>
#include <QPointer>
#include <QString>

#include "mailbackend.h"

class JmapSession;
class JmapRequest;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

/**
 * The JMAP side of MailBackend, over JmapSession and JmapRequest.
 *
 * Structurally simpler than ImapBackend, and for one reason: HTTP does not
 * serialize. There is no connection pool, no IDLE session, no backfill cursor
 * and no sequence-number bookkeeping — a header page is one POST carrying an
 * `Email/query` and the `Email/get` that reads its output, and a folder the
 * user just clicked cannot queue behind a background fetch because the two are
 * separate requests from the start.
 *
 * Two translations do the real work, both of them one-way seams the rest of
 * the application never sees through:
 *
 * - **Ids to paths.** MailBackend identifies folders by path because IMAP does;
 *   JMAP identifies mailboxes by opaque id and describes the tree with
 *   `parentId`. The mailbox tree is therefore kept here, and paths are built
 *   from it, so `listFolders()` can answer in the vocabulary the models expect.
 * - **JMAP properties to a header block.** `HeaderInfo::message` is a parsed
 *   RFC 5322 header, and the spam and DKIM paths read its raw octets — so the
 *   header block is rebuilt from `Email/get`'s `headers` property, which
 *   returns every field in original order with folding and leading spaces
 *   intact. Verified byte-identical against the same message's blob on Cyrus;
 *   see doc/JMAP_ROADMAP.md. It is a reconstruction, not a copy, so
 *   headerFidelityIsExact() exists for callers that would rather pay for the
 *   blob than trust it.
 *
 * Reading, writing, sending, delta sync and push are all implemented; see
 * doc/JMAP_ROADMAP.md for what each cost to get right.
 */
class JmapBackend : public MailBackend
{
    Q_OBJECT

public:
    explicit JmapBackend(QObject *parent = nullptr);
    ~JmapBackend() override;

    Protocol protocol() const override { return Protocol::Jmap; }
    qint64 localKeyFor(const QString &remoteId) const override
    {
        return hashedLocalKey(remoteId);
    }

    void connectAccount(const Credentials &credentials) override;
    void disconnectAccount() override;
    bool isConnected() const override { return m_connected; }

    /// JMAP files the sent copy as part of the submission — sendMessage()'s
    /// `onSuccessUpdateEmail` — so callers must not append one themselves.
    bool sentCopyIsAutomatic() const override { return true; }

    /// The hierarchy separator paths are built with. JMAP has none of its own:
    /// mailbox names may contain any character, so the separator is this
    /// backend's invention and exists only to speak MailBackend's language.
    static QChar pathSeparator();

    // --- Reading -----------------------------------------------------------

    void listFolders() override;
    void openFolder(const QString &folder, const QString &syncToken) override;
    void fetchHeaderWindow(const QString &folder, int fromNewest, int count,
                           bool background, const OpCallback &done) override;
    void fetchHeadersSince(const QString &folder, const QString &sinceRemoteId,
                           const OpCallback &done) override;
    void fetchHeadersById(const QString &folder, const QStringList &remoteIds,
                          const OpCallback &done) override;
    void fetchBodies(const QString &folder, const QStringList &remoteIds,
                     const OpCallback &done) override;
    int freeBodySlots() const override;
    bool bodyFetchActive() const override { return m_bodiesInFlight > 0; }
    /// Connected is ready: HTTP does not serialize requests, so background
    /// work needs no connection of its own and there is nothing to prepare.
    bool ensureBackgroundReady() override { return isConnected(); }
    void fetchUnseenIds(
        const QString &folder,
        const std::function<void(Error, const QStringList &ids,
                                 const QString &message)> &done) override;
    void folderUnreadCounts(
        const QStringList &folders,
        const std::function<void(Error, const QHash<QString, int> &counts,
                                 const QString &message)> &done) override;
    void search(const QString &folder, const QString &query, bool headersOnly,
                bool byRecipient,
                const OpCallback &done) override;

    // --- Writing -----------------------------------------------------------

    void setFlags(const QString &folder, const QStringList &remoteIds,
                  const QStringList &addFlags, const QStringList &removeFlags,
                  const OpCallback &done) override;
    void moveMessages(const QString &folder, const QStringList &remoteIds,
                      const QString &targetFolder, const OpCallback &done) override;
    void deleteMessages(const QString &folder, const QStringList &remoteIds,
                        const OpCallback &done) override;
    void createFolder(const QString &path, const OpCallback &done) override;
    void renameFolder(const QString &from, const QString &to,
                      const OpCallback &done) override;
    void deleteFolder(const QString &path, const OpCallback &done) override;
    void storeMessage(const QString &folder, const QByteArray &raw,
                      const QStringList &flags,
                      const std::function<void(Error, const QString &remoteId,
                                               const QString &message)> &done) override;
    void sendMessage(const QByteArray &raw, const QString &from,
                     const QStringList &recipients, const OpCallback &done) override;

    // --- Push --------------------------------------------------------------

    /// Opens the session's EventSource stream (RFC 8620 §7.3) — JMAP's answer
    /// to IDLE, and a better one: the stream is account-wide, so switching
    /// folders costs nothing where IMAP must re-issue IDLE on the new mailbox.
    /// \a folder names which folder the resulting folderChanged() is about.
    void startPush(const QString &folder) override;
    void stopPush() override;
    bool pushActive() const override { return m_pushActive; }

    // --- Translations, exposed because they are worth testing --------------

    /// Rebuilds the RFC 5322 header block from `Email/get`'s `headers` value —
    /// a JSON array of `{name, value}`. The value carries the raw field body
    /// including its leading space and any folding, so each field is written
    /// back as `name` `:` `value` CRLF and nothing is re-encoded.
    static QByteArray headerBlockFromJmap(const QJsonArray &headers);
    /// The MailBackend flag vocabulary for a JMAP `keywords` object. An empty
    /// keywords object means unread, which is why absence matters as much as
    /// presence here.
    static QStringList flagsFromKeywords(const QJsonObject &keywords);
    /// The JMAP keyword a MailBackend flag name means, or empty when the
    /// protocol has none. "deleted" is the empty case and the reason this
    /// returns rather than asserts: IMAP deletes by flagging, JMAP by removing
    /// a message from every mailbox, so the flag simply has no counterpart.
    static QString keywordForFlag(const QString &flag);
    /// The `Email/set` update patch that adds \a addFlags and removes
    /// \a removeFlags. Patch keys are JSON pointers into the Email object
    /// (`keywords/$seen`), and a removal is a null rather than a false — JMAP
    /// keywords are present or absent, never present-and-false.
    static QJsonObject keywordPatch(const QStringList &addFlags,
                                    const QStringList &removeFlags);
    /// The `onSuccessUpdateEmail` patch that files the sent copy: out of the
    /// mailbox it was held in, into Sent, and no longer a draft. With no Sent
    /// mailbox — or one that is already where the message sits — nothing moves,
    /// which matters more than it looks: clearing the only mailbox an Email is
    /// in destroys it, JMAP having no other notion of where a message lives.
    static QJsonObject sentCopyPatch(const QString &holdId, const QString &sentId);
    /// The FolderRole a JMAP mailbox `role` names.
    static FolderRole roleFromJmap(const QString &role);
    /// The single yes-or-no a `/set` response amounts to. \a rejectedKey is
    /// the response's failure map ("notUpdated", "notCreated", "notDestroyed"),
    /// whose first entry supplies both the error type and the words to show.
    ///
    /// This is the trap in JMAP's write path, and why it is a named function
    /// rather than a line inside each caller: a `/set` that refuses *every*
    /// object still answers with a perfectly ordinary success response. Nothing
    /// above notices unless the rejection maps are read, so a delete that the
    /// server declined would report as done and the message would come back on
    /// the next sync.
    static Error setError(const QJsonObject &arguments, const char *rejectedKey,
                          QString *message);
    /// The first rejection object itself — `{type, description, …}` — for the
    /// callers that need more than a yes-or-no. `alreadyExists` is the reason
    /// this exists: it carries an `existingId`, which turns a refusal into an
    /// answer.
    static QJsonObject firstRejection(const QJsonObject &arguments, const char *rejectedKey);
    /// One parsed Server-Sent Events block — the fields of RFC 8620 §7.3's
    /// push channel, which is plain SSE.
    struct PushEvent {
        QString name;    ///< the `event:` field; "ping" for a keepalive
        QByteArray data; ///< the `data:` fields, several joined by newlines
        QString id;      ///< the `id:` field, replayed as Last-Event-ID
    };
    /// Takes every complete event out of \a buffer, leaving the partial tail
    /// behind for the next read. Line endings are normalised on the way.
    ///
    /// Framing is separate from parsing because it is where the subtle bug
    /// lives: a read can end anywhere, including between the CR and the LF of
    /// one line ending. Normalising a trailing CR straight away invents a line
    /// break, and if the next read begins with LF the pair then reads as a
    /// blank line — dispatching an event that was never sent and truncating the
    /// one that was. So a trailing CR waits for its LF.
    static QList<QByteArray> takeSseBlocks(QByteArray &buffer);
    /// Parses one `\n\n`-terminated event block. Pure, and separate from the
    /// socket because SSE has more edge cases than it looks: several `data:`
    /// lines are one payload, a leading space after the colon is syntax rather
    /// than content, a line with no colon is a field with an empty value, and
    /// a line starting with `:` is a comment servers send to keep the
    /// connection warm.
    static PushEvent parseSseBlock(const QByteArray &block);
    /// Whether a StateChange payload (RFC 8620 §7.1) says something changed in
    /// \a accountId's mail. False for another account on the same session, and
    /// for the calendar and contact types that share the channel.
    static bool stateChangeTouchesMail(const QByteArray &data, const QString &accountId);

    /// A stable local key for a JMAP message id — what localKeyFor() answers,
    /// exposed separately because the derivation is worth pinning in a test:
    /// change it and every cached row is orphaned.
    ///
    /// JMAP ids are opaque strings and MailStore wants an integer; this is the
    /// first 63 bits of the id's SHA-256, stable across runs and across
    /// restarts. Collisions are theoretically possible and practically not: two
    /// ids in one account would have to agree in 63 bits.
    static qint64 hashedLocalKey(const QString &remoteId);

    /// Whether the header blocks this backend produces are byte-exact
    /// reconstructions. True unless a server has been observed to normalise
    /// them; kept as a hook because only DKIM cares, and only DKIM would pay
    /// the blob download to avoid the question.
    bool headerFidelityIsExact() const { return true; }

private:
    struct Mailbox {
        QString id;
        QString name;
        QString parentId;
        QString role;
        qint64 total = 0;
        qint64 unread = 0;
    };

    /// A request configured for this account, or nullptr with \a done already
    /// called when there is no session to send it over.
    JmapRequest *newRequest();
    /// One mailbox as `Mailbox/get` describes it.
    static Mailbox mailboxFromJson(const QJsonObject &object);
    /// Every mailbox, from scratch. What a first listing does, and what a
    /// delta falls back to when the server can no longer compute one.
    void listAllMailboxes();
    /// Only what moved since m_mailboxState, merged into the cached tree.
    void listChangedMailboxes();
    /// Emits foldersListed() for the whole cached tree. Both listing paths end
    /// here: the caller is given the complete tree either way, a delta being an
    /// optimisation of how it was learned rather than a different answer.
    void emitFolderList();
    /// Reports \a error both to the caller's callback and, when it is worth
    /// the user's attention, as errorOccurred().
    void report(const OpCallback &done, Error error, const QString &message);
    /// The mailbox id for \a path, or empty.
    QString mailboxId(const QString &path) const;
    /// The id of the mailbox the server gave \a role, or empty when it named
    /// none. Only the write path needs this — sending has to know which
    /// mailbox the sent copy belongs in, and no path can be assumed.
    QString mailboxIdForRole(const QString &role) const;
    /// Rebuilds m_pathById/m_idByPath from \a mailboxes.
    void rebuildPaths(const QList<Mailbox> &mailboxes);
    /// Re-derives the paths from the mailboxes already cached. What a
    /// successful Mailbox/set calls, so the new spelling of the tree is usable
    /// immediately rather than only after the caller re-lists.
    void rebuildPathsFromCache();
    /// Splits \a path into the id of its parent mailbox and its leaf name.
    /// False when the path names a parent that does not exist, which is the
    /// one failure the caller can explain better than the server would.
    bool splitPath(const QString &path, QString *parentId, QString *name) const;
    /// Turns an `Email/get` list into HeaderInfo and emits headersFetched().
    void emitHeaders(const QString &folder, const QJsonArray &list);
    /// The Email/query + Email/get pair every header read is made of.
    void queryAndGet(const QString &folder, const QJsonObject &filter,
                     int position, int limit, const OpCallback &done);
    void downloadNextBody();

    // --- Writing helpers ---------------------------------------------------

    /// Applies \a patch to every message in \a remoteIds with `Email/set
    /// update`, in as many requests as the server's maxObjectsInSet allows,
    /// each waiting for the last. \a what names the operation for the error
    /// message. Both flag changes and moves come through here: JMAP spells
    /// them as the same call on different properties.
    void updateEmails(const QStringList &remoteIds, const QJsonObject &patch,
                      const QString &what, const OpCallback &done);
    /// Uploads \a raw to the session's upload endpoint and answers with the
    /// blob id the server filed it under. The one part of JMAP that is not a
    /// method call: a plain POST, because a batch is JSON and a message is not.
    void uploadBlob(const QByteArray &raw, const QByteArray &contentType,
                    const std::function<void(Error, const QString &blobId,
                                             const QString &message)> &done);
    /// The identity to submit \a from with, fetched once and remembered.
    /// Submission is refused without one, and the identity is the server's to
    /// state: an address the account may send as need not be one it can prove.
    void withIdentity(const QString &from,
                      const std::function<void(Error, const QString &identityId,
                                               const QString &message)> &done);
    /// The last leg of sendMessage(), once the identity is known and the bytes
    /// are uploaded: `Email/import` and `EmailSubmission/set` in one request.
    /// Split out because the two things it waits for are asynchronous and
    /// nesting all three reads as a staircase.
    void submitBlob(const QString &blobId, const QString &identityId, const QString &from,
                    const QStringList &recipients, const OpCallback &done);
    /// Submits an Email the server already holds, naming it by id rather than
    /// by the creation id of an import in the same request. Where submitBlob()
    /// lands when the import answers `alreadyExists`: the server has this exact
    /// message already, so there is nothing to import and everything still to
    /// send.
    void submitExistingEmail(const QString &emailId, const QString &identityId,
                             const QString &from, const QStringList &recipients,
                             const OpCallback &done);
    /// The `EmailSubmission/set` create object for \a emailId. \a emailId is
    /// either a real id or a `#creationId` reference — JMAP accepts both, which
    /// is what lets the two submit paths share this.
    QJsonObject submissionCreate(const QString &emailId, const QString &identityId,
                                 const QString &from,
                                 const QStringList &recipients) const;
    // --- Push helpers ------------------------------------------------------

    /// (Re)opens the EventSource stream. Silent on failure: push is
    /// best-effort by contract, and a server that offers no stream costs the
    /// caller a poll timer, not a feature.
    void openPushStream();
    /// Drains whatever arrived and dispatches each complete event.
    void readPushStream();
    /// One `\n\n`-terminated SSE event block: `event:`, `data:` and `id:`
    /// fields, or a comment line the server sends to keep the socket warm.
    void handlePushEvent(const QByteArray &block);
    /// Schedules another attempt after the stream dropped, backing off with
    /// jitter so a server that has just restarted is not met by every client
    /// at once.
    void schedulePushRetry();

    /// Destroys \a remoteId and says nothing whatever happens. What a failed
    /// submission does with the draft it had already imported: the user is
    /// being shown why the send failed, and a second error about the tidying
    /// would only bury it.
    void destroyEmailQuietly(const QString &remoteId);

    JmapSession *m_session = nullptr;
    QNetworkAccessManager *m_net = nullptr;
    bool m_connected = false;

    QHash<QString, Mailbox> m_mailboxes; ///< by id
    QHash<QString, QString> m_pathById;
    QHash<QString, QString> m_idByPath;
    /// The Mailbox state the cached tree above is at — what `Mailbox/changes`
    /// resumes from. Empty means no tree has been learned yet, which is what
    /// sends listFolders() down the full-listing path.
    QString m_mailboxState;

    QString m_openFolder;
    /// The Email state each folder was last opened at, keyed by path — what
    /// `Email/changes` resumes from. Seeded by openFolder() with what the
    /// caller had stored, and moved forward by every delta that succeeds.
    ///
    /// Per folder, though JMAP's Email state is account-wide: the caller stores
    /// one token per folder and catches folders up one at a time, so a single
    /// shared cursor would be moved past changes the other folders had not yet
    /// been told about.
    QHash<QString, QString> m_emailState;
    /// blobId by message id, learned from header fetches so a body read need
    /// not ask again.
    QHash<QString, QString> m_blobIds;

    struct PendingBody {
        QString folder;
        QString remoteId;
        QString blobId;
        qint64 size = 0;
    };
    QList<PendingBody> m_bodyQueue;
    QHash<QString, OpCallback> m_bodyBatchDone; ///< by folder
    QHash<QString, int> m_bodyBatchOutstanding;
    int m_bodiesInFlight = 0;

    /// Identity ids by lower-cased address, and the one to fall back on.
    /// Fetched on the first send and kept: identities change about as often as
    /// the account settings do, and a session that outlives a change is
    /// re-established by the same 401 path everything else uses.
    QHash<QString, QString> m_identityByEmail;
    QString m_defaultIdentityId;
    /// Distinguishes "no identities" from "not asked yet"; without it an
    /// account the server offers none for costs an Identity/get per send.
    bool m_identitiesFetched = false;

    // --- Push state --------------------------------------------------------

    QPointer<QNetworkReply> m_pushReply;
    QByteArray m_pushBuffer;   ///< partial SSE text between readyRead's
    QString m_pushFolder;      ///< what folderChanged() will name
    /// The last event id the server sent, replayed as `Last-Event-ID` on a
    /// reconnect so changes during the gap are not missed.
    QString m_pushLastEventId;
    QTimer *m_pushRetryTimer = nullptr;
    int m_pushRetries = 0;
    /// Whether push *should* be running. Distinct from m_pushActive, which is
    /// whether it *is*: a dropped stream is retried only while the caller still
    /// wants one, and stopPush() must not be undone by a retry already pending.
    bool m_pushWanted = false;
    bool m_pushActive = false;
};
