// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include <functional>
#include <memory>

namespace KMime
{
class Message;
}

/**
 * What a mail protocol has to be able to do, stated without reference to any
 * one protocol — the seam between MailClient (the QML "Mail" singleton: models,
 * viewer, cache, compose, settings) and the wire (ImapBackend today,
 * JmapBackend next; see doc/JMAP_ROADMAP.md).
 *
 * The rule that decides where a line of code belongs: a backend knows how to
 * *ask the server* for something and how to decode the answer, and nothing
 * else. It never touches MailStore, the folder/message models, the status
 * breadcrumb or the busy flag. Everything a server reply means to the
 * application — caching it, scoring it for spam, deciding which folder to open
 * next — is MailClient's, because all of it is identical whichever protocol
 * delivered the bytes.
 *
 * Calls are asynchronous and return void; results arrive as signals. That is
 * not a stylistic choice: both backends run on the GUI thread's event loop and
 * nothing here may block it (KIMAP jobs and QNetworkAccessManager replies
 * alike). Every reply signal names the folder it belongs to, because a reply
 * can arrive after the user has moved on and the caller must be able to tell.
 *
 * Connection multiplicity is deliberately not in this interface. IMAP needs
 * three connections (interactive, IDLE, background sync) because KIMAP
 * serializes jobs per connection; JMAP needs one, since HTTP does not. That is
 * an implementation detail of each backend, as is IMAP's backfill cursor.
 */
class MailBackend : public QObject
{
    Q_OBJECT

public:
    using QObject::QObject;
    ~MailBackend() override = default;

    /// Which protocol an account speaks. Persisted per account (the `protocol`
    /// key), so the value of each enumerator is part of the on-disk format and
    /// must not be renumbered.
    enum class Protocol { Imap = 0, Jmap = 1 };

    /// The credentials and endpoints an account connects with. Filled by
    /// MailClient from the account settings and the wallet; the backend reads
    /// only the fields its protocol uses (JMAP has no SMTP leg at all, and
    /// discovers its own endpoints from the session object).
    struct Credentials {
        QString host;
        int port = 0;
        int security = 0;      ///< MailClient::Security
        QString user;
        QString password;      ///< empty when authType != 0
        QString accessToken;   ///< OAuth bearer, empty for password auth
        int authType = 0;      ///< 0 password, 1 Gmail OAuth2, 2 Microsoft OAuth2
        QString smtpHost;      ///< IMAP only — JMAP submits over its own API
        int smtpPort = 0;
        int smtpSecurity = 0;
    };

    /// The role a server assigns a mailbox, where it says so at all: RFC 6154
    /// special-use flags over IMAP, the `role` property over JMAP. This is what
    /// lets "which folder is the trash" stop being a guess from the folder's
    /// name — MailClient keeps the name-based fallback for servers that
    /// announce nothing, but a role stated here always wins.
    enum class FolderRole { None, Inbox, Sent, Drafts, Trash, Junk, Archive, All };

    /// One mailbox as the server describes it. Presentation (indent level,
    /// display name, sort position) is derived by MailClient from the whole
    /// set, so it is deliberately absent: a single descriptor cannot know
    /// which of its ancestors are themselves mailboxes.
    struct FolderInfo {
        QString path;           ///< full path as the protocol names it
        QChar separator;        ///< hierarchy delimiter; null when not hierarchical
        bool selectable = true; ///< IMAP \Noselect, or a JMAP container mailbox
        FolderRole role = FolderRole::None;
    };

    /// One message header as fetched, before the application makes anything of
    /// it. Spam scoring, DKIM and the list row are all derived from the header
    /// block by MailClient, identically for every protocol.
    ///
    /// `message` is the *already parsed* header — never re-parsed downstream.
    /// KIMAP hands back a parsed message and re-parsing one loses fidelity, so
    /// the backend passes its own through; a backend that receives raw bytes
    /// (JMAP) parses them once, here. `message->head()` is the raw block for
    /// the rules that want the octets.
    struct HeaderInfo {
        qint64 uid = -1;   ///< local primary key (IMAP uid; synthetic for JMAP)
        QString remoteId;  ///< the protocol's own id — MessageListModel::Header::remoteId
        std::shared_ptr<KMime::Message> message;
        QStringList flags; ///< normalized: "seen", "deleted", "draft", "flagged"
        qint64 size = 0;
    };

    /// Why a request failed, to the extent the application acts differently on
    /// it. Anything finer stays in the human-readable message.
    enum class Error {
        None,
        Auth,        ///< credentials rejected — re-authentication may help
        Connection,  ///< could not reach or stay connected to the server
        Throttled,   ///< server is pushing back; back off and retry later
        NotFound,    ///< folder or message is gone
        Protocol     ///< the server refused the request itself
    };

    /// How a write operation reports back. A callback rather than a signal
    /// because the caller has to correlate the answer with the request that
    /// earned it — folder deletes are chained one mailbox at a time, and a
    /// single `finished` signal cannot say which one it is answering without
    /// the caller keeping a queue purely to find out.
    ///
    /// The rule the rest of this interface follows: an operation answered by a
    /// single yes-or-no takes a callback; one that streams data back, or that
    /// nobody asked for, is a signal. \a error is Error::None on success, and
    /// \a message is empty then.
    using OpCallback = std::function<void(Error error, const QString &message)>;

    // --- Session lifecycle -------------------------------------------------

    virtual Protocol protocol() const = 0;
    /// The local primary key for \a remoteId — the same qint64 that arrives on
    /// HeaderInfo::uid, and what MailStore rows are keyed by.
    ///
    /// Callers hold remote ids (search results, a body that just arrived) and
    /// the cache wants keys, so the translation has to live somewhere; it lives
    /// here because only the backend knows what its ids are. IMAP's remote id
    /// *is* its uid written out, so the conversion is a parse. JMAP's is an
    /// opaque string with a key derived from it, and parsing one yields 0 —
    /// which is why this is a method and not a call to toLongLong() at each
    /// site: the wrong answer there is silent, and every message collides on
    /// the same row.
    virtual qint64 localKeyFor(const QString &remoteId) const = 0;
    /// Opens whatever connections the protocol needs and authenticates.
    /// connected() follows; failure arrives as errorOccurred(Error::Auth or
    /// Error::Connection).
    virtual void connectAccount(const Credentials &credentials) = 0;
    /// Closes everything and cancels work in flight. Safe to call when not
    /// connected. Emits no signal: the caller asked for this.
    virtual void disconnectAccount() = 0;
    virtual bool isConnected() const = 0;

    // --- Reading -----------------------------------------------------------

    /// Enumerates every mailbox; answered by foldersListed().
    virtual void listFolders() = 0;
    /// Makes \a folder the one subsequent header requests address, and reports
    /// its size and sync token via folderOpened(). Over IMAP this is SELECT;
    /// over JMAP it is bookkeeping plus an Email/query count.
    ///
    /// \a syncToken is what the caller stored from the last folderOpened() for
    /// this folder, empty when it has never heard one. It is handed back rather
    /// than compared by the caller because *what a change means* is the
    /// protocol's business and nothing the caller can know: IMAP's token is
    /// UIDVALIDITY, and a different one means the mailbox was regenerated and
    /// every cached uid is meaningless; JMAP's is a state string that changes
    /// every time anything at all is modified, so reading a change as
    /// invalidation would throw the cache away each time mail arrived. A
    /// backend that decides the cache is void says so with folderInvalidated().
    virtual void openFolder(const QString &folder, const QString &syncToken) = 0;
    /// Fetches \a count headers starting \a fromNewest messages back from the
    /// newest in the folder (0 = starting at the newest). Positional paging,
    /// which is how history is walked backwards before any id is known: IMAP
    /// turns it into a sequence range, JMAP into an Email/query `position`.
    ///
    /// Sequence numbers deliberately do not appear anywhere in this interface.
    /// They are the correct IMAP mechanism for exactly this and ImapBackend
    /// keeps them, but they are IMAP's spelling of a shared idea — asking a
    /// JMAP backend for one would be asking it to fake a concept it does not
    /// have.
    /// \a background marks work nobody is waiting on (the idle-time backfill).
    /// A backend may serve it on a separate connection, or at lower priority,
    /// so a folder the user just clicked never queues behind it.
    virtual void fetchHeaderWindow(const QString &folder, int fromNewest, int count,
                                   bool background, const OpCallback &done) = 0;
    /// Fetches every header newer than \a sinceRemoteId — the cheap catch-up a
    /// reconnect wants, which no positional window can express (IMAP "uid:*",
    /// JMAP Email/changes against the sync token openFolder() was given). An
    /// empty id means "everything".
    ///
    /// A protocol that can also report what *went away* does so through
    /// messagesVanished() during this call; one that cannot simply does not,
    /// which is why the caller must treat that signal as extra news rather than
    /// as a complete account of the folder.
    virtual void fetchHeadersSince(const QString &folder, const QString &sinceRemoteId,
                                   const OpCallback &done) = 0;
    /// Fetches the headers of specific messages, named the protocol's own way
    /// (search results, a refresh of known rows).
    virtual void fetchHeadersById(const QString &folder, const QStringList &remoteIds,
                                  const OpCallback &done) = 0;
    /// Fetches complete RFC 5322 messages. Both protocols can serve the
    /// original bytes — IMAP as BODY.PEEK[], JMAP as a blob download — which is
    /// what lets the existing KMime parsing, viewer and DKIM paths stay
    /// untouched. Answered by bodyFetched() per message.
    virtual void fetchBodies(const QString &folder, const QStringList &remoteIds,
                             const OpCallback &done) = 0;
    /// How many more body batches can be started right now. A backend may keep
    /// several connections for bulk transfer (IMAP does; HTTP does not need
    /// to), and the caller paces its queue by this rather than guessing.
    virtual int freeBodySlots() const = 0;
    /// True while any body transfer is in flight, so the caller can tell an
    /// idle moment from a busy one before scheduling more background work.
    virtual bool bodyFetchActive() const = 0;
    /// Whether background work — the idle-time header backfill and body
    /// prefetch — can start right now. False means "not yet": the backend has
    /// begun whatever it needs to become ready and the caller should retry on
    /// a later tick rather than falling back to the interactive path, since
    /// work nobody is waiting on must never queue in front of a click.
    ///
    /// This is the whole of what a caller needs to know about connection
    /// multiplicity, which is why it is a yes-or-no and not a connection. IMAP
    /// answers it with the state of its dedicated background connection (and
    /// reopens that connection here, which is why this is not const); JMAP is
    /// ready whenever it is connected, HTTP not being serialized.
    virtual bool ensureBackgroundReady() = 0;
    /// Unread counts for the named mailboxes, keyed by path — a mail check,
    /// not a sync. Folders with none may be omitted. IMAP answers with STATUS,
    /// which needs no SELECT and so never disturbs the mailbox state of a
    /// client idling on the account elsewhere; JMAP reads `unreadEmails` off
    /// Mailbox/get in a single call.
    ///
    /// This is how an account that is *not* the open one gets its counts: a
    /// backend instance is one account, so the caller makes a short-lived
    /// backend for each account it wants to poll.
    virtual void folderUnreadCounts(
        const QStringList &folders,
        const std::function<void(Error, const QHash<QString, int> &counts,
                                 const QString &message)> &done) = 0;

    /// Server-side search within \a folder. \a headersOnly limits matching to
    /// sender and subject; otherwise the body and all headers count. Answered
    /// by searchResults().
    /// \a byRecipient searches To instead of From in the header pass. Set for
    /// the user's own outgoing folders, where every message is from them and a
    /// From search matches everything or nothing.
    virtual void search(const QString &folder, const QString &query, bool headersOnly,
                        bool byRecipient,
                        const OpCallback &done) = 0;

    // --- Writing -----------------------------------------------------------

    /// Adds and/or removes flags (the vocabulary of HeaderInfo::flags) on the
    /// named messages.
    virtual void setFlags(const QString &folder, const QStringList &remoteIds,
                          const QStringList &addFlags, const QStringList &removeFlags,
                          const OpCallback &done) = 0;
    /// Moves messages to another mailbox — what deleting to trash, filing spam
    /// and the sidebar's drag-and-drop all come down to.
    virtual void moveMessages(const QString &folder, const QStringList &remoteIds,
                              const QString &targetFolder, const OpCallback &done) = 0;
    /// Destroys messages outright (emptying the trash).
    virtual void deleteMessages(const QString &folder, const QStringList &remoteIds,
                                const OpCallback &done) = 0;

    virtual void createFolder(const QString &path, const OpCallback &done) = 0;
    /// Renames or reparents \a from to \a to, subtree included.
    virtual void renameFolder(const QString &from, const QString &to,
                              const OpCallback &done) = 0;
    /// Removes one mailbox. Deliberately not a subtree operation: a server may
    /// refuse to delete a mailbox that still has children, so the order is the
    /// caller's to choose and its partial success its to handle.
    virtual void deleteFolder(const QString &path, const OpCallback &done) = 0;

    /// Files an already-composed message in \a folder without sending it —
    /// saving a draft, and over IMAP also the sent copy. \a done receives the
    /// id it was filed under, empty when the server did not say (IMAP without
    /// UIDPLUS).
    virtual void storeMessage(const QString &folder, const QByteArray &raw,
                              const QStringList &flags,
                              const std::function<void(Error, const QString &remoteId,
                                                       const QString &message)> &done) = 0;
    /// Sends \a raw to \a recipients (the envelope, not the visible headers —
    /// they differ for Bcc). Whether a copy lands in Sent is the protocol's
    /// business: IMAP needs a separate storeMessage(), JMAP files it as part of
    /// the submission, so callers must not append one themselves —
    /// sentCopyIsAutomatic() says which. On failure \a done carries the
    /// server's own words: they are shown verbatim in the compose window, never
    /// shortened into the status breadcrumb.
    /// \a from is the envelope sender, which is not derivable from the
    /// credentials — a login name need not be an address, nor share its domain.
    /// \a recipients is the flat envelope list; the To/Cc/Bcc distinction is a
    /// header matter and Bcc must never appear in one.
    virtual void sendMessage(const QByteArray &raw, const QString &from,
                             const QStringList &recipients, const OpCallback &done) = 0;
    /// True when sendMessage() also files the sent copy server-side.
    virtual bool sentCopyIsAutomatic() const = 0;

    // --- Push --------------------------------------------------------------

    /// Starts server-initiated change notifications — IMAP IDLE on the open
    /// folder, JMAP EventSource across all of them. Best-effort by contract:
    /// failure is silent and simply means the caller's poll timer remains the
    /// only refresh. Changes arrive as folderChanged().
    virtual void startPush(const QString &folder) = 0;
    virtual void stopPush() = 0;
    /// True while push is actually established, so the caller knows whether
    /// its fallback poll timer still has work to do. Always false for a
    /// backend whose startPush() failed or was never called.
    virtual bool pushActive() const = 0;

Q_SIGNALS:
    /// The connection came up or went away. A backend that reconnects by
    /// itself emits this twice rather than hiding the gap.
    void connectedChanged(bool connected);
    /// A connection that *had* come up dropped on its own. Distinct from
    /// errorOccurred(Error::Connection), which reports one that never came up
    /// at all, because the two want opposite responses: a drop is retried
    /// quietly, a refusal is shown to the user. Always followed by
    /// connectedChanged(false); a caller-requested disconnectAccount() emits
    /// only the latter.
    void connectionLost();
    /// Answers listFolders(). \a separator is the hierarchy delimiter the
    /// server reported, for building child paths.
    void foldersListed(const QList<MailBackend::FolderInfo> &folders, QChar separator);
    /// Answers openFolder(). \a messageCount is what the server holds;
    /// \a syncToken is the opaque resume point for MailStore::setSyncState()
    /// (IMAP puts UIDVALIDITY here as text, JMAP its state string), and an
    /// empty one means the backend has no delta position to offer.
    ///
    /// Opaque means opaque: store it, hand it back to the next openFolder(),
    /// and read nothing into it — not even that a changed one is bad news.
    void folderOpened(const QString &folder, qint64 messageCount, const QString &syncToken);
    /// Everything cached for \a folder is void and must be thrown away — the
    /// mailbox was regenerated (IMAP UIDVALIDITY) or the server can no longer
    /// say what changed since the caller's position (JMAP
    /// `cannotCalculateChanges`, which a server answers when its change log no
    /// longer reaches that far back).
    ///
    /// A signal rather than something inferred from folderOpened() because the
    /// two protocols encode it in opposite ways, and the caller guessing got it
    /// wrong in the expensive direction: a JMAP state string changes on every
    /// modification, so "the token changed" would have discarded a
    /// multi-gigabyte cache every time a message arrived. Always followed by
    /// the folder being re-read from scratch, so it is safe to act on
    /// immediately.
    void folderInvalidated(const QString &folder);
    /// Messages that are gone from \a folder, learned from a delta the caller
    /// asked for. Best-effort by protocol: JMAP's `Email/changes` names its
    /// `destroyed` ids, IMAP's open-ended UID fetch cannot, so an empty
    /// account of what vanished is not a promise that nothing did.
    void messagesVanished(const QString &folder, const QStringList &remoteIds);
    /// A batch of headers. Several may answer one request; completion is the
    /// request's own OpCallback, not a flag here — that is what lets a caller
    /// tell apart the several fetches that can be in flight at once (the open
    /// folder and a background backfill run on different connections).
    void headersFetched(const QString &folder,
                        const QList<MailBackend::HeaderInfo> &headers);
    /// One complete message, parsed by the backend — never re-parsed by the
    /// caller (see HeaderInfo::message for why). Several arrive per
    /// fetchBodies() request; the request's OpCallback marks the end.
    void bodyFetched(const QString &folder, const QString &remoteId,
                     const std::shared_ptr<KMime::Message> &message);
    /// The server declined to store a body (too large, gone). Lets the caller
    /// stop asking rather than retrying it on every backfill pass.
    void bodyUnavailable(const QString &folder, const QString &remoteId, qint64 size);
    /// Answers search() — the ids that matched, in server order.
    void searchResults(const QString &folder, const QStringList &remoteIds);
    /// Something changed in \a folder — new mail, or flags altered elsewhere.
    /// What actually changed is then fetched the ordinary way, which keeps
    /// IDLE and EventSource interchangeable.
    void folderChanged(const QString &folder);
    /// Something changed somewhere in this account, and the backend cannot say
    /// where. Raised alongside folderChanged() for the open folder, not
    /// instead of it: the two answer different questions, and a caller that
    /// only wanted the open folder can ignore this one entirely.
    ///
    /// This is the shape of JMAP's push and the reason it is worth having.
    /// IMAP IDLE watches the one mailbox the connection has selected, so a
    /// backend built on it can only ever name that mailbox — everything else
    /// waits for a poll. A JMAP EventSource carries a StateChange for the whole
    /// account, so mail arriving in a folder nobody is looking at is known
    /// immediately; there is simply no folder to name, the state being
    /// account-wide. Callers use it to refresh what they show *about* other
    /// folders — unread counts — without opening any of them.
    void accountChanged();
    /// A request failed. Reported rather than thrown because most failures are
    /// recoverable and the application decides what to do: Error::Throttled
    /// means back off, Error::Auth means re-authenticate.
    void errorOccurred(MailBackend::Error error, const QString &message);
    /// The server is refusing work (an IMAP throttling NO/BAD, a JMAP 429).
    /// Distinct from errorOccurred(Error::Throttled) in that nothing failed —
    /// this is the server asking for a slower pace before it has to.
    void throttled();
};

Q_DECLARE_METATYPE(MailBackend::FolderInfo)
Q_DECLARE_METATYPE(MailBackend::HeaderInfo)
