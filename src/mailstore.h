// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QCoreApplication>
#include <QHash>
#include <QList>
#include <QSet>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QString>
#include <QStringList>
#include <QVariantList>

#include <functional>
#include <tuple>

#include "messagelistmodel.h"

/**
 * SQLite cache: message headers per folder, raw message bodies, and an FTS5
 * full-text index (subject/sender/body). Folders open instantly from cache
 * while the network refresh runs, previously read messages open offline,
 * and keyword search hits the local index before falling back further.
 *
 * All message/body/search rows are keyed per account (setAccountKey) so
 * several accounts never mix their identically-named folders (INBOX…).
 * Folder lists are stored per account explicitly so the folder tree of an
 * inactive account can still be shown in the sidebar.
 *
 * v1 ignores UIDVALIDITY — if a server resets UIDs the cache heals itself
 * on the next header refresh (INSERT OR REPLACE), stale bodies just expire.
 */
class MailStore
{
    // Not a QObject, but the migration labels below are shown to the user.
    Q_DECLARE_TR_FUNCTIONS(MailStore)
public:
    bool open();

    /// Scopes all folder-keyed operations below to this account ("user@host").
    void setAccountKey(const QString &key);
    QString accountKey() const { return m_accountKey; }

    // --- deferred one-time migrations --------------------------------------
    //
    // Every migration that has to walk a large table is kept out of open() and
    // run on a worker behind the progress modal instead — see
    // MaintenanceScheduler::startCacheMigrations(). Inline they cost a launch
    // that got slower the more mail was cached, with a frozen window and
    // nothing on screen saying why: a full sweep of `bodies` on a multi-gigabyte
    // cache is minutes, and the user was made to wait for it before seeing a
    // single message. Cheap flag flips and the schema statements stay in
    // open(), which must finish before the first query can run at all.
    struct Migration {
        QString flag;  ///< meta_flags key recording it done
        QString label; ///< what the modal says while it runs
    };
    /// The migrations still outstanding on the open cache, in the order they
    /// must run. \a account is whose the pre-multi-account rows are to become;
    /// empty skips that step (a local archive's key postdates the migration and
    /// must not adopt another account's leftovers).
    QList<Migration> pendingMigrations(const QString &account) const;
    /// Runs one of them on \a db, a worker connection. \a progress reports
    /// 0-100 for steps that can count their work; the rest leave the bar
    /// indeterminate. \a cancelled is polled between slices — a step that stops
    /// early leaves its flag unset and resumes from the start next launch, so
    /// every one of them is written to be safe to re-run.
    static void runMigration(QSqlDatabase &db, const Migration &step, const QString &account,
                             const std::function<void(int)> &progress,
                             const std::function<bool()> &cancelled);

    QStringList cachedFolders(const QString &account);
    void storeFolders(const QString &account, const QStringList &folders);

    /// Teaches the store which mailboxes are junk folders, so that every path
    /// that reads cached headers marks what it finds there.
    ///
    /// Set once at startup by MailClient, which is the only thing that knows —
    /// the answer comes from the server's \Junk attribute, the JMAP role and a
    /// list of folder names, none of which is the cache's business. It lives
    /// here anyway because the cache is where the rows come from: SyncEngine
    /// re-reads them on every merge, page and reconcile, and a rule applied in
    /// one caller was silently undone by the next refresh.
    ///
    /// Given the whole folder key ("account\x1fmailbox"), not just the mailbox:
    /// the cache holds every account's rows, and an imported archive's "Junk"
    /// folder is a record of what some other mail system once decided rather
    /// than a verdict this client should restate.
    ///
    /// Static because sortedHeadersOn() is, and read from the sort worker as
    /// well as the GUI thread. Set before either exists and never again.
    static void setJunkFolderTest(std::function<bool(const QString &)> isJunk);

    QList<MessageListModel::Header> cachedHeaders(const QString &folder, int limit = 1000);
    /// Next page of cached headers strictly older than the (date, uid) anchor
    /// — keyset pagination for endless scrolling through the disk cache.
    QList<MessageListModel::Header> cachedHeadersBefore(const QString &folder, qint64 dateSecs,
                                                        qint64 uid, int limit = 500);
    /// A page of the folder under the sort the list is showing: the first
    /// \a limit rows when \a after is null, else the \a limit rows that follow
    /// \a after — keyset pagination in the sort's own direction, so scrolling
    /// down appends the next contiguous block and never leaves a gap. \a column
    /// is a MessageListModel::SortColumn; the ordering mirrors the model's
    /// lessThan() so the pages arrive already in list order.
    ///
    /// Static and taking its own \a db because only "date" has an index behind
    /// it: by sender or subject every page sorts the folder, which on a
    /// 50k-message folder is half a second — it must not run on the GUI
    /// thread. \a scopedFolder is what scopedKey() returns for the folder.
    static QList<MessageListModel::Header> sortedHeadersOn(QSqlDatabase &db,
                                                           const QString &scopedFolder,
                                                           int column, bool descending, int limit,
                                                           const MessageListModel::Header *after);
    /// Same on the GUI thread's connection — for the date column only, where
    /// idx_messages_date makes a page a few milliseconds in either direction,
    /// exactly like cachedHeadersBefore(). The other columns sort the folder
    /// per page and must go through sortedHeadersOn() on a worker.
    QList<MessageListModel::Header> sortedHeaders(const QString &folder, int column,
                                                  bool descending, int limit,
                                                  const MessageListModel::Header *after);
    /// Number of cached headers of a folder (no row limit).
    int cachedHeaderCount(const QString &folder);
    /// Highest cached uid of a folder (0 when nothing is cached).
    qint64 maxCachedUid(const QString &folder);
    void storeHeaders(const QString &folder, const QList<MessageListModel::Header> &headers);
    /// storeHeaders() on an explicit connection and an already-scoped folder
    /// key, for workers (the Thunderbird importer) that do not own m_db.
    /// \a ftsAvailable is passed in because a worker cannot ask the instance.
    static void storeHeadersOn(QSqlDatabase &db, const QString &scopedFolder,
                               const QList<MessageListModel::Header> &headers,
                               bool ftsAvailable);

    // --- Another account's rows ---------------------------------------------
    //
    // Everything above addresses the account setAccountKey() named — the one
    // the user has open. The background poll syncs the inbox of accounts that
    // are *not* open, so these name the account instead. Deliberately not a
    // temporary swap of the scope: the poll and the open account's own sync
    // interleave on the same event loop, and a swapped scope that outlived a
    // callback would file one account's mail under the other.
    int cachedHeaderCountIn(const QString &account, const QString &folder);
    qint64 maxCachedUidIn(const QString &account, const QString &folder);
    void storeHeadersIn(const QString &account, const QString &folder,
                        const QList<MessageListModel::Header> &headers);
    QString syncStateIn(const QString &account, const QString &folder);
    void setSyncStateIn(const QString &account, const QString &folder, const QString &state);

    void removeMessages(const QString &folder, const QList<qint64> &uids);
    /// Refined attachment kind (MessageListModel::AttachKind) learned from the
    /// full body — "single .ics calendar invite", or "no attachment after all"
    /// for a multipart/mixed that wraps nothing but the message text.
    void setAttachKind(const QString &folder, qint64 uid, int kind);
    /// OpenPGP shape learned from the full body (PgpMime::StoredKind) — the
    /// head only shows the outer content type, which cannot see inline PGP or
    /// a signature nested inside an encrypted message.
    void setCrypto(const QString &folder, qint64 uid, int kind);

    /// Records a spam verdict for one message. \a state follows
    /// MessageListModel::Header::spamState — 1 headers only, 2 with the body,
    /// 3 cleared by the user.
    void setSpamVerdict(const QString &folder, qint64 uid, int score, int state,
                        const QString &detail);
    /// One cached message's raw bytes, for the recipient backfill.
    struct RawRow {
        qint64 uid = 0;
        QByteArray raw;
    };
    /// Rows of \a folder that have no recipients recorded but do have their
    /// bytes cached, newest first, at most \a limit of them.
    ///
    /// The To line was never a column until recently, so every message cached
    /// before it existed has none — which in the Sent folder is every row on
    /// screen. The bytes are still here though: a cached body keeps the whole
    /// head even when its attachments have been lifted out, so the header can
    /// be read back locally and nothing has to be re-fetched.
    /// Static, taking their own connection: this runs as a one-time migration
    /// over tens of thousands of rows, parsing a header out of each, and must
    /// never touch the GUI thread. \a scopedFolder is what scopedKey() returns.
    static QList<RawRow> rawsMissingRecipientsOn(QSqlDatabase &db, const QString &scopedFolder,
                                                 int limit);
    /// Writes a batch of recipient lines in one transaction.
    static void setRecipientsBatchOn(QSqlDatabase &db, const QString &scopedFolder,
                                     const QHash<qint64, QString> &byUid);
    /// How many rows of \a scopedFolder still need one — the migration's total,
    /// for the progress bar.
    static int missingRecipientCountOn(QSqlDatabase &db, const QString &scopedFolder);
    /// Every folder key the message cache holds, for *all* accounts. The
    /// migration cannot ask the folder model: that holds the open account's
    /// folders only, so driving the migration from it silently skipped every
    /// other account's Sent folder.
    static QStringList allCachedFolderKeysOn(QSqlDatabase &db);

    /// The stored verdict state, or 0 when the message is not cached. Read
    /// before a body-stage re-score, which must leave state 3 alone.
    int spamStateOf(const QString &folder, qint64 uid);
    /// Marks a cached header as read, so the state survives a restart even
    /// before the next header sync confirms it from the server.
    void setSeen(const QString &folder, qint64 uid);
    /// Marks every cached row of \a folder read, and returns how many changed.
    /// For reconciling with the server: mail read on another device changes a
    /// folder's unseen count but not its size, and no sync path re-reads old
    /// flags — so when the server reports a folder fully read, this is how the
    /// cache is made to agree.
    int clearUnseenIn(const QString &account, const QString &folder);
    /// One cached message named both ways at once: the local key the cache and
    /// the list model use, and the id a MailBackend operation takes.
    struct AgedMessage {
        qint64 uid = -1;
        QString remoteId;
    };
    /// Messages in \a folder whose date is before \a cutoffSecs, plus any with
    /// no usable date at all (stored as 0 — the "1970" rows), which count as
    /// old rather than as new. Indexed by (folder, date). Both names come back
    /// in one pass because the caller deletes them on the server by remote id
    /// and forgets them locally by uid.
    QList<AgedMessage> messagesOlderThan(const QString &folder, qint64 cutoffSecs);
    /// Clears \Seen on one cached message — the "mark unread" counterpart.
    void setUnseen(const QString &folder, qint64 uid);
    /// Every unread cached message in \a folder, named both ways — what
    /// "mark all read" has to tell the server about. Seeks (folder, uid), the
    /// primary key, so it visits this folder's rows only.
    QList<AgedMessage> unseenMessages(const QString &folder);
    /// Marks every cached message in \a folder read, in one statement. Same
    /// key seek as above; the rows already read are left alone.
    void setFolderSeen(const QString &folder);
    /// Local-only color-scale mark (0 = none, 1..5), never synced to IMAP.
    void setColorLabel(const QString &folder, qint64 uid, int color);

    /// Our own DKIM/ARC verdict for one message, as recorded when we last had
    /// a copy worth verifying. \a dkimStatus is empty when the message has
    /// never been verified — the only value that means "ask again".
    struct AuthVerdict {
        QString dkimStatus;
        QString dkimDetail;
        bool dkimTrusted = false;
        QString arcStatus;
        QString arcSealer;
        QString arcDetail;
        bool isEmpty() const { return dkimStatus.isEmpty(); }
    };
    AuthVerdict authVerdict(const QString &folder, qint64 uid);
    void storeAuthVerdict(const QString &folder, qint64 uid, const AuthVerdict &v);
    /// Every cached header of a folder carrying this color mark, newest first
    /// (indexed query — fast even on big folders).
    QList<MessageListModel::Header> headersByColor(const QString &folder, int color,
                                                   int limit = 1000);

    /// Cached UIDVALIDITY for a folder (0 = unknown). IMAP-specific and now
    /// write-only: syncState() is what every reader asks for, and an IMAP
    /// backend simply puts its UIDVALIDITY in that token. Kept because it is
    /// what caches written before the token existed hold.
    qint64 uidValidity(const QString &folder);
    void setUidValidity(const QString &folder, qint64 validity);
    /// Opaque per-folder sync position, written and read only by the backend
    /// that owns the account — an IMAP UIDVALIDITY or a JMAP `Email/changes`
    /// state string. Empty means "no delta position known", i.e. sync from
    /// scratch. The store never parses it, with one exception: a folder cached
    /// before this column existed has its recorded UIDVALIDITY returned as the
    /// token, so the upgrade does not read as "never synced" and lose the one
    /// mailbox-regenerated check that spans it.
    QString syncState(const QString &folder);
    void setSyncState(const QString &folder, const QString &state);
    /// Wipes every cached header/body/FTS row of a folder (UIDVALIDITY change).
    void clearFolder(const QString &folder);

    /// Re-keys the cached rows of \a oldFolder — and of its whole subtree —
    /// onto \a newFolder after a server-side RENAME, so a reparented folder
    /// keeps its offline mail instead of having to sync again. \a separator is
    /// the server's hierarchy delimiter; \a account scopes the folder keys.
    /// Rewrites body blobs, so it blocks: MailClient drives it on a worker
    /// connection, never on the GUI thread.
    static void renameFolderOn(QSqlDatabase &db, const QString &account,
                               const QString &oldFolder, const QString &newFolder,
                               QChar separator);

    /// The account-scoped storage key for a folder ("account\x1ffolder"), for
    /// the off-thread helpers below which have no access to the account state.
    QString scopedKey(const QString &folder) const { return scoped(folder); }

    /// Cached unread count per mailbox for \a account, keyed by bare folder
    /// path. Counts what is in the cache, which for a folder still syncing is
    /// fewer messages than the server holds.
    ///
    /// Takes an explicit connection because the first call also builds the
    /// partial index it relies on, and that is a full pass over `messages`:
    /// MailClient drives this on a worker, never on the GUI thread.
    static QHash<QString, int> unreadCountsOn(QSqlDatabase &db, const QString &account);
    /// Same on the GUI connection, for a caller comparing the cache against
    /// what a server just reported.
    QHash<QString, int> unreadCounts(const QString &account) const;
    /// How many rows are cached per folder — not how many are unread. Tells a
    /// count of zero that means "read" apart from one that means "this folder
    /// has never been cached", which are the same number and opposite facts.
    QHash<QString, int> cachedRowCounts(const QString &account) const;
    /// Makes \a folder's cached rows agree with the server's own list of
    /// unread ids: everything in \a unseenIds becomes unread, everything else
    /// in that folder becomes read. Returns how many rows changed.
    ///
    /// The only operation that can settle a disagreement about *which* mail is
    /// unread. A count says how many and names none of them, which is why a
    /// badge could sit at ten over a folder whose every row was read.
    int applyUnseenSet(const QString &account, const QString &folder,
                       const QStringList &unseenIds);

    /// The one-time-work marker every deferred migration already uses, for the
    /// two callers outside this file. \a db is a worker connection.
    static bool workDoneOn(QSqlDatabase &db, const QString &flag);
    static void markWorkDoneOn(QSqlDatabase &db, const QString &flag);
    /// Same question on the GUI connection, so a caller can decide whether
    /// there is any reason to start a worker at all.
    bool workDone(const QString &flag) const;

    /// Deletes at most \a limit cached messages (header + body + search rows)
    /// of \a scopedFolder, using \a db. Returns how many were removed; 0 means
    /// nothing is left. Deleting a body releases its blob pages, which is far
    /// too slow for the GUI thread at 100 KB a row — so this takes an explicit
    /// connection and is meant to be driven by purgeFolder() on a worker.
    static int purgeChunkOn(QSqlDatabase &db, const QString &scopedFolder, int limit);

    /// Runs purgeChunkOn() to completion on its own connection. Blocks, so
    /// call it from a worker thread. \a cancel aborts between chunks; \a
    /// progress is invoked with the running total after each chunk.
    static void purgeFolder(const QString &scopedFolder, const QAtomicInt &cancel,
                            const std::function<void(int)> &progress);

    /// Size of the cache file on disk, and how much of it is free pages that
    /// only a vacuum() can hand back to the filesystem.
    qint64 databaseBytes() const;
    qint64 reclaimableBytes();
    /// Rebuilds the database file, releasing free pages. Blocks for minutes on

    /// Where the cache file lives. One definition, because the compaction
    /// below has to name it from three places.
    static QString databaseFilePath();
    /// Writes a compacted copy of the cache to \a target — SQLite's
    /// VACUUM INTO, which reads the live database rather than rewriting it.
    /// Safe to run for minutes on a worker thread: it takes no lock the GUI
    /// connection waits on, so the client stays usable throughout. Needs free
    /// space of roughly the current file size. Returns false and leaves the
    /// cache untouched on failure — including "disk full", which the in-place
    /// VACUUM could only report after having already stopped everything.
    static bool vacuumInto(const QString &target, QString *error = nullptr);
    /// Puts \a compacted in place of the live cache and reopens the
    /// connection. GUI thread only, and only with every worker stopped: it
    /// closes the one connection the client reads through, replaces the file
    /// with a rename, and opens it again. The rename is the only moment the
    /// cache is unavailable, and it is a single filesystem operation rather
    /// than the minutes an in-place VACUUM held everything for.
    bool swapInCompacted(const QString &compacted, QString *error = nullptr);

    /// Newest-first uids of cached headers that have no cached body yet —
    /// the work list for the idle-time body backfill.
    QList<qint64> uidsWithoutBody(const QString &folder, int limit = 10);
    /// How many cached headers still lack a cached body.
    int missingBodyCount(const QString &folder);

    /// Records that a body was deliberately not cached (over the size limit).
    /// Both queries above skip these, so the backfill stops asking for them.
    void skipBody(const QString &folder, qint64 uid, qint64 size);
    /// Makes skipped bodies eligible again after the limit is raised — those
    /// no bigger than \a maxSize (0 = no limit, clears the whole list).
    /// Returns how many became eligible.
    int unskipBodiesUpTo(qint64 maxSize);

    QByteArray cachedBody(const QString &folder, qint64 uid);
    /// The backend's own id for one cached message — what a MailBackend
    /// operation names it by. Falls back to the uid in decimal, which is what
    /// an IMAP backend expects and what rows cached before the remote_id
    /// column existed hold implicitly. Empty when the row is unknown. A point
    /// lookup on the (folder, uid) primary key, for callers that hold a
    /// message rather than a model row.
    QString remoteIdFor(const QString &folder, qint64 uid);
    /// Drops just the cached body (and its part references) of one message,
    /// keeping the header. Used when a stub turns out to reference a payload
    /// that is no longer on disk, so the next open re-fetches it cleanly.
    void removeBodyOnly(const QString &folder, qint64 uid);
    void storeBody(const QString &folder, qint64 uid, const QByteArray &raw,
                   const QString &indexText);

    /// One attachment payload lifted out of a message into the file store.
    struct PartRef {
        QString partId;   ///< MIME path within the message, e.g. "2.1"
        QString hash;     ///< content address in AttachmentStore
        QString filename;
        QString mime;
        qint64 size = 0;  ///< decoded size
        qint64 stored = 0;///< bytes on disk after compression
        int codec = 0;    ///< 0 = raw, 1 = zstd
    };
    /// Records the parts lifted out of one message and takes a reference on
    /// each payload. Call inside the same transaction as its stub write.
    void storeParts(const QString &folder, qint64 uid, const QList<PartRef> &parts);
    /// Same, on an explicit connection and an already-scoped folder key.
    static void storePartsOn(QSqlDatabase &db, const QString &scopedFolder, qint64 uid,
                             const QList<PartRef> &parts);
    /// The parts of a message, for putting the payloads back when it is read.
    QList<PartRef> partsFor(const QString &folder, qint64 uid);
    /// Drops the part rows of the given messages and deletes any payload whose
    /// last referrer just went away. Returns bytes freed on disk.
    qint64 releaseParts(const QString &scopedFolder, const QList<qint64> &uids);
    /// Same, on an explicit connection, for the workers that do not own m_db.
    static qint64 releasePartsOn(QSqlDatabase &db, const QString &scopedFolder,
                                 const QList<qint64> &uids);
    /// Total size of the attachment file store, and how much of it is unused.
    qint64 attachmentBytes();
    /// True until every pre-existing body has had its attachments moved into
    /// the file store. Survives restarts, so an interrupted run resumes.
    bool attachmentMigrationPending();
    /// Splits one chunk of already-cached bodies. \a splitFn receives a raw
    /// message and returns its stub, filling the part list — it is a callback
    /// so the store stays free of MIME knowledge. Advances \a cursor and
    /// returns how many rows were examined; 0 means the migration is finished.
    /// Runs on \a db, i.e. on a worker thread.
    static int migrateAttachmentsChunk(
        QSqlDatabase &db, qint64 &cursor, int limit, qint64 &bytesSaved,
        const std::function<QByteArray(const QByteArray &, QList<PartRef> *)> &splitFn);
    /// Marks the migration complete (worker connection).
    static void finishAttachmentMigration(QSqlDatabase &db);

    /// Deletes payload files with no referring row, left behind by a run that
    /// was interrupted between writing a file and committing its part row.
    /// Returns how many were removed.
    int sweepOrphanAttachments();

    /// One cached body waiting to be written, already account-scoped.
    struct BodyWrite {
        QString scopedFolder;
        qint64 uid = 0;
        QByteArray raw;       ///< the stub: message with big payloads removed
        QString indexText;
        QList<PartRef> parts; ///< payloads lifted into the file store
    };
    /// Writes a batch of bodies in a single transaction on \a db. Storing a
    /// ~100 KB blob plus its FTS rows costs tens of ms, so the GUI thread does
    /// not do this — MailClient drains its queue on a writer thread.
    static void writeBodiesOn(QSqlDatabase &db, const QList<BodyWrite> &batch);
    /// Opens an additional connection to the cache for a worker thread.
    /// \a name must be unique per thread. Returns an invalid db on failure.
    static QSqlDatabase openWorkerConnection(const QString &name);

    /// Local keyword search inside one folder; matches partial words too
    /// (FTS5 prefix query plus a substring scan over subject/sender).
    /// Blocking, and on a large folder the substring pass is not fast — callers
    /// on the GUI thread should use searchOn() on a worker instead.
    QList<MessageListModel::Header> search(const QString &folder, const QString &keyword,
                                          bool byRecipient = false);

    /// Receives search hits in batches as they are found; returning false
    /// abandons the search (a newer query, a folder switch, shutdown).
    using SearchSink = std::function<bool(const QList<MessageListModel::Header> &)>;

    /// search(), on a worker thread's connection, delivering as it goes.
    /// \a scopedFolder is what scopedKey() returns for the folder.
    /// \a headersOnly limits the full-text pass to sender and subject.
    static void searchOn(QSqlDatabase &db, const QString &scopedFolder, const QString &keyword,
                         bool ftsAvailable, const SearchSink &deliver, bool headersOnly = false,
                         bool byRecipient = false);

    /// Whether the FTS index exists — searchOn() takes this as a parameter
    /// because it cannot ask the instance from a worker thread.
    bool ftsAvailable() const { return m_ftsAvailable; }

    /// True when the search index was built before diacritic folding, so
    /// "ave" does not find "ávé". An fts5 tokenizer cannot be changed in
    /// place; the index has to be copied into a new table. Noted at open(),
    /// carried out by MailClient on a worker.
    bool ftsNeedsRebuild() const { return m_ftsRebuildNeeded; }
    /// Re-answers that from the schema. The deferred fts_rowid migration
    /// replaces the whole index with one that already folds diacritics, so the
    /// answer noted at open() is stale the moment it has run — and acting on
    /// the stale answer costs a second full copy of the index for nothing.
    void refreshFtsRebuildNeeded();
    /// Creates the folded index if it is not there yet.
    static bool beginFtsRebuild(QSqlDatabase &db);
    /// Where a previous run stopped (0 = nothing copied yet).
    static qint64 ftsRebuildCursor(QSqlDatabase &db);
    /// Copies up to \a limit rows past \a cursor, advancing it. Returns the
    /// number copied, 0 when the old index is exhausted, -1 on failure.
    static int copyFtsChunk(QSqlDatabase &db, qint64 *cursor, int limit);
    /// Swaps the folded index in for the old one. Returns false if the swap
    /// failed, in which case the old index is untouched and still usable.
    static bool finishFtsRebuild(QSqlDatabase &db);
    /// Queues the given bodies for background re-indexing (fts_pending).
    static void queueForReindex(QSqlDatabase &db, const QList<BodyWrite> &batch);
    /// Rough denominator for rebuild progress.
    static qint64 indexedMessageCount(QSqlDatabase &db);

    /// A cached body whose text still has to be (re)indexed for search.
    struct PendingBody {
        QString scopedFolder; ///< raw folder key as stored ("account\x1ffolder")
        qint64 uid = 0;
        QByteArray raw;
    };
    /// Next batch of bodies awaiting search indexing (fts rebuild work list).
    QList<PendingBody> pendingBodyIndex(int limit);
    /// Writes the extracted body text into the search index and removes the
    /// entry from the work list. \a scopedFolder as given by pendingBodyIndex.
    void finishBodyIndex(const QString &scopedFolder, qint64 uid, const QString &indexText);
    /// Same, for a whole batch in one transaction — one fsync instead of N.
    /// Entries are (scopedFolder, uid, indexText).
    void finishBodyIndexBatch(const QList<std::tuple<QString, qint64, QString>> &entries);

    /// Per-sender "load remote content" preference (sender = addr-spec, lowercase).
    bool remoteContentAllowedFor(const QString &sender);
    void setRemoteContentAllowedFor(const QString &sender, bool allowed);

    /// Remembers an address mail was sent to (compose autocompletion).
    /// Repeated adds bump a use counter that ranks the suggestions.
    void addRecipient(const QString &address, const QString &name = {});
    /// Known recipient addresses matching \a prefix (substring of the address
    /// or display name), best-ranked first.
    QStringList recipientCompletions(const QString &prefix, int limit = 8);
    /// Remembers a recipient of one specific Sent message, so that removing
    /// that message can undo it (see recipient_refs). The pair (message,
    /// address) is recorded once however often the message is seen again, so
    /// re-opening a Sent message no longer inflates its use counter.
    void addSentRecipient(const QString &folder, qint64 uid, const QString &address,
                          const QString &name = {});
    /// Undoes the above for messages that are going away. An address survives
    /// as long as any other Sent message still holds it; the last one taking
    /// it away is what removes it. Addresses that came from somewhere other
    /// than a message are untouched.
    void dropSentRecipients(const QString &folder, const QList<qint64> &uids);
    /// Drops \a folder's refs *without* forgetting anybody. For the paths
    /// where the mail is not gone, only mailove's copy of it: an invalidated
    /// folder cache is about to be re-synced, and a UIDVALIDITY reset renumbers
    /// the messages, so refs naming the old uids have to go — but the people
    /// those messages were addressed to have not changed.
    void forgetRecipientRefs(const QString &folder);
    /// One (message, address) pair for the batched import path below.
    struct SentRecipient {
        qint64 uid = 0;
        QString address;
        QString name;
    };
    /// addSentRecipient() for a worker connection, a batch per transaction.
    static void addSentRecipientsOn(QSqlDatabase &db, const QString &account,
                                    const QString &scopedFolder,
                                    const QList<SentRecipient> &batch);

    /// True when mail has ever been sent to \a address from any account —
    /// the spam filter's Rule 0. Matches on the address alone, ignoring any
    /// +tag, and deliberately across accounts: it is a statement about a
    /// person, not about a mailbox. See SpamHeuristics::score().
    bool isKnownCorrespondent(const QString &address);
    /// Batched isKnownCorrespondent() for a whole FETCH worth of senders.
    /// Returns the subset of \a addresses that are known, normalized.
    QSet<QString> knownCorrespondents(const QSet<QString> &addresses);

    /// The subset of \a msgids that the cache already holds a message for,
    /// angle brackets stripped. Answers "is this a reply to something in my
    /// mailbox?" for a whole FETCH batch at once, over idx_messages_msgid.
    QSet<QString> knownMessageIds(const QSet<QString> &msgids);

    /// How much of a history one sending organization has here.
    struct DomainHistory {
        int seen = 0; ///< messages cached from it
        int days = 0; ///< since the oldest of them
    };
    /// History for a batch of organizational domains, missing entries meaning
    /// "never seen". Reads the sender_domains aggregate — never the messages
    /// table, which has no index that could answer this.
    QHash<QString, DomainHistory> senderDomainHistory(const QSet<QString> &orgs);

    /// Which top-level domains the user's own outgoing mail goes to.
    struct SentTldProfile {
        QStringList familiar; ///< each holding >= spam/tldSharePercent of \a sample
        int sample = 0;       ///< distinct sent-to addresses behind it
    };
    /// The profile for the open account, computed over the recipients table.
    ///
    /// Per-account, unlike isKnownCorrespondent(): "who you have written to" is
    /// a fact about a person and holds across mailboxes, but "where your mail
    /// goes" is a fact about a mailbox — a work account writing to one country
    /// and a personal one writing to another are two different profiles, and
    /// merging them would describe neither.
    ///
    /// Cached, because the spam scorer asks per message and this is a scan of
    /// every recipient row. Invalidated whenever a recipient is added or
    /// dropped, and expiring on its own after a few minutes so that rows a
    /// worker connection wrote behind our back cannot be missed forever.
    SentTldProfile sentTldProfile();

    /// Attachment heuristic on a raw RFC-2822 head: top-level multipart/mixed.
    /// Works on the raw bytes because KMime downgrades multipart/* to
    /// text/plain when parsing a header-only (body-less) message shell.
    static bool headIndicatesAttachment(const QByteArray &head);
    /// Message-ID from a raw header block, angle brackets stripped. Empty when
    /// the message has none (which is legal, if rare).
    static QString messageIdFromHead(const QByteArray &head);

    /// Fills in msgid for up to \a limit cached rows that do not have one yet,
    /// reading only each message's head rather than its payload. Returns how
    /// many rows it touched; 0 means there is nothing left to do. Deliberately
    /// chunked and resumable — the bodies table is multiple gigabytes and this
    /// must never become one long scan.
    int backfillMessageIds(int limit);

    /// Subjects of the given cached messages, in the order asked and at most
    /// \a limit of them; a message whose row has gone yields an empty string.
    /// Point lookups on the (folder, uid) primary key — for naming a handful
    /// of messages in a report, never for listing a folder.
    QStringList subjectsOf(const QString &folder, const QList<qint64> &uids, int limit = 3);

    /// Every cached copy of \a msgid, as (folder, uid). More than one is normal:
    /// the same message commonly exists in a folder and in All Mail.
    QList<QPair<QString, qint64>> locateByMessageId(const QString &msgid);

    // --- soft delete --------------------------------------------------------
    //
    // A message the user has deleted or moved away is hidden, not destroyed:
    // the row, its body and its attachments stay until the server confirms,
    // which is what a failed change is rolled back from. Every read above
    // filters these out; only confirmation purges them (removeMessages).

    /// Hides \a uids of \a folder — the local half of a move or a delete.
    void softDeleteMessages(const QString &folder, const QList<qint64> &uids);
    /// Puts them back, for a change that was given up on.
    void restoreSoftDeleted(const QString &folder, const QList<qint64> &uids);
    /// Every provisionally deleted row of \a account, by unscoped folder.
    /// Reads the tiny `WHERE soft_deleted = 1` index, so it is cheap enough to
    /// ask on every start — which is when the reconcile needs it.
    QHash<QString, QList<qint64>> softDeletedIn(const QString &account) const;

    // --- the journal --------------------------------------------------------
    //
    // Every mutation the server has still to be told about, in the order it was
    // made. See doc/OFFLINE_FIRST_ROADMAP.md: the cache is written immediately
    // and an op is appended here, and replay is the only thing that calls the
    // backend. That makes offline the ordinary path rather than a special case,
    // and it makes a change durable — before this, everything but "mark folder
    // read" was simply dropped when the connection was down.

    /// One recorded change. \a op is the kind; which fields carry meaning
    /// depends on it (see the op table in the roadmap).
    struct JournalOp {
        qint64 id = 0;          ///< replay order; never reused (AUTOINCREMENT)
        QString account;
        QString op;             ///< flag | move | delete | folder_rename | folder_delete
        QString folder;         ///< source mailbox, unscoped
        QStringList remoteIds;  ///< what the backend names the messages by
        QList<qint64> uids;     ///< the same messages as the cache names them,
                                ///< so the change can be rolled back locally
        QString target;         ///< destination mailbox / new path
        QStringList flagsAdd;
        QStringList flagsDel;
        qint64 queuedAt = 0;    ///< seconds since the epoch
        int tries = 0;
        QString lastError;
        bool retired = false;   ///< given up on, rolled back, kept for the user
    };

    /// Appends \a op and returns its id (0 on failure). \a op.account and
    /// \a op.queuedAt are filled in from the open account and the clock when
    /// left empty.
    qint64 appendJournalOp(JournalOp op);
    /// Live ops of \a account, oldest first — the replay work list.
    QList<JournalOp> journalOps(const QString &account) const;
    /// Ops of \a account that were given up on, newest first.
    QList<JournalOp> retiredJournalOps(const QString &account) const;
    /// How many of each there are, without reading the rows.
    int journalOpCount(const QString &account, bool retired = false) const;
    /// Folders of \a account holding a live op. A folder in this list must not
    /// be synced until it drains — invariant 3.
    QSet<QString> journalFolders(const QString &account) const;
    /// Records one failed attempt, keeping the op live.
    void recordJournalFailure(qint64 id, const QString &error);
    /// Gives up on an op: it stops being replayed, keeps its row and its error,
    /// and the caller rolls its local change back.
    void retireJournalOp(qint64 id, const QString &error);
    /// Forgets an op outright — confirmed, discarded, or invalidated.
    void dropJournalOp(qint64 id);
    /// Puts a retired op back in the queue with a clean slate ("Retry").
    void reviveJournalOp(qint64 id);
    /// Forgets every retired op of \a account ("Discard all").
    void clearRetiredJournalOps(const QString &account);
    /// Forgets every op of \a account, retired or not (account removal).
    void dropAccountJournal(const QString &account);
    /// Forgets live ops of \a account queued before \a cutoffSecs, returning
    /// them so the caller can roll them back. Retired ops are exempt: they are
    /// the record the user has still to read.
    QList<JournalOp> takeStaleJournalOps(const QString &account, qint64 cutoffSecs);
    /// Live ops of \a account naming \a folder — what a UIDVALIDITY reset has
    /// to discard, since every id in them has just been declared meaningless.
    QList<JournalOp> journalOpsFor(const QString &account, const QString &folder) const;
    /// Rewrites a live op after the world moved under it: used to follow a
    /// message to the folder a preceding move put it in, and to follow a
    /// renamed folder. Only ops after \a afterId are touched.
    void rewriteJournalFolder(const QString &account, qint64 afterId, const QString &from,
                              const QString &to, QChar separator);
    /// Where one moved message ended up, as the destination server named it.
    struct MovedMessage {
        QString remoteId;
        qint64 uid = 0;
    };
    /// Same, for the messages one move relocated: later ops of \a account naming
    /// any of \a moved's keys in \a from are re-pointed at \a to and renamed to
    /// what the destination calls them. A message with no entry can no longer be
    /// named at all — the ops naming it are returned so the caller retires them.
    QList<JournalOp> rewriteJournalIds(const QString &account, qint64 afterId,
                                       const QString &from, const QString &to,
                                       const QHash<QString, MovedMessage> &moved);

    // --- the outbox ---------------------------------------------------------
    //
    // Messages waiting to be sent, as final wire bytes — persisted before the
    // network is attempted, so a quit, crash or dead connection never loses a
    // pressed Send. See doc/OUTBOX_ROADMAP.md. Deliberately its own table, not
    // a folder in `messages`: these rows have no uid and no server identity,
    // and they are meant to disappear. The wire stays one blob — an outbox row
    // is written once, lives for seconds to hours, and must be byte-exact when
    // it goes out, so nothing here goes through stripAttachments().

    /// One queued send.  wire is post-crypto: exactly what sendMessage()
    /// will be handed.  encrypted is remembered because it decides what the
    /// UI may offer — ciphertext cannot be re-opened for editing.  subject
    /// and  envelope are display copies; the authoritative ones ride inside
    /// the wire.
    struct OutboxMessage {
        qint64 id = 0;          ///< send order; never reused (AUTOINCREMENT)
        QString account;
        QByteArray wire;        ///< assembled bytes, post-crypto
        QStringList envelope;   ///< flat recipient list, as sendMessage() takes it
        QString sender;         ///< envelope sender
        QString subject;        ///< for the queue list; "" for an encrypted subject
        qint64 created = 0;     ///< seconds since the epoch
        int attempts = 0;
        QString lastError;
        qint64 nextTry = 0;     ///< seconds since the epoch; 0 = now
        int state = Queued;
        bool encrypted = false;
        /// The wire carries attachments (or inline images). Like \a encrypted
        /// it gates Edit: re-opening the composer from the wire reconstructs
        /// only addresses, subject and body, and silently dropping the rest
        /// would be data loss dressed as a feature.
        bool hasAttachments = false;
    };
    /// OutboxMessage::state. Failed rows are kept for the user, like retired
    /// journal ops: they stop being tried until "Retry now" revives them.
    enum OutboxState { Queued = 0, Sending = 1, Failed = 2 };

    /// Appends  msg and returns its id (0 on failure).  msg.account and
    ///  msg.created are filled in from the open account and the clock when
    /// left empty.
    qint64 enqueueOutbox(OutboxMessage msg);
    /// Every row of  account in send order — the Outbox list, wire included.
    QList<OutboxMessage> outboxMessages(const QString &account) const;
    /// One row by id, for acting on a list entry. id 0 on a row that is gone.
    OutboxMessage outboxMessage(qint64 id) const;
    /// The next row due to go out: the oldest Queued one whose nextTry has
    /// passed. id 0 when nothing is due.
    OutboxMessage nextOutboxMessage(const QString &account, qint64 nowSecs) const;
    /// How many rows the account has, without reading the blobs. Failed rows
    /// count too — the badge is "mail that has not gone out", not "mail that
    /// is about to".
    int outboxCount(const QString &account) const;
    /// When the earliest Queued row may go out, or 0 with none queued — what
    /// the drain worker arms its backoff timer from.
    qint64 outboxNextTry(const QString &account) const;
    /// Marks a row Sending before its network attempt starts.
    void markOutboxSending(qint64 id);
    /// Records one failed attempt: back to Queued with  nextTry, or straight
    /// to Failed when  permanent — a server that has said no will keep
    /// saying it.
    void recordOutboxFailure(qint64 id, const QString &error, qint64 nextTry, bool permanent);
    /// Puts a Sending row back to Queued without spending an attempt — the
    /// connection died under it, not the message's fault.
    void deferOutboxMessage(qint64 id);
    /// Forgets a row outright — sent and filed, or cancelled by the user.
    void dropOutboxMessage(qint64 id);
    /// Puts a Failed row back in the queue with a clean slate ("Retry now").
    void reviveOutboxMessage(qint64 id);
    /// Rows still marked Sending are from a process that died mid-send —
    /// whether the message left is unknowable, so they become Failed with
    ///  note rather than being silently resent. Returns how many there were.
    int recoverStaleOutbox(const QString &account, const QString &note);
    /// Forgets every row of  account (account removal).
    void dropAccountOutbox(const QString &account);

private:
    /// Reads an OutboxMessage out of the current row of  q, which must have
    /// selected the columns in kOutboxColumns order.
    static OutboxMessage outboxRowOf(const QSqlQuery &q);
    /// Shared body of the outbox reads above.
    QList<OutboxMessage> outboxSelect(const QString &where, const QVariantList &binds) const;

    /// Reads a JournalOp out of the current row of \a q, which must have
    /// selected the columns in kJournalColumns order.
    static JournalOp journalRowOf(const QSqlQuery &q);
    /// Shared body of journalOps()/retiredJournalOps()/journalOpsFor().
    QList<JournalOp> journalSelect(const QString &where, const QVariantList &binds) const;

    /// Folder key as stored in messages/bodies/fts: "account\x1ffolder".
    QString scoped(const QString &folder) const;
    /// scoped() against an account named outright rather than the open one.
    static QString scopedIn(const QString &account, const QString &folder);
    /// Shared body of both dropSentRecipients() overloads: \a where is a
    /// recipient_refs predicate whose single bind is \a scopedFolder.
    void dropRecipientRefs(const QString &where, const QString &scopedFolder);

    QSqlDatabase m_db;
    QString m_accountKey;
    SentTldProfile m_tldProfile;      ///< sentTldProfile() cache
    qint64 m_tldProfileAt = 0;        ///< when it was computed, 0 = never
    QString m_tldProfileAccount;      ///< which account it describes
    bool m_ftsAvailable = false;
    bool m_ftsRebuildNeeded = false; ///< index predates diacritic folding
};
