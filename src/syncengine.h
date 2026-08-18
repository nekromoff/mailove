// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QHash>
#include <QList>
#include <QObject>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <functional>

#include "foldermodel.h"
#include "mailbackend.h"
#include "mailstore.h"
#include "messagelistmodel.h"

/**
 * Keeps the cache and the visible list in step with the server.
 *
 * Owns the whole sync state machine: where the open folder's history has been
 * fetched to, which other folder the background pass is walking, the disk-cache
 * paging anchor, the body prefetch queue, and the throttle backoff that paces
 * all of it. Every one of those is a cursor into "how much of the mailbox do we
 * have", which is why they belong together rather than beside the UI action
 * that happened to move one of them.
 *
 * Deliberately knows nothing about spam scoring, sender authentication or what
 * a header means: the client scores a backend's delivery and hands the finished
 * rows over with addPendingHeaders(). Nor does it know which protocol answered
 * — that is MailBackend's.
 */
class SyncEngine : public QObject
{
    Q_OBJECT
public:
    SyncEngine(MailStore &store, MessageListModel &messages, FolderModel &folders,
               QObject *parent = nullptr);

    /// The backend to sync through. Re-set when the account's protocol
    /// changes, which replaces the object outright.
    void setBackend(MailBackend *backend) { m_backend = backend; }
    /// Which folder is on screen. Kept in step by the client, because opening
    /// one is a UI action (it also clears the reading pane) rather than a sync
    /// one.
    void setOpenFolder(const QString &folder) { m_selectedFolder = folder; }
    /// True while search results have replaced the folder listing: results for
    /// the folder underneath then go to the cache only, never to the list.
    void setSearchActive(bool active) { m_searchActive = active; }
    /// Whether something user-triggered is in flight. Background work waits
    /// for it rather than competing with it.
    void setBusyProvider(std::function<bool()> busy) { m_isBusy = std::move(busy); }
    /// Answers "does this folder still hold changes the server has not been
    /// told about". A folder is never synced while it does: a merge landing
    /// between an op's local write and its push would read the server's
    /// untouched state back and undo the user's change. Waiting is a far
    /// simpler rule than making every merge path individually aware of the
    /// queue, and it is short — the drain runs before the header sync on every
    /// connect. See doc/OFFLINE_FIRST_ROADMAP.md.
    void setPendingOpsProvider(std::function<bool(const QString &)> pending)
    {
        m_hasPendingOps = std::move(pending);
    }

    // --- opening and resuming ---------------------------------------------
    /// Clears the per-folder sync cursors and stops the backfill. Called when
    /// the folder on screen changes, before the new one is opened.
    void resetForFolderChange();
    /// Asks the backend to open \a folder for reading, and remembers that the
    /// answer is to rebuild the list from it.
    void openSelectedFolder(const QString &folder);
    /// Asks it to reopen the folder already on screen, merging whatever is new
    /// rather than reloading.
    void refreshSelectedFolder(const QString &folder);
    /// Records a folder's size and sync token once the backend has opened it,
    /// and hands the result to whichever of the two openers asked for it.
    void applyFolderOpened(const QString &folder, qint64 messageCount,
                           const QString &syncToken);
    /// Stores \a folder's new sync position, and reads nothing into it. What a
    /// changed token means is the protocol's business — for IMAP a regenerated
    /// mailbox, for JMAP simply that something happened — so a backend that
    /// finds the cache void says so with folderInvalidated() instead.
    void applySyncToken(const QString &folder, const QString &syncToken);
    /// Throws away everything cached for \a folder, and re-reads it when it is
    /// the one on screen.
    void applyFolderInvalidated(const QString &folder);
    /// Drops messages the backend reports gone from \a folder — deleted or
    /// moved away by another client.
    void applyMessagesVanished(const QString &folder, const QStringList &remoteIds);
    /// A background open was refused (a mailbox deleted or made unreadable
    /// since the listing). Returns true when the refusal was this pass's, so
    /// the caller knows it has been handled rather than being a real error.
    bool handleBackgroundOpenFailure(const QString &message);

    // --- headers -----------------------------------------------------------
    /// Headers the backend delivered for a fetch still in flight, already
    /// scored into list rows. The open folder and a background backfill of
    /// another folder can stream at the same time, so they cannot share one
    /// buffer.
    void addPendingHeaders(const QString &folder, const QList<MessageListModel::Header> &rows);
    /// Takes the buffered rows for \a folder — what a search fetch reads.
    QList<MessageListModel::Header> takePendingHeaders(const QString &folder);
    /// Fetches the next (older) window of headers; no-op if everything is
    /// loaded. Pages in cached history first and only then asks the server.
    void loadMoreMessages();
    /// Pages in every remaining cached header of the open folder at once.
    /// Returns true if anything was added.
    bool loadAllCachedMessages();
    /// Tells the engine which sort the list is showing. Anything other than
    /// the newest-first default puts it in a "sorted browse": the visible list
    /// is then fed by keyset pages in that sort's order (via
    /// MaintenanceScheduler), and the engine's own newest-first window
    /// handling — cache paging and the post-refresh window reload — stands
    /// down so it cannot clobber the browsed list or wedge pages into its
    /// middle. Header syncing itself is unaffected: fetched mail still lands
    /// in the cache, where the sorted pages read it.
    void setSortOrder(int column, bool descending);
    /// True when a non-default sort is showing (see setSortOrder()).
    bool sortedBrowse() const { return m_sortColumn != 0 || !m_sortDescending; }
    /// Puts one sorted page into the model: the first page replaces the list,
    /// a follow-on page appends. Returns true if anything changed.
    bool applySortedPage(const QList<MessageListModel::Header> &rows, bool replace);
    /// Reloads the newest-first cache window into the model — what leaving a
    /// sorted browse shows again.
    void reloadWindow();
    /// Declares the open folder's history fully fetched, which is what
    /// disables "load more" while search results are showing in place of it.
    void markFullySynced() { m_fetchedFromNewest = m_folderMessageCount; }
    /// Remembers the oldest (date, uid) shown from the disk cache, so
    /// loadMoreMessages() can page the next cached chunk in from there.
    void updatePageAnchor(const QList<MessageListModel::Header> &page);

    // --- backfill ----------------------------------------------------------
    /// Arms the idle-time fetch of the next older header window.
    void scheduleBackfill(int delayMs = 4000);
    /// Grow the backoff after server pushback (a throttling NO/BAD, or a
    /// dropped connection) and re-arm the backfill after that pause.
    void backoffBackfill();
    /// Clear the throttle backoff/attempt state — called when a fetch succeeds
    /// and on (re)connect or folder change, so a healthy server resumes at
    /// full pace.
    void resetBackfillBackoff();
    /// Suspends background syncing (a vacuum holds the exclusive lock).
    void setSyncPaused(bool paused);
    /// The all-folders pass latches itself done once per connect; the poll
    /// timer re-arms it so mail in a folder nobody has open still reaches the
    /// cache. Returns false when a pass is already due.
    bool restartFolderPass();
    /// A fresh folder list restarts the all-folders background sync pass.
    void restartFolderQueue();
    /// The background connection dropped mid-fetch: the server pushing back.
    /// The in-flight fetch died with it, so the flag comes down whether or not
    /// this earns a backoff — otherwise the timer sees work still running and
    /// never re-arms.
    void handleThrottled();
    /// Stops every timer and clears every cursor — a session going away.
    void teardown();
    /// Forgets how much of the open folder's history has been fetched. An
    /// account switch, where the count belongs to the mailbox being left.
    void resetFolderCursor() { m_fetchedFromNewest = 0; m_folderMessageCount = 0; }

    // --- bodies -------------------------------------------------------------
    /// Queues one message's body for a background fetch (hover read-ahead).
    /// Newest first, and the queue stays tiny — this is opportunistic.
    void prefetchBody(const QString &folder, qint64 uid);
    /// Hands the next queued batches to the backend, as many as it has
    /// connections free for.
    void processPrefetchQueue();

    /// Cached missingBodyCount() for one folder — recomputed only when the
    /// folder changes or a write invalidates it.
    int missingBodiesIn(const QString &folder);
    void noteBodyStored(const QString &folder);
    void invalidateMissingBodies() { m_missingBodies = -1; }
    /// Composed background-sync status for the open folder: the header-sync
    /// progress ("N of M synced") and the body-caching progress ("caching K
    /// bodies") shown together, so the two phases don't overwrite each other's
    /// numbers. Empty when nothing is syncing.
    QString openFolderSyncStatus(const QString &folder);

Q_SIGNALS:
    void statusMessage(const QString &text);
    void errorOccurred(const QString &message);
    /// Something user-facing started or finished; the client owns the busy
    /// property and the spinner it drives.
    void busyRequested(bool busy);
    /// Folder contents were refreshed from the server (initial or re-open).
    void folderRefreshed();
    /// Freshly synced headers change the sidebar's unread pills.
    void unreadRecountNeeded();

private:
    void applySelectedFolderOpened(const QString &folder, qint64 messageCount,
                                   bool cacheDropped);
    void fetchNewerThanCache(qint64 maxCachedUid, int cachedCount);
    void fetchOlderFromServer();
    void requestHeaderWindow(const QString &folder, qint64 fromNewest, int count,
                             bool append, bool background);
    void applyFetchedHeaders(const QString &folder, qint64 reachedFromNewest,
                             bool append, bool background);
    /// Idle-time body caching: queues \a folder's next few headers that have
    /// no cached body yet. Runs only after the header backfill has finished,
    /// so a fresh account always shows the full list first. Returns false when
    /// the folder has no missing bodies (nothing was queued).
    bool backfillBodies(const QString &folder);
    /// Once the open folder is fully synced, walks the account's remaining
    /// folders (headers, then bodies) so every mailbox gets cached.
    void continueFolderBackfill();
    void onBackfillTick();
    bool connected() const;
    bool busy() const { return m_isBusy && m_isBusy(); }
    bool pendingOps(const QString &folder) const
    {
        return m_hasPendingOps && m_hasPendingOps(folder);
    }

    MailStore &m_store;
    MessageListModel &m_messages;
    FolderModel &m_folders;
    MailBackend *m_backend = nullptr;
    std::function<bool()> m_isBusy;
    std::function<bool(const QString &)> m_hasPendingOps;

    QString m_selectedFolder;
    bool m_searchActive = false;

    /// Why the open folder was (re)opened on the backend, so the one reply
    /// signal can serve both callers. Opening rebuilds the list from the cache
    /// and the newest window; refreshing only tops up the newest headers.
    enum class FolderOpenIntent { None, Open, Refresh };
    FolderOpenIntent m_folderOpenIntent = FolderOpenIntent::None;

    QHash<QString, QList<MessageListModel::Header>> m_pendingHeaders;

    /// How many of the folder's newest messages have been fetched. Counted
    /// from the newest rather than in IMAP sequence numbers, which are the
    /// protocol's own spelling and now live only in ImapBackend: the history is
    /// fully synced once this reaches m_folderMessageCount.
    qint64 m_fetchedFromNewest = 0;
    qint64 m_folderMessageCount = 0; ///< total messages in the open folder

    QTimer m_backfillTimer;  ///< idle-time fetch of older header windows
    bool m_backfill = false; ///< the running header fetch is a backfill one
    int m_backfillAttempt = 0; ///< consecutive throttle hits (0 while healthy)
    bool m_syncPaused = false; ///< backfill suspended after too many throttles
    QStringList m_folderBackfillQueue; ///< folders still to background-sync
    QString m_backfillFolder;   ///< non-open folder currently background-syncing
    /// An open of m_backfillFolder is outstanding. What makes a refusal
    /// attributable to the background pass rather than to something the user
    /// asked for — the error itself does not name a folder.
    bool m_backfillOpenPending = false;
    qint64 m_backfillFolderCount = -1;      ///< its size (-1 = not asked yet)
    qint64 m_backfillFetchedFromNewest = 0; ///< its own newest-fetched cursor
    bool m_folderBackfillPassDone = false; ///< all folders visited this connect
    /// Whether this pass's queue has been filled. Distinguishes an empty queue
    /// that has not started from one that has finished — without it the pass
    /// refills itself and runs forever. See continueFolderBackfill().
    bool m_folderPassPrimed = false;
    /// "All folders synced" already said since this connect. The poll timer
    /// re-arms the pass every interval, and a breadcrumb that re-announces the
    /// same thing every few minutes is noise; a real (re)connect clears it.
    bool m_folderSyncAnnounced = false;
    bool m_headerFetch = false;  ///< a header FETCH is in flight (any session)
    bool m_bodyBackfill = false; ///< the idle body-caching phase is running

    qint64 m_pageDate = 0; ///< disk-cache paging anchor: oldest shown date
    qint64 m_pageUid = 0;  ///< …and its uid (keyset pagination tiebreaker)

    // The sort the list is showing — see setSortOrder().
    int m_sortColumn = 0;
    bool m_sortDescending = true;

    QList<QPair<QString, qint64>> m_prefetchQueue; ///< (folder, uid) waiting for a body fetch

    int m_missingBodies = -1; ///< -1 = stale, recompute on next use
    QString m_missingBodiesFolder;
};
