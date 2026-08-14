// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QAtomicInt>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QWaitCondition>

#include <functional>

#include "mailstore.h"

class QThread;

namespace KMime
{
class Message;
}

/**
 * Every background job the cache needs, and the threads that run them.
 *
 * The body writer, the VACUUM, the attachment migration, the archive purge,
 * the folder-cache re-key, the search-index rebuild and the unread recount
 * all share one property: they are slow, they touch SQLite, and none of them
 * may ever run on the GUI thread. Keeping them together is what makes the
 * ordering rules between them statable in one place — above all that a vacuum
 * takes an exclusive lock, so every other writer must have *finished* first.
 *
 * Nothing here knows about accounts, folders or the network. What to purge and
 * which accounts to count are asked for by the caller, in the caller's terms;
 * results come back as signals on the GUI thread.
 */
class MaintenanceScheduler : public QObject
{
    Q_OBJECT
public:
    /// \a store is the GUI thread's cache handle — used only for the cheap
    /// size/pending queries; every worker opens a connection of its own.
    /// \a indexText extracts a message's searchable text. Supplied by the
    /// caller so the one definition of "the text of a message" stays with the
    /// viewer that also renders it.
    /// \a accountKeys is asked at recount time, not at schedule time, for the
    /// storage keys of every account whose unread pills are on screen.
    MaintenanceScheduler(MailStore &store,
                         std::function<QString(KMime::Message *)> indexText,
                         std::function<QStringList()> accountKeys,
                         QObject *parent = nullptr);
    /// Stops and joins every worker. None of them may outlive this object:
    /// each holds a raw `this` and a SQLite connection.
    ~MaintenanceScheduler() override;

    // --- body writer -----------------------------------------------------
    /// Queues a fetched body for the writer thread, starting it if needed.
    void queueBodyWrite(MailStore::BodyWrite &&write);
    /// Stops the writer thread and waits for it to flush. It restarts by
    /// itself on the next queueBodyWrite(), so callers only need this to reach
    /// a state where nothing else holds a write lock on the cache.
    void stopBodyWriter();

    // --- vacuum ----------------------------------------------------------
    bool reclaiming() const { return m_reclaiming; }
    /// Whether a rebuild would actually hand anything back.
    bool reclaimWorthwhile() const;
    /// Human-readable cache size, e.g. "13.4 GB (6.2 GB reclaimable)".
    QString cacheSizeText() const;
    /// Rebuilds the cache file on a worker thread to hand free pages back to
    /// the filesystem. Emits syncPauseRequested() first and
    /// syncResumeRequested() when it is done, either way.
    void reclaimDiskSpace();

    // --- attachment migration --------------------------------------------
    /// Moves attachments of already-cached messages into the file store, a
    /// chunk at a time on a worker thread. Resumes after a restart.
    void startAttachmentMigration();
    void stopAttachmentMigration();

    // --- archive purge ----------------------------------------------------
    /// Starts the background removal of \a scopedKey's cached rows (Gmail's
    /// All Mail). A no-op while a vacuum runs or a purge is already going.
    void startAllMailPurge(const QString &scopedKey);
    /// Cancels it and waits for the worker to finish.
    void stopAllMailPurge();

    // --- folder cache maintenance -----------------------------------------
    /// Drops the cached mail of folders deleted from the server (chunked, so
    /// the GUI thread never waits for a write lock). \a scopedKeys are already
    /// account-scoped. Emits folderOpsFinished() when done.
    void purgeCachedFolders(const QStringList &scopedKeys);
    /// Moves the cached mail of a renamed subtree onto its new paths. \a done,
    /// if given, runs on the GUI thread once the re-key has finished — after
    /// folderOpsFinished().
    void renameCachedFolder(const QString &account, const QString &from,
                            const QString &to, QChar separator,
                            std::function<void()> done = {});
    /// Joins the folder-maintenance worker, if one is running.
    void stopFolderOps();

    // --- search index ------------------------------------------------------
    /// Copies the search index into one that folds diacritics, in slices on a
    /// worker, resuming where a previous run stopped.
    void startIndexRebuild();
    /// Cancels the rebuild between slices and joins its thread.
    void stopIndexRebuild();
    bool indexRebuilding() const { return m_indexRebuilding; }
    int indexRebuildPercent() const { return m_indexPercent; }

    // --- one-time migrations ----------------------------------------------
    //
    // A cache migration is not maintenance that can wait for an idle moment:
    // until it finishes the list shows the wrong thing, so the user is told
    // what is happening and how far along it is. The three below drive one
    // generic modal, so the next migration needs a worker and nothing else —
    // no new properties, no new dialog.
    bool migrationRunning() const { return m_migrationRunning; }
    /// What to show the user, e.g. "Reading recipients from cached mail".
    QString migrationLabel() const { return m_migrationLabel; }
    /// 0-100, or -1 while the total is not known yet (indeterminate bar).
    int migrationPercent() const { return m_migrationPercent; }

    /// Fills in the To column of mail cached before that column existed, by
    /// reading the header back out of the cached message. Offline: everything
    /// it needs is already on disk. Returns without doing anything when there
    /// is nothing to fill in, which is the normal case after the first run.
    /// \a isOutgoing decides, from a folder key alone, whether that folder
    /// shows recipients. A predicate rather than a list of folders because the
    /// folders are enumerated from the cache on the worker: they belong to
    /// every account, and the caller can only see the open one's.
    void startRecipientBackfill(std::function<bool(const QString &)> isOutgoing);

    /// Announces a migration's progress from a worker thread. Public so that a
    /// future migration living elsewhere can drive the same modal; always call
    /// them through QMetaObject::invokeMethod, they touch GUI-thread state.
    void beginMigration(const QString &label);
    void reportMigration(int percent);
    void endMigration();
    /// Arms the drip-feed repair of the body search index.
    void startReindexTimer();
    void stopReindexTimer();

    // --- unread recount ----------------------------------------------------
    /// Asks for the sidebar's unread pills to be recomputed. Debounced and
    /// coalesced: marking a run of messages read fires this once per burst,
    /// and a request arriving while the worker runs re-runs it once afterwards
    /// rather than queueing one pass per call.
    void scheduleUnreadRecount();

    // --- sorted paging -----------------------------------------------------
    /// Reads one page of \a scopedFolder under the sort the list is showing and
    /// hands it back through sortPageReady(): the first page when \a after is
    /// null, else the page following \a after (keyset, in the sort's own
    /// direction). Sorting by sender or subject has no index behind it and so
    /// sorts the whole folder per page, which is why this is a worker job and
    /// not a call on the store.
    ///
    /// Only the newest request matters — the user clicking through three column
    /// headers wants the third one — so a request arriving while a worker runs
    /// replaces whatever was waiting rather than queueing behind it.
    void startSortPage(const QString &scopedFolder, int column, bool descending,
                       const MessageListModel::Header *after, int limit = 500);

Q_SIGNALS:
    /// A breadcrumb for the status line.
    void statusMessage(const QString &text);
    void errorOccurred(const QString &message);
    void reclaimingChanged();
    void indexRebuildChanged();
    /// Any of migrationRunning/Label/Percent changed.
    void migrationChanged();
    /// The search-index rebuild reached its end (successfully or not).
    void indexRebuildFinished();
    /// A vacuum is about to take the exclusive lock — stop every other writer.
    void syncPauseRequested();
    /// It is done; background syncing may resume.
    void syncResumeRequested();
    /// A folder purge or re-key finished: anything keyed by folder path (header
    /// counts, the missing-body estimate) is now stale.
    void folderOpsFinished();
    /// Fresh unread counts for every account, by storage key.
    void unreadCountsReady(const QHash<QString, QHash<QString, int>> &counts);
    /// One page of \a scopedFolder under (\a column, \a descending). The sort
    /// and folder are echoed back because the answer arrives after a click or
    /// a folder switch may have moved on, and a stale page must not be shown.
    /// \a append distinguishes a follow-on page from a first page (which
    /// replaces the list); an empty \a rows with \a append set means the end
    /// of the cache was reached.
    void sortPageReady(const QString &scopedFolder, int column, bool descending, bool append,
                       const QList<MessageListModel::Header> &rows);

private:
    /// Writer-thread loop: drains m_bodyWriteQueue into batched transactions.
    void runBodyWriter();
    /// True once every background writer has stopped. The purge and migration
    /// threads clear their own pointer from a queued finished handler, so a
    /// null pointer means stopped *and* reaped; the body writer is joined in
    /// startVacuumWhenWritersIdle(), which costs nothing once it has finished.
    bool writersIdle() const;
    /// Polls for that, then starts the vacuum thread. Polling rather than
    /// joining: the GUI thread must keep serving the event loop meanwhile.
    void startVacuumWhenWritersIdle();
    /// One tiny batch of search-index repair (bodies queued in fts_pending):
    /// parses the raw message and writes its text into the FTS index.
    void reindexPendingBodies();
    void startUnreadRecount();
    /// Runs the pending sorted-page request, if there is one and no worker
    /// holds the slot.
    void startSortPageNow();

    MailStore &m_store;
    std::function<QString(KMime::Message *)> m_indexText;
    std::function<QStringList()> m_accountKeys;

    /// Bodies wait here for the writer thread; the mutex guards the queue and
    /// pairs with m_bodyWriteWake.
    QList<MailStore::BodyWrite> m_bodyWriteQueue;
    QMutex m_bodyWriteMutex;
    QWaitCondition m_bodyWriteWake;
    QThread *m_bodyWriterThread = nullptr;
    QAtomicInt m_bodyWriterStop;

    QThread *m_migrateThread = nullptr; ///< attachment externalisation of old mail
    QAtomicInt m_migrateCancel;
    QThread *m_reindexThread = nullptr; ///< off-thread body text extraction
    QTimer m_reindexTimer;   ///< drip-feed repair of the body search index

    QThread *m_purgeThread = nullptr; ///< background removal of the excluded archive
    QAtomicInt m_purgeCancel;
    int m_purgedRows = 0;

    QThread *m_folderOpThread = nullptr; ///< cache re-key / purge after a folder move
    QAtomicInt m_folderOpCancel;

    QThread *m_vacuumThread = nullptr;
    bool m_reclaiming = false; ///< a VACUUM is running on a worker thread

    QThread *m_indexThread = nullptr; ///< diacritics rebuild of the FTS index
    QAtomicInt m_indexCancel;
    /// Read by the body-writer thread, so it knows to queue what it indexes
    /// for repair after the swap.
    QAtomicInt m_indexRebuildActive;
    bool m_indexRebuilding = false;
    int m_indexPercent = 0;

    QThread *m_migrationThread = nullptr;
    QAtomicInt m_migrationCancel;
    bool m_migrationRunning = false;
    QString m_migrationLabel;
    int m_migrationPercent = -1;

    QThread *m_unreadThread = nullptr;  ///< unread-count recount for the sidebar
    bool m_unreadRecountQueued = false; ///< a request arrived while one was running
    QTimer m_unreadDebounce;

    QThread *m_sortPageThread = nullptr; ///< reads one sorted page of the folder
    bool m_sortPagePending = false;      ///< m_sortPage* holds a request not yet run
    QString m_sortPageFolder;
    int m_sortPageColumn = 0;
    bool m_sortPageDescending = true;
    int m_sortPageLimit = 500;
    bool m_sortPageHasAnchor = false; ///< false = first page, true = page after the anchor
    MessageListModel::Header m_sortPageAnchor;
};
