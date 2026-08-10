// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "maintenancescheduler.h"

#include "mimeutils.h"

#include <QLocale>
#include <QSqlQuery>
#include <QThread>
#include <QTimer>

#include <kmime/message.h>
#include <kmime/util.h>

#include <utility>

namespace
{
/// Below this, rebuilding the file costs minutes to hand back nothing anyone
/// would notice.
constexpr qint64 kReclaimWorthwhile = 16 * 1024 * 1024;
}

MaintenanceScheduler::MaintenanceScheduler(MailStore &store,
                                           std::function<QString(KMime::Message *)> indexText,
                                           std::function<QStringList()> accountKeys,
                                           QObject *parent)
    : QObject(parent)
    , m_store(store)
    , m_indexText(std::move(indexText))
    , m_accountKeys(std::move(accountKeys))
{
    // Search-index repair: cached bodies queued for re-indexing (after an FTS
    // rebuild) are processed a couple at a time so the GUI thread never
    // stalls; the timer stops itself once the queue is empty.
    m_reindexTimer.setInterval(300);
    connect(&m_reindexTimer, &QTimer::timeout, this,
            &MaintenanceScheduler::reindexPendingBodies);
}

MaintenanceScheduler::~MaintenanceScheduler()
{
    stopBodyWriter();
    stopAllMailPurge();
    stopFolderOps();
    stopAttachmentMigration();
    // Cancelled between slices, never mid-slice: the cursor is committed with
    // each one, so the next run picks up where this leaves off.
    stopIndexRebuild();
    if (m_reindexThread)
        m_reindexThread->wait();
    if (m_unreadThread)
        m_unreadThread->wait();
    m_sortPagePending = false; // nothing may start a new worker from here on
    if (m_sortPageThread)
        m_sortPageThread->wait();
    // A vacuum cannot be interrupted; joining is the only safe option, and it
    // is why the UI warns before starting one.
    if (m_vacuumThread)
        m_vacuumThread->wait();
}

// --- body writer ----------------------------------------------------------

void MaintenanceScheduler::queueBodyWrite(MailStore::BodyWrite &&write)
{
    {
        QMutexLocker lock(&m_bodyWriteMutex);
        m_bodyWriteQueue.append(std::move(write));
    }
    if (!m_bodyWriterThread) {
        m_bodyWriterStop.storeRelaxed(0);
        m_bodyWriterThread = QThread::create([this] { runBodyWriter(); });
        // Priority goes to start(): setPriority() on a thread that is not
        // running yet does nothing but warn ("Cannot set priority").
        m_bodyWriterThread->start(QThread::LowPriority);
    }
    m_bodyWriteWake.wakeOne();
}

void MaintenanceScheduler::runBodyWriter()
{
    QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("mailstore-bodies"));
    while (!m_bodyWriterStop.loadRelaxed()) {
        QList<MailStore::BodyWrite> batch;
        {
            QMutexLocker lock(&m_bodyWriteMutex);
            if (m_bodyWriteQueue.isEmpty()) {
                // 500 ms so a stop request is noticed promptly even when idle.
                m_bodyWriteWake.wait(&m_bodyWriteMutex, 500);
                if (m_bodyWriteQueue.isEmpty())
                    continue;
            }
            // Whatever has piled up goes in one transaction, capped so a burst
            // never builds an unbounded write.
            const int take = qMin(m_bodyWriteQueue.size(), 25);
            batch = m_bodyWriteQueue.mid(0, take);
            m_bodyWriteQueue.remove(0, take);
        }
        // Lift the attachments out here rather than at queue time: hashing,
        // compressing and writing a payload file is exactly the kind of work
        // the GUI thread must never do. Parsing a private copy also keeps the
        // caller's message object (which may be on screen) untouched.
        for (MailStore::BodyWrite &w : batch) {
            KMime::Message copy;
            copy.setContent(KMime::CRLFtoLF(w.raw));
            copy.parse();
            w.parts = MimeUtils::stripAttachments(&copy);
            if (!w.parts.isEmpty()) {
                copy.assemble();
                w.raw = copy.encodedContent();
            }
        }
        MailStore::writeBodiesOn(db, batch);
        // A body indexed while the folded index is being built lands in the old
        // table, and the copy may already be past that row — so queue it for
        // the background re-indexer, which runs after the swap and heals it.
        if (m_indexRebuildActive.loadRelaxed())
            MailStore::queueForReindex(db, batch);
    }
    // Flush whatever is left so a quit does not lose fetched bodies.
    QList<MailStore::BodyWrite> rest;
    {
        QMutexLocker lock(&m_bodyWriteMutex);
        rest.swap(m_bodyWriteQueue);
    }
    MailStore::writeBodiesOn(db, rest);
    db.close();
    // Drop the handle before removeDatabase — a live one is "still in use"
    // to Qt and the removal warns at shutdown (same rule as the scoped
    // handles in the other workers).
    db = QSqlDatabase();
    QSqlDatabase::removeDatabase(QStringLiteral("mailstore-bodies"));
}

void MaintenanceScheduler::stopBodyWriter()
{
    if (!m_bodyWriterThread)
        return;
    m_bodyWriterStop.storeRelaxed(1);
    m_bodyWriteWake.wakeAll();
    m_bodyWriterThread->wait();
    delete m_bodyWriterThread;
    m_bodyWriterThread = nullptr;
}

// --- vacuum ---------------------------------------------------------------

bool MaintenanceScheduler::reclaimWorthwhile() const
{
    return m_store.reclaimableBytes() >= kReclaimWorthwhile;
}

QString MaintenanceScheduler::cacheSizeText() const
{
    // The cache is two stores now: the database and the attachment files.
    // Reporting only the first would look like mail had gone missing.
    const qint64 db = m_store.databaseBytes();
    const qint64 files = m_store.attachmentBytes();
    const qint64 free = m_store.reclaimableBytes();
    const QLocale loc;
    const QString total = loc.formattedDataSize(db + files);
    if (free < kReclaimWorthwhile)
        return tr("%1 (%2 attachments)").arg(total, loc.formattedDataSize(files));
    return tr("%1 (%2 attachments, %3 reclaimable)")
        .arg(total, loc.formattedDataSize(files), loc.formattedDataSize(free));
}

void MaintenanceScheduler::reclaimDiskSpace()
{
    if (m_reclaiming)
        return;
    m_reclaiming = true;
    Q_EMIT reclaimingChanged();
    // Pause every background writer: VACUUM takes an exclusive lock, and a
    // backfill batch landing mid-rebuild would just block on it.
    Q_EMIT syncPauseRequested();
    m_reindexTimer.stop();
    // Ask the writers to stop, but do NOT join them here. A worker only checks
    // its cancel flag between batches, and a batch mid-statement on a large
    // cache can run for many seconds — joining on the GUI thread blocked the
    // event loop for exactly that long, so the desktop marked the window
    // unresponsive and offered to kill it, all before the "Reclaiming disk
    // space" dialog had had a chance to paint.
    m_purgeCancel.storeRelaxed(1);
    m_migrateCancel.storeRelaxed(1);
    if (m_bodyWriterThread) {
        // The body writer was the one background writer left running through a
        // rebuild: its batches would have sat on busy_timeout for 15 s a piece
        // against the exclusive lock, and any that timed out would have lost a
        // fetched body. Stopping it flushes the queue first.
        m_bodyWriterStop.storeRelaxed(1);
        m_bodyWriteWake.wakeAll();
    }
    Q_EMIT statusMessage(tr("Reclaiming disk space — this can take several minutes"));
    startVacuumWhenWritersIdle();
}

bool MaintenanceScheduler::writersIdle() const
{
    return !m_purgeThread && !m_migrateThread
        && (!m_bodyWriterThread || m_bodyWriterThread->isFinished());
}

/// VACUUM takes an exclusive lock, so every other writer must have finished —
/// not merely been asked to stop — before it starts. Waiting for that by
/// polling keeps the event loop running, which is what lets the modal dialog
/// appear and the window keep answering the compositor.
void MaintenanceScheduler::startVacuumWhenWritersIdle()
{
    if (!writersIdle()) {
        QTimer::singleShot(100, this, [this] { startVacuumWhenWritersIdle(); });
        return;
    }
    stopBodyWriter(); // already finished: joins and deletes immediately

    const qint64 before = m_store.databaseBytes();
    m_vacuumThread = QThread::create([this, before] {
        QString error;
        const bool ok = MailStore::vacuum(&error);
        // Back to the GUI thread before touching any state it owns.
        QMetaObject::invokeMethod(this, [this, ok, error, before] {
            m_reclaiming = false;
            Q_EMIT reclaimingChanged();
            m_reindexTimer.start();
            Q_EMIT syncResumeRequested();
            startAttachmentMigration();
            if (!ok) {
                Q_EMIT errorOccurred(tr("Reclaiming disk space failed: %1").arg(error));
                return;
            }
            const qint64 freed = before - m_store.databaseBytes();
            const QLocale loc;
            Q_EMIT statusMessage(freed > 0
                                     ? tr("Reclaimed %1").arg(loc.formattedDataSize(freed))
                                     : tr("Nothing to reclaim"));
        }, Qt::QueuedConnection);
    });
    connect(m_vacuumThread, &QThread::finished, this, [this] {
        m_vacuumThread->deleteLater();
        m_vacuumThread = nullptr;
    });
    m_vacuumThread->start();
}

// --- attachment migration -------------------------------------------------

/// Walks the existing cache and moves attachment payloads out of the message
/// BLOBs into the content-addressed file store. Runs on a worker thread with
/// its own connection: every message has to be parsed and every payload
/// hashed and compressed, which is far past anything the GUI thread may do.
/// Progress is persisted, so quitting mid-way simply resumes next launch.
void MaintenanceScheduler::startAttachmentMigration()
{
    if (m_migrateThread || m_reclaiming || !m_store.attachmentMigrationPending())
        return;
    m_migrateCancel.storeRelaxed(0);
    m_migrateThread = QThread::create([this] {
        QSqlDatabase db =
            MailStore::openWorkerConnection(QStringLiteral("mailstore-migrate"));
        if (!db.isOpen())
            return;
        qint64 cursor = 0;
        {
            QSqlQuery q(db);
            q.prepare(QStringLiteral(
                "SELECT value FROM meta_values WHERE key = 'attach_migrate_cursor'"));
            if (q.exec() && q.next())
                cursor = q.value(0).toLongLong();
        }
        qint64 saved = 0;
        int done = 0;
        // MIME work lives here, behind a callback, so MailStore stays free of
        // any KMime dependency.
        const auto split = [](const QByteArray &raw, QList<MailStore::PartRef> *parts) {
            KMime::Message msg;
            msg.setContent(KMime::CRLFtoLF(raw));
            msg.parse();
            *parts = MimeUtils::stripAttachments(&msg);
            if (parts->isEmpty())
                return raw;
            msg.assemble();
            const QByteArray stub = msg.encodedContent();
            // The original bytes are about to be overwritten, so prove the
            // stub plus the stored payloads reproduces them first. Anything
            // that fails is simply left inline — a message that stays big is
            // an inconvenience, one that loses its attachment is a bug.
            QString reason;
            if (!MimeUtils::verifyRoundTrip(stub, *parts, &reason)) {
                qWarning() << "mailo: attachment migration skipped a message —" << reason;
                parts->clear();
                return raw;
            }
            return stub;
        };
        while (!m_migrateCancel.loadRelaxed()) {
            const int n = MailStore::migrateAttachmentsChunk(db, cursor, 50, saved, split);
            if (n == 0) {
                MailStore::finishAttachmentMigration(db);
                break;
            }
            done += n;
            const qint64 savedSoFar = saved;
            const int doneSoFar = done;
            if (done % 2000 < 50) {
                QMetaObject::invokeMethod(this, [this, doneSoFar, savedSoFar] {
                    const QLocale loc;
                    Q_EMIT statusMessage(
                        tr("Compacting attachments — %1 messages, %2 saved")
                            .arg(doneSoFar)
                            .arg(loc.formattedDataSize(savedSoFar)));
                }, Qt::QueuedConnection);
            }
            // Yield the write lock so the UI's own writes never queue behind
            // a migration chunk.
            QThread::msleep(25);
        }
        const bool finished = !m_migrateCancel.loadRelaxed();
        const qint64 savedTotal = saved;
        db.close();
        QSqlDatabase::removeDatabase(QStringLiteral("mailstore-migrate"));
        QMetaObject::invokeMethod(this, [this, finished, savedTotal] {
            if (!finished)
                return;
            m_store.sweepOrphanAttachments();
            // Nothing moved means there was nothing to move — an empty or
            // already-migrated cache. Announcing "0 bytes freed" on a first
            // run reported housekeeping the user never asked for and could
            // not act on.
            if (savedTotal <= 0)
                return;
            const QLocale loc;
            // The space is only handed back to the filesystem by a vacuum —
            // deleting from a SQLite table just marks pages reusable.
            Q_EMIT statusMessage(
                tr("Attachments compacted — %1 freed inside the cache; "
                   "use Reclaim disk space in Settings")
                    .arg(loc.formattedDataSize(savedTotal)));
        }, Qt::QueuedConnection);
    });
    connect(m_migrateThread, &QThread::finished, this, [this] {
        m_migrateThread->deleteLater();
        m_migrateThread = nullptr;
    });
    // Priority goes to start(); setPriority() before it only warns.
    m_migrateThread->start(QThread::LowestPriority);
}

void MaintenanceScheduler::stopAttachmentMigration()
{
    if (!m_migrateThread)
        return;
    m_migrateCancel.storeRelaxed(1);
    m_migrateThread->wait();
}

// --- archive purge --------------------------------------------------------

/// Deletes the excluded archive's cached rows on a worker thread. Releasing the
/// blob pages of a ~100 KB body is far too slow to do on the GUI thread, and at
/// 200k messages there is no chunk size that both finishes this decade and
/// stays inside the 20 ms budget — so it runs on its own connection instead,
/// yielding the write lock between small chunks.
void MaintenanceScheduler::startAllMailPurge(const QString &scopedKey)
{
    if (scopedKey.isEmpty() || m_purgeThread || m_reclaiming)
        return;
    m_purgeCancel.storeRelaxed(0);
    m_purgeThread = QThread::create([this, scopedKey] {
        MailStore::purgeFolder(scopedKey, m_purgeCancel, [this](int total) {
            // Status text belongs to the GUI thread.
            QMetaObject::invokeMethod(this, [this, total] {
                m_purgedRows = total;
                if (total % 5000 < 100)
                    Q_EMIT statusMessage(
                        tr("Clearing archive cache — %1 messages").arg(total));
            }, Qt::QueuedConnection);
        });
        QMetaObject::invokeMethod(this, [this] {
            if (!m_purgeCancel.loadRelaxed() && m_purgedRows > 0)
                Q_EMIT statusMessage(
                    tr("Archive cache cleared — reclaim disk space in Settings"));
            m_purgedRows = 0;
        }, Qt::QueuedConnection);
    });
    connect(m_purgeThread, &QThread::finished, this, [this] {
        m_purgeThread->deleteLater();
        m_purgeThread = nullptr;
    });
    // Below the UI's own work: this must never make a folder switch wait.
    m_purgeThread->start(QThread::LowestPriority);
}

/// Stops the purge worker and waits for it, so no connection outlives the
/// object that owns it (and so a vacuum never starts while it still writes).
void MaintenanceScheduler::stopAllMailPurge()
{
    if (!m_purgeThread)
        return;
    m_purgeCancel.storeRelaxed(1);
    m_purgeThread->wait();
}

// --- folder cache maintenance ---------------------------------------------

void MaintenanceScheduler::purgeCachedFolders(const QStringList &scopedKeys)
{
    if (scopedKeys.isEmpty())
        return;
    stopFolderOps();
    // Both purges open a connection under the same name, so they must not run
    // at once. The archive one is restartable and picks up where it stopped on
    // the next connect, so cancelling it here costs nothing.
    stopAllMailPurge();
    m_folderOpCancel.storeRelaxed(0);
    m_folderOpThread = QThread::create([this, scopedKeys] {
        for (const QString &key : scopedKeys) {
            if (m_folderOpCancel.loadRelaxed())
                return;
            // Chunked with a yield between chunks, so the GUI thread never
            // queues behind this for a write lock (see MailStore::purgeFolder).
            MailStore::purgeFolder(key, m_folderOpCancel, {});
        }
    });
    connect(m_folderOpThread, &QThread::finished, this, [this] {
        m_folderOpThread->deleteLater();
        m_folderOpThread = nullptr;
        Q_EMIT folderOpsFinished();
    });
    m_folderOpThread->start(QThread::LowestPriority);
}

void MaintenanceScheduler::renameCachedFolder(const QString &account, const QString &from,
                                              const QString &to, QChar separator,
                                              std::function<void()> done)
{
    stopFolderOps(); // one maintenance worker at a time
    m_folderOpCancel.storeRelaxed(0);
    m_folderOpThread = QThread::create([account, from, to, separator] {
        QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("mailstore-folderop"));
        if (db.isOpen()) {
            MailStore::renameFolderOn(db, account, from, to, separator);
            db.close();
        }
        QSqlDatabase::removeDatabase(QStringLiteral("mailstore-folderop"));
    });
    connect(m_folderOpThread, &QThread::finished, this,
            [this, done = std::move(done)] {
        m_folderOpThread->deleteLater();
        m_folderOpThread = nullptr;
        // Header counts and the missing-body estimate were keyed by the old path.
        Q_EMIT folderOpsFinished();
        if (done)
            done();
    });
    // Below the UI's own work: a folder switch must never wait for this.
    m_folderOpThread->start(QThread::LowestPriority);
}

void MaintenanceScheduler::stopFolderOps()
{
    if (!m_folderOpThread)
        return;
    m_folderOpCancel.storeRelaxed(1);
    m_folderOpThread->wait();
}

// --- search index ----------------------------------------------------------

void MaintenanceScheduler::startReindexTimer()
{
    m_reindexTimer.start();
}

void MaintenanceScheduler::stopReindexTimer()
{
    m_reindexTimer.stop();
}

void MaintenanceScheduler::reindexPendingBodies()
{
    if (m_reindexThread || m_reclaiming)
        return; // a batch is already in flight
    // 10, not more: reading the batch still pulls raw blobs on this thread, so
    // the read itself has to stay inside the frame budget. The win is in the
    // parsing and the single commit, not in a bigger read.
    const auto batch = m_store.pendingBodyIndex(10);
    if (batch.isEmpty()) {
        m_reindexTimer.stop();
        return;
    }
    m_reindexThread = QThread::create([this, batch] {
        QList<std::tuple<QString, qint64, QString>> done;
        done.reserve(batch.size());
        for (const auto &pending : batch) {
            KMime::Message msg;
            msg.setContent(KMime::CRLFtoLF(pending.raw));
            msg.parse();
            done.append({pending.scopedFolder, pending.uid, m_indexText(&msg)});
        }
        // The writes go back to the GUI thread's connection: they are small
        // (no blobs) and keeping one writer avoids lock contention entirely.
        QMetaObject::invokeMethod(this, [this, done] {
            m_store.finishBodyIndexBatch(done);
        }, Qt::QueuedConnection);
    });
    connect(m_reindexThread, &QThread::finished, this, [this] {
        m_reindexThread->deleteLater();
        m_reindexThread = nullptr;
    });
    // Priority goes to start(); setPriority() before it only warns.
    m_reindexThread->start(QThread::LowestPriority);
}

void MaintenanceScheduler::startIndexRebuild()
{
    if (m_indexThread || m_reclaiming || !m_store.ftsNeedsRebuild())
        return;
    m_indexCancel.storeRelaxed(0);
    m_indexRebuildActive.storeRelaxed(1);
    m_indexRebuilding = true;
    m_indexPercent = 0;
    Q_EMIT indexRebuildChanged();

    m_indexThread = QThread::create([this] {
        QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("mailstore-ftsdia"));
        if (!db.isOpen())
            return;
        bool ok = MailStore::beginFtsRebuild(db);
        const qint64 total = qMax<qint64>(1, MailStore::indexedMessageCount(db));
        qint64 cursor = MailStore::ftsRebuildCursor(db);
        qint64 copied = 0;
        while (ok && !m_indexCancel.loadRelaxed()) {
            const int n = MailStore::copyFtsChunk(db, &cursor, 500);
            if (n < 0) {
                ok = false;
                break;
            }
            if (n == 0) {
                ok = MailStore::finishFtsRebuild(db);
                break;
            }
            copied += n;
            const int percent = int(qMin<qint64>(99, copied * 100 / total));
            QMetaObject::invokeMethod(this, [this, percent] {
                if (percent == m_indexPercent)
                    return;
                m_indexPercent = percent;
                Q_EMIT statusMessage(tr("Rebuilding the search index — %1%").arg(percent));
                Q_EMIT indexRebuildChanged();
            }, Qt::QueuedConnection);
            // Yield the write lock between slices, exactly as the attachment
            // migration does: the user's own writes must never queue behind us.
            QThread::msleep(25);
        }
        const bool finished = ok && !m_indexCancel.loadRelaxed();
        db.close();
        QSqlDatabase::removeDatabase(QStringLiteral("mailstore-ftsdia"));
        m_indexRebuildActive.storeRelaxed(0);
        QMetaObject::invokeMethod(this, [this, finished] {
            m_indexRebuilding = false;
            m_indexPercent = finished ? 100 : 0;
            Q_EMIT indexRebuildChanged();
            if (finished) {
                // The store's own connection still points at the table that was
                // just swapped out; it reopens with the new one on next start.
                Q_EMIT statusMessage(
                    tr("Search index rebuilt — accents are ignored from the next start"));
            }
            Q_EMIT indexRebuildFinished();
        }, Qt::QueuedConnection);
    });
    connect(m_indexThread, &QThread::finished, this, [this] {
        m_indexThread->deleteLater();
        m_indexThread = nullptr;
    });
    m_indexThread->start(QThread::LowestPriority);
}

void MaintenanceScheduler::stopIndexRebuild()
{
    if (!m_indexThread)
        return;
    m_indexCancel.storeRelaxed(1);
    m_indexThread->wait();
}

// --- unread recount --------------------------------------------------------

void MaintenanceScheduler::scheduleUnreadRecount()
{
    if (!m_unreadDebounce.isSingleShot()) {
        m_unreadDebounce.setSingleShot(true);
        // Long enough that reading a run of messages, or a sync landing a
        // batch of headers, collapses into one pass; short enough that the
        // pill still feels like it answers the click.
        m_unreadDebounce.setInterval(700);
        connect(&m_unreadDebounce, &QTimer::timeout, this,
                &MaintenanceScheduler::startUnreadRecount);
    }
    m_unreadDebounce.start();
}

void MaintenanceScheduler::startUnreadRecount()
{
    if (m_unreadThread) {
        m_unreadRecountQueued = true; // re-run once this one lands
        return;
    }
    // Every account, not just the open one: the pane shows the other accounts'
    // cached trees at the same time, and one connection answers for all of them.
    const QStringList accounts = m_accountKeys ? m_accountKeys() : QStringList();
    if (accounts.isEmpty())
        return;

    auto result = std::make_shared<QHash<QString, QHash<QString, int>>>();
    m_unreadThread = QThread::create([accounts, result] {
        // Scoped so the handle is gone before removeDatabase — a live handle
        // is "still in use" to Qt and the removal voids it noisily.
        {
            QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("mailstore-unread"));
            if (db.isOpen()) {
                for (const QString &account : accounts)
                    result->insert(account, MailStore::unreadCountsOn(db, account));
                db.close();
            }
        }
        QSqlDatabase::removeDatabase(QStringLiteral("mailstore-unread"));
    });
    connect(m_unreadThread, &QThread::finished, this, [this, result] {
        m_unreadThread->deleteLater();
        m_unreadThread = nullptr;
        Q_EMIT unreadCountsReady(*result);
        if (m_unreadRecountQueued) {
            m_unreadRecountQueued = false;
            scheduleUnreadRecount();
        }
    });
    // The sidebar is never worth a stutter in the list the user is reading.
    m_unreadThread->start(QThread::LowestPriority);
}

// --- sorted paging ---------------------------------------------------------

void MaintenanceScheduler::startSortPage(const QString &scopedFolder, int column, bool descending,
                                         const MessageListModel::Header *after, int limit)
{
    if (scopedFolder.isEmpty())
        return;
    m_sortPageFolder = scopedFolder;
    m_sortPageColumn = column;
    m_sortPageDescending = descending;
    m_sortPageLimit = limit;
    m_sortPageHasAnchor = after != nullptr;
    if (after)
        m_sortPageAnchor = *after;
    m_sortPagePending = true;
    startSortPageNow();
}

void MaintenanceScheduler::startSortPageNow()
{
    if (m_sortPageThread || !m_sortPagePending)
        return;
    m_sortPagePending = false;
    const QString folder = m_sortPageFolder;
    const int column = m_sortPageColumn;
    const bool descending = m_sortPageDescending;
    const int limit = m_sortPageLimit;
    const bool append = m_sortPageHasAnchor;
    const MessageListModel::Header anchor = m_sortPageAnchor;

    auto rows = std::make_shared<QList<MessageListModel::Header>>();
    m_sortPageThread = QThread::create([folder, column, descending, limit, append, anchor, rows] {
        // Scoped for the same reason as the unread worker: the handle must be
        // gone before removeDatabase.
        {
            QSqlDatabase db =
                MailStore::openWorkerConnection(QStringLiteral("mailstore-sortpage"));
            if (db.isOpen()) {
                *rows = MailStore::sortedHeadersOn(db, folder, column, descending, limit,
                                                   append ? &anchor : nullptr);
                db.close();
            }
        }
        QSqlDatabase::removeDatabase(QStringLiteral("mailstore-sortpage"));
    });
    connect(m_sortPageThread, &QThread::finished, this,
            [this, folder, column, descending, append, rows] {
        m_sortPageThread->deleteLater();
        m_sortPageThread = nullptr;
        // Empty pages are reported too: an empty follow-on page is the end of
        // the cache, and the client stops asking once told.
        Q_EMIT sortPageReady(folder, column, descending, append, *rows);
        // A click that landed while this one ran is what the user is waiting
        // to see, so it goes now.
        startSortPageNow();
    });
    // Normal priority, unlike the recount: the user is scrolling toward the
    // rows this fetches, and at lowest priority the thread is starved by the
    // very scroll activity that made the request — the page then lands only
    // after the scrolling pauses, which is the stall it exists to prevent.
    m_sortPageThread->start(QThread::NormalPriority);
}
