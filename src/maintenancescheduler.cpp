// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "maintenancescheduler.h"

#include "mimeutils.h"

#include <QFile>
#include <QLocale>
#include <QLoggingCategory>
#include <QSqlQuery>
#include <QThread>
#include <QTimer>

#include <kmime/message.h>
#include <kmime/util.h>

#include <utility>

/// Defined in mailstore.cpp — the migration trail, on by default.
Q_DECLARE_LOGGING_CATEGORY(logMigrate)

/// The long maintenance jobs. On by default for the same reason as the
/// migration trail: a compaction runs for minutes, holds the user's attention
/// the whole time, happens once in a blue moon, and leaves nothing behind to
/// inspect — so "it froze while reclaiming space" has to be answerable from
/// what is already in the log, not from asking for a repeat of the one thing
/// nobody wants to sit through twice. A handful of lines per run.
Q_LOGGING_CATEGORY(logMaintenance, "mailove.maintenance")

namespace
{
/// Below this, rebuilding the file costs minutes to hand back nothing anyone
/// would notice.
constexpr qint64 kReclaimWorthwhile = 16 * 1024 * 1024;
/// Records that the To-column backfill has nothing left to do, ever.
const QString kRecipientBackfillFlag = QStringLiteral("recipients_backfilled1");
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
    // Cancelled between batches; each batch is committed, so a run cut short
    // simply leaves rows for the next one to find.
    m_migrationCancel.storeRelaxed(1);
    if (m_migrationThread)
        m_migrationThread->wait();
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
    qCInfo(logMaintenance) << "reclaim: requested," << m_store.databaseBytes()
                           << "bytes on disk," << m_store.reclaimableBytes()
                           << "reclaimable";
    m_reclaimTimer.start();
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
    qCInfo(logMaintenance) << "reclaim: writers idle after" << m_reclaimTimer.elapsed()
                           << "ms, compacting";

    const qint64 before = m_store.databaseBytes();
    // Beside the cache, so the rename that puts it in place stays within one
    // filesystem — across one it would be a copy, and not atomic.
    const QString compacted = MailStore::databaseFilePath() + QStringLiteral(".compacting");
    m_vacuumThread = QThread::create([this, before, compacted] {
        QElapsedTimer timer;
        timer.start();
        QString error;
        // Reads the live cache into a new file rather than rewriting it in
        // place. The old VACUUM held the write lock for its whole run, and
        // every statement the GUI thread issued in the meantime sat on
        // busy_timeout — 15 seconds each — which is what "the whole app is
        // frozen" was. Nothing waits on this one.
        const bool ok = MailStore::vacuumInto(compacted, &error);
        const qint64 ms = timer.elapsed();
        // Back to the GUI thread before touching any state it owns — and the
        // swap itself must happen there, because it closes and reopens the
        // connection the GUI thread reads through.
        QMetaObject::invokeMethod(this, [this, ok, error, before, ms, compacted] {
            QString swapError = error;
            bool done = ok;
            if (ok) {
                qCInfo(logMaintenance) << "reclaim: compacted in" << ms << "ms, swapping in";
                done = m_store.swapInCompacted(compacted, &swapError);
            }
            QFile::remove(compacted); // a no-op once the rename has moved it
            m_reclaiming = false;
            Q_EMIT reclaimingChanged();
            m_reindexTimer.start();
            Q_EMIT syncResumeRequested();
            startAttachmentMigration();
            if (!done) {
                qCWarning(logMaintenance) << "reclaim: failed:" << swapError;
                Q_EMIT errorOccurred(tr("Reclaiming disk space failed: %1").arg(swapError));
                return;
            }
            const qint64 freed = before - m_store.databaseBytes();
            qCInfo(logMaintenance) << "reclaim: done in" << m_reclaimTimer.elapsed()
                                   << "ms, freed" << freed << "bytes";
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
                qWarning() << "mailove: attachment migration skipped a message —" << reason;
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

// --- one-time migrations ---------------------------------------------------

namespace
{
/// "about 3 minutes left", from milliseconds. Deliberately coarse: the estimate
/// is a measured rate extrapolated over work that is not uniform — bodies vary
/// in size, folders in length — so a figure to the second would be claiming a
/// precision it does not have, and would visibly jitter while it did.
QString etaText(qint64 msLeft)
{
    const qint64 secs = msLeft / 1000;
    if (secs < 60)
        return MaintenanceScheduler::tr("less than a minute left");
    const qint64 mins = (secs + 59) / 60; // round up: better long than short
    if (mins < 60)
        return MaintenanceScheduler::tr("about %n minute(s) left", nullptr, int(mins));
    const qint64 hours = (mins + 59) / 60;
    return MaintenanceScheduler::tr("about %n hour(s) left", nullptr, int(hours));
}
}

void MaintenanceScheduler::beginMigration(const QString &label, int step, int stepCount)
{
    m_migrationRunning = true;
    m_migrationLabel = label;
    m_migrationPercent = -1; // indeterminate until the first slice reports
    m_migrationEta.clear();
    m_migrationStep = step;
    m_migrationSteps = stepCount;
    m_migrationClock.start();
    Q_EMIT migrationChanged();
}

void MaintenanceScheduler::reportMigration(int percent)
{
    if (percent == m_migrationPercent)
        return;
    m_migrationPercent = percent;

    // Elapsed against the fraction done. Held back until 2% and a second of
    // work: before that the divisor is small enough that the first slice's
    // start-up cost — a cold page cache, the count query — is most of what is
    // being extrapolated, and the figure swings by minutes between updates.
    if (percent >= 2 && m_migrationClock.isValid() && m_migrationClock.elapsed() > 1000) {
        const qint64 elapsed = m_migrationClock.elapsed();
        m_migrationEta = etaText(elapsed * (100 - percent) / percent);
    }
    Q_EMIT migrationChanged();
}

void MaintenanceScheduler::endMigration()
{
    if (!m_migrationRunning)
        return;
    m_migrationRunning = false;
    m_migrationPercent = 100;
    m_migrationEta.clear();
    m_migrationStep = 0;
    m_migrationSteps = 0;
    m_migrationClock.invalidate();
    Q_EMIT migrationChanged();
}

int MaintenanceScheduler::runRecipientBackfill(
    QSqlDatabase &db, const std::function<bool(const QString &)> &isOutgoing)
{
    if (!isOutgoing)
        return 0;
    // Latched, like every other one-time job. Without this the count below ran
    // on every launch and every account switch — listing all cached folders and
    // counting the missing column in each — to arrive at zero every time. New
    // mail is written with its recipients, so once there is nothing left to
    // backfill there never will be again.
    if (MailStore::workDoneOn(db, kRecipientBackfillFlag))
        return 0;

    // Every account's folders, read from the cache rather than from the folder
    // model: the model holds the open account only, and a migration that runs
    // for one account and silently skips the rest is worse than one that does
    // not run at all — nothing later would notice.
    QStringList scopedFolders;
    const QStringList all = MailStore::allCachedFolderKeysOn(db);
    for (const QString &key : all) {
        if (isOutgoing(key))
            scopedFolders.append(key);
    }
    if (scopedFolders.isEmpty())
        return 0;

    // Counted first so the bar means something. Cheap next to the work itself,
    // and zero is the answer on every run after the first — which is what keeps
    // this from being a startup cost forever.
    int total = 0;
    for (const QString &folder : std::as_const(scopedFolders))
        total += MailStore::missingRecipientCountOn(db, folder);
    if (total == 0) {
        MailStore::markWorkDoneOn(db, kRecipientBackfillFlag);
        return 0;
    }

    QMetaObject::invokeMethod(this, [this] {
        beginMigration(tr("Reading recipients from cached mail"));
    }, Qt::QueuedConnection);

    int done = 0;
    for (const QString &folder : std::as_const(scopedFolders)) {
        while (!m_migrationCancel.loadRelaxed()) {
            const auto rows = MailStore::rawsMissingRecipientsOn(db, folder, 200);
            if (rows.isEmpty())
                break;
            QHash<qint64, QString> byUid;
            byUid.reserve(rows.size());
            for (const auto &row : rows) {
                // Only the head is parsed. A cached body can be megabytes, and
                // every byte after the blank line is irrelevant here — handing
                // the lot to KMime would turn a header read into a full MIME
                // parse tens of thousands of times over.
                QByteArray raw = KMime::CRLFtoLF(row.raw);
                const int blank = raw.indexOf("\n\n");
                if (blank > 0)
                    raw.truncate(blank + 1);
                KMime::Message msg;
                msg.setContent(raw);
                msg.parse();
                byUid.insert(row.uid, msg.to() ? msg.to()->asUnicodeString() : QString());
            }
            MailStore::setRecipientsBatchOn(db, folder, byUid);
            done += rows.size();
            const int percent = int(qMin<qint64>(99, qint64(done) * 100 / total));
            QMetaObject::invokeMethod(this, [this, percent] {
                reportMigration(percent);
            }, Qt::QueuedConnection);
            // The same courtesy every other worker here pays: the user's own
            // writes must not queue behind a migration.
            QThread::msleep(15);
        }
    }
    return done;
}

void MaintenanceScheduler::startCacheMigrations(const QString &account,
                                                std::function<bool(const QString &)> isOutgoing)
{
    if (m_migrationThread)
        return;
    // Asked on the GUI thread, off the store's own connection, before the
    // worker exists: it is a handful of indexed lookups in meta_flags, and the
    // answer decides whether there is any reason to start a thread at all.
    const QList<MailStore::Migration> steps = m_store.pendingMigrations(account);
    // Nothing to migrate and the recipient backfill already latched: no thread,
    // no worker connection, no log line. This is the state every launch after
    // the first upgrade is in, and it was costing ~80 ms of the GUI thread's
    // startup plus a full "migrations pending / finished" trail saying that
    // nothing had happened.
    if (steps.isEmpty() && (!isOutgoing || m_store.workDone(kRecipientBackfillFlag))) {
        Q_EMIT cacheMigrationsFinished();
        return;
    }
    m_migrationCancel.storeRelaxed(0);

    QStringList flags;
    flags.reserve(steps.size());
    for (const MailStore::Migration &step : steps)
        flags.append(step.flag);
    qCInfo(logMigrate) << "cache migrations pending:" << flags;

    // Every background writer pauses for the duration, exactly as it does for a
    // VACUUM and for the same reason: the fts_rowid step holds one write
    // transaction for its whole run — it swaps the search index out, which
    // cannot be done a chunk at a time — so a body write landing mid-migration
    // would sit on busy_timeout and, if that expired, lose a fetched body
    // outright. The others commit per chunk and would only be slowed, but there
    // is no reason to have them competing for the write lock during the one
    // part of the run the user is sitting and watching.
    //
    // Only for the store's steps, though. The To-column backfill below runs on
    // every launch until it is done, holds the lock for one small batch at a
    // time, and is the whole of the work on all but the first launch after an
    // upgrade — pausing the sync for it would be a permanent tax paid for
    // nothing.
    const bool quietWriters = !steps.isEmpty();
    if (quietWriters) {
        Q_EMIT syncPauseRequested();
        m_reindexTimer.stop();
        if (m_bodyWriterThread) {
            // Ask it to stop — which flushes what it holds — but do not join
            // here: a batch mid-statement can run for seconds, and the GUI
            // thread must keep serving the event loop or the modal never
            // paints. It restarts itself on the next queueBodyWrite().
            m_bodyWriterStop.storeRelaxed(1);
            m_bodyWriteWake.wakeAll();
        }
    }

    m_migrationThread = QThread::create([this, steps, account, quietWriters,
                                         isOutgoing = std::move(isOutgoing)] {
        QElapsedTimer runClock;
        runClock.start();
        const QString connection = QStringLiteral("mailstore-migrations");
        QSqlDatabase db = MailStore::openWorkerConnection(connection);
        if (!db.isOpen()) {
            qCWarning(logMigrate) << "cache migrations skipped: no worker connection";
            QMetaObject::invokeMethod(this, [this, quietWriters] {
                if (quietWriters) {
                    m_reindexTimer.start();
                    Q_EMIT syncResumeRequested();
                }
                Q_EMIT cacheMigrationsFinished();
            }, Qt::QueuedConnection);
            return;
        }

        const auto cancelled = [this] { return m_migrationCancel.loadRelaxed() != 0; };
        // The To-column backfill is the last step, but whether it has anything
        // to do is only known once its folders are counted — which is its own
        // first slice. Counting it in the total up front would be wrong
        // whenever it turns out to be a no-op, so the run is numbered over the
        // store's steps and the backfill relabels the modal without a number.
        const int stepCount = int(steps.size());
        int stepIndex = 0;
        for (const MailStore::Migration &step : steps) {
            if (cancelled())
                break;
            ++stepIndex;
            // One modal for the lot, relabelled per step: what changes between
            // them is the sentence, not the fact that the cache is busy.
            QMetaObject::invokeMethod(this, [this, label = step.label, stepIndex, stepCount] {
                beginMigration(label, stepIndex, stepCount);
            }, Qt::QueuedConnection);
            MailStore::runMigration(db, step, account, [this](int percent) {
                QMetaObject::invokeMethod(this, [this, percent] {
                    reportMigration(percent);
                }, Qt::QueuedConnection);
            }, cancelled);
        }

        int recipients = 0;
        if (!cancelled())
            recipients = runRecipientBackfill(db, isOutgoing);

        db.close();
        db = QSqlDatabase(); // drop the handle before removeDatabase warns
        QSqlDatabase::removeDatabase(connection);
        qCInfo(logMigrate).nospace()
            << "cache migrations " << (cancelled() ? "cancelled after " : "finished in ")
            << runClock.elapsed() << " ms, " << recipients << " recipients read";
        QMetaObject::invokeMethod(this, [this, recipients, quietWriters] {
            endMigration();
            // Let the writers back in before anything else: syncing has been
            // held off since before the first step, and the body writer revives
            // on its own once there is something to write.
            if (quietWriters) {
                m_reindexTimer.start();
                Q_EMIT syncResumeRequested();
            }
            if (recipients > 0)
                Q_EMIT statusMessage(tr("Recipients read for %1 cached messages").arg(recipients));
            // No migrationChanged() of its own here: endMigration() above
            // already announced the close when anything had opened the modal,
            // and that announcement is what reloads the list. When nothing ran
            // at all it stays silent — an unconditional emit re-read the
            // folder model and the open folder a few seconds into every
            // launch, to show what it was already showing.
            Q_EMIT cacheMigrationsFinished();
        }, Qt::QueuedConnection);
    });
    connect(m_migrationThread, &QThread::finished, this, [this] {
        m_migrationThread->deleteLater();
        m_migrationThread = nullptr;
    });
    m_migrationThread->start(QThread::LowestPriority);
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
