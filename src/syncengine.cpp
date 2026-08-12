// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "syncengine.h"

#include <QLoggingCategory>
#include <QRandomGenerator>

#include <utility>

Q_DECLARE_LOGGING_CATEGORY(logTrace)

// Background-sync pacing. Headers are cheap, bodies move real bandwidth, so
// they are fetched in modest windows with a deliberate pause between windows
// rather than back-to-back. This keeps sustained backfill under the rate/
// bandwidth limits that make servers like Gmail drop the connection. The
// adaptive backoff (backoffBackfill) still layers on top when a server pushes
// back regardless.
static constexpr int kHeaderWindow = 200;   ///< headers fetched per request
/// Bigger for a folder nobody is watching: fewer round trips for the same
/// history, and no one is waiting on any single window of it.
static constexpr int kBackfillFolderWindow = 250;
static constexpr int kHeaderPauseMs = 400;  ///< pause between header windows
static constexpr int kBodyPauseMs = 600;    ///< pause between body-fetch batches

// Throttle backoff: exponential with full jitter, so a server that pushed back
// is not met by every client at the same moment on the way back up.
static constexpr int kBackoffBaseMs = 1000;   ///< 2^1 * 500 → ~1 s first wait
static constexpr int kBackoffCapMs = 64000;   ///< per-attempt ceiling (64 s)
static constexpr int kBackoffJitterMs = 1000; ///< full jitter added on top
static constexpr int kBackoffMaxAttempts = 8; ///< then pause syncing

SyncEngine::SyncEngine(MailStore &store, MessageListModel &messages, FolderModel &folders,
                       QObject *parent)
    : QObject(parent)
    , m_store(store)
    , m_messages(messages)
    , m_folders(folders)
{
    // Idle-time backfill: while the user reads recent mail (or writes one, or
    // does nothing), quietly walk the remaining older header windows and then
    // cache the missing bodies. Headers strictly first, so a freshly added
    // account shows the complete list before any body downloads.
    m_backfillTimer.setSingleShot(true);
    m_backfillTimer.setInterval(4000);
    connect(&m_backfillTimer, &QTimer::timeout, this, &SyncEngine::onBackfillTick);
}

bool SyncEngine::connected() const
{
    return m_backend && m_backend->isConnected();
}

void SyncEngine::onBackfillTick()
{
    if (!connected() || m_searchActive || m_syncPaused)
        return;
    // Whatever the backend needs for work nobody is waiting on may have gone
    // away on its own (Gmail throttling the backfill while leaving the
    // interactive connection up is the usual way). It puts itself back together
    // here; the retry gives that time to land.
    if (!m_backend->ensureBackgroundReady()) {
        m_backfillTimer.start(1000);
        return;
    }
    // Something user-triggered (or a prefetch) is running — retry soon.
    if (busy() || m_headerFetch || m_backend->bodyFetchActive()
        || !m_prefetchQueue.isEmpty()) {
        m_backfillTimer.start(500);
        return;
    }
    if (m_fetchedFromNewest < m_folderMessageCount) {
        m_backfill = true;
        fetchOlderFromServer();
        return;
    }
    if (backfillBodies(m_selectedFolder))
        return;
    // The open folder is completely cached — sync the account's other folders
    // so offline reading and search cover the whole mailbox.
    continueFolderBackfill();
}

void SyncEngine::resetForFolderChange()
{
    m_backfillTimer.stop();
    m_backfill = false;
    m_bodyBackfill = false;
    // A deliberate folder change is a fresh start — un-pause any throttled
    // backfill and clear the backoff so this folder syncs at full pace.
    resetBackfillBackoff();
    // Queued prefetch uids belong to the folder that queued them.
    m_prefetchQueue.clear();
}

void SyncEngine::openSelectedFolder(const QString &folder)
{
    m_selectedFolder = folder;
    // The folder's size and sync position come back on folderOpened(); what the
    // open makes of them is applySelectedFolderOpened(), which is where the
    // reply lands however long the round trip takes.
    m_folderOpenIntent = FolderOpenIntent::Open;
    m_backend->openFolder(folder, m_store.syncState(folder));
}

void SyncEngine::refreshSelectedFolder(const QString &folder)
{
    m_selectedFolder = folder;
    m_folderOpenIntent = FolderOpenIntent::Refresh;
    m_backend->openFolder(folder, m_store.syncState(folder));
}

void SyncEngine::teardown()
{
    m_backfillTimer.stop();
    m_backfill = false;
    m_bodyBackfill = false;
    resetBackfillBackoff();
    m_folderBackfillQueue.clear();
    m_backfillFolder.clear();
    m_backfillOpenPending = false;
    m_folderBackfillPassDone = false;
    m_folderSyncAnnounced = false;
    m_prefetchQueue.clear();
    m_folderOpenIntent = FolderOpenIntent::None;
}

void SyncEngine::setSyncPaused(bool paused)
{
    m_syncPaused = paused;
    if (paused)
        m_backfillTimer.stop();
}

bool SyncEngine::restartFolderPass()
{
    if (!m_folderBackfillPassDone || m_syncPaused)
        return false;
    m_folderBackfillPassDone = false;
    scheduleBackfill(500);
    return true;
}

void SyncEngine::restartFolderQueue()
{
    m_folderBackfillPassDone = false;
    m_folderSyncAnnounced = false;
    m_folderBackfillQueue.clear();
}

void SyncEngine::handleThrottled()
{
    const bool wasFetching = m_backfill || (m_backend && m_backend->bodyFetchActive());
    m_backfill = false;
    if (wasFetching)
        backoffBackfill();
}

void SyncEngine::addPendingHeaders(const QString &folder,
                                   const QList<MessageListModel::Header> &rows)
{
    m_pendingHeaders[folder] += rows;
}

QList<MessageListModel::Header> SyncEngine::takePendingHeaders(const QString &folder)
{
    return m_pendingHeaders.take(folder);
}

bool SyncEngine::handleBackgroundOpenFailure(const QString &message)
{
    if (!m_backfillOpenPending)
        return false;
    // A mailbox deleted or made unreadable since the listing: skip it rather
    // than letting the pass stall on it. Leaving m_backfillFolder set would
    // re-issue the same open on the next tick, forever.
    qWarning() << "mailove: skipping" << m_backfillFolder << "-" << message;
    m_backfillOpenPending = false;
    m_backfillFolder.clear();
    m_backfillFolderCount = -1;
    scheduleBackfill(50);
    return true;
}

int SyncEngine::missingBodiesIn(const QString &folder)
{
    if (folder != m_missingBodiesFolder || m_missingBodies < 0) {
        m_missingBodiesFolder = folder;
        m_missingBodies = m_store.missingBodyCount(folder);
    }
    return m_missingBodies;
}

void SyncEngine::noteBodyStored(const QString &folder)
{
    if (folder == m_missingBodiesFolder && m_missingBodies > 0)
        --m_missingBodies;
}

QString SyncEngine::openFolderSyncStatus(const QString &folder)
{
    if (folder.isEmpty() || folder != m_selectedFolder)
        return {};

    QStringList parts;
    // Header sync: still older messages to pull from the server.
    if (m_folderMessageCount > 0 && m_fetchedFromNewest < m_folderMessageCount) {
        parts << tr("%1 of %2 headers")
                     .arg(m_fetchedFromNewest)
                     .arg(m_folderMessageCount);
    }
    // Body caching: message bodies still to fetch for offline/search.
    const int missingBodies = missingBodiesIn(folder);
    if (missingBodies > 0) {
        parts << (missingBodies == 1
                      ? tr("caching 1 body")
                      : tr("caching %1 bodies").arg(missingBodies));
    }
    if (parts.isEmpty())
        return {};
    // "INBOX — 500 of 1200 headers · caching 42 bodies…"
    return tr("%1 — %2").arg(folder, parts.join(QStringLiteral(" · ")));
}


void SyncEngine::applySelectedFolderOpened(const QString &folder, qint64 messageCount,
                                           bool cacheDropped)
{
    // Full-cache numbers from SQL, not from the (row-limited) preview list —
    // the resume point must account for everything ever fetched. Read here
    // rather than when the open was requested: this is after the sync token
    // has had its say, so a cache the token just invalidated reads as empty
    // instead of as a resume point into rows that no longer exist.
    qint64 maxCachedUid = m_store.maxCachedUid(folder);
    int cachedCount = m_store.cachedHeaderCount(folder);
    if (cacheDropped) {
        m_messages.clear();
        maxCachedUid = 0;
        cachedCount = 0;
    }

    m_folderMessageCount = messageCount;
    m_fetchedFromNewest = 0;
    // (re)watch the newly opened folder for pushed mail
    m_backend->startPush(folder);
    if (messageCount <= 0) {
        Q_EMIT busyRequested(false);
        // Deliberately no breadcrumb. An empty folder is the terminal state of
        // its own open — nothing follows to overwrite it — so this used to sit
        // in the status bar saying something the empty list already says. The
        // trace still records it.
        qCDebug(logTrace, "folder %s is empty", qUtf8Printable(folder));
        return;
    }
    if (cachedCount > 0 && maxCachedUid > 0) {
        // Resume where we left off: fetch only what is newer than the cache
        // and continue the backfill below it.
        fetchNewerThanCache(maxCachedUid, cachedCount);
    } else {
        // Newest 100 messages; older ones on demand.
        requestHeaderWindow(folder, 0, 100, /*append=*/false, /*background=*/false);
    }
}

void SyncEngine::fetchNewerThanCache(qint64 maxCachedUid, int cachedCount)
{
    const QString folder = m_selectedFolder;
    Q_EMIT statusMessage(tr("%1 — checking").arg(folder));
    // "Everything newer than this", not a positional window: after a reconnect
    // the point is to catch up on whatever arrived, and how much that is, is
    // exactly what is not yet known. JMAP answers the same question with
    // Email/changes against the stored sync state.
    m_backend->fetchHeadersSince(
        folder, QString::number(maxCachedUid),
        [this, folder, cachedCount](MailBackend::Error error, const QString &message) {
            const QList<MessageListModel::Header> headers = m_pendingHeaders.take(folder);
            if (error != MailBackend::Error::None) {
                Q_EMIT busyRequested(false);
                Q_EMIT statusMessage(tr("Fetching headers failed"));
                Q_EMIT errorOccurred(message);
                return;
            }
            Q_EMIT busyRequested(false);
            m_store.storeHeaders(folder, headers);
            invalidateMissingBodies();
            Q_EMIT unreadRecountNeeded(); // freshly synced headers change the pills
            // Cache is updated above either way, but the visible list and the
            // backfill cursor belong to whatever folder is open NOW.
            if (folder != m_selectedFolder || m_searchActive)
                return;
            // In a sorted browse the visible list is keyset pages in another
            // order; reloading the newest-first window over it would throw the
            // user's position away. The rows are cached above either way.
            if (!sortedBrowse()) {
                const auto merged = m_store.cachedHeaders(m_selectedFolder);
                if (m_messages.totalCount() > 0) {
                    // Already showing rows — merge, don't reset (see
                    // applyHeadersFetched for the full story: a reset is a
                    // 40–120 ms freeze, and mid-scroll it also throws the
                    // browsed rows away).
                    m_messages.appendHeaders(merged);
                } else {
                    updatePageAnchor(merged);
                    m_messages.setHeaders(merged);
                }
                Q_EMIT folderRefreshed();
            }
            // Cached block + newly fetched mail occupy the top of the mailbox;
            // everything below is still-unfetched history for the backfill.
            m_fetchedFromNewest = qMin(m_folderMessageCount,
                                       qint64(cachedCount) + headers.size());
            if (m_fetchedFromNewest < m_folderMessageCount) {
                Q_EMIT statusMessage(openFolderSyncStatus(m_selectedFolder));
            } else {
                // rowCount is page-limited; report the folder's real size.
                Q_EMIT statusMessage(tr("%1 — %2 cached")
                              .arg(m_selectedFolder)
                              .arg(m_folderMessageCount > 0 ? m_folderMessageCount
                                                            : m_messages.rowCount()));
            }
            scheduleBackfill(); // more headers, or the body-caching phase
        });
}

void SyncEngine::scheduleBackfill(int delayMs)
{
    // The timer tick decides what still needs doing: older header windows
    // first, then missing bodies; it stops arming itself when both are done.
    m_backfillTimer.start(delayMs);
}

void SyncEngine::backoffBackfill()
{
    ++m_backfillAttempt;
    if (m_backfillAttempt > kBackoffMaxAttempts) {
        // Give up retrying for now — the server is persistently pushing back.
        // Sync resumes on the next (re)connect or when the user opens another
        // folder (both reset the attempt counter via resetBackfillBackoff).
        m_syncPaused = true;
        m_backfillTimer.stop();
        Q_EMIT statusMessage(tr("%1 — sync paused (server busy)")
                      .arg(m_selectedFolder.isEmpty() ? tr("Mail")
                                                       : m_selectedFolder));
        qWarning() << "mailove: backfill paused after" << kBackoffMaxAttempts
                   << "throttle/backoff attempts";
        return;
    }
    // Wait = min(2^n * base + full jitter, cap).
    const qint64 exp = qint64(kBackoffBaseMs) << m_backfillAttempt; // 2^n * base
    const int jitter = int(QRandomGenerator::global()->bounded(kBackoffJitterMs + 1));
    const int wait = int(qMin<qint64>(exp + jitter, kBackoffCapMs));
    scheduleBackfill(wait);
}

void SyncEngine::resetBackfillBackoff()
{
    m_backfillAttempt = 0;
    m_syncPaused = false;
}

bool SyncEngine::backfillBodies(const QString &folder)
{
    if (folder.isEmpty())
        return false;
    const auto missing = m_store.uidsWithoutBody(folder, 50);
    if (missing.isEmpty()) {
        if (folder == m_selectedFolder && m_bodyBackfill) {
            m_bodyBackfill = false;
            Q_EMIT statusMessage(tr("%1 — fully synced")
                          .arg(folder));
        }
        return false; // nothing left in this folder
    }
    if (folder == m_selectedFolder)
        m_bodyBackfill = true;
    // Compose with any header-sync progress so this doesn't clobber the
    // "N of M synced" figure while both phases are running.
    const QString composed = openFolderSyncStatus(folder);
    if (!composed.isEmpty()) {
        Q_EMIT statusMessage(composed);
    } else {
        const int remaining = missingBodiesIn(folder);
        Q_EMIT statusMessage(remaining == 1
                      ? tr("%1 — caching 1 body").arg(folder)
                      : tr("%1 — caching %2 bodies").arg(folder).arg(remaining));
    }
    for (qint64 uid : missing) {
        const auto item = qMakePair(folder, uid);
        if (!m_prefetchQueue.contains(item))
            m_prefetchQueue.append(item);
    }
    processPrefetchQueue();
    scheduleBackfill(); // next batch (or the "done" status) on a later tick
    return true;
}

/// Records a folder's sync position. The token is opaque and is now treated as
/// such: it is stored, and handed back to the next openFolder() so the backend
/// can resume from it. Nothing is read into a change.
///
/// It used to mean more than that — a different token cleared the folder's
/// cache, on the reasoning that a mailbox the server regenerated has cached
/// uids that mean nothing. True of IMAP, where the token is UIDVALIDITY. Flatly
/// wrong for JMAP, whose token is a state string that changes every time
/// *anything* in the account is modified: every message that arrived would have
/// discarded the whole folder. Whether a change is bad news is the protocol's
/// business, so the backends now say so outright with folderInvalidated().
void SyncEngine::applySyncToken(const QString &folder, const QString &syncToken)
{
    if (syncToken.isEmpty())
        return; // the backend has no position to offer
    if (syncToken != m_store.syncState(folder))
        m_store.setSyncState(folder, syncToken);
}

/// The backend says everything cached for \a folder is void — an IMAP mailbox
/// regenerated under us, or a JMAP server that can no longer say what changed
/// since our position. Either way the cache cannot be merged into and has to go.
void SyncEngine::applyFolderInvalidated(const QString &folder)
{
    m_store.clearFolder(folder);
    invalidateMissingBodies();
    if (folder != m_selectedFolder || m_searchActive)
        return;
    // The open folder is on screen, so it also has to be re-read rather than
    // left showing rows whose ids no longer name anything.
    m_messages.clear();
    m_fetchedFromNewest = 0;
    requestHeaderWindow(folder, 0, 100, /*append=*/false, /*background=*/false);
}

/// Messages the backend has learned are gone from \a folder — deleted, or moved
/// away, by some other client. Only JMAP can report this; IMAP's open-ended uid
/// fetch has no way to mention what is missing, so an empty account of what
/// vanished never means "nothing did".
void SyncEngine::applyMessagesVanished(const QString &folder, const QStringList &remoteIds)
{
    if (remoteIds.isEmpty())
        return;
    QList<qint64> uids;
    uids.reserve(remoteIds.size());
    for (const QString &remoteId : remoteIds)
        uids.append(m_backend->localKeyFor(remoteId));
    m_store.removeMessages(folder, uids);
    Q_EMIT unreadRecountNeeded();
    if (folder != m_selectedFolder || m_searchActive || sortedBrowse())
        return;
    m_messages.setHeaders(m_store.cachedHeaders(folder));
    Q_EMIT folderRefreshed();
}

/// A folder the backend has opened reported its size and sync token. Both the
/// open folder and the background backfill come through here; which one this
/// answers is the folder plus, for the open one, the intent that asked.
void SyncEngine::applyFolderOpened(const QString &folder, qint64 messageCount,
                                   const QString &syncToken)
{
    if (folder == m_selectedFolder && m_folderOpenIntent != FolderOpenIntent::None) {
        const FolderOpenIntent intent = m_folderOpenIntent;
        m_folderOpenIntent = FolderOpenIntent::None;
        applySyncToken(folder, syncToken);
        // A cache thrown away arrives as folderInvalidated() *before* this,
        // the backend having decided it while opening; applyFolderInvalidated()
        // has then already emptied the folder, so an open here finds no cache
        // to resume from and starts at the newest page of its own accord.
        const bool dropped = m_store.cachedHeaderCount(folder) == 0;
        if (intent == FolderOpenIntent::Open) {
            applySelectedFolderOpened(folder, messageCount, dropped);
            return;
        }
        // A refresh: the rows are already on screen and nobody is waiting on a
        // spinner, so this is a top-up rather than a reload.
        if (messageCount <= 0)
            return;
        m_folderMessageCount = messageCount;
        // Newest few headers; appendHeaders() dedupes and updates in place.
        requestHeaderWindow(folder, 0, 20, /*append=*/true, /*background=*/false);
        return;
    }

    if (folder != m_backfillFolder)
        return;
    m_backfillOpenPending = false;
    applySyncToken(folder, syncToken);
    m_backfillFolderCount = qMax(qint64(0), messageCount);
    // Everything already cached → straight to the body phase.
    if (messageCount <= 0 || m_store.cachedHeaderCount(folder) >= messageCount)
        m_backfillFetchedFromNewest = m_backfillFolderCount;
    scheduleBackfill(50);
}

void SyncEngine::continueFolderBackfill()
{
    if (!connected() || !m_backend->ensureBackgroundReady() || m_folderBackfillPassDone)
        return; // background work waits for its own capacity — never the UI's
    if (m_backfillFolder.isEmpty()) {
        if (m_folderBackfillQueue.isEmpty())
            m_folderBackfillQueue = m_folders.selectableMailBoxes();
        while (!m_folderBackfillQueue.isEmpty()) {
            const QString next = m_folderBackfillQueue.takeFirst();
            if (next != m_selectedFolder) {
                m_backfillFolder = next;
                m_backfillFolderCount = -1; // size unknown until the open below
                m_backfillFetchedFromNewest = 0;
                break;
            }
        }
        if (m_backfillFolder.isEmpty()) {
            // Every folder visited; a new pass starts on the next (re)connect
            // or folder-list refresh.
            m_folderBackfillPassDone = true;
            if (!m_folderSyncAnnounced) {
                m_folderSyncAnnounced = true;
                Q_EMIT statusMessage(tr("All folders synced"));
            }
            return;
        }
    }
    const QString folder = m_backfillFolder;
    if (m_backfillFolderCount < 0) {
        // Fresh folder: learn its size (and sync token) through the backend,
        // which reports both via folderOpened. Flagged as outstanding so a
        // refusal (a mailbox deleted or made unreadable since the listing) is
        // recognised as this pass's and skipped — see the error handler.
        m_backfillOpenPending = true;
        m_backend->openFolder(folder, m_store.syncState(folder));
        return;
    }
    if (m_backfillFetchedFromNewest < m_backfillFolderCount) {
        // Next header window; cache-only — applyFetchedHeaders never touches
        // the visible list for a folder that is not the open one.
        m_backfill = true;
        requestHeaderWindow(folder, m_backfillFetchedFromNewest, kBackfillFolderWindow,
                            /*append=*/true, /*background=*/true);
        return;
    }
    if (!backfillBodies(folder)) {
        // Headers and bodies complete — move on to the next folder.
        m_backfillFolder.clear();
        scheduleBackfill(50);
    }
}

void SyncEngine::updatePageAnchor(const QList<MessageListModel::Header> &page)
{
    if (page.isEmpty()) {
        m_pageDate = 0;
        m_pageUid = 0;
        return;
    }
    // cachedHeaders* returns date DESC — the last row is the oldest shown.
    m_pageDate = page.last().date.toSecsSinceEpoch();
    m_pageUid = page.last().uid;
}

void SyncEngine::loadMoreMessages()
{
    if (m_searchActive)
        return;
    // A sorted browse pages through MailClient::loadMoreMessages() →
    // startSortPage(); this newest-first walk would insert rows into the
    // middle of the sorted list.
    if (sortedBrowse())
        return;
    // Older mail already cached on disk appears instantly, without touching
    // the network; the server is only asked below the end of the cache.
    if (m_pageUid > 0) {
        const auto older =
            m_store.cachedHeadersBefore(m_selectedFolder, m_pageDate, m_pageUid);
        if (!older.isEmpty()) {
            updatePageAnchor(older);
            m_messages.appendHeaders(older);
            return;
        }
    }
    fetchOlderFromServer();
}

bool SyncEngine::loadAllCachedMessages()
{
    // In a sorted browse "everything" means sorting the whole folder into the
    // model at once — by sender that is the folder's slowest query times its
    // size in rows. End-of-list stays paged there.
    if (m_searchActive || sortedBrowse() || m_pageUid <= 0)
        return false;
    // One unlimited query rather than a loop of pages: the folder index
    // already orders these rows, so the cost is in handing them to the model,
    // and doing that once beats doing it eighty times. For a local archive
    // this is the whole folder, and so genuinely the oldest message; for a
    // server account it is as far back as the cache goes — anything older
    // still has to be backfilled before it can be jumped to.
    const auto rest = m_store.cachedHeadersBefore(m_selectedFolder, m_pageDate, m_pageUid, -1);
    if (rest.isEmpty())
        return false;
    updatePageAnchor(rest);
    m_messages.appendHeaders(rest);
    return true;
}

void SyncEngine::setSortOrder(int column, bool descending)
{
    m_sortColumn = column;
    m_sortDescending = descending;
}

bool SyncEngine::applySortedPage(const QList<MessageListModel::Header> &rows, bool replace)
{
    if (m_searchActive || m_selectedFolder.isEmpty())
        return false;
    // The newest-first page anchor is left alone: it belongs to the default
    // window, which reloadWindow() restores when the sorted browse ends.
    if (replace) {
        m_messages.setHeaders(rows);
        return true;
    }
    // Follow-on pages arrive already in list order and sort after everything
    // shown, so this is a run appended at the end — the model's cheap path.
    return m_messages.appendHeaders(rows) > 0;
}

void SyncEngine::reloadWindow()
{
    if (m_searchActive || m_selectedFolder.isEmpty())
        return;
    const auto merged = m_store.cachedHeaders(m_selectedFolder);
    updatePageAnchor(merged);
    m_messages.setHeaders(merged);
}

void SyncEngine::fetchOlderFromServer()
{
    if (!connected() || busy() || m_headerFetch
        || m_fetchedFromNewest >= m_folderMessageCount) {
        m_backfill = false;
        return;
    }
    // Background backfill must not flip the busy state — busy is what makes
    // the UI feel blocked, and nothing user-facing is waiting on this.
    if (!m_backfill)
        Q_EMIT busyRequested(true);
    // Fetch older history in modest windows with a pause between them
    // (scheduleBackfill below) so sustained backfill stays under server rate
    // limits instead of hammering the connection until it drops.
    requestHeaderWindow(m_selectedFolder, m_fetchedFromNewest, kHeaderWindow,
                        /*append=*/true, m_backfill);
}

void SyncEngine::requestHeaderWindow(const QString &folder, qint64 fromNewest, int count,
                                     bool append, bool background)
{
    m_headerFetch = true;
    if (background) {
        // Show header-sync AND body-caching progress together, so the two
        // background phases don't overwrite each other's numbers.
        const QString composed = openFolderSyncStatus(folder);
        Q_EMIT statusMessage(!composed.isEmpty() ? composed
                                      : tr("%1 — fetching headers").arg(folder));
    } else {
        Q_EMIT statusMessage(tr("Fetching headers"));
    }
    m_backend->fetchHeaderWindow(
        folder, int(fromNewest), count, background,
        [this, folder, fromNewest, count, append, background](MailBackend::Error error,
                                                              const QString &message) {
            m_headerFetch = false;
            if (background)
                m_backfill = false;
            else
                Q_EMIT busyRequested(false);
            if (error != MailBackend::Error::None) {
                m_pendingHeaders.remove(folder);
                if (!background) {
                    Q_EMIT statusMessage(tr("Fetching headers failed"));
                    Q_EMIT errorOccurred(message);
                    return;
                }
                // Server pushback (throttling NO/BAD, dropped connection…):
                // retry with growing pauses instead of hammering it. Shedding a
                // connection when the server capped us is the backend's own
                // answer, already applied by the time this runs.
                backoffBackfill();
                return;
            }
            resetBackfillBackoff();
            const qint64 total = (folder == m_selectedFolder) ? m_folderMessageCount
                                                              : m_backfillFolderCount;
            qint64 reached = fromNewest + count;
            if (total > 0)
                reached = qMin(reached, total);
            applyFetchedHeaders(folder, reached, append, background);
        });
}

void SyncEngine::applyFetchedHeaders(const QString &folder, qint64 reachedFromNewest,
                                     bool append, bool background)
{
    const QList<MessageListModel::Header> headers = m_pendingHeaders.take(folder);
    m_store.storeHeaders(folder, headers);
    invalidateMissingBodies();
    Q_EMIT unreadRecountNeeded(); // freshly synced headers change the pills

    // A background pass over a non-open folder: advance that folder's own
    // cursor and keep chaining its windows.
    if (folder != m_selectedFolder && folder == m_backfillFolder) {
        m_backfillFetchedFromNewest = qMax(m_backfillFetchedFromNewest, reachedFromNewest);
        scheduleBackfill(kHeaderPauseMs);
        return;
    }
    // The user may have moved on: results for a folder that is no longer open
    // go to the cache only — never into the visible list or the current
    // folder's backfill cursor.
    if (folder != m_selectedFolder || m_searchActive)
        return;
    // Only ever forwards: a top-window refresh (poll/IDLE) must not make
    // already-fetched history look unfetched again.
    m_fetchedFromNewest = qMax(m_fetchedFromNewest, reachedFromNewest);
    const bool moreHistory = m_fetchedFromNewest < m_folderMessageCount;
    // In a sorted browse none of this window handling touches the list: the
    // fetched rows are cached (that already happened) and the sorted pages
    // read them from there. Wedging newest-first rows into a list held in
    // another order is what put 500-row inserts into its middle — the cursor
    // and status keep updating below either way.
    if (sortedBrowse()) {
        // nothing — visible list is fed by applySortedPage()
    } else if (append) {
        const int added = m_messages.appendHeaders(headers); // dedupes by uid
        if (added == 0 && moreHistory && !background) {
            // This window was already on screen from the cache — keep walking
            // older windows until something new shows up, otherwise the scroll
            // appears "stuck" at the cached tail.
            loadMoreMessages();
            return;
        }
    } else {
        // Union of fresh fetch + everything cached, so previously scrolled-in
        // older messages stay visible across sessions.
        const auto merged = m_store.cachedHeaders(m_selectedFolder);
        if (m_messages.totalCount() > 0) {
            // A background refresh (the poll timer, IDLE, a reconnect) landing
            // as setHeaders() here was a full model reset over a list already
            // showing: every paged-in row thrown away, every delegate rebuilt
            // (a 40–120 ms freeze), the cursor re-found by uid — felt as the
            // list going heavy at whatever moment the refresh landed, and
            // worst mid-scroll, where it also discarded everything paged in.
            // Merging leaves the shown rows and the page anchor alone;
            // refreshed rows update in place and new mail sorts in at the
            // top. Only rows deleted on the server linger until the folder's
            // expunge event or its next open — those come through
            // applyMessagesVanished, not this refresh.
            m_messages.appendHeaders(merged);
        } else {
            updatePageAnchor(merged);
            m_messages.setHeaders(merged);
        }
        Q_EMIT folderRefreshed();
    }
    if (moreHistory) {
        // More history on the server — keep syncing it while nothing else is
        // going on, showing header progress together with any body caching so
        // the two phases don't overwrite each other's numbers.
        Q_EMIT statusMessage(openFolderSyncStatus(m_selectedFolder));
    } else {
        // The visible model is page-limited (cachedHeaders caps at 1000 rows)
        // — the status must report the folder's real size.
        const int total = m_folderMessageCount > 0 ? int(m_folderMessageCount)
                                                   : m_messages.rowCount();
        if (background)
            Q_EMIT statusMessage(tr("%1 — synced, %2 cached").arg(m_selectedFolder).arg(total));
        else
            Q_EMIT statusMessage(tr("%1 — %2 cached").arg(m_selectedFolder).arg(total));
    }
    // Pace the next window: a deliberate pause between windows keeps the
    // sustained fetch rate under server limits (see kHeaderPauseMs). The longer
    // idle pause is only for entering the body-caching phase.
    scheduleBackfill(moreHistory ? kHeaderPauseMs : 500);
}


// Same-folder run of up to 50 queued uids, removed from the queue. One FETCH
// per batch: the server streams the bodies back to back instead of paying a
// full round trip per message.
void SyncEngine::prefetchBody(const QString &folder, qint64 uid)
{
    if (uid < 0 || !connected())
        return;
    const auto item = qMakePair(folder, uid);
    if (m_prefetchQueue.contains(item))
        return;
    if (!m_store.cachedBody(folder, uid).isEmpty())
        return;
    // Newest request first; keep the queue tiny — this is opportunistic.
    // (Trimmed background-backfill entries are re-derived on a later tick.)
    m_prefetchQueue.prepend(item);
    while (m_prefetchQueue.size() > 4)
        m_prefetchQueue.removeLast();
    processPrefetchQueue();
}

/// Takes up to 50 queued uids that share the queue head's folder, as the ids
/// the backend names messages by.
static QStringList takeBodyBatchIds(QList<QPair<QString, qint64>> &queue,
                                    QString *folderOut)
{
    const QString folder = queue.first().first;
    QStringList ids;
    for (int i = 0; i < queue.size() && ids.size() < 50;) {
        if (queue.at(i).first != folder) {
            ++i;
            continue;
        }
        ids.append(QString::number(queue.at(i).second));
        queue.removeAt(i);
    }
    *folderOut = folder;
    return ids;
}

/// Hands the next queued batches to the backend, as many as it has connections
/// free for. Which bodies to fetch is the application's business (the idle
/// backfill and the hover read-ahead fill the queue); how many can stream at
/// once is the protocol's.
void SyncEngine::processPrefetchQueue()
{
    if (m_prefetchQueue.isEmpty() || !connected())
        return;
    // Not "slots" — Qt defines that as a keyword macro.
    int budget = m_backend->freeBodySlots();
    while (budget-- > 0 && !m_prefetchQueue.isEmpty()) {
        QString folder;
        const QStringList ids = takeBodyBatchIds(m_prefetchQueue, &folder);
        m_backend->fetchBodies(folder, ids, [this](MailBackend::Error error,
                                                   const QString &) {
            if (error != MailBackend::Error::None) {
                // The backend has already shed a connection if the server
                // capped us; pausing the loop is what is left to do here.
                backoffBackfill();
                return;
            }
            resetBackfillBackoff();
            processPrefetchQueue();
            // Body backfill: pace the next batch so bulk downloads stay under
            // server bandwidth limits (bodies are far heavier than headers),
            // rather than requesting the next one immediately.
            if (m_prefetchQueue.isEmpty() && !m_backend->bodyFetchActive())
                scheduleBackfill(kBodyPauseMs);
        });
    }
}

