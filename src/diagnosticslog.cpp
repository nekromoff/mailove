// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "diagnosticslog.h"

#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QLockFile>
#include <QRegularExpression>
#include <QThread>
#include <QUrl>

namespace
{
/// What the model holds and what the file is compacted back to.
constexpr int kMaxLines = 5000;
/// The file may drift this far past kMaxLines before it is rewritten.
/// Compaction is O(file), so it is amortised over the slack rather than paid
/// per line: one rewrite per 1000 lines instead of one per append.
constexpr int kHighWater = 6000;
/// Ceiling on what may be waiting for either consumer. Reached only if a
/// consumer stalls — a disk that stopped answering, or an event loop that
/// has not turned. The oldest go, because in a stall the newest lines are
/// the ones describing it.
constexpr int kPendingCap = kMaxLines;
/// How long the writer sleeps when there is nothing to write. Also the
/// longest a debug line can sit unwritten; warnings and worse wake it.
constexpr int kWriterTickMs = 250;
/// How long to wait for another instance to finish its flush. Long enough to
/// cover a compaction, short enough that we come back and try again rather
/// than holding a batch forever.
constexpr int kLockWaitMs = 2000;

/// The longest a single line may be. A sender picks the length of the URLs in
/// their HTML, and one of the CSP refusals below arrived 1500 characters long
/// — enough for a handful of them to be most of what the buffer holds. The
/// head is what identifies the line; the tail of a very long URL identifies
/// nothing anyone reads.
constexpr int kMaxLineChars = 400;

QString shortened(const QString &line)
{
    if (line.size() <= kMaxLineChars)
        return line;
    return line.left(kMaxLineChars) + QLatin1String(" ...(+")
        + QString::number(line.size() - kMaxLineChars) + QLatin1String(" chars)");
}

/// What two lines have in common when they differ only in a URL or another
/// long quoted value. Bursts in a mail client are shaped this way — one line
/// per blocked image, per skipped message, per refused key — and they are read
/// as "this happened, N times", not as N separate facts.
QString shapeKey(const QString &line)
{
    static const QRegularExpression longValue(
        QStringLiteral("'[^']{24,}'|\"[^\"]{24,}\"|https?://\\S{24,}"));
    QString key = line;
    key.replace(longValue, QStringLiteral("<value>"));
    return key;
}

int severityOf(QtMsgType type)
{
    // Spelled out rather than cast: Qt's enum runs Debug, Warning, Critical,
    // Fatal, Info — Info was added last and sorts where it was added, not
    // where it belongs.
    switch (type) {
    case QtDebugMsg:
        return 0;
    case QtInfoMsg:
        return 1;
    case QtWarningMsg:
        return 2;
    case QtCriticalMsg:
        return 3;
    case QtFatalMsg:
        return 4;
    }
    return 0;
}

QChar severityMark(int severity)
{
    static const char marks[] = {'D', 'I', 'W', 'C', 'F'};
    return QLatin1Char(marks[qBound(0, severity, 4)]);
}
}

DiagnosticsLog &DiagnosticsLog::instance()
{
    static DiagnosticsLog log;
    return log;
}

DiagnosticsLog::DiagnosticsLog()
{
    m_drainTimer.setInterval(200);
    connect(&m_drainTimer, &QTimer::timeout, this, &DiagnosticsLog::drainToModel);
}

DiagnosticsLog::~DiagnosticsLog()
{
    stop();
}

// --- the producing side ----------------------------------------------------

void DiagnosticsLog::append(QtMsgType type, const QMessageLogContext &context,
                            const QString &message)
{
    // Belt and braces. Nothing below logs, but a future edit here that does
    // would recurse forever through the handler that called us, and the stack
    // would say nothing about why.
    static thread_local bool inside = false;
    if (inside)
        return;
    inside = true;

    Entry entry;
    entry.severity = severityOf(type);
    entry.category = context.category && *context.category
        ? QString::fromLatin1(context.category)
        : QStringLiteral("default");
    // One entry, one physical line: the file's line count is what bounds it,
    // and a multi-line SQL error would otherwise count as one line while
    // occupying six. Escaped rather than indented so grep still returns whole
    // messages.
    QString body = message;
    body.replace(QLatin1Char('\n'), QLatin1String("\\n"));
    const QString full = entry.category + QLatin1String(": ") + body;
    const QString tail = shortened(full);
    // Keyed on the whole line, not the truncated one. A URL long enough to be
    // cut loses its closing quote, so the pattern that recognises "the same
    // line with a different value in it" stopped matching exactly on the lines
    // long enough to need collapsing most — three CSP refusals in a row, each
    // naming an image, came out as three lines because the third was cut.
    const QString key = shapeKey(full);

    {
        QMutexLocker locker(&m_mutex);
        // A retry storm repeats one line thousands of times, and left alone it
        // would evict everything that explains it. Collapsed into a count,
        // which is emitted when the run ends.
        // Two ways to be a repeat, and they are reported differently: the
        // same line again is "repeated", a line of the same shape with a
        // different URL in it is "similar". Both are runs the reader wants
        // one entry for; only the first can honestly be re-printed.
        if (tail == m_lastLine) {
            ++m_repeats;
            inside = false;
            return;
        }
        if (!m_lastKey.isEmpty() && key == m_lastKey) {
            ++m_repeats;
            m_exactRun = false;
            entry.line = QDateTime::currentDateTime().toString(
                             QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
                + QLatin1String(" [") + severityMark(entry.severity)
                + QLatin1String("] ") + tail;
            m_swallowed = entry;
            inside = false;
            return;
        }
        if (m_repeats > 0) {
            m_filePending.append(repeatEntry());
            m_uiPending.append(m_filePending.constLast());
        }
        m_lastLine = tail;
        m_lastKey = key;
        m_exactRun = true;
        m_lastSeverity = entry.severity;

        entry.line = QDateTime::currentDateTime().toString(
                         QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
            + QLatin1Char(' ') + QLatin1Char('[') + severityMark(entry.severity)
            + QLatin1String("] ") + tail;
        m_filePending.append(entry);
        m_uiPending.append(entry);

        int lost = 0;
        if (m_filePending.size() > kPendingCap) {
            lost = m_filePending.size() - kPendingCap;
            m_filePending.remove(0, lost);
        }
        if (m_uiPending.size() > kPendingCap)
            m_uiPending.remove(0, m_uiPending.size() - kPendingCap);
        if (lost > 0)
            m_dropped += lost;
        // A warning is the line someone will come looking for after a crash,
        // so it does not wait out the tick. The wake only schedules the write;
        // this thread never touches the disk.
        if (entry.severity >= 2)
            m_wake.wakeAll();
    }
    inside = false;
}

DiagnosticsLog::Entry DiagnosticsLog::repeatEntry()
{
    Entry entry;
    entry.severity = m_lastSeverity;
    entry.category = m_lastLine.left(m_lastLine.indexOf(QLatin1String(": ")));
    const QString stamp = QDateTime::currentDateTime().toString(
        QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    // A run of two is not worth a sentence about itself: the marker exists to
    // stand in for lines that would have buried everything else, and at one
    // suppressed line it is longer than what it replaced and says less. So
    // print the line again, which is what the reader wanted to see.
    if (!m_exactRun && m_repeats == 1) {
        // One line swallowed: print it. A summary of a single line is longer
        // than the line and says less about it.
        Entry only = m_swallowed;
        m_repeats = 0;
        m_exactRun = true;
        m_swallowed = Entry();
        return only;
    }
    if (!m_exactRun) {
        // Not re-printed: the run's lines differ, so repeating the first one
        // with a count on the end would state something untrue about the
        // other nine. Just say how many there were, and of what.
        entry.line = stamp + QLatin1String(" [") + severityMark(entry.severity)
            + QLatin1String("] ") + entry.category + QLatin1String(": ... and ")
            + QString::number(m_repeats) + QLatin1String(" similar lines");
    } else if (m_repeats == 1) {
        entry.line = stamp + QLatin1String(" [") + severityMark(entry.severity)
            + QLatin1String("] ") + m_lastLine;
    } else {
        entry.line = stamp + QLatin1String(" [") + severityMark(entry.severity)
            + QLatin1String("] ") + m_lastLine + QLatin1String("   (repeated ")
            + QString::number(m_repeats) + QLatin1String(" more times)");
    }
    m_repeats = 0;
    m_exactRun = true;
    m_swallowed = Entry();
    return entry;
}

// --- the model side --------------------------------------------------------

int DiagnosticsLog::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : int(m_view.size());
}

QVariant DiagnosticsLog::data(const QModelIndex &index, int role) const
{
    if (index.row() < 0 || index.row() >= m_view.size())
        return {};
    const Entry &entry = m_rows.at(m_view.at(index.row()));
    switch (role) {
    case LineRole:
    case Qt::DisplayRole:
        // Masked here rather than only in plainText(): what is on screen and
        // what lands on the clipboard have to be the same text, or the switch
        // above the list is describing something the reader cannot check.
        // Costs one regex over one line, for the rows actually on screen.
        return m_redact ? redactedText(entry.line) : entry.line;
    case SeverityRole:
        return entry.severity;
    case CategoryRole:
        return entry.category;
    }
    return {};
}

QHash<int, QByteArray> DiagnosticsLog::roleNames() const
{
    return {{LineRole, "line"}, {SeverityRole, "severity"}, {CategoryRole, "category"}};
}

void DiagnosticsLog::setMinimumSeverity(int severity)
{
    severity = qBound(0, severity, 4);
    if (severity == m_minimumSeverity)
        return;
    m_minimumSeverity = severity;
    rebuildView();
    Q_EMIT minimumSeverityChanged();
}

void DiagnosticsLog::setRedact(bool redact)
{
    if (redact == m_redact)
        return;
    m_redact = redact;
    if (!m_view.isEmpty()) {
        Q_EMIT dataChanged(index(0, 0), index(int(m_view.size()) - 1, 0),
                           {LineRole, Qt::DisplayRole});
    }
    Q_EMIT redactChanged();
}

void DiagnosticsLog::rebuildView()
{
    beginResetModel();
    m_view.clear();
    for (int i = 0; i < m_rows.size(); ++i) {
        if (m_rows.at(i).severity >= m_minimumSeverity)
            m_view.append(i);
    }
    endResetModel();
}

void DiagnosticsLog::drainToModel()
{
    QList<Entry> batch;
    int dropped = 0;
    {
        QMutexLocker locker(&m_mutex);
        batch.swap(m_uiPending);
        dropped = m_dropped;
    }
    if (dropped != m_reportedDropped) {
        m_reportedDropped = dropped;
        Q_EMIT droppedLinesChanged();
    }
    if (batch.isEmpty())
        return;

    // Evict first, so the model never briefly holds more than it is allowed
    // to and the insert below lands at a settled end.
    const int over = int(m_rows.size() + batch.size()) - kMaxLines;
    if (over > 0) {
        int goneFromView = 0;
        while (goneFromView < m_view.size() && m_view.at(goneFromView) < over)
            ++goneFromView;
        if (goneFromView > 0) {
            beginRemoveRows(QModelIndex(), 0, goneFromView - 1);
            m_view.remove(0, goneFromView);
            endRemoveRows();
        }
        // The survivors' indices all shift down by what was cut off the front.
        for (int &index : m_view)
            index -= over;
        m_rows.remove(0, over);
    }

    QList<int> added;
    added.reserve(batch.size());
    for (int i = 0; i < batch.size(); ++i) {
        if (batch.at(i).severity >= m_minimumSeverity)
            added.append(int(m_rows.size()) + i);
    }
    if (added.isEmpty()) {
        m_rows += batch;
        Q_EMIT totalLinesChanged();
        return;
    }
    beginInsertRows(QModelIndex(), int(m_view.size()),
                    int(m_view.size() + added.size()) - 1);
    m_rows += batch;
    m_view += added;
    endInsertRows();
    Q_EMIT totalLinesChanged();
}

// --- the file side ---------------------------------------------------------

QString DiagnosticsLog::filePath() const
{
    QMutexLocker locker(&m_mutex);
    return m_path;
}

QString DiagnosticsLog::lastError() const
{
    QMutexLocker locker(&m_mutex);
    return m_error;
}

int DiagnosticsLog::droppedLines() const
{
    QMutexLocker locker(&m_mutex);
    return m_dropped;
}

void DiagnosticsLog::setError(const QString &error)
{
    {
        QMutexLocker locker(&m_mutex);
        if (m_error == error)
            return;
        m_error = error;
    }
    // Queued: this is the writer thread, and the property feeds a binding.
    QMetaObject::invokeMethod(this, [this] { Q_EMIT lastErrorChanged(); },
                              Qt::QueuedConnection);
}

void DiagnosticsLog::start()
{
    if (m_writerThread)
        return;
    // XDG_STATE_HOME, not the cache or the data directory: this is exactly
    // what the spec means by state — useful across restarts, not precious
    // enough to back up, and fine to lose. Qt only grew an enum for it in
    // 6.7, so it is spelled out here.
    QString base = qEnvironmentVariable("XDG_STATE_HOME");
    if (base.isEmpty())
        base = QDir::homePath() + QLatin1String("/.local/state");
    const QString dir = base + QLatin1String("/mailove");
    QDir().mkpath(dir);
    {
        QMutexLocker locker(&m_mutex);
        m_path = dir + QLatin1String("/mailove.log");
        m_lockPath = m_path + QLatin1String(".lock");
    }
    m_drainTimer.start();
    m_writerStop.storeRelaxed(0);
    m_writerThread = QThread::create([this] { runWriter(); });
    m_writerThread->setObjectName(QStringLiteral("mailove-log"));
    m_writerThread->start();
}

void DiagnosticsLog::stop()
{
    m_drainTimer.stop();
    if (!m_writerThread)
        return;
    m_writerStop.storeRelaxed(1);
    m_wake.wakeAll();
    m_writerThread->wait();
    delete m_writerThread;
    m_writerThread = nullptr;
}

void DiagnosticsLog::runWriter()
{
    while (!m_writerStop.loadRelaxed()) {
        if (m_truncateRequested.fetchAndStoreRelaxed(0))
            truncateFile();
        QList<Entry> batch;
        {
            QMutexLocker locker(&m_mutex);
            if (m_filePending.isEmpty()) {
                m_wake.wait(&m_mutex, kWriterTickMs);
                if (m_filePending.isEmpty())
                    continue;
            }
            batch.swap(m_filePending);
        }
        writeBatch(batch);
    }
    // A clean exit writes its own last lines: the shutdown trail is the half
    // of a hang report that says whether the event loop ever returned.
    QList<Entry> rest;
    {
        QMutexLocker locker(&m_mutex);
        rest.swap(m_filePending);
        if (m_repeats > 0)
            rest.append(repeatEntry());
    }
    if (!rest.isEmpty())
        writeBatch(rest);
}

void DiagnosticsLog::writeBatch(const QList<Entry> &batch)
{
    QString path;
    QString lockPath;
    {
        QMutexLocker locker(&m_mutex);
        path = m_path;
        lockPath = m_lockPath;
    }
    if (path.isEmpty())
        return;

    // Held across the whole flush, and across the compaction inside it: two
    // instances appending is harmless, but two instances rewriting the file
    // at once would leave one of them writing into a length that no longer
    // exists. Stale locks time out, so a killed instance cannot wedge this.
    QLockFile lock(lockPath);
    lock.setStaleLockTime(30000);
    if (!lock.tryLock(kLockWaitMs)) {
        // Another instance is busy. Put the batch back rather than lose it —
        // the pending cap is what stops this growing if it never clears.
        QMutexLocker locker(&m_mutex);
        m_filePending = batch + m_filePending;
        if (m_filePending.size() > kPendingCap) {
            const int lost = m_filePending.size() - kPendingCap;
            m_filePending.remove(0, lost);
            m_dropped += lost;
        }
        return;
    }

    // Counted once, under the lock, then tracked: the steady-state append
    // never reads the file back. Re-read if another instance compacted while
    // we were waiting is not needed — it only ever shrinks the file, and an
    // overcount just brings our own next compaction forward.
    if (!m_fileCounted) {
        QFile existing(path);
        if (existing.open(QIODevice::ReadOnly)) {
            const QByteArray all = existing.readAll();
            m_fileLines = int(all.count('\n'));
            existing.close();
        }
        m_fileCounted = true;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
        setError(QStringLiteral("Cannot write %1: %2").arg(path, file.errorString()));
        return;
    }
    // A log nobody else can read: it carries addresses, subjects, folder
    // names and hostnames. Set every time — cheap, and it repairs a file
    // created before this was here.
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);

    QByteArray blob;
    for (const Entry &entry : batch) {
        blob += entry.line.toUtf8();
        blob += '\n';
    }
    const qint64 written = file.write(blob);
    // flush(), not fsync: this reaches the kernel, which is what makes it
    // survive the crash we are logging for. Only a power cut could lose it,
    // and paying 1-10 ms of disk latency per batch to cover that would buy
    // nothing a mail client needs.
    file.flush();
    file.close();
    if (written != blob.size()) {
        setError(QStringLiteral("Short write to %1: %2").arg(path, file.errorString()));
        return;
    }
    setError(QString());
    m_fileLines += int(batch.size());
    if (m_fileLines > kHighWater)
        compact();
}

void DiagnosticsLog::compact()
{
    QString path;
    {
        QMutexLocker locker(&m_mutex);
        path = m_path;
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        setError(QStringLiteral("Cannot compact %1: %2").arg(path, file.errorString()));
        return;
    }
    const QByteArray all = file.readAll();
    file.close();

    QList<QByteArray> lines = all.split('\n');
    // split() leaves an empty tail after the final newline.
    if (!lines.isEmpty() && lines.constLast().isEmpty())
        lines.removeLast();
    if (lines.size() > kMaxLines)
        lines = lines.mid(lines.size() - kMaxLines);

    QByteArray blob;
    blob.reserve(all.size());
    for (const QByteArray &line : lines) {
        blob += line;
        blob += '\n';
    }
    // Truncate in place rather than write-and-rename: another instance may
    // have this path open, and a rename would leave it appending to an
    // unlinked inode nobody will ever read.
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        setError(QStringLiteral("Cannot compact %1: %2").arg(path, file.errorString()));
        return;
    }
    file.write(blob);
    file.flush();
    file.close();
    m_fileLines = int(lines.size());
}

// --- what the viewer asks for ----------------------------------------------

QString DiagnosticsLog::plainText(bool redact) const
{
    return rangeText(-1, -1, redact);
}

QString DiagnosticsLog::rangeText(int first, int last, bool redact) const
{
    if (first < 0) {
        first = 0;
        last = int(m_view.size()) - 1;
    }
    first = qBound(0, first, int(m_view.size()) - 1);
    last = qBound(first, last, int(m_view.size()) - 1);
    QString out;
    for (int row = first; row <= last && row < m_view.size(); ++row) {
        out += m_rows.at(m_view.at(row)).line;
        out += QLatin1Char('\n');
    }
    return redact ? redactedText(out) : out;
}

void DiagnosticsLog::copyToClipboard(bool redact) const
{
    copyRange(-1, -1, redact);
}

void DiagnosticsLog::copyRange(int first, int last, bool redact) const
{
    if (QClipboard *clipboard = QGuiApplication::clipboard())
        clipboard->setText(rangeText(first, last, redact));
}

QString DiagnosticsLog::saveTo(const QUrl &url, bool redact) const
{
    const QString path = url.isLocalFile() ? url.toLocalFile() : url.toString();
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return file.errorString();
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    const QByteArray blob = plainText(redact).toUtf8();
    if (file.write(blob) != blob.size())
        return file.errorString();
    return QString();
}

void DiagnosticsLog::clear()
{
    beginResetModel();
    m_rows.clear();
    m_view.clear();
    endResetModel();
    Q_EMIT totalLinesChanged();

    QString path;
    {
        QMutexLocker locker(&m_mutex);
        m_uiPending.clear();
        m_filePending.clear();
        m_lastLine.clear();
        m_lastKey.clear();
        m_repeats = 0;
        m_exactRun = true;
        m_dropped = 0;
        path = m_path;
    }
    Q_EMIT droppedLinesChanged();
    m_reportedDropped = 0;
    if (path.isEmpty())
        return;
    // Handed to the writer rather than done here: emptying the file means
    // taking the lock file, and a click must never wait on another instance
    // to let go of it. It is emptied within a tick, and nothing written in
    // between survives it — the writer's queue was dropped above.
    m_truncateRequested.storeRelaxed(1);
    m_wake.wakeAll();
}

void DiagnosticsLog::truncateFile()
{
    QString path;
    QString lockPath;
    {
        QMutexLocker locker(&m_mutex);
        path = m_path;
        lockPath = m_lockPath;
    }
    if (path.isEmpty())
        return;
    QLockFile lock(lockPath);
    lock.setStaleLockTime(30000);
    if (!lock.tryLock(kLockWaitMs))
        return;
    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        file.close();
    m_fileLines = 0;
    m_fileCounted = true;
}

QString DiagnosticsLog::redactedText(const QString &text)
{
    QString out = text;
    // The local part is the identifying half; the domain is what makes a
    // report readable ("it fails on gmail.com"). Deliberately not a promise
    // of anonymity — the viewer says as much next to the switch.
    static const QRegularExpression address(
        QStringLiteral("[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})"));
    out.replace(address, QStringLiteral("***@\\1"));
    const QString home = QDir::homePath();
    if (!home.isEmpty())
        out.replace(home, QStringLiteral("~"));
    return out;
}
