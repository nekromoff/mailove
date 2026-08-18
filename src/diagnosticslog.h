// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QAbstractListModel>
#include <QAtomicInt>
#include <QList>
#include <QMutex>
#include <QString>
#include <QTimer>
#include <QWaitCondition>

class QThread;
class QUrl;

/**
 * Everything the console would have said, kept where someone who only ever
 * runs the GUI can still read it.
 *
 * Two sinks, one source. The message handler in main.cpp hands every line
 * here; this class keeps the most recent 5000 in memory (what Settings shows)
 * and mirrors them to a single file (what survives a crash). Neither ever
 * grows: the model evicts on append, and the file is compacted back to 5000
 * lines whenever it drifts 1000 past that. There is no rotation, no second
 * file and no cleanup job to forget to run — a bounded thing needs no
 * housekeeping.
 *
 * The thread rules matter, because append() is called from every thread the
 * client has — sync sessions, the body writer, the purge and migration
 * workers, the GUI:
 *
 *   - append() only takes a mutex and copies a string. No file I/O, no lock
 *     file, no allocation beyond the line itself. Nothing that logs may ever
 *     wait on a disk, least of all the GUI thread (see the SLOW warnings in
 *     mailstore.cpp, which are what this rule exists to avoid adding to).
 *   - the file is written by one thread of our own, woken by append() and
 *     otherwise batching on a 250 ms tick.
 *   - the model is filled on the GUI thread by a timer that drains the same
 *     way. Rows are only ever inserted and removed from the thread that owns
 *     the views.
 *
 * Nothing here calls qWarning(), on any path, including its own failures: the
 * handler that would receive it is the one that called us. Failures are kept
 * in lastError() and shown in the viewer instead.
 */
class DiagnosticsLog : public QAbstractListModel
{
    Q_OBJECT
    /// Where the mirror is, shown in the viewer so a bug report can name it.
    Q_PROPERTY(QString filePath READ filePath CONSTANT)
    /// Set when the file cannot be written — a full disk, a read-only home,
    /// or another instance holding the lock for longer than we will wait.
    /// The in-memory half keeps working regardless.
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)
    /// Lines the writer never got to, because they arrived faster than the
    /// disk took them. Zero in every normal run; if it is not, the file has a
    /// gap and the reader deserves to know before drawing conclusions.
    Q_PROPERTY(int droppedLines READ droppedLines NOTIFY droppedLinesChanged)
    /// Debug 0, Info 1, Warning 2, Critical 3, Fatal 4. Rows below this are
    /// not in the model at all — hiding delegates would leave their spacing
    /// behind, and a filtered log is mostly hidden rows.
    Q_PROPERTY(int minimumSeverity READ minimumSeverity WRITE setMinimumSeverity
                   NOTIFY minimumSeverityChanged)
    /// Rows the filter is currently hiding, for "showing 41 of 5000".
    Q_PROPERTY(int totalLines READ totalLines NOTIFY totalLinesChanged)
    /// Whether addresses are masked. Applies to what the viewer *shows*, not
    /// only to what it copies: a switch in the window's own header reads as a
    /// statement about the window, and one that quietly meant "later, on the
    /// clipboard" would be read as a promise it was not making. On by
    /// default, because sending this to someone else is why it gets opened.
    Q_PROPERTY(bool redact READ redact WRITE setRedact NOTIFY redactChanged)

public:
    enum Role {
        LineRole = Qt::UserRole + 1, ///< the formatted line, as written to the file
        SeverityRole,                ///< 0..4, as minimumSeverity
        CategoryRole,                ///< logging category, "default" when unset
    };
    Q_ENUM(Role)

    /// The one instance. Deliberately a function-local static: the first
    /// append() can land before main() has built anything, and must not need
    /// an owner to exist yet.
    static DiagnosticsLog &instance();

    /// Called by the message handler, on any thread, for every line that
    /// survives the noise filter. Cheap by contract — see the class note.
    void append(QtMsgType type, const QMessageLogContext &context, const QString &message);

    /// Opens the mirror and starts the writer and the model drain. Called
    /// from main() once there is an event loop; everything logged before then
    /// is already buffered and lands in the first batch.
    void start();
    /// Final flush and join. Called before main() returns, so the last lines
    /// before a clean exit are on disk like every other line.
    void stop();

    QString filePath() const;
    QString lastError() const;
    int droppedLines() const;
    int minimumSeverity() const { return m_minimumSeverity; }
    void setMinimumSeverity(int severity);
    int totalLines() const { return int(m_rows.size()); }
    bool redact() const { return m_redact; }
    void setRedact(bool redact);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    /// The visible rows as one blob, for the clipboard and for Save as.
    /// \a redact runs redactedText() over it first.
    Q_INVOKABLE QString plainText(bool redact) const;
    /// Rows \a first..\a last of what is on screen, inclusive and clamped.
    /// A negative \a first means all of them.
    Q_INVOKABLE QString rangeText(int first, int last, bool redact) const;
    Q_INVOKABLE void copyToClipboard(bool redact) const;
    /// What the mouse selected, or everything when nothing is selected.
    Q_INVOKABLE void copyRange(int first, int last, bool redact) const;
    /// Writes plainText() to \a url. Returns "" on success, else the reason.
    Q_INVOKABLE QString saveTo(const QUrl &url, bool redact) const;
    /// Empties both halves, in memory and on disk. What the user asks for
    /// when they are about to reproduce a bug and want only that in the file.
    Q_INVOKABLE void clear();

    /// Masks the local part of every address and replaces the home directory
    /// with ~. Not a promise of anonymity — subjects, folder names and server
    /// hostnames are still in there, which is why the viewer says so.
    Q_INVOKABLE static QString redactedText(const QString &text);

Q_SIGNALS:
    void lastErrorChanged();
    void droppedLinesChanged();
    void minimumSeverityChanged();
    void totalLinesChanged();
    void redactChanged();

private:
    DiagnosticsLog();
    ~DiagnosticsLog() override;
    Q_DISABLE_COPY_MOVE(DiagnosticsLog)

    struct Entry {
        QString line;
        QString category;
        int severity = 0;
    };

    /// The line that stands in for a collapsed run, built from the last one
    /// accepted. Caller holds the mutex; resets the counter.
    Entry repeatEntry();
    /// Both consumers are fed from append(); each drains its own queue at its
    /// own pace, so a stalled disk cannot hold up the viewer and vice versa.
    void drainToModel();
    void runWriter();
    /// Appends \a batch under the lock file, compacting when the file has
    /// drifted past the high-water mark. Writer thread only.
    void writeBatch(const QList<Entry> &batch);
    /// Re-reads the file and keeps its newest kMaxLines. Caller holds the
    /// lock file.
    void compact();
    /// Empties the file. Writer thread only, on a request from clear().
    void truncateFile();
    void setError(const QString &error);
    /// Recomputes m_view from m_rows. Called when the filter changes.
    void rebuildView();

    // --- shared between every thread (m_mutex) ---------------------------
    mutable QMutex m_mutex;
    QWaitCondition m_wake;
    QList<Entry> m_filePending;
    QList<Entry> m_uiPending;
    /// Repeat collapsing, so a retry storm cannot evict the lines that
    /// explain it. Compared against the last line accepted, not the last
    /// distinct one — "A A A B A" collapses the run, not the return to A.
    QString m_lastLine;
    /// The last line with its long quoted values and URLs blanked — what makes
    /// "same line" and "same line about a different image" both collapsible.
    QString m_lastKey;
    /// False once a run has collected a line that only matches by shape, which
    /// is what decides whether the run can be re-printed or only counted.
    bool m_exactRun = true;
    /// The most recent line a run swallowed, kept whole. A run of exactly two
    /// is not worth summarising — printing the second line costs the same
    /// space as a sentence about it and loses nothing.
    Entry m_swallowed;
    int m_lastSeverity = 0;
    int m_repeats = 0;
    int m_dropped = 0;
    QString m_error;

    // --- GUI thread -------------------------------------------------------
    QList<Entry> m_rows;   ///< newest kMaxLines, oldest first
    QList<int> m_view;     ///< indices into m_rows passing the severity filter
    QTimer m_drainTimer;
    int m_minimumSeverity = 0;
    bool m_redact = true;
    /// Last drop count the property reported, so the signal fires on change
    /// rather than on every tick.
    int m_reportedDropped = 0;

    // --- writer thread ----------------------------------------------------
    QThread *m_writerThread = nullptr;
    QAtomicInt m_writerStop;
    /// Set by clear() on the GUI thread, acted on by the writer: emptying the
    /// file means taking the lock, and nothing that a person clicks may wait
    /// on another process to let go of it.
    QAtomicInt m_truncateRequested;
    QString m_path;
    QString m_lockPath;
    /// Lines currently in the file. Counted once when the writer opens it,
    /// then tracked, so the common append path never reads the file back.
    int m_fileLines = 0;
    bool m_fileCounted = false;
};
