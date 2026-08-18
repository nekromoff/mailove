// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// The log sink: the two bounds that make it safe to leave on forever, and the
// three things the viewer promises. The bounds are the point — a log that can
// grow needs a cleanup job, and a cleanup job is a thing that does not run.
//
//   - the file recycles in place: 5000 lines kept, allowed to drift to 6000
//     before it is rewritten, and never one line more
//   - the model holds 5000 and evicts the oldest
//   - a repeated line collapses into a count, so a retry storm cannot push
//     out what explains it
//   - the severity filter, the redaction, and Clear emptying both halves
//
// Runs against a throwaway XDG_STATE_HOME, so it never touches a real log.

#include "diagnosticslog.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QThread>

#include <cstdio>

static int failures = 0;
static void check(bool ok, const QString &what)
{
    std::printf("%s %s\n", ok ? "ok  :" : "FAIL:", qPrintable(what));
    if (!ok)
        ++failures;
}

/// Both consumers are asynchronous by design — see diagnosticslog.h. Spin the
/// event loop (the model's drain) while the writer thread gets its ticks.
static void settle(int ms = 1200)
{
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < ms) {
        QCoreApplication::processEvents();
        QThread::msleep(20);
    }
}

static int fileLines(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return -1;
    return int(file.readAll().count('\n'));
}

/// Straight into the sink, bypassing the handler: this test is about what the
/// sink does with a line, not about which lines reach it.
static void log(QtMsgType type, const char *category, const QString &message)
{
    QMessageLogContext context(nullptr, 0, nullptr, category);
    DiagnosticsLog::instance().append(type, context, message);
}

int main(int argc, char **argv)
{
    const QString sandbox = QDir::tempPath() + QStringLiteral("/mailove-diagnosticslogtest");
    QDir(sandbox).removeRecursively();
    QDir().mkpath(sandbox);
    qputenv("XDG_STATE_HOME", sandbox.toUtf8());

    QCoreApplication app(argc, argv);
    DiagnosticsLog &log_ = DiagnosticsLog::instance();
    log_.start();
    const QString path = log_.filePath();
    std::printf("file: %s\n", qPrintable(path));
    check(path.startsWith(sandbox), "the log lands under XDG_STATE_HOME");

    // --- the bound ---------------------------------------------------------
    // Well past the high-water mark, so the file has been compacted at least
    // twice by the time this finishes.
    for (int i = 0; i < 14000; ++i)
        log(QtWarningMsg, "mailove.test", QStringLiteral("line %1").arg(i));
    settle();

    const int lines = fileLines(path);
    std::printf("file lines: %d\n", lines);
    check(lines > 0 && lines <= 6000, "the file never exceeds the high-water mark");
    check(lines >= 5000, "the file keeps at least the 5000 it promises");
    check(log_.totalLines() == 5000, "the model holds exactly 5000");

    // Newest kept, oldest gone — the opposite would be a log that stops
    // recording the moment it fills up.
    QFile file(path);
    check(file.open(QIODevice::ReadOnly), "the file is readable");
    const QByteArray content = file.readAll();
    file.close();
    check(content.contains("line 13999"), "the newest line survives");
    check(!content.contains("line 0 "), "the oldest lines are gone");
    check(log_.data(log_.index(log_.rowCount() - 1, 0), DiagnosticsLog::LineRole)
              .toString().endsWith(QStringLiteral("line 13999")),
          "the model's last row is the newest line");

    // --- repeat collapsing -------------------------------------------------
    log_.clear();
    settle(600);
    for (int i = 0; i < 500; ++i)
        log(QtWarningMsg, "mailove.test", QStringLiteral("the same complaint"));
    log(QtWarningMsg, "mailove.test", QStringLiteral("something else"));
    settle();
    check(log_.totalLines() == 3,
          QStringLiteral("500 identical lines collapse to 3 rows (got %1)")
              .arg(log_.totalLines()));
    check(log_.plainText(false).contains(QStringLiteral("repeated 499 more times")),
          "the collapsed run says how many it stood for");

    // A run of two collapses to the line printed twice, not to a marker
    // longer than the line it replaced.
    log_.clear();
    settle(600);
    log(QtWarningMsg, "mailove.test", QStringLiteral("said once"));
    log(QtWarningMsg, "mailove.test", QStringLiteral("said once"));
    log(QtWarningMsg, "mailove.test", QStringLiteral("and then something else"));
    settle();
    check(!log_.plainText(false).contains(QStringLiteral("repeated 1")),
          "a single repeat prints the line again instead of counting it");
    check(log_.plainText(false).count(QStringLiteral("said once")) == 2,
          "and it really is printed twice");

    // --- bursts that differ only in a URL ------------------------------
    // The shape a sender controls: one CSP refusal per blocked image, each
    // line identical but for a URL, and the URLs can be a thousand characters
    // long. Left alone, one message's images are most of what the log holds.
    log_.clear();
    settle(600);
    const QString csp = QStringLiteral(
        "viewer js: Refused to load the image '%1' because it violates the "
        "following Content Security Policy directive: \"img-src mailove: data:\"");
    for (int i = 0; i < 11; ++i) {
        log(QtWarningMsg, "qml",
            csp.arg(QStringLiteral("https://lh3.googleusercontent.com/a-/")
                    + QString(60, QLatin1Char('A')) + QString::number(i)));
    }
    log(QtWarningMsg, "qml", QStringLiteral("viewer js: something unrelated"));
    settle();
    check(log_.totalLines() == 3,
          QStringLiteral("11 lines differing only by URL become 2 rows plus the "
                         "next line (got %1)").arg(log_.totalLines()));
    check(log_.plainText(false).contains(QStringLiteral("... and 10 similar lines")),
          "the run is counted rather than re-printed");
    check(log_.plainText(false).contains(QStringLiteral("Refused to load the image")),
          "the first of them is kept in full, so the reader knows what happened");

    // Two of a shape are printed, not summarised — and nothing written to the
    // log may be non-ASCII: it is read in terminals, pasted into issue
    // trackers, and opened by editors that guess the encoding.
    log_.clear();
    settle(600);
    log(QtWarningMsg, "qml", csp.arg(QStringLiteral("https://example.com/") + QString(40, 'a')));
    log(QtWarningMsg, "qml", csp.arg(QStringLiteral("https://example.com/") + QString(40, 'b')));
    log(QtWarningMsg, "qml", QStringLiteral("unrelated"));
    settle();
    check(!log_.plainText(false).contains(QStringLiteral("similar line")),
          "a run of two prints the second line instead of summarising it");
    check(log_.plainText(false).contains(QString(40, QLatin1Char('b'))),
          "and the second line is the one that was swallowed");
    check(log_.plainText(false).toUtf8() == log_.plainText(false).toLatin1(),
          "nothing the log writes is outside ASCII");

    // A burst whose lines are long enough to be truncated still collapses:
    // the shape is read from the whole line, before the cut.
    log_.clear();
    settle(600);
    for (int i = 0; i < 5; ++i) {
        log(QtWarningMsg, "qml",
            csp.arg(QStringLiteral("https://lh3.googleusercontent.com/")
                    + QString(700, QLatin1Char('x')) + QString::number(i)));
    }
    log(QtWarningMsg, "qml", QStringLiteral("done"));
    settle();
    check(log_.totalLines() == 3,
          QStringLiteral("five truncated lines of one shape become 2 rows plus the next "
                         "(got %1)").arg(log_.totalLines()));

    // No single line may be long enough to matter to the buffer's bound.
    log_.clear();
    settle(600);
    log(QtWarningMsg, "qml",
        QStringLiteral("blocked ") + QString(4000, QLatin1Char('u')));
    settle();
    check(log_.plainText(false).size() < 600,
          QStringLiteral("a 4000-character line is truncated (kept %1)")
              .arg(log_.plainText(false).size()));
    check(log_.plainText(false).contains(QStringLiteral("chars)")),
          "and says how much it dropped");

    // --- the severity filter ----------------------------------------------
    log_.clear();
    settle(600);
    log(QtDebugMsg, "mailove.test", QStringLiteral("chatter"));
    log(QtInfoMsg, "mailove.test", QStringLiteral("progress"));
    log(QtWarningMsg, "mailove.test", QStringLiteral("trouble"));
    log(QtCriticalMsg, "mailove.test", QStringLiteral("worse"));
    settle();
    log_.setMinimumSeverity(0);
    check(log_.rowCount() == 4, "everything shows all four");
    log_.setMinimumSeverity(2);
    check(log_.rowCount() == 2, "problems only drops the debug and the info");
    log_.setMinimumSeverity(3);
    check(log_.rowCount() == 1, "errors only keeps the critical");
    check(log_.plainText(false).contains(QStringLiteral("worse")),
          "the copied text is what the filter left, not everything");
    log_.setMinimumSeverity(0);

    // --- redaction ---------------------------------------------------------
    const QString masked = DiagnosticsLog::redactedText(
        QStringLiteral("login failed for alice.smith@example.com on imap.example.com"));
    check(!masked.contains(QStringLiteral("alice.smith")), "the local part is masked");
    check(masked.contains(QStringLiteral("@example.com")),
          "the domain survives, which is what makes a report readable");
    check(masked.contains(QStringLiteral("imap.example.com")),
          "a bare hostname is not mistaken for an address");
    check(!DiagnosticsLog::redactedText(
               QStringLiteral("from no-reply@accounts.google.com"))
               .contains(QStringLiteral("no-reply")),
          "a hyphenated local part is masked whole");

    // What the window shows and what Copy produces have to be the same text:
    // the switch is above the list, so it is read as a statement about the
    // list. This is the check that was missing when it only masked on the way
    // out.
    log_.clear();
    settle(600);
    log(QtWarningMsg, "mailove.test",
        QStringLiteral("remembered remote-content for no-reply@accounts.google.com"));
    settle();
    log_.setRedact(true);
    const QString shown = log_.data(log_.index(0, 0), DiagnosticsLog::LineRole).toString();
    check(!shown.contains(QStringLiteral("no-reply")),
          "the rows on screen are masked, not just the clipboard");
    check(log_.plainText(true) == shown + QStringLiteral("\n"),
          "what is copied is exactly what is shown");
    log_.setRedact(false);
    check(log_.data(log_.index(0, 0), DiagnosticsLog::LineRole).toString()
              .contains(QStringLiteral("no-reply")),
          "switching it off shows the address again");
    log_.setRedact(true);

    // --- Clear -------------------------------------------------------------
    log(QtWarningMsg, "mailove.test", QStringLiteral("before the clear"));
    settle();
    log_.clear();
    settle();
    check(log_.totalLines() == 0, "Clear empties the model");
    check(fileLines(path) == 0, "Clear empties the file too");

    // --- the shutdown flush ------------------------------------------------
    // The last lines before a clean exit are the half of a hang report that
    // says whether the event loop ever came back.
    log(QtWarningMsg, "mailove.test", QStringLiteral("the very last thing"));
    log_.stop();
    check(fileLines(path) >= 1, "stop() flushes what was still queued");

    std::printf("%s\n", failures == 0 ? "all checks passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
