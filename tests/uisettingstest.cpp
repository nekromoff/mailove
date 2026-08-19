// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// The bug this class exists for: hand-picked colour labels kept coming back
// empty. QML's Settings type holds every key in its category from startup and
// rewrites all of them on any one change, so a colour written to the file by
// anything else — a second Mailove, an editor — was reverted the next time the
// window touched an unrelated setting. What is checked here is that a write is
// one key deep, that a key this build does not know is never disturbed, and
// that a change made in the file underneath a running client is picked up
// rather than overwritten.

#include "uisettings.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSettings>
#include <QStandardPaths>

#include <cstdio>

static int failures = 0;
static void check(bool ok, const QString &what)
{
    std::printf("%s %s\n", ok ? "ok  :" : "FAIL:", qPrintable(what));
    if (!ok)
        ++failures;
}

/// The file the settings actually live in, as QSettings decides it.
static QString confPath()
{
    return QSettings(QStringLiteral("mailove"), QStringLiteral("mailove")).fileName();
}

/// Writes the file behind the client's back, the way a second instance or an
/// editor would.
static void writeBehindItsBack(const QByteArray &text)
{
    QFile f(confPath());
    f.open(QIODevice::WriteOnly | QIODevice::Truncate);
    f.write(text);
    f.close();
}

static QByteArray fileNow()
{
    QFile f(confPath());
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return f.readAll();
}

int main(int argc, char **argv)
{
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication::setOrganizationName(QStringLiteral("mailove"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove"));
    QCoreApplication app(argc, argv);
    QFile::remove(confPath());
    QDir().mkpath(QFileInfo(confPath()).absolutePath());

    // A file with a colour already picked, plus a key from some other build
    // that this one has never heard of.
    writeBehindItsBack("[ui]\nscaleColor1=#ff0000\nsomeFutureKey=keepme\n");

    UiSettings ui;
    check(ui.value(QStringLiteral("scaleColor1")).toString() == QStringLiteral("#ff0000"),
          QStringLiteral("a stored colour is read back"));
    check(ui.value(QStringLiteral("rowDensity")).toInt() == 1,
          QStringLiteral("an unstored key falls back to its default"));
    check(ui.value(QStringLiteral("sortDescending")).toBool(),
          QStringLiteral("a bool default survives the trip through INI"));

    // The clobber, exactly: change something unrelated and see whether the
    // colour is still there afterwards.
    ui.setProperty("rowDensity", 2); // the QML-side write, which is what persists
    check(fileNow().contains("scaleColor1=#ff0000"),
          QStringLiteral("writing one setting leaves another one alone"));
    check(fileNow().contains("someFutureKey=keepme"),
          QStringLiteral("…and leaves a key this build does not know alone"));
    check(QSettings(QStringLiteral("mailove"), QStringLiteral("mailove"))
                  .value(QStringLiteral("ui/rowDensity")).toInt() == 2,
          QStringLiteral("…and the setting written is on disk at once"));

    // A colour picked in the window reaches the file without waiting for exit.
    ui.setProperty("scaleColor2", QStringLiteral("#00ff00"));
    check(fileNow().contains("scaleColor2=#00ff00"),
          QStringLiteral("a picked colour is on disk before the client quits"));

    // The file changes underneath a running client: picked up, not reverted.
    writeBehindItsBack("[ui]\nscaleColor1=#0000ff\nrowDensity=2\nscaleColor2=#00ff00\n");
    // The watcher is asynchronous; give it the event loop it needs.
    for (int i = 0; i < 50
             && ui.value(QStringLiteral("scaleColor1")).toString() != QStringLiteral("#0000ff");
         ++i)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    check(ui.value(QStringLiteral("scaleColor1")).toString() == QStringLiteral("#0000ff"),
          QStringLiteral("a colour changed in the file underneath is picked up"));

    // …and the next write does not carry the stale value back out.
    ui.setProperty("rowDensity", 0);
    check(fileNow().contains("scaleColor1=#0000ff"),
          QStringLiteral("…and the next write does not revert it"));

    std::printf("%s\n", failures == 0 ? "all checks passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
