// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// The settings backup, and the one property that makes it worth having: a
// session that changes nothing must not be able to touch it. A copy taken at
// startup fails exactly when it is needed — four launches after something has
// emptied the colour labels, all four have dutifully backed up the emptied
// file. What is checked here is that the good copy survives those four.

#include "settingsbackup.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>

#include <cstdio>

static int failures = 0;
static void check(bool ok, const QString &what)
{
    std::printf("%s %s\n", ok ? "ok  :" : "FAIL:", qPrintable(what));
    if (!ok)
        ++failures;
}

static void write(const QString &path, const QByteArray &text)
{
    QFile f(path);
    f.open(QIODevice::WriteOnly | QIODevice::Truncate);
    f.write(text);
    f.close();
}

static QByteArray read(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return f.readAll();
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString dir = QDir::tempPath() + QStringLiteral("/mailove-settingsbackuptest");
    QDir(dir).removeRecursively();
    QDir().mkpath(dir);
    const QString conf = dir + QStringLiteral("/mailove.conf");
    const QString bak = conf + QStringLiteral(".bak");

    const QByteArray good = "[ui]\nscaleColor1=#ff0000\nscaleKey1=1\n";

    // A first run with no file yet must not create a backup of nothing.
    check(!SettingsBackup::writeIfChanged(conf, SettingsBackup::snapshot(conf)),
          QStringLiteral("no file, no backup"));
    check(!QFile::exists(bak), QStringLiteral("…and none was written"));

    // A session that changes nothing leaves no backup behind either.
    write(conf, good);
    {
        const QByteArray before = SettingsBackup::snapshot(conf);
        check(!SettingsBackup::writeIfChanged(conf, before),
              QStringLiteral("a session that changes nothing writes no backup"));
        check(!QFile::exists(bak), QStringLiteral("…so there is still none"));
    }

    // The session that does the damage is the one that saves the good copy.
    {
        const QByteArray before = SettingsBackup::snapshot(conf);
        write(conf, "[ui]\nscaleColor1=\nscaleKey1=\n"); // the labels, emptied
        check(SettingsBackup::writeIfChanged(conf, before),
              QStringLiteral("a session that changed the file writes a backup"));
        check(read(bak) == good,
              QStringLiteral("…and the backup holds what was there BEFORE the change"));
    }

    // The point of the whole exercise: launching four more times afterwards
    // must not replace that copy with the damaged file.
    for (int run = 0; run < 4; ++run) {
        const QByteArray before = SettingsBackup::snapshot(conf);
        SettingsBackup::writeIfChanged(conf, before);
    }
    check(read(bak) == good,
          QStringLiteral("four launches after the damage leave the good copy intact"));

    // A later session that changes something legitimately does move it on —
    // the backup is one generation, not an archive.
    {
        const QByteArray before = SettingsBackup::snapshot(conf);
        write(conf, "[ui]\nscaleColor1=#00ff00\n");
        check(SettingsBackup::writeIfChanged(conf, before),
              QStringLiteral("a later change writes a new backup"));
        check(read(bak) != good && read(bak) == before,
              QStringLiteral("…of the state before that change"));
    }

    std::printf("%s\n", failures == 0 ? "all checks passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
