// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// The settings backup: a spare copy of the settings file, taken at exit, that
// the client itself never reads. What is checked here is that it copies what
// is actually there, that it refuses to replace a good copy with an empty or
// missing file, and that writing it leaves the settings file untouched — the
// backup is the user's to restore by hand, and never writes back on its own.

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

    // A first run with no file yet has nothing to copy.
    check(!SettingsBackup::write(conf), QStringLiteral("no file, no backup"));
    check(!QFile::exists(bak), QStringLiteral("…and none was written"));

    // The ordinary case: the file as it stands at exit.
    write(conf, good);
    check(SettingsBackup::write(conf), QStringLiteral("a settings file is copied"));
    check(read(bak) == good, QStringLiteral("…exactly as it stands"));
    check(read(conf) == good, QStringLiteral("…and the settings file is left alone"));

    // Later runs move the copy on: it is one generation, not an archive.
    write(conf, "[ui]\nscaleColor1=#00ff00\n");
    check(SettingsBackup::write(conf), QStringLiteral("a later run copies the newer file"));
    check(read(bak) == read(conf), QStringLiteral("…so the copy follows the settings"));

    // An emptied file is what a truncated write leaves behind. Copying it over
    // the spare would destroy the one thing the spare is for.
    const QByteArray keep = read(bak);
    write(conf, "");
    check(!SettingsBackup::write(conf), QStringLiteral("an empty settings file is not copied"));
    check(read(bak) == keep, QStringLiteral("…so the last good copy stands"));

    // Nothing here restores: the backup never writes back into the settings.
    check(read(conf).isEmpty(),
          QStringLiteral("the backup does not put itself back over the settings"));

    std::printf("%s\n", failures == 0 ? "all checks passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
