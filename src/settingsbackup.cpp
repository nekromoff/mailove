// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "settingsbackup.h"

#include <QFile>

namespace SettingsBackup
{

QByteArray snapshot(const QString &settingsPath)
{
    QFile file(settingsPath);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return file.readAll();
}

bool writeIfChanged(const QString &settingsPath, const QByteArray &before)
{
    // Nothing to protect: no file at startup means a first run, and the empty
    // "before" it would save is worse than no backup at all.
    if (before.isEmpty())
        return false;
    QFile now(settingsPath);
    if (!now.open(QIODevice::ReadOnly))
        return false; // the file went away; the last good backup stands
    if (now.readAll() == before)
        return false; // this session changed nothing

    const QString backupPath = settingsPath + QStringLiteral(".bak");
    const QString temp = backupPath + QStringLiteral(".tmp");
    QFile::remove(temp);
    QFile out(temp);
    if (!out.open(QIODevice::WriteOnly))
        return false;
    const bool whole = out.write(before) == before.size();
    out.close();
    if (!whole) {
        QFile::remove(temp);
        return false;
    }
    QFile::remove(backupPath);
    return QFile::rename(temp, backupPath);
}

}
