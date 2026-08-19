// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "settingsbackup.h"

#include <QFile>

namespace SettingsBackup
{

bool write(const QString &settingsPath)
{
    QFile now(settingsPath);
    if (!now.open(QIODevice::ReadOnly))
        return false; // no settings yet, or unreadable; the last copy stands
    const QByteArray current = now.readAll();
    // An empty file is what a truncated write leaves behind. Copying it over
    // the spare would destroy the one thing the spare is for.
    if (current.isEmpty())
        return false;

    const QString backupPath = settingsPath + QStringLiteral(".bak");
    const QString temp = backupPath + QStringLiteral(".tmp");
    QFile::remove(temp);
    QFile out(temp);
    if (!out.open(QIODevice::WriteOnly))
        return false;
    const bool whole = out.write(current) == current.size();
    out.close();
    if (!whole) {
        QFile::remove(temp);
        return false;
    }
    QFile::remove(backupPath);
    return QFile::rename(temp, backupPath);
}

}
