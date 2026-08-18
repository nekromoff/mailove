// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QString>

/**
 * One copy of the settings file, kept from before the session that changed it.
 *
 * Everything a user configures by hand and cannot get back in a minute lives in
 * one file: the colour labels and their keys, every shortcut binding, the
 * layout. One bad write empties it.
 *
 * The rule is "on change, at exit, and nowhere else", and the second half is
 * what makes it worth having. A backup taken at startup is useless: run the
 * client four more times after something has emptied the labels and all four
 * launches faithfully back up the emptied file. What has to survive is the
 * state *before* the change — so the file is read into memory at startup and
 * written out only if this session left the file different from how it found
 * it. A session that changes nothing cannot touch the backup.
 *
 * Not a substitute for backing up a home directory: a process that is killed
 * outright never reaches its exit, so the copy is only as current as the last
 * session that ended normally.
 */
namespace SettingsBackup
{
/// The file's contents, or empty when there is no file to protect yet.
QByteArray snapshot(const QString &settingsPath);

/// Writes \a before to "<settingsPath>.bak" when the file now differs from it.
/// Returns true when a backup was written. Written through a temporary and
/// renamed, so an interrupted write cannot leave a half-file where the good
/// copy was.
bool writeIfChanged(const QString &settingsPath, const QByteArray &before);
}
