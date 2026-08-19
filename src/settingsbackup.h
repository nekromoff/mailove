// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QString>

/**
 * One copy of the settings file, taken as the client shuts down.
 *
 * Everything a user configures by hand and cannot get back in a minute lives in
 * one file: the colour labels and their keys, every shortcut binding, the
 * layout. This is the spare copy of it, and nothing more than that.
 *
 * It is written at exit, from the file as it then stands, and it is never read.
 * Mailove does not restore from it, does not compare against it, and will not
 * put it back over the settings file for any reason — a backup that can write
 * itself into the live config is one more thing that can empty it. Putting it
 * back is a deliberate act by the user, with a file manager: edit
 * "mailove.conf.bak", or rename it over "mailove.conf" while the client is
 * closed.
 *
 * Not a substitute for backing up a home directory: a process that is killed
 * outright never reaches its exit, so the copy is only as current as the last
 * session that ended normally.
 */
namespace SettingsBackup
{
/// Copies \a settingsPath to "<settingsPath>.bak". Returns true when a backup
/// was written. Written through a temporary and renamed, so an interrupted
/// write cannot leave a half-file where the good copy was; an absent or empty
/// settings file writes nothing, leaving the last good copy alone rather than
/// replacing it with nothing.
bool write(const QString &settingsPath);
}
