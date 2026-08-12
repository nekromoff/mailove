// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QString>

/**
 * Overwriting decrypted mail before it is freed, and keeping it out of core
 * dumps while it is held.
 *
 * What this is for: a decrypted message lives in memory for as long as it is
 * open (doc/openpgp.md §4 keeps it out of the cache, not out of RAM). Qt's
 * containers free without overwriting, so without this the plaintext stays in
 * the heap until something else happens to reuse those pages.
 *
 * What it is *not*: a guarantee. The limits are spelled out on each function,
 * and the honest summary is that this shortens the window rather than closing
 * it. Closing it properly needs plaintext to live in a buffer type of its own —
 * uniquely owned, mlock'd, wiped on destruction — which is what gpgme does
 * internally and what mailove would have to do to make the same claim.
 */
namespace SecureWipe
{

/// Overwrites \a b and empties it.
///
/// Skips the overwrite when the buffer is shared: Qt containers are
/// copy-on-write, and writing through a shared one detaches first — which
/// would wipe a fresh private copy and leave the bytes everyone else is
/// holding untouched. That failure is invisible and looks like success, so the
/// shared case is dropped rather than faked.
void wipe(QByteArray &b);

/// Same for text. A QString holds UTF-16, so this clears twice the character
/// count in bytes.
void wipe(QString &s);

/// While at least one caller holds decrypted plaintext, the process refuses to
/// dump core.
///
/// A crash runs no destructors, so nothing above can help there; suppressing
/// the dump is the only thing that keeps an open message out of a file on
/// disk. Reference-counted and reversible, so ordinary crashes stay
/// debuggable — the suppression lasts exactly as long as there is something
/// worth protecting.
///
/// Does nothing on platforms without prctl.
void holdPlaintext();
void releasePlaintext();

}
