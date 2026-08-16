// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QString>

/**
 * Content-addressed file store for attachment payloads.
 *
 * Attachments used to live base64-encoded inside the message BLOB in SQLite,
 * which cost three ways at once: the encoding inflates every payload by a
 * third, the same file re-appears in full under every folder/label that holds
 * the message, and a 25 MB attachment turns into a 34 MB row that every
 * scan of the table has to walk past.
 *
 * Here a payload is stored once, decoded, keyed by the SHA-256 of its bytes:
 *
 *     <AppDataLocation>/attachments/ab/abcdef0123…
 *
 * Identical payloads collapse onto one file no matter how many messages,
 * folders or accounts reference them, and the reference counting that makes
 * eviction possible lives in the `attachments` table (see MailStore).
 *
 * Files are compressed with zstd when that actually helps — see put(), which
 * samples before committing the CPU. Everything here is pure filesystem work
 * with no database or GUI involvement, so it is safe to call from any thread.
 */
namespace AttachmentStore
{
/// Payloads at or above this go to their own file; smaller parts stay inline
/// in the message stub, where per-file overhead would outweigh the saving.
/// From the advanced-settings schema (attachments/externalizeThresholdBytes),
/// since where that line falls depends on the filesystem underneath.
int externalizeThreshold();

/// Result of storing a payload.
struct Stored {
    QString hash;         ///< SHA-256 (hex) of the decoded bytes; empty on failure
    qint64 size = 0;      ///< decoded size
    qint64 stored = 0;    ///< bytes actually written (after any compression)
    int codec = 0;        ///< 0 = raw, 1 = zstd
    bool deduplicated = false; ///< the payload was already on disk
};

/// Writes \a data (decoded bytes) and returns its content address. Writing the
/// same bytes twice is a no-op that reports the existing file. The write is
/// tmp-file-then-rename, so an interrupted run never leaves a torn payload.
Stored put(const QByteArray &data);

/// Reads back a payload by hash and codec. Empty when the file is missing —
/// callers treat that as "not cached" and re-fetch from the server.
QByteArray get(const QString &hash, int codec);

/// True when the payload is on disk.
bool contains(const QString &hash);

/// Deletes a payload. Only called once its reference count reaches zero.
bool remove(const QString &hash);

/// Absolute path for a hash (does not check existence).
QString pathFor(const QString &hash);

/// Root of the store; created on demand, owner-only like the database.
QString rootDir();

/// Every hash currently on disk — for the orphan sweep that reconciles the
/// filesystem against the `attachments` table after an interrupted run.
QStringList allHashes();
}
