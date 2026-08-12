// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// Round-trip tests for the content-addressed attachment store. The migration
// rewrites cached messages in place, so "what went in comes back out" has to
// hold for every path — including the deduplicating one, which is where a
// payload written compressed was being reported as raw.

#include "../src/attachmentstore.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QStandardPaths>
#include <QtGlobal>

#include <cstdio>

namespace
{
int failures = 0;

void check(bool ok, const char *what)
{
    std::printf("%s  %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok)
        ++failures;
}

/// Highly compressible: zstd should take this and the codec byte should say so.
QByteArray compressibleData(int size)
{
    QByteArray out;
    while (out.size() < size)
        out += "the quick brown fox jumps over the lazy dog; ";
    return out.left(size);
}

/// Incompressible: a deterministic pseudo-random stream, so the store should
/// decide compression is not worth it and keep the bytes raw.
QByteArray incompressibleData(int size)
{
    QByteArray out;
    QByteArray seed("mailove-seed");
    while (out.size() < size) {
        seed = QCryptographicHash::hash(seed, QCryptographicHash::Sha256);
        out += seed;
    }
    return out.left(size);
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-test"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove-test"));

    // Never touch the real cache.
    const QString root = AttachmentStore::rootDir();
    QDir(root).removeRecursively();

    const QByteArray text = compressibleData(200 * 1024);
    const auto storedText = AttachmentStore::put(text);
    check(!storedText.hash.isEmpty(), "put() returns a hash for compressible data");
    check(storedText.codec == 1, "compressible payload is stored zstd-compressed");
    check(storedText.stored < text.size(), "compressed payload is smaller on disk");
    check(AttachmentStore::get(storedText.hash, storedText.codec) == text,
          "compressible payload round-trips byte for byte");

    const QByteArray blob = incompressibleData(200 * 1024);
    const auto storedBlob = AttachmentStore::put(blob);
    check(storedBlob.codec == 0, "incompressible payload is stored raw");
    check(AttachmentStore::get(storedBlob.hash, storedBlob.codec) == blob,
          "incompressible payload round-trips byte for byte");

    // The regression this suite exists for: storing the same bytes twice used
    // to report codec 0 on the second call, because the early return could not
    // see how the existing file had been written. Reading it back with that
    // codec then handed the caller a zstd frame instead of the payload.
    const auto again = AttachmentStore::put(text);
    check(again.deduplicated, "second put() of identical bytes deduplicates");
    check(again.hash == storedText.hash, "deduplicated put() reports the same hash");
    check(again.codec == storedText.codec,
          "deduplicated put() reports the codec the file was written with");
    check(AttachmentStore::get(again.hash, again.codec) == text,
          "deduplicated payload round-trips byte for byte");

    // A reader that was handed a stale codec must still get the right bytes:
    // the file is authoritative, the column is advisory.
    check(AttachmentStore::get(storedText.hash, 0) == text,
          "wrong codec argument still decodes correctly");

    check(AttachmentStore::contains(storedText.hash), "contains() finds a stored payload");
    check(AttachmentStore::allHashes().size() == 2, "allHashes() lists both payloads");
    check(AttachmentStore::remove(storedText.hash), "remove() deletes a payload");
    check(!AttachmentStore::contains(storedText.hash), "removed payload is gone");
    check(AttachmentStore::get(storedText.hash, 1).isEmpty(),
          "reading a missing payload yields empty, not garbage");

    QDir(root).removeRecursively();
    std::printf("%s\n", failures == 0 ? "all attachment store tests passed"
                                      : "ATTACHMENT STORE TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
