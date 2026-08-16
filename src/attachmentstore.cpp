// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "attachmentstore.h"

#include "advancedconfig.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStandardPaths>

#include <zstd.h>

namespace
{
/// zstd level 3 (its default): most of the ratio of the slower levels at a
/// speed where compressing a mail attachment is not worth measuring.
int kZstdLevel() { return AdvancedConfig::i("attachments/zstdLevel"); }

/// Bytes sampled to decide whether compressing the whole payload is worth it.
int kSampleBytes() { return AdvancedConfig::i("attachments/compressionSampleBytes"); }

/// Every payload file starts with these four bytes: a magic pair, a format
/// version, and the codec. The codec has to live *in the file* rather than
/// only in the database, because a payload can be written once and then
/// referenced by many messages — a later caller that deduplicates against an
/// existing file has no idea how the original was encoded, and would happily
/// record "raw" for a compressed file.
constexpr char kMagic0 = 'M';
constexpr char kMagic1 = 'A';
constexpr char kVersion = '1';
constexpr int kHeaderBytes = 4;

/// Codec recorded in an existing file, or -1 if it is not one of ours.
int codecOfFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return -1;
    const QByteArray head = f.read(kHeaderBytes);
    if (head.size() != kHeaderBytes || head[0] != kMagic0 || head[1] != kMagic1
        || head[2] != kVersion)
        return -1;
    return head[3] - '0';
}

/// Compress only when the sample shrinks at least this much. JPEG/PNG/MP4/ZIP
/// (and so also docx/xlsx/pptx, which are ZIP containers) sit well above it
/// and are stored raw rather than burning CPU to grow them by a few bytes.
double kWorthwhileRatio() { return AdvancedConfig::d("attachments/worthwhileRatio"); }

/// Nothing this store handles legitimately approaches it; the point of the
/// ceiling is that the sizes below stay inside what a qsizetype allocation can
/// actually express, whatever a frame header claims.
unsigned long long kMaxPayloadBytes()
{
    return static_cast<unsigned long long>(AdvancedConfig::i("attachments/maxPayloadBytes"));
}

QByteArray zstdCompress(const QByteArray &in)
{
    const size_t bound = ZSTD_compressBound(size_t(in.size()));
    if (bound > kMaxPayloadBytes())
        return {};
    // qsizetype, never int: QByteArray is 64-bit-sized in Qt 6, and narrowing
    // the length to int here would allocate a buffer smaller than the length
    // handed to zstd alongside it — a heap overflow written by zstd itself.
    QByteArray out(qsizetype(bound), Qt::Uninitialized);
    const size_t n = ZSTD_compress(out.data(), bound, in.constData(), size_t(in.size()),
                                   kZstdLevel());
    if (ZSTD_isError(n))
        return {};
    out.resize(qsizetype(n));
    return out;
}

QByteArray zstdDecompress(const QByteArray &in)
{
    const unsigned long long size =
        ZSTD_getFrameContentSize(in.constData(), size_t(in.size()));
    if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN)
        return {};
    // The frame header states this length; it is not evidence of anything.
    if (size > kMaxPayloadBytes())
        return {};
    QByteArray out(qsizetype(size), Qt::Uninitialized);
    const size_t n = ZSTD_decompress(out.data(), size_t(size), in.constData(),
                                     size_t(in.size()));
    if (ZSTD_isError(n) || n != size)
        return {};
    return out;
}

/// Worth compressing? Judged from a sample so incompressible payloads cost one
/// small compression instead of a full-size one.
bool worthCompressing(const QByteArray &data)
{
    const QByteArray sample = data.left(kSampleBytes());
    const QByteArray probe = zstdCompress(sample);
    if (probe.isEmpty())
        return false;
    return double(probe.size()) / double(sample.size()) < kWorthwhileRatio();
}
}

int AttachmentStore::externalizeThreshold()
{
    return AdvancedConfig::i("attachments/externalizeThresholdBytes");
}

QString AttachmentStore::rootDir()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/attachments");
    static bool created = false;
    if (!created) {
        QDir().mkpath(dir);
        // Cached mail is private data, exactly like the database.
        QFile::setPermissions(dir, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
        created = true;
    }
    return dir;
}

QString AttachmentStore::pathFor(const QString &hash)
{
    // One byte of fanout: 256 directories keeps any single one small enough
    // that listing it stays cheap, without a deep tree to walk.
    return rootDir() + QLatin1Char('/') + hash.left(2) + QLatin1Char('/') + hash;
}

AttachmentStore::Stored AttachmentStore::put(const QByteArray &data)
{
    Stored result;
    if (data.isEmpty())
        return result;

    result.hash = QString::fromLatin1(
        QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
    result.size = data.size();

    const QString path = pathFor(result.hash);
    if (QFileInfo::exists(path)) {
        // Same bytes already stored — the whole point of content addressing.
        // Read the codec back out of the file: the payload may have been
        // written compressed by whichever message stored it first, and
        // guessing "raw" here would hand the next reader a zstd frame.
        const int codec = codecOfFile(path);
        if (codec < 0)
            QFile::remove(path); // not ours or truncated — rewrite it below
        else {
            result.deduplicated = true;
            result.codec = codec;
            result.stored = QFileInfo(path).size();
            return result;
        }
    }

    QDir().mkpath(QFileInfo(path).absolutePath());

    QByteArray payload = data;
    result.codec = 0;
    if (worthCompressing(data)) {
        const QByteArray packed = zstdCompress(data);
        // Guard against the sample lying about the tail of a mixed payload.
        if (!packed.isEmpty() && packed.size() < data.size()) {
            payload = packed;
            result.codec = 1;
        }
    }

    // QSaveFile writes to a temporary and renames on commit, so a crash or a
    // full disk can never leave a half-written payload under a hash that
    // claims to describe complete bytes.
    QByteArray header;
    header.append(kMagic0);
    header.append(kMagic1);
    header.append(kVersion);
    header.append(char('0' + result.codec));
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return {};
    if (file.write(header) != header.size()
        || file.write(payload) != payload.size() || !file.commit())
        return {};
    QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner);
    result.stored = payload.size();
    return result;
}

QByteArray AttachmentStore::get(const QString &hash, int codec)
{
    Q_UNUSED(codec) // advisory only; the file itself is authoritative
    if (hash.isEmpty())
        return {};
    QFile file(pathFor(hash));
    if (!file.open(QIODevice::ReadOnly))
        return {};
    const QByteArray blob = file.readAll();
    if (blob.size() < kHeaderBytes || blob[0] != kMagic0 || blob[1] != kMagic1
        || blob[2] != kVersion)
        return {};
    const QByteArray payload = blob.mid(kHeaderBytes);
    return blob[3] == '1' ? zstdDecompress(payload) : payload;
}

bool AttachmentStore::contains(const QString &hash)
{
    return !hash.isEmpty() && QFileInfo::exists(pathFor(hash));
}

bool AttachmentStore::remove(const QString &hash)
{
    return !hash.isEmpty() && QFile::remove(pathFor(hash));
}

QStringList AttachmentStore::allHashes()
{
    QStringList out;
    QDir root(rootDir());
    const auto buckets = root.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &bucket : buckets) {
        QDir dir(root.filePath(bucket));
        const auto files = dir.entryList(QDir::Files);
        for (const QString &name : files)
            out.append(name);
    }
    return out;
}
