// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "mimeutils.h"

#include "attachmentstore.h"

#include <QHash>
#include <QRegularExpression>
#include <QUrl>
#include <QUuid>

#include <kmime/content.h>
#include <kmime/message.h>
#include <kmime/util.h>

#include <utility>

namespace MimeUtils
{

KMime::Content *findPartByType(KMime::Content *root, const char *mimeType)
{
    if (const auto *ct = std::as_const(*root).contentType(); ct && ct->isMimeType(mimeType))
        return root;
    const auto children = root->contents();
    for (KMime::Content *child : children) {
        if (KMime::Content *found = findPartByType(child, mimeType))
            return found;
    }
    return nullptr;
}

void walkParts(KMime::Content *node, const QString &prefix,
               const std::function<void(KMime::Content *, const QString &)> &fn)
{
    const auto children = node->contents();
    for (int i = 0; i < children.size(); ++i) {
        const QString id = prefix.isEmpty() ? QString::number(i + 1)
                                            : prefix + QLatin1Char('.') + QString::number(i + 1);
        fn(children.at(i), id);
        walkParts(children.at(i), id, fn);
    }
}

bool isAttachmentPart(KMime::Content *part)
{
    if (!part->contents().isEmpty())
        return false; // a container, not a payload
    const auto *cd = std::as_const(*part).contentDisposition();
    if (cd && cd->disposition() == KMime::Headers::CDattachment)
        return true;
    // Inline images referenced by HTML mail are attachments for our purposes:
    // they are big, binary, and repeat across every message in a newsletter.
    return cd && !cd->filename().isEmpty();
}

QList<MailStore::PartRef> stripAttachments(KMime::Message *msg)
{
    QList<MailStore::PartRef> lifted;
    walkParts(msg, QString(), [&lifted](KMime::Content *part, const QString &id) {
        if (!isAttachmentPart(part))
            return;
        const QByteArray decoded = part->decodedBody();
        if (decoded.size() < AttachmentStore::kExternalizeThreshold)
            return; // small enough that a file of its own would cost more
        const AttachmentStore::Stored stored = AttachmentStore::put(decoded);
        if (stored.hash.isEmpty())
            return; // could not write it; leave the payload where it is
        MailStore::PartRef ref;
        ref.partId = id;
        ref.hash = stored.hash;
        ref.size = stored.size;
        ref.stored = stored.stored;
        ref.codec = stored.codec;
        const auto *cd = std::as_const(*part).contentDisposition();
        ref.filename = cd ? cd->filename() : QString();
        if (const auto *ct = std::as_const(*part).contentType())
            ref.mime = QString::fromLatin1(ct->mimeType());
        lifted.append(ref);
        part->setBody({});
        lifted.last().partId = id;
    });
    return lifted;
}

bool restoreAttachments(KMime::Message *msg, const QList<MailStore::PartRef> &parts)
{
    if (parts.isEmpty())
        return true;
    QHash<QString, const MailStore::PartRef *> byId;
    for (const auto &p : parts)
        byId.insert(p.partId, &p);
    bool complete = true;
    walkParts(msg, QString(), [&byId, &complete](KMime::Content *part, const QString &id) {
        const auto it = byId.constFind(id);
        if (it == byId.cend())
            return;
        const QByteArray payload = AttachmentStore::get((*it)->hash, (*it)->codec);
        if (payload.isEmpty()) {
            complete = false;
            return;
        }
        if (auto *cte = part->contentTransferEncoding())
            cte->setEncoding(KMime::Headers::CEbinary);
        part->setBody(payload);
    });
    return complete;
}

void collectBodies(KMime::Content *node, QString *text, QString *html)
{
    if (!node)
        return;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children)
            collectBodies(child, text, html);
        return;
    }
    const QByteArray mime =
        node->contentType() ? node->contentType()->mimeType().toLower() : QByteArray();
    if (mime == "text/html" && html->isEmpty())
        *html = node->decodedText();
    else if (mime == "text/plain" && text->isEmpty())
        *text = node->decodedText();
}

void collectAttachments(KMime::Content *node, QStringList *names)
{
    if (!node)
        return;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children)
            collectAttachments(child, names);
        return;
    }
    QString name;
    if (auto *cd = node->contentDisposition(); cd && !cd->filename().isEmpty())
        name = cd->filename();
    else if (auto *ct = node->contentType(); ct && !ct->name().isEmpty())
        name = ct->name();
    if (!name.isEmpty())
        names->append(name);
}

namespace
{

/// True when the ZIP in \a data has at least one entry with the encryption bit
/// set. Walks local file headers from the front rather than reading the central
/// directory: an attachment may be truncated in the cache, and the first entry
/// is enough to answer the question.
bool zipIsEncrypted(const QByteArray &data)
{
    constexpr int localHeader = 30; // fixed part of a local file header
    qsizetype pos = 0;
    while (pos + localHeader <= data.size()) {
        if (static_cast<uchar>(data.at(pos)) != 'P'
            || static_cast<uchar>(data.at(pos + 1)) != 'K'
            || static_cast<uchar>(data.at(pos + 2)) != 0x03
            || static_cast<uchar>(data.at(pos + 3)) != 0x04) {
            return false; // not (or no longer) at a local file header
        }
        const auto u16 = [&data](qsizetype at) {
            return static_cast<quint16>(static_cast<uchar>(data.at(at))
                                        | (static_cast<uchar>(data.at(at + 1)) << 8));
        };
        const quint16 flags = u16(pos + 6);
        if (flags & 0x0001)
            return true; // bit 0: this entry needs a password
        // Sizes live in the data descriptor after the payload when bit 3 is
        // set, which makes the next header unfindable from here. One entry
        // answered is enough; stop rather than guess.
        if (flags & 0x0008)
            return false;
        const quint32 compressed = static_cast<quint32>(u16(pos + 18))
            | (static_cast<quint32>(u16(pos + 20)) << 16);
        pos += localHeader + u16(pos + 26) + u16(pos + 28) + compressed;
    }
    return false;
}

} // namespace

bool hasEncryptedArchive(KMime::Content *node)
{
    if (!node)
        return false;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children) {
            if (hasEncryptedArchive(child))
                return true;
        }
        return false;
    }
    QString name;
    if (auto *cd = node->contentDisposition(); cd && !cd->filename().isEmpty())
        name = cd->filename();
    else if (auto *ct = node->contentType(); ct && !ct->name().isEmpty())
        name = ct->name();
    if (!name.trimmed().toLower().endsWith(QLatin1String(".zip")))
        return false;
    return zipIsEncrypted(node->decodedBody());
}

bool verifyRoundTrip(const QByteArray &stub, const QList<MailStore::PartRef> &parts,
                     QString *reason)
{
    KMime::Message check;
    check.setContent(KMime::CRLFtoLF(stub));
    check.parse();
    if (!restoreAttachments(&check, parts)) {
        *reason = QStringLiteral("a payload could not be read back from disk");
        return false;
    }
    QHash<QString, qint64> expect;
    for (const auto &p : parts)
        expect.insert(p.partId, p.size);
    bool ok = true;
    walkParts(&check, QString(), [&expect, &ok, reason](KMime::Content *part, const QString &id) {
        const auto it = expect.constFind(id);
        if (it == expect.cend())
            return;
        const qint64 got = part->decodedBody().size();
        if (got != it.value()) {
            // Back, but not with the bytes we stored.
            *reason = QStringLiteral("part %1 came back %2 bytes, expected %3")
                          .arg(id).arg(got).arg(it.value());
            ok = false;
        }
    });
    return ok;
}

QList<InlineImage> takeInlineImages(QString &html, const QString &idDomain)
{
    // Attribute-level, not tag-level: an <img> written by QTextDocument carries
    // width, height and style attributes in an order that is not ours to
    // predict, and the src is the only part of it this rewrite touches.
    static const QRegularExpression imgRe(
        QStringLiteral("<img\\b[^>]*>"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression srcRe(
        QStringLiteral("(\\bsrc\\s*=\\s*)([\"'])(file:[^\"']*)\\2"),
        QRegularExpression::CaseInsensitiveOption);

    const QString domain = idDomain.isEmpty() ? QStringLiteral("mailove.invalid") : idDomain;
    QList<InlineImage> images;
    QHash<QString, QByteArray> idForPath; // one part per file, however often used

    QString out;
    out.reserve(html.size());
    qsizetype copied = 0;
    auto tags = imgRe.globalMatch(html);
    while (tags.hasNext()) {
        const auto tag = tags.next();
        const auto src = srcRe.match(tag.captured());
        if (!src.hasMatch())
            continue;
        const QUrl url(src.captured(3));
        const QString path = url.toLocalFile();
        if (path.isEmpty())
            continue;

        QByteArray cid = idForPath.value(path);
        if (cid.isEmpty()) {
            cid = QUuid::createUuid().toByteArray(QUuid::WithoutBraces) + '@' + domain.toUtf8();
            idForPath.insert(path, cid);
            images.append({path, cid});
        }
        // Offsets inside the tag are relative to it; the copy below works in
        // whole-document coordinates.
        const qsizetype from = tag.capturedStart() + src.capturedStart(0);
        const qsizetype to = tag.capturedStart() + src.capturedEnd(0);
        out += QStringView(html).sliced(copied, from - copied);
        out += src.captured(1) + QLatin1Char('"') + QLatin1String("cid:")
            + QString::fromUtf8(cid) + QLatin1Char('"');
        copied = to;
    }
    if (images.isEmpty())
        return {};
    out += QStringView(html).sliced(copied);
    html = out;
    return images;
}

} // namespace MimeUtils
