// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "mimeutils.h"

#include "attachmentstore.h"

#include <QHash>
#include <QRegularExpression>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextFragment>
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

QString plainTextWithLinks(const QString &html)
{
    // A bare QTextDocument, parse only: resources (images, stylesheets) are
    // requested at layout time, and nothing here ever lays out — so hostile
    // markup cannot make this fetch anything.
    QTextDocument doc;
    doc.setHtml(html);

    QString out;
    out.reserve(doc.characterCount() + doc.characterCount() / 8);
    QString anchorHref;  // href of the anchor span currently open
    QString anchorText;  // its accumulated visible text

    // The visible text already says where the link goes: a bare URL, the
    // mailto: of the shown address, or the URL minus its scheme ("www.x.y"
    // shown for "https://www.x.y"). Printing the target again is noise.
    // Empty visible text is an image-only link — silent, see the header.
    auto targetShown = [](const QString &href, const QString &shown) {
        if (shown.isEmpty() || href == shown)
            return true;
        if (href.startsWith(QLatin1String("mailto:")) && href.mid(7) == shown)
            return true;
        return href.endsWith(shown) && href.size() - shown.size() <= 8;
    };
    auto closeAnchor = [&] {
        if (anchorHref.isEmpty())
            return;
        out += anchorText;
        if (!targetShown(anchorHref, anchorText.trimmed()))
            out += QStringLiteral(" (") + anchorHref + QLatin1Char(')');
        anchorHref.clear();
        anchorText.clear();
    };

    for (QTextBlock block = doc.begin(); block != doc.end(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            if (!fragment.isValid())
                continue;
            QString text = fragment.text();
            text.replace(QChar::LineSeparator, QLatin1Char('\n')); // <br>
            const QTextCharFormat format = fragment.charFormat();
            const QString href = format.isAnchor() ? format.anchorHref() : QString();
            // One link arrives as several fragments when its text changes
            // formatting mid-way ("click <b>here</b>") — the URL is emitted
            // once, where the anchor span ends, not per fragment.
            if (href != anchorHref)
                closeAnchor();
            if (href.isEmpty()) {
                out += text;
            } else {
                anchorHref = href;
                anchorText += text;
            }
        }
        closeAnchor(); // an anchor ends with its block
        out += QLatin1Char('\n');
    }
    if (!out.isEmpty())
        out.chop(1); // the loop's trailing block separator
    return out;
}

QString flattenMarkdownTables(const QString &markdown)
{
    // Row furniture: only pipes, dashes, colons and spaces (separator rows,
    // empty rows). Anything else starting with a pipe is a row whose cells
    // may hold content worth keeping.
    static const QRegularExpression furnitureRe(QStringLiteral("^[|\\-:\\s]*$"));
    const QStringList lines = markdown.split(QLatin1Char('\n'));
    QStringList out;
    int blanks = 0;
    auto append = [&](const QString &line) {
        blanks = line.trimmed().isEmpty() ? blanks + 1 : 0;
        // Dropped furniture merges the blank gaps around it; cap the runs
        // here so the caller does not need condenseBlankLines() — which
        // strips trailing whitespace and would eat the hard breaks below.
        if (blanks <= 2)
            out.append(line);
    };
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (!trimmed.startsWith(QLatin1Char('|'))) {
            append(line); // not a table row; pipes mid-text stay untouched
            continue;
        }
        if (furnitureRe.match(trimmed).hasMatch())
            continue;
        // Unwrap the cells: non-empty ones joined by a space, as one line —
        // with a trailing double space, Markdown's hard line break, so
        // stacked rows render as the separate lines they visually were.
        // Heading cells ("## …") break out onto lines of their own with
        // blank lines around them: heading syntax only counts at the start
        // of a line, glued mid-line it renders as literal hashes.
        const QStringList cells = trimmed.split(QLatin1Char('|'));
        QStringList kept;
        auto flushKept = [&] {
            if (kept.isEmpty())
                return;
            append(kept.join(QLatin1Char(' ')) + QStringLiteral("  "));
            kept.clear();
        };
        // List items land one per cell when a list sat in a table cell —
        // joined by spaces they degrade to prose, so they too get lines of
        // their own; consecutive ones re-form the list.
        static const QRegularExpression listCellRe(
            QStringLiteral("^([-*+]|\\d{1,3}[.)])\\s"));
        for (const QString &cell : cells) {
            const QString content = cell.trimmed();
            if (content.isEmpty() || furnitureRe.match(content).hasMatch())
                continue;
            if (content.startsWith(QLatin1Char('#'))) {
                flushKept();
                append(QString());
                append(content);
                append(QString());
            } else if (listCellRe.match(content).hasMatch()) {
                flushKept();
                append(content);
            } else {
                kept.append(content);
            }
        }
        flushKept();
    }
    return out.join(QLatin1Char('\n'));
}

QString condenseBlankLines(QString text)
{
    // Object-replacement characters are where images sat in text extracted
    // from HTML — invisible-but-not-blank, they defeat the collapse below
    // and render as nothing (or a stray box). A text rendering has no use
    // for them anywhere in a line.
    text.remove(QChar::ObjectReplacementCharacter);
    // Lines holding only invisible ink become truly empty, so they count
    // toward the run: whitespace, no-break spaces (the &nbsp; spacer lines
    // of layout-table mail), zero-width spaces and joiners, BOMs.
    static const QRegularExpression invisibleTail(QStringLiteral(
        "[ \\t\\x{00A0}\\x{200B}\\x{200C}\\x{2060}\\x{FEFF}]+\\n"));
    text.replace(invisibleTail, QStringLiteral("\n"));
    // Then anything past two consecutive empty lines collapses.
    static const QRegularExpression blankRuns(QStringLiteral("\\n{4,}"));
    text.replace(blankRuns, QStringLiteral("\n\n\n"));
    return text;
}

} // namespace MimeUtils
