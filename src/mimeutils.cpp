// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "mimeutils.h"

#include "attachmentstore.h"

#include <QHash>
#include <QRegularExpression>
#include <QTextBlock>
#include <QTextCursor>
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
        if (decoded.size() < AttachmentStore::externalizeThreshold())
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

/// True when the leading run of the body (whitespace aside) is drawn from the
/// base64 alphabet. Only the first 512 significant bytes are read: raw text
/// or HTML fails within the first line, and a genuine base64 body cannot
/// contain anything else at any point, so nothing is gained by reading on.
static bool looksLikeBase64(const QByteArray &body)
{
    int seen = 0;
    for (const char c : body) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            continue;
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        if (!ok)
            return false;
        if (++seen >= 512)
            break;
    }
    return true;
}

void repairTransferEncodings(KMime::Content *node)
{
    if (!node)
        return;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children)
            repairTransferEncodings(child);
        return;
    }
    if (!node->hasHeader("Content-Transfer-Encoding"))
        return;
    auto *cte = node->contentTransferEncoding();
    if (!cte || cte->encoding() != KMime::Headers::CEbase64)
        return;
    const QByteArray body = node->body();
    if (body.isEmpty() || looksLikeBase64(body))
        return;
    // Two things, because KMime undoes each on its own: the header object,
    // and then setBody() with the very same bytes, which drops the decoded
    // body KMime keeps from the first read. Both allowed on a frozen message,
    // whose encodedContent() still answers with the wire — the head text is
    // deliberately not rewritten, because that IS the wire for the DKIM
    // verdict and the cache. The price is that parse() would rebuild the
    // header from the head text and undo this; parseIfNeeded() exists so no
    // consumer parses an already-parsed message.
    cte->setEncoding(KMime::Headers::CEbinary);
    node->setBody(body);
}

void parseIfNeeded(KMime::Content *node)
{
    if (!node)
        return;
    if (!node->contents().isEmpty())
        return;
    const auto *ct = std::as_const(*node).contentType();
    const bool container = ct && (ct->isMultipart() || ct->isMimeType("message/rfc822"));
    if (container)
        node->parse();
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

QString htmlToMarkdown(const QString &html)
{
    QTextDocument doc;
    doc.setHtml(html);
    // Images out — on the parsed document, not with a regex over the markup.
    // toMarkdown() would emit "![](cid:…)", a reference to a part of a message
    // the paste target has never seen. The parser keeps the author's alt text
    // as ImageAltText, and alt is written for a reader who cannot see the
    // picture — which is exactly the reader of the pasted text.
    QList<std::pair<QTextFragment, std::pair<QString, QTextCharFormat>>> images;
    for (QTextBlock block = doc.begin(); block.isValid(); block = block.next()) {
        for (QTextBlock::iterator it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            const QTextCharFormat format = fragment.charFormat();
            if (!fragment.isValid() || !format.isImageFormat())
                continue;
            const QString alt = format.property(QTextFormat::ImageAltText).toString().trimmed();
            const QString href = format.isAnchor() ? format.anchorHref().trimmed() : QString();
            // Alt inside a link keeps the link and becomes its label. Alt with
            // no link is plain text. And the newsletter button — an image that
            // is the whole content of a link, no alt — would otherwise take
            // the href with it when it goes, or leave "[ ](https://…)", a
            // label nobody can read or click; the address itself is the honest
            // thing to leave behind, as text rather than as a link labelled
            // with its own address.
            QTextCharFormat replacementFormat;
            if (!alt.isEmpty() && !href.isEmpty()) {
                replacementFormat.setAnchor(true);
                replacementFormat.setAnchorHref(href);
            }
            images.append({fragment, {alt.isEmpty() ? href : alt, replacementFormat}});
        }
    }
    // Back to front: each edit shifts every position after it.
    for (auto it = images.crbegin(); it != images.crend(); ++it) {
        QTextCursor cursor(&doc);
        cursor.setPosition(it->first.position());
        cursor.setPosition(it->first.position() + it->first.length(), QTextCursor::KeepAnchor);
        // insertText on a selection replaces it; an empty string deletes.
        cursor.insertText(it->second.first, it->second.second);
    }
    // <br> parses to line-separator characters, which toMarkdown() emits as
    // bare newlines — soft breaks that renderers join into one line. Promoted
    // to real paragraph breaks, they survive as the separate lines the reader
    // saw. (The writer's own 80-column prose wrapping also emits bare
    // newlines, so this cannot be fixed after the fact — only here, where the
    // two are still distinguishable.)
    for (QTextCursor cursor(&doc);;) {
        cursor = doc.find(QString(QChar::LineSeparator), cursor);
        if (cursor.isNull())
            break;
        cursor.insertBlock();
    }
    // Layout-table furniture stripped (with blank runs capped) — the paste
    // target gets content, not a diagram of the newsletter's grid.
    QString markdown =
        flattenMarkdownTables(doc.toMarkdown(QTextDocument::MarkdownDialectGitHub)).trimmed();
    // A link whose only content was an image has no label left once the image
    // is gone, and Qt writes it as "[ ](https://…)" — a link that renders as
    // a blank you cannot click and cannot read. Every tracking-link button in
    // a newsletter is one of these. Emitted as the bare URL instead: still
    // the whole address, still one click in anything that autolinks, and it
    // says where it goes. (Over generated Markdown, not over the message's
    // markup — the house rule is about parsing mail, and this is our own
    // output, line-oriented like flattenMarkdownTables above.)
    static const QRegularExpression emptyLinkRe(
        QStringLiteral("(?<!!)\\[[ \\t]*\\]\\(\\s*([^()\\s]+)\\s*\\)"));
    markdown.replace(emptyLinkRe, QStringLiteral("\\1"));
    return markdown;
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
