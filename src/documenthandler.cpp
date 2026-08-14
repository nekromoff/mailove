// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "documenthandler.h"

#include <QBuffer>
#include <QClipboard>
#include <QFile>
#include <QGuiApplication>
#include <QImage>
#include <QMimeData>
#include <QMimeDatabase>
#include <QQuickTextDocument>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextImageFormat>
#include <QTextList>
#include <QTextListFormat>
#include <QUrl>

void DocumentHandler::setDocument(QQuickTextDocument *document)
{
    if (m_document == document)
        return;
    m_document = document;
    Q_EMIT documentChanged();
    Q_EMIT formatChanged();
}

QTextCursor DocumentHandler::textCursor() const
{
    if (!m_document)
        return {};
    QTextCursor cursor(m_document->textDocument());
    if (m_selectionStart != m_selectionEnd) {
        cursor.setPosition(m_selectionStart);
        cursor.setPosition(m_selectionEnd, QTextCursor::KeepAnchor);
    } else {
        cursor.setPosition(m_cursorPosition >= 0 ? m_cursorPosition : 0);
    }
    return cursor;
}

void DocumentHandler::mergeFormat(const QTextCharFormat &format)
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull())
        return;
    if (!cursor.hasSelection())
        cursor.select(QTextCursor::WordUnderCursor);
    cursor.mergeCharFormat(format);
    Q_EMIT formatChanged();
}

void DocumentHandler::setCursorPosition(int position)
{
    if (m_cursorPosition == position)
        return;
    m_cursorPosition = position;
    Q_EMIT cursorPositionChanged();
    Q_EMIT formatChanged();
}

void DocumentHandler::setSelectionStart(int position)
{
    if (m_selectionStart == position)
        return;
    m_selectionStart = position;
    Q_EMIT selectionStartChanged();
}

void DocumentHandler::setSelectionEnd(int position)
{
    if (m_selectionEnd == position)
        return;
    m_selectionEnd = position;
    Q_EMIT selectionEndChanged();
}

bool DocumentHandler::bold() const
{
    return textCursor().charFormat().fontWeight() >= QFont::Bold;
}

void DocumentHandler::setBold(bool bold)
{
    QTextCharFormat format;
    format.setFontWeight(bold ? QFont::Bold : QFont::Normal);
    mergeFormat(format);
}

bool DocumentHandler::italic() const
{
    return textCursor().charFormat().fontItalic();
}

void DocumentHandler::setItalic(bool italic)
{
    QTextCharFormat format;
    format.setFontItalic(italic);
    mergeFormat(format);
}

int DocumentHandler::fontSize() const
{
    const int size = int(textCursor().charFormat().font().pointSizeF());
    return size > 0 ? size : 11;
}

void DocumentHandler::setFontSize(int size)
{
    if (size < 6 || size > 72)
        return;
    QTextCharFormat format;
    format.setFontPointSize(size);
    mergeFormat(format);
}

void DocumentHandler::toggleList(int listStyle)
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull())
        return;
    cursor.beginEditBlock();
    if (QTextList *list = cursor.currentList();
        list && list->format().style() == listStyle) {
        // Already this list type → remove list formatting from the block.
        QTextBlockFormat blockFormat = cursor.blockFormat();
        blockFormat.setIndent(0);
        blockFormat.setObjectIndex(-1);
        cursor.setBlockFormat(blockFormat);
    } else {
        QTextListFormat listFormat;
        listFormat.setStyle(QTextListFormat::Style(listStyle));
        cursor.createList(listFormat);
    }
    cursor.endEditBlock();
    Q_EMIT formatChanged();
}

void DocumentHandler::toggleBulletList()
{
    toggleList(QTextListFormat::ListDisc);
}

void DocumentHandler::toggleOrderedList()
{
    toggleList(QTextListFormat::ListDecimal);
}

namespace {

/// Bullets change shape as they nest, the way every other editor draws them,
/// so a sub-item is recognisable as one without counting the indent.
QTextListFormat::Style bulletStyleForLevel(int level)
{
    switch (level % 3) {
    case 2:
        return QTextListFormat::ListCircle;
    case 0:
        return QTextListFormat::ListSquare;
    default:
        return QTextListFormat::ListDisc;
    }
}

bool isBulletStyle(int style)
{
    return style == QTextListFormat::ListDisc || style == QTextListFormat::ListCircle
        || style == QTextListFormat::ListSquare;
}

/// Takes a block out of its list, keeping whatever is written in it.
void unlistBlock(QTextCursor &cursor)
{
    if (QTextList *list = cursor.currentList())
        list->remove(cursor.block());
    QTextBlockFormat blockFormat = cursor.blockFormat();
    blockFormat.setIndent(0);
    blockFormat.setObjectIndex(-1);
    cursor.setBlockFormat(blockFormat);
}

} // namespace

/// True when the cursor sits at the very start of its block with nothing
/// selected — the position where Backspace means "one level out", not "delete
/// the character before me".
bool DocumentHandler::atBlockStart(const QTextCursor &cursor) const
{
    return !cursor.hasSelection() && cursor.position() == cursor.block().position();
}

bool DocumentHandler::startBulletList()
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull() || cursor.hasSelection())
        return false;
    // Inside a list a dash is just a dash — the list already has its marker.
    if (cursor.currentList())
        return false;
    const QTextBlock block = cursor.block();
    const QString text = block.text();
    // The marker has to be the whole line so far, with the cursor right after
    // it: a dash mid-sentence, or one gone back to, is not a list being begun.
    if (cursor.position() != block.position() + text.size())
        return false;
    if (text != QLatin1String("-") && text != QLatin1String("*"))
        return false;

    QTextListFormat listFormat;
    listFormat.setStyle(QTextListFormat::ListDisc);
    applyMarkerList(cursor, listFormat);
    return true;
}

bool DocumentHandler::startOrderedList(const QString &terminator)
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull() || cursor.hasSelection())
        return false;
    if (cursor.currentList())
        return false;
    const QTextBlock block = cursor.block();
    const QString text = block.text();
    if (cursor.position() != block.position() + text.size())
        return false;
    // Digits and nothing else: the terminator being typed is what turns them
    // into a marker, so it is not in the block yet.
    if (text.isEmpty() || text.size() > 4)
        return false;
    bool ok = false;
    const int start = QStringView(text).toInt(&ok);
    // A list numbered from zero is a typo, not a list.
    if (!ok || start < 1)
        return false;

    QTextListFormat listFormat;
    listFormat.setStyle(QTextListFormat::ListDecimal);
    // "3." counts from three — the number typed was a decision.
    listFormat.setStart(start);
    // And "1)" stays a bracket: the two are different house styles, and
    // rewriting one into the other overrules a choice already made.
    listFormat.setNumberSuffix(terminator);
    applyMarkerList(cursor, listFormat);
    return true;
}

/// Replaces the typed marker with a real list of the given format. The marker
/// goes because the list draws its own, and leaving it would give the first
/// item two.
void DocumentHandler::applyMarkerList(QTextCursor &cursor, const QTextListFormat &listFormat)
{
    cursor.beginEditBlock();
    cursor.movePosition(QTextCursor::StartOfBlock, QTextCursor::KeepAnchor);
    cursor.removeSelectedText();
    cursor.createList(listFormat);
    cursor.endEditBlock();
    Q_EMIT formatChanged();
}

bool DocumentHandler::leaveEmptyListItem()
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull() || cursor.hasSelection())
        return false;
    QTextList *list = cursor.currentList();
    // Only on an item with nothing in it: that empty item is the first Enter,
    // and this is the second one.
    if (!list || !cursor.block().text().isEmpty())
        return false;

    // A nested empty item steps out one level at a time before it leaves the
    // list, so Enter unwinds the nesting the same way Shift+Tab would.
    if (list->format().indent() > 1)
        return changeListIndent(-1);

    cursor.beginEditBlock();
    unlistBlock(cursor);
    cursor.endEditBlock();
    Q_EMIT formatChanged();
    return true;
}

bool DocumentHandler::changeListIndent(int delta)
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull())
        return false;
    QTextList *list = cursor.currentList();
    if (!list)
        return false;

    const QTextListFormat oldFormat = list->format();
    const int level = oldFormat.indent() + delta;
    cursor.beginEditBlock();
    if (level < 1) {
        // Out of the outermost level is out of the list.
        unlistBlock(cursor);
        cursor.endEditBlock();
        Q_EMIT formatChanged();
        return true;
    }

    QTextListFormat listFormat = oldFormat;
    listFormat.setIndent(level);
    if (isBulletStyle(oldFormat.style()))
        listFormat.setStyle(bulletStyleForLevel(level));

    // Join the sibling list at this level if there is one immediately above,
    // rather than starting a second list beside it — otherwise every indented
    // item becomes its own list and numbering restarts at each one.
    QTextList *sibling = nullptr;
    for (QTextBlock b = cursor.block().previous(); b.isValid(); b = b.previous()) {
        QTextList *l = b.textList();
        if (!l)
            break;
        const int otherLevel = l->format().indent();
        if (otherLevel < level)
            break;
        if (otherLevel == level && l->format().style() == listFormat.style()) {
            sibling = l;
            break;
        }
    }
    if (sibling)
        sibling->add(cursor.block());
    else
        cursor.createList(listFormat);
    cursor.endEditBlock();
    Q_EMIT formatChanged();
    return true;
}

bool DocumentHandler::indentListItem()
{
    QTextCursor cursor = textCursor();
    // Only inside a list, and only with nothing selected: everywhere else Tab
    // still means what Tab means, and moves on to the next control.
    if (cursor.isNull() || cursor.hasSelection() || !cursor.currentList())
        return false;
    return changeListIndent(1);
}

bool DocumentHandler::outdentListItem()
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull() || cursor.hasSelection() || !cursor.currentList())
        return false;
    return changeListIndent(-1);
}

bool DocumentHandler::outdentAtBlockStart()
{
    QTextCursor cursor = textCursor();
    if (cursor.isNull() || !atBlockStart(cursor) || !cursor.currentList())
        return false;
    return changeListIndent(-1);
}

bool DocumentHandler::pastePlainText()
{
    const QClipboard *clipboard = QGuiApplication::clipboard();
    if (!clipboard)
        return false;
    // text() rather than the mime data: whatever the source offered, this is
    // the paste that deliberately takes none of its markup.
    const QString text = clipboard->text();
    if (text.isEmpty())
        return false;
    QTextCursor cursor = textCursor();
    if (cursor.isNull())
        return false;
    // One undo step for the whole thing, replacement included.
    cursor.beginEditBlock();
    if (cursor.hasSelection())
        cursor.removeSelectedText();
    // insertText() without a format of its own uses the cursor's, so the text
    // arrives looking like the paragraph it was dropped into; line feeds in it
    // become paragraph breaks.
    cursor.insertText(text);
    cursor.endEditBlock();
    return true;
}

namespace {

/// Mail carries pictures badly enough without a screenshot pasted at retina
/// size; past this the paste is refused rather than quietly building a message
/// no server will accept.
constexpr qint64 kMaxPastedImage = 20 * 1024 * 1024;

/// How wide a pasted image is drawn — in the editor and, since the size
/// travels with the HTML, in the recipient's client. The pixels are all still
/// there; this is the display size, the way any editor scales an image dropped
/// into a page. A modern screenshot is several thousand pixels wide and would
/// otherwise arrive at that width.
constexpr int kDisplayWidth = 640;

/// Clipboard formats worth taking as they are, best first. A JPEG photo
/// re-encoded as PNG is several times the size for no gain, and a GIF loses
/// its animation — so the source's own bytes are sent whenever they are in a
/// format every mail client can render.
struct ClipboardImageFormat {
    const char *mimeType;
    const char *suffix;
};
constexpr ClipboardImageFormat kNativeFormats[] = {
    {"image/png", "png"},
    {"image/jpeg", "jpg"},
    {"image/gif", "gif"},
    {"image/webp", "webp"},
};

/// Local image files on the clipboard — copying a picture in a file manager
/// puts the file's URL there and nothing else. All or nothing: a mixed
/// selection, or anything that is not a local image, is left to the ordinary
/// paste, which is what puts the path in as text.
QStringList localImageFiles(const QMimeData *mime)
{
    if (!mime->hasUrls())
        return {};
    QMimeDatabase mimeDb;
    QStringList out;
    const QList<QUrl> urls = mime->urls();
    for (const QUrl &url : urls) {
        const QString path = url.toLocalFile();
        if (path.isEmpty())
            return {};
        if (!mimeDb.mimeTypeForFile(path).name().startsWith(QLatin1String("image/")))
            return {};
        out.append(path);
    }
    return out;
}

QString suffixOf(const QString &path)
{
    const qsizetype dot = path.lastIndexOf(QLatin1Char('.'));
    const QString suffix = dot > 0 ? path.sliced(dot + 1) : QString();
    return suffix.isEmpty() ? QStringLiteral("png") : suffix;
}

} // namespace

bool DocumentHandler::clipboardHasImage() const
{
    const QClipboard *clipboard = QGuiApplication::clipboard();
    const QMimeData *mime = clipboard ? clipboard->mimeData() : nullptr;
    if (!mime)
        return false;
    return mime->hasImage() || !localImageFiles(mime).isEmpty();
}

bool DocumentHandler::pasteImage()
{
    const QClipboard *clipboard = QGuiApplication::clipboard();
    const QMimeData *mime = clipboard ? clipboard->mimeData() : nullptr;
    if (!mime)
        return false;

    // Image data first, and ahead of any text or HTML offered beside it: a
    // clipboard that holds a picture at all is one where the picture is what
    // was copied. The HTML a browser offers with it references the image by
    // URL, which would leave the message depending on someone else's server.
    if (mime->hasImage()) {
        for (const auto &format : kNativeFormats) {
            if (!mime->hasFormat(QLatin1String(format.mimeType)))
                continue;
            const QByteArray data = mime->data(QLatin1String(format.mimeType));
            if (!data.isEmpty())
                return insertImage(data, QLatin1String(format.suffix));
        }
        // Offered as a decoded image and nothing else (X11 clipboards often
        // are): PNG it, which is lossless and understood everywhere.
        const QImage image = qvariant_cast<QImage>(mime->imageData());
        if (image.isNull())
            return false;
        QByteArray png;
        QBuffer buffer(&png);
        buffer.open(QIODevice::WriteOnly);
        if (!image.save(&buffer, "PNG")) {
            Q_EMIT imagePasteFailed(tr("The image on the clipboard could not be read."));
            return true;
        }
        return insertImage(png, QStringLiteral("png"));
    }

    const QStringList files = localImageFiles(mime);
    if (files.isEmpty())
        return false;
    bool inserted = false;
    for (const QString &path : files) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            Q_EMIT imagePasteFailed(tr("Could not read %1.").arg(path));
            continue;
        }
        inserted = insertImage(file.readAll(), suffixOf(path)) || inserted;
    }
    return inserted;
}

bool DocumentHandler::insertImage(const QByteArray &data, const QString &suffix)
{
    if (!m_document)
        return false;
    if (data.size() > kMaxPastedImage) {
        Q_EMIT imagePasteFailed(
            tr("That image is %1 MB — too large to put in a message. Attach it instead.")
                .arg(data.size() / (1024 * 1024)));
        return true;
    }
    // Decoded here for two reasons: it is how the image's size is known, and a
    // payload that does not decode is not an image at all, whatever the
    // clipboard called it.
    const QImage image = QImage::fromData(data);
    if (image.isNull()) {
        Q_EMIT imagePasteFailed(tr("The image on the clipboard could not be read."));
        return true;
    }

    if (!m_imageDir)
        m_imageDir = std::make_unique<QTemporaryDir>();
    if (!m_imageDir->isValid()) {
        Q_EMIT imagePasteFailed(tr("Could not create a temporary file for the image."));
        return true;
    }
    const QString path = m_imageDir->filePath(
        QStringLiteral("pasted-%1.%2").arg(++m_imageCount).arg(suffix));
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size()) {
        Q_EMIT imagePasteFailed(tr("Could not write the image to %1.").arg(path));
        return true;
    }
    file.close();

    QTextCursor cursor = textCursor();
    if (cursor.isNull())
        return false;

    const QUrl url = QUrl::fromLocalFile(path);
    // The document would load the file by itself, asynchronously; handing it
    // the decoded image outright means the paste appears at once, and appears
    // even if the temporary directory is somewhere the loader will not follow.
    m_document->textDocument()->addResource(QTextDocument::ImageResource, url, image);

    QTextImageFormat format;
    format.setName(url.toString());
    if (image.width() > kDisplayWidth) {
        format.setWidth(kDisplayWidth);
        format.setHeight(qRound(double(image.height()) * kDisplayWidth / image.width()));
    }
    cursor.beginEditBlock();
    if (cursor.hasSelection())
        cursor.removeSelectedText();
    cursor.insertImage(format);
    cursor.endEditBlock();
    return true;
}
