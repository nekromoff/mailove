// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "documenthandler.h"

#include "advancedconfig.h"

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
#include <QElapsedTimer>
#include <QImageReader>
#include <QLoggingCategory>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTextFragment>
#include <QTextFrame>
#include <QTextTable>
#include <QTimer>
#include <QVariant>

// Same category mailclient's tracing uses, so one logging rule shows the
// whole reply/forward timeline, quote streaming included.
Q_LOGGING_CATEGORY(logQuote, "mailove.trace")

namespace
{
/// A QTextDocument that will not touch the disk or the network. Parsing and
/// layout request resources lazily; answering every request with nothing
/// makes setHtml() on hostile markup side-effect free.
class InertTextDocument : public QTextDocument
{
protected:
    QVariant loadResource(int, const QUrl &) override { return {}; }
};

/// A reference the compose editor may keep: already on this machine or inside
/// the message itself. Everything else is a network fetch waiting to happen.
bool localReference(const QString &name)
{
    const QString ref = name.trimmed();
    return ref.startsWith(QLatin1String("data:"), Qt::CaseInsensitive)
        || ref.startsWith(QLatin1String("file:"), Qt::CaseInsensitive)
        || ref.startsWith(QLatin1String("cid:"), Qt::CaseInsensitive);
}
} // namespace

QString DocumentHandler::stripRemoteContent(const QString &html)
{
    InertTextDocument doc;
    doc.setHtml(html);

    // Images: collect first, then delete — editing invalidates the fragment
    // iterators mid-walk. Deleted, not blanked: an <img src=""> resolves
    // against the document's base URL, and the editor then stalls retrying
    // that nonsense load on every layout pass. Removing the element also
    // matches what the user saw — these images were never loaded.
    struct ImageRef { int position; int length; };
    QList<ImageRef> remoteImages;
    for (QTextBlock block = doc.begin(); block != doc.end(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            if (!fragment.isValid() || !fragment.charFormat().isImageFormat())
                continue;
            const QString name = fragment.charFormat().toImageFormat().name();
            if (!localReference(name)) // empty included — it cannot render
                remoteImages.append({fragment.position(), fragment.length()});
        }
    }
    // Back to front, so earlier positions stay valid as later text is removed.
    for (auto it = remoteImages.crbegin(); it != remoteImages.crend(); ++it) {
        QTextCursor cursor(&doc);
        cursor.setPosition(it->position);
        cursor.setPosition(it->position + it->length, QTextCursor::KeepAnchor);
        cursor.removeSelectedText();
    }

    // Backgrounds: a background attribute lands on the body's or a table's
    // frame format — or on a cell's format — as BackgroundImageUrl.
    auto remoteBackground = [](const QTextFormat &format) {
        return format.hasProperty(QTextFormat::BackgroundImageUrl)
            && !localReference(
                format.property(QTextFormat::BackgroundImageUrl).toString());
    };
    QList<QTextFrame *> frames{doc.rootFrame()};
    while (!frames.isEmpty()) {
        QTextFrame *frame = frames.takeLast();
        frames.append(frame->childFrames());
        if (QTextFrameFormat format = frame->frameFormat(); remoteBackground(format)) {
            format.clearProperty(QTextFormat::BackgroundImageUrl);
            frame->setFrameFormat(format);
        }
        const auto *table = qobject_cast<QTextTable *>(frame);
        if (!table)
            continue;
        for (int row = 0; row < table->rows(); ++row) {
            for (int column = 0; column < table->columns(); ++column) {
                QTextTableCell cell = table->cellAt(row, column);
                if (QTextCharFormat format = cell.format(); remoteBackground(format)) {
                    format.clearProperty(QTextFormat::BackgroundImageUrl);
                    cell.setFormat(format);
                }
            }
        }
    }

    return doc.toHtml();
}

void DocumentHandler::startQuoteStream(const QStringList &chunks, bool stripRemote)
{
    cancelQuoteStream();
    if (chunks.isEmpty() || !m_document)
        return;
    m_quoteChunks = chunks;
    m_quoteStripRemote = stripRemote;
    m_quoteTotalChunks = chunks.size();
    m_quoteStreamMs = 0;
    // At the end of whatever the composer was opened with; keepPositionOnInsert
    // stays false, so this cursor rides along behind each inserted chunk while
    // the user's own cursor (usually parked at the top) is left alone.
    m_quoteCursor = QTextCursor(m_document->textDocument());
    m_quoteCursor.movePosition(QTextCursor::End);
    qCDebug(logQuote, "quoteStream: start, %d chunks, strip=%d",
            m_quoteTotalChunks, stripRemote);
    Q_EMIT quoteStreamingChanged();
    QTimer::singleShot(0, this, [this] { streamQuoteBatch(false); });
}

void DocumentHandler::cancelQuoteStream()
{
    // Downloads die with the stream either way; the cache of finished ones
    // stays for the next quote from the same sender.
    const auto replies = m_remoteImageReplies.values();
    m_remoteImageReplies.clear();
    for (QNetworkReply *reply : replies)
        reply->abort(); // finished handler sees the entry gone and just deletes
    if (m_remoteImageTimeout)
        m_remoteImageTimeout->stop();
    if (m_quoteChunks.isEmpty())
        return;
    qCDebug(logQuote, "quoteStream: cancelled with %lld/%d chunks pending",
            static_cast<qint64>(m_quoteChunks.size()), m_quoteTotalChunks);
    m_quoteChunks.clear();
    m_quoteCursor = QTextCursor();
    Q_EMIT quoteStreamingChanged();
}

void DocumentHandler::flushQuoteStream()
{
    if (m_quoteChunks.isEmpty())
        return;
    qCDebug(logQuote, "quoteStream: flushing %lld remaining chunks synchronously",
            static_cast<qint64>(m_quoteChunks.size()));
    streamQuoteBatch(true);
}

void DocumentHandler::streamQuoteBatch(bool all)
{
    if (m_quoteChunks.isEmpty())
        return; // cancelled since the tick was scheduled
    if (!m_document || m_quoteCursor.isNull()) {
        cancelQuoteStream();
        return;
    }
    QElapsedTimer timer;
    timer.start();
    int inserted = 0;
    qint64 stripMs = 0;
    bool waiting = false;
    // ~half a 60 Hz frame of work per tick: the other half is left for the
    // incremental relayout and whatever else the GUI thread is doing.
    while (!m_quoteChunks.isEmpty() && (all || timer.elapsed() < 8)) {
        QString chunk = m_quoteChunks.first();
        if (m_quoteStripRemote) {
            QElapsedTimer stripTimer;
            stripTimer.start();
            chunk = stripRemoteContent(chunk);
            stripMs += stripTimer.elapsed();
        } else if (!resolveChunkImages(chunk, all)) {
            waiting = true; // head chunk's images still downloading
            break;
        }
        m_quoteChunks.removeFirst();
        m_quoteCursor.beginEditBlock();
        m_quoteCursor.insertHtml(chunk);
        m_quoteCursor.endEditBlock();
        ++inserted;
    }
    m_quoteStreamMs += timer.elapsed();
    // First content in: an empty document had its caret at position 0 == the
    // insertion point, so the insert dragged it (and the view) along — tell
    // the sheet so it can park the caret back at the top.
    if (inserted > 0 && m_quoteTotalChunks - m_quoteChunks.size() == inserted)
        Q_EMIT quoteStreamContentArrived();
    qCDebug(logQuote, "quoteStream: tick +%d chunks in %lldms (strip %lldms)%s, %lld/%d left",
            inserted, timer.elapsed(), stripMs,
            waiting ? ", waiting on images" : "",
            static_cast<qint64>(m_quoteChunks.size()), m_quoteTotalChunks);
    if (m_quoteChunks.isEmpty()) {
        qCDebug(logQuote, "quoteStream: done, %d chunks in %lldms insertion time total",
                m_quoteTotalChunks, m_quoteStreamMs);
        m_quoteCursor = QTextCursor();
        Q_EMIT quoteStreamingChanged();
        Q_EMIT quoteStreamFinished();
        return;
    }
    // One batch per frame, not back-to-back: a zero-delay chain saturates
    // the event loop and typing into the half-open composer goes choppy.
    // A download completion resumes a waiting stream on its own.
    if (!waiting)
        QTimer::singleShot(16, this, [this] { streamQuoteBatch(false); });
}

bool DocumentHandler::resolveChunkImages(QString &chunk, bool flush)
{
    // Nothing that looks like an image with a scheme? Then nothing to do —
    // the parse below is cheap on a 2 KB chunk but free is better.
    if (!chunk.contains(QLatin1String("<img"), Qt::CaseInsensitive))
        return true;

    InertTextDocument doc;
    doc.setHtml(chunk);
    struct ImageRef { int position; int length; QTextImageFormat format; QString url; };
    QList<ImageRef> images;
    QStringList missing;
    for (QTextBlock block = doc.begin(); block != doc.end(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            if (!fragment.isValid() || !fragment.charFormat().isImageFormat())
                continue;
            const QTextImageFormat format = fragment.charFormat().toImageFormat();
            QString url = format.name().trimmed();
            if (localReference(url))
                continue;
            if (url.startsWith(QLatin1String("//")))
                url.prepend(QLatin1String("https:")); // protocol-relative
            images.append({fragment.position(), fragment.length(), format, url});
            const bool fetchable = url.startsWith(QLatin1String("http"), Qt::CaseInsensitive);
            if (fetchable && !m_remoteImageCache.contains(url))
                missing.append(url);
        }
    }
    if (images.isEmpty())
        return true;

    if (!missing.isEmpty() && !flush) {
        for (const QString &url : std::as_const(missing))
            fetchRemoteImage(url);
        // Cap how long a slow server may hold the quote: whatever has not
        // landed by then is failed and the image dropped, like a strip.
        if (!m_remoteImageTimeout) {
            m_remoteImageTimeout = new QTimer(this);
            m_remoteImageTimeout->setSingleShot(true);
            m_remoteImageTimeout->setInterval(6000);
            connect(m_remoteImageTimeout, &QTimer::timeout, this, [this] {
                const auto pending = m_remoteImageReplies.keys();
                qCDebug(logQuote, "quoteStream: image timeout, failing %lld downloads",
                        static_cast<qint64>(pending.size()));
                for (const QString &url : pending)
                    m_remoteImageCache.insert(url, QString());
                const auto replies = m_remoteImageReplies.values();
                m_remoteImageReplies.clear();
                for (QNetworkReply *reply : replies)
                    reply->abort();
                streamQuoteBatch(false);
            });
        }
        m_remoteImageTimeout->start();
        return false;
    }

    // Rewrite back to front so earlier positions stay valid. Downloaded →
    // file: reference (composeMessage() embeds it on send). Failed or
    // unfetchable (a relative src with no base) → the element goes; left in,
    // the editor's render thread would try the load itself and block the
    // scene graph for seconds. On a flush, still-loading images keep their
    // remote src — the sent message means the same, only the recipient's
    // client does the loading.
    for (auto it = images.crbegin(); it != images.crend(); ++it) {
        QTextCursor cursor(&doc);
        cursor.setPosition(it->position);
        cursor.setPosition(it->position + it->length, QTextCursor::KeepAnchor);
        const bool fetchable = it->url.startsWith(QLatin1String("http"), Qt::CaseInsensitive);
        if (!fetchable) {
            cursor.removeSelectedText();
            continue;
        }
        const auto cached = m_remoteImageCache.constFind(it->url);
        if (cached == m_remoteImageCache.constEnd())
            continue; // flush with the download still in flight: keep remote src
        if (cached->isEmpty()) {
            cursor.removeSelectedText(); // failed or timed out
            continue;
        }
        QTextImageFormat resolved = it->format;
        resolved.setName(QUrl::fromLocalFile(*cached).toString());
        cursor.setCharFormat(resolved);
    }
    chunk = doc.toHtml();
    return true;
}

namespace
{
/// http(s) image sources of \a html, by lexical scan — parsing hundreds of
/// KB just to list URLs would stall the click this exists to keep fast.
/// Over-collecting (a src= that is not an image) costs one harmless fetch.
QStringList remoteImageSources(const QString &html)
{
    QStringList out;
    qsizetype pos = 0;
    while (true) {
        pos = html.indexOf(QLatin1String("src="), pos, Qt::CaseInsensitive);
        if (pos < 0)
            break;
        pos += 4;
        if (pos >= html.size())
            break;
        const QChar quote = html.at(pos);
        if (quote != QLatin1Char('"') && quote != QLatin1Char('\''))
            continue;
        const qsizetype end = html.indexOf(quote, pos + 1);
        if (end < 0)
            break;
        QString url = html.sliced(pos + 1, end - pos - 1).trimmed();
        pos = end + 1;
        if (url.startsWith(QLatin1String("//")))
            url.prepend(QLatin1String("https:"));
        if (url.startsWith(QLatin1String("http"), Qt::CaseInsensitive) && !out.contains(url))
            out.append(url);
    }
    return out;
}
} // namespace

void DocumentHandler::prefetchQuoteImages(const QString &html)
{
    const QStringList urls = remoteImageSources(html);
    const int maxPrefetch = AdvancedConfig::i("compose/remoteImagePrefetch");
    int started = 0;
    for (const QString &url : urls) {
        if (m_remoteImageCache.contains(url) || m_remoteImageReplies.contains(url))
            continue;
        if (started >= maxPrefetch)
            break;
        ++started;
        fetchRemoteImage(url);
    }
    qCDebug(logQuote, "prefetchQuoteImages: %lld urls, %d new fetches",
            static_cast<qint64>(urls.size()), started);
}

QString DocumentHandler::embedFetchedImages(const QString &html)
{
    if (html.isEmpty() || m_remoteImageCache.isEmpty())
        return html;
    QElapsedTimer timer;
    timer.start();
    InertTextDocument doc;
    doc.setHtml(html);
    struct ImageRef { int position; int length; QTextImageFormat format; QString file; };
    QList<ImageRef> resolved;
    for (QTextBlock block = doc.begin(); block != doc.end(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            if (!fragment.isValid() || !fragment.charFormat().isImageFormat())
                continue;
            const QTextImageFormat format = fragment.charFormat().toImageFormat();
            QString url = format.name().trimmed();
            if (url.startsWith(QLatin1String("//")))
                url.prepend(QLatin1String("https:"));
            const auto cached = m_remoteImageCache.constFind(url);
            if (cached == m_remoteImageCache.constEnd() || cached->isEmpty())
                continue; // in flight or failed: the remote src stays
            resolved.append({fragment.position(), fragment.length(), format, *cached});
        }
    }
    if (resolved.isEmpty())
        return html;
    for (auto it = resolved.crbegin(); it != resolved.crend(); ++it) {
        QTextCursor cursor(&doc);
        cursor.setPosition(it->position);
        cursor.setPosition(it->position + it->length, QTextCursor::KeepAnchor);
        QTextImageFormat format = it->format;
        format.setName(QUrl::fromLocalFile(it->file).toString());
        cursor.setCharFormat(format);
    }
    qCDebug(logQuote, "embedFetchedImages: %lld images embedded in %lldms",
            static_cast<qint64>(resolved.size()), timer.elapsed());
    return doc.toHtml();
}

void DocumentHandler::fetchRemoteImage(const QString &url)
{
    if (m_remoteImageReplies.contains(url))
        return; // already on its way
    if (!m_network)
        m_network = new QNetworkAccessManager(this);
    if (!m_remoteImageDir) {
        m_remoteImageDir = std::make_unique<QTemporaryDir>(
            QDir::tempPath() + QStringLiteral("/mailove-quote-images-XXXXXX"));
    }
    QNetworkRequest request{QUrl(url)};
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setTransferTimeout(5000);
    QElapsedTimer started;
    started.start();
    QNetworkReply *reply = m_network->get(request);
    m_remoteImageReplies.insert(url, reply);
    qCDebug(logQuote, "quoteStream: fetching %s (%lld in flight)",
            qUtf8Printable(url), static_cast<qint64>(m_remoteImageReplies.size()));
    connect(reply, &QNetworkReply::finished, this, [this, url, reply, started] {
        reply->deleteLater();
        // Removed already = cancelled or timed out; the verdict fell then.
        if (m_remoteImageReplies.take(url) == nullptr)
            return;
        QString path;
        const qint64 maxImageBytes = AdvancedConfig::i("compose/maxRemoteImageBytes");
        const QByteArray data = reply->error() == QNetworkReply::NoError
            ? reply->read(maxImageBytes + 1) : QByteArray();
        QBuffer probe;
        probe.setData(data);
        probe.open(QIODevice::ReadOnly);
        const QByteArray imageType = QImageReader::imageFormat(&probe);
        if (!data.isEmpty() && data.size() <= maxImageBytes && !imageType.isEmpty()
            && m_remoteImageDir && m_remoteImageDir->isValid()) {
            path = m_remoteImageDir->filePath(
                QStringLiteral("quote-%1.%2")
                    .arg(++m_remoteImageCount)
                    .arg(QString::fromLatin1(imageType)));
            QFile file(path);
            if (file.open(QIODevice::WriteOnly))
                file.write(data);
            else
                path.clear();
        }
        m_remoteImageCache.insert(url, path);
        qCDebug(logQuote, "quoteStream: fetched %s: %lld bytes in %lldms -> %s",
                qUtf8Printable(url), static_cast<qint64>(data.size()), started.elapsed(),
                path.isEmpty() ? qUtf8Printable(reply->errorString()) : qUtf8Printable(path));
        // A waiting stream may be unblocked now.
        if (!m_quoteChunks.isEmpty() && m_remoteImageReplies.isEmpty())
            streamQuoteBatch(false);
    });
}

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
qint64 kMaxPastedImage() { return AdvancedConfig::i("compose/maxPastedImageBytes"); }

/// How wide a pasted image is drawn — in the editor and, since the size
/// travels with the HTML, in the recipient's client. The pixels are all still
/// there; this is the display size, the way any editor scales an image dropped
/// into a page. A modern screenshot is several thousand pixels wide and would
/// otherwise arrive at that width.
int kDisplayWidth() { return AdvancedConfig::i("compose/pastedImageDisplayWidth"); }

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
    if (data.size() > kMaxPastedImage()) {
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
    if (image.width() > kDisplayWidth()) {
        format.setWidth(kDisplayWidth());
        format.setHeight(qRound(double(image.height()) * kDisplayWidth() / image.width()));
    }
    cursor.beginEditBlock();
    if (cursor.hasSelection())
        cursor.removeSelectedText();
    cursor.insertImage(format);
    cursor.endEditBlock();
    return true;
}
