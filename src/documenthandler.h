// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QObject>
#include <QQuickTextDocument>
#include <QTemporaryDir>
#include <QTextCursor>
#include <QTextListFormat>

#include <memory>

/**
 * Formatting backend for the compose editor. QML TextArea has no API for
 * lists or programmatic character formatting, so this wraps QTextCursor.
 */
class DocumentHandler : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QQuickTextDocument *document READ document WRITE setDocument NOTIFY documentChanged)
    Q_PROPERTY(int cursorPosition READ cursorPosition WRITE setCursorPosition NOTIFY cursorPositionChanged)
    Q_PROPERTY(int selectionStart READ selectionStart WRITE setSelectionStart NOTIFY selectionStartChanged)
    Q_PROPERTY(int selectionEnd READ selectionEnd WRITE setSelectionEnd NOTIFY selectionEndChanged)
    Q_PROPERTY(bool bold READ bold WRITE setBold NOTIFY formatChanged)
    Q_PROPERTY(bool italic READ italic WRITE setItalic NOTIFY formatChanged)
    Q_PROPERTY(int fontSize READ fontSize WRITE setFontSize NOTIFY formatChanged)
    /// True while a reply/forward quote is still streaming into the document.
    Q_PROPERTY(bool quoteStreaming READ quoteStreaming NOTIFY quoteStreamingChanged)

public:
    using QObject::QObject;

    /// Neutralizes every reference \a html could make the editor fetch from
    /// the network: remote images deleted, remote backgrounds cleared. Done
    /// on a parsed document (never on markup with regexes) by a QTextDocument
    /// that answers every resource request with nothing, so the parse itself
    /// is side-effect free. Only data:, file: and cid: references survive.
    static QString stripRemoteContent(const QString &html);

    QQuickTextDocument *document() const { return m_document; }
    void setDocument(QQuickTextDocument *document);

    int cursorPosition() const { return m_cursorPosition; }
    void setCursorPosition(int position);
    int selectionStart() const { return m_selectionStart; }
    void setSelectionStart(int position);
    int selectionEnd() const { return m_selectionEnd; }
    void setSelectionEnd(int position);

    bool bold() const;
    void setBold(bool bold);
    bool italic() const;
    void setItalic(bool italic);
    int fontSize() const;
    void setFontSize(int size);

    Q_INVOKABLE void toggleBulletList();
    Q_INVOKABLE void toggleOrderedList();

    /// Turns a "-" or "*" written on its own at the start of a block into a
    /// bulleted list, swallowing the space that triggered it. Returns true when
    /// it did, so the caller can eat the key press.
    Q_INVOKABLE bool startBulletList();

    /// Same for a number written at the start of a block, triggered by the
    /// terminator being typed after it ("." or ")") rather than by a following
    /// space. The terminator is kept as the list's number suffix.
    Q_INVOKABLE bool startOrderedList(const QString &terminator);

    /// Leaves the list when Return is pressed on an empty item — the second of
    /// the two Enters that ends a list. Returns true when it did.
    Q_INVOKABLE bool leaveEmptyListItem();

    /// Tab and Shift+Tab inside a list: one level in, one level out. False when
    /// the cursor is not in a list, leaving Tab to move focus as usual.
    Q_INVOKABLE bool indentListItem();
    Q_INVOKABLE bool outdentListItem();

    /// Backspace at the start of a list item: out one level, and out of the
    /// list itself from the outermost one.
    Q_INVOKABLE bool outdentAtBlockStart();

    /// Ctrl+Shift+V: inserts the clipboard as unformatted text, taking the
    /// formatting of the text it lands in rather than dragging the source
    /// document's fonts and colors into the message. False when the clipboard
    /// holds no text, so the caller can leave the key press alone.
    Q_INVOKABLE bool pastePlainText();

    /// Ctrl+V when the clipboard holds a picture: inserts it into the body at
    /// the cursor rather than leaving "attach a file" as the only way to send
    /// one. False when the clipboard holds no image, so the caller can let the
    /// ordinary text paste happen.
    ///
    /// The bytes are written to a file of this handler's own (deleted with the
    /// composer) and referenced from the document, because that is the only
    /// kind of image reference a QTextDocument renders; composeMessage() turns
    /// those references into cid: parts when the message is built.
    Q_INVOKABLE bool pasteImage();

    /// Whether pasteImage() would do anything — for the "Paste image" hint.
    Q_INVOKABLE bool clipboardHasImage() const;

    /// The document's edit revision — bumped by every change, free to read.
    /// The composer's modified check compares this instead of body text:
    /// serializing a newsletter-sized document back to HTML just to compare
    /// strings blocks the GUI for the better part of a second.
    Q_INVOKABLE int documentRevision() const
    {
        return m_document && m_document->textDocument()
            ? m_document->textDocument()->revision() : 0;
    }

    bool quoteStreaming() const { return !m_quoteChunks.isEmpty(); }
    /// Begins streaming a large reply/forward quote into the document: the
    /// chunks (structurally self-contained HTML, from the C++ splitter) are
    /// appended at the end of the document a time-boxed batch per event-loop
    /// tick, so the composer opens instantly and stays responsive while the
    /// quote fills in top-down. \a stripRemote applies stripRemoteContent()
    /// to each chunk right before insertion — per chunk, so even that never
    /// blocks a frame. Cancels any stream already running.
    Q_INVOKABLE void startQuoteStream(const QStringList &chunks, bool stripRemote);
    /// Drops whatever has not been inserted yet (composer reused or closed).
    Q_INVOKABLE void cancelQuoteStream();
    /// Inserts everything still pending, synchronously — for Send and Save
    /// as draft, which read the body and must not read half a quote.
    Q_INVOKABLE void flushQuoteStream();

    /// Starts background downloads of \a html's remote images (a deferred
    /// forward with remote content allowed), so embedFetchedImages() can
    /// embed them at send time. Fire-and-forget; capped.
    Q_INVOKABLE void prefetchQuoteImages(const QString &html);
    /// Rewrites \a html's remote image sources that finished downloading to
    /// their local files — composeMessage() then embeds them as cid: parts.
    /// Images still in flight or failed keep their remote src: the send never
    /// waits on the network, it degrades per image instead.
    Q_INVOKABLE QString embedFetchedImages(const QString &html);

Q_SIGNALS:
    /// The whole quote is in (also after a flush). Not emitted on cancel.
    void quoteStreamFinished();
    /// The first chunk is in the document — the moment to put the caret back
    /// at the top if the insert dragged it along (empty document, caret at 0).
    void quoteStreamContentArrived();
    void quoteStreamingChanged();
    /// A pasted image was not inserted, with a line saying why. Nothing else
    /// reports it: the paste simply appears not to have happened otherwise.
    void imagePasteFailed(const QString &message);

    void documentChanged();
    void cursorPositionChanged();
    void selectionStartChanged();
    void selectionEndChanged();
    void formatChanged();

private:
    QTextCursor textCursor() const;
    bool atBlockStart(const QTextCursor &cursor) const;
    void mergeFormat(const QTextCharFormat &format);
    void toggleList(int listStyle);
    void applyMarkerList(QTextCursor &cursor, const QTextListFormat &listFormat);
    bool changeListIndent(int delta);
    /// Writes \a data into the scratch directory and inserts it at the cursor.
    /// \a suffix is the file extension the format wants.
    bool insertImage(const QByteArray &data, const QString &suffix);

    /// One time-boxed batch of quote chunks; \a all inserts every remaining one.
    void streamQuoteBatch(bool all);
    /// Resolves \a chunk's remote images to downloaded local files, in place.
    /// False = downloads still in flight, insert nothing yet. \a flush skips
    /// waiting: unresolved images keep their remote src (send semantics
    /// unchanged) instead of holding up a Send.
    bool resolveChunkImages(QString &chunk, bool flush);
    /// Starts (or reuses) the download of one remote image URL.
    void fetchRemoteImage(const QString &url);

    QQuickTextDocument *m_document = nullptr;
    QStringList m_quoteChunks;      ///< still to insert, in document order
    bool m_quoteStripRemote = false;
    int m_quoteTotalChunks = 0;     ///< for progress logging
    qint64 m_quoteStreamMs = 0;     ///< accumulated insertion time, logged at end
    QTextCursor m_quoteCursor;      ///< end of the streamed quote so far

    // Remote images of a quote whose remote content the user allowed: the
    // editor must still never see an http: src (Qt Quick's render thread
    // would start the load itself and block scene-graph sync for seconds),
    // so they are downloaded here and the chunks rewritten to file: before
    // insertion. composeMessage() then embeds them on send.
    class QNetworkAccessManager *m_network = nullptr;
    QHash<QString, QString> m_remoteImageCache; ///< url -> local file; "" = failed
    QHash<QString, class QNetworkReply *> m_remoteImageReplies;
    std::unique_ptr<QTemporaryDir> m_remoteImageDir;
    int m_remoteImageCount = 0;
    class QTimer *m_remoteImageTimeout = nullptr;
    /// Holds the pasted images until the composer closes. Created on the first
    /// paste — a composer that never sees one leaves nothing behind.
    std::unique_ptr<QTemporaryDir> m_imageDir;
    int m_imageCount = 0;
    int m_cursorPosition = -1;
    int m_selectionStart = 0;
    int m_selectionEnd = 0;
};
