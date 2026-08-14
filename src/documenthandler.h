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

public:
    using QObject::QObject;

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

Q_SIGNALS:
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

    QQuickTextDocument *m_document = nullptr;
    /// Holds the pasted images until the composer closes. Created on the first
    /// paste — a composer that never sees one leaves nothing behind.
    std::unique_ptr<QTemporaryDir> m_imageDir;
    int m_imageCount = 0;
    int m_cursorPosition = -1;
    int m_selectionStart = 0;
    int m_selectionEnd = 0;
};
