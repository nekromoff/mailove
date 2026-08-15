// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QObject>
#include <QString>
#include <QUrl>

class MessageContext;
class ViewerSchemeHandler;

namespace KMime
{
class Content;
class Message;
}

/**
 * Turns a parsed message into what the viewer shows, for one MessageContext.
 *
 * The reading pane and every detached window each own a context; this class
 * has none of its own. Everything it does is a function of the context handed
 * in, which is what lets a detached window keep rendering after the reading
 * pane has moved on to another message.
 *
 * Presentation only — no cache, no network, no crypto. Whether a message is
 * signed is MessageVerifier's question; this class renders whatever verdict
 * it finds already on the context.
 */
class MessagePresenter : public QObject
{
    Q_OBJECT
public:
    explicit MessagePresenter(QObject *parent = nullptr);

    /// The scheme handler that serves message bodies to the viewer. Null until
    /// main.cpp installs one, and every path here checks.
    void setViewerHandler(ViewerSchemeHandler *handler) { m_handler = handler; }

    /// Fills \a ctx's body, preview, inline parts and attachments from \a root.
    /// Runs a second time, over the decrypted tree, for an encrypted message.
    /// \a junk forces the plain-text view, as junk folders do.
    void applyBodyParts(MessageContext *ctx, KMime::Message *root, bool junk);

    /// Rendered HTML view; falls back to the text part when there is no HTML.
    QString htmlViewUrl(MessageContext *ctx);
    /// Plain-text part of the message ("discard HTML").
    QString textViewUrl(MessageContext *ctx);
    /// The complete raw RFC-822 message, escaped and monospace.
    QString sourceViewUrl(MessageContext *ctx);

    /// True when the attachment could execute code if opened (.sh, .desktop,
    /// AppImage, .exe, …) — the UI shows a confirmation first.
    bool attachmentRisky(const MessageContext *ctx, int index) const;
    /// Writes attachment \a index to \a fileUrl.
    void saveAttachment(MessageContext *ctx, int index, const QUrl &fileUrl);
    /// Opens attachment \a index with the system handler (via a temp copy).
    void openAttachment(MessageContext *ctx, int index);
    /// Saves attachment \a index into ~/Downloads under its own filename,
    /// deduplicating ("name (1).pdf") instead of overwriting.
    void saveAttachmentToDownloads(MessageContext *ctx, int index);
    /// Writes every attachment out as a temp file and returns their URLs, so a
    /// forward can pre-fill the composer's attachment list — composeMessage()
    /// reads them back into parts on send.
    QList<QUrl> exportAttachments(MessageContext *ctx);

    /// Offers a public key attached to the message, if there is one.
    void findAttachedKey(MessageContext *ctx, KMime::Content *root);
    /// Registers \a root's cid: parts with the scheme handler under \a ctx's
    /// own slot. Public because a detached window re-registers the parts it
    /// inherited, so it keeps rendering once the reading pane moves on.
    void collectInlineParts(MessageContext *ctx, KMime::Content *root);

    /// Renders \a ctx's HTML into a slot of its own for the composer's
    /// read-only quote preview — the same sanitize/CSP/cid pipeline the
    /// viewer uses, so a deferred quote previews with full fidelity.
    /// Allocates *slot on first use; the caller keeps it alive until
    /// releasePreviewSlot(). Empty when the message has no HTML part.
    QString composePreviewUrl(MessageContext *ctx, quint64 *slot);
    void releasePreviewSlot(quint64 slot);

Q_SIGNALS:
    void statusMessage(const QString &text);
    void errorOccurred(const QString &message);
    /// The instant plain-text stand-in for the message just applied, shown
    /// while the HTML view renders.
    void previewTextChanged(const QString &text);

private:
    /// Sanitized basename of attachment \a index — the one string the label,
    /// the confirmation dialog and the on-disk name all agree on.
    QString attachmentName(const MessageContext *ctx, int index) const;
    void collectAttachments(MessageContext *ctx, KMime::Content *root);
    void registerInlineParts(quint64 slot, KMime::Content *root);
    bool writeAttachment(const MessageContext *ctx, int index, const QString &path);

    ViewerSchemeHandler *m_handler = nullptr;
};
