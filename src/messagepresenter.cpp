// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "messagepresenter.h"

#include "messagecontext.h"
#include "mimeutils.h"
#include "viewersecurity.h"

#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocale>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTextDocumentFragment>

#include <kmime/content.h>
#include <kmime/message.h>

#include <utility>

MessagePresenter::MessagePresenter(QObject *parent)
    : QObject(parent)
{
}

/// Strips the parts of a sender-supplied filename that can misrepresent what
/// the file is: directory components, C0/C1 control characters, and the Unicode
/// direction overrides that make "invoice<U+202E>cod.exe" render as
/// "invoiceexe.doc" in every label we put it in.
static QString sanitizeFileName(const QString &raw)
{
    QString out;
    out.reserve(raw.size());
    for (const QChar c : raw) {
        const char16_t u = c.unicode();
        const bool bidiControl = (u >= 0x202A && u <= 0x202E) // LRE…RLO, PDF
            || (u >= 0x2066 && u <= 0x2069)                   // LRI…PDI
            || u == 0x200E || u == 0x200F || u == 0x061C;     // LRM, RLM, ALM
        if (u < 0x20 || (u >= 0x7F && u <= 0x9F) || bidiControl)
            continue;
        out.append(c == QLatin1Char('/') || c == QLatin1Char('\\') ? QLatin1Char('_') : c);
    }
    out = out.trimmed();
    while (out.startsWith(QLatin1Char('.'))) // no hidden files, no "." or ".."
        out.remove(0, 1);
    return out.left(200); // stay under NAME_MAX once a suffix is appended
}

void MessagePresenter::collectAttachments(MessageContext *ctx, KMime::Content *root)
{
    ctx->m_attachmentParts.clear();
    ctx->m_attachments.clear();
    const auto parts = root->attachments();
    for (KMime::Content *part : parts) {
        QString name;
        if (const auto *cd = std::as_const(*part).contentDisposition())
            name = cd->filename();
        if (name.isEmpty()) {
            if (const auto *ct = std::as_const(*part).contentType())
                name = ct->name();
        }
        // Sanitize once, here, so the list label, the confirmation dialog, the
        // risky-extension check and the on-disk name all agree on one string.
        name = sanitizeFileName(QFileInfo(name).fileName());
        if (name.isEmpty())
            name = tr("attachment %1").arg(ctx->m_attachmentParts.size() + 1);

        ctx->m_attachmentParts.append(part);
        ctx->m_attachments.append(QVariantMap{
            {QStringLiteral("name"), name},
            {QStringLiteral("sizeText"), QLocale().formattedDataSize(part->decodedBody().size())},
        });
    }
}


/// Escapes \a text for HTML with web links wrapped in anchors, so the
/// plain-text view gets clickable URLs. Detection runs on the raw text and
/// each piece is escaped separately — a match on already-escaped text would
/// trip over the &amp; entities inside query strings. Only ever produces
/// http(s) hrefs, and the viewer opens link clicks externally anyway (the
/// WebEngineView never navigates), so this adds no surface beyond the text.
static QString escapeAndLinkify(const QString &text)
{
    static const QRegularExpression urlRe(
        QStringLiteral("\\b(?:https?://|www\\.)[^\\s<>\"]+"),
        QRegularExpression::CaseInsensitiveOption);
    QString out;
    out.reserve(text.size() + text.size() / 8);
    qsizetype pos = 0;
    auto it = urlRe.globalMatch(text);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        QString url = m.captured();
        // Trailing punctuation belongs to the sentence, not the URL —
        // "see https://a.b/c." must not link the dot. Brackets only come off
        // while unbalanced, so Wikipedia-style "…/Foo_(bar)" paths survive.
        static const QString trailing = QStringLiteral(".,;:!?'\"");
        while (!url.isEmpty()) {
            const QChar last = url.back();
            if (trailing.contains(last)) {
                url.chop(1);
                continue;
            }
            if ((last == QLatin1Char(')')
                 && url.count(QLatin1Char('(')) < url.count(QLatin1Char(')')))
                || (last == QLatin1Char(']')
                    && url.count(QLatin1Char('[')) < url.count(QLatin1Char(']')))) {
                url.chop(1);
                continue;
            }
            break;
        }
        // "www." alone (or all-punctuation leftovers) is not a link.
        if (url.length() <= 4) {
            out += text.mid(pos, m.capturedEnd() - pos).toHtmlEscaped();
            pos = m.capturedEnd();
            continue;
        }
        out += text.mid(pos, m.capturedStart() - pos).toHtmlEscaped();
        const QString href = url.startsWith(QLatin1String("www."), Qt::CaseInsensitive)
            ? QStringLiteral("https://") + url
            : url;
        out += QStringLiteral("<a href=\"") + href.toHtmlEscaped() + QStringLiteral("\">")
            + url.toHtmlEscaped() + QStringLiteral("</a>");
        pos = m.capturedStart() + url.size();
    }
    out += text.mid(pos).toHtmlEscaped();
    return out;
}

static QByteArray preformattedPage(const QString &content, bool monospace, bool linkify = false)
{
    // Same CSP as the HTML view, minus the remote opt-in: these pages are built
    // from escaped text and reference nothing, so the policy costs nothing and
    // means the Text and Source views are not the two documents in the app
    // running without one. Remote content is never allowed here — there is no
    // per-message toggle behind a view whose whole content is escaped text.
    return QByteArrayLiteral("<html><head><meta charset=\"utf-8\">") + messageCsp(false)
        + QByteArrayLiteral("</head><body><pre style=\""
                             "white-space:pre-wrap;word-break:break-word;font-family:")
        + (monospace ? QByteArrayLiteral("monospace") : QByteArrayLiteral("sans-serif"))
        + QByteArrayLiteral(";\">")
        + (linkify ? escapeAndLinkify(content) : content.toHtmlEscaped()).toUtf8()
        + QByteArrayLiteral("</pre></body></html>");
}


void MessagePresenter::collectInlineParts(MessageContext *ctx, KMime::Content *root)
{
    if (const auto *cid = std::as_const(*root).contentID(); cid && !cid->identifier().isEmpty()) {
        const auto *ct = std::as_const(*root).contentType();
        m_handler->setInlinePart(ctx->viewerContext(),
                                       QString::fromLatin1(cid->identifier()),
                                       ct ? ct->mimeType() : QByteArray(),
                                       root->decodedBody());
    }
    const auto children = root->contents();
    for (KMime::Content *child : children)
        collectInlineParts(ctx, child);
}


QString MessagePresenter::htmlViewUrl(MessageContext *ctx)
{
    if (!m_handler)
        return {};
    ctx->m_handler = m_handler;
    if (ctx->m_htmlBody.isEmpty())
        return textViewUrl(ctx);
    // Strip scripting hooks and embedded documents before anything else looks
    // at the markup. Backed by the CSP below — see sanitizeMessageHtml().
    QString html = sanitizeMessageHtml(ctx->m_htmlBody);
    // Point inline references at our scheme handler — but only actual
    // src/href attributes and CSS url() values, not arbitrary body text.
    static const QRegularExpression attrCidRe(
        QStringLiteral("((?:src|href|background)\\s*=\\s*[\"'])cid:"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression cssCidRe(
        QStringLiteral("(url\\(\\s*[\"']?)cid:"), QRegularExpression::CaseInsensitiveOption);
    const QString cidBase =
        QStringLiteral("\\1mailove:cid/") + QString::number(ctx->viewerContext())
        + QLatin1Char('/');
    html.replace(attrCidRe, cidBase);
    html.replace(cssCidRe, cidBase);
    return m_handler->setMessageHtml(
        ctx->viewerContext(),
        QByteArrayLiteral("<meta charset=\"utf-8\">")
            + messageCsp(ctx->remoteContentAllowed()) + html.toUtf8());
}

QString MessagePresenter::textViewUrl(MessageContext *ctx)
{
    if (!m_handler)
        return {};
    ctx->m_handler = m_handler;
    QString text = ctx->m_textBody;
    if (text.isEmpty() && !ctx->m_htmlBody.isEmpty()) {
        // HTML-only message: show its stripped text — the junk folders'
        // text-only default must not degrade to an empty stub.
        text = QTextDocumentFragment::fromHtml(ctx->m_htmlBody.left(500000))
                   .toPlainText();
    }
    if (text.isEmpty())
        text = tr("(this message has no displayable text part)");
    // Monospace: plain-text mail (patches, tables, ASCII art — the Bugzilla
    // change tables are the classic case) is written for a fixed-width grid
    // and falls apart in a proportional font. Linkified so URLs are clickable
    // like in the HTML view; the source view stays verbatim.
    return m_handler->setMessageHtml(ctx->viewerContext(),
                                           preformattedPage(text, true, true));
}

QString MessagePresenter::sourceViewUrl(MessageContext *ctx)
{
    if (!m_handler)
        return {};
    ctx->m_handler = m_handler;
    // Always the complete raw RFC-822 message — headers, MIME structure and
    // every part, verbatim. Showing just the HTML part here (as this once
    // did) left HTML mail with a "source" view that had no headers at all.
    return m_handler->setMessageHtml(
        ctx->viewerContext(), preformattedPage(QString::fromUtf8(ctx->m_raw), true));
}


QString MessagePresenter::attachmentName(const MessageContext *ctx, int index) const
{
    // Basename only — a hostile filename must not traverse directories — and
    // sanitized again so this never depends on collectAttachments() having run.
    const QString name = sanitizeFileName(
        QFileInfo(ctx->m_attachments.at(index).toMap().value(QStringLiteral("name")).toString())
            .fileName());
    return name.isEmpty() ? QStringLiteral("attachment") : name;
}

bool MessagePresenter::writeAttachment(const MessageContext *ctx, int index, const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        Q_EMIT errorOccurred(tr("Could not write %1: %2").arg(path, file.errorString()));
        return false;
    }
    file.write(ctx->m_attachmentParts.at(index)->decodedBody());
    return true;
}

void MessagePresenter::saveAttachment(MessageContext *ctx, int index, const QUrl &fileUrl)
{
    if (index < 0 || index >= ctx->m_attachmentParts.size())
        return;
    if (writeAttachment(ctx, index, fileUrl.toLocalFile()))
        Q_EMIT statusMessage(tr("Saved %1").arg(QFileInfo(fileUrl.toLocalFile()).fileName()));
}

bool MessagePresenter::attachmentRisky(const MessageContext *ctx, int index) const
{
    if (index < 0 || index >= ctx->m_attachmentParts.size())
        return false;
    const QString name =
        ctx->m_attachments.at(index).toMap().value(QStringLiteral("name")).toString().toLower();
    static const QStringList riskyExtensions = {
        // Shells and interpreters
        QStringLiteral(".sh"),        QStringLiteral(".bash"),    QStringLiteral(".zsh"),
        QStringLiteral(".ksh"),       QStringLiteral(".csh"),     QStringLiteral(".fish"),
        QStringLiteral(".py"),        QStringLiteral(".pyc"),     QStringLiteral(".pyo"),
        QStringLiteral(".pl"),        QStringLiteral(".rb"),      QStringLiteral(".lua"),
        QStringLiteral(".php"),       QStringLiteral(".tcl"),     QStringLiteral(".awk"),
        // Native executables and libraries
        QStringLiteral(".run"),       QStringLiteral(".bin"),     QStringLiteral(".elf"),
        QStringLiteral(".so"),        QStringLiteral(".out"),     QStringLiteral(".exe"),
        QStringLiteral(".dll"),       QStringLiteral(".scr"),     QStringLiteral(".com"),
        QStringLiteral(".pif"),       QStringLiteral(".cpl"),     QStringLiteral(".msc"),
        // Packages and installers — opening these hands off to a package tool
        QStringLiteral(".appimage"),  QStringLiteral(".flatpakref"),
        QStringLiteral(".flatpakrepo"), QStringLiteral(".snap"),  QStringLiteral(".deb"),
        QStringLiteral(".rpm"),       QStringLiteral(".msi"),     QStringLiteral(".msix"),
        QStringLiteral(".appx"),      QStringLiteral(".pkg"),     QStringLiteral(".dmg"),
        // Windows scripting hosts
        QStringLiteral(".bat"),       QStringLiteral(".cmd"),     QStringLiteral(".ps1"),
        QStringLiteral(".psm1"),      QStringLiteral(".vbs"),     QStringLiteral(".vbe"),
        QStringLiteral(".js"),        QStringLiteral(".jse"),     QStringLiteral(".wsf"),
        QStringLiteral(".wsh"),       QStringLiteral(".hta"),     QStringLiteral(".reg"),
        // Launchers and shortcuts — these run something else
        QStringLiteral(".desktop"),   QStringLiteral(".lnk"),     QStringLiteral(".url"),
        QStringLiteral(".appref-ms"), QStringLiteral(".jar"),     QStringLiteral(".jnlp"),
        // Mountable images: opening one exposes whatever is inside it
        QStringLiteral(".iso"),       QStringLiteral(".img"),     QStringLiteral(".vhd"),
        QStringLiteral(".vhdx"),      QStringLiteral(".udf")};
    for (const QString &ext : riskyExtensions) {
        if (name.endsWith(ext))
            return true;
    }
    // No extension at all: nothing tells the desktop what this is, so the
    // handler is decided by content sniffing. Treat it as needing confirmation.
    if (!name.contains(QLatin1Char('.')))
        return true;
    // Also honor what the sender *declared* — a lie either way is suspicious.
    const QByteArray mime = std::as_const(*ctx->m_attachmentParts.at(index)).contentType()
        ? std::as_const(*ctx->m_attachmentParts.at(index)).contentType()->mimeType().toLower()
        : QByteArray();
    return mime.contains("executable") || mime.contains("x-sharedlib")
        || mime.contains("x-desktop") || mime.contains("shellscript")
        || mime.contains("x-msdownload") || mime.contains("java-archive");
}

void MessagePresenter::openAttachment(MessageContext *ctx, int index)
{
    if (index < 0 || index >= ctx->m_attachmentParts.size())
        return;
    // A fixed path under /tmp is reachable by every other user on the machine:
    // they can pre-create the directory, plant a symlink at a plausible file
    // name so our write lands somewhere else, or swap the contents between the
    // write and the open. QTemporaryDir gives us a 0700 directory with an
    // unpredictable name, which closes all three. Process-lifetime static:
    // cleaned up on exit, and files must outlive this call so the handler
    // application can still read them.
    static QTemporaryDir tempDir(QDir::tempPath() + QStringLiteral("/mailove-attachments-XXXXXX"));
    if (!tempDir.isValid()) {
        Q_EMIT errorOccurred(tr("Could not create a private temporary directory: %1")
                                 .arg(tempDir.errorString()));
        return;
    }
    const QString path = tempDir.filePath(attachmentName(ctx, index));
    if (!writeAttachment(ctx, index, path))
        return;
    // Same as an external link: the application opening is the feedback.
    if (!QDesktopServices::openUrl(QUrl::fromLocalFile(path))) {
        Q_EMIT errorOccurred(tr("No application could open %1.")
                                 .arg(attachmentName(ctx, index)));
    }
}

void MessagePresenter::saveAttachmentToDownloads(MessageContext *ctx, int index)
{
    if (index < 0 || index >= ctx->m_attachmentParts.size())
        return;
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    QDir().mkpath(dir);

    const QFileInfo info(attachmentName(ctx, index));
    QString candidate = dir + QLatin1Char('/') + info.fileName();
    for (int i = 1; QFile::exists(candidate); ++i) {
        const QString suffix = info.completeSuffix().isEmpty()
            ? QString()
            : QLatin1Char('.') + info.completeSuffix();
        candidate = QStringLiteral("%1/%2 (%3)%4").arg(dir, info.baseName()).arg(i).arg(suffix);
    }
    if (writeAttachment(ctx, index, candidate))
        Q_EMIT statusMessage(tr("Saved to %1").arg(candidate));
}


void MessagePresenter::findAttachedKey(MessageContext *ctx, KMime::Content *root)
{
    const auto parts = root->attachments();
    for (KMime::Content *part : parts) {
        const auto *ct = std::as_const(*part).contentType();
        const QByteArray mime = ct ? ct->mimeType().toLower() : QByteArray();
        QString name;
        if (const auto *cd = std::as_const(*part).contentDisposition())
            name = cd->filename();
        if (name.isEmpty() && ct)
            name = ct->name();

        // The declared type, or an .asc/.gpg file whose contents say so. Many
        // clients attach keys as application/octet-stream.
        const bool declared = mime == "application/pgp-keys";
        const bool looksLikeKey = name.endsWith(QLatin1String(".asc"), Qt::CaseInsensitive)
            || name.endsWith(QLatin1String(".gpg"), Qt::CaseInsensitive)
            || name.endsWith(QLatin1String(".pgp"), Qt::CaseInsensitive);
        if (!declared && !looksLikeKey)
            continue;

        const QByteArray body = part->decodedBody();
        // A signature file also ends in .asc, and importing one does nothing;
        // only a key block is offered.
        if (!body.contains("BEGIN PGP PUBLIC KEY BLOCK") && !declared)
            continue;
        // Keys are small. Anything this size is not one, and refusing it here
        // keeps a hostile attachment out of gpg entirely.
        if (body.isEmpty() || body.size() > 1024 * 1024)
            continue;

        ctx->m_attachedKeyData = body;
        ctx->m_attachedKeyName = name.isEmpty() ? tr("public key") : name;
        return;
    }
}


/// Fills in everything the viewer renders from one MIME tree: the body parts,
/// the instant preview, the inline images and the attachment list.
///
/// Split out of presentMessage() because it runs twice for an encrypted
/// message — once over the ciphertext (which has nothing to show), and again
/// over the decrypted tree when gpg answers. \a root is the tree to read;
/// ctx->m_message stays the message as it arrived either way.
void MessagePresenter::applyBodyParts(MessageContext *ctx, KMime::Message *root, bool junk)
{
    const bool encrypted = ctx->m_cryptoState == QLatin1String("encrypted")
        || ctx->m_cryptoState == QLatin1String("decrypting")
        || ctx->m_cryptoState == QLatin1String("failed");
    // Nothing readable yet: the parts are ciphertext, and searching them for a
    // text/html would only find nothing and warn about it.
    const bool opaque = encrypted && !ctx->m_decrypted;

    KMime::Content *htmlPart = nullptr;
    KMime::Content *textPart = nullptr;
    if (!opaque) {
        htmlPart = root->mainBodyPart("text/html");
        if (!htmlPart)
            htmlPart = MimeUtils::findPartByType(root, "text/html");
        textPart = root->mainBodyPart("text/plain");
        if (!textPart)
            textPart = MimeUtils::findPartByType(root, "text/plain");
        if (!textPart && !htmlPart)
            textPart = root->textContent();
    }

    ctx->m_htmlBody = htmlPart ? htmlPart->decodedText() : QString();
    ctx->m_textBody = textPart ? textPart->decodedText() : QString();

    if (opaque) {
        // The viewer needs something to show while gpg works, or in place of a
        // message it could not open. This is the only body it gets — the
        // ciphertext is not put on screen as text.
        ctx->m_textBody = ctx->m_cryptoDetail.isEmpty()
            ? tr("Encrypted message")
            : ctx->m_cryptoDetail;
    } else if (ctx->m_htmlBody.isEmpty() && ctx->m_textBody.isEmpty()) {
        const auto *ct = std::as_const(*root).contentType();
        qWarning() << "mailove: no displayable part found. content-type:"
                   << (ct ? ct->mimeType() : QByteArrayLiteral("(none)"))
                   << "children:" << root->contents().size()
                   << "raw size:" << ctx->m_raw.size();
    }

    // Plain-text stand-in shown while Chromium renders the HTML view. Never
    // decrypted text: this string also reaches the message list, and the whole
    // point of §4 is that no plaintext leaves the viewer.
    QString preview;
    if (encrypted) {
        preview = tr("Encrypted message");
    } else if (!ctx->m_textBody.isEmpty()) {
        preview = ctx->m_textBody;
    } else {
        // Cap the input: stripping hundreds of KB of HTML would defeat the
        // purpose of an *instant* preview.
        preview = QTextDocumentFragment::fromHtml(ctx->m_htmlBody.left(100000)).toPlainText();
    }
    Q_EMIT previewTextChanged(preview);

    if (m_handler) {
        m_handler->clearInlineParts(ctx->viewerContext());
        if (!opaque)
            collectInlineParts(ctx, root);
    }
    ctx->m_attachedKeyName.clear();
    ctx->m_attachedKeyData.clear();
    if (opaque) {
        ctx->m_attachmentParts.clear();
        ctx->m_attachments.clear();
    } else {
        // For a decrypted message these parts live in ctx->m_decrypted, in
        // memory. They reach the disk only when the user saves one by hand —
        // the attachment store never sees them (doc/openpgp.md §4).
        collectAttachments(ctx, root);
        findAttachedKey(ctx, root);
    }

    ctx->m_bodyUrl = (htmlPart && !junk) ? htmlViewUrl(ctx) : textViewUrl(ctx);
}

