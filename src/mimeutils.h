// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

#include <functional>

#include "mailstore.h"

namespace KMime
{
class Content;
class Message;
}

/**
 * MIME tree operations with no state and no policy: finding a part, numbering
 * parts, and the attachment split/restore pair the cache is built on.
 *
 * Free functions on purpose — the attachment round trip is the one piece of
 * cache behaviour that can be checked without a mailbox, a connection or a
 * MailClient, and keeping it here is what makes that possible.
 */
namespace MimeUtils
{

/// Depth-first search of the whole MIME tree — mainBodyPart() misses parts
/// nested in structures like multipart/mixed → multipart/related → text/html.
KMime::Content *findPartByType(KMime::Content *root, const char *mimeType);

/// Walks the MIME tree in a fixed order, numbering parts "1", "2", "2.1", …
/// Split and restore both walk it the same way, so a part id written today
/// still identifies the same node when the message is read back.
void walkParts(KMime::Content *node, const QString &prefix,
               const std::function<void(KMime::Content *, const QString &)> &fn);

/// True for a part whose payload is an attachment rather than the message
/// text — the only thing worth lifting out into the file store.
bool isAttachmentPart(KMime::Content *part);

/// Replaces every large attachment payload with an empty body, returning the
/// parts that were lifted out. The message keeps all of its headers — notably
/// Authentication-Results, which is what the SPF/DKIM display reads — so the
/// stub stays a valid, self-describing MIME message.
QList<MailStore::PartRef> stripAttachments(KMime::Message *msg);

/// Puts the payloads back into a parsed stub. Bodies are stored decoded, so
/// the transfer encoding is rewritten to match rather than re-encoding to
/// base64: every consumer reads decodedContent(), and this keeps the read
/// path allocation-cheap. A payload missing from disk leaves that part empty,
/// which the caller treats as a cache miss.
bool restoreAttachments(KMime::Message *msg, const QList<MailStore::PartRef> &parts);

/// Fixes a part whose Content-Transfer-Encoding says base64 while its body is
/// plainly not — a delivery path (a milter that rewrites bodies, a broken
/// gateway) decoded the content and left the header alone. KMime would then
/// base64-decode raw HTML into a few bytes of noise, and that is what the
/// reader would see. Such a part is re-labelled binary so it reads as-is. The
/// wire bytes are untouched: a frozen message still answers encodedContent()
/// with what arrived, and the DKIM verdict keeps judging that.
///
/// Must run straight after parse(), before anything reads a body: KMime
/// decodes in place on first access, and a body already "decoded" under the
/// wrong label is noise that cannot be told from real binary.
void repairTransferEncodings(KMime::Content *node);

/// parse() only where it would create something: a multipart or encapsulated
/// message with no children yet. The "contents().isEmpty() ? parse()" guard
/// this replaces was wrong for every single-part message — a leaf never has
/// contents, so it was parsed again by each consumer, and parse() rebuilds
/// every header from the raw head text, undoing repairTransferEncodings().
/// A leaf that was never parsed needs no parse: KMime reads its headers from
/// the head text on demand.
void parseIfNeeded(KMime::Content *node);

/// The text of \a field as it should read, for a message whose encoded word
/// lies about its charset: "=?us-ascii?Q?Vr=C3=A1tenie?=" carries UTF-8 under
/// a label that cannot hold it, and KMime — obeying the label, as it must —
/// hands back a replacement character per byte ("Vr??tenie"). The raw head is
/// re-read, the lying label corrected to the encoding the bytes actually are,
/// and the word decoded again. \a decoded is returned untouched whenever
/// nothing in the header lies, which is every ordinary message.
///
/// Display only. Nothing is written back to the message: the head text is what
/// the DKIM verdict is computed over and what the cache stores, and a client
/// that rewrote it would be answering for bytes it changed. The scorer reads
/// the raw fields itself for the same reason — the false charset is evidence
/// there, not a defect to be tidied away.
QString repairedHeaderText(const KMime::Message *msg, QByteArrayView field,
                           const QString &decoded);

/// The first text/plain and text/html parts, decoded. Used by the spam scorer
/// and by tests/spamtool, which must see the same two strings or the tool stops
/// measuring what the client does.
void collectBodies(KMime::Content *node, QString *text, QString *html);

/// Filenames of the parts that present themselves as attachments. Name only:
/// the scorer judges what a part *claims* to be, which is the same thing the
/// reader is being invited to click.
void collectAttachments(KMime::Content *node, QStringList *names);

/// True when any attached archive needs a password to open.
///
/// Reads the ZIP local file headers directly rather than shelling out to an
/// unpacker: the question is one bit wide (general-purpose flag bit 0) and
/// answering it must not run anything over untrusted bytes. Non-ZIP containers
/// answer false — 7z and RAR encryption is not readable this cheaply, and a
/// missed rule is the safe direction here.
bool hasEncryptedArchive(KMime::Content *node);

/// Confirms that a stub plus its stored payloads reproduces the original
/// parts. Used before the migration overwrites a cached message: the payload
/// has just made a round trip through hashing, zstd and the filesystem, and
/// the original bytes are about to be gone.
bool verifyRoundTrip(const QByteArray &stub, const QList<MailStore::PartRef> &parts,
                     QString *reason);

/// One image the composer embedded in the body, on its way out as a MIME part.
struct InlineImage {
    QString path; ///< local file the editor referenced
    QByteArray contentId; ///< generated here, without angle brackets
};

/// Turns the local-file image references a rich-text composer writes
/// (<img src="file:///…">) into cid: references, and says which files they
/// were. The editor can only render an image it can open, so a pasted one
/// lives in a file until the message is built; a receiving client can only
/// render one that travels with the message, which is what cid: means.
///
/// \a html is rewritten in place. The same file referenced twice gets one
/// Content-ID and one part. \a idDomain is the right-hand side of the
/// generated IDs — the sender's domain, so they are globally unique the way
/// RFC 2045 asks. Images referenced by anything other than a local file
/// (http:, data:, an existing cid:) are left exactly as they are.
QList<InlineImage> takeInlineImages(QString &html, const QString &idDomain);

/// Caps runs of blank lines at two — text renditions of layout-table mail
/// pad the content with dozens of them. Whitespace-only lines count as
/// blank. Used by every plain-text rendering: the viewer's text view, the
/// reply/forward text quote, and anything else that shows a text part.
QString condenseBlankLines(QString text);

/// HTML to plain text with the link targets kept: "click here" becomes
/// "click here (https://…)". QTextDocument::toPlainText() drops every href —
/// the URL lives in the character format, not in the text — so this walks
/// the parsed document's fragments instead. Links whose visible text already
/// is the target (bare URLs, mailto: on the address itself) stay bare, and
/// image-only links stay silent — text renderings are for reading, not an
/// inventory of every button. Callers cap the input themselves and run
/// condenseBlankLines() after, as with any text rendering.
QString plainTextWithLinks(const QString &html);

/// Strips table scaffolding from generated Markdown: separator rows and
/// empty cells vanish, cells with content unwrap into plain lines. Mail
/// tables are layout, not data — QTextDocument::toMarkdown() renders them
/// as `|`-furniture that reads as garbage wherever it is pasted.
QString flattenMarkdownTables(const QString &markdown);

/// HTML to GitHub-dialect Markdown, as both "Copy as Markdown" actions
/// produce it: the selection one converts what the renderer put on the
/// clipboard, the whole-message one converts the sanitized HTML part. Same
/// output for the same markup, which is the point of them sharing this.
///
/// Images are dropped, keeping their alt text. A mail's images are either
/// cid: parts — whose references mean nothing once the text leaves mailove —
/// or remote URLs, and pasting those into a document that fetches them would
/// hand the sender the read receipt the viewer spent its remote-content
/// policy refusing. Neither survives the paste usefully, so neither goes.
QString htmlToMarkdown(const QString &html);

} // namespace MimeUtils
