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

} // namespace MimeUtils
