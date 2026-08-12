// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pgpmime.h"

#include <KMime/Content>
#include <KMime/Headers>
#include <KMime/Util>

#include <QSet>

namespace
{
const char kPgpMessageBegin[] = "-----BEGIN PGP MESSAGE-----";
const char kPgpMessageEnd[] = "-----END PGP MESSAGE-----";

QByteArray mimeTypeOf(KMime::Content *c)
{
    if (!c)
        return {};
    const auto *ct = std::as_const(*c).contentType();
    return ct ? ct->mimeType().toLower() : QByteArray();
}

/// The protocol parameter, lowercased. RFC 3156 requires it on both
/// multipart/encrypted and multipart/signed, and a message without it is not
/// one we will treat as OpenPGP: guessing from the part types alone is how a
/// message gets a badge its structure does not support.
QString protocolOf(KMime::Content *c)
{
    if (!c)
        return {};
    const auto *ct = std::as_const(*c).contentType();
    return ct ? ct->parameter("protocol").toLower() : QString();
}

/// The armored PGP MESSAGE block in \a text, but only when the block is the
/// whole of it. Armor with a covering note above it, or a signature block
/// below, is deliberately refused: decrypting the middle of a message and
/// showing it next to the sender's own plaintext is the MIME-mixing spoof in
/// its oldest form, and we would have no way to mark which half was which.
QByteArray wholeArmoredBlock(const QByteArray &text)
{
    const QByteArray trimmed = text.trimmed();
    if (!trimmed.startsWith(kPgpMessageBegin))
        return {};
    const qsizetype end = trimmed.lastIndexOf(kPgpMessageEnd);
    if (end < 0)
        return {};
    // Nothing but whitespace may follow the end line.
    const QByteArray tail =
        trimmed.mid(end + qstrlen(kPgpMessageEnd)).trimmed();
    if (!tail.isEmpty())
        return {};
    return trimmed;
}

/// Does any part of this tree carry OpenPGP that the top level did not
/// declare? That is a partially encrypted message, which we show as such
/// rather than decrypting a fragment of.
bool hasNestedOpenPgp(KMime::Content *root)
{
    const auto children = root->contents();
    for (KMime::Content *child : children) {
        const QByteArray type = mimeTypeOf(child);
        if (type == "multipart/encrypted" || type == "application/pgp-encrypted")
            return true;
        if (type == "text/plain"
            && !wholeArmoredBlock(child->decodedBody()).isEmpty())
            return true;
        if (hasNestedOpenPgp(child))
            return true;
    }
    return false;
}

/// Every descendant of \a root that is a multipart/encrypted.
void collectEncryptedParts(KMime::Content *root, QList<KMime::Content *> &out)
{
    const auto children = root->contents();
    for (KMime::Content *child : children) {
        if (mimeTypeOf(child) == "multipart/encrypted")
            out.append(child);
        else
            collectEncryptedParts(child, out);
    }
}

/// Everything at or below \a root, so a part can be tested for being inside it.
void collectSubtree(KMime::Content *root, QSet<KMime::Content *> &out)
{
    out.insert(root);
    const auto children = root->contents();
    for (KMime::Content *child : children)
        collectSubtree(child, out);
}

/// The text a reader would actually see in an HTML part. Markup is not
/// content: Gmail sends "<div dir=\"ltr\"></div>" as the body of a message
/// whose only real content is an encrypted attachment, and treating that as
/// something worth protecting the reader from would refuse the decryption.
QByteArray visibleHtmlText(const QByteArray &html)
{
    QByteArray text;
    bool inTag = false;
    for (char c : html) {
        if (c == '<')
            inTag = true;
        else if (c == '>')
            inTag = false;
        else if (!inTag)
            text.append(c);
    }
    // &nbsp; is whitespace to a reader, and an empty-looking body often has
    // one or two in it.
    text.replace("&nbsp;", " ");
    return text.trimmed();
}

/// True when \a c is a leaf a reader would see something in. An empty or
/// whitespace-only text part is not: clients routinely wrap an encrypted part
/// in a multipart/mixed next to a blank text/plain, and that blank is not
/// content anyone could be misled by.
bool carriesVisibleContent(KMime::Content *c)
{
    if (!c->contents().isEmpty())
        return false; // a container; its leaves are judged on their own
    const QByteArray type = mimeTypeOf(c);
    if (type == "text/html")
        return !visibleHtmlText(c->decodedBody()).isEmpty();
    if (type.startsWith("text/"))
        return !c->decodedBody().trimmed().isEmpty();
    // Anything else — an attachment, an image — is content beside the
    // encrypted part, and showing it under an "encrypted" badge is exactly the
    // mixing this guards against.
    return true;
}

/// Every descendant of \a root whose body *is* an armored PGP MESSAGE,
/// whatever it claims to be.
///
/// Not every encrypted message uses RFC 3156. Gmail with a browser extension —
/// and several mobile clients — attach the armor as a file instead:
/// text/plain or application/octet-stream named "encrypted.asc", base64
/// encoded, inside an ordinary multipart/mixed. There is no
/// multipart/encrypted anywhere in such a message, so it has to be recognised
/// by its content.
void collectArmoredParts(KMime::Content *root, QList<KMime::Content *> &out)
{
    const auto children = root->contents();
    if (children.isEmpty()) {
        if (!wholeArmoredBlock(root->decodedBody()).isEmpty())
            out.append(root);
        return;
    }
    for (KMime::Content *child : children)
        collectArmoredParts(child, out);
}

/// True when \a encrypted is the only thing in \a root carrying content, so
/// decrypting it means decrypting the whole of what the reader will see.
bool nothingVisibleBeside(KMime::Content *root, KMime::Content *encrypted)
{
    QSet<KMime::Content *> inside;
    collectSubtree(encrypted, inside);

    QList<KMime::Content *> queue{root};
    while (!queue.isEmpty()) {
        KMime::Content *c = queue.takeFirst();
        if (inside.contains(c))
            continue;
        if (c != root && carriesVisibleContent(c))
            return false;
        const auto children = c->contents();
        for (KMime::Content *child : children)
            queue.append(child);
    }
    return true;
}
}

namespace PgpMime
{

Structure classify(KMime::Content *root)
{
    Structure out;
    if (!root)
        return out;
    out.root = root;

    const QByteArray type = mimeTypeOf(root);
    const auto children = root->contents();

    if (type == "multipart/encrypted") {
        // RFC 3156 §4: exactly two parts, the first application/pgp-encrypted
        // with "Version: 1", the second the ciphertext. A message that does
        // not have that shape is not one we can decrypt, so it is not one we
        // will claim is encrypted either.
        if (protocolOf(root) == QLatin1String("application/pgp-encrypted")
            && children.size() == 2
            && mimeTypeOf(children.at(0)) == "application/pgp-encrypted") {
            out.kind = Kind::Encrypted;
            out.cipherPart = children.at(1);
            return out;
        }
        out.kind = Kind::Partial;
        return out;
    }

    if (type == "multipart/signed") {
        if (protocolOf(root) == QLatin1String("application/pgp-signature")
            && children.size() == 2
            && mimeTypeOf(children.at(1)) == "application/pgp-signature") {
            out.kind = Kind::Signed;
            out.signedPart = children.at(0);
            out.signaturePart = children.at(1);
            return out;
        }
        out.kind = Kind::Partial;
        return out;
    }

    // Legacy inline PGP. Receive-only: mailove never produces it.
    if (type == "text/plain" || type.isEmpty()) {
        const QByteArray body = root->decodedBody();
        const QByteArray block = wholeArmoredBlock(body);
        if (!block.isEmpty()) {
            out.kind = Kind::InlineEncrypted;
            out.inlineBlock = block;
            return out;
        }
        // Armor with the sender's own text around it. Refused as a unit —
        // see wholeArmoredBlock — but still worth saying so, because the
        // reader can see an encrypted block on screen and would otherwise be
        // left wondering why nothing happened to it.
        if (body.contains(kPgpMessageBegin)) {
            out.kind = Kind::Partial;
            return out;
        }
    }

    if (!children.isEmpty()) {
        // An encrypted part wrapped in a multipart/mixed is ordinary — plenty
        // of clients send that, usually with an empty text/plain beside it.
        // What makes a message "partly encrypted" is not the nesting, it is
        // sender content sitting *next to* the encrypted part: decrypt one
        // half and the reader has no way to tell which half was protected.
        // With nothing beside it there is nothing to confuse, and refusing to
        // decrypt would just be showing an empty message.
        QList<KMime::Content *> encryptedParts;
        collectEncryptedParts(root, encryptedParts);
        if (encryptedParts.size() == 1
            && nothingVisibleBeside(root, encryptedParts.first())) {
            Structure inner = classify(encryptedParts.first());
            if (inner.kind == Kind::Encrypted)
                return inner;
        }
        // The same question for armor attached as a file rather than wrapped
        // per RFC 3156 — see collectArmoredParts. Judged by the same rule: it
        // decrypts when it is the only thing carrying content.
        if (encryptedParts.isEmpty()) {
            QList<KMime::Content *> armored;
            collectArmoredParts(root, armored);
            if (armored.size() == 1 && nothingVisibleBeside(root, armored.first())) {
                out.kind = Kind::InlineEncrypted;
                out.inlineBlock = wholeArmoredBlock(armored.first()->decodedBody());
                return out;
            }
            if (!armored.isEmpty()) {
                out.kind = Kind::Partial;
                return out;
            }
        }

        if (!encryptedParts.isEmpty() || hasNestedOpenPgp(root)) {
            out.kind = Kind::Partial;
            return out;
        }
    }

    return out;
}

QByteArray ciphertext(const Structure &s)
{
    switch (s.kind) {
    case Kind::Encrypted:
        return s.cipherPart ? s.cipherPart->decodedBody() : QByteArray();
    case Kind::InlineEncrypted:
        return s.inlineBlock;
    default:
        return {};
    }
}

QByteArray signedOctets(const Structure &s)
{
    if (s.kind != Kind::Signed || !s.signedPart)
        return {};
    // RFC 3156 §5: the signature is over the part as it travels, with CRLF
    // line endings. Everything inside mailove holds messages LF-normalised
    // (KMime::CRLFtoLF on the way in), so the octets have to be put back the
    // way they were signed or nothing ever verifies. Normalising first makes
    // this idempotent whatever the tree happens to hold.
    //
    // What this still cannot promise is that encodedContent() reproduces the
    // part byte for byte — re-serialising from a parsed tree can reorder or
    // refold headers, the same fidelity problem the roadmap records for DKIM.
    // That is why a mismatch is reported as "not verified" and never as
    // "invalid" (doc/openpgp.md §3).
    return KMime::LFtoCRLF(KMime::CRLFtoLF(s.signedPart->encodedContent()));
}

QByteArray signedOctets(const QByteArray &raw, const Structure &s, bool *exact)
{
    if (exact)
        *exact = false;
    if (s.kind != Kind::Signed || !s.signedPart || !s.root || raw.isEmpty())
        return signedOctets(s);

    const auto *ct = std::as_const(*s.root).contentType();
    const QByteArray boundary = ct ? ct->boundary() : QByteArray();
    if (boundary.isEmpty())
        return signedOctets(s);

    // Work in the wire form throughout: the cache holds messages LF-normalised
    // and the delimiters have to be found in whatever form the slice will be
    // returned in, or the offsets do not line up.
    const QByteArray wire = KMime::LFtoCRLF(KMime::CRLFtoLF(raw));
    const QByteArray delimiter = "\r\n--" + boundary;

    // The opening delimiter may be the very first line of the body, in which
    // case there is no CRLF in front of it to match on.
    qsizetype first = wire.indexOf(delimiter);
    qsizetype partStart;
    if (first < 0) {
        if (!wire.startsWith(delimiter.mid(2)))
            return signedOctets(s);
        partStart = delimiter.size() - 2;
    } else {
        partStart = first + delimiter.size();
    }
    // Past the rest of the delimiter line (a transport may have appended
    // whitespace to it, which RFC 2046 allows).
    const qsizetype eol = wire.indexOf("\r\n", partStart);
    if (eol < 0)
        return signedOctets(s);
    partStart = eol + 2;

    // RFC 2046: the CRLF before the next delimiter belongs to the delimiter,
    // not to the part, so the slice stops before it.
    const qsizetype partEnd = wire.indexOf(delimiter, partStart);
    if (partEnd < 0 || partEnd <= partStart)
        return signedOctets(s);

    const QByteArray slice = wire.mid(partStart, partEnd - partStart);
    // A sanity check against slicing the wrong part out of a message whose
    // structure did not survive: what we cut must be the part we classified.
    // Compared on the body only — the headers are exactly what re-serialising
    // is liable to have changed, so requiring those to match would defeat the
    // purpose.
    const QByteArray body = s.signedPart->body();
    if (!body.isEmpty()) {
        const QByteArray flat = KMime::CRLFtoLF(slice);
        if (!flat.contains(KMime::CRLFtoLF(body).trimmed()))
            return signedOctets(s);
    }
    if (exact)
        *exact = true;
    return slice;
}

QByteArray signature(const Structure &s)
{
    if (s.kind != Kind::Signed || !s.signaturePart)
        return {};
    return s.signaturePart->decodedBody();
}

namespace
{
/// A header line that describes the body rather than the message. These travel
/// *inside* the OpenPGP wrapper; everything else stays outside it.
bool isContentHeader(const QByteArray &line)
{
    static const char *const kContent[] = {"content-type:", "content-transfer-encoding:",
                                           "content-disposition:", "content-id:",
                                           "content-description:"};
    const QByteArray lower = line.toLower();
    for (const char *h : kContent) {
        if (lower.startsWith(h))
            return true;
    }
    return false;
}

/// MIME-Version belongs to neither half: it describes the message as a whole,
/// and the wrapper emits its own. Carrying the original through would either
/// duplicate it on the outside or bury it inside a part where it means nothing.
bool isMimeVersion(const QByteArray &line)
{
    return line.toLower().startsWith("mime-version:");
}
}

bool looksLikeMimeEntity(const QByteArray &data)
{
    const QByteArray flat = KMime::CRLFtoLF(data);
    const qsizetype blank = flat.indexOf("\n\n");
    if (blank <= 0)
        return false; // no header/body separator: not an entity
    // Every line before the separator has to be a header, or the continuation
    // of one. One line of prose that happens to contain a colon is not enough
    // to treat a paragraph as a message.
    const QList<QByteArray> lines = flat.left(blank).split('\n');
    bool sawMimeHeader = false;
    for (const QByteArray &line : lines) {
        if (line.isEmpty())
            return false;
        if (line.startsWith(' ') || line.startsWith('\t')) {
            if (!sawMimeHeader)
                return false; // a continuation with nothing to continue
            continue;
        }
        const qsizetype colon = line.indexOf(':');
        if (colon <= 0)
            return false;
        // A header name is a token — no spaces in it.
        if (line.left(colon).contains(' '))
            return false;
        if (isContentHeader(line) || isMimeVersion(line))
            sawMimeHeader = true;
    }
    // Syntax alone cannot settle this: "Note:" is as valid a field name as
    // "Content-Type:", so a paragraph opening with one would parse as a header
    // block and a decrypted note would be rendered as an empty MIME entity.
    // What actually separates the two is *which* headers are there — a MIME
    // entity carries at least one Content-* or MIME-Version, and prose does
    // not. Requiring one costs nothing real: an entity without any of them
    // describes no body, so there would be nothing to render either way.
    return sawMimeHeader;
}

OutgoingParts splitForCrypto(const QByteArray &assembled)
{
    OutgoingParts out;
    const QByteArray wire = KMime::LFtoCRLF(KMime::CRLFtoLF(assembled));
    const qsizetype blank = wire.indexOf("\r\n\r\n");
    if (blank < 0)
        return out;

    const QByteArray head = wire.left(blank + 2); // keep the trailing CRLF
    const QByteArray body = wire.mid(blank + 4);

    QByteArray contentHeaders;
    QByteArray identity;
    // Unfolding matters: a continuation line belongs to whichever header it
    // continues, and misfiling one would put half a Content-Type outside the
    // wrapper.
    qsizetype pos = 0;
    bool inContent = false;
    bool dropping = false;
    while (pos < head.size()) {
        qsizetype eol = head.indexOf("\r\n", pos);
        if (eol < 0)
            eol = head.size();
        const QByteArray line = head.mid(pos, eol - pos + 2);
        const bool continuation = !line.isEmpty()
            && (line.startsWith(' ') || line.startsWith('\t'));
        if (!continuation) {
            dropping = isMimeVersion(line);
            inContent = isContentHeader(line);
        }
        if (!dropping)
            (inContent ? contentHeaders : identity).append(line);
        pos = eol + 2;
    }

    out.identityHeaders = identity;
    out.contentPart = contentHeaders + "\r\n" + body;
    out.valid = !out.contentPart.isEmpty();
    return out;
}

QByteArray buildSigned(const OutgoingParts &parts, const QByteArray &signature,
                       const QString &micalg)
{
    if (!parts.valid || signature.isEmpty())
        return {};
    // Not KMime::multiPartBoundary(): the boundary must not appear anywhere in
    // the signed octets, and this one is checked against them.
    QByteArray boundary = KMime::multiPartBoundary();
    while (parts.contentPart.contains(boundary))
        boundary = KMime::multiPartBoundary();

    QByteArray out = parts.identityHeaders;
    out += "MIME-Version: 1.0\r\n";
    out += "Content-Type: multipart/signed; boundary=\"" + boundary + "\";\r\n";
    out += " micalg=" + micalg.toLatin1() + "; protocol=\"application/pgp-signature\"\r\n";
    out += "\r\n";
    out += "This is an OpenPGP/MIME signed message (RFC 3156).\r\n";
    out += "--" + boundary + "\r\n";
    // Verbatim. See buildSigned's contract.
    out += parts.contentPart;
    out += "\r\n--" + boundary + "\r\n";
    out += "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n";
    out += "Content-Description: OpenPGP digital signature\r\n";
    out += "Content-Disposition: attachment; filename=\"signature.asc\"\r\n";
    out += "\r\n";
    out += KMime::LFtoCRLF(KMime::CRLFtoLF(signature));
    if (!out.endsWith("\r\n"))
        out += "\r\n";
    out += "--" + boundary + "--\r\n";
    return out;
}

QByteArray buildEncrypted(const OutgoingParts &parts, const QByteArray &armoredCipher)
{
    if (!parts.valid || armoredCipher.isEmpty())
        return {};
    QByteArray boundary = KMime::multiPartBoundary();
    while (armoredCipher.contains(boundary))
        boundary = KMime::multiPartBoundary();

    QByteArray out = parts.identityHeaders;
    out += "MIME-Version: 1.0\r\n";
    out += "Content-Type: multipart/encrypted; boundary=\"" + boundary + "\";\r\n";
    out += " protocol=\"application/pgp-encrypted\"\r\n";
    out += "\r\n";
    out += "This is an OpenPGP/MIME encrypted message (RFC 3156).\r\n";
    out += "--" + boundary + "\r\n";
    out += "Content-Type: application/pgp-encrypted\r\n";
    out += "Content-Description: PGP/MIME version identification\r\n";
    out += "\r\n";
    out += "Version: 1\r\n";
    out += "\r\n--" + boundary + "\r\n";
    out += "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
    out += "Content-Description: OpenPGP encrypted message\r\n";
    out += "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n";
    out += "\r\n";
    out += KMime::LFtoCRLF(KMime::CRLFtoLF(armoredCipher));
    if (!out.endsWith("\r\n"))
        out += "\r\n";
    out += "--" + boundary + "--\r\n";
    return out;
}

Kind kindFromHead(const QByteArray &head)
{
    const QByteArray lower = head.toLower();
    // Encrypted wins when both appear: a signed message inside an encrypted
    // one has the encrypted type on the outside, which is the one that decides
    // what can be read without a key.
    if (lower.contains("multipart/encrypted"))
        return Kind::Encrypted;
    if (lower.contains("multipart/signed"))
        return Kind::Signed;
    return Kind::None;
}

int storedKind(Kind kind)
{
    switch (kind) {
    case Kind::Encrypted:
    case Kind::InlineEncrypted:
        return StoredEncrypted;
    case Kind::Signed:
        return StoredSigned;
    default:
        // Partial included: nothing about it is worth a lock in the message
        // list, and marking it as encrypted would promise a decryption that
        // deliberately never happens.
        return StoredNone;
    }
}

}
