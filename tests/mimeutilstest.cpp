// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/// Checks the attachment split/restore pair the offline cache is built on.
///
/// Every cached message with a large attachment is stored as a stub plus a
/// content-addressed payload file, and put back together on read. If that
/// round trip is wrong the message is not merely rendered oddly — the payload
/// is gone, because stripAttachments() is what the writer thread stores and
/// the original bytes are overwritten by it.
///
/// verifyRoundTrip() is the guard the attachment migration runs before it
/// overwrites anything, so its own honesty matters just as much: it has to
/// reject a stub whose payloads cannot be read back, not just pass one that
/// can.
///
/// Self-contained: no cache, no network, no keyring. The payload store is
/// redirected to a test-only location.
///
/// Exit 0 = all checks passed.

#include "mimeutils.h"

#include "attachmentstore.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QDir>
#include <QStandardPaths>
#include <QTextStream>
#include <QTimeZone>

#include <kmime/content.h>
#include <kmime/message.h>
#include <kmime/util.h>

#include <memory>

namespace
{
QTextStream out(stdout);
int failures = 0;

void check(bool ok, const char *what)
{
    out << (ok ? "ok   " : "FAIL ") << what << '\n';
    if (!ok)
        ++failures;
    out.flush();
}

/// A payload comfortably over AttachmentStore::kExternalizeThreshold, and not
/// compressible to nothing — a run of zeroes would pass even a broken codec.
QByteArray bigPayload()
{
    QByteArray p;
    p.reserve(80 * 1024);
    for (int i = 0; p.size() < 80 * 1024; ++i)
        p += QByteArray::number(i) + "-payload-";
    return p;
}

/// multipart/mixed: a text part, one large attachment, one small attachment.
/// The small one must stay inline — a file of its own would cost more than it
/// saves — so it also proves the threshold is honoured.
std::shared_ptr<KMime::Message> buildMessage(const QByteArray &big, const QByteArray &small)
{
    QByteArray raw;
    raw += "From: A <a@x.example>\r\n";
    raw += "To: B <b@y.example>\r\n";
    raw += "Subject: with attachments\r\n";
    raw += "MIME-Version: 1.0\r\n";
    raw += "Content-Type: multipart/mixed; boundary=\"SEP\"\r\n";
    raw += "\r\n";
    raw += "--SEP\r\n";
    raw += "Content-Type: text/plain; charset=utf-8\r\n";
    raw += "\r\n";
    raw += "body text\r\n";
    raw += "--SEP\r\n";
    raw += "Content-Type: application/octet-stream\r\n";
    raw += "Content-Transfer-Encoding: base64\r\n";
    raw += "Content-Disposition: attachment; filename=\"big.bin\"\r\n";
    raw += "\r\n";
    raw += big.toBase64() + "\r\n";
    raw += "--SEP\r\n";
    raw += "Content-Type: application/octet-stream\r\n";
    raw += "Content-Transfer-Encoding: base64\r\n";
    raw += "Content-Disposition: attachment; filename=\"small.bin\"\r\n";
    raw += "\r\n";
    raw += small.toBase64() + "\r\n";
    raw += "--SEP--\r\n";

    auto msg = std::make_shared<KMime::Message>();
    msg->setContent(KMime::CRLFtoLF(raw));
    msg->parse();
    return msg;
}
}

int main(int argc, char **argv)
{
    // QTextDocument::toMarkdown() asks QFontDatabase whether a block is fixed
    // pitch, and QFontDatabase is fatal without a QGuiApplication — so this
    // test needs one, offscreen as viewertest does it. Nothing here draws.
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QGuiApplication app(argc, argv);
    // Both together are what redirect AppDataLocation — where AttachmentStore
    // writes its payload files — away from the real cache.
    QCoreApplication::setApplicationName(QStringLiteral("mailove-mimeutilstest"));
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-mimeutilstest"));
    QStandardPaths::setTestModeEnabled(true);

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty() || !dir.contains(QLatin1String("mailove-mimeutilstest"))) {
        qWarning() << "refusing to run: test data location is not isolated:" << dir;
        return 2;
    }
    // Start from nothing, so a rerun is not reading a previous run's payloads.
    QDir(dir).removeRecursively();

    const QByteArray big = bigPayload();
    const QByteArray small = QByteArrayLiteral("tiny");

    // --- the split -------------------------------------------------------
    auto msg = buildMessage(big, small);
    const QByteArray originalEncoded = msg->encodedContent();

    QList<MailStore::PartRef> parts = MimeUtils::stripAttachments(msg.get());
    check(parts.size() == 1, "only the over-threshold attachment is lifted out");
    if (parts.size() == 1) {
        check(parts.first().size == big.size(), "the stored size is the decoded size");
        check(parts.first().filename == QLatin1String("big.bin"), "the filename survives");
        check(!parts.first().hash.isEmpty(), "the payload got a content hash");
    }

    msg->assemble();
    const QByteArray stub = msg->encodedContent();
    check(stub.size() < originalEncoded.size() / 2, "the stub is much smaller than the message");
    // The headers are what the SPF/DKIM display reads back off a cached
    // message, so a stub that dropped them would be unreadable in the viewer
    // even though the body came back intact.
    check(stub.contains("Subject: with attachments"), "the stub keeps its headers");
    check(stub.contains("small.bin"), "the small attachment stayed inline");
    check(!stub.contains(big.left(64)), "the large payload is no longer in the stub");

    // --- the guard -------------------------------------------------------
    QString reason;
    check(MimeUtils::verifyRoundTrip(stub, parts, &reason),
          "verifyRoundTrip accepts a stub whose payloads are on disk");

    // …and rejects one whose payload cannot be read back. This is the case
    // that matters: it is the only thing standing between a failed write and
    // the migration overwriting a message with a stub it cannot reconstitute.
    {
        QList<MailStore::PartRef> broken = parts;
        broken[0].hash = QStringLiteral("0000000000000000000000000000000000000000000000000000000000000000");
        QString why;
        check(!MimeUtils::verifyRoundTrip(stub, broken, &why),
              "verifyRoundTrip rejects a payload missing from disk");
        check(!why.isEmpty(), "…and says why");
    }
    // A payload that comes back the wrong length is the other failure the
    // guard exists for — back, but not with the bytes we stored.
    {
        QList<MailStore::PartRef> wrongSize = parts;
        wrongSize[0].size = big.size() + 1;
        QString why;
        check(!MimeUtils::verifyRoundTrip(stub, wrongSize, &why),
              "verifyRoundTrip rejects a payload of the wrong size");
    }

    // --- the restore -----------------------------------------------------
    KMime::Message restored;
    restored.setContent(KMime::CRLFtoLF(stub));
    restored.parse();
    check(MimeUtils::restoreAttachments(&restored, parts), "restoreAttachments reports success");

    const auto attachments = restored.attachments();
    check(attachments.size() == 2, "both attachments are present after the restore");
    bool bigBack = false, smallBack = false;
    for (KMime::Content *part : attachments) {
        const QByteArray body = part->decodedBody();
        if (body == big)
            bigBack = true;
        if (body == small)
            smallBack = true;
    }
    check(bigBack, "the externalised payload comes back byte-for-byte");
    check(smallBack, "the inline payload is untouched");

    // A stub with no lifted parts is the common case (most mail has no large
    // attachment) and must be a no-op rather than an error.
    {
        KMime::Message plain;
        plain.setContent(KMime::CRLFtoLF(stub));
        plain.parse();
        check(MimeUtils::restoreAttachments(&plain, {}), "restoring nothing succeeds");
    }

    // --- findPartByType ---------------------------------------------------
    // mainBodyPart() misses parts nested below the first level; this is what
    // the viewer falls back to, so a regression here shows up as a blank
    // message rather than an error.
    check(MimeUtils::findPartByType(msg.get(), "text/plain") != nullptr,
          "findPartByType reaches a nested text part");
    check(MimeUtils::findPartByType(msg.get(), "text/nonexistent") == nullptr,
          "findPartByType returns null for a type that is not there");

    // --- the collectors the spam scorer reads ----------------------------
    {
        QString text, html;
        MimeUtils::collectBodies(msg.get(), &text, &html);
        check(text.contains(QLatin1String("body text")), "collectBodies finds the text part");
        QStringList names;
        MimeUtils::collectAttachments(msg.get(), &names);
        check(names.contains(QStringLiteral("big.bin"))
                  && names.contains(QStringLiteral("small.bin")),
              "collectAttachments names both attachments");
    }

    // --- the encrypted-archive probe --------------------------------------
    // A password-protected attachment scores +50 on its own, so a probe that
    // answered true for an ordinary zip would mark real mail. Both directions
    // are checked for that reason. The two archives are written by hand rather
    // than by an unpacker: what is being tested is the reading of one flag
    // bit, and a fixture built by the same assumption as the code under test
    // would prove nothing.
    {
        const auto zipWith = [](quint16 flags) {
            QByteArray z;
            z += QByteArray("PK\x03\x04", 4);
            z += QByteArray("\x14\x00", 2);                                  // version
            z += QByteArray(1, char(flags & 0xFF)) + QByteArray(1, char(flags >> 8));
            z += QByteArray("\x00\x00", 2);                                  // method: store
            z += QByteArray(4, '\0');                                        // time, date
            z += QByteArray(4, '\0');                                        // crc
            z += QByteArray("\x04\x00\x00\x00", 4);                          // compressed size
            z += QByteArray("\x04\x00\x00\x00", 4);                          // uncompressed
            z += QByteArray("\x05\x00", 2);                                  // name length
            z += QByteArray("\x00\x00", 2);                                  // extra length
            z += QByteArray("a.txt", 5);
            z += QByteArray("data", 4);
            return z;
        };
        const auto messageWithZip = [](const QByteArray &zip) {
            QByteArray raw;
            raw += "From: A <a@x.example>\r\nSubject: docs\r\nMIME-Version: 1.0\r\n";
            raw += "Content-Type: multipart/mixed; boundary=\"SEP\"\r\n\r\n";
            raw += "--SEP\r\nContent-Type: text/plain\r\n\r\ntext\r\n";
            raw += "--SEP\r\nContent-Type: application/zip; name=\"docs.zip\"\r\n";
            raw += "Content-Transfer-Encoding: base64\r\n";
            raw += "Content-Disposition: attachment; filename=\"docs.zip\"\r\n\r\n";
            raw += zip.toBase64() + "\r\n--SEP--\r\n";
            auto m = std::make_shared<KMime::Message>();
            m->setContent(KMime::CRLFtoLF(raw));
            m->parse();
            return m;
        };
        check(MimeUtils::hasEncryptedArchive(messageWithZip(zipWith(0x0001)).get()),
              "hasEncryptedArchive sees the encryption flag");
        check(!MimeUtils::hasEncryptedArchive(messageWithZip(zipWith(0x0000)).get()),
              "hasEncryptedArchive leaves an ordinary zip alone");
        check(!MimeUtils::hasEncryptedArchive(msg.get()),
              "hasEncryptedArchive says nothing about a message with no archive");
    }

    // --- pasted images on their way out of the composer -------------------
    // The composer references a pasted image as a local file, which is the
    // only thing it can render; the message has to reference it as cid:, which
    // is the only thing a recipient can render. Getting this rewrite wrong
    // sends a message pointing at a path on the sender's machine.
    {
        QString html = QStringLiteral(
            "<p>before</p><img src=\"file:///tmp/x/pasted-1.png\" width=\"640\" />"
            "<p><img src='file:///tmp/x/pasted-1.png' /> again</p>"
            "<img src=\"https://example.com/tracker.gif\">"
            "<img src=\"cid:already@there\">");
        const auto images = MimeUtils::takeInlineImages(html, QStringLiteral("x.example"));
        check(images.size() == 1, "one part per file, however often it is referenced");
        check(!html.contains(QLatin1String("file:")), "no local path survives into the message");
        check(html.contains(QLatin1String("width=\"640\"")),
              "the display size the editor wrote is kept");
        check(html.contains(QLatin1String("https://example.com/tracker.gif")),
              "a remote image is left exactly as it was");
        check(html.contains(QLatin1String("cid:already@there")),
              "an existing cid: reference is left alone");
        if (images.size() == 1) {
            check(images.first().path == QLatin1String("/tmp/x/pasted-1.png"),
                  "the file to read the bytes from is named");
            check(images.first().contentId.endsWith("@x.example"),
                  "the Content-ID is in the sender's domain");
            check(!images.first().contentId.contains('<'),
                  "…and carries no angle brackets, which KMime adds itself");
            // Both references have to point at the one part, or the second
            // image renders as a broken box.
            check(html.count(QStringLiteral("cid:") + QString::fromUtf8(images.first().contentId))
                      == 2,
                  "both references point at the same part");
        }
    }
    // A body with nothing pasted into it must come back untouched — every
    // message goes through this call, not just the ones with images.
    {
        QString html = QStringLiteral("<p>plain <b>body</b></p>");
        const QString before = html;
        check(MimeUtils::takeInlineImages(html, QStringLiteral("x.example")).isEmpty()
                  && html == before,
              "a body with no pasted image is left as it is");
    }
    // file: images that cannot or must not be embedded: the reference goes,
    // everything else stays. An Outlook-for-Mac signature quoted in a reply
    // used to block the send with "Could not read the pasted image".
    {
        QString html = QStringLiteral(
            "<p>hi</p><img src=\"file:////Users/someone/Library/sig.png\" width=\"80\">"
            "<img src='file:///tmp/x/keep.png'><img src=\"cid:part@x\"><p>bye</p>");
        const int n = MimeUtils::dropFileImages(html, [](const QString &path) {
            return path.startsWith(QLatin1String("//Users/"));
        });
        check(n == 1, "only the image the predicate picks is dropped");
        check(!html.contains(QLatin1String("Users")), "the dropped tag is gone whole");
        check(html.contains(QLatin1String("file:///tmp/x/keep.png"))
                  && html.contains(QLatin1String("cid:part@x"))
                  && html.startsWith(QLatin1String("<p>hi</p>"))
                  && html.endsWith(QLatin1String("<p>bye</p>")),
              "other images and the text around them are untouched");
        check(MimeUtils::dropFileImages(html, [](const QString &) { return true; }) == 1
                  && !html.contains(QLatin1String("file:")),
              "drop-all leaves no local reference behind");
    }

    // Blank-line condensing: at most two empty lines survive between text,
    // and invisible-ink lines (nbsp spacers, object-replacement characters
    // from extracted images, zero-width spaces) count as blank.
    {
        check(MimeUtils::condenseBlankLines(QStringLiteral("a\n\n\n\n\n\n\nb"))
                  == QStringLiteral("a\n\n\nb"),
              "runs of empty lines collapse to two");
        check(MimeUtils::condenseBlankLines(QStringLiteral("a\n\n\nb"))
                  == QStringLiteral("a\n\n\nb"),
              "two empty lines are left alone");
        const QString invisible = QStringLiteral("a\n \n￼\n  \n​\n  \nb");
        check(MimeUtils::condenseBlankLines(invisible) == QStringLiteral("a\n\n\nb"),
              "nbsp/object-replacement/zero-width lines count as blank");
        check(MimeUtils::condenseBlankLines(QStringLiteral("x￼y"))
                  == QStringLiteral("xy"),
              "object-replacement characters go even mid-line");
        check(MimeUtils::condenseBlankLines(QStringLiteral("plain\ntext\n"))
                  == QStringLiteral("plain\ntext\n"),
              "ordinary text is untouched");
    }

    // Plain text with link targets kept — what toPlainText() drops.
    {
        check(MimeUtils::plainTextWithLinks(
                  QStringLiteral("<p>click <a href=\"https://x.example/p\">here</a> now</p>"))
                  == QStringLiteral("click here (https://x.example/p) now"),
              "an anchor's target follows its text");
        check(MimeUtils::plainTextWithLinks(
                  QStringLiteral("<p>click <a href=\"https://x.example/p\">right "
                                 "<b>here</b></a></p>"))
                  == QStringLiteral("click right here (https://x.example/p)"),
              "a link split by formatting emits its target once");
        check(MimeUtils::plainTextWithLinks(
                  QStringLiteral("<p><a href=\"https://x.example/\">https://x.example/</a></p>"))
                  == QStringLiteral("https://x.example/"),
              "a bare URL is not repeated");
        check(MimeUtils::plainTextWithLinks(
                  QStringLiteral("<p><a href=\"https://www.x.example/\">www.x.example/</a></p>"))
                  == QStringLiteral("www.x.example/"),
              "a URL shown without its scheme is not repeated");
        check(MimeUtils::plainTextWithLinks(
                  QStringLiteral("<p><a href=\"mailto:a@x.example\">a@x.example</a></p>"))
                  == QStringLiteral("a@x.example"),
              "mailto: on the shown address stays bare");
        check(MimeUtils::plainTextWithLinks(QStringLiteral("<p>one</p><p>two</p>"))
                  == QStringLiteral("one\ntwo"),
              "blocks separate with newlines, no trailing one");
    }

    // Markdown table furniture from layout-table mail is stripped down to
    // the cells' content.
    {
        const QString garbage = QStringLiteral(
            "||\n||\n|![Logo](https://x.example/l.png)||\n|-||\n| ||\n\n"
            "|              |\n|--------------|\n|Real text [link](https://x.example/p)|\n");
        check(MimeUtils::flattenMarkdownTables(garbage).trimmed()
                  == QStringLiteral("![Logo](https://x.example/l.png)  \n\n"
                                    "Real text [link](https://x.example/p)"),
              "table scaffolding is stripped, cell content unwrapped");
        check(MimeUtils::flattenMarkdownTables(
                  QStringLiteral("|Suma: 84,70|\n|Splatnost: 03.09.2026|\n|IBAN: SK28|"))
                  == QStringLiteral("Suma: 84,70  \nSplatnost: 03.09.2026  \nIBAN: SK28  "),
              "stacked rows keep hard line breaks, not soft-joined prose");
        check(MimeUtils::flattenMarkdownTables(
                  QStringLiteral("|## Prehľad|Môj hosting|## Informácie:|"))
                  == QStringLiteral("\n## Prehľad\n\nMôj hosting  \n\n## Informácie:\n"),
              "heading cells break out onto their own lines");
        check(MimeUtils::flattenMarkdownTables(QStringLiteral("|- alpha  |- beta   |"))
                  == QStringLiteral("- alpha\n- beta"),
              "a list in a table cell re-forms as a list");
        check(MimeUtils::flattenMarkdownTables(QStringLiteral("a | b in prose"))
                  == QStringLiteral("a | b in prose"),
              "a pipe mid-sentence is not table furniture");
    }

    // --- html to markdown, shared by both Copy as Markdown actions --------
    {
        check(MimeUtils::htmlToMarkdown(QStringLiteral("<p>Hello <b>there</b></p>"))
                  == QStringLiteral("Hello **there**"),
              "inline markup converts");
        check(MimeUtils::htmlToMarkdown(QStringLiteral("<p>one<br>two</p>"))
                  == QStringLiteral("one\n\ntwo"),
              "a <br> is a real break, not a soft one renderers rejoin");
        // Images: the reference is worthless outside mailove (cid:) or a read
        // receipt waiting to fire (remote), so only the author's alt survives.
        check(MimeUtils::htmlToMarkdown(
                  QStringLiteral("<p><img src=\"cid:x@y\" alt=\"Company logo\">Hi</p>"))
                  == QStringLiteral("Company logoHi"),
              "a cid: image leaves its alt text behind");
        check(!MimeUtils::htmlToMarkdown(
                   QStringLiteral("<p><img src=\"https://track.test/pixel.gif\">Hi</p>"))
                   .contains(QLatin1String("track.test")),
              "a remote image's URL does not ride out on the clipboard");
        check(MimeUtils::htmlToMarkdown(QStringLiteral("<p><img src=\"cid:z\">Hi</p>"))
                  == QStringLiteral("Hi"),
              "an image with no alt leaves nothing");
        // The newsletter button: an image wrapped in a tracking link. With the
        // image gone the label is empty, and "[ ](https://…)" renders as a
        // blank nobody can click or read.
        check(MimeUtils::htmlToMarkdown(
                  QStringLiteral("<a href=\"https://t.test/l?m=1\"><img src=\"cid:b\"></a>"))
                  == QStringLiteral("https://t.test/l?m=1"),
              "an image-only link becomes the plain URL, not an empty label");
        check(MimeUtils::htmlToMarkdown(
                  QStringLiteral("<a href=\"https://t.test/l\"><img src=\"cid:b\" "
                                 "alt=\"Read online\"></a>"))
                  == QStringLiteral("[Read online](https://t.test/l)"),
              "...but alt text still makes a proper label");
        check(MimeUtils::htmlToMarkdown(QStringLiteral("<a href=\"https://e.test/\">Link</a>"))
                  == QStringLiteral("[Link](https://e.test/)"),
              "a link keeps its target — the whole reason not to copy plain text");
        check(MimeUtils::htmlToMarkdown(QString()).isEmpty(), "empty html converts to nothing");
    }

    // --- repairTransferEncodings ------------------------------------------
    // A delivery path decoded the base64 body and left the header: KMime would
    // read raw HTML as base64 and hand the viewer a few bytes of noise.
    {
        auto lied = std::make_shared<KMime::Message>();
        lied->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: b2b@shop.test\r\n"
            "Subject: hi\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "<!doctype html>\r\n<html><body><p>V\xc3\xa1\xc5\xbe" "en\xc3\xbd z\xc3\xa1kazn\xc3\xadk</p></body></html>\r\n")));
        lied->setFrozen(true);
        lied->parse();
        const QByteArray wire = lied->encodedContent();
        // Straight after parse(), before any read: KMime decodes the body in
        // place the first time anything asks for it, and a body already
        // decoded under the wrong label is noise nobody can undo — which is
        // why every caller runs the repair first.
        MimeUtils::repairTransferEncodings(lied.get());
        // What presentMessage() and storeFetchedBody() do next: a leaf has no
        // contents, so their guard parses again, and parse() rebuilds every
        // header from the raw head. The repair has to survive that.
        MimeUtils::parseIfNeeded(lied.get());
        check(lied->decodedText().contains(QStringLiteral("V\u00e1\u017een\u00fd z\u00e1kazn\u00edk")),
              "a base64 label on a raw body is ignored and the text shows");
        check(lied->encodedContent() == wire,
              "...while the wire bytes DKIM judges are untouched");

        auto honest = std::make_shared<KMime::Message>();
        honest->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: b2b@shop.test\r\n"
            "Subject: hi\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "PHA+aGVsbG88L3A+\r\n")));
        honest->parse();
        MimeUtils::repairTransferEncodings(honest.get());
        check(honest->decodedText() == QStringLiteral("<p>hello</p>"),
              "genuine base64 still decodes");

        auto multi = std::make_shared<KMime::Message>();
        multi->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: b2b@shop.test\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=\"b\"\r\n"
            "\r\n"
            "--b\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "plain words, not base64\r\n"
            "--b\r\n"
            "Content-Type: text/html\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "PHA+aGVsbG88L3A+\r\n"
            "--b--\r\n")));
        multi->parse();
        MimeUtils::repairTransferEncodings(multi.get());
        QString text;
        QString html;
        MimeUtils::collectBodies(multi.get(), &text, &html);
        check(text.contains(QStringLiteral("plain words")) && html == QStringLiteral("<p>hello</p>"),
              "each leaf is judged on its own body");
    }

    // Encoded words that lie about their charset — the header half of the
    // same fault repairTransferEncodings() answers in the body.
    {
        auto lying = std::make_shared<KMime::Message>();
        lying->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: =?us-ascii?Q?Da=C5=88ov=C3=BD_=C3=BArad?= <tax@office.test>\r\n"
            "Subject: =?us-ascii?Q?Vr=C3=A1tenie_preplatku?=\r\n"
            "\r\n"
            "body\r\n")));
        lying->parse();
        const QString kmimeSubject = lying->subject()->asUnicodeString();
        check(kmimeSubject.contains(QChar::ReplacementCharacter),
              "us-ascii label over UTF-8 is what KMime cannot decode");
        check(MimeUtils::repairedHeaderText(lying.get(), "Subject", kmimeSubject)
                  == QString::fromUtf8("Vrátenie preplatku"),
              "the subject is read as the UTF-8 it actually is");
        check(MimeUtils::repairedHeaderText(lying.get(), "From",
                                            lying->from()->asUnicodeString())
                  .contains(QString::fromUtf8("Daňový úrad")),
              "and so is the display name");

        // An honest header is handed back untouched, whatever it is encoded in.
        auto honest = std::make_shared<KMime::Message>();
        honest->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: a@b.test\r\n"
            "Subject: =?iso-8859-2?Q?Vr=E1tenie_preplatku?=\r\n"
            "\r\n"
            "body\r\n")));
        honest->parse();
        const QString latin2 = honest->subject()->asUnicodeString();
        check(latin2 == QString::fromUtf8("Vrátenie preplatku"),
              "a truthful legacy charset decodes on its own");
        check(MimeUtils::repairedHeaderText(honest.get(), "Subject", latin2) == latin2,
              "and is returned unchanged — the repair never second-guesses it");

        // Base64 in the same shape, folded across two lines, and a plain ASCII
        // word whose label is beside the point.
        auto folded = std::make_shared<KMime::Message>();
        folded->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: a@b.test\r\n"
            "Subject: =?us-ascii?B?VnLDoXRlbmll?=\r\n"
            " =?us-ascii?B?IHByZXBsYXRrdQ==?=\r\n"
            "\r\n"
            "body\r\n")));
        folded->parse();
        check(MimeUtils::repairedHeaderText(folded.get(), "Subject",
                                            folded->subject()->asUnicodeString())
                  == QString::fromUtf8("Vrátenie preplatku"),
              "base64, and folded across two lines");

        auto ascii = std::make_shared<KMime::Message>();
        ascii->setContent(KMime::CRLFtoLF(QByteArrayLiteral(
            "From: a@b.test\r\n"
            "Subject: =?us-ascii?Q?Refund_notice?=\r\n"
            "\r\n"
            "body\r\n")));
        ascii->parse();
        check(MimeUtils::repairedHeaderText(ascii.get(), "Subject",
                                            ascii->subject()->asUnicodeString())
                  == QStringLiteral("Refund notice"),
              "an ASCII payload is nobody's evidence of a wrong label");
    }

    {
        // An Outlook meeting request, the shape Exchange sends: a
        // multipart/alternative whose text part is empty, whose HTML part is
        // a Word page around one &nbsp;, and whose third alternative is the
        // text/calendar carrying everything — with no disposition and no
        // name, so KMime lists no attachment at all.
        const QByteArray ics = QByteArrayLiteral(
            "BEGIN:VCALENDAR\r\n"
            "METHOD:REQUEST\r\n"
            "PRODID:Microsoft Exchange Server 2010\r\n"
            "VERSION:2.0\r\n"
            "BEGIN:VEVENT\r\n"
            "ORGANIZER;CN=Milan Organizer:mailto:milan@partners.example\r\n"
            "ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=Daniel Rea\r\n"
            " der:mailto:daniel@hotels.example\r\n"
            "ATTENDEE;ROLE=OPT-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=\"Room: 2nd\r\n"
            " \":mailto:room@partners.example\r\n"
            "DESCRIPTION;LANGUAGE=sk-SK:\\n\r\n"
            "UID:0400000082\r\n"
            "SUMMARY;LANGUAGE=sk-SK:stretnutie <b>Hotels</b>\r\n"
            "DTSTART;TZID=Central Europe Standard Time:20261014T100000\r\n"
            "DTEND;TZID=Central Europe Standard Time:20261014T110000\r\n"
            "LOCATION;LANGUAGE=sk-SK:PARTNERS\\, Main square 7\\, Bratislava\\, 2nd Floor meeti\r\n"
            " ng room\r\n"
            "END:VEVENT\r\n"
            "END:VCALENDAR\r\n");
        QByteArray raw;
        raw += "From: Milan Organizer <milan@partners.example>\r\n";
        raw += "To: daniel@hotels.example\r\n";
        raw += "Subject: stretnutie\r\n";
        raw += "MIME-Version: 1.0\r\n";
        raw += "Content-Type: multipart/alternative; boundary=\"ALT\"\r\n";
        raw += "\r\n";
        raw += "--ALT\r\n";
        raw += "Content-Type: text/plain; charset=\"iso-8859-2\"\r\n";
        raw += "Content-Transfer-Encoding: quoted-printable\r\n";
        raw += "\r\n";
        raw += "\r\n";
        raw += "--ALT\r\n";
        raw += "Content-Type: text/html; charset=\"iso-8859-2\"\r\n";
        raw += "Content-Transfer-Encoding: quoted-printable\r\n";
        raw += "\r\n";
        raw += "<html><head><style>p.MsoNormal{margin:0cm}</style></head>\r\n";
        raw += "<body lang=3D\"SK\"><div class=3D\"WordSection1\">\r\n";
        raw += "<p class=3D\"MsoNormal\"><o:p>&nbsp;</o:p></p></div></body></html>\r\n";
        raw += "--ALT\r\n";
        raw += "Content-Type: text/calendar; charset=\"utf-8\"; method=REQUEST\r\n";
        raw += "Content-Transfer-Encoding: base64\r\n";
        raw += "\r\n";
        raw += ics.toBase64() + "\r\n";
        raw += "--ALT--\r\n";
        auto msg = std::make_shared<KMime::Message>();
        msg->setContent(KMime::CRLFtoLF(raw));
        msg->parse();

        check(msg->attachments().isEmpty(), "KMime itself lists no attachment for the invite");
        KMime::Content *cal = MimeUtils::findCalendarPart(msg.get());
        check(cal != nullptr, "the text/calendar alternative is found");
        const auto parts = MimeUtils::attachmentParts(msg.get());
        check(parts.size() == 1 && parts.first() == cal,
              "and it is the one attachment the reading pane lists");
        QStringList names;
        MimeUtils::collectAttachments(msg.get(), &names);
        check(names == QStringList{QStringLiteral("invitation.ics")},
              "collectAttachments names it invitation.ics");

        const QString html = msg->mainBodyPart("text/html")->decodedText();
        check(MimeUtils::htmlIsBlank(html), "the Word &nbsp; page counts as blank");
        check(!MimeUtils::htmlIsBlank(QStringLiteral("<p>Hi</p>")), "a page with text does not");
        check(!MimeUtils::htmlIsBlank(QStringLiteral("<img src=\"cid:x\">")),
              "nor a page that is only a picture");

        const MimeUtils::CalendarInvite inv = MimeUtils::parseCalendarInvite(cal ? cal->decodedBody() : ics);
        check(inv.valid && inv.method == QLatin1String("REQUEST"), "VEVENT + METHOD read");
        check(inv.summary == QStringLiteral("stretnutie <b>Hotels</b>"), "summary read verbatim");
        check(inv.location == QStringLiteral("PARTNERS, Main square 7, Bratislava, 2nd Floor meeting room"),
              "location unfolded and unescaped");
        check(inv.description.isEmpty(), "an escaped newline alone is no description");
        check(inv.organizer == QStringLiteral("Milan Organizer <milan@partners.example>"),
              "organizer as name <address>");
        check(inv.attendees.size() == 2
                  && inv.attendees.at(0) == QStringLiteral("Daniel Reader <daniel@hotels.example>")
                  && inv.attendees.at(1) == QStringLiteral("Room: 2nd <room@partners.example> (optional)"),
              "attendees: folded name, quoted CN with a colon, optional marked");
        // 10:00 in Exchange's "Central Europe Standard Time" is 08:00 UTC on
        // that (summer-time) date, whatever zone this machine is in.
        check(inv.start.isValid()
                  && inv.start.toUTC() == QDateTime(QDate(2026, 10, 14), QTime(8, 0), QTimeZone::UTC),
              "a Windows zone name resolves; start is 08:00 UTC");
        check(inv.end.toUTC() == QDateTime(QDate(2026, 10, 14), QTime(9, 0), QTimeZone::UTC),
              "end is 09:00 UTC");
        check(!inv.allDay && inv.timeZone == QStringLiteral("Central Europe Standard Time"),
              "timed event, TZID remembered");

        const QString card = MimeUtils::calendarInviteHtml(inv);
        check(card.contains(QStringLiteral("Invitation: stretnutie &lt;b&gt;Hotels&lt;/b&gt;")),
              "card heading, summary escaped");
        check(card.contains(QStringLiteral("href=\"mailto:milan@partners.example\"")),
              "organizer linked as mailto");
        check(card.contains(QStringLiteral("Main square 7")) && !card.contains(QStringLiteral("\\,")),
              "location on the card, unescaped");
        const QString text = MimeUtils::calendarInviteText(inv);
        check(text.startsWith(QStringLiteral("Invitation: stretnutie <b>Hotels</b>\nWhen: "))
                  && text.contains(QStringLiteral("Where: PARTNERS, Main square 7")),
              "text rendering for the preview");

        check(MimeUtils::prependToHtmlBody(QStringLiteral("<html><head><style>x</style></head><body class=\"a\"><p>t</p></body></html>"),
                                           QStringLiteral("[card]"))
                  == QStringLiteral("<html><head><style>x</style></head><body class=\"a\">[card]<p>t</p></body></html>"),
              "card goes right after the body tag");
        check(MimeUtils::prependToHtmlBody(QStringLiteral("<p>t</p>"), QStringLiteral("[card]"))
                  == QStringLiteral("[card]<p>t</p>"),
              "or in front of a bare fragment");

        // Date-only and UTC shapes.
        const auto allDay = MimeUtils::parseCalendarInvite(QByteArrayLiteral(
            "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Day\nDTSTART;VALUE=DATE:20261220\n"
            "DTEND;VALUE=DATE:20261221\nEND:VEVENT\nEND:VCALENDAR\n"));
        check(allDay.valid && allDay.allDay && allDay.start.date() == QDate(2026, 12, 20),
              "all-day event");
        const auto utc = MimeUtils::parseCalendarInvite(QByteArrayLiteral(
            "BEGIN:VCALENDAR\nMETHOD:CANCEL\nBEGIN:VEVENT\nDTSTART:20261220T150000Z\nEND:VEVENT\nEND:VCALENDAR\n"));
        check(utc.start.toUTC() == QDateTime(QDate(2026, 12, 20), QTime(15, 0), QTimeZone::UTC),
              "UTC stamp");
        check(MimeUtils::calendarInviteText(utc).startsWith(QStringLiteral("Cancelled: (no title)")),
              "cancellation without a summary");
        check(!MimeUtils::parseCalendarInvite(QByteArrayLiteral("BEGIN:VCALENDAR\nEND:VCALENDAR\n")).valid,
              "no VEVENT, no invite");
    }

    out << (failures == 0 ? "all mime utils tests passed\n"
                          : QStringLiteral("%1 check(s) failed\n").arg(failures));
    out.flush();
    return failures == 0 ? 0 : 1;
}
