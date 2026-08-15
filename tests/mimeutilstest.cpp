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
#include <QDir>
#include <QStandardPaths>
#include <QTextStream>

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
    QCoreApplication app(argc, argv);
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

    out << (failures == 0 ? "all mime utils tests passed\n"
                          : QStringLiteral("%1 check(s) failed\n").arg(failures));
    out.flush();
    return failures == 0 ? 0 : 1;
}
