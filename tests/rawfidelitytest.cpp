// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/// Which KMime accessor returns a message's original octets after the parse
/// KIMAP has already performed — and, above all, that encodedContent() still
/// does.
///
/// That one is load-bearing: DKIM verifies the bytes as they travelled, and
/// MessageVerifier hands it LFtoCRLF(ctx->m_raw), which is encodedContent()
/// of the parsed message. If a KMime upgrade ever stops round-tripping there,
/// every signature silently starts failing its body hash and mailove reports
/// perfectly good mail as unverified. This asserts it so that lands here
/// instead of in the badge.
///
/// The other two accessors are reported, not asserted — they are known to
/// diverge, and why is documented at each call below.
///
/// Exit 0 = the round-trip invariant holds.
#include <KMime/Message>
#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <cstdio>

static QByteArray realistic()
{
    QByteArray m;
    m += "Received: by 10.0.0.1 with SMTP id abc;\r\n";
    m += "        Fri, 31 Jul 2026 00:54:07 -0700 (PDT)\r\n";
    m += "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=x.example; s=s1;\r\n";
    m += "\th=from:to:subject; bh=AAAA=; b=BBBB=\r\n";
    m += "From: A <a@x.example>\r\n";
    m += "To: B <b@y.example>\r\n";
    m += "Subject: realistic\r\n";
    m += "MIME-Version: 1.0\r\n";
    m += "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n";
    m += "\r\n";
    m += "This is a MIME preamble that parsers often drop.\r\n";
    m += "\r\n";
    m += "--OUTER\r\n";
    m += "Content-Type: multipart/alternative; boundary=\"INNER\"\r\n";
    m += "\r\n";
    m += "--INNER\r\n";
    m += "Content-Type: text/plain; charset=utf-8\r\n";
    m += "Content-Transfer-Encoding: quoted-printable\r\n";
    m += "\r\n";
    m += "hello =C3=A9t=C3=A9\r\n";
    m += "\r\n";
    m += "--INNER\r\n";
    m += "Content-Type: text/html; charset=utf-8\r\n";
    m += "\r\n";
    m += "<p>hi</p>\r\n";
    m += "--INNER--\r\n";
    m += "\r\n";
    m += "--OUTER\r\n";
    m += "Content-Type: text/calendar; charset=UTF-8; method=REQUEST\r\n";
    m += "Content-Transfer-Encoding: base64\r\n";
    m += "Content-Disposition: attachment; filename*=UTF-8''invite.ics\r\n";
    m += "\r\n";
    m += "QkVHSU46VkNBTEVOREFSDQpWRVJTSU9OOjIuMA0KRU5EOlZDQUxFTkRBUg0K\r\n";
    m += "\r\n";
    m += "--OUTER--\r\n";
    m += "\r\n"; // trailing empty line, which "simple" must preserve-then-trim
    return m;
}

static int failures = 0;

static bool report(const char *label, const QByteArray &got, const QByteArray &want)
{
    // The digest is printed so a variant can be matched against bytes this
    // program never sees — in particular the bodies.raw of a real cache.
    printf("%-34s %-6s (%lld vs %lld bytes) sha256=%s\n", label,
           got == want ? "SAME" : "DIFFER", (long long)got.size(), (long long)want.size(),
           QCryptographicHash::hash(got, QCryptographicHash::Sha256).toHex().left(16).constData());
    if (got != want) {
        qsizetype i = 0;
        while (i < got.size() && i < want.size() && got[i] == want[i])
            ++i;
        printf("     first difference at %lld\n", (long long)i);
        printf("     original: %s\n", want.mid(i, 60).replace("\r\n", "\\r\\n").constData());
        printf("     got     : %s\n", got.mid(i, 60).replace("\r\n", "\\r\\n").constData());
    }
    return got == want;
}

int main(int argc, char **argv)
{
    QByteArray original = realistic();
    if (argc > 1) { // or a real message off disk
        QFile f(QString::fromLocal8Bit(argv[1]));
        if (f.open(QIODevice::ReadOnly))
            original = KMime::LFtoCRLF(f.readAll());
    }

    auto msg = std::make_shared<KMime::Message>();
    msg->setContent(KMime::CRLFtoLF(original));
    if (msg->contents().isEmpty())
        msg->parse();

    // The invariant mailove depends on. Asserted.
    if (!report("encodedContent()", KMime::LFtoCRLF(msg->encodedContent()), original)) {
        printf("FAIL: encodedContent() no longer round-trips — DKIM body hashes\n"
               "      will fail against every freshly fetched message.\n");
        ++failures;
    }

    // Reported only: head() stops at the end of the headers, so the MIME
    // preamble between them and the first boundary is not part of either
    // accessor. Expected to differ, and nothing reads it this way.
    report("head() + body()",
           KMime::LFtoCRLF(msg->head() + QByteArrayLiteral("\n") + msg->body()), original);

    // assemble() is the destructive one: it marks every part dirty, so the
    // following encodedContent() re-encodes each body from its decoded form
    // using KMime's own quoted-printable choices rather than the sender's.
    // Nothing above this line reproduces that, which is why a test that only
    // exercised setContent()+parse() cleared KMime by mistake.
    //
    // Reported only, and deliberately not a failure: this is upstream
    // behaviour we cannot fix from here, and it is why nothing on the
    // verification path may call assemble() before hashing.
    msg->assemble();
    report("assemble() + encodedContent()", KMime::LFtoCRLF(msg->encodedContent()), original);

    if (failures == 0)
        printf("all fidelity invariants hold\n");
    return failures == 0 ? 0 : 1;
}
