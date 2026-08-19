// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// What sanitizeMessageHtml() promises about URL-bearing attributes.
//
// The interesting cases are the ones where the source text and the URL the
// engine acts on are not the same string: character references, tabs and
// newlines inside a scheme, leading control characters. A check that reads the
// raw source passes all of those through — see
// doc/research/css-the-bomb-inside-your-inbox.md on sanitizer/browser
// discrepancies, which is the general shape of the bug.
//
// This layer is defence in depth, not the thing standing between a message and
// the user: scripting is off, script-src is 'none', and openExternalUrl()
// allowlists schemes at click time. It is pinned here anyway, because "covered
// by something else" is how a layer quietly stops working.
//
// Exit 0 = every case behaves.

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cstdio>

#include "../src/viewersecurity.h"

#define LOG(...)                                                                                   \
    do {                                                                                           \
        fprintf(stderr, __VA_ARGS__);                                                              \
        fputc('\n', stderr);                                                                       \
    } while (0)

namespace {

struct Case {
    const char *what;
    QString input;
    bool shouldSurvive; ///< true = the href must still be there afterwards
};

QList<Case> cases()
{
    return {
        // --- must be neutralized -------------------------------------------
        {"plain javascript:", QStringLiteral("<a href=\"javascript:alert(1)\">x</a>"), false},
        {"uppercase scheme", QStringLiteral("<a href=\"JaVaScRiPt:alert(1)\">x</a>"), false},
        {"decimal reference",
         QStringLiteral("<a href=\"&#106;avascript:alert(1)\">x</a>"), false},
        {"hex reference", QStringLiteral("<a href=\"&#x6a;avascript:alert(1)\">x</a>"), false},
        {"zero-padded reference",
         QStringLiteral("<a href=\"&#0000106;avascript:alert(1)\">x</a>"), false},
        // The semicolon is optional to the HTML parser, so it has to be
        // optional here too.
        {"reference without semicolon",
         QStringLiteral("<a href=\"&#106avascript:alert(1)\">x</a>"), false},
        {"encoded tab inside scheme",
         QStringLiteral("<a href=\"java&#9;script:alert(1)\">x</a>"), false},
        {"literal tab inside scheme",
         QStringLiteral("<a href=\"java\tscript:alert(1)\">x</a>"), false},
        {"literal newline inside scheme",
         QStringLiteral("<a href=\"java\nscript:alert(1)\">x</a>"), false},
        {"&Tab; inside scheme",
         QStringLiteral("<a href=\"java&Tab;script:alert(1)\">x</a>"), false},
        {"&NewLine; inside scheme",
         QStringLiteral("<a href=\"java&NewLine;script:alert(1)\">x</a>"), false},
        {"encoded colon", QStringLiteral("<a href=\"javascript&colon;alert(1)\">x</a>"), false},
        {"leading control character",
         QStringLiteral("<a href=\"\1javascript:alert(1)\">x</a>"), false},
        {"leading whitespace", QStringLiteral("<a href=\"   javascript:alert(1)\">x</a>"), false},
        {"vbscript", QStringLiteral("<a href=\"vbscript:msgbox(1)\">x</a>"), false},
        {"single-quoted value", QStringLiteral("<a href='javascript:alert(1)'>x</a>"), false},
        {"unquoted value", QStringLiteral("<a href=javascript:alert(1)>x</a>"), false},
        {"data: document", QStringLiteral("<a href=\"data:text/html,<b>hi\">x</a>"), false},
        {"data: document, encoded",
         QStringLiteral("<a href=\"&#100;ata:text/html,<b>hi\">x</a>"), false},
        {"data: xhtml document",
         QStringLiteral("<a href=\"data:application/xhtml+xml,x\">y</a>"), false},
        {"src attribute too", QStringLiteral("<img src=\"&#106;avascript:alert(1)\">"), false},
        // Ours, and only our own cid: rewriting may produce one — a sender
        // writing this is naming another message's context.
        {"forged mailove: scheme",
         QStringLiteral("<img src=\"mailove:cid/1/logo\">"), false},
        {"unknown scheme", QStringLiteral("<a href=\"weirdscheme:payload\">x</a>"), false},

        // --- must survive untouched ----------------------------------------
        {"http", QStringLiteral("<a href=\"http://example.com/a\">x</a>"), true},
        {"https", QStringLiteral("<a href=\"https://example.com/a?b=1&c=2\">x</a>"), true},
        {"mailto", QStringLiteral("<a href=\"mailto:a@b.example\">x</a>"), true},
        {"cid image", QStringLiteral("<img src=\"cid:part1@example\">"), true},
        {"tel", QStringLiteral("<a href=\"tel:+421900000000\">x</a>"), true},
        {"relative path", QStringLiteral("<img src=\"images/logo.png\">"), true},
        {"fragment", QStringLiteral("<a href=\"#section\">x</a>"), true},
        {"protocol-relative", QStringLiteral("<img src=\"//example.com/a.png\">"), true},
        {"data: image", QStringLiteral("<img src=\"data:image/png;base64,iVBORw0=\">"), true},
        // "&amp;#106;" is the literal text "&#106;" to a browser, not "j".
        // Decoding twice would turn this ordinary link into a false positive.
        {"double-encoded ampersand is not decoded twice",
         QStringLiteral("<a href=\"https://e.example/?x=&amp;#106;avascript\">x</a>"), true},
    };
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    QStringList failures;
    for (const Case &c : cases()) {
        const QString out = sanitizeMessageHtml(c.input);
        const bool neutralized = out.contains(QLatin1String("blocked:"));
        const bool survived = !neutralized;

        if (survived != c.shouldSurvive) {
            failures.append(QStringLiteral("%1\n      in:  %2\n      out: %3\n      "
                                           "expected the URL to be %4")
                                .arg(QLatin1String(c.what), c.input, out,
                                     c.shouldSurvive ? QStringLiteral("kept")
                                                     : QStringLiteral("neutralized")));
        }
        LOG("%-46s %s", c.what,
            survived != c.shouldSurvive ? "FAIL"
                                        : (c.shouldSurvive ? "kept" : "neutralized"));
    }

    // Event handlers and embedded documents are the older half of this
    // function's job; a rewrite of the URL half must not have cost them.
    struct { const char *what; QString in; QString mustNotContain; } structural[] = {
        {"onerror handler removed", QStringLiteral("<img src=\"x.png\" onerror=\"alert(1)\">"),
         QStringLiteral("onerror")},
        {"script element removed", QStringLiteral("<script>alert(1)</script>hi"),
         QStringLiteral("alert")},
        {"iframe removed", QStringLiteral("<iframe src=\"https://e.example\"></iframe>"),
         QStringLiteral("iframe")},
        {"base element removed", QStringLiteral("<base href=\"https://e.example/\">"),
         QStringLiteral("base")},
        {"meta refresh removed",
         QStringLiteral("<meta http-equiv=\"refresh\" content=\"0;url=https://e.example\">"),
         QStringLiteral("refresh")},
    };
    for (const auto &s : structural) {
        const QString out = sanitizeMessageHtml(s.in);
        const bool ok = !out.contains(s.mustNotContain, Qt::CaseInsensitive);
        if (!ok)
            failures.append(QStringLiteral("%1\n      out: %2").arg(QLatin1String(s.what), out));
        LOG("%-46s %s", s.what, ok ? "removed" : "FAIL");
    }

    // Body text must not be mistaken for markup — the reason attribute
    // cleanup runs per tag rather than over the whole document.
    const QString prose = QStringLiteral("<p>the one=1 case, and mailto:a@b in passing</p>");
    if (sanitizeMessageHtml(prose) != prose)
        failures.append(QStringLiteral("body text was rewritten: %1")
                            .arg(sanitizeMessageHtml(prose)));

    LOG("%s", "");
    if (!failures.isEmpty()) {
        for (const QString &f : failures)
            LOG("FAIL: %s", qPrintable(f));
        LOG("%d of %lld case(s) failed", int(failures.size()), qint64(cases().size()));
        return 1;
    }
    LOG("PASS: %lld URL cases plus the structural and prose checks.",
        qint64(cases().size()));
    return 0;
}

