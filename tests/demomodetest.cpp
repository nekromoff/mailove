// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Demo mode's scrambler: every word replaced, the same word the same way,
// the shape of the line kept, and HTML markup never touched — a body whose
// tags were scrambled would not render, and one whose <style> was would
// render wrong.

#include "demomode.h"

#include <QCoreApplication>
#include <QRegularExpression>
#include <cstdio>

static int failures = 0;
static void check(bool ok, const QString &what)
{
    std::printf("%s %s\n", ok ? "ok  :" : "FAIL:", qPrintable(what));
    if (!ok)
        ++failures;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const quint64 salt = 42;

    const QString subject = QStringLiteral("Re: Faktúra 2026/104 pre Daniela");
    const QString fake = DemoMode::scrambleText(subject, salt);
    std::printf("  %s -> %s\n", qPrintable(subject), qPrintable(fake));
    check(fake.startsWith(QLatin1String("Re: ")), "reply prefix kept");
    check(!fake.contains(QLatin1String("Faktúra")) && !fake.contains(QLatin1String("Daniela")),
          "real words gone");
    check(!fake.contains(QLatin1String("2026")) && !fake.contains(QLatin1String("104")),
          "real numbers gone");
    check(fake.contains(QRegularExpression(QStringLiteral("\\d{4}/\\d{3}"))),
          "number shape kept");
    check(fake == DemoMode::scrambleText(subject, salt), "same input, same output");
    check(fake != DemoMode::scrambleText(subject, salt + 1), "another salt, another mapping");
    check(DemoMode::scrambleText(QStringLiteral("Daniela"), salt)
              == DemoMode::scrambleText(QStringLiteral("daniela"), salt).replace(0, 1, QString(DemoMode::scrambleText(QStringLiteral("daniela"), salt).at(0).toUpper())),
          "case does not change the word chosen");
    check(DemoMode::scrambleText(QStringLiteral("URGENT"), salt).isUpper(), "ALL CAPS kept");
    check(DemoMode::scrambleText(QStringLiteral("Inbox"), salt) == QLatin1String("Inbox"),
          "standard folder names kept");

    const QString from = QStringLiteral("Daniel Duris <dusoft@staznosti.sk>");
    const QString fakeFrom = DemoMode::scrambleText(from, salt);
    std::printf("  %s -> %s\n", qPrintable(from), qPrintable(fakeFrom));
    check(!fakeFrom.contains(QLatin1String("staznosti")) && !fakeFrom.contains(QLatin1String("dusoft")),
          "address replaced");
    check(fakeFrom.contains(QRegularExpression(
              QStringLiteral("<[a-z.]+@[a-z]+\\.(com|org|net)>$"))),
          "address still looks like one");

    const QString html = QStringLiteral(
        "<html><head><style>p { color: red; font-family: Arial }</style></head>"
        "<body><p class=\"greeting\" title='Hello > there'>Hello Daniel &amp; Eva&nbsp;!</p>"
        "<!-- secret comment --><script>var name = 'Daniel';</script>"
        "<a href=\"https://staznosti.sk/x\">visit</a></body></html>");
    const QString fakeHtml = DemoMode::scrambleHtml(html, salt);
    std::printf("  %s\n", qPrintable(fakeHtml));
    check(fakeHtml.contains(QLatin1String("<style>p { color: red; font-family: Arial }</style>")),
          "style body untouched");
    check(fakeHtml.contains(QLatin1String("<p class=\"greeting\" title='Hello > there'>")),
          "tag with quoted > untouched");
    check(fakeHtml.contains(QLatin1String("&amp;")) && fakeHtml.contains(QLatin1String("&nbsp;")),
          "entities untouched");
    check(fakeHtml.contains(QLatin1String("<script>var name = 'Daniel';</script>")),
          "script body untouched");
    check(fakeHtml.contains(QLatin1String("<a href=\"https://staznosti.sk/x\">")),
          "attributes untouched");
    check(!fakeHtml.contains(QLatin1String("Hello Daniel")) && !fakeHtml.contains(QLatin1String(">visit<")),
          "text nodes replaced");

    check(DemoMode::scrambleText(QString(), salt).isEmpty(), "empty stays empty");
    const QString longWord = QStringLiteral("Donaudampfschifffahrtsgesellschaft");
    const QString fakeLong = DemoMode::scrambleText(longWord, salt);
    std::printf("  %s -> %s\n", qPrintable(longWord), qPrintable(fakeLong));
    check(fakeLong.size() >= 20 && fakeLong.size() <= 40, "long word becomes a compound");

    const QString fp = QStringLiteral("9F3A 77C1 0B2E 4D5F 8A61  1C3E 0047 D9B2 EE10 5A6C");
    const QString fakeFp = DemoMode::scrambleFingerprint(fp, salt);
    std::printf("  %s -> %s\n", qPrintable(fp), qPrintable(fakeFp));
    check(fakeFp != fp, "fingerprint replaced");
    check(fakeFp.size() == fp.size()
              && QString(fakeFp).replace(QRegularExpression(QStringLiteral("[0-9A-F]")), QStringLiteral("x"))
                     == QString(fp).replace(QRegularExpression(QStringLiteral("[0-9A-F]")), QStringLiteral("x")),
          "fingerprint grouping kept");
    check(DemoMode::scrambleFingerprint(QString(fp).remove(u' ').toLower(), salt)
              == QString(fakeFp).remove(u' ').toLower(),
          "same key, grouped or not, same fake");
    const QString fakeFpTail = DemoMode::scrambleFingerprint(QStringLiteral("EE105A6C"), salt);
    check(!QString(fakeFp).remove(u' ').endsWith(fakeFpTail), "key id is not the fake fingerprint's tail");

    const QString verdict = QStringLiteral(
        "Signed by dusoft@staznosti.sk, whose key 0B2E4D5F8A611C3E matches the From address.");
    const QString fakeVerdict = DemoMode::scrambleIdentifiers(verdict, salt);
    std::printf("  %s\n", qPrintable(fakeVerdict));
    check(fakeVerdict.startsWith(QLatin1String("Signed by "))
              && fakeVerdict.endsWith(QLatin1String(" matches the From address.")),
          "the sentence around the identifiers kept");
    check(!fakeVerdict.contains(QLatin1String("staznosti"))
              && !fakeVerdict.contains(QLatin1String("0B2E4D5F8A611C3E")),
          "address and key id replaced");

    std::printf("%s\n", failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}
