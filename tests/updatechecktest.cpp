// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// What the update check concludes from a redirect.
//
// The network half — HEAD, ManualRedirectPolicy, the 5-second transfer timeout
// — is thin Qt glue. The half worth pinning is what happens to the string that
// comes back: it is server-controlled, it decides whether a marker appears in
// the window's own title row, and it decides where clicking that marker sends
// the user's browser. So the decisions are pure functions (UpdateCheckLogic)
// and this covers them directly, with no socket and no waiting.
//
// Exit 0 = every case behaves.

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <cstdio>

#include "../src/updatecheck.h"

#define LOG(...)                                                                                   \
    do {                                                                                           \
        fprintf(stderr, __VA_ARGS__);                                                              \
        fputc('\n', stderr);                                                                       \
    } while (0)

using namespace UpdateCheckLogic;

namespace {

QStringList g_failures;

void check(bool ok, const QString &what)
{
    if (!ok)
        g_failures.append(what);
    LOG("%-64s %s", qPrintable(what), ok ? "ok" : "FAIL");
}

const QString kHost = QStringLiteral("github.com");

/// End to end over the two steps the reply handler actually performs.
QString versionFrom(const QString &location)
{
    return versionFromTag(tagFromLocation(location, kHost));
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // --- the real answer -----------------------------------------------------
    check(versionFrom("https://github.com/nekromoff/mailove/releases/tag/3.0")
              == QLatin1String("3.0"),
          QStringLiteral("the live endpoint's redirect yields 3.0"));
    check(versionFrom("https://github.com/nekromoff/mailove/releases/tag/v3.1")
              == QLatin1String("3.1"),
          QStringLiteral("a future v-prefixed tag still parses"));
    check(versionFrom("https://github.com/nekromoff/mailove/releases/tag/3.1.4")
              == QLatin1String("3.1.4"),
          QStringLiteral("three components parse"));

    // --- tags that are not versions -----------------------------------------
    for (const auto *tag : {"SECURITY: act now", "latest", "", "3.0-rc1", "../../etc/passwd",
                            "99999", "<b>3.0</b>", "3.0;rm -rf /"}) {
        const QString loc =
            QStringLiteral("https://github.com/nekromoff/mailove/releases/tag/%1")
                .arg(QString::fromUtf8(tag));
        check(versionFrom(loc).isEmpty(),
              QStringLiteral("refused as a version: \"%1\"").arg(QString::fromUtf8(tag)));
    }
    check(versionFromTag(QStringLiteral("3.0.0.0.0")).isEmpty(),
          QStringLiteral("more than four components is refused"));
    check(versionFromTag(QStringLiteral("99999.1")).isEmpty(),
          QStringLiteral("an over-long component is refused"));

    // --- redirects that leave home -------------------------------------------
    check(versionFrom("https://evil.example/nekromoff/mailove/releases/tag/9.9").isEmpty(),
          QStringLiteral("a redirect to another host is refused"));
    check(versionFrom("http://github.com/nekromoff/mailove/releases/tag/9.9").isEmpty(),
          QStringLiteral("a redirect downgraded to http is refused"));
    check(versionFrom("javascript:alert(1)").isEmpty(),
          QStringLiteral("a non-http scheme in Location is refused"));
    check(versionFrom("").isEmpty(), QStringLiteral("an absent Location is refused"));
    check(tagFromLocation(QStringLiteral("https://GitHub.com/x/y/releases/tag/3.1"), kHost)
              == QLatin1String("3.1"),
          QStringLiteral("host comparison is case-insensitive"));

    // --- which version wins ---------------------------------------------------
    struct { const char *candidate; const char *running; bool newer; } order[] = {
        {"3.1", "3.0", true},
        {"3.0", "3.0", false},
        {"2.9", "3.0", false},
        // The one a string compare gets backwards.
        {"3.10", "3.9", true},
        {"3.9", "3.10", false},
        {"3.1", "3.0.9", true},
        {"3.1", "3.1.0", false},
        {"3.1.0", "3.1", false},
        {"3.1.1", "3.1", true},
        {"10.0", "9.9", true},
        {"4", "3.0", true},
    };
    for (const auto &c : order) {
        check(isNewer(QString::fromUtf8(c.candidate), QString::fromUtf8(c.running)) == c.newer,
              QStringLiteral("%1 %2 newer than %3")
                  .arg(QString::fromUtf8(c.candidate),
                       c.newer ? QStringLiteral("is") : QStringLiteral("is not"),
                       QString::fromUtf8(c.running)));
    }

    // --- the --force-version= affordance -------------------------------------
    // The whole point is exercising the marker without cutting a release, so
    // the forced value has to actually move the comparison — and has to be
    // held to the same standard as anything off the network.
    UpdateCheck::setRunningVersion(QStringLiteral("2.9"));
    check(UpdateCheck::runningVersion() == QLatin1String("2.9"),
          QStringLiteral("--force-version=2.9 is taken"));
    check(isNewer(QStringLiteral("3.0"), UpdateCheck::runningVersion()),
          QStringLiteral("3.0 counts as newer once 2.9 is forced"));
    UpdateCheck::setRunningVersion(QStringLiteral("not-a-version"));
    check(UpdateCheck::runningVersion() == QLatin1String("2.9"),
          QStringLiteral("a junk --force-version is ignored, not stored"));

    LOG("%s", "");
    if (!g_failures.isEmpty()) {
        for (const QString &f : g_failures)
            LOG("FAIL: %s", qPrintable(f));
        LOG("%lld case(s) failed", qint64(g_failures.size()));
        return 1;
    }
    LOG("PASS: redirect parsing, host and scheme checks, version ordering, "
        "and --force-version.");
    return 0;
}

