// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// The advanced-settings file: defaults when there is none, a verbatim
// round trip (comments and all), and the three ways a hand-edited file can
// be wrong — out of range, unknown key, junk value — none of which may stop
// the rest of it from applying. Syntax errors are the one refusal, and they
// have to name their line or the editor cannot point at them.
//
// Runs against a throwaway HOME so it never reads or writes the real file.

#include "advancedconfig.h"
#include <QCoreApplication>
#include <QDebug>
#include <cstdio>
#include <QDir>
#include <QFile>

static int failures = 0;
static void check(bool ok, const QString &what)
{
    std::printf("%s %s\n", ok ? "ok  :" : "FAIL:", qPrintable(what));
    if (!ok) ++failures;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // A throwaway config location: this test writes advanced.conf, and it must
    // never be the one the user is running with.
    const QString sandbox = QDir::tempPath() + QStringLiteral("/mailove-advancedconfigtest");
    QDir(sandbox).removeRecursively();
    QDir().mkpath(sandbox);
    qputenv("XDG_CONFIG_HOME", sandbox.toUtf8());
    QCoreApplication::setOrganizationName(QStringLiteral("mailove"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove"));

    AdvancedConfig &cfg = AdvancedConfig::instance();
    std::printf("file: %s\n", qPrintable(AdvancedConfig::filePath()));

    // Defaults with no file at all.
    check(AdvancedConfig::i("sync/headerWindow") == 200, "default int");
    check(qFuzzyCompare(AdvancedConfig::d("view/markReadSeconds"), 0.1),
          "markReadSeconds default");
    check(AdvancedConfig::i("spam/threshold") == 50, "spam threshold default");
    check(AdvancedConfig::d("attachments/worthwhileRatio") > 0.89, "double default");
    check(AdvancedConfig::s("psl/listUrl").startsWith(QLatin1String("https://")), "string default");

    // The seeded template must be inert: every key commented out.
    const QString tpl = cfg.defaultTemplate();
    check(cfg.problems(tpl).isEmpty(), "template parses with no problems");
    check(tpl.contains(QLatin1String("# markReadSeconds = 0.1")),
          "template documents markReadSeconds");
    check(tpl.contains(QLatin1String("[oauth]")), "template has groups");

    // A real edit.
    const QString good = QStringLiteral(
        "# mine\n[view]\nmarkReadSeconds = 0\n\n[sync]\nheaderWindow = 40\n");
    check(cfg.problems(good).isEmpty(), "valid file has no problems");
    check(cfg.save(good).isEmpty(), "save succeeds");
    check(AdvancedConfig::d("view/markReadSeconds") == 0.0, "markReadSeconds now never");
    check(AdvancedConfig::i("sync/headerWindow") == 40, "headerWindow now 40");
    check(cfg.text() == good, "text round-trips verbatim (comments kept)");

    // Clamping, unknown keys, junk values: warnings, never a refusal.
    const QString messy = QStringLiteral(
        "[sync]\nheaderWindow = 99999\n[imap]\nnosuchkey = 3\n[spam]\nthreshold = abc\n");
    const QVariantList p = cfg.problems(messy);
    bool sawClamp = false, sawUnknown = false, sawJunk = false, anyFatal = false;
    for (const QVariant &v : p) {
        const QVariantMap m = v.toMap();
        const QString t = m.value(QStringLiteral("text")).toString();
        if (m.value(QStringLiteral("fatal")).toBool()) anyFatal = true;
        if (t.contains(QLatin1String("outside"))) sawClamp = true;
        if (t.contains(QLatin1String("unknown key"))) sawUnknown = true;
        if (t.contains(QLatin1String("not a whole number"))) sawJunk = true;
    }
    check(sawClamp, "out-of-range value warns");
    check(sawUnknown, "unknown key warns");
    check(sawJunk, "non-numeric value warns");
    check(!anyFatal, "none of those are fatal");
    check(cfg.save(messy).isEmpty(), "messy file still saves");
    check(AdvancedConfig::i("sync/headerWindow") == 1000, "clamped to the maximum");
    check(AdvancedConfig::i("spam/threshold") == 50, "junk value falls back to default");

    // Syntax errors are fatal and name their line.
    const QString broken = QStringLiteral("[sync\nheaderWindow = 10\nstray line\n");
    const QVariantList bp = cfg.problems(broken);
    bool fatalWithLine = false;
    for (const QVariant &v : bp) {
        const QVariantMap m = v.toMap();
        if (m.value(QStringLiteral("fatal")).toBool() && m.value(QStringLiteral("line")).toInt() > 0)
            fatalWithLine = true;
    }
    check(fatalWithLine, "syntax error is fatal and carries a line number");
    check(!cfg.save(broken).isEmpty(), "broken file is refused");
    check(AdvancedConfig::i("sync/headerWindow") == 1000, "refused save changed nothing");

    // Restart keys are reported as such.
    const QString restarty = QStringLiteral("[imap]\nbodyPoolSize = 5\n");
    check(cfg.restartKeys(restarty).contains(QLatin1String("imap/bodyPoolSize")),
          "restart-only key is flagged");
    check(!cfg.restartKeys(QStringLiteral("[sync]\nheaderWindow = 33\n"))
               .contains(QLatin1String("sync/headerWindow")),
          "live key is not flagged");

    // A '#' inside a value stays part of the value.
    check(cfg.save(QStringLiteral("[psl]\nlistUrl = https://x.example/l.dat#frag\n")).isEmpty(),
          "url with fragment saves");
    check(AdvancedConfig::s("psl/listUrl").endsWith(QLatin1String("#frag")),
          "inline '#' is not a comment");

    // withKey(): what the reference list's click does. It must reuse a section
    // rather than repeat its header, and must never set the same key twice.
    {
        const QString base = QStringLiteral("[sync]\nheaderWindow = 40\n");
        const QString merged = cfg.withKey(base, QStringLiteral("sync/bodyPauseMs"));
        check(merged.count(QLatin1String("[sync]")) == 1, "existing section is reused");
        check(merged.contains(QLatin1String("bodyPauseMs = 600")), "key added at its default");
        check(merged.indexOf(QLatin1String("bodyPauseMs"))
                  > merged.indexOf(QLatin1String("headerWindow")),
              "added after the section's last line");

        const QString added = cfg.withKey(base, QStringLiteral("imap/bodyPoolSize"));
        check(added.contains(QLatin1String("[imap]")), "missing section is created");
        check(cfg.problems(added).isEmpty(), "the result parses cleanly");

        check(cfg.withKey(base, QStringLiteral("sync/headerWindow")) == base,
              "a key already set is left alone");
        // Into an empty file, and into one whose last section is not the target.
        check(cfg.problems(cfg.withKey(QString(), QStringLiteral("spam/threshold"))).isEmpty(),
              "insert into an empty file parses");
        const QString twoGroups =
            QStringLiteral("[sync]\nheaderWindow = 40\n\n[spam]\nthreshold = 60\n");
        const QString back = cfg.withKey(twoGroups, QStringLiteral("sync/bodyPauseMs"));
        check(back.count(QLatin1String("[sync]")) == 1, "no duplicate header for an earlier group");
        check(back.indexOf(QLatin1String("bodyPauseMs")) < back.indexOf(QLatin1String("[spam]")),
              "landed inside its own section, not after the next one");
        check(cfg.problems(back).isEmpty(), "and it still parses");
    }

    // Blank lines at the ends go; the ones between sections are layout and
    // stay. An emptied file is removed rather than left behind blank.
    {
        const QString padded =
            QStringLiteral("\n\n[sync]\nheaderWindow = 40\n\n\n[spam]\nthreshold = 60\n\n\n");
        check(cfg.save(padded).isEmpty(), "padded file saves");
        check(cfg.text().startsWith(QLatin1String("[sync]")), "leading blank lines trimmed");
        check(cfg.text().endsWith(QLatin1String("threshold = 60\n")), "trailing ones too");
        check(cfg.text().contains(QLatin1String("= 40\n\n\n[spam]")),
              "blank lines between sections are left alone");

        check(cfg.save(QStringLiteral("\n\n   \n\n")).isEmpty(), "an all-blank file saves");
        check(cfg.text().isEmpty(), "and leaves nothing behind");
        check(!QFile::exists(AdvancedConfig::filePath()), "the file itself is removed");
        check(AdvancedConfig::i("sync/headerWindow") == 200, "back to stock defaults");
        // Restored for the checks below, which read a file that overrides.
        check(cfg.save(QStringLiteral("[psl]\nlistUrl = https://x.example/l.dat#frag\n"))
                  .isEmpty(),
              "and a later save recreates it");
    }

    // Reference marks what the file overrides.
    bool marked = false;
    for (const QVariant &v : cfg.reference()) {
        const QVariantMap m = v.toMap();
        if (m.value(QStringLiteral("key")).toString() == QLatin1String("psl/listUrl"))
            marked = m.value(QStringLiteral("set")).toBool();
    }
    check(marked, "reference marks an overridden key as set");

    // Secrets: never on disk, always in the wallet, whatever was typed.
    {
        QHash<QString, QString> wallet;
        AdvancedConfig::setSecretSink([&wallet](const QString &key, const QString &value) {
            if (value.isEmpty())
                wallet.remove(key);
            else
                wallet.insert(key, value);
        });
        const QString withSecret =
            QStringLiteral("[oauth]\ngoogleClientId = mine.apps.googleusercontent.com\n"
                           "googleClientSecret = hunter2\n");
        bool warned = false;
        for (const QVariant &v : cfg.problems(withSecret)) {
            if (v.toMap().value(QStringLiteral("text")).toString().contains(
                    QLatin1String("system wallet")))
                warned = true;
        }
        check(warned, "a secret in the text warns before it is saved");
        check(cfg.save(withSecret).isEmpty(), "file with a secret saves");
        check(!cfg.text().contains(QLatin1String("hunter2")), "the secret is not in the text");
        check(cfg.text().contains(QLatin1String("googleClientSecret = @wallet")),
              "the line keeps the placeholder");
        check(cfg.text().contains(QLatin1String("mine.apps.googleusercontent.com")),
              "the client id beside it is untouched");
        check(wallet.value(QStringLiteral("advanced/oauth/googleClientSecret"))
                  == QLatin1String("hunter2"),
              "the secret reached the wallet");
        QFile onDisk(AdvancedConfig::filePath());
        check(onDisk.open(QIODevice::ReadOnly), "the file is readable");
        check(!QString::fromUtf8(onDisk.readAll()).contains(QLatin1String("hunter2")),
              "and never reached the file");
        onDisk.close();

        // Clearing the line forgets it rather than leaving it in the wallet.
        check(cfg.save(QStringLiteral("[oauth]\ngoogleClientSecret =\n")).isEmpty(),
              "an emptied secret saves");
        check(!wallet.contains(QStringLiteral("advanced/oauth/googleClientSecret")),
              "an emptied secret is deleted from the wallet");

        // A file hand-edited behind the client's back is swept at startup.
        QFile edited(AdvancedConfig::filePath());
        check(edited.open(QIODevice::WriteOnly | QIODevice::Text), "the file is writable");
        edited.write("[oauth]\nmicrosoftClientSecret = s3cret\n");
        edited.close();
        cfg.sweepSecrets();
        check(edited.open(QIODevice::ReadOnly), "the swept file is readable");
        const QString swept = QString::fromUtf8(edited.readAll());
        edited.close();
        check(!swept.contains(QLatin1String("s3cret")), "a hand-typed secret is swept off disk");
        check(wallet.value(QStringLiteral("advanced/oauth/microsoftClientSecret"))
                  == QLatin1String("s3cret"),
              "and into the wallet instead");
        AdvancedConfig::setSecretSink({});
        check(!cfg.save(QStringLiteral("[oauth]\ngoogleClientSecret = nope\n")).isEmpty(),
              "with no wallet the save is refused, not silently blanked");
    }


    QDir(QDir::tempPath() + QStringLiteral("/mailove-advancedconfigtest")).removeRecursively();
    std::printf("%s (%d failures)\n", failures == 0 ? "ALL PASS" : "FAILURES", failures);
    return failures;
}
