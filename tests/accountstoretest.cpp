// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/// Checks how accounts are stored, migrated and re-read.
///
/// Three rules here are load-bearing and none of them are visible from the
/// UI until they are already wrong:
///
///  * the account key. It names the wallet entry and the on-disk cache, so a
///    change to how it is derived orphans every cached folder and stored
///    password on an existing install.
///  * the session keys. saveAccountPrefs() must refuse them, because a
///    settings-page autosave writing a "host" would tear the connection down
///    on a keystroke; and saveAccountDetails() must report them as changed,
///    because that is what makes a real server change reconnect.
///  * the array rewrite. Removing or reordering an account rewrites every
///    account from a fixed key list, so a key missing from that list is a key
///    silently dropped from every account.
///
/// Runs against a test-only QSettings scope — the real ~/.config/mailove is
/// never opened. Nothing here touches the keyring: every case passes an empty
/// password, which is what stops AccountStore from starting a wallet job.
///
/// Exit 0 = all checks passed.

#include "accountstore.h"

#include <QCoreApplication>
#include <QFile>
#include <QStandardPaths>
#include <QTextStream>

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

/// A complete account map, so each case only states what it is varying.
QVariantMap account(const QString &host, const QString &user)
{
    return {
        {QStringLiteral("host"), host},
        {QStringLiteral("port"), 993},
        {QStringLiteral("security"), 0},
        {QStringLiteral("user"), user},
        {QStringLiteral("email"), user},
        {QStringLiteral("smtpHost"), QStringLiteral("smtp.example.net")},
        {QStringLiteral("smtpPort"), 587},
        {QStringLiteral("smtpSecurity"), 1},
        {QStringLiteral("authType"), 0},
        {QStringLiteral("signature"), QStringLiteral("<p>regards</p>")},
        {QStringLiteral("htmlMail"), true},
    };
}
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QStandardPaths::setTestModeEnabled(true);

    // AccountStore::settings() names the file itself ("mailove"/"mailove"), so the
    // isolation has to come from test mode alone. Prove it landed somewhere
    // disposable before writing a single key.
    const QString path = AccountStore::settings().fileName();
    if (!path.contains(QLatin1String("qttest"))) {
        qWarning() << "refusing to run: settings are not isolated:" << path;
        return 2;
    }
    QFile::remove(path); // a rerun must not judge the previous run's array

    // --- the account key -------------------------------------------------
    {
        AccountConfig cfg;
        cfg.user = QStringLiteral("jane");
        cfg.host = QStringLiteral("imap.example.net");
        check(cfg.accountKey() == QLatin1String("jane@imap.example.net"),
              "the account key is login@host");
        check(!cfg.valid() == false, "an account with a host and a login is usable");

        // An imported archive keeps its own key forever: filling in server
        // details later changes user/host, and without this the whole imported
        // cache would be orphaned by that edit.
        cfg.cacheKey = QStringLiteral("import:Thunderbird");
        check(cfg.accountKey() == QLatin1String("import:Thunderbird"),
              "an explicit cacheKey wins over login@host");

        AccountConfig empty;
        check(!empty.valid(), "an account with no host and no login is not usable");
    }

    // --- creating and reading back ---------------------------------------
    AccountStore store;
    store.migrate();
    check(store.count() == 0, "a fresh scope has no accounts");

    AccountStore::SaveResult first =
        store.saveDetails(-1, account(QStringLiteral("imap.example.net"),
                                      QStringLiteral("jane@example.net")));
    check(first.index == 0, "an out-of-range index appends");
    check(!first.existed, "…and is reported as new");
    check(store.count() == 1, "the account is in the array");

    const QVariantMap read = store.details(0);
    check(read.value(QStringLiteral("host")).toString() == QLatin1String("imap.example.net"),
          "the host round-trips");
    check(read.value(QStringLiteral("smtpPort")).toInt() == 587, "the SMTP port round-trips");
    // Absent means IMAP: every account written before JMAP existed is one, so
    // the key's absence has to keep meaning that.
    check(read.value(QStringLiteral("protocol")).toInt()
              == static_cast<int>(MailBackend::Protocol::Imap),
          "an account with no stored protocol reads back as IMAP");
    check(read.value(QStringLiteral("pgpAutoWkd")).toBool(),
          "WKD lookup defaults to on");

    store.setCurrentIndex(0);
    AccountConfig loaded = store.loadFields();
    check(loaded.user == QLatin1String("jane@example.net"), "loadFields reads the login");
    check(loaded.signature == QLatin1String("<p>regards</p>"), "loadFields reads the signature");
    check(loaded.protocol == static_cast<int>(MailBackend::Protocol::Imap),
          "loadFields defaults the protocol to IMAP");

    // --- what forces a reconnect -----------------------------------------
    {
        // Saving the same values again changes nothing a session is built
        // from — this is what stops a settings write from dropping a live
        // connection (and, on Gmail, spending one out of a small budget).
        AccountStore::SaveResult same =
            store.saveDetails(0, account(QStringLiteral("imap.example.net"),
                                         QStringLiteral("jane@example.net")));
        check(same.existed, "re-saving an existing account is reported as existing");
        check(!same.sessionChanged, "an unchanged save does not need a new session");

        QVariantMap sig = account(QStringLiteral("imap.example.net"),
                                  QStringLiteral("jane@example.net"));
        sig.insert(QStringLiteral("signature"), QStringLiteral("<p>new</p>"));
        AccountStore::SaveResult sigSave = store.saveDetails(0, sig);
        check(!sigSave.sessionChanged, "changing the signature does not need a new session");
        check(sigSave.signature == QLatin1String("<p>new</p>"),
              "…and the new signature is handed back for the live session");

        QVariantMap moved = account(QStringLiteral("imap.elsewhere.net"),
                                    QStringLiteral("jane@example.net"));
        AccountStore::SaveResult hostSave = store.saveDetails(0, moved);
        check(hostSave.sessionChanged, "changing the host does need a new session");

        // Back to where the rest of the cases expect it.
        store.saveDetails(0, account(QStringLiteral("imap.example.net"),
                                     QStringLiteral("jane@example.net")));
    }

    // --- header injection --------------------------------------------------
    // Both fields go into headers, so a newline in one would be an injection
    // point. Stripped on the way in, not on the way out.
    {
        QVariantMap evil = account(QStringLiteral("imap.example.net"),
                                   QStringLiteral("jane@example.net"));
        evil.insert(QStringLiteral("displayName"),
                    QStringLiteral("Jane\r\nBcc: attacker@evil.example"));
        evil.insert(QStringLiteral("organization"), QStringLiteral("Acme\nX-Evil: 1"));
        AccountStore::SaveResult r = store.saveDetails(0, evil);
        check(!r.displayName.contains(QLatin1Char('\n'))
                  && !r.displayName.contains(QLatin1Char('\r')),
              "a newline in the display name is stripped");
        check(!r.organization.contains(QLatin1Char('\n'))
                  && !r.organization.contains(QLatin1Char('\r')),
              "a newline in the organization is stripped");
    }

    // --- prefs refuse the session keys -------------------------------------
    {
        const QString hostBefore = store.details(0).value(QStringLiteral("host")).toString();
        QVariantMap prefs;
        prefs.insert(QStringLiteral("host"), QStringLiteral("imap.hijack.net")); // refused
        prefs.insert(QStringLiteral("signature"), QStringLiteral("<p>via prefs</p>"));
        const QVariantMap merged = store.savePrefs(0, prefs);
        check(!merged.isEmpty(), "a prefs write that changes something reports the account");
        check(store.details(0).value(QStringLiteral("host")).toString() == hostBefore,
              "savePrefs refuses to write a session key");
        check(store.details(0).value(QStringLiteral("signature")).toString()
                  == QLatin1String("<p>via prefs</p>"),
              "savePrefs writes a non-session key");

        // Nothing actually different must not announce a change — this is what
        // keeps a settings page that autosaves on focus-out quiet.
        check(store.savePrefs(0, prefs).isEmpty(), "an unchanged prefs write reports nothing");
        check(store.savePrefs(99, prefs).isEmpty(), "a prefs write to an unknown index is refused");
    }

    // --- the array rewrite keeps every key ---------------------------------
    {
        store.saveDetails(-1, account(QStringLiteral("imap.second.net"),
                                      QStringLiteral("bob@second.net")));
        check(store.count() == 2, "a second account appends");

        // Reordering rewrites the whole array from the fixed key list. A key
        // missing from that list is dropped from every account here, silently.
        const QVariantMap beforeMove = store.details(0);
        check(store.move(0, 1), "accounts can be reordered");
        const QVariantMap afterMove = store.details(1);
        check(afterMove.value(QStringLiteral("signature"))
                  == beforeMove.value(QStringLiteral("signature")),
              "the signature survives a reorder");
        check(afterMove.value(QStringLiteral("smtpSecurity"))
                  == beforeMove.value(QStringLiteral("smtpSecurity")),
              "the SMTP security survives a reorder");
        check(afterMove.value(QStringLiteral("pgpAutoWkd"))
                  == beforeMove.value(QStringLiteral("pgpAutoWkd")),
              "the OpenPGP settings survive a reorder");
        check(!store.move(0, 0), "a move to the same place is a no-op");
        check(!store.move(0, 9), "a move out of range is refused");
    }

    // --- imported archives ---------------------------------------------------
    {
        QVariantMap archive;
        archive.insert(QStringLiteral("user"), QStringLiteral("Thunderbird"));
        archive.insert(QStringLiteral("local"), true);
        archive.insert(QStringLiteral("cacheKey"), QStringLiteral("import:Thunderbird"));
        const int slot = store.append(archive);
        check(slot >= 0, "an archive account can be appended");
        check(store.indexOfCacheKey(QStringLiteral("import:Thunderbird")) == slot,
              "an archive is found by its cache key");
        check(store.indexOfCacheKey(QStringLiteral("import:nope")) == -1,
              "an unknown cache key is not found");

        bool isLocal = false;
        check(store.storedKeyAt(slot, &isLocal) == QLatin1String("import:Thunderbird"),
              "storedKeyAt returns the archive's own key");
        check(isLocal, "…and reports it as a local account");

        check(store.removeByCacheKey(QStringLiteral("import:Thunderbird")),
              "an archive can be taken back out by cache key");
        check(store.indexOfCacheKey(QStringLiteral("import:Thunderbird")) == -1,
              "…and is gone afterwards");
        check(!store.removeByCacheKey(QStringLiteral("import:Thunderbird")),
              "removing it twice reports nothing removed");
    }

    // --- unknown indices ---------------------------------------------------
    check(store.details(99).isEmpty(), "details() of an unknown index is empty");
    check(store.storedKeyAt(99).isEmpty(), "storedKeyAt() of an unknown index is empty");
    check(store.remove(99) == -1, "removing an unknown index is refused");

    // --- removal ------------------------------------------------------------
    {
        const int before = store.count();
        check(store.remove(0) == before - 1, "removing an account reports what is left");
        check(store.count() == before - 1, "…and the array agrees");
    }

    // --- the legacy single-account migration ---------------------------------
    // Pre-array installs kept one account under "account/…" and "smtp/…". The
    // migration has to move it into slot 0 and clear the old keys, or the next
    // start migrates it a second time.
    {
        QFile::remove(path);
        {
            QSettings s = AccountStore::settings();
            s.setValue(QStringLiteral("account/host"), QStringLiteral("imap.old.net"));
            s.setValue(QStringLiteral("account/user"), QStringLiteral("olduser"));
            s.setValue(QStringLiteral("account/port"), 143);
            s.setValue(QStringLiteral("smtp/host"), QStringLiteral("smtp.old.net"));
            s.setValue(QStringLiteral("smtp/port"), 25);
        }
        AccountStore legacy;
        legacy.migrate();
        check(legacy.count() == 1, "the legacy account becomes slot 0");
        const QVariantMap m = legacy.details(0);
        check(m.value(QStringLiteral("host")).toString() == QLatin1String("imap.old.net"),
              "the legacy host is carried over");
        check(m.value(QStringLiteral("port")).toInt() == 143, "the legacy port is carried over");
        check(m.value(QStringLiteral("smtpHost")).toString() == QLatin1String("smtp.old.net"),
              "the legacy SMTP host is carried over");
        check(AccountStore::settings().value(QStringLiteral("account/host")).isNull(),
              "the legacy keys are cleared");

        // The login was the address on those installs, and that is what they
        // sent as — so it is copied across rather than re-derived on every send.
        check(legacy.details(0).value(QStringLiteral("email")).toString().isEmpty(),
              "a login that is not an address gets no address");
    }

    // --- the address migration ------------------------------------------------
    {
        QFile::remove(path);
        {
            QSettings s = AccountStore::settings();
            s.beginWriteArray(QStringLiteral("accounts"), 1);
            s.setArrayIndex(0);
            s.setValue(QStringLiteral("host"), QStringLiteral("imap.example.net"));
            s.setValue(QStringLiteral("user"), QStringLiteral("jane@example.net"));
            s.endArray();
        }
        AccountStore migrated;
        migrated.migrate();
        check(migrated.details(0).value(QStringLiteral("email")).toString()
                  == QLatin1String("jane@example.net"),
              "a login that is an address is copied into the address field");
    }

    // --- the wallet key ---------------------------------------------------
    // Keyed on the login, not the address: rebasing it would orphan every
    // stored password on an existing install.
    check(AccountStore::walletKeyFor(QStringLiteral("jane"), QStringLiteral("imap.example.net"))
              == QLatin1String("imap-password:jane@imap.example.net"),
          "the wallet key is the password key plus login@host");
    check(AccountStore::oauthWalletKeyFor(QStringLiteral("jane"),
                                          QStringLiteral("imap.example.net"))
              == QLatin1String("oauth-refresh:jane@imap.example.net"),
          "the OAuth key is its own namespace");

    // --- secrets ----------------------------------------------------------
    {
        AccountStore s;
        check(!s.secretReady(), "a fresh store has not settled its secret");
        // A local archive owns no secret, and a password handed in for this
        // session is already here — both settle it without a wallet read.
        s.setSessionSecret(QStringLiteral("hunter2"));
        check(s.secretReady(), "a session secret settles it");
        check(s.password() == QLatin1String("hunter2"), "…and is what gets offered");
        s.setSessionSecret(QString());
        check(s.secretReady() && s.password().isEmpty(),
              "an empty session secret settles it too (the archive case)");

        s.setAccessToken(QStringLiteral("tok"), QDateTime::currentDateTimeUtc());
        s.setRefreshToken(QStringLiteral("ref"));
        s.clearTokens();
        check(s.accessToken().isEmpty() && s.refreshToken().isEmpty(),
              "tokens do not survive an account switch");
    }

    QFile::remove(path);
    out << (failures == 0 ? "all account store tests passed\n"
                          : QStringLiteral("%1 check(s) failed\n").arg(failures));
    out.flush();
    return failures == 0 ? 0 : 1;
}
