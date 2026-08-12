// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "accountstore.h"

#include <QRegularExpression>

#include <qt6keychain/keychain.h>

static const auto kWalletService = QStringLiteral("mailove");
static const auto kWalletKey = QStringLiteral("imap-password");

/// SslTls — the enumerator lives on MailClient, which this class deliberately
/// does not include. The value is part of the on-disk format either way.
static constexpr int kSecuritySslTls = 0;

AccountStore::AccountStore(QObject *parent)
    : QObject(parent)
{
}

QSettings AccountStore::settings()
{
    return QSettings(QStringLiteral("mailove"), QStringLiteral("mailove"));
}

QString AccountStore::walletKeyFor(const QString &user, const QString &host)
{
    return kWalletKey + QLatin1Char(':') + user + QLatin1Char('@') + host;
}

QString AccountStore::oauthWalletKeyFor(const QString &user, const QString &host)
{
    return QStringLiteral("oauth-refresh:") + user + QLatin1Char('@') + host;
}

QString AccountStore::storedKeyAt(QSettings &s, int index, bool *local)
{
    QString user, host, cacheKey;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (index >= 0 && index < count) {
        s.setArrayIndex(index);
        user = s.value(QStringLiteral("user")).toString();
        host = s.value(QStringLiteral("host")).toString();
        cacheKey = s.value(QStringLiteral("cacheKey")).toString();
        if (local)
            *local = s.value(QStringLiteral("local"), false).toBool();
    }
    s.endArray();
    if (!cacheKey.isEmpty())
        return cacheKey;
    if (host.isEmpty() && user.isEmpty())
        return {};
    return user + QLatin1Char('@') + host;
}

QString AccountStore::storedKeyAt(int index, bool *local) const
{
    QSettings s = settings();
    return storedKeyAt(s, index, local);
}

int AccountStore::count() const
{
    QSettings s = settings();
    const int n = s.beginReadArray(QStringLiteral("accounts"));
    s.endArray();
    return n;
}

QStringList AccountStore::names() const
{
    QSettings s = settings();
    QStringList names;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    for (int i = 0; i < count; ++i) {
        s.setArrayIndex(i);
        // The list is user-facing, so it shows the address; the login and the
        // host are only fallbacks for accounts that have no address stored.
        const QString email = s.value(QStringLiteral("email")).toString();
        const QString user = s.value(QStringLiteral("user")).toString();
        if (!email.isEmpty())
            names.append(email);
        else
            names.append(user.isEmpty() ? s.value(QStringLiteral("host")).toString() : user);
    }
    s.endArray();
    return names;
}

QVariantMap AccountStore::details(int index) const
{
    QSettings s = settings();
    QVariantMap out;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (index >= 0 && index < count) {
        s.setArrayIndex(index);
        out.insert(QStringLiteral("host"), s.value(QStringLiteral("host")).toString());
        out.insert(QStringLiteral("protocol"),
                   s.value(QStringLiteral("protocol"),
                           static_cast<int>(MailBackend::Protocol::Imap))
                       .toInt());
        out.insert(QStringLiteral("port"), s.value(QStringLiteral("port"), 993).toInt());
        out.insert(QStringLiteral("security"),
                   s.value(QStringLiteral("security"), kSecuritySslTls).toInt());
        out.insert(QStringLiteral("user"), s.value(QStringLiteral("user")).toString());
        out.insert(QStringLiteral("email"), s.value(QStringLiteral("email")).toString());
        out.insert(QStringLiteral("displayName"),
                   s.value(QStringLiteral("displayName")).toString());
        out.insert(QStringLiteral("organization"),
                   s.value(QStringLiteral("organization")).toString());
        out.insert(QStringLiteral("smtpHost"), s.value(QStringLiteral("smtpHost")).toString());
        out.insert(QStringLiteral("smtpPort"), s.value(QStringLiteral("smtpPort"), 587).toInt());
        out.insert(QStringLiteral("smtpSecurity"),
                   s.value(QStringLiteral("smtpSecurity"), 1).toInt());
        out.insert(QStringLiteral("authType"), s.value(QStringLiteral("authType"), 0).toInt());
        out.insert(QStringLiteral("bearerAuth"),
                   s.value(QStringLiteral("bearerAuth"), false).toBool());
        out.insert(QStringLiteral("clientId"), s.value(QStringLiteral("clientId")).toString());
        out.insert(QStringLiteral("clientSecret"),
                   s.value(QStringLiteral("clientSecret")).toString());
        out.insert(QStringLiteral("signature"),
                   s.value(QStringLiteral("signature")).toString());
        out.insert(QStringLiteral("htmlMail"),
                   s.value(QStringLiteral("htmlMail"), true).toBool());
        out.insert(QStringLiteral("local"), s.value(QStringLiteral("local"), false).toBool());
        // OpenPGP: the fingerprint of this identity's key and what to do with
        // it. No key material — that stays in the user's GnuPG home, and this
        // is only a pointer into it (doc/openpgp.md §8).
        out.insert(QStringLiteral("pgpKeyFp"), s.value(QStringLiteral("pgpKeyFp")).toString());
        out.insert(QStringLiteral("pgpSignByDefault"),
                   s.value(QStringLiteral("pgpSignByDefault"), false).toBool());
        out.insert(QStringLiteral("pgpEncryptByDefault"),
                   s.value(QStringLiteral("pgpEncryptByDefault"), false).toBool());
        out.insert(QStringLiteral("pgpAutoWkd"),
                   s.value(QStringLiteral("pgpAutoWkd"), true).toBool());
    }
    s.endArray();
    return out;
}

/// The settings a live session is built from: change one and the connection
/// has to be made again, which is exactly what savePrefs() must never do.
/// "local" and "cacheKey" are in here because they decide whether there is a
/// session at all and which cache it reads.
static const QStringList kSessionKeys = {
    QStringLiteral("host"),         QStringLiteral("port"),
    QStringLiteral("security"),     QStringLiteral("user"),
    QStringLiteral("email"),        QStringLiteral("smtpHost"),
    QStringLiteral("smtpPort"),     QStringLiteral("smtpSecurity"),
    QStringLiteral("authType"),     QStringLiteral("clientId"),
    QStringLiteral("clientSecret"), QStringLiteral("local"),
    QStringLiteral("cacheKey"),
    // Which header the secret goes in decides whether the login works at all.
    QStringLiteral("bearerAuth"),
    // Changing the protocol replaces the backend outright, so it belongs here
    // with the rest of what a live connection depends on.
    QStringLiteral("protocol")};

/// Every per-account setting, in one place: the account array is rewritten
/// wholesale when an account is removed or reordered, and a key missing from
/// this list is a key silently dropped from every account by that rewrite.
static QStringList accountSettingKeys()
{
    return {QStringLiteral("host"),         QStringLiteral("port"),
            QStringLiteral("security"),     QStringLiteral("user"),
            QStringLiteral("email"),        QStringLiteral("displayName"),
            QStringLiteral("organization"),
            QStringLiteral("smtpHost"),     QStringLiteral("smtpPort"),
            QStringLiteral("smtpSecurity"), QStringLiteral("authType"),
            // Both decide how (and whether) the account connects, and this
            // list is what a prefs autosave rewrites the account from: leaving
            // them out quietly turned a saved JMAP account back into an IMAP
            // one the next time its signature changed.
            QStringLiteral("protocol"),     QStringLiteral("bearerAuth"),
            QStringLiteral("clientId"),
            QStringLiteral("clientSecret"), QStringLiteral("signature"),
            QStringLiteral("htmlMail"),     QStringLiteral("local"),
            QStringLiteral("cacheKey"),
            QStringLiteral("pgpKeyFp"),     QStringLiteral("pgpSignByDefault"),
            QStringLiteral("pgpEncryptByDefault"),
            QStringLiteral("pgpAutoWkd")};
}

/// Reads the whole account array out of \a s so it can be rewritten.
static QList<QVariantMap> readAccountArray(QSettings &s)
{
    const QStringList keys = accountSettingKeys();
    QList<QVariantMap> accounts;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    for (int i = 0; i < count; ++i) {
        s.setArrayIndex(i);
        QVariantMap a;
        for (const QString &k : keys)
            a.insert(k, s.value(k));
        accounts.append(a);
    }
    s.endArray();
    return accounts;
}

/// Replaces the account array in \a s with \a accounts.
static void writeAccountArray(QSettings &s, const QList<QVariantMap> &accounts)
{
    s.remove(QStringLiteral("accounts"));
    s.beginWriteArray(QStringLiteral("accounts"), accounts.size());
    for (int i = 0; i < accounts.size(); ++i) {
        s.setArrayIndex(i);
        for (auto it = accounts.at(i).constBegin(); it != accounts.at(i).constEnd(); ++it)
            s.setValue(it.key(), it.value());
    }
    s.endArray();
}

QList<QVariantMap> AccountStore::all() const
{
    QSettings s = settings();
    return readAccountArray(s);
}

/// One-time migration of the legacy single-account keys ("account/…",
/// "smtp/…") into slot 0 of the accounts array.
static void migrateLegacyAccount(QSettings &s)
{
    if (s.value(QStringLiteral("accounts/size"), 0).toInt() > 0)
        return;
    // Every legacy value is read up front, before beginWriteArray(). Inside
    // the array scope a plain key resolves *relative to it* — "account/port"
    // becomes "accounts/1/account/port", which does not exist — so reading
    // them there silently handed back the defaults instead, and a pre-array
    // install migrated with its port reset to 993 and its SMTP host lost.
    const QString host = s.value(QStringLiteral("account/host")).toString();
    const QString user = s.value(QStringLiteral("account/user")).toString();
    if (host.isEmpty() && user.isEmpty())
        return;
    const QVariant port = s.value(QStringLiteral("account/port"), 993);
    const QVariant security = s.value(QStringLiteral("account/security"), kSecuritySslTls);
    const QVariant smtpHost = s.value(QStringLiteral("smtp/host"));
    const QVariant smtpPort = s.value(QStringLiteral("smtp/port"), 587);
    const QVariant smtpSecurity = s.value(QStringLiteral("smtp/security"), 1);

    s.beginWriteArray(QStringLiteral("accounts"), 1);
    s.setArrayIndex(0);
    s.setValue(QStringLiteral("host"), host);
    s.setValue(QStringLiteral("port"), port);
    s.setValue(QStringLiteral("security"), security);
    s.setValue(QStringLiteral("user"), user);
    s.setValue(QStringLiteral("smtpHost"), smtpHost);
    s.setValue(QStringLiteral("smtpPort"), smtpPort);
    s.setValue(QStringLiteral("smtpSecurity"), smtpSecurity);
    s.endArray();
    s.setValue(QStringLiteral("currentAccount"), 0);
    s.remove(QStringLiteral("account/host"));
    s.remove(QStringLiteral("account/port"));
    s.remove(QStringLiteral("account/security"));
    s.remove(QStringLiteral("account/user"));
    s.remove(QStringLiteral("smtp"));
    // "account/secret" (pre-wallet plaintext) is handled by takeLegacySecret().
}

/// One-time migration: before the address had its own field, accounts kept it
/// in the login, and that is what they sent as. Copy it across so the address
/// is stored outright rather than re-derived on every send. Logins that are
/// not addresses are left alone — there is nothing to copy, and ownAddress()
/// keeps guessing for them until the account dialog is filled in.
static void migrateAccountEmail(QSettings &s)
{
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    QList<int> needsEmail;
    for (int i = 0; i < count; ++i) {
        s.setArrayIndex(i);
        if (!s.value(QStringLiteral("email")).toString().isEmpty())
            continue;
        if (s.value(QStringLiteral("user")).toString().contains(QLatin1Char('@')))
            needsEmail.append(i);
    }
    s.endArray();
    if (needsEmail.isEmpty())
        return;

    s.beginWriteArray(QStringLiteral("accounts"), count);
    for (const int i : needsEmail) {
        s.setArrayIndex(i);
        s.setValue(QStringLiteral("email"), s.value(QStringLiteral("user")));
    }
    s.endArray();
}

void AccountStore::migrate()
{
    QSettings s = settings();
    migrateLegacyAccount(s);
    migrateAccountEmail(s);
    m_current = s.value(QStringLiteral("currentAccount"), 0).toInt();
}

void AccountStore::setCurrentIndex(int index)
{
    m_current = index;
    settings().setValue(QStringLiteral("currentAccount"), index);
}

AccountConfig AccountStore::loadFields()
{
    AccountConfig cfg;
    QSettings s = settings();
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (count == 0) {
        s.endArray();
        clearTokens();
        return cfg; // all defaults: no account configured
    }
    m_current = qBound(0, m_current, count - 1);
    s.setArrayIndex(m_current);
    cfg.host = s.value(QStringLiteral("host")).toString();
    cfg.protocol = s.value(QStringLiteral("protocol"),
                           static_cast<int>(MailBackend::Protocol::Imap))
                       .toInt();
    cfg.port = s.value(QStringLiteral("port"), 993).toInt();
    cfg.security = s.value(QStringLiteral("security"), kSecuritySslTls).toInt();
    cfg.user = s.value(QStringLiteral("user")).toString();
    cfg.email = s.value(QStringLiteral("email")).toString();
    cfg.displayName = s.value(QStringLiteral("displayName")).toString();
    cfg.organization = s.value(QStringLiteral("organization")).toString();
    cfg.smtpHost = s.value(QStringLiteral("smtpHost")).toString();
    cfg.smtpPort = s.value(QStringLiteral("smtpPort"), 587).toInt();
    cfg.smtpSecurity = s.value(QStringLiteral("smtpSecurity"), 1).toInt();
    cfg.authType = s.value(QStringLiteral("authType"), 0).toInt();
    cfg.bearerAuth = s.value(QStringLiteral("bearerAuth"), false).toBool();
    cfg.clientId = s.value(QStringLiteral("clientId")).toString();
    cfg.clientSecret = s.value(QStringLiteral("clientSecret")).toString();
    cfg.signature = s.value(QStringLiteral("signature")).toString();
    cfg.htmlMail = s.value(QStringLiteral("htmlMail"), true).toBool();
    cfg.local = s.value(QStringLiteral("local"), false).toBool();
    cfg.cacheKey = s.value(QStringLiteral("cacheKey")).toString();
    s.endArray();

    clearTokens(); // tokens never survive an account switch
    if (cfg.smtpHost.isEmpty() && !cfg.host.isEmpty()) {
        // Sensible default: imap.example.com → smtp.example.com
        cfg.smtpHost = cfg.host;
        cfg.smtpHost.replace(QRegularExpression(QStringLiteral("^imap")),
                             QStringLiteral("smtp"));
    }
    return cfg;
}

AccountStore::SaveResult AccountStore::saveDetails(int index, const QVariantMap &d)
{
    SaveResult result;
    const QString trimmedHost = d.value(QStringLiteral("host")).toString().trimmed();
    const QString trimmedUser = d.value(QStringLiteral("user")).toString().trimmed();
    const QString trimmedEmail = d.value(QStringLiteral("email")).toString().trimmed();
    // The display name goes into a header, so a newline in it would be a
    // header-injection point — same treatment the compose fields get.
    static const QRegularExpression headerCrlfRe(QStringLiteral("[\\r\\n]"));
    const QString displayName = d.value(QStringLiteral("displayName"))
                                    .toString()
                                    .remove(headerCrlfRe)
                                    .trimmed();
    const QString organization = d.value(QStringLiteral("organization"))
                                     .toString()
                                     .remove(headerCrlfRe)
                                     .trimmed();
    const QString password = d.value(QStringLiteral("password")).toString();
    const bool savePassword = d.value(QStringLiteral("savePassword"), true).toBool();
    const int authType = d.value(QStringLiteral("authType"), 0).toInt();

    QSettings s = settings();
    // An imported archive keeps its storage key forever, and stops being a
    // local (never-connecting) account the moment a server is filled in —
    // that is the whole upgrade path from "dead archive" to live account.
    bool wasLocal = false;
    QString cacheKey;
    // The encryption settings as they stand, so a caller that does not mention
    // them — the archive importer, say — does not silently unset the account's
    // key by omission.
    QVariantMap pgpNow;
    // The session-deciding fields as they stand, so an unchanged save does not
    // drop the connection (see the comparison at the end of this function).
    QVariantMap sessionNow;
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (index >= 0 && index < count) {
        s.setArrayIndex(index);
        result.existed = true;
        for (const QString &k : kSessionKeys)
            sessionNow.insert(k, s.value(k));
        wasLocal = s.value(QStringLiteral("local"), false).toBool();
        cacheKey = s.value(QStringLiteral("cacheKey")).toString();
        pgpNow.insert(QStringLiteral("pgpKeyFp"), s.value(QStringLiteral("pgpKeyFp"), QString()));
        pgpNow.insert(QStringLiteral("pgpSignByDefault"),
                      s.value(QStringLiteral("pgpSignByDefault"), false));
        pgpNow.insert(QStringLiteral("pgpEncryptByDefault"),
                      s.value(QStringLiteral("pgpEncryptByDefault"), false));
        pgpNow.insert(QStringLiteral("pgpAutoWkd"),
                      s.value(QStringLiteral("pgpAutoWkd"), true));
    }
    s.endArray();
    if (index < 0 || index > count)
        index = count; // append as a new account
    // The account dialog states the type outright ("Imported account"), so
    // take it at its word. The old rule — an archive stays one while it has no
    // server — remains the fallback for callers that do not say, which is what
    // the import path itself relies on.
    const bool stillLocal = d.contains(QStringLiteral("local"))
        ? d.value(QStringLiteral("local")).toBool()
        : (wasLocal && trimmedHost.isEmpty());

    s.beginWriteArray(QStringLiteral("accounts"), qMax(count, index + 1));
    s.setArrayIndex(index);
    s.setValue(QStringLiteral("host"), trimmedHost);
    // Absent means IMAP: every account written before JMAP existed is one, and
    // the enumerator values are part of the on-disk format (MailBackend.h).
    s.setValue(QStringLiteral("protocol"),
               d.value(QStringLiteral("protocol"),
                       static_cast<int>(MailBackend::Protocol::Imap))
                   .toInt());
    s.setValue(QStringLiteral("port"), d.value(QStringLiteral("port"), 993).toInt());
    s.setValue(QStringLiteral("security"), d.value(QStringLiteral("security"), 0).toInt());
    s.setValue(QStringLiteral("user"), trimmedUser);
    s.setValue(QStringLiteral("email"), trimmedEmail);
    s.setValue(QStringLiteral("displayName"), displayName);
    s.setValue(QStringLiteral("organization"), organization);
    s.setValue(QStringLiteral("smtpHost"),
               d.value(QStringLiteral("smtpHost")).toString().trimmed());
    s.setValue(QStringLiteral("smtpPort"), d.value(QStringLiteral("smtpPort"), 587).toInt());
    s.setValue(QStringLiteral("smtpSecurity"),
               d.value(QStringLiteral("smtpSecurity"), 1).toInt());
    s.setValue(QStringLiteral("authType"), authType);
    // Absent means "offer the secret as a password", which is what every
    // account written before tokens existed meant.
    s.setValue(QStringLiteral("bearerAuth"),
               d.value(QStringLiteral("bearerAuth"), false).toBool());
    s.setValue(QStringLiteral("clientId"), d.value(QStringLiteral("clientId")).toString());
    s.setValue(QStringLiteral("clientSecret"),
               d.value(QStringLiteral("clientSecret")).toString());
    s.setValue(QStringLiteral("signature"), d.value(QStringLiteral("signature")).toString());
    s.setValue(QStringLiteral("htmlMail"), d.value(QStringLiteral("htmlMail"), true).toBool());
    s.setValue(QStringLiteral("local"), stillLocal);
    s.setValue(QStringLiteral("cacheKey"), cacheKey);
    s.setValue(QStringLiteral("pgpKeyFp"),
               d.value(QStringLiteral("pgpKeyFp"),
                       pgpNow.value(QStringLiteral("pgpKeyFp"), QString()))
                   .toString()
                   .trimmed());
    s.setValue(QStringLiteral("pgpSignByDefault"),
               d.value(QStringLiteral("pgpSignByDefault"),
                       pgpNow.value(QStringLiteral("pgpSignByDefault"), false))
                   .toBool());
    s.setValue(QStringLiteral("pgpEncryptByDefault"),
               d.value(QStringLiteral("pgpEncryptByDefault"),
                       pgpNow.value(QStringLiteral("pgpEncryptByDefault"), false))
                   .toBool());
    s.setValue(QStringLiteral("pgpAutoWkd"),
               d.value(QStringLiteral("pgpAutoWkd"),
                       pgpNow.value(QStringLiteral("pgpAutoWkd"), true))
                   .toBool());
    s.endArray();

    if (authType == 0) {
        if (!password.isEmpty() && savePassword) {
            auto *write = new QKeychain::WritePasswordJob(kWalletService, this);
            write->setKey(walletKeyFor(trimmedUser, trimmedHost));
            write->setTextData(password);
            write->start();
        } else if (!savePassword) {
            auto *del = new QKeychain::DeletePasswordJob(kWalletService, this);
            del->setKey(walletKeyFor(trimmedUser, trimmedHost));
            del->start();
        }
    }

    // What was just written, for the comparison below.
    QVariantMap sessionNext;
    const int written = s.beginReadArray(QStringLiteral("accounts"));
    if (index < written) {
        s.setArrayIndex(index);
        for (const QString &k : kSessionKeys)
            sessionNext.insert(k, s.value(k));
    }
    s.endArray();

    result.index = index;
    result.sessionChanged = sessionNext != sessionNow;
    result.password = password;
    result.authType = authType;
    result.displayName = displayName;
    result.organization = organization;
    result.signature = d.value(QStringLiteral("signature")).toString();
    result.htmlMail = d.value(QStringLiteral("htmlMail"), true).toBool();
    return result;
}

QVariantMap AccountStore::savePrefs(int index, const QVariantMap &d)
{
    QSettings s = settings();
    QList<QVariantMap> accounts = readAccountArray(s);
    // An account that moved or was removed under an open settings page: the
    // write would land on somebody else's row, so it does not happen.
    if (index < 0 || index >= accounts.size())
        return {};

    static const QRegularExpression headerCrlfRe(QStringLiteral("[\\r\\n]"));
    QVariantMap account = accounts.at(index);
    bool touched = false;
    for (auto it = d.constBegin(); it != d.constEnd(); ++it) {
        if (kSessionKeys.contains(it.key()))
            continue; // explicit save only — see the header
        QVariant value = it.value();
        // Both go into headers, where a newline would be an injection point.
        if (it.key() == QLatin1String("displayName")
            || it.key() == QLatin1String("organization"))
            value = value.toString().remove(headerCrlfRe).trimmed();
        if (account.value(it.key()) == value)
            continue;
        account.insert(it.key(), value);
        touched = true;
    }
    if (!touched)
        return {}; // nothing to write, nothing to announce

    accounts[index] = account;
    writeAccountArray(s, accounts);
    return account;
}

int AccountStore::remove(int index)
{
    QSettings s = settings();
    QList<QVariantMap> accounts = readAccountArray(s);
    if (index < 0 || index >= accounts.size())
        return -1;

    const QString delUser = accounts.at(index).value(QStringLiteral("user")).toString();
    const QString delHost = accounts.at(index).value(QStringLiteral("host")).toString();
    for (const QString &key : {walletKeyFor(delUser, delHost),
                               oauthWalletKeyFor(delUser, delHost)}) {
        auto *del = new QKeychain::DeletePasswordJob(kWalletService, this);
        del->setKey(key);
        del->start();
    }

    accounts.removeAt(index);
    writeAccountArray(s, accounts);
    return int(accounts.size());
}

int AccountStore::append(const QVariantMap &account)
{
    QSettings s = settings();
    QList<QVariantMap> accounts = readAccountArray(s);
    accounts.append(account);
    writeAccountArray(s, accounts);
    return int(accounts.size()) - 1;
}

int AccountStore::indexOfCacheKey(const QString &cacheKey) const
{
    const QList<QVariantMap> accounts = all();
    for (int i = 0; i < accounts.size(); ++i) {
        if (accounts.at(i).value(QStringLiteral("cacheKey")).toString() == cacheKey)
            return i;
    }
    return -1;
}

bool AccountStore::removeByCacheKey(const QString &cacheKey)
{
    QSettings s = settings();
    QList<QVariantMap> accounts = readAccountArray(s);
    bool removed = false;
    for (int i = accounts.size() - 1; i >= 0; --i) {
        if (accounts.at(i).value(QStringLiteral("cacheKey")).toString() == cacheKey) {
            accounts.removeAt(i);
            removed = true;
        }
    }
    if (removed)
        writeAccountArray(s, accounts);
    return removed;
}

bool AccountStore::move(int from, int to)
{
    QSettings s = settings();
    QList<QVariantMap> accounts = readAccountArray(s);
    if (from == to || from < 0 || from >= accounts.size() || to < 0 || to >= accounts.size())
        return false;

    accounts.move(from, to);
    writeAccountArray(s, accounts);
    return true;
}

void AccountStore::setSessionSecret(const QString &password)
{
    ++m_walletGen; // cancel any in-flight wallet read
    m_password = password;
    m_secretReady = true;
}

void AccountStore::clearTokens()
{
    m_accessToken.clear();
    m_refreshToken.clear();
    m_accessTokenExpiry = QDateTime();
}

bool AccountStore::takeLegacySecret(QString *password)
{
    // One-time migration: pre-wallet builds kept the password base64-encoded
    // in the config file. The caller moves it into the system wallet, which is
    // what wipes it.
    const QByteArray legacy =
        settings().value(QStringLiteral("account/secret")).toByteArray();
    if (legacy.isEmpty())
        return false;
    if (password)
        *password = QString::fromUtf8(QByteArray::fromBase64(legacy));
    return true;
}

void AccountStore::readSecret(const AccountConfig &cfg)
{
    m_password.clear();
    m_refreshToken.clear();
    m_secretReady = false;
    const int gen = ++m_walletGen;

    auto finish = [this, gen] {
        if (gen != m_walletGen)
            return; // the account changed while we were reading — stale result
        m_secretReady = true;
        Q_EMIT secretsReady();
    };

    // OAuth accounts keep a refresh token in the wallet instead of a password.
    if (cfg.authType != 0) {
        auto *read = new QKeychain::ReadPasswordJob(kWalletService, this);
        read->setKey(oauthWalletKeyFor(cfg.user, cfg.host));
        connect(read, &QKeychain::Job::finished, this, [this, read, gen, finish] {
            if (gen != m_walletGen)
                return;
            if (!read->error())
                m_refreshToken = read->textData();
            finish();
        });
        read->start();
        return;
    }

    const AccountConfig captured = cfg;
    auto *read = new QKeychain::ReadPasswordJob(kWalletService, this);
    read->setKey(walletKeyFor(cfg.user, cfg.host));
    connect(read, &QKeychain::Job::finished, this, [this, read, gen, finish, captured] {
        if (gen != m_walletGen)
            return;
        if (!read->error()) {
            m_password = read->textData();
            finish();
            return;
        }
        if (read->error() != QKeychain::EntryNotFound) {
            qWarning() << "mailove: wallet read failed:" << read->errorString();
            finish();
            return;
        }
        // Single-account era stored the password under a fixed key. Read it
        // once and re-store it under the per-account key.
        auto *legacy = new QKeychain::ReadPasswordJob(kWalletService, this);
        legacy->setKey(kWalletKey);
        connect(legacy, &QKeychain::Job::finished, this,
                [this, legacy, gen, finish, captured] {
            if (gen != m_walletGen)
                return;
            if (!legacy->error()) {
                m_password = legacy->textData();
                writeSecretToWallet(captured);
            }
            finish();
        });
        legacy->start();
    });
    read->start();
}

void AccountStore::writeSecretToWallet(const AccountConfig &cfg)
{
    auto *write = new QKeychain::WritePasswordJob(kWalletService, this);
    write->setKey(walletKeyFor(cfg.user, cfg.host));
    write->setTextData(m_password);
    connect(write, &QKeychain::Job::finished, this, [this, write] {
        if (write->error()) {
            Q_EMIT errorOccurred(
                tr("Could not store the password in the system wallet: %1")
                    .arg(write->errorString()));
            return;
        }
        // Only drop the plaintext once the wallet definitely has it.
        settings().remove(QStringLiteral("account/secret"));
    });
    write->start();
}
