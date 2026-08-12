// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pgpengine.h"

#include "keydiscovery.h"

#include <QFile>
#include <QLoggingCategory>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>

#include <algorithm>

#ifdef MAILOVE_HAVE_OPENPGP
#include <gpgme++/context.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/encryptionresult.h>
#include <gpgme++/error.h>
#include <gpgme++/global.h>
#include <gpgme++/importresult.h>
#include <gpgme++/key.h>
#include <gpgme++/keygenerationresult.h>
#include <gpgme++/keylistresult.h>
#include <gpgme++/signingresult.h>
#include <gpgme++/verificationresult.h>

#include <qgpgme/changeownertrustjob.h>
#include <qgpgme/decryptverifyjob.h>
#include <qgpgme/deletejob.h>
#include <qgpgme/encryptjob.h>
#include <qgpgme/exportjob.h>
#include <qgpgme/importjob.h>
#include <qgpgme/keygenerationjob.h>
#include <qgpgme/listallkeysjob.h>
#include <qgpgme/protocol.h>
#include <qgpgme/signjob.h>
#include <qgpgme/verifydetachedjob.h>

#include <gpg-error.h>

#include <vector>
#endif

namespace
{
/// Its own category rather than mailove.trace: this file is also linked into
/// pgpkeytool, which has no MailClient and so no trace category to borrow.
/// Enable with QT_LOGGING_RULES="mailove.pgp.debug=true".
Q_LOGGING_CATEGORY(logPgp, "mailove.pgp")

PgpEngine *g_instance = nullptr;
}

// --- PgpKey ---------------------------------------------------------------

bool PgpKey::matches(const QString &address) const
{
    const QString wanted = address.trimmed();
    if (wanted.isEmpty())
        return false;
    for (const QString &a : addresses) {
        if (a.compare(wanted, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

QVariantMap PgpKey::toVariantMap() const
{
    return {
        {QStringLiteral("fingerprint"), fingerprint},
        {QStringLiteral("keyId"), keyId},
        {QStringLiteral("name"), name},
        {QStringLiteral("email"), email},
        {QStringLiteral("uid"), uid},
        {QStringLiteral("addresses"), addresses},
        {QStringLiteral("created"), created},
        {QStringLiteral("expires"), expires},
        {QStringLiteral("algorithm"), algorithm},
        {QStringLiteral("secret"), secret},
        {QStringLiteral("expired"), expired},
        {QStringLiteral("revoked"), revoked},
        {QStringLiteral("disabled"), disabled},
        {QStringLiteral("invalid"), invalid},
        {QStringLiteral("canEncrypt"), canEncrypt},
        {QStringLiteral("canSign"), canSign},
        {QStringLiteral("validity"), validity},
        {QStringLiteral("ownerTrust"), ownerTrust},
        {QStringLiteral("bad"), isBad()},
    };
}

// --- Private --------------------------------------------------------------

class PgpEngine::Private
{
public:
#ifdef MAILOVE_HAVE_OPENPGP
    /// The GpgME keys behind the m_keys snapshot. Looked up by fingerprint,
    /// not by position — m_keys is sorted for display and the two are not
    /// parallel.
    std::vector<GpgME::Key> rawKeys;

    GpgME::Key rawKey(const QString &fingerprint) const
    {
        const QByteArray fp = fingerprint.toLatin1();
        for (const GpgME::Key &k : rawKeys) {
            if (k.primaryFingerprint() && fp == k.primaryFingerprint())
                return k;
        }
        return {};
    }
#endif
};

#ifdef MAILOVE_HAVE_OPENPGP
namespace
{
QString cstr(const char *s)
{
    return s ? QString::fromUtf8(s) : QString();
}

/// time_t 0 means "no such time" throughout GpgME — never expires, or a
/// creation date the key does not record.
QDateTime timeOrNull(time_t t)
{
    return t == 0 ? QDateTime() : QDateTime::fromSecsSinceEpoch(qint64(t));
}

PgpKey convertKey(const GpgME::Key &k)
{
    PgpKey out;
    out.fingerprint = cstr(k.primaryFingerprint());
    out.keyId = cstr(k.shortKeyID());
    out.secret = k.hasSecret();
    out.expired = k.isExpired();
    out.revoked = k.isRevoked();
    out.disabled = k.isDisabled();
    out.invalid = k.isInvalid();
    out.canEncrypt = k.canEncrypt();
    out.canSign = k.canSign();
    out.ownerTrust = int(k.ownerTrust());

    const std::vector<GpgME::UserID> uids = k.userIDs();
    if (!uids.empty()) {
        const GpgME::UserID &primary = uids.front();
        out.name = cstr(primary.name());
        out.email = cstr(primary.email());
        out.uid = cstr(primary.id());
        out.validity = int(primary.validity());
    }
    for (const GpgME::UserID &uid : uids) {
        // Revoked user IDs are not addresses this key speaks for any more —
        // matching one would offer the key for an address its owner withdrew.
        if (uid.isRevoked() || uid.isInvalid())
            continue;
        const QString addr = QString::fromStdString(uid.addrSpec());
        if (!addr.isEmpty() && !out.addresses.contains(addr, Qt::CaseInsensitive))
            out.addresses.append(addr);
    }
    if (out.uid.isEmpty())
        out.uid = out.fingerprint;

    // The primary subkey carries the dates and the algorithm the UI shows;
    // capabilities are read off the key as a whole above, because they are
    // spread over the subkeys.
    const std::vector<GpgME::Subkey> subkeys = k.subkeys();
    if (!subkeys.empty()) {
        const GpgME::Subkey &primary = subkeys.front();
        out.created = timeOrNull(primary.creationTime());
        out.expires = primary.neverExpires() ? QDateTime()
                                             : timeOrNull(primary.expirationTime());
        out.algorithm = QString::fromStdString(primary.algoName());
    }
    for (const GpgME::Subkey &sub : subkeys) {
        const QString fpr = cstr(sub.fingerprint()).toUpper();
        const QString id = cstr(sub.keyID()).toUpper();
        if (!fpr.isEmpty())
            out.subkeyIds.append(fpr);
        if (!id.isEmpty() && id != fpr)
            out.subkeyIds.append(id);
    }
    return out;
}
}
#endif

// --- PgpEngine ------------------------------------------------------------

PgpEngine::PgpEngine(QObject *parent)
    : QObject(parent)
    , d(std::make_unique<Private>())
{
    if (!g_instance)
        g_instance = this;

    // The reasons a machine has no OpenPGP, in the order they are worth
    // checking. Each one ends here: nothing below talks to gpg, and the UI
    // shows the reason in place of the encryption settings.
    if (qEnvironmentVariableIsSet("MAILOVE_NO_OPENPGP")) {
        // The off switch, for a session that should not touch gpg at all —
        // and the only way to see the degraded UI on a machine that has it.
        m_unavailableReason = tr("OpenPGP encryption is switched off "
                                 "(MAILOVE_NO_OPENPGP is set).");
    }
#ifdef MAILOVE_HAVE_OPENPGP
    else if (const GpgME::Error initErr = GpgME::initializeLibrary(0)) {
        // Must run before any other GpgME call, and is safe to repeat.
        qCWarning(logPgp, "openpgp: library init failed: %s",
                  initErr.asStdString().c_str());
        m_unavailableReason = tr("The OpenPGP library on this system could not "
                                 "be initialised.");
    } else if (const GpgME::Error engineErr = GpgME::checkEngine(GpgME::OpenPGP)) {
        // Overwhelmingly this is "gpg is not installed" — the AppImage case.
        // The gpg error itself ("Invalid crypto engine") tells a user nothing,
        // so it goes to the log and the message says what to do instead.
        qCWarning(logPgp, "openpgp: no usable gpg engine: %s",
                  engineErr.asStdString().c_str());
        m_unavailableReason = tr("GnuPG was not found on this system. Install "
                                 "gnupg to sign, encrypt and read encrypted mail.");
    } else if (!QGpgME::openpgp()) {
        m_unavailableReason = tr("The OpenPGP backend on this system is not usable.");
    } else {
        m_available = true;
    }
#else
    else {
        m_unavailableReason = tr("This build of Mailove has no OpenPGP support.");
    }
#endif

    if (m_available) {
        m_discovery = new KeyDiscovery(this);
        connect(m_discovery, &KeyDiscovery::finished, this,
                [this](const QString &address, const QByteArray &keyData,
                       const QString &source, const QString &error) {
                    jobFinished();
                    if (!error.isEmpty()) {
                        Q_EMIT errorOccurred(
                            tr("Key lookup for %1 failed: %2").arg(address, error));
                        Q_EMIT lookupFinished(address, false, source);
                        return;
                    }
                    if (keyData.isEmpty()) {
                        Q_EMIT lookupFinished(address, false, source);
                        return;
                    }
                    Q_EMIT lookupFinished(address, true, source);
                    importKeyData(keyData);
                });
        refresh();
    } else {
        qCDebug(logPgp, "openpgp: unavailable — %s", qPrintable(m_unavailableReason));
    }
}

PgpEngine::~PgpEngine()
{
    if (g_instance == this)
        g_instance = nullptr;
}

PgpEngine *PgpEngine::instance()
{
    return g_instance;
}

void PgpEngine::jobStarted()
{
    if (m_pending++ == 0)
        Q_EMIT busyChanged();
}

void PgpEngine::jobFinished()
{
    if (m_pending > 0 && --m_pending == 0)
        Q_EMIT busyChanged();
}

void PgpEngine::reportUnavailable()
{
    Q_EMIT errorOccurred(m_unavailableReason);
}

void PgpEngine::refresh()
{
    if (!m_available)
        return;
#ifdef MAILOVE_HAVE_OPENPGP
    if (m_refreshing) {
        // Whatever changed the keyring did so after the running listing read
        // it, so that listing's answer is already out of date.
        m_refreshQueued = true;
        return;
    }
    QGpgME::ListAllKeysJob *job = QGpgME::openpgp()->listAllKeysJob(false, true);
    if (!job) {
        Q_EMIT errorOccurred(tr("The key list could not be read."));
        return;
    }
    m_refreshing = true;
    jobStarted();
    connect(job, &QGpgME::ListAllKeysJob::result, this,
            [this](const GpgME::KeyListResult &result,
                   const std::vector<GpgME::Key> &pub,
                   const std::vector<GpgME::Key> &sec) {
                m_refreshing = false;
                jobFinished();
                if (result.error() && !result.error().isCanceled()) {
                    Q_EMIT errorOccurred(
                        tr("The key list could not be read: %1")
                            .arg(QString::fromStdString(result.error().asStdString())));
                }

                // Public and secret keys come back as two lists, and a key the
                // user owns is in both. The public entry is the one that
                // carries the user IDs and their validity, so that is the one
                // kept — flagged as secret rather than listed a second time.
                d->rawKeys = pub;
                QSet<QByteArray> pubFps;
                for (const GpgME::Key &k : pub) {
                    if (k.primaryFingerprint())
                        pubFps.insert(QByteArray(k.primaryFingerprint()));
                }
                QSet<QByteArray> secretFps;
                for (const GpgME::Key &k : sec) {
                    if (!k.primaryFingerprint())
                        continue;
                    const QByteArray fp(k.primaryFingerprint());
                    secretFps.insert(fp);
                    // A secret key with no public half at all is unusual but
                    // real (an imported private key). Losing it would hide the
                    // user's own identity from the picker.
                    if (!pubFps.contains(fp))
                        d->rawKeys.push_back(k);
                }

                m_keys.clear();
                m_keys.reserve(int(d->rawKeys.size()));
                for (const GpgME::Key &k : d->rawKeys) {
                    PgpKey key = convertKey(k);
                    if (!key.secret && key.fingerprint.size()
                        && secretFps.contains(key.fingerprint.toLatin1()))
                        key.secret = true;
                    m_keys.append(key);
                }
                std::sort(m_keys.begin(), m_keys.end(),
                          [](const PgpKey &a, const PgpKey &b) {
                              // Own identities first — the list exists mostly to
                              // pick one — then by the name the user reads.
                              if (a.secret != b.secret)
                                  return a.secret;
                              const int byUid = a.uid.compare(b.uid, Qt::CaseInsensitive);
                              return byUid != 0 ? byUid < 0
                                                : a.fingerprint < b.fingerprint;
                          });
                Q_EMIT keysChanged();

                if (m_refreshQueued) {
                    m_refreshQueued = false;
                    refresh();
                }
            });
    const GpgME::Error err = job->start(false);
    if (err) {
        m_refreshing = false;
        jobFinished();
        job->deleteLater();
        Q_EMIT errorOccurred(tr("The key list could not be read: %1")
                                 .arg(QString::fromStdString(err.asStdString())));
    }
#endif
}

QVariantList PgpEngine::secretKeysFor(const QString &address) const
{
    QVariantList out;
    for (const PgpKey &k : m_keys) {
        if (!k.secret || !k.canSign || !k.matches(address))
            continue;
        // Expired, revoked and disabled keys are left out entirely. Offering
        // one is offering a choice that cannot work: signing with it fails,
        // and a recipient's copy of it is stale anyway. An expired key already
        // *chosen* for the account is still shown — the account page adds it
        // back by fingerprint, with the warning that it needs extending — so
        // nothing disappears silently; it just stops being on the menu.
        if (k.isBad())
            continue;
        out.append(k.toVariantMap());
    }
    return out;
}

QVariantMap PgpEngine::keyInfo(const QString &fingerprint) const
{
    if (fingerprint.isEmpty())
        return {};
    for (const PgpKey &k : m_keys) {
        if (k.fingerprint.compare(fingerprint, Qt::CaseInsensitive) == 0)
            return k.toVariantMap();
    }
    return {};
}

QString PgpEngine::primaryFingerprintFor(const QString &idOrFingerprint) const
{
    if (idOrFingerprint.isEmpty())
        return {};
    const QString needle = idOrFingerprint.toUpper();
    for (const PgpKey &k : m_keys) {
        if (k.fingerprint.compare(needle, Qt::CaseInsensitive) == 0)
            return k.fingerprint;
        // A bare key ID is the last 16 digits of its fingerprint, so endsWith
        // covers both forms in one pass over the subkey list.
        for (const QString &sub : k.subkeyIds) {
            if (sub == needle || sub.endsWith(needle))
                return k.fingerprint;
        }
    }
    return {};
}

void PgpEngine::importKeyData(const QByteArray &keyData)
{
    if (!m_available) {
        reportUnavailable();
        Q_EMIT importFinished(0, 0, m_unavailableReason);
        return;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    if (keyData.isEmpty()) {
        Q_EMIT importFinished(0, 0, tr("There is no key here to import."));
        return;
    }
    QGpgME::ImportJob *job = QGpgME::openpgp()->importJob();
    if (!job) {
        Q_EMIT importFinished(0, 0, tr("Keys cannot be imported."));
        return;
    }
    jobStarted();
    connect(job, &QGpgME::ImportJob::result, this,
            [this](const GpgME::ImportResult &result) {
                jobFinished();
                if (result.error()) {
                    Q_EMIT importFinished(
                        0, 0, QString::fromStdString(result.error().asStdString()));
                    return;
                }
                Q_EMIT importFinished(result.numImported(), result.numUnchanged(),
                                      QString());
                // A secret key in the block is worth saying so separately: it
                // is the user's own identity arriving, not a correspondent's.
                if (result.numSecretKeysImported() > 0
                    || result.numSecretKeysUnchanged() > 0) {
                    QString fp;
                    const auto imports = result.imports();
                    for (const GpgME::Import &imp : imports) {
                        if (imp.status() & GpgME::Import::ContainedSecretKey) {
                            fp = cstr(imp.fingerprint());
                            break;
                        }
                    }
                    // gpg does not always flag the individual import, only the
                    // totals; fall back to the first key in the block.
                    if (fp.isEmpty() && !imports.empty())
                        fp = cstr(imports.front().fingerprint());
                    Q_EMIT secretKeyImported(fp);
                }
                // Even an import that changed nothing can have added a user ID
                // or a signature to a key already held, so always re-read.
                refresh();
            });
    const GpgME::Error err = job->start(keyData);
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT importFinished(0, 0, QString::fromStdString(err.asStdString()));
    }
#endif
}

void PgpEngine::importKeyFile(const QUrl &fileUrl)
{
    if (!m_available) {
        reportUnavailable();
        Q_EMIT importFinished(0, 0, m_unavailableReason);
        return;
    }
    const QString path = fileUrl.isLocalFile() ? fileUrl.toLocalFile() : fileUrl.toString();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        Q_EMIT importFinished(0, 0, tr("%1 could not be opened.").arg(path));
        return;
    }
    // A key file is kilobytes; anything of a size worth streaming is not one,
    // and reading it whole would block the GUI thread for as long as it takes.
    const qint64 kMaxKeyFile = 4 * 1024 * 1024;
    if (f.size() > kMaxKeyFile) {
        Q_EMIT importFinished(0, 0, tr("%1 is too large to be a key file.").arg(path));
        return;
    }
    importKeyData(f.readAll());
}

void PgpEngine::exportPublicKey(const QString &fingerprint, const QUrl &fileUrl)
{
    const QString path = fileUrl.isLocalFile() ? fileUrl.toLocalFile() : fileUrl.toString();
    if (!m_available) {
        reportUnavailable();
        Q_EMIT exportFinished(path, m_unavailableReason);
        return;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    QGpgME::ExportJob *job = QGpgME::openpgp()->publicKeyExportJob(true);
    if (!job) {
        Q_EMIT exportFinished(path, tr("Keys cannot be exported."));
        return;
    }
    jobStarted();
    connect(job, &QGpgME::ExportJob::result, this,
            [this, path](const GpgME::Error &error, const QByteArray &keyData) {
                jobFinished();
                if (error) {
                    Q_EMIT exportFinished(path,
                                          QString::fromStdString(error.asStdString()));
                    return;
                }
                QSaveFile out(path);
                if (!out.open(QIODevice::WriteOnly)
                    || out.write(keyData) != keyData.size() || !out.commit()) {
                    Q_EMIT exportFinished(path, tr("%1 could not be written.").arg(path));
                    return;
                }
                Q_EMIT exportFinished(path, QString());
            });
    const GpgME::Error err = job->start({fingerprint});
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT exportFinished(path, QString::fromStdString(err.asStdString()));
    }
#endif
}

void PgpEngine::setOwnerTrust(const QString &fingerprint, int trust)
{
    if (!m_available) {
        reportUnavailable();
        return;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    const GpgME::Key key = d->rawKey(fingerprint);
    if (key.isNull()) {
        Q_EMIT errorOccurred(tr("That key is no longer in the keyring."));
        return;
    }
    if (trust < 0 || trust > int(GpgME::Key::Ultimate)) {
        Q_EMIT errorOccurred(tr("That is not a trust level."));
        return;
    }
    QGpgME::ChangeOwnerTrustJob *job = QGpgME::openpgp()->changeOwnerTrustJob();
    if (!job) {
        Q_EMIT errorOccurred(tr("Trust cannot be changed here."));
        return;
    }
    jobStarted();
    connect(job, &QGpgME::ChangeOwnerTrustJob::result, this,
            [this](const GpgME::Error &error) {
                jobFinished();
                if (error) {
                    Q_EMIT errorOccurred(tr("The trust level could not be changed: %1")
                                             .arg(QString::fromStdString(error.asStdString())));
                    return;
                }
                Q_EMIT statusMessage(tr("Trust updated."));
                // gpg recomputes validity for this key and every key it has
                // signed, so the whole snapshot is stale, not just one row.
                refresh();
            });
    const GpgME::Error err = job->start(key, GpgME::Key::OwnerTrust(trust));
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT errorOccurred(tr("The trust level could not be changed: %1")
                                 .arg(QString::fromStdString(err.asStdString())));
    }
#else
    Q_UNUSED(fingerprint)
    Q_UNUSED(trust)
#endif
}

void PgpEngine::deletePublicKey(const QString &fingerprint)
{
    if (!m_available) {
        reportUnavailable();
        return;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    const GpgME::Key key = d->rawKey(fingerprint);
    if (key.isNull()) {
        Q_EMIT errorOccurred(tr("That key is no longer in the keyring."));
        return;
    }
    if (key.hasSecret()) {
        // Deleting a secret key destroys the ability to read every message
        // ever encrypted to it. That is a decision for gpg or Kleopatra, with
        // their warnings, not for a button in a mail client.
        Q_EMIT errorOccurred(tr("This is one of your own keys. Delete it with "
                                "GnuPG or Kleopatra, which will warn you about "
                                "what is lost with it."));
        return;
    }
    QGpgME::DeleteJob *job = QGpgME::openpgp()->deleteJob();
    if (!job) {
        Q_EMIT errorOccurred(tr("Keys cannot be deleted."));
        return;
    }
    jobStarted();
    connect(job, &QGpgME::DeleteJob::result, this, [this](const GpgME::Error &error) {
        jobFinished();
        if (error) {
            Q_EMIT errorOccurred(tr("The key could not be deleted: %1")
                                     .arg(QString::fromStdString(error.asStdString())));
            return;
        }
        Q_EMIT statusMessage(tr("Key deleted."));
        refresh();
    });
    const GpgME::Error err = job->start(key, false);
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT errorOccurred(tr("The key could not be deleted: %1")
                                 .arg(QString::fromStdString(err.asStdString())));
    }
#endif
}

void PgpEngine::generateKey(const QString &name, const QString &email, int expiryYears)
{
    if (!m_available) {
        reportUnavailable();
        Q_EMIT keyGenerated(QString(), m_unavailableReason);
        return;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    // The parameter block is line-oriented and unescaped, so a colon or a
    // newline in either field would write a parameter of the attacker's
    // choosing — the same header-injection shape the compose fields guard
    // against. Neither belongs in a name or an address anyway.
    static const QRegularExpression unsafe(QStringLiteral("[\\r\\n:<>]"));
    const QString safeName = QString(name).remove(unsafe).trimmed();
    const QString safeEmail = QString(email).remove(unsafe).trimmed();
    if (safeEmail.isEmpty()) {
        Q_EMIT keyGenerated(QString(), tr("A key needs an e-mail address."));
        return;
    }

    QString expiry = QStringLiteral("0"); // gpg's "never"
    if (expiryYears > 0)
        expiry = QStringLiteral("%1y").arg(expiryYears);

    // Ed25519 for signing with a Curve25519 encryption subkey: the modern
    // default, and what gpg --quick-gen-key produces. %ask-passphrase sends
    // the passphrase prompt to pinentry — it never passes through mailove.
    QString params = QStringLiteral(
        "<GnupgKeyParms format=\"internal\">\n"
        "%ask-passphrase\n"
        "Key-Type: EDDSA\n"
        "Key-Curve: ed25519\n"
        "Key-Usage: sign\n"
        "Subkey-Type: ECDH\n"
        "Subkey-Curve: cv25519\n"
        "Subkey-Usage: encrypt\n");
    if (!safeName.isEmpty())
        params += QStringLiteral("Name-Real: %1\n").arg(safeName);
    params += QStringLiteral("Name-Email: %1\n").arg(safeEmail);
    params += QStringLiteral("Expire-Date: %1\n").arg(expiry);
    params += QStringLiteral("</GnupgKeyParms>\n");

    QGpgME::KeyGenerationJob *job = QGpgME::openpgp()->keyGenerationJob();
    if (!job) {
        Q_EMIT keyGenerated(QString(), tr("Keys cannot be generated here."));
        return;
    }
    jobStarted();
    connect(job, &QGpgME::KeyGenerationJob::result, this,
            [this](const GpgME::KeyGenerationResult &result) {
                jobFinished();
                // A cancelled pinentry is reported as neither a fingerprint
                // nor an error — nothing was created and nothing went wrong.
                // The empty-fingerprint check is not redundant: gpg does not
                // always set an error code when the passphrase prompt is
                // dismissed, and without it a cancelled generation was
                // announced as a new key.
                const QString fingerprint = cstr(result.fingerprint());
                if (result.error().isCanceled() || (!result.error() && fingerprint.isEmpty())) {
                    Q_EMIT keyGenerated(QString(), QString());
                    return;
                }
                if (result.error()) {
                    Q_EMIT keyGenerated(
                        QString(), QString::fromStdString(result.error().asStdString()));
                    return;
                }
                Q_EMIT keyGenerated(fingerprint, QString());
                refresh();
            });
    const GpgME::Error err = job->start(params);
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT keyGenerated(QString(), QString::fromStdString(err.asStdString()));
    }
#else
    Q_UNUSED(name)
    Q_UNUSED(email)
    Q_UNUSED(expiryYears)
#endif
}

#ifdef MAILOVE_HAVE_OPENPGP
namespace
{
/// Turns GpgME's verdict into the one the UI states, and names the signer from
/// the key we hold. The mapping is where the honesty rule lives: Red — the
/// signature did not check out — becomes NotVerified rather than "invalid",
/// because our copy of the signed octets is a re-serialisation and may not be
/// the bytes that were signed.
PgpSignatureInfo convertSignature(const GpgME::Signature &sig, const QList<PgpKey> &keys)
{
    PgpSignatureInfo out;
    out.fingerprint = cstr(sig.fingerprint());

    const unsigned int summary = sig.summary();
    if (summary & GpgME::Signature::KeyRevoked) {
        out.status = PgpSignatureInfo::Revoked;
        out.detail = PgpEngine::tr("The signing key has been revoked. Its owner "
                                   "withdrew it, so it vouches for nothing.");
    } else if (summary & GpgME::Signature::KeyExpired) {
        out.status = PgpSignatureInfo::Expired;
        out.detail = PgpEngine::tr("The signature is good, but the signing key "
                                   "has expired.");
    } else if (summary & GpgME::Signature::KeyMissing) {
        out.status = PgpSignatureInfo::UnknownKey;
        out.detail = PgpEngine::tr("Signed with a key you do not have, so there "
                                   "is nothing to check it against.");
    } else if (summary & GpgME::Signature::Valid) {
        out.status = PgpSignatureInfo::Valid;
    } else if (sig.status().code() == GPG_ERR_NO_PUBKEY) {
        out.status = PgpSignatureInfo::UnknownKey;
        out.detail = PgpEngine::tr("Signed with a key you do not have, so there "
                                   "is nothing to check it against.");
    } else if (summary & GpgME::Signature::Red
               || sig.status().code() == GPG_ERR_BAD_SIGNATURE) {
        out.status = PgpSignatureInfo::NotVerified;
        // Deliberately not "this signature is invalid". See the note on
        // PgpSignatureInfo: mailove cannot yet prove it is checking the original
        // octets, and every mailing list in the world rewrites them.
        out.detail = PgpEngine::tr(
            "The signature does not match the message as Mailove reconstructed "
            "it. That happens whenever anything on the way — a mailing list, a "
            "forwarder — rewrites the message, and Mailove cannot tell that apart "
            "from a bad signature, so it claims neither.");
    } else if (sig.status()) {
        out.status = PgpSignatureInfo::Error;
        out.detail = QString::fromStdString(sig.status().asStdString());
    } else {
        out.status = PgpSignatureInfo::Valid;
    }

    // The signer's name comes from the keyring, not from the message: a name
    // the message supplies is a name the sender chose. gpg reports the
    // *signing subkey's* fingerprint here — on a modern key the primary only
    // certifies — so the match must go through the subkey list, and the
    // fingerprint we pass on is normalised to the primary: it is what the key
    // manager, keyInfo() and the badge's click target all speak.
    const QString reported = out.fingerprint.toUpper();
    for (const PgpKey &k : keys) {
        const bool owns = k.fingerprint.compare(reported, Qt::CaseInsensitive) == 0
            || std::any_of(k.subkeyIds.cbegin(), k.subkeyIds.cend(),
                           [&reported](const QString &sub) {
                               return sub == reported || sub.endsWith(reported);
                           });
        if (!reported.isEmpty() && owns) {
            out.signerName = k.name;
            out.signerEmail = k.email;
            out.fingerprint = k.fingerprint;
            break;
        }
    }
    if (out.status == PgpSignatureInfo::Valid && out.detail.isEmpty()) {
        out.detail = out.signerEmail.isEmpty()
            ? PgpEngine::tr("Good signature.")
            : PgpEngine::tr("Good signature from %1.").arg(out.signerEmail);
    }
    return out;
}

/// The signature worth reporting out of a verification result: the first one
/// that verified, or failing that the first one at all. A message with several
/// signatures where only one holds is not a message to show a tick for, but the
/// UI only has room for one verdict, and "signed by someone we could check"
/// beats an arbitrary pick.
PgpSignatureInfo pickSignature(const GpgME::VerificationResult &result,
                               const QList<PgpKey> &keys)
{
    PgpSignatureInfo out;
    const auto sigs = result.signatures();
    if (sigs.empty())
        return out;
    for (const GpgME::Signature &sig : sigs) {
        const PgpSignatureInfo info = convertSignature(sig, keys);
        if (info.status == PgpSignatureInfo::Valid)
            return info;
        if (out.status == PgpSignatureInfo::None)
            out = info;
    }
    return out;
}
}
#endif

quint64 PgpEngine::verifyDetached(const QByteArray &signedOctets, const QByteArray &signature)
{
    if (!m_available) {
        reportUnavailable();
        return 0;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    if (signedOctets.isEmpty() || signature.isEmpty())
        return 0;
    QGpgME::VerifyDetachedJob *job = QGpgME::openpgp()->verifyDetachedJob();
    if (!job)
        return 0;
    const quint64 id = m_nextJobId++;
    jobStarted();
    connect(job, &QGpgME::VerifyDetachedJob::result, this,
            [this, id](const GpgME::VerificationResult &result) {
                jobFinished();
                PgpSignatureInfo info = pickSignature(result, m_keys);
                if (result.error() && info.status == PgpSignatureInfo::None) {
                    info.status = PgpSignatureInfo::Error;
                    info.detail = QString::fromStdString(result.error().asStdString());
                }
                Q_EMIT verifyFinished(id, info);
            });
    const GpgME::Error err = job->start(signature, signedOctets);
    if (err) {
        jobFinished();
        job->deleteLater();
        PgpSignatureInfo info;
        info.status = PgpSignatureInfo::Error;
        info.detail = QString::fromStdString(err.asStdString());
        Q_EMIT verifyFinished(id, info);
    }
    return id;
#else
    return 0;
#endif
}

QVariantMap PgpEngine::encryptionKeysFor(const QStringList &addresses) const
{
    QVariantMap out;
    for (const QString &address : addresses) {
        const QString wanted = address.trimmed();
        if (wanted.isEmpty())
            continue;
        QString best;
        for (const PgpKey &k : m_keys) {
            // Unusable keys are not candidates: encrypting to an expired or
            // revoked key produces mail its owner cannot read.
            if (!k.canEncrypt || k.isBad() || !k.matches(wanted))
                continue;
            // A key we hold the private half of is this user's own identity and
            // beats a correspondent's copy of the same address.
            if (best.isEmpty() || k.secret)
                best = k.fingerprint;
            if (k.secret)
                break;
        }
        out.insert(wanted, best);
    }
    return out;
}

quint64 PgpEngine::signDetached(const QByteArray &data, const QString &signerFingerprint)
{
    if (!m_available) {
        reportUnavailable();
        return 0;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    const GpgME::Key signer = d->rawKey(signerFingerprint);
    if (data.isEmpty() || signer.isNull()) {
        Q_EMIT signFinished(0, {}, {}, tr("The signing key is not in your keyring."));
        return 0;
    }
    QGpgME::SignJob *job = QGpgME::openpgp()->signJob(true, true);
    if (!job)
        return 0;
    const quint64 id = m_nextJobId++;
    jobStarted();
    connect(job, &QGpgME::SignJob::result, this,
            [this, id](const GpgME::SigningResult &result, const QByteArray &signature) {
                jobFinished();
                if (result.error()) {
                    Q_EMIT signFinished(
                        id, {}, {},
                        result.error().isCanceled()
                            ? tr("Signing was cancelled.")
                            : QString::fromStdString(result.error().asStdString()));
                    return;
                }
                // RFC 3156 §5 wants the hash named on the multipart/signed, and
                // only gpg knows which one it actually used.
                QString micalg = QStringLiteral("pgp-sha256");
                const auto created = result.createdSignatures();
                if (!created.empty() && created.front().hashAlgorithmAsString()) {
                    micalg = QStringLiteral("pgp-")
                        + QString::fromLatin1(created.front().hashAlgorithmAsString()).toLower();
                }
                Q_EMIT signFinished(id, signature, micalg, QString());
            });
    // Detached, armored, text mode: exactly what RFC 3156 specifies.
    const GpgME::Error err = job->start({signer}, data, GpgME::Detached);
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT signFinished(id, {}, {}, QString::fromStdString(err.asStdString()));
    }
    return id;
#else
    Q_UNUSED(data)
    Q_UNUSED(signerFingerprint)
    return 0;
#endif
}

quint64 PgpEngine::encryptTo(const QByteArray &data, const QStringList &fingerprints)
{
    if (!m_available) {
        reportUnavailable();
        return 0;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    std::vector<GpgME::Key> recipients;
    for (const QString &fp : fingerprints) {
        const GpgME::Key k = d->rawKey(fp);
        if (!k.isNull())
            recipients.push_back(k);
    }
    if (data.isEmpty() || recipients.empty()) {
        Q_EMIT encryptFinished(0, {}, tr("No usable key to encrypt to."));
        return 0;
    }
    QGpgME::EncryptJob *job = QGpgME::openpgp()->encryptJob(true, true);
    if (!job)
        return 0;
    const quint64 id = m_nextJobId++;
    jobStarted();
    connect(job, &QGpgME::EncryptJob::result, this,
            [this, id](const GpgME::EncryptionResult &result, const QByteArray &cipherText) {
                jobFinished();
                if (result.error()) {
                    Q_EMIT encryptFinished(
                        id, {},
                        result.error().isCanceled()
                            ? tr("Encryption was cancelled.")
                            : QString::fromStdString(result.error().asStdString()));
                    return;
                }
                Q_EMIT encryptFinished(id, cipherText, QString());
            });
    // AlwaysTrust: the user chose these keys through mailove's own UI, which only
    // offers keys that are in the keyring and usable. Without it gpg refuses
    // any key the user has not signed, which for mail is nearly all of them.
    const GpgME::Error err = job->start(recipients, data, GpgME::Context::AlwaysTrust);
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT encryptFinished(id, {}, QString::fromStdString(err.asStdString()));
    }
    return id;
#else
    Q_UNUSED(data)
    Q_UNUSED(fingerprints)
    return 0;
#endif
}

quint64 PgpEngine::decrypt(const QByteArray &cipherText)
{
    if (!m_available) {
        reportUnavailable();
        return 0;
    }
#ifdef MAILOVE_HAVE_OPENPGP
    if (cipherText.isEmpty())
        return 0;
    QGpgME::DecryptVerifyJob *job = QGpgME::openpgp()->decryptVerifyJob();
    if (!job) {
        Q_EMIT errorOccurred(tr("This installation of GnuPG cannot decrypt."));
        return 0;
    }
    const quint64 id = m_nextJobId++;
    jobStarted();
    // decryptVerifyJob, not decryptJob: a message encrypted *and* signed with
    // one OpenPGP operation carries its signature inside the ciphertext, where
    // only the decrypter can see it. That signature is over the plaintext gpg
    // itself produced, so unlike the detached RFC 3156 case there is no
    // question about which octets were checked — it is the one signature here
    // that can be reported without the fidelity caveat.
    connect(job, &QGpgME::DecryptVerifyJob::result, this,
            [this, id](const GpgME::DecryptionResult &result,
                       const GpgME::VerificationResult &verification,
                       const QByteArray &plainText) {
                jobFinished();
                const GpgME::Error err = result.error();
                if (err) {
                    const bool noKey = err.code() == GPG_ERR_NO_SECKEY
                        || err.code() == GPG_ERR_DECRYPT_FAILED;
                    qCDebug(logPgp, "decrypt %llu failed: %s", id,
                            err.asStdString().c_str());
                    Q_EMIT decryptFinished(
                        id, {},
                        err.isCanceled()
                            ? tr("Decryption was cancelled.")
                            : QString::fromStdString(err.asStdString()),
                        noKey);
                    return;
                }
                // Named before the plaintext, so a receiver has the key in
                // hand when the message arrives.
                const auto recipients = result.recipients();
                for (const GpgME::DecryptionResult::Recipient &r : recipients) {
                    // The one that actually worked: gpg lists every recipient
                    // the message was encrypted to, including keys we do not
                    // hold, and only the one it decrypted with has no status.
                    if (!r.status() && r.keyID()) {
                        Q_EMIT decryptRecipient(id, cstr(r.keyID()));
                        break;
                    }
                }
                Q_EMIT decryptFinished(id, plainText, QString(), false);
                // After the plaintext, so a receiver has the message in hand
                // before it is told who signed it.
                const PgpSignatureInfo info = pickSignature(verification, m_keys);
                if (info.status != PgpSignatureInfo::None)
                    Q_EMIT verifyFinished(id, info);
            });
    const GpgME::Error err = job->start(cipherText);
    if (err) {
        jobFinished();
        job->deleteLater();
        Q_EMIT decryptFinished(id, {}, QString::fromStdString(err.asStdString()), false);
    }
    return id;
#else
    return 0;
#endif
}

void PgpEngine::lookupWkd(const QString &address)
{
    if (!m_available || !m_discovery) {
        reportUnavailable();
        Q_EMIT lookupFinished(address, false, QStringLiteral("WKD"));
        return;
    }
    jobStarted();
    m_discovery->lookupWkd(address.trimmed());
}

void PgpEngine::lookupKeyserver(const QString &address)
{
    if (!m_available || !m_discovery) {
        reportUnavailable();
        Q_EMIT lookupFinished(address, false, QStringLiteral("keys.openpgp.org"));
        return;
    }
    jobStarted();
    m_discovery->lookupKeyserver(address.trimmed());
}
