// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QDateTime>
#include <QList>
#include <QObject>
#include <QString>
#include <QUrl>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

#include <memory>

class KeyDiscovery;

/// One OpenPGP key as the UI needs it: the primary user ID flattened out, the
/// capabilities already resolved over the subkeys, and no GpgME types.
///
/// Deliberately a plain value type. Nothing above this line includes a GpgME
/// header, so the whole application builds — with encryption unavailable —
/// when the backend is not present at build time (see MAILOVE_HAVE_OPENPGP in
/// CMakeLists.txt), and QML never sees a type it cannot own.
struct PgpKey {
    QString fingerprint;
    QString keyId;      ///< short form, for display next to the fingerprint
    QString name;       ///< primary user ID's name
    QString email;      ///< primary user ID's address
    QString uid;        ///< "Name <address>", already assembled
    /// Every address on the key, primary first. A key commonly carries several
    /// user IDs, and matching only the primary one would fail to find the key
    /// a correspondent actually publishes for the address in question.
    QStringList addresses;
    /// Fingerprints and key IDs of every subkey, uppercased. GnuPG names
    /// subkeys, not primaries, whenever it reports which key actually did
    /// something: a signature carries the signing subkey's fingerprint, a
    /// decryption names the encryption subkey's ID. Anything that matches
    /// those reports against the keyring must look here, not at
    /// `fingerprint` — on a modern key the primary only certifies.
    QStringList subkeyIds;
    QDateTime created;
    QDateTime expires;  ///< invalid = never expires
    QString algorithm;  ///< "ed25519", "rsa4096", …
    bool secret = false;   ///< the private half is in the keyring
    bool expired = false;
    bool revoked = false;
    bool disabled = false;
    bool invalid = false;
    bool canEncrypt = false;
    bool canSign = false;
    /// GpgME::UserID::Validity of the primary user ID, 0-5 (unknown … ultimate).
    /// *Computed* by gpg from signatures and owner trust — not what the user
    /// set. Read-only, and the thing the list shows.
    int validity = 0;
    /// GpgME::Key::OwnerTrust, 0-5: what the *user* decided about this key's
    /// owner. This is the one that can be changed, and the only input the user
    /// has into the validity above.
    int ownerTrust = 0;

    /// Unusable for new mail — expired, revoked, disabled or malformed. A key
    /// in this state still verifies old signatures, so it is shown rather than
    /// hidden, but it is never offered as a target.
    bool isBad() const { return expired || revoked || disabled || invalid; }
    /// True when \a address is one of this key's user IDs (addresses are
    /// compared case-insensitively; the domain half is by definition, and
    /// treating the local part that way costs nothing here and matches what
    /// every mail host does in practice).
    bool matches(const QString &address) const;
    QVariantMap toVariantMap() const;
};

/// The verdict on one OpenPGP signature, in the terms the UI states it in.
///
/// Note what is missing: there is no "invalid". A signature that does not match
/// is reported as NotVerified, because the octets we hand the verifier are
/// re-serialised from the parsed MIME tree and are not guaranteed to be the
/// bytes that were signed (doc/openpgp.md §3, and the same fidelity problem the
/// roadmap records for DKIM). Announcing forgery on good mail is the worse
/// error of the two, and until the octets are known-original this code has no
/// way to tell the cases apart.
struct PgpSignatureInfo {
    enum Status {
        None,        ///< no signature at all
        Valid,       ///< good signature from a key we hold
        NotVerified, ///< did not match, and we cannot say whose fault that is
        UnknownKey,  ///< we do not have the signer's key
        Expired,     ///< good signature, expired key
        Revoked,     ///< good signature, revoked key
        Error,       ///< the verification itself failed
    };

    Status status = None;
    QString signerName;
    QString signerEmail;
    QString fingerprint;
    QString detail; ///< one line for the tooltip

    /// A verdict worth showing a name next to.
    bool named() const { return status == Valid || status == Expired || status == Revoked; }
};

/**
 * Thin, non-blocking wrapper over QGpgME's key operations.
 *
 * Key material stays in the user's GnuPG home: mailove never reads, writes or
 * caches a private key or a passphrase — gpg-agent/pinentry owns that, which
 * is also what makes a smartcard work without any code here. What this class
 * owns is a snapshot of the public keyring for the UI to bind to, refreshed
 * after every operation that could change it.
 *
 * Every call is asynchronous: QGpgME runs each job on its own thread and
 * delivers result() on ours, so nothing here blocks the GUI thread — key
 * listing over a large keyring and any lookup that touches the network both
 * would, given the chance.
 *
 * When the backend is missing — built without it, gnupg not installed, or
 * MAILOVE_NO_OPENPGP set in the environment — available() is false,
 * unavailableReason() says why in one line, and nothing here ever calls gpg:
 * no keyring is listed, no lookup is made, and every operation returns after
 * reporting the same reason. Callers do not need to branch; the settings page
 * shows that one line in place of the encryption controls.
 */
class PgpEngine : public QObject
{
    Q_OBJECT
    /// False when there is no usable OpenPGP backend. Fixed at construction —
    /// gpg does not appear mid-session, and if it did, every key operation
    /// would still have to be re-run to notice.
    Q_PROPERTY(bool available READ available CONSTANT)
    /// One line explaining an unavailable backend, for the UI to show in place
    /// of the encryption settings. Empty when available.
    Q_PROPERTY(QString unavailableReason READ unavailableReason CONSTANT)
    /// True while any key job is in flight (listing, import, export, lookup).
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

public:
    explicit PgpEngine(QObject *parent = nullptr);
    ~PgpEngine() override;

    /// The one instance, for PgpKeyModel — which QML creates itself and so
    /// cannot be handed the engine through a constructor.
    static PgpEngine *instance();

    bool available() const { return m_available; }
    QString unavailableReason() const { return m_unavailableReason; }
    bool busy() const { return m_pending > 0; }

    /// The current keyring snapshot, public and secret keys merged (a key whose
    /// private half is present appears once, with secret == true).
    const QList<PgpKey> &keys() const { return m_keys; }

    /// Re-lists the keyring. Cheap to call redundantly: a refresh already in
    /// flight is not started twice.
    Q_INVOKABLE void refresh();

    /// Secret keys usable as \a address's identity, as variant maps for the
    /// account key picker. Two exclusions, both because the picker should only
    /// offer choices that work: keys whose user IDs do not include the address
    /// (signing as an identity you cannot prove), and keys that are expired,
    /// revoked or disabled — importing an expired key does not make it usable,
    /// so it does not appear here either.
    Q_INVOKABLE QVariantList secretKeysFor(const QString &address) const;

    /// One key by fingerprint, or an empty map. Used by the account page to
    /// describe a stored key without holding a model.
    Q_INVOKABLE QVariantMap keyInfo(const QString &fingerprint) const;

    /// Primary fingerprint of the key that owns \a idOrFingerprint, which may
    /// name the primary itself or any subkey, by fingerprint or key ID.
    /// Empty when the keyring holds no such key. Everything gpg reports about
    /// "which key did this" names a subkey; everything the UI shows is a
    /// primary — this is the bridge.
    Q_INVOKABLE QString primaryFingerprintFor(const QString &idOrFingerprint) const;

    /// Imports every key in an armored or binary key block. Reports through
    /// importFinished().
    Q_INVOKABLE void importKeyData(const QByteArray &keyData);
    /// Same, from a file chosen in the UI. Handles both halves: a file that
    /// carries a *private* key is imported as one, so a user whose key lives
    /// in a backup file rather than in GnuPG's keyring can point Mailove at it
    /// and be done. GnuPG prompts for the file's passphrase if it has one, and
    /// from then on the key is in its keyring like any other — Mailove still
    /// never sees the key material or the passphrase.
    Q_INVOKABLE void importKeyFile(const QUrl &fileUrl);

    /// Writes \a fingerprint's public key, armored, to \a fileUrl. Public only:
    /// exporting a secret key is a backup operation with its own risks, and gpg
    /// (or Kleopatra) is the right place for it.
    Q_INVOKABLE void exportPublicKey(const QString &fingerprint, const QUrl &fileUrl);

    /// Sets how far the user vouches for this key's owner (GpgME::Key::
    /// OwnerTrust, 0-5). 0 clears it back to "nothing said".
    ///
    /// This is a statement about a person, not about bytes: gpg folds it into
    /// the validity it computes for this key *and* for keys that one has
    /// signed. It is the only trust input mailove offers, and it is deliberately
    /// reversible.
    Q_INVOKABLE void setOwnerTrust(const QString &fingerprint, int trust);

    /// Deletes a key from the local keyring. Public keys only — a secret key is
    /// not something to lose to a mis-click in a mail client, and deleting one
    /// silently destroys the ability to read every message encrypted to it.
    Q_INVOKABLE void deletePublicKey(const QString &fingerprint);

    /// Creates a key for \a name <\a email> expiring in \a expiryYears (0 =
    /// never). gpg-agent prompts for the passphrase through pinentry; no
    /// passphrase passes through mailove. Reports through keyGenerated().
    Q_INVOKABLE void generateKey(const QString &name, const QString &email, int expiryYears);

    /// Web Key Directory lookup — asks the address's own domain, so it is safe
    /// to run automatically (see doc/openpgp.md §7). Imports what it finds.
    Q_INVOKABLE void lookupWkd(const QString &address);

    /// keys.openpgp.org lookup. Explicit user action only: it tells a third
    /// party who the user is about to write to.
    Q_INVOKABLE void lookupKeyserver(const QString &address);

    /// Decrypts \a cipherText. Returns a token that comes back with the
    /// result, because the reader can move to another message long before
    /// gpg-agent has finished asking for a passphrase — the caller matches the
    /// answer to the message it was for, and drops it if that message is gone.
    /// Returns 0 if the job could not be started at all.
    ///
    /// gpg-agent owns the passphrase prompt; this call blocks nothing.
    quint64 decrypt(const QByteArray &cipherText);

    /// Which of \a addresses this keyring can encrypt to. Returns a map from
    /// address to fingerprint, with an empty string for every address no
    /// usable key was found for — the compose window needs both halves to say
    /// what it can and cannot do.
    Q_INVOKABLE QVariantMap encryptionKeysFor(const QStringList &addresses) const;

    /// Detached signature over \a data by \a signerFingerprint (RFC 3156 §5).
    /// gpg-agent prompts for the passphrase; nothing here sees it.
    quint64 signDetached(const QByteArray &data, const QString &signerFingerprint);

    /// Encrypts \a data to every key in \a fingerprints. The caller is
    /// responsible for including the sender's own key — leaving it out is how
    /// a Sent copy becomes unreadable to the person who sent it.
    quint64 encryptTo(const QByteArray &data, const QStringList &fingerprints);

    /// Verifies \a signature over \a signedOctets — the RFC 3156 detached case.
    /// Same token scheme as decrypt(). Returns 0 if no job could be started.
    quint64 verifyDetached(const QByteArray &signedOctets, const QByteArray &signature);

Q_SIGNALS:
    /// The keyring snapshot changed — models reload.
    void keysChanged();
    void busyChanged();
    /// A one-line result for the UI's status area. Not an error.
    void statusMessage(const QString &text);
    /// Something failed, in one line the user can act on.
    void errorOccurred(const QString &text);
    /// \a imported new keys, \a unchanged already-known ones. \a error is empty
    /// on success; the counts are then meaningful.
    void importFinished(int imported, int unchanged, const QString &error);
    /// A *private* key was imported — \a fingerprint is the first one. Its own
    /// signal because it means something different from importing a
    /// correspondent's public key: the user just gained an identity they can
    /// sign and decrypt with, and the account page adopts it.
    void secretKeyImported(const QString &fingerprint);
    /// Key generation finished. Both strings empty means the user dismissed
    /// the passphrase prompt: no key, no failure to report.
    void keyGenerated(const QString &fingerprint, const QString &error);
    /// A discovery attempt finished. \a found is false when the address simply
    /// has no published key, which is not an error.
    void lookupFinished(const QString &address, bool found, const QString &source);
    void exportFinished(const QString &fileName, const QString &error);
    /// \a plainText is the decrypted inner MIME tree for the job \a id
    /// identifies. On failure it is empty and \a error says why in one line.
    /// \a noSecretKey separates "not encrypted to any key you hold" — the
    /// common case, and the one worth its own wording — from a real failure.
    void decryptFinished(quint64 id, const QByteArray &plainText, const QString &error,
                         bool noSecretKey);
    /// Which of the user's keys the message was encrypted to, as a key ID.
    /// Emitted before decryptFinished when gpg says. Lets the viewer offer the
    /// key for inspection — for a message that is encrypted but not signed, it
    /// is the only key involved.
    void decryptRecipient(quint64 id, const QString &keyId);
    /// The verdict for the job \a id identifies — from verifyDetached(), or
    /// from a signature gpg found inside a message it was decrypting.
    void verifyFinished(quint64 id, const PgpSignatureInfo &signature);
    /// \a signature is the armored detached signature for job \a id, and
    /// \a micalg the hash it used ("pgp-sha256"), which RFC 3156 requires on
    /// the multipart/signed. Empty with \a error set on failure.
    void signFinished(quint64 id, const QByteArray &signature, const QString &micalg,
                      const QString &error);
    /// \a cipherText is the armored ciphertext for job \a id.
    void encryptFinished(quint64 id, const QByteArray &cipherText, const QString &error);

private:
    /// Wraps a job start/finish pair so busy() and the pending count stay in
    /// step even when several jobs overlap.
    void jobStarted();
    void jobFinished();
    void reportUnavailable();

    /// Holds the GpgME::Key objects behind the snapshot — operations like
    /// delete take a key, not a fingerprint, and re-listing the keyring to
    /// find one again would be both slow and a race. Opaque here so this
    /// header stays free of GpgME types.
    class Private;
    std::unique_ptr<Private> d;

    QList<PgpKey> m_keys;
    KeyDiscovery *m_discovery = nullptr;
    QString m_unavailableReason;
    int m_pending = 0;
    /// Hands out decrypt() tokens. Never reused within a session, so a result
    /// can never be matched to the wrong message.
    quint64 m_nextJobId = 1;
    bool m_available = false;
    bool m_refreshing = false;
    /// A refresh asked for while one was already running: the keyring changed
    /// under it, so the snapshot it produces is already stale.
    bool m_refreshQueued = false;
};
