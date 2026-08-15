// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QObject>
#include <QPointer>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

#include <memory>

namespace KMime
{
class Content;
class Message;
}
class MailClient;
class ViewerSchemeHandler;

/**
 * One on-screen message: the parsed state behind a MessageViewer.
 *
 * The reading pane owns one long-lived instance (Mail.readingContext);
 * every detached message window gets its own via double-click. Each context
 * keeps the KMime message (and thus the attachment payloads) alive and holds
 * its own slot in the ViewerSchemeHandler, so windows keep rendering — and
 * keep serving inline images, attachments, Reply/Forward — no matter what
 * the main list moves on to.
 *
 * The state is populated by MailClient and its presentation collaborators
 * (friends); the Q_INVOKABLEs delegate
 * back into MailClient, where the composition and attachment logic lives.
 */
class MessageContext : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasMessage READ hasMessage NOTIFY messageChanged)
    /// Identifies the message this context holds — account, folder and uid.
    /// The tab strip uses it to recognise a message it already has open.
    Q_PROPERTY(QString sourceKey READ sourceKey NOTIFY messageChanged)
    Q_PROPERTY(QString subject READ subject NOTIFY messageChanged)
    Q_PROPERTY(QString from READ from NOTIFY messageChanged)
    Q_PROPERTY(QString to READ to NOTIFY messageChanged)
    Q_PROPERTY(QString cc READ cc NOTIFY messageChanged)
    Q_PROPERTY(QString date READ date NOTIFY messageChanged)
    Q_PROPERTY(QString authInfo READ authInfo NOTIFY messageChanged)
    /// The view to load when the message (first) appears — HTML, or plain
    /// text for junk-folder mail.
    Q_PROPERTY(QString bodyUrl READ bodyUrl NOTIFY messageChanged)
    /// [{name, sizeText}, …] of this message's attachments.
    Q_PROPERTY(QVariantList attachments READ attachments NOTIFY messageChanged)
    /// True when the message came from a junk/spam folder: plain text by
    /// default, HTML only on explicit request.
    Q_PROPERTY(bool junkTextOnly READ junkTextOnly NOTIFY messageChanged)
    /// Mirrors the viewer's HTML/Text choice for this message: replying to or
    /// forwarding a message being read as plain text quotes the plain text.
    Q_PROPERTY(bool quotePlainText READ quotePlainText WRITE setQuotePlainText
                   NOTIFY quotePlainTextChanged)
    /// Per-message opt-in for remote images/CSS/fonts (persisted per sender).
    Q_PROPERTY(bool remoteContentAllowed READ remoteContentAllowed
                   WRITE setRemoteContentAllowed NOTIFY remoteContentAllowedChanged)
    /// DKIM verification we performed ourselves, as opposed to authInfo, which
    /// is only what the receiving server said. "" while still checking, then
    /// one of none/pass/fail/temperror/permerror.
    Q_PROPERTY(QString dkimStatus READ dkimStatus NOTIFY dkimChanged)
    /// Short human-readable reason, for the tooltip.
    Q_PROPERTY(QString dkimDetail READ dkimDetail NOTIFY dkimChanged)
    /// The only property a "verified" badge may key off: a valid signature
    /// AND a signing domain that matches the sender. A valid-but-unaligned
    /// signature is what a forger's own signature looks like.
    Q_PROPERTY(bool dkimTrusted READ dkimTrusted NOTIFY dkimChanged)
    /// True between opening the message and the verifier answering.
    Q_PROPERTY(bool dkimChecking READ dkimChecking NOTIFY dkimChanged)
    /// ARC chain validation (RFC 8617), checked only when DKIM could not give
    /// the reader an answer to rely on. "" when not checked, otherwise one of
    /// none/pass/sealsonly/fail/error.
    Q_PROPERTY(QString arcStatus READ arcStatus NOTIFY dkimChanged)
    /// Domain of the outermost seal — the party whose word the chain rests on.
    /// A chain says nothing on its own; it says what this domain vouches for.
    Q_PROPERTY(QString arcSealer READ arcSealer NOTIFY dkimChanged)
    /// Short human-readable reason, for the tooltip.
    Q_PROPERTY(QString arcDetail READ arcDetail NOTIFY dkimChanged)

    /// OpenPGP state of this message: "" (nothing), "encrypted" (decrypted and
    /// shown), "failed" (encrypted, and we could not read it), or "partial"
    /// (OpenPGP inside a larger message — never decrypted for display, see
    /// doc/openpgp.md §3).
    Q_PROPERTY(QString cryptoState READ cryptoState NOTIFY cryptoChanged)
    /// True between opening an encrypted message and gpg answering. The
    /// passphrase prompt lives in this window, so it can be a long while.
    Q_PROPERTY(bool cryptoChecking READ cryptoChecking NOTIFY cryptoChanged)
    /// One line for the badge's tooltip.
    Q_PROPERTY(QString cryptoDetail READ cryptoDetail NOTIFY cryptoChanged)
    /// The OpenPGP signature verdict, or "" when the message carries none:
    /// "valid", "unverified", "unknownKey", "expired", "revoked", "error".
    /// Deliberately no "invalid" — see PgpSignatureInfo.
    Q_PROPERTY(QString signatureStatus READ signatureStatus NOTIFY cryptoChanged)
    /// Who the signature says signed it, named from our own keyring rather
    /// than from anything the message claims. May be empty for a valid
    /// signature whose key carries no name.
    Q_PROPERTY(QString signerName READ signerName NOTIFY cryptoChanged)
    Q_PROPERTY(QString signerEmail READ signerEmail NOTIFY cryptoChanged)
    Q_PROPERTY(QString signerFingerprint READ signerFingerprint NOTIFY cryptoChanged)
    /// The only property a "signed by X" badge may key off: a valid signature
    /// AND a signing address that matches the From header. A valid signature
    /// from an unrelated key is exactly what a forger's own key produces —
    /// the same rule dkimTrusted follows, for the same reason.
    Q_PROPERTY(bool signerTrusted READ signerTrusted NOTIFY cryptoChanged)
    /// The key this message was encrypted to (a key ID), when it was
    /// encrypted to one of ours. Lets the viewer open the key manager on it
    /// for a message that carries no signature to name a key instead.
    Q_PROPERTY(QString decryptionKeyId READ decryptionKeyId NOTIFY cryptoChanged)
    /// True once decrypted content is what the viewer is showing. The remote-
    /// content opt-in keys off this: a request made from decrypted mail can
    /// carry the plaintext back to whoever chose the URL.
    Q_PROPERTY(bool showingDecrypted READ showingDecrypted NOTIFY cryptoChanged)
    /// Description of a public key this message carries as an attachment
    /// ("key for jane@example.com"), or "" when it carries none. Nothing is
    /// imported without the reader asking: a key that arrives by mail is a
    /// claim about an identity, and accepting it silently is how the wrong key
    /// ends up trusted.
    Q_PROPERTY(QString attachedKeyName READ attachedKeyName NOTIFY cryptoChanged)

public:
    explicit MessageContext(MailClient *client);
    ~MessageContext() override;

    bool hasMessage() const { return m_hasMessage; }
    QString sourceKey() const { return m_sourceKey; }
    QString subject() const { return m_subject; }
    QString from() const { return m_from; }
    QString to() const { return m_to; }
    QString cc() const { return m_cc; }
    QString date() const { return m_date; }
    QString authInfo() const { return m_authInfo; }
    QString bodyUrl() const { return m_bodyUrl; }
    QVariantList attachments() const { return m_attachments; }
    bool junkTextOnly() const { return m_junk; }
    bool quotePlainText() const { return m_quotePlain; }
    void setQuotePlainText(bool plain)
    {
        if (m_quotePlain == plain)
            return;
        m_quotePlain = plain;
        Q_EMIT quotePlainTextChanged();
    }
    bool remoteContentAllowed() const { return m_remoteAllowed; }
    void setRemoteContentAllowed(bool allow);
    QString dkimStatus() const { return m_dkimStatus; }
    QString dkimDetail() const { return m_dkimDetail; }
    bool dkimTrusted() const { return m_dkimTrusted; }
    bool dkimChecking() const { return m_dkimChecking; }
    QString arcStatus() const { return m_arcStatus; }
    QString arcSealer() const { return m_arcSealer; }
    QString arcDetail() const { return m_arcDetail; }
    QString cryptoState() const { return m_cryptoState; }
    bool cryptoChecking() const { return m_cryptoChecking; }
    QString cryptoDetail() const { return m_cryptoDetail; }
    bool showingDecrypted() const { return m_decrypted != nullptr; }
    QString decryptionKeyId() const { return m_decryptionKeyId; }
    QString signatureStatus() const { return m_signatureStatus; }
    QString signerName() const { return m_signerName; }
    QString signerEmail() const { return m_signerEmail; }
    QString signerFingerprint() const { return m_signerFingerprint; }
    bool signerTrusted() const { return m_signerTrusted; }
    QString attachedKeyName() const { return m_attachedKeyName; }
    /// Imports the key this message carries. Reports through PgpEngine's
    /// importFinished, which the viewer is already listening to.
    Q_INVOKABLE void importAttachedKey();

    // View URLs for the HTML / Text / Source toggle (this message's, always —
    // independent of what the reading pane shows).
    Q_INVOKABLE QString htmlViewUrl();
    Q_INVOKABLE QString textViewUrl();
    Q_INVOKABLE QString sourceViewUrl();

    /// Compose prefill for replying to this message — see MailClient::replyData.
    Q_INVOKABLE QVariantMap replyData(bool replyAll);
    /// Compose prefill for forwarding this message — see MailClient::forwardData.
    Q_INVOKABLE QVariantMap forwardData();
    /// Compose prefill for forwarding this message as a message/rfc822
    /// attachment — see MailClient::forwardAsAttachmentData.
    Q_INVOKABLE QVariantMap forwardAsAttachmentData();

    Q_INVOKABLE bool attachmentRisky(int index) const;
    Q_INVOKABLE void openAttachment(int index);
    Q_INVOKABLE void saveAttachmentToDownloads(int index);
    Q_INVOKABLE void saveAttachment(int index, const QUrl &fileUrl);

    /// Back to "no message" (reading pane only — windows just close).
    Q_INVOKABLE void clear();
    /// Frees the context when its window closes: drops the scheme-handler
    /// slot (body + inline parts) and deletes this object.
    Q_INVOKABLE void release();

Q_SIGNALS:
    /// A different message (or none) is now behind this context.
    void messageChanged();
    void remoteContentAllowedChanged();
    void quotePlainTextChanged();
    void dkimChanged();
    void cryptoChanged();

private:
    friend class MailClient;
    // Fills the presentation fields below from a MIME tree, and reads
    // them back to render the viewer and save attachments.
    friend class MessagePresenter;
    // Owns the DKIM/OpenPGP verdict fields and the jobs behind them.
    friend class MessageVerifier;

    /// The scheme-handler slot, allocated on first use.
    quint64 viewerContext();
    /// Sets the flag without persisting a per-sender preference.
    void applyRemoteAllowed(bool allow);

    /// Overwrites the decrypted message held in memory, then drops it.
    ///
    /// Called when the message goes away — cleared, or the window closed. Qt's
    /// containers free without overwriting, so without this the plaintext
    /// stays in the heap until something else happens to reuse those pages.
    ///
    /// Best effort, and worth being exact about the limits: Qt strings are
    /// copy-on-write, so if a copy of a buffer is still alive elsewhere this
    /// wipes ours and leaves theirs; nothing here is in locked memory, so the
    /// pages can reach swap; and a crash runs no destructors at all, so a core
    /// dump can still contain a message that was open. Closing a message is
    /// covered. Those three are not.
    void wipeSecrets();

    /// Declares whether this context is holding decrypted plaintext, which is
    /// what suppresses core dumps for as long as any context is. Idempotent,
    /// so the reference count cannot drift.
    void markPlaintextHeld(bool held);

    MailClient *m_client = nullptr;
    QPointer<ViewerSchemeHandler> m_handler;
    quint64 m_viewerContext = 0; // 0 = not allocated yet

    std::shared_ptr<KMime::Message> m_message; ///< keeps attachment parts alive
    /// The decrypted inner MIME tree, when there is one. Held only here, in
    /// memory, for exactly as long as the message is open: it is never written
    /// to the cache, the search index or the attachment store (doc/openpgp.md
    /// §4). m_message and m_raw stay the ciphertext as it arrived.
    std::shared_ptr<KMime::Message> m_decrypted;
    /// The plaintext gpg produced, exactly as it produced it. Held for the
    /// same reason m_raw is: a signature inside a decrypted message is over
    /// these octets, not over whatever re-serialising the parsed tree yields.
    /// In memory only, and dropped with the message (doc/openpgp.md §4).
    QByteArray m_decryptedRaw;
    /// Whether this context is counted in the core-dump suppression above.
    bool m_plaintextHeld = false;
    QList<KMime::Content *> m_attachmentParts; ///< owned by m_message
    QVariantList m_attachments;
    QString m_htmlBody;  ///< raw HTML part
    QString m_textBody;  ///< plain-text part
    QByteArray m_raw;    ///< complete RFC-822 source
    qint64 m_uid = -1;
    QString m_folder;    ///< mailbox this message was opened from
    QString m_sourceKey; ///< account + folder + uid; see sourceKey()
    QString m_senderAddress; ///< addr-spec of the sender (remote-content key)
    bool m_junk = false;
    bool m_remoteAllowed = false;
    bool m_quotePlain = false; ///< viewer is showing this message as plain text
    bool m_hasMessage = false;

    QString m_subject, m_from, m_to, m_cc, m_date, m_authInfo, m_bodyUrl;

    QString m_dkimStatus;
    QString m_dkimDetail;
    QString m_arcStatus;
    QString m_arcSealer;
    QString m_arcDetail;
    QString m_cryptoState;
    QString m_cryptoDetail;
    QString m_decryptionKeyId;
    QString m_signatureStatus;
    QString m_signerName;
    QString m_signerEmail;
    QString m_signerFingerprint;
    QString m_attachedKeyName;
    /// The attached key block itself, kept so importing it does not depend on
    /// the message still being parsed when the reader gets around to clicking.
    QByteArray m_attachedKeyData;
    bool m_signerTrusted = false;
    bool m_cryptoChecking = false;
    /// The verify job this context is waiting for, 0 when it is not.
    quint64 m_verifyJob = 0;
    /// Whether the octets handed to the OpenPGP verifier were the message's
    /// own, sliced out of the raw bytes, rather than rebuilt from the parsed
    /// tree. Decides whether a mismatch may be reported as a fact about the
    /// message — the same question m_dkimFromCache settles for DKIM.
    bool m_pgpOctetsExact = false;
    /// Whether the bytes the OpenPGP signature was checked against came out of
    /// the offline cache. Bodies written by older builds are not the octets
    /// that arrived, so a mismatch against them says nothing about the message
    /// until it has been refetched once — see MailClient::healCachedBody.
    bool m_pgpFromCache = false;
    /// The decrypt job this context is waiting for, 0 when it is not. Results
    /// for any other id belong to a message the reader has already left.
    quint64 m_decryptJob = 0;

    bool m_dkimTrusted = false;
    bool m_dkimChecking = false;
    int m_dkimAttempt = 0; ///< DNS retries used for this message so far
    /// Whether the bytes handed to the verifier came from the offline cache
    /// rather than straight off the wire. Decides how a body-hash mismatch is
    /// reported: our stored copy may be at fault, the server's copy is not.
    bool m_dkimFromCache = false;
};
