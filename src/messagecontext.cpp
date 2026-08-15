// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "messagecontext.h"

#include "mailclient.h"
#include "pgpengine.h"
#include "securewipe.h"
#include "viewersecurity.h"

MessageContext::MessageContext(MailClient *client)
    : QObject(client)
    , m_client(client)
{
}

MessageContext::~MessageContext()
{
    // A detached window closing is the common way a decrypted message goes
    // away, and it never passes through clear().
    wipeSecrets();
    if (m_handler && m_viewerContext)
        m_handler->releaseContext(m_viewerContext);
}

void MessageContext::wipeSecrets()
{
    // Only the decrypted side. m_raw is the ciphertext exactly as it arrived —
    // it is what the server holds and what the cache already stores, so there
    // is nothing to protect there.
    SecureWipe::wipe(m_decryptedRaw);
    // The rendered bodies are the decrypted text once a message has been
    // decrypted; for anything else they are plaintext that arrived plaintext,
    // and wiping them costs nothing either way.
    SecureWipe::wipe(m_htmlBody);
    SecureWipe::wipe(m_textBody);
    // The parsed tree owns the part bodies; dropping it is all we can do,
    // since KMime hands out no way to overwrite them in place.
    m_decrypted.reset();
    markPlaintextHeld(false);
    // Inline images from a decrypted message live in the scheme handler, not
    // here, and are the one decrypted payload that outlives this object's
    // members.
    if (m_handler && m_viewerContext)
        m_handler->clearInlineParts(m_viewerContext);
}

quint64 MessageContext::viewerContext()
{
    if (!m_viewerContext && m_handler)
        m_viewerContext = m_handler->allocateContext();
    return m_viewerContext;
}

void MessageContext::setRemoteContentAllowed(bool allow)
{
    // User toggle: remember the choice for this sender.
    if (m_client)
        m_client->rememberRemoteContent(m_senderAddress, allow);
    applyRemoteAllowed(allow);
}

void MessageContext::markPlaintextHeld(bool held)
{
    if (m_plaintextHeld == held)
        return;
    m_plaintextHeld = held;
    if (held)
        SecureWipe::holdPlaintext();
    else
        SecureWipe::releasePlaintext();
}

void MessageContext::applyRemoteAllowed(bool allow)
{
    // The interceptor flag is profile-global; pushing it on every apply means
    // it always matches the view that is about to (re)load.
    if (m_handler)
        m_handler->setRemoteContentAllowed(allow);
    if (m_remoteAllowed == allow)
        return;
    m_remoteAllowed = allow;
    Q_EMIT remoteContentAllowedChanged();
}

QString MessageContext::htmlViewUrl()
{
    return m_client ? m_client->htmlViewUrlFor(this) : QString();
}

QString MessageContext::textViewUrl()
{
    return m_client ? m_client->textViewUrlFor(this) : QString();
}

QString MessageContext::sourceViewUrl()
{
    return m_client ? m_client->sourceViewUrlFor(this) : QString();
}

QVariantMap MessageContext::replyData(bool replyAll)
{
    return m_client ? m_client->replyDataFor(this, replyAll) : QVariantMap();
}

QVariantMap MessageContext::forwardData()
{
    return m_client ? m_client->forwardDataFor(this) : QVariantMap();
}

QVariantMap MessageContext::forwardAsAttachmentData()
{
    return m_client ? m_client->forwardAsAttachmentDataFor(this) : QVariantMap();
}

bool MessageContext::attachmentRisky(int index) const
{
    return m_client && m_client->attachmentRiskyFor(this, index);
}

void MessageContext::openAttachment(int index)
{
    if (m_client)
        m_client->openAttachmentFor(this, index);
}

void MessageContext::saveAttachmentToDownloads(int index)
{
    if (m_client)
        m_client->saveAttachmentToDownloadsFor(this, index);
}

void MessageContext::saveAttachment(int index, const QUrl &fileUrl)
{
    if (m_client)
        m_client->saveAttachmentFor(this, index, fileUrl);
}

void MessageContext::importAttachedKey()
{
    if (m_attachedKeyData.isEmpty())
        return;
    if (PgpEngine *engine = PgpEngine::instance())
        engine->importKeyData(m_attachedKeyData);
}

void MessageContext::clear()
{
    m_hasMessage = false;
    m_message.reset();
    // The decrypted tree goes with the message it came from — leaving it
    // behind would keep plaintext in memory for a message nobody is reading.
    wipeSecrets();
    m_decryptJob = 0;
    m_cryptoState.clear();
    m_cryptoDetail.clear();
    m_decryptionKeyId.clear();
    m_signatureStatus.clear();
    m_signerName.clear();
    m_signerEmail.clear();
    m_signerFingerprint.clear();
    m_attachedKeyName.clear();
    m_attachedKeyData.clear();
    m_signerTrusted = false;
    m_cryptoChecking = false;
    m_verifyJob = 0;
    m_pgpOctetsExact = false;
    m_pgpFromCache = false;
    m_attachmentParts.clear();
    m_attachments.clear();
    m_raw.clear();
    m_uid = -1;
    m_folder.clear();
    m_senderAddress.clear();
    m_subject.clear();
    m_from.clear();
    m_to.clear();
    m_cc.clear();
    m_date.clear();
    m_authInfo.clear();
    m_bodyUrl.clear();
    if (m_handler && m_viewerContext)
        m_handler->clearInlineParts(m_viewerContext);
    Q_EMIT messageChanged();
    Q_EMIT cryptoChanged();
}

void MessageContext::release()
{
    if (m_handler && m_viewerContext) {
        m_handler->releaseContext(m_viewerContext);
        m_viewerContext = 0;
    }
    deleteLater();
}
