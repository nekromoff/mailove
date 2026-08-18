// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QString>

/**
 * Outcome of verifying one message's DKIM signatures.
 *
 * \a aligned is not decoration. A valid signature only proves that whoever
 * controls \a domain signed the message — an attacker can sign their own mail
 * with their own domain and get Pass. The result is only meaningful to a user
 * once \a domain is checked against the From: header domain, so any UI that
 * says "verified" must require aligned == true.
 */
/**
 * Outcome of validating a message's ARC chain (RFC 8617).
 *
 * ARC exists for the case DKIM cannot survive: a mailing list rewrites the
 * subject or appends a footer, the author's signature stops matching, and the
 * only evidence that the message authenticated *before* the change is what the
 * list recorded on its way through. Each hop adds a set of three headers — the
 * authentication results it saw, a signature over the message as it forwarded
 * it, and a seal over every ARC header so far — so the chain is tamper-evident
 * even though the message body is not.
 *
 * An intact chain is emphatically not proof the message is genuine. It proves
 * the sealers signed what they claim to have seen; believing the claim means
 * trusting \a sealer, which is a judgement only the reader can make. Any UI
 * built on this must name the sealer rather than reduce it to a checkmark.
 */
struct ArcResult {
    enum Status {
        None,      ///< no ARC headers at all — the ordinary case
        Pass,      ///< every seal verified, and so did the newest signature
        /// Every seal verified, but the newest ARC-Message-Signature did not
        /// match the body. Kept apart from Fail for the same reason as
        /// DkimResult::BodyMismatch: the seals held, so the chain is intact —
        /// what changed is the body, after the last sealer saw it. The seals
        /// cover only the ARC headers, so they stay meaningful when the body
        /// hash does not.
        SealsOnly,
        Fail,      ///< a seal did not verify, or a hop recorded cv=fail
        TempError, ///< DNS lookup failed; retrying later may succeed
        PermError, ///< malformed chain, unusable key, unsupported algorithm
    };

    Status status = None;
    QString sealer; ///< d= of the outermost seal — who is vouching for the chain
    int sets = 0;   ///< how many hops sealed the message
    QString detail; ///< short human-readable reason, for the tooltip
};

struct DkimResult {
    enum Status {
        None,      ///< no DKIM-Signature header at all
        Pass,      ///< at least one signature verified
        Fail,      ///< the signature did not match the published key
        TempError, ///< DNS lookup failed; retrying later may succeed
        PermError, ///< malformed signature, unusable key, no key published
        /// Signed with an algorithm we will not verify — in practice rsa-sha1,
        /// which RFC 8301 forbids because SHA-1 collisions are affordable.
        /// Deliberately not Fail: we could compute it, but a "pass" from a
        /// broken hash is not evidence of anything, and calling it invalid
        /// would claim we checked something we refused to check. The honest
        /// answer is that this signature cannot be evaluated.
        Unsupported,
        /// The body hash did not match. Deliberately NOT Fail: the key was
        /// fetched and the header hash checked out — what differs is the body,
        /// and a changed body is the everyday work of mailing lists and
        /// forwarders appending footers or re-encoding parts. Since 2.9 the
        /// fetch path preserves the original octets (doc/roadmap.md), so on
        /// freshly fetched mail this really means "not the body that was
        /// signed" — but announcing "signature invalid" for it would still cry
        /// wolf on most list mail, which is ARC's case to explain, not Fail's.
        BodyMismatch,
    };

    Status status = None;
    QString domain;   ///< d= of the signature this result describes
    QString selector; ///< s= of that signature
    bool aligned = false;
    /// l= cut the signature short of the whole body (RFC 6376 §3.5). Everything
    /// past the stated length is unsigned and can be appended by anyone who
    /// handles the message, so what verified is a prefix, not what is on screen.
    bool bodyTruncated = false;
    QString detail; ///< short human-readable reason, for the tooltip
    /// Only filled in when it could change what the reader is told: a signature
    /// that already verifies and aligns needs no second opinion, and checking
    /// anyway would spend DNS queries to say the same thing.
    ArcResult arc;

    bool trustworthy() const { return status == Pass && aligned && !bodyTruncated; }
};

/**
 * Which of two verdicts on the same message deserves to be the one shown.
 *
 * A message may carry several signatures — the author's plus a mailing list's
 * or an ESP's — and only one verdict reaches the badge. An aligned Pass ends
 * the search before this is ever consulted; everything below it needs ordering,
 * because "whichever signature happened to be last in the header block" is not
 * a judgement about the message.
 *
 * The order runs from most evidence to least, and it deliberately does not put
 * the harshest verdict first. Fail is the one accusation the badge makes, and
 * on a message a list rewrote it is also the ordinary outcome for the author's
 * signature — so a valid signature from someone else, or a body hash that did
 * not match, both say more and accuse less. Nothing here is hidden: every
 * signature's fate is in the tooltip.
 *
 * Exposed for the tests, which check the orderings that used to come out wrong.
 */
[[nodiscard]] bool moreInformative(const DkimResult &candidate, const DkimResult &current);

/**
 * Canonicalization primitives (RFC 6376 §3.4).
 *
 * Exposed only so tests can check them against the RFC's own vectors in
 * §3.4.5. This is where DKIM verifiers usually go wrong: a canonicalization
 * that is subtly off rejects legitimate mail rather than failing loudly, so it
 * needs external ground truth rather than a round-trip against our own signer.
 */
namespace DkimCanon
{
QByteArray headerRelaxed(const QByteArray &name, const QByteArray &value);
/// Takes the field's original bytes: "simple" must not normalize anything.
QByteArray headerSimple(const QByteArray &rawField);
QByteArray bodyRelaxed(const QByteArray &body);
QByteArray bodySimple(const QByteArray &body);
}

/**
 * Verifies DKIM signatures (RFC 6376) against the DNS-published public key.
 *
 * Lives on its own thread and must only be driven through queued calls to
 * verify(): the work is a DNS round trip plus SHA-256 over the whole message
 * and a public-key operation, none of which belongs on the GUI thread.
 * Verification is deliberately not run for every header in the message list —
 * only for a message the user actually opens. That keeps the cost off the sync
 * path and avoids emitting a DNS query for every sender who has ever mailed
 * you, which would leak the shape of the mailbox to the resolver.
 *
 * The caller passes the message as it appeared on the wire (CRLF line endings);
 * see MailClient::rawMessageForDkim().
 */
class DkimVerifier : public QObject
{
    Q_OBJECT

public:
    using QObject::QObject;

public Q_SLOTS:
    /// \a rawMessageCrlf must be the original octets, CRLF-terminated.
    /// \a fromDomain is the domain of the From: header, for the alignment test.
    /// Answers with finished(\a requestId, …) exactly once.
    void verify(quint64 requestId, const QByteArray &rawMessageCrlf, const QString &fromDomain);

public:
    /// Test seam: supplies the DKIM key record that would otherwise come from
    /// DNS, so verification can be exercised without a resolver. Never set in
    /// the application.
    void setKeyRecordForTest(const QByteArray &record) { m_testKeyRecord = record; }

Q_SIGNALS:
    void finished(quint64 requestId, const DkimResult &result);

private:
    struct Signature; // one parsed DKIM-Signature header

    /// Everything except the DNS step; returns false with \a out filled in when
    /// the signature is unusable before we ever need the key.
    bool prepare(const QByteArray &head, const QByteArray &body, const Signature &sig,
                 QByteArray *signedData, DkimResult *out) const;

    /// RFC 8617 §5.2. Walks every ARC set from the oldest hop outwards.
    /// \a keyCache is shared with the DKIM pass: a chain signs its message
    /// signature and its seal with the same selector more often than not, and a
    /// long chain would otherwise mean a DNS round trip per hop.
    ArcResult verifyArcChain(const QByteArray &head, const QByteArray &body,
                             QHash<QString, QByteArray> *keyCache);

    /// DNS TXT for a `<selector>._domainkey.<domain>` record, through
    /// \a cache (per message) and m_dnsCache (across messages, TTL-bound).
    /// An empty result with *\a tempError false means "no such key".
    QByteArray publicKeyRecord(const QString &dnsName, bool *tempError,
                               QHash<QString, QByteArray> *cache);

    QByteArray m_testKeyRecord;

    /// Cross-message DNS cache. Only touched from the verifier's own thread.
    struct CachedKey {
        QByteArray record; ///< empty = the domain publishes no such key
        qint64 expiry = 0; ///< secsSinceEpoch after which it must be re-asked
    };
    QHash<QString, CachedKey> m_dnsCache;
};

Q_DECLARE_METATYPE(DkimResult)
