// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>

/**
 * Header and structure based spam scoring.
 *
 * Deliberately free of I/O: no database, no network, no DNS. Everything the
 * scorer cannot read out of the message itself arrives in a Context filled in
 * by the caller, which is what makes the whole thing checkable offline by
 * tests/spamtool.cpp against a corpus of real mail. A scorer that queries
 * things while it scores cannot be measured, and an unmeasurable spam filter
 * is one whose false-positive rate nobody knows.
 *
 * The weights below are not a probability model — they are an ordering. What
 * matters is that no single weak signal can reach the spam threshold on its
 * own, so a legitimate message has to trip several independent rules before it
 * is ever marked. Anything that fires on ordinary bulk mail (newsletters hiding
 * a preheader with font-size:0, for instance) is either weighted so low it
 * cannot matter or left out entirely; see the notes in spamheuristics.cpp.
 */
namespace SpamHeuristics
{

/// One rule that fired, with the reason shown in the "Why?" tooltip.
struct Hit {
    QString id;      ///< stable identifier, e.g. "known-contact-spoofed"
    int weight = 0;  ///< positive = spammier, negative = hammier
    QString detail;  ///< one line of human-readable evidence
};

/// Three-way, never two-way. "Unsure" is the whole point: a filter forced to
/// choose between spam and ham on thin evidence gets to be wrong about mail it
/// had no business judging, so anything short of confident stays unmarked.
enum class Verdict {
    Ham,
    Unsure,
    Spam,
};

/// Score at or above this is marked. The default is chosen so that no two
/// ordinary rules can reach it together — it takes either one decisive signal
/// (a known contact whose authentication failed) or an accumulation of three
/// or four. Not a constant: it is read from the advanced-settings schema
/// (spam/threshold), which is where mail unusual enough to need a different
/// number is accommodated.
int spamThreshold();
/// The weight of a fact rather than an inference: a message already filed as
/// junk. Far above the threshold on purpose — no accumulation of ham credit,
/// not an OpenPGP signature and a long correspondence together, may pull a
/// message the user has thrown away back out of the marked state.
inline constexpr int JunkFolderWeight = 999;
/// Below this, nothing is shown at all.
inline constexpr int UnsureThreshold = 25;

/// What the caller knows and the message does not say for itself.
struct Context {
    /// The From address appears in the recipients table — mail has been sent to
    /// this person from one of the user's accounts. See MailStore::isKnownCorrespondent().
    bool knownCorrespondent = false;

    /// Our own receiving server reported spf/dkim/dmarc = fail, softfail or
    /// permerror. Only ever set from an Authentication-Results header whose
    /// authserv-id we trust — a sender's own AR header is worthless here.
    bool authFailed = false;
    /// Same provenance, reporting a pass.
    bool authPassed = false;
    /// Same provenance, but the softer verdict: spf=softfail is the domain's
    /// own hedge (~all), "probably not ours, but do not bounce it". Scored by
    /// its own lower-weighted rule, and — unlike \a authFailed — it never
    /// revokes the known-correspondent exemption: a known contact's mail
    /// crossing a forwarder is precisely what softfail looks like.
    bool authSoftFailed = false;

    /// The same trusted Authentication-Results reported arc=pass.
    ///
    /// ARC exists for exactly one situation: a mailing list or forwarder took
    /// delivery of a message, rewrote or re-sent it, and broke SPF and DKIM in
    /// the process. The chain carries the verdict from before that happened, so
    /// arc=pass means "this failed here, but it passed where it started".
    /// Scoring the failure anyway would mark every mailing list the user is on
    /// — which is what \a authFailed does on its own, and why this exists.
    ///
    /// Not validated here: verifying a seal needs DNS, and this file does no
    /// I/O. It is trusted on exactly the same basis as \a authPassed, being
    /// read from the same header our own receiving server stamped.
    bool arcPassed = false;
    /// The raw trusted Authentication-Results value, for the detail line.
    QString authInfo;

    /// How many messages from the From address's organizational domain are
    /// already in the cache, and over how many days they are spread. Filled by
    /// the caller from MailStore::senderDomainHistory().
    ///
    /// This is the "we have seen this domain before" signal, and it exists
    /// because knownCorrespondent only knows who the user has *written to* —
    /// which is nobody, for the banks, invoices and notification bots that are
    /// otherwise the hardest mail to score. Zero means "never seen", which is
    /// what ordinary first contact looks like and is never scored as
    /// suspicious: familiarity can only ever earn ham credit here.
    int seenFromOrg = 0;
    int daysKnownOrg = 0;

    /// The top-level domains the user's own outgoing mail actually goes to,
    /// each one holding at least spam/tldSharePercent of everything they have
    /// written to. Filled from MailStore::sentTldProfile().
    ///
    /// A weaker, coarser cousin of \a knownCorrespondent and \a seenFromOrg,
    /// and the only one of the three that can say anything about a sender who
    /// is a complete stranger from a domain never seen here: someone who
    /// corresponds within .sk and .com has no business receiving a first
    /// contact from .top, and it is exactly the first contact that the other
    /// two familiarity signals are structurally blind to.
    ///
    /// Only ever an accusation, never credit — a message from a TLD the user
    /// does write to is not thereby any less spammy, and most spam arrives
    /// from .com. See \a sentTldSample for why it is also weighted low.
    QStringList familiarTlds;
    /// How many sent-to addresses the list above was computed from. The rule
    /// stays silent below spam/tldMinSample, because a profile built from a
    /// handful of sent messages describes the user's last week rather than
    /// their correspondence, and a fresh install has no Sent folder synced at
    /// all. Zero disables the rule outright.
    int sentTldSample = 0;

    /// Every address the user receives mail at, lowercased and +tag-stripped.
    /// Used only to notice that a message is addressed to nobody the user is —
    /// never to require it, because ordinary bcc'd mail looks exactly the same.
    /// Empty disables the rule outright, which is the right behaviour when the
    /// caller has no account list to hand.
    QStringList ownAddresses;

    /// The message's In-Reply-To or References names a Message-ID that is
    /// already in the cache: this is a reply inside a conversation the user
    /// already has. Filled from MailStore::knownMessageIds().
    ///
    /// A strong ham signal, and one that cannot be forged usefully — a spammer
    /// would have to know a Message-ID from the user's own mailbox to claim it.
    bool inReplyToKnown = false;

    /// PgpMime::StoredKind — 0 none, 1 encrypted, 2 signed, 3 both. Taken as a
    /// strong ham signal without checking the key: at list-build time no
    /// signature has been verified yet, and spam that bothers to be OpenPGP
    /// signed or encrypted to the recipient's key is not a thing that happens.
    int crypto = 0;

    /// The message is sitting in a junk/spam folder.
    ///
    /// Decisive, and the only signal here that outranks Rule 0. Everything else
    /// in this file is the filter guessing; this is a fact about where the
    /// message already is — either the user put it there by hand, or a
    /// server-side rule did, and in both cases the judgement has been made by
    /// something better informed than a header scorer. Mail that arrived before
    /// any of these rules existed is the case that matters most: it carries no
    /// stored verdict at all, and without this it would sit unmarked in the
    /// junk folder forever.
    ///
    /// Scoring continues past it rather than stopping, so the tooltip still
    /// lists whatever else the message trips. "It is in your Junk folder" is a
    /// true answer to "why is this marked?" but a thin one, and the rules that
    /// would have caught it anyway are worth showing.
    bool inJunkFolder = false;

    /// True to skip the known-correspondent short circuit and score the message
    /// anyway. Only for spamtool, which needs to see what a message would have
    /// scored without the exemption masking it.
    bool alwaysScore = false;
};

struct Score {
    int total = 0;
    Verdict verdict = Verdict::Ham;
    QList<Hit> hits;

    /// Set when Rule 0 applied and scoring was skipped entirely.
    bool exempt = false;
    QString exemptReason;

    /// Multi-line "Why?" text: one line per rule that fired. Empty when nothing
    /// fired, so the UI can use emptiness to mean "nothing to explain".
    QString explanation() const;
};

/// The parts of a message the scorer looks at. \a html and \a text are
/// optional: at list-build time only the head is available, and every rule that
/// needs a body simply does not fire. That is why the same message can score
/// higher once its body arrives, and why the stored score is refined rather
/// than treated as final.
struct Message {
    QByteArray head;
    QString html;
    QString text;

    /// Attachment filenames as the message declares them, in any case. Empty
    /// at list-build time, like \a html and \a text, so the rules that read it
    /// simply do not fire until a body has been parsed.
    QStringList attachmentNames;
    /// An attached archive that needs a password to open. Set by the caller,
    /// which is the only side that has looked inside the container.
    bool encryptedArchive = false;
};

Score score(const Message &msg, const Context &ctx);

/// An Authentication-Results value with its (comments) and quoted strings
/// dropped. Both carry sender-supplied text — a genuine header echoes the
/// envelope sender in smtp.mailfrom= — and both may contain ';' or the literal
/// "dkim=pass", so they have to go before the value is split into fields or a
/// sender could smuggle a verdict past the parser.
QString stripAuthCommentsAndQuotes(const QString &value);
/// The "method=result" verdicts of an Authentication-Results value, lowercased
/// and in header order: spf, dkim, dmarc, arc, and compauth (Microsoft's
/// composite verdict, stamped only by Exchange Online). Only the leading token
/// of each ';'-delimited field counts — everything after it echoes
/// sender-supplied data.
QStringList authResultVerdicts(const QString &value);
/// Whether spam/trust<Method> says this method's verdicts count — the same
/// switch for scoring and for display, so the viewer's badge never shows a
/// verdict the score ignored. Unknown methods are trusted (there is no key to
/// say otherwise).
bool authMethodTrusted(const QString &method);
/// True when a verdict reports an outright authentication failure:
/// spf/dkim/dmarc fail, hardfail or permerror — and compauth=fail, unless
/// spam/trustCompauth is off. softfail is deliberately not this
/// (authResultsSoftFailed), and arc= entries are not read here: a broken
/// chain is not evidence of forgery, only a missing exemption.
bool authResultsFailed(const QString &value);
/// True when a trusted method reported softfail — the domain hedging rather
/// than denying. Weighted apart from a failure, and never strong enough to
/// revoke the known-correspondent exemption.
bool authResultsSoftFailed(const QString &value);
/// True when spf, dkim, dmarc or (when trusted) compauth reports a pass.
/// arc=pass deliberately does not count: what it certifies is that a relay
/// broke the others, which is authResultsArcPassed()'s question, not this one.
bool authResultsPassed(const QString &value);
/// True when the value carries arc=pass. See Context::arcPassed for what that
/// is worth and why it is read apart from a plain pass.
bool authResultsArcPassed(const QString &value);

/// The bare addr-spec of a From/Reply-To style header value, lowercased and
/// with any +tag stripped. Empty when the value carries no address.
QString addressOf(const QString &headerValue);
/// The address with its +tag removed, lowercased. Used for allowlist lookups so
/// that mail to you+shopping@ still recognises you@.
QString normalizeAddress(const QString &address);
/// Display name of a mailbox header value, unquoted, without the address part.
QString displayNameOf(const QString &headerValue);
/// Top-level domain of an address — the last label of its domain, lowercased,
/// without a leading dot ("sk", "com"). Deliberately the bare TLD and not the
/// public suffix: "co.uk" and "org.uk" are the same country to a reader
/// deciding whether they know anybody there. Empty when there is no domain, and
/// for an address literal ([192.0.2.1]), which has no TLD to speak of.
QString tldOf(const QString &address);
/// Registrable domain of an address, via the Public Suffix List. Falls back to
/// the full domain when the list has not loaded, which can only ever make two
/// domains look *less* related — the safe direction.
QString organizationalDomainOf(const QString &address);

} // namespace SpamHeuristics
