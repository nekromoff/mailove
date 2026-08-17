// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/// Pass/fail checks for the spam scorer, as opposed to tests/spamtool, which
/// only prints what fired.
///
/// Two things are being guarded, and the second matters more than the first.
/// One: every rule still fires on the shape it was written for — a rule that
/// silently stops matching is a filter quietly getting worse, and nothing else
/// in the build would notice. Two: none of the ham below ever reaches the
/// unsure threshold. A spam filter's only real cost is the wanted message it
/// hides, so the ham set is the part of this file that must never be relaxed
/// to make a new rule fit; the rule gets a lower weight instead.
///
/// The messages are written inline rather than kept as .eml files: each one
/// exists to exercise exactly one rule, and having the header that triggers it
/// three lines above the assertion is what keeps the pair honest.
///
/// Self-contained: no cache, no network, no keyring, and a throwaway config
/// location — every weight is overridable through advanced.conf now, so a
/// reader's own file would otherwise decide what this test measures. The
/// Public Suffix List is
/// loaded from a handful of rules written into this file rather than the real
/// one, so the domain-alignment rules are exercised the same way on every
/// machine and a stale download cannot change what a check means.
///
/// Exit 0 = all checks passed.

#include "advancedconfig.h"
#include "publicsuffixlist.h"
#include "spamheuristics.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDir>
#include <QStringList>
#include <QTextStream>

namespace
{
QTextStream out(stdout);
int failures = 0;

void check(bool ok, const QString &what)
{
    out << (ok ? "ok   " : "FAIL ") << what << '\n';
    if (!ok)
        ++failures;
    out.flush();
}

bool fired(const SpamHeuristics::Score &s, const char *id)
{
    for (const SpamHeuristics::Hit &h : s.hits) {
        if (h.id == QLatin1String(id))
            return true;
    }
    return false;
}

QString hitList(const SpamHeuristics::Score &s)
{
    QStringList ids;
    for (const SpamHeuristics::Hit &h : s.hits)
        ids.append(QStringLiteral("%1%2").arg(h.id).arg(h.weight));
    return ids.join(QLatin1Char(' '));
}

SpamHeuristics::Message headOnly(const char *head)
{
    SpamHeuristics::Message m;
    m.head = QByteArray(head);
    return m;
}

/// A well-formed head with nothing wrong with it, so a rule under test is the
/// only thing a fixture is missing. Anything a fixture wants to break it
/// replaces by writing that field itself.
const char *plainHead()
{
    return "Received: from mail.sender.test (mail.sender.test [198.51.100.7])"
           " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
           "From: Alice Sender <alice@sender.test>\r\n"
           "To: You <you@example.org>\r\n"
           "Subject: Lunch on Thursday\r\n"
           "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
           "Message-ID: <c1@sender.test>\r\n";
}

/// One rule, one message. Asserts the rule fired and — because a rule that
/// fires with the wrong strength is as much a defect as one that does not fire
/// — that the verdict came out where it was meant to.
void expectRule(const char *id, const char *head, SpamHeuristics::Verdict want,
                const SpamHeuristics::Context &ctx = {})
{
    const SpamHeuristics::Score s = SpamHeuristics::score(headOnly(head), ctx);
    check(fired(s, id), QStringLiteral("%1 fires (total %2: %3)")
                            .arg(QLatin1String(id))
                            .arg(s.total)
                            .arg(hitList(s)));
    check(s.verdict == want, QStringLiteral("%1 verdict %2, wanted %3")
                                 .arg(QLatin1String(id))
                                 .arg(int(s.verdict))
                                 .arg(int(want)));
}

// --- the new header rules ------------------------------------------------

void testBrandImpersonation()
{
    expectRule("brand-impersonation",
               "Received: from x.test (x.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: \"PayPal Service\" <billing@secure-x1z.test>\r\n"
               "To: You <you@example.org>\r\n"
               "Subject: Your account\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <b1@secure-x1z.test>\r\n",
               SpamHeuristics::Verdict::Unsure);

    // The same name from the domain the brand really uses must say nothing.
    const SpamHeuristics::Score genuine = SpamHeuristics::score(
        headOnly("Received: from mx.paypal.com (mx.paypal.com [198.51.100.9])"
                 " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: \"PayPal Service\" <service@paypal.com>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Your receipt\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <b2@paypal.com>\r\n"),
        {});
    check(!fired(genuine, "brand-impersonation"),
          QStringLiteral("brand-impersonation silent on the brand's own domain (%1)")
              .arg(hitList(genuine)));

    // And familiarity clears it, for the brand that mails via a bulk sender.
    SpamHeuristics::Context familiar;
    familiar.seenFromOrg = 40;
    familiar.daysKnownOrg = 200;
    const SpamHeuristics::Score known = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: \"Apple\" <no-reply@apple-mailer.test>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Your receipt\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <b3@apple-mailer.test>\r\n"),
        familiar);
    check(!fired(known, "brand-impersonation"),
          QStringLiteral("brand-impersonation silent on a familiar domain (%1)")
              .arg(hitList(known)));
}

void testFreemailShapes()
{
    expectRule("freemail-reply-to",
               "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: Finance <finance@supplier-co.test>\r\n"
               "Reply-To: supplier.finance881@gmail.com\r\n"
               "To: You <you@example.org>\r\n"
               "Subject: Updated bank details\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <f1@supplier-co.test>\r\n",
               SpamHeuristics::Verdict::Unsure);

    expectRule("freemail-brand-name",
               "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: \"Acme Billing Support\" <acme.billing44@gmail.com>\r\n"
               "To: You <you@example.org>\r\n"
               "Subject: Invoice overdue\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <f2@gmail.com>\r\n",
               SpamHeuristics::Verdict::Unsure);

    // An ordinary person mailing from the same provider must stay clean.
    const SpamHeuristics::Score person = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: \"Jana Novakova\" <jana.novakova@gmail.com>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Photos from Saturday\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <f3@gmail.com>\r\n"),
        {});
    check(!fired(person, "freemail-brand-name"),
          QStringLiteral("freemail-brand-name silent on a person (%1)").arg(hitList(person)));
}

void testEnvelopeAndRouting()
{
    // A platform posting for a domain that authorises it in SPF. Scored at all,
    // this was 6% of a real inbox; the rule is gone and this pins it gone.
    const SpamHeuristics::Score esp = SpamHeuristics::score(
        headOnly("Return-Path: <bounce@mailin.fr>\r\n"
                 "Received: from a.mailin.fr (a.mailin.fr [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Alerts <alerts@phish.id>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Statement ready\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <e1@mailin.fr>\r\n"),
        {});
    check(!fired(esp, "return-path-mismatch") && esp.total == 0,
          QStringLiteral("a platform posting under its own envelope scores nothing (%1)")
              .arg(hitList(esp)));

    expectRule("single-hop-unknown",
               "Received: from unknown ([203.0.113.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: Sender <s@one-hop.test>\r\n"
               "To: You <you@example.org>\r\n"
               "Subject: Hello\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <e2@one-hop.test>\r\n",
               SpamHeuristics::Verdict::Ham);

    expectRule("undisclosed-recipients",
               "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: Sender <s@blast.test>\r\n"
               "To: undisclosed-recipients:;\r\n"
               "Subject: Offer inside\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <e3@blast.test>\r\n",
               SpamHeuristics::Verdict::Ham);

    SpamHeuristics::Context mine;
    mine.ownAddresses = {QStringLiteral("you@example.org")};
    expectRule("not-addressed-to-you",
               "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: Sender <s@blast.test>\r\n"
               "To: someone-else@elsewhere.test\r\n"
               "Subject: Offer inside\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <e4@blast.test>\r\n",
               SpamHeuristics::Verdict::Ham, mine);

    // Delivered-To answers the alias the account list does not know about.
    const SpamHeuristics::Score alias = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "Delivered-To: you@example.org\r\n"
                 "From: Sender <s@list.test>\r\n"
                 "To: announce@list.test\r\n"
                 "Subject: Release notes\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <e5@list.test>\r\n"),
        mine);
    check(!fired(alias, "not-addressed-to-you"),
          QStringLiteral("not-addressed-to-you silent when Delivered-To is ours (%1)")
              .arg(hitList(alias)));
}

void testSubjectTricks()
{
    expectRule("zero-width-obfuscation",
               "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: Sender <s@x1z.test>\r\n"
               "To: You <you@example.org>\r\n"
               "Subject: Pay\xE2\x80\x8BPal account limited\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <s1@x1z.test>\r\n",
               SpamHeuristics::Verdict::Unsure);

    expectRule("charset-mismatch",
               "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
               " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
               "From: Sender <s@x1z.test>\r\n"
               "To: You <you@example.org>\r\n"
               "Subject: =?gb2312?B?SGVsbG8gZnJpZW5k?=\r\n"
               "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
               "Message-ID: <s2@x1z.test>\r\n",
               SpamHeuristics::Verdict::Ham);
}

void testThreadReplyIsHam()
{
    SpamHeuristics::Context ctx;
    ctx.inReplyToKnown = true;
    // A reply that would otherwise have collected several small penalties.
    const SpamHeuristics::Score s = SpamHeuristics::score(
        headOnly("Received: from unknown ([203.0.113.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Colleague <c@partner.test>\r\n"
                 "Reply-To: c.private@gmail.com\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Re: the contract\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "In-Reply-To: <earlier@example.org>\r\n"
                 "Message-ID: <t1@partner.test>\r\n"),
        ctx);
    check(fired(s, "thread-reply"),
          QStringLiteral("thread-reply fires (%1)").arg(hitList(s)));
    check(s.verdict == SpamHeuristics::Verdict::Ham,
          QStringLiteral("a reply in a known thread stays ham (total %1)").arg(s.total));
}

/// Four false positives found by running the scorer over a real mailbox, each
/// one a rule reading a legitimate arrangement as an attack. They are grouped
/// here because they share a cause: the assumption that the domain in From is
/// the only domain a legitimate message may involve. It is not — mail crosses
/// relays, is posted by mailing platforms, and links to a brand's own alias
/// domains, and none of that is evidence of anything.
void testMeasuredFalsePositives()
{
    // 1. Google Groups rewrites From to the list and keeps the author's name
    //    in the display name. Reading the two together said the user's own
    //    company was impersonating Google.
    const SpamHeuristics::Score viaList = SpamHeuristics::score(
        headOnly("Received: from mail-relay.test (mail-relay.test [198.51.100.2])"
                 " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: \"'Google Ads' via mcc\" <mcc@company.test>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Your campaign report\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <v1@company.test>\r\n"),
        {});
    check(!fired(viaList, "brand-impersonation"),
          QStringLiteral("a \"X via list\" relay is not brand impersonation (%1)")
              .arg(hitList(viaList)));

    // 2. A mailing list breaks SPF and DKIM by design; ARC is what carries the
    //    original verdict past it. Without reading ARC the scorer marked every
    //    list a user subscribes to, and revoked Rule 0 for lists they post to.
    SpamHeuristics::Context relayFail;
    relayFail.authFailed = true;
    relayFail.arcPassed = true;
    relayFail.knownCorrespondent = true;
    const char *listMail =
        "Received: from lists.project.test (lists.project.test [198.51.100.8])"
        " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Contributor <contributor@personal.test>\r\n"
        "To: devel@lists.project.test\r\n"
        "Subject: [PATCH] tidy up the parser\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "List-Id: <devel.lists.project.test>\r\n"
        "List-Unsubscribe: <https://lists.project.test/u>\r\n"
        "Message-ID: <v2@personal.test>\r\n";
    const SpamHeuristics::Score arcOk = SpamHeuristics::score(headOnly(listMail), relayFail);
    check(!fired(arcOk, "auth-fail") && !fired(arcOk, "known-contact-spoofed"),
          QStringLiteral("arc=pass explains a relay's SPF/DKIM failure (%1)")
              .arg(hitList(arcOk)));
    check(arcOk.exempt || arcOk.verdict == SpamHeuristics::Verdict::Ham,
          QStringLiteral("list mail with arc=pass stays ham (total %1)").arg(arcOk.total));

    // Without ARC the same failure must still count: this is a suppression
    // with a reason, not a way for anything claiming to be a list to opt out.
    SpamHeuristics::Context noArc = relayFail;
    noArc.arcPassed = false;
    const SpamHeuristics::Score noArcScore = SpamHeuristics::score(headOnly(listMail), noArc);
    check(fired(noArcScore, "known-contact-spoofed"),
          QStringLiteral("without ARC the failure still counts (%1)").arg(hitList(noArcScore)));

    // 3. A brand's own link shortener is not a mismatch. c.gle is Google's.
    SpamHeuristics::Message m;
    m.head = QByteArray("Received: from mx.google.com (mx.google.com [198.51.100.1])"
                        " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                        "From: Google <googlebase-noreply@google.com>\r\n"
                        "To: You <you@example.org>\r\n"
                        "Subject: Merchant Center update\r\n"
                        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                        "Message-ID: <v3@google.com>\r\n");
    m.html = QStringLiteral("<a href=\"https://c.gle/abc123\">www.google.com</a>");
    const SpamHeuristics::Score alias = SpamHeuristics::score(m, {});
    check(!fired(alias, "link-text-mismatch") && !fired(alias, "url-shortener"),
          QStringLiteral("a brand's own shortener is not a mismatch (%1)").arg(hitList(alias)));

    // But a lookalike still is: the family test must not become a way through.
    // The second form is the one that matters — a brand's domain used as a
    // *prefix* of somebody else's must never read as belonging to the brand.
    m.html = QStringLiteral("<a href=\"https://google.com.evil-x1z.test/a\">www.google.com</a>");
    const SpamHeuristics::Score prefixed = SpamHeuristics::score(m, {});
    check(fired(prefixed, "link-text-mismatch"),
          QStringLiteral("a brand name as someone else's prefix still fires (%1)")
              .arg(hitList(prefixed)));

    m.html = QStringLiteral("<a href=\"https://g00gle-login.test/abc\">www.google.com</a>");
    const SpamHeuristics::Score fake = SpamHeuristics::score(m, {});
    check(fired(fake, "link-text-mismatch"),
          QStringLiteral("a genuine link mismatch still fires (%1)").arg(hitList(fake)));

    // 3b. The general form of the same problem, and the reason the alias table
    //     cannot be the mechanism: a brand's asset and CDN domains are not
    //     enumerable, and there will always be one more. Nothing here depends
    //     on stripecdn.com being listed — it is exempt because the *sender* is
    //     Stripe, and a brand cannot impersonate itself.
    m.head = QByteArray("Received: from mx.stripe.com (mx.stripe.com [198.51.100.1])"
                        " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                        "From: Stripe <receipts@stripe.com>\r\n"
                        "To: You <you@example.org>\r\n"
                        "Subject: Your receipt\r\n"
                        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                        "Message-ID: <v5@stripe.com>\r\n");
    m.html = QStringLiteral("<a href=\"https://stripe.assets.stripecdn.test/x\">View</a>");
    const SpamHeuristics::Score ownCdn = SpamHeuristics::score(m, {});
    check(ownCdn.total == 0,
          QStringLiteral("a brand's own unlisted CDN is not impersonation (%1)")
              .arg(hitList(ownCdn)));

    // The exemption is conditioned on authentication: a forged From claiming to
    // be the brand must not be able to buy silence with the claim itself.
    SpamHeuristics::Context forgedBrand;
    forgedBrand.authFailed = true;
    const SpamHeuristics::Score forgedCdn = SpamHeuristics::score(m, forgedBrand);
    check(forgedCdn.verdict == SpamHeuristics::Verdict::Spam,
          QStringLiteral("the same mail with a failed authentication is marked (total %1: %2)")
              .arg(forgedCdn.total)
              .arg(hitList(forgedCdn)));

    // 4. Mailing platforms mint Message-IDs on their own domain while the
    //    sending domain authorises them in SPF. The rule that read that as a
    //    discrepancy fired on 61% of a real mailbox and is gone; this pins it.
    const SpamHeuristics::Score espMsgid = SpamHeuristics::score(
        headOnly("Received: from mail.mandrillapp.com (mail.mandrillapp.com [198.51.100.10])"
                 " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Petition <info@chcemvediet.sk>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Your request was answered\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <v4@mandrillapp.com>\r\n"),
        {});
    check(!fired(espMsgid, "msgid-domain-mismatch"),
          QStringLiteral("an ESP-minted Message-ID is not scored (%1)").arg(hitList(espMsgid)));
    check(espMsgid.total < SpamHeuristics::UnsureThreshold,
          QStringLiteral("ordinary platform-sent mail scores %1, under %2")
              .arg(espMsgid.total)
              .arg(SpamHeuristics::UnsureThreshold));
}

/// Ordinary bulk mail through a mailing platform: a different envelope domain,
/// a different Reply-To, a Message-ID minted by the platform. Three separate
/// rules used to read that as three findings and reach the unsure threshold on
/// it; two of them are now gone and the third cannot get there alone.
void testPlatformMailStaysQuiet()
{
    const SpamHeuristics::Score s = SpamHeuristics::score(
        headOnly("Return-Path: <bounce@esp.test>\r\n"
                 "Received: from mta.esp.test (mta.esp.test [198.51.100.11])"
                 " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Shop <news@shop.test>\r\n"
                 "Reply-To: replies@esp.test\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: This week's offers\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <a1@esp.test>\r\n"),
        {});
    check(s.total < SpamHeuristics::UnsureThreshold,
          QStringLiteral("bulk mail through an ESP scores %1, under %2 (%3)")
              .arg(s.total)
              .arg(SpamHeuristics::UnsureThreshold)
              .arg(hitList(s)));
}

/// The junk folder, which is a fact rather than a guess and outranks every
/// other rule here — including Rule 0, whose whole purpose is to protect mail
/// from people the user writes to. If the user threw a known contact's message
/// in the bin, the filter's opinion about that contact is not the relevant one.
void testJunkFolderIsDecisive()
{
    SpamHeuristics::Context junk;
    junk.inJunkFolder = true;
    const char *ordinary =
        "Received: from mail.sender.test (mail.sender.test [198.51.100.7])"
        " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Alice Sender <alice@sender.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: Lunch on Thursday\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <j1@sender.test>\r\n";

    const SpamHeuristics::Score s = SpamHeuristics::score(headOnly(ordinary), junk);
    check(fired(s, "junk-folder") && s.verdict == SpamHeuristics::Verdict::Spam,
          QStringLiteral("mail in the junk folder is marked (total %1)").arg(s.total));

    // Rule 0 must not exempt it: the user's own filing beats the allowlist.
    SpamHeuristics::Context knownInJunk = junk;
    knownInJunk.knownCorrespondent = true;
    const SpamHeuristics::Score known = SpamHeuristics::score(headOnly(ordinary), knownInJunk);
    check(!known.exempt && known.verdict == SpamHeuristics::Verdict::Spam,
          QStringLiteral("a known contact moved to junk is still marked (total %1, exempt %2)")
              .arg(known.total)
              .arg(known.exempt));

    // Nor may any accumulation of ham credit pull it back out.
    SpamHeuristics::Context hammy = junk;
    hammy.crypto = 2;          // OpenPGP signed, -50
    hammy.authPassed = true;
    hammy.inReplyToKnown = true; // -30
    hammy.seenFromOrg = 100;
    hammy.daysKnownOrg = 400;  // familiar, so auth-pass is worth -25
    const SpamHeuristics::Score credited = SpamHeuristics::score(headOnly(ordinary), hammy);
    check(credited.verdict == SpamHeuristics::Verdict::Spam,
          QStringLiteral("no amount of ham credit unmarks junk (total %1: %2)")
              .arg(credited.total)
              .arg(hitList(credited)));

    // And the tooltip still explains the rest, not just the folder.
    SpamHeuristics::Message m;
    m.head = QByteArray(ordinary);
    m.attachmentNames = {QStringLiteral("invoice.pdf.exe")};
    const SpamHeuristics::Score withMore = SpamHeuristics::score(m, junk);
    check(fired(withMore, "junk-folder") && fired(withMore, "attachment-double-extension"),
          QStringLiteral("scoring continues past the junk rule (%1)").arg(hitList(withMore)));

    // The same message outside the junk folder is untouched by any of this.
    const SpamHeuristics::Score elsewhere = SpamHeuristics::score(headOnly(ordinary), {});
    check(!fired(elsewhere, "junk-folder") && elsewhere.total == 0,
          QStringLiteral("the rule is about the folder, nothing else (%1)")
              .arg(hitList(elsewhere)));
}

/// The scorer reads the raw head, where any non-ASCII header travels as an
/// RFC 2047 encoded-word — so every rule that judges a name or a subject has
/// to be shown the decoded text or it is judging base64. Measured before the
/// fix, subject-confusable had never fired on a real junk folder: the mail it
/// exists for was invisible to it.
void testEncodedHeaders()
{
    // "РayРal alert" — Cyrillic Р in a Latin word, base64-encoded as mail
    // software really sends it. The homoglyph rule must see through the coat.
    const SpamHeuristics::Score subj = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Sender <s@x1z.test>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: =?UTF-8?B?0KBhedCgYWwgYWxlcnQ=?=\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <w1@x1z.test>\r\n"),
        {});
    check(fired(subj, "subject-confusable"),
          QStringLiteral("an encoded-word homoglyph subject is seen (%1)").arg(hitList(subj)));

    // "PayPal" as an encoded display name from a domain that is not PayPal's.
    const SpamHeuristics::Score name = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: =?UTF-8?B?UGF5UGFs?= <billing@x1z.test>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Account notice\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <w2@x1z.test>\r\n"),
        {});
    check(fired(name, "brand-impersonation"),
          QStringLiteral("an encoded-word brand name is seen (%1)").arg(hitList(name)));

    // charset-mismatch, both directions. The raw form of an encoded word is
    // ASCII by construction, so before the fix the "decodes to plain ASCII"
    // test was vacuously true and the rule fired on genuinely Chinese mail.
    const char *gbAscii =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Sender <s@x1z.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: =?gb2312?B?SGVsbG8gZnJpZW5k?=\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <w3@x1z.test>\r\n";
    check(fired(SpamHeuristics::score(headOnly(gbAscii), {}), "charset-mismatch"),
          QStringLiteral("gb2312 wrapping plain ASCII still fires"));
    const char *gbReal =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Sender <s@x1z.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: =?gb2312?B?xOO6ww==?=\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <w4@x1z.test>\r\n";
    const SpamHeuristics::Score real = SpamHeuristics::score(headOnly(gbReal), {});
    check(!fired(real, "charset-mismatch"),
          QStringLiteral("a genuinely Chinese gb2312 subject does not (%1)").arg(hitList(real)));
    check(!fired(real, "subject-confusable"),
          QStringLiteral("...and its mojibake does not read as a homoglyph (%1)")
              .arg(hitList(real)));

    // Two encoded words joined across transport whitespace stay one word —
    // splitting mid-word is how long names travel, and a space inserted there
    // would hide the very word the rules examine.
    const SpamHeuristics::Score split = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: =?UTF-8?B?UGF5?= =?UTF-8?B?UGFsIHNlcnZpY2U=?= <b@x1z.test>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Account notice\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <w5@x1z.test>\r\n"),
        {});
    check(fired(split, "brand-impersonation"),
          QStringLiteral("a name split across two encoded words is rejoined (%1)")
              .arg(hitList(split)));
}

/// Click trackers: in list mail, "the text names one domain, the href another"
/// is how the mail was built, not a deception. Measured over a real inbox this
/// was 82% of all residual noise, against zero list-mail catches in junk.
void testListMailLinksAreExempt()
{
    SpamHeuristics::Message m;
    m.head = QByteArray(
        "Received: from mta.esp.test (mta.esp.test [198.51.100.4]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: News <news@shop.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: This week\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "List-Unsubscribe: <https://esp.test/u/1>\r\n"
        "Message-ID: <l1@esp.test>\r\n");
    m.html = QStringLiteral(
        "<a href=\"https://tr.esp-track.test/c/9\">www.gov.uk</a>"
        "<a href=\"https://facebook.assets.esp-track.test/i\">pic</a>");
    const SpamHeuristics::Score list = SpamHeuristics::score(m, {});
    check(!fired(list, "link-text-mismatch") && !fired(list, "url-brand-subdomain"),
          QStringLiteral("tracked links in list mail say nothing (%1)").arg(hitList(list)));

    // The same message without the list header is still judged.
    m.head = QByteArray(
        "Received: from mta.esp.test (mta.esp.test [198.51.100.4]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: News <news@shop.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: This week\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <l2@esp.test>\r\n");
    const SpamHeuristics::Score bare = SpamHeuristics::score(m, {});
    check(fired(bare, "link-text-mismatch"),
          QStringLiteral("outside list mail the mismatch still fires (%1)").arg(hitList(bare)));

    // What the exemption must NOT cover: fake list headers buy nothing the
    // message was actually caught by.
    m.html = QStringLiteral("<form><input type=\"password\"></form>"
                            "<a href=\"https://paypal.com@evil.test/\">x</a>");
    m.head = QByteArray(
        "Received: from a.test (a.test [198.51.100.4]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: X <x@evil.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: verify\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "List-Unsubscribe: <https://evil.test/u>\r\n"
        "Message-ID: <l3@evil.test>\r\n");
    const SpamHeuristics::Score phish = SpamHeuristics::score(m, {});
    check(fired(phish, "html-password-form") && fired(phish, "url-credential-trick"),
          QStringLiteral("fake list headers do not exempt the real catches (%1)")
              .arg(hitList(phish)));

    // P2, pinned: Stripe's CDN belongs to Stripe even when the sender is a
    // customer of Stripe's (an invoice mail), and Microsoft's office domains
    // belong to the outlook/microsoft names.
    m.head = QByteArray(
        "Received: from mail.vendor.test (mail.vendor.test [198.51.100.5])"
        " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Billing <invoice@vendor.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: Your receipt\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <l4@vendor.test>\r\n");
    m.html = QStringLiteral(
        "<a href=\"https://stripe.assets.stripecdn.com/x\">receipt</a>"
        "<a href=\"https://outlook.cdn.office.net/y\">calendar</a>");
    const SpamHeuristics::Score vendors = SpamHeuristics::score(m, {});
    check(!fired(vendors, "url-brand-subdomain"),
          QStringLiteral("brand asset domains are the brand's (%1)").arg(hitList(vendors)));
}

// --- the body rules ------------------------------------------------------

void testBodyRules()
{
    SpamHeuristics::Message m;
    m.head = QByteArray(plainHead());
    m.html = QStringLiteral(
        "<html><body><p>Please sign in to keep your account:</p>"
        "<form action=\"https://harvest.test/p\">"
        "<input type=\"password\" name=\"p\"></form></body></html>");
    const SpamHeuristics::Score pw = SpamHeuristics::score(m, {});
    check(fired(pw, "html-password-form"),
          QStringLiteral("html-password-form fires (%1)").arg(hitList(pw)));

    m.html = QStringLiteral("<a href=\"https://paypal.com@evil.test/login\">Sign in</a>");
    const SpamHeuristics::Score cred = SpamHeuristics::score(m, {});
    check(fired(cred, "url-credential-trick"),
          QStringLiteral("url-credential-trick fires (%1)").arg(hitList(cred)));

    m.html = QStringLiteral("<a href=\"https://203.0.113.44/login\">Sign in</a>");
    const SpamHeuristics::Score ip = SpamHeuristics::score(m, {});
    check(fired(ip, "url-ip-host"), QStringLiteral("url-ip-host fires (%1)").arg(hitList(ip)));

    m.html = QStringLiteral(
        "<a href=\"https://paypal.com.account-check.test/verify\">Verify</a>");
    const SpamHeuristics::Score sub = SpamHeuristics::score(m, {});
    check(fired(sub, "url-brand-subdomain"),
          QStringLiteral("url-brand-subdomain fires (%1)").arg(hitList(sub)));

    m.html = QStringLiteral("<a href=\"https://bit.ly/3xYzQ\">Read more</a>");
    const SpamHeuristics::Score sh = SpamHeuristics::score(m, {});
    check(fired(sh, "url-shortener"), QStringLiteral("url-shortener fires (%1)").arg(hitList(sh)));

    m.html.clear();
    m.attachmentNames = {QStringLiteral("Invoice_2026.html")};
    const QString wasText = m.text;
    const SpamHeuristics::Score att = SpamHeuristics::score(m, {});
    check(fired(att, "html-attachment"),
          QStringLiteral("html-attachment fires (%1)").arg(hitList(att)));
    m.attachmentNames.clear();
    m.text = wasText;

    m.text = QStringLiteral("  ");
    m.html = QStringLiteral("<html><body>") + QString(600, QLatin1Char('x'))
        + QStringLiteral("</body></html>");
    const SpamHeuristics::Score div = SpamHeuristics::score(m, {});
    check(fired(div, "text-html-divergence"),
          QStringLiteral("text-html-divergence fires (%1)").arg(hitList(div)));
}

/// The link group must not let a message accumulate its way to a verdict: a
/// newsletter with hundreds of links is not hundreds of times as suspicious.
void testLinkGroupIsCapped()
{
    SpamHeuristics::Message m;
    m.head = QByteArray(plainHead());
    QString html;
    for (int i = 0; i < 40; ++i) {
        html += QStringLiteral("<a href=\"https://paypal.com@evil%1.test/\">go</a>"
                               "<a href=\"https://203.0.113.%1/\">go</a>"
                               "<a href=\"https://bit.ly/x%1\">go</a>")
                    .arg(i);
    }
    m.html = html;
    const SpamHeuristics::Score s = SpamHeuristics::score(m, {});
    int linkTotal = 0;
    for (const SpamHeuristics::Hit &h : s.hits) {
        if (h.id.startsWith(QLatin1String("url-")) || h.id == QLatin1String("link-text-mismatch"))
            linkTotal += h.weight;
    }
    check(linkTotal <= 40,
          QStringLiteral("link group capped at 40, got %1 (%2)").arg(linkTotal).arg(hitList(s)));
}

// --- ham -----------------------------------------------------------------

/// The part of this file that must never be relaxed. Each of these is mail a
/// user wants, written the way the software that sends it really writes it.
void testHamStaysUnmarked()
{
    SpamHeuristics::Context ctx;
    ctx.ownAddresses = {QStringLiteral("you@example.org")};
    ctx.authPassed = true;

    struct Case {
        const char *what;
        const char *head;
    };
    const Case cases[] = {
        {"a marketing newsletter with a list header",
         "Received: from mta.bulk-sender.test (mta.bulk-sender.test [198.51.100.4])"
         " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
         "Return-Path: <bounce-991@mta.bulk-sender.test>\r\n"
         "From: \"Shop News\" <news@shop.test>\r\n"
         "To: you@example.org\r\n"
         "Subject: Your August picks are here\r\n"
         "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
         "List-Id: <news.shop.test>\r\n"
         "List-Unsubscribe: <https://shop.test/u/991>\r\n"
         "Message-ID: <n1@shop.test>\r\n"},
        {"a code-hosting notification",
         "Received: from out.forge.test (out.forge.test [198.51.100.5])"
         " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
         "Return-Path: <notifications@forge.test>\r\n"
         "From: \"Dana (via Forge)\" <notifications@forge.test>\r\n"
         "Reply-To: reply+abc@forge.test\r\n"
         "To: you@example.org\r\n"
         "Subject: Re: [proj/repo] Fix the parser (#412)\r\n"
         "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
         "List-Id: <proj.repo.forge.test>\r\n"
         "List-Unsubscribe: <https://forge.test/u>\r\n"
         "Message-ID: <n2@forge.test>\r\n"},
        {"a bank statement notice to a role address",
         "Received: from mx1.bank.test (mx1.bank.test [198.51.100.6])"
         " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
         "Return-Path: <noreply@bank.test>\r\n"
         "From: \"Bank Alerts\" <alerts@bank.test>\r\n"
         "To: you@example.org\r\n"
         "Subject: Your statement is ready\r\n"
         "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
         "Message-ID: <n3@bank.test>\r\n"},
        {"a mailing-list post",
         "Received: from lists.project.test (lists.project.test [198.51.100.8])"
         " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
         "Return-Path: <devel-bounces@lists.project.test>\r\n"
         "From: Contributor <contributor@personal.test>\r\n"
         "To: devel@lists.project.test\r\n"
         "Subject: [PATCH] tidy up the parser\r\n"
         "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
         "List-Id: <devel.lists.project.test>\r\n"
         "List-Unsubscribe: <https://lists.project.test/u>\r\n"
         "Message-ID: <n4@personal.test>\r\n"},
        {"a plain reply from a colleague",
         "Received: from mail.partner.test (mail.partner.test [198.51.100.3])"
         " by mx.example.org; Fri, 14 Aug 2026 09:00:01 +0000\r\n"
         "Return-Path: <colleague@partner.test>\r\n"
         "From: Colleague <colleague@partner.test>\r\n"
         "To: You <you@example.org>\r\n"
         "Subject: Re: Thursday\r\n"
         "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
         "Message-ID: <n5@partner.test>\r\n"},
    };

    // Twice: once with a passing authentication, and once with no verdict at
    // all. The second is the harder and the more common case — plenty of
    // servers stamp no Authentication-Results the client is willing to trust,
    // and mail through them must not be marked for the lack of it.
    SpamHeuristics::Context unauth = ctx;
    unauth.authPassed = false;
    for (const Case &c : cases) {
        for (const SpamHeuristics::Context &use : {ctx, unauth}) {
            const SpamHeuristics::Score s = SpamHeuristics::score(headOnly(c.head), use);
            check(s.total < SpamHeuristics::UnsureThreshold,
                  QStringLiteral("%1%2 scores %3, under %4 (%5)")
                      .arg(QLatin1String(c.what),
                           use.authPassed ? QString() : QStringLiteral(", unauthenticated"))
                      .arg(s.total)
                      .arg(SpamHeuristics::UnsureThreshold)
                      .arg(hitList(s)));
        }
    }

    // The newsletter again, this time with the body it really carries: a
    // hidden preheader, an image, and forty tracked links. Every one of those
    // is a textbook spam signal and none of them may cost it anything.
    SpamHeuristics::Message m;
    m.head = QByteArray(cases[0].head);
    m.text = QStringLiteral("Your August picks are here. View online: https://shop.test/v/991");
    m.html = QStringLiteral(
        "<div style=\"display:none;font-size:0\">Twenty new arrivals inside</div>"
        "<img src=\"https://cdn.shop.test/hero.jpg\">");
    for (int i = 0; i < 40; ++i) {
        m.html += QStringLiteral("<a href=\"https://click.shop.test/t/%1\">Item %1</a>"
                                 "<p>A short description of item %1 for the reader.</p>")
                      .arg(i);
    }
    const SpamHeuristics::Score full = SpamHeuristics::score(m, ctx);
    check(full.total < SpamHeuristics::UnsureThreshold,
          QStringLiteral("the newsletter with its body scores %1, under %2 (%3)")
              .arg(full.total)
              .arg(SpamHeuristics::UnsureThreshold)
              .arg(hitList(full)));
}

/// Rule 0 and the exemption path, which no other check here exercises.
void testKnownCorrespondentExemption()
{
    SpamHeuristics::Context ctx;
    ctx.knownCorrespondent = true;
    const SpamHeuristics::Score s = SpamHeuristics::score(
        headOnly("From: Alice <alice@sender.test>\r\nSubject: hi\r\n"), ctx);
    check(s.exempt && s.verdict == SpamHeuristics::Verdict::Ham,
          QStringLiteral("a known correspondent is exempt (%1)").arg(s.exemptReason));

    // Unless the message failed authentication while claiming to be them.
    ctx.authFailed = true;
    const SpamHeuristics::Score forged = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Alice <alice@sender.test>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: urgent payment\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <k1@sender.test>\r\n"),
        ctx);
    check(!forged.exempt && forged.verdict == SpamHeuristics::Verdict::Spam,
          QStringLiteral("a spoofed known contact is marked (total %1: %2)")
              .arg(forged.total)
              .arg(hitList(forged)));
}

/// The tooltip's arithmetic. Every hit gets a row, the total gets a row, and
/// the number on the last row is the one the verdict was made from — a tooltip
/// that does not add up is worse than none, because it invites the reader to
/// trust a filter that is visibly confused.
void testExplanationRows()
{
    const SpamHeuristics::Score s = SpamHeuristics::score(
        headOnly("From: \"PayPal Service\" <billing@x1z.test>\r\n"
                 "Subject: Account limited\r\n"),
        {});
    const QStringList lines = s.explanation().split(QLatin1Char('\n'));
    check(lines.size() == s.hits.size() + 2,
          QStringLiteral("explanation has %1 lines for %2 hits (wanted %3)")
              .arg(lines.size())
              .arg(s.hits.size())
              .arg(s.hits.size() + 2));
    check(lines.constLast().contains(QString::number(s.total)),
          QStringLiteral("the last row carries the total %1: \"%2\"")
              .arg(s.total)
              .arg(lines.constLast()));
    check(SpamHeuristics::Score{}.explanation().isEmpty(),
          QStringLiteral("a score with nothing to explain explains nothing"));

    // Printed rather than asserted: the exact wording is not a contract, but
    // whoever changes a weight should see the tooltip they are changing.
    out << "\n--- the tooltip, as the message list shows it ---\n"
        << "Marked as spam because:\n"
        << s.explanation() << "\n\n";
}

} // namespace

void testUnfamiliarTld()
{
    // A mailbox that writes to .sk and .com and nowhere else.
    SpamHeuristics::Context ctx;
    ctx.familiarTlds = {QStringLiteral("sk"), QStringLiteral("com")};
    ctx.sentTldSample = 400;

    const char *fromHr =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Marko <marko@shop.hr>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: Offer\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <u1@shop.hr>\r\n";
    const SpamHeuristics::Score foreign = SpamHeuristics::score(headOnly(fromHr), ctx);
    check(fired(foreign, "unfamiliar-tld"),
          QStringLiteral("unfamiliar-tld fires on a TLD you never write to (%1)")
              .arg(hitList(foreign)));
    // And on its own it decides nothing: not marked, not even shown as unsure.
    check(foreign.total < SpamHeuristics::UnsureThreshold,
          QStringLiteral("unfamiliar-tld cannot mark a message by itself (total %1)")
              .arg(foreign.total));

    // A TLD the user does write to says nothing at all.
    const SpamHeuristics::Score home = SpamHeuristics::score(
        headOnly("Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
                 " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
                 "From: Jano <jano@firma.sk>\r\n"
                 "To: You <you@example.org>\r\n"
                 "Subject: Offer\r\n"
                 "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
                 "Message-ID: <u2@firma.sk>\r\n"),
        ctx);
    check(!fired(home, "unfamiliar-tld"),
          QStringLiteral("unfamiliar-tld silent on a TLD you write to (%1)").arg(hitList(home)));

    // Too little sent mail to have a profile: the rule disables itself rather
    // than describe a fresh install's first week as the user's habits.
    SpamHeuristics::Context thin = ctx;
    thin.sentTldSample = 3;
    check(!fired(SpamHeuristics::score(headOnly(fromHr), thin), "unfamiliar-tld"),
          QStringLiteral("unfamiliar-tld silent without enough sent mail behind it"));

    // No profile at all — the caller filled nothing in — is the same.
    check(!fired(SpamHeuristics::score(headOnly(fromHr), {}), "unfamiliar-tld"),
          QStringLiteral("unfamiliar-tld silent with no profile"));

    // A domain with a real history here outranks the country it is in: the
    // familiarity rule has already answered the same question with evidence.
    SpamHeuristics::Context familiar = ctx;
    familiar.seenFromOrg = 40;
    familiar.daysKnownOrg = 200;
    const SpamHeuristics::Score old = SpamHeuristics::score(headOnly(fromHr), familiar);
    check(!fired(old, "unfamiliar-tld"),
          QStringLiteral("unfamiliar-tld silent on a domain you hear from (%1)")
              .arg(hitList(old)));

    // Rule 0 still comes first: someone the user has written to is not judged
    // on which country they are in.
    SpamHeuristics::Context correspondent = ctx;
    correspondent.knownCorrespondent = true;
    check(SpamHeuristics::score(headOnly(fromHr), correspondent).exempt,
          QStringLiteral("a known correspondent in an unusual TLD stays exempt"));
}

/// The weights are defaults, not constants: spamrules/<id> overrides one, and
/// 0 removes the rule from the score and from the tooltip alike.
void testRuleWeightOverrides()
{
    const char *shouting =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Shop <news@shop.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: BUY NOW ONLY TODAY\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <w1@shop.test>\r\n";
    AdvancedConfig &cfg = AdvancedConfig::instance();

    const SpamHeuristics::Score stock = SpamHeuristics::score(headOnly(shouting), {});
    check(fired(stock, "subject-shouting") && stock.total == 6,
          QStringLiteral("subject-shouting is worth its schema default (%1)").arg(stock.total));

    check(cfg.save(QStringLiteral("[spamrules]\nsubject-shouting = 40\n")).isEmpty(),
          QStringLiteral("a rule weight saves"));
    const SpamHeuristics::Score raised = SpamHeuristics::score(headOnly(shouting), {});
    check(raised.total == 40,
          QStringLiteral("the configured weight is the one scored (%1)").arg(raised.total));

    check(cfg.save(QStringLiteral("[spamrules]\nsubject-shouting = 0\n")).isEmpty(),
          QStringLiteral("a rule turned off saves"));
    const SpamHeuristics::Score off = SpamHeuristics::score(headOnly(shouting), {});
    check(!fired(off, "subject-shouting") && off.total == 0,
          QStringLiteral("a rule set to 0 leaves the tooltip as well as the score (%1)")
              .arg(hitList(off)));

    // Back to stock, so nothing below inherits an edited weight.
    check(cfg.save(QString()).isEmpty(), QStringLiteral("the overrides clear again"));
    check(SpamHeuristics::score(headOnly(shouting), {}).total == 6,
          QStringLiteral("clearing the file restores the schema defaults"));
}

/// The hacked-website rules adapted from kawaiipantsu/spamassassin-rules:
/// script-origin headers, an ancient PHPMailer, and the random-token .php link.
void testHackedPhpShapes()
{
    const char *base =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Shop <info@shop.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: Order\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <p1@shop.test>\r\n";

    const SpamHeuristics::Score evald = SpamHeuristics::score(
        headOnly(QByteArray(base)
                 + "X-PHP-Originating-Script: 33:eval()'d code\r\n"),
        {});
    check(fired(evald, "php-eval-source"),
          QStringLiteral("php-eval-source fires on eval()'d code (%1)").arg(hitList(evald)));

    const SpamHeuristics::Score wp = SpamHeuristics::score(
        headOnly(QByteArray(base)
                 + "X-PHP-Originating-Script: 1001:mailer.php\r\n"
                 + "X-Source-Dir: victim.test/public_html/wp-content/uploads\r\n"),
        {});
    check(fired(wp, "php-cms-origin") && !fired(wp, "php-script-origin"),
          QStringLiteral("a script in wp-content is the CMS rule, not the plain one "
                         "(%1)").arg(hitList(wp)));

    // Joomla spells its compromise differently: the path arrives in
    // X-Source-Args, and no X-PHP-Originating-Script need be present.
    const SpamHeuristics::Score joomla = SpamHeuristics::score(
        headOnly(QByteArray(base)
                 + "X-Source-Args: /usr/bin/php /home/victim/public_html/"
                   "components/com_contact/helpers/files.php\r\n"),
        {});
    check(fired(joomla, "php-cms-origin"),
          QStringLiteral("a Joomla component path is the CMS rule too (%1)")
              .arg(hitList(joomla)));

    const SpamHeuristics::Score plain = SpamHeuristics::score(
        headOnly(QByteArray(base) + "X-PHP-Originating-Script: 12:order.php\r\n"), {});
    check(fired(plain, "php-script-origin"),
          QStringLiteral("a bare PHP script origin fires the low rule (%1)")
              .arg(hitList(plain)));
    // The whole point of the low weight: a shop's PHP-sent receipt must stay ham.
    check(plain.total < SpamHeuristics::UnsureThreshold,
          QStringLiteral("a PHP-sent order mail alone stays unmarked (total %1)")
              .arg(plain.total));

    const SpamHeuristics::Score relic = SpamHeuristics::score(
        headOnly(QByteArray(base) + "X-Mailer: PHPMailer 5.2.9 (https://example.test)\r\n"),
        {});
    check(fired(relic, "vulnerable-mailer"),
          QStringLiteral("vulnerable-mailer fires on PHPMailer 5.x (%1)").arg(hitList(relic)));
    check(!fired(SpamHeuristics::score(
                     headOnly(QByteArray(base) + "X-Mailer: PHPMailer 6.9.1\r\n"), {}),
                 "vulnerable-mailer"),
          QStringLiteral("a current PHPMailer does not"));

    // The link: a .php endpoint fed three long letter-and-digit tokens.
    SpamHeuristics::Message hacked;
    hacked.head = QByteArray(base);
    hacked.html = QStringLiteral(
        "<p><a href=\"http://victim.test/wp/go.php?u=a1B2c3D4e5F6&c=9zY8xW7vU6t5&t=Qq1Ww2Ee3Rr4\">"
        "offer</a></p>");
    const SpamHeuristics::Score badLink = SpamHeuristics::score(hacked, {});
    check(fired(badLink, "hacked-php-url"),
          QStringLiteral("hacked-php-url fires on random-token .php links (%1)")
              .arg(hitList(badLink)));

    // Words are not tokens: an ordinary PHP shop link stays silent.
    SpamHeuristics::Message shop = hacked;
    shop.html = QStringLiteral(
        "<p><a href=\"http://shop.test/cart.php?utm_source=newsletter&utm_medium=email"
        "&utm_campaign=augustsale\">cart</a></p>");
    check(!fired(SpamHeuristics::score(shop, {}), "hacked-php-url"),
          QStringLiteral("hacked-php-url silent on word-valued parameters"));

    // And list mail is exempt wholesale, like the other link rules: click
    // trackers mint exactly these tokens.
    SpamHeuristics::Message list = hacked;
    list.head = QByteArray(base) + "List-Id: <deals.shop.test>\r\n"
        + "List-Unsubscribe: <mailto:leave@shop.test>\r\n";
    check(!fired(SpamHeuristics::score(list, {}), "hacked-php-url"),
          QStringLiteral("hacked-php-url silent in list mail"));

    // A compromised webroot mailing from the ACME challenge directory.
    const SpamHeuristics::Score acme = SpamHeuristics::score(
        headOnly(QByteArray(base)
                 + "X-Source-Args: /usr/bin/php /home/victim/public_html/"
                   ".well-known/pki-validation/m.php\r\n"),
        {});
    check(fired(acme, "php-cms-origin"),
          QStringLiteral("a script under /.well-known/ is a compromised webroot (%1)")
              .arg(hitList(acme)));

    // A link into WordPress's code tree, where no page for a reader lives.
    SpamHeuristics::Message wpLink;
    wpLink.head = QByteArray(base);
    wpLink.html = QStringLiteral(
        "<p><a href=\"http://victim.test/wp-includes/js/tmp/offer.html\">see</a></p>");
    check(fired(SpamHeuristics::score(wpLink, {}), "hacked-wordpress-link"),
          QStringLiteral("hacked-wordpress-link fires on a wp-includes link"));

    SpamHeuristics::Message wpPlugin = wpLink;
    wpPlugin.html = QStringLiteral(
        "<p><a href=\"http://victim.test/wp-content/plugins/seo/landing.php\">go</a></p>");
    check(fired(SpamHeuristics::score(wpPlugin, {}), "hacked-wordpress-link"),
          QStringLiteral("hacked-wordpress-link fires on a script under wp-content"));

    // The everyday case that must stay silent: a newsletter's image hosted
    // under wp-content/uploads.
    SpamHeuristics::Message wpMedia = wpLink;
    wpMedia.html = QStringLiteral(
        "<p><img src=\"http://shop.test/wp-content/uploads/2026/08/banner.jpg\"></p>");
    check(!fired(SpamHeuristics::score(wpMedia, {}), "hacked-wordpress-link"),
          QStringLiteral("hacked-wordpress-link silent on wp-content media"));
}

/// The Authentication-Results parsing the client feeds the scorer from. Lives
/// here since the compauth work moved it into spamheuristics.cpp — the ARC
/// exemption spent months dead because the old parser in mailclient.cpp never
/// extracted arc= and no test could see it.
void testAuthResultParsing()
{
    using namespace SpamHeuristics;

    // The M365 spoof shape: explicit methods inconclusive, compauth=fail.
    const QString spoofed = QStringLiteral(
        "mx.microsoft.com 1; spf=none (sender IP is 203.0.113.9)"
        " smtp.mailfrom=victim.test; dkim=none; dmarc=none action=none"
        " header.from=victim.test; compauth=fail reason=601");
    check(authResultsFailed(spoofed),
          QStringLiteral("compauth=fail counts as an authentication failure"));
    check(!authResultsPassed(spoofed),
          QStringLiteral("...and certainly not as a pass"));

    const QString implicit = QStringLiteral(
        "mx.microsoft.com 1; spf=pass smtp.mailfrom=shop.test; dkim=none;"
        " dmarc=bestguesspass; compauth=pass reason=109");
    check(authResultsPassed(implicit) && !authResultsFailed(implicit),
          QStringLiteral("compauth=pass counts as a pass"));

    // The mailing-list shape: dkim broke in transit, arc carries the verdict.
    const QString relayed = QStringLiteral(
        "mx.example.org; spf=fail smtp.mailfrom=list.test; dkim=fail"
        " header.d=member.test; arc=pass (as.1.list.test=pass)");
    check(authResultsFailed(relayed),
          QStringLiteral("the relay's dkim failure is still reported"));
    check(authResultsArcPassed(relayed),
          QStringLiteral("...and arc=pass is extracted alongside it (the bug this "
                         "test exists for)"));
    check(!authResultsPassed(relayed),
          QStringLiteral("arc=pass alone is not an authentication pass"));

    // A broken chain accuses nobody.
    check(!authResultsFailed(QStringLiteral("mx.example.org; arc=fail; spf=pass")),
          QStringLiteral("arc=fail is not an authentication failure"));

    // Sender-supplied text must not smuggle a verdict past the parser.
    const QString smuggled = QStringLiteral(
        "mx.example.org; spf=fail smtp.mailfrom=\"x; dkim=pass\" (comment; "
        "compauth=pass); dmarc=fail");
    check(authResultsFailed(smuggled) && !authResultsPassed(smuggled),
          QStringLiteral("verdicts inside quotes and comments are ignored"));

    // Per-method trust switches in advanced.conf. The badge in the viewer
    // filters by the same authMethodTrusted(), so distrusted is invisible too.
    AdvancedConfig &cfg = AdvancedConfig::instance();
    check(cfg.save(QStringLiteral("[spam]\ntrustCompauth = 0\n")).isEmpty(),
          QStringLiteral("trustCompauth saves"));
    const QString compauthOnlyPass = QStringLiteral(
        "mx.microsoft.com 1; spf=none; dkim=none; dmarc=none;"
        " compauth=pass reason=109");
    check(!authResultsFailed(spoofed) && !authResultsPassed(compauthOnlyPass),
          QStringLiteral("with trustCompauth off, compauth says nothing either way"));
    check(authResultsFailed(relayed),
          QStringLiteral("...while a dkim failure still counts"));

    check(cfg.save(QStringLiteral("[spam]\ntrustSpf = 0\n")).isEmpty(),
          QStringLiteral("trustSpf saves"));
    check(!authResultsFailed(QStringLiteral("mx.example.org; spf=fail; dkim=none")),
          QStringLiteral("with trustSpf off an SPF failure says nothing"));
    check(authResultsFailed(QStringLiteral("mx.example.org; spf=fail; dkim=fail")),
          QStringLiteral("...while DKIM keeps counting"));
    check(!authMethodTrusted(QStringLiteral("spf"))
              && authMethodTrusted(QStringLiteral("dkim")),
          QStringLiteral("the badge filter sees the same switches"));

    check(cfg.save(QStringLiteral("[spam]\ntrustArc = 0\n")).isEmpty(),
          QStringLiteral("trustArc saves"));
    check(!authResultsArcPassed(relayed),
          QStringLiteral("with trustArc off, arc=pass excuses nothing"));
    check(cfg.save(QString()).isEmpty(), QStringLiteral("...and the overrides clear"));

    // softfail is the domain hedging, not denying: its own function, never
    // authResultsFailed's business.
    const QString hedged = QStringLiteral("mx.example.org; spf=softfail; dkim=none");
    check(!authResultsFailed(hedged) && authResultsSoftFailed(hedged),
          QStringLiteral("softfail is soft, not a failure"));
    check(authResultsFailed(QStringLiteral("mx.example.org; spf=softfail; dmarc=fail")),
          QStringLiteral("...but a hard failure beside it still counts"));
}

/// The softfail rule: weaker than auth-fail, exempt-preserving, arc-suppressed.
void testSoftfailRule()
{
    const char *ordinary =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Colleague <c@partner.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: Notes\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <sf1@partner.test>\r\n";

    SpamHeuristics::Context soft;
    soft.authSoftFailed = true;
    const SpamHeuristics::Score s = SpamHeuristics::score(headOnly(ordinary), soft);
    check(fired(s, "auth-softfail") && !fired(s, "auth-fail"),
          QStringLiteral("softfail scores its own rule, not auth-fail (%1)").arg(hitList(s)));
    check(s.total < SpamHeuristics::spamThreshold(),
          QStringLiteral("softfail alone cannot mark (total %1)").arg(s.total));

    // A known contact whose forwarded mail softfails stays exempt — the case
    // the split exists for.
    SpamHeuristics::Context knownSoft = soft;
    knownSoft.knownCorrespondent = true;
    const SpamHeuristics::Score known = SpamHeuristics::score(headOnly(ordinary), knownSoft);
    check(known.exempt,
          QStringLiteral("a known contact's softfail keeps the exemption (total %1)")
              .arg(known.total));

    // And arc=pass explains a softfail exactly as it explains a failure.
    SpamHeuristics::Context relayedSoft = soft;
    relayedSoft.arcPassed = true;
    check(!fired(SpamHeuristics::score(headOnly(ordinary), relayedSoft), "auth-softfail"),
          QStringLiteral("arc=pass silences the softfail rule"));
}

/// Provider-specific upstream verdict headers, each another spelling of "the
/// server's filter decided". All feed the same upstream-* rules, so one
/// spamrules key governs the lot. The Received line below each header is what
/// lets addedInTransit() accept it as transit-added rather than sender-forged.
void testProviderUpstreamHeaders()
{
    const char *tail =
        "Received: from a.test (a.test [198.51.100.9]) by mx.example.org;"
        " Fri, 14 Aug 2026 09:00:01 +0000\r\n"
        "From: Shop <news@shop.test>\r\n"
        "To: You <you@example.org>\r\n"
        "Subject: Offer\r\n"
        "Date: Fri, 14 Aug 2026 09:00:00 +0000\r\n"
        "Message-ID: <up1@shop.test>\r\n";

    const auto scored = [&](const char *header) {
        return SpamHeuristics::score(headOnly(QByteArray(header) + tail), {});
    };

    // Barracuda is SpamAssassin's format under its own name: score/required
    // read the same, including the decisive doubled-threshold case.
    const SpamHeuristics::Score barracuda =
        scored("X-Barracuda-Spam-Status: Yes, score=15.00 tests=MANY required=7.00\r\n");
    check(fired(barracuda, "upstream-spam-high"),
          QStringLiteral("Barracuda's status header scores like X-Spam-Status (%1)")
              .arg(hitList(barracuda)));

    const SpamHeuristics::Score proofpoint =
        scored("X-Proofpoint-Spam-Details: rule=spam policy=default score=99\r\n");
    check(fired(proofpoint, "upstream-spam"),
          QStringLiteral("Proofpoint's rule=spam is an upstream verdict (%1)")
              .arg(hitList(proofpoint)));
    check(!fired(scored("X-Proofpoint-Spam-Details: rule=notspam policy=default"
                        " score=30\r\n"),
                 "upstream-spam"),
          QStringLiteral("...and rule=notspam accuses nobody"));

    check(fired(scored("X-Yandex-Spam: 1\r\n"), "upstream-spam"),
          QStringLiteral("Yandex's flag counts"));
    check(fired(scored("X-Gm-Phishy: 1\r\n"), "upstream-spam"),
          QStringLiteral("Google Workspace's phishing flag counts"));
    check(!fired(scored("X-Gm-Spam: 0\r\n"), "upstream-spam"),
          QStringLiteral("a 0 flag accuses nobody"));

    check(fired(scored("X-UI-Filterresults: junk:10;V03:K0:abc\r\n"), "upstream-spam"),
          QStringLiteral("GMX's junk verdict counts"));
    check(!fired(scored("X-UI-Filterresults: notjunk:1;V03:K0:abc\r\n"), "upstream-spam"),
          QStringLiteral("...and notjunk accuses nobody"));

    // Forgery gate unchanged: the same header below every Received line — the
    // position only the sender writes into — is ignored.
    const SpamHeuristics::Score forged = SpamHeuristics::score(
        headOnly(QByteArray(tail) + "X-Yandex-Spam: 1\r\n"), {});
    check(!fired(forged, "upstream-spam"),
          QStringLiteral("a sender-written provider flag is ignored (%1)")
              .arg(hitList(forged)));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // A throwaway config location: testRuleWeightOverrides() writes
    // advanced.conf, and it must never be the one the user is running with.
    const QString sandbox = QDir::tempPath() + QStringLiteral("/mailove-spamheuristicstest");
    QDir(sandbox).removeRecursively();
    QDir().mkpath(sandbox);
    qputenv("XDG_CONFIG_HOME", sandbox.toUtf8());
    QCoreApplication::setOrganizationName(QStringLiteral("mailove"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove"));

    // Enough of the list for every domain used below. Without it
    // organizationalDomain() returns the name unchanged, and every rule that
    // compares two organizations silently stops comparing anything.
    PublicSuffixList::instance().setRulesFromData(
        "// test rules\ncom\norg\nnet\ntest\nuk\nco.uk\nde\nsk\ncz\nme\nru\n");

    testBrandImpersonation();
    testFreemailShapes();
    testEnvelopeAndRouting();
    testSubjectTricks();
    testThreadReplyIsHam();
    testUnfamiliarTld();
    testMeasuredFalsePositives();
    testPlatformMailStaysQuiet();
    testJunkFolderIsDecisive();
    testEncodedHeaders();
    testListMailLinksAreExempt();
    testBodyRules();
    testLinkGroupIsCapped();
    testHamStaysUnmarked();
    testKnownCorrespondentExemption();
    testExplanationRows();
    testRuleWeightOverrides();
    testHackedPhpShapes();
    testAuthResultParsing();
    testSoftfailRule();
    testProviderUpstreamHeaders();

    out << (failures == 0 ? "\nall checks passed\n"
                          : QStringLiteral("\n%1 check(s) failed\n").arg(failures));
    out.flush();
    return failures == 0 ? 0 : 1;
}
