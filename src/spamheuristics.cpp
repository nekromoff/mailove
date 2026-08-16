// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "spamheuristics.h"

#include "advancedconfig.h"

#include "publicsuffixlist.h"

#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QUrl>

#include <algorithm>

namespace SpamHeuristics
{

int spamThreshold()
{
    return AdvancedConfig::i("spam/threshold");
}


namespace
{

/// One header field, unfolded. Kept as a list rather than a map because order
/// matters for Received: the topmost one is the last hop, and that is the only
/// one in the chain a sender cannot have written.
struct Field {
    QString name; ///< lowercased
    QString value;
};

/// Splits a raw header block into unfolded fields. Tolerant on purpose: spam is
/// frequently malformed, and refusing to parse it would be a way of not
/// noticing it.
QList<Field> parseHead(const QByteArray &head)
{
    QList<Field> out;
    const QString text = QString::fromUtf8(head);
    const QStringList lines = text.split(QRegularExpression(QStringLiteral("\r?\n")));
    for (const QString &line : lines) {
        if (line.isEmpty())
            continue;
        // Continuation of the previous field.
        if ((line.startsWith(QLatin1Char(' ')) || line.startsWith(QLatin1Char('\t')))
            && !out.isEmpty()) {
            out.last().value += QLatin1Char(' ') + line.trimmed();
            continue;
        }
        const int colon = line.indexOf(QLatin1Char(':'));
        if (colon <= 0)
            continue;
        out.append({line.left(colon).trimmed().toLower(), line.mid(colon + 1).trimmed()});
    }
    return out;
}

QString firstValue(const QList<Field> &fields, QLatin1String name)
{
    for (const Field &f : fields) {
        if (f.name == name)
            return f.value;
    }
    return {};
}

bool hasField(const QList<Field> &fields, QLatin1String name)
{
    for (const Field &f : fields) {
        if (f.name == name)
            return true;
    }
    return false;
}

int countFields(const QList<Field> &fields, QLatin1String name)
{
    int n = 0;
    for (const Field &f : fields) {
        if (f.name == name)
            ++n;
    }
    return n;
}

/// Position of the first field with this name, or -1.
qsizetype indexOfField(const QList<Field> &fields, QLatin1String name)
{
    for (qsizetype i = 0; i < fields.size(); ++i) {
        if (fields.at(i).name == name)
            return i;
    }
    return -1;
}

/// Position of the last field with this name, or -1.
qsizetype lastIndexOfField(const QList<Field> &fields, QLatin1String name)
{
    for (qsizetype i = fields.size() - 1; i >= 0; --i) {
        if (fields.at(i).name == name)
            return i;
    }
    return -1;
}

/// True when the field at \a index was added by a mail server on the delivery
/// path rather than written by the sender.
///
/// X-Spam-Status, unlike Authentication-Results, carries no authserv-id: there
/// is no name in it to check against a trusted list, so position is the only
/// provenance it has. The sound test is the *bottom-most* Received, because
/// every hop prepends its own — so the sender's original headers all sit below
/// every Received line in the message, and nothing the sender wrote can appear
/// above one.
///
/// Deliberately not the topmost Received, which would be the stronger claim
/// "our own delivering server wrote this". That claim is not reliable enough to
/// build on: a filter may add its verdict either side of the Received line its
/// own MTA prepended, and demanding the stronger position would silently
/// discard genuine verdicts from ordinary setups — a filter that quietly does
/// nothing being far worse than one whose limits are written down. Callers
/// compensate by taking the topmost qualifying header, which is the one from
/// the hop closest to us.
///
/// A message with no Received headers at all never passes: no delivery path, no
/// reason to believe anything in it.
bool addedInTransit(const QList<Field> &fields, qsizetype index)
{
    const qsizetype lastReceived = lastIndexOfField(fields, QLatin1String("received"));
    return lastReceived >= 0 && index < lastReceived;
}

/// What the receiving server's own filter concluded, if it said so where we can
/// believe it.
struct Upstream {
    bool present = false;
    bool spam = false;   ///< explicit "this is spam" flag
    bool scored = false; ///< \a score and \a required are meaningful
    int score = 0;       ///< hundredths, so the scorer stays integer-only
    int required = 0;    ///< the server's own threshold, hundredths
};

int hundredths(const QString &s, bool *ok)
{
    const double v = s.toDouble(ok);
    return static_cast<int>(qRound(v * 100.0));
}

/// Reads SpamAssassin's X-Spam-Status/X-Spam-Flag or Rspamd's X-Spamd-Result,
/// whichever the server writes, and only from a position the sender cannot
/// reach. Nothing here trusts a number's absolute size: each server tunes its
/// own threshold, so the verdict is always the score *relative to* the
/// required= value in the same header.
Upstream readUpstream(const QList<Field> &fields)
{
    Upstream out;
    // Servers prepend, so the topmost qualifying header is the verdict from the
    // hop closest to us — first one wins, per field.
    bool haveFlag = false;

    // SpamAssassin: "No, score=1.43 required=5 tests=... version=4.0.0"
    static const QRegularExpression statusRe(
        QStringLiteral("^\\s*(yes|no)\\b"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression scoreRe(
        QStringLiteral("\\bscore=(-?[0-9]+(?:\\.[0-9]+)?)"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression requiredRe(
        QStringLiteral("\\brequired=(-?[0-9]+(?:\\.[0-9]+)?)"),
        QRegularExpression::CaseInsensitiveOption);
    // Rspamd: "default: False [1.20 / 15.00]"
    static const QRegularExpression rspamdRe(
        QStringLiteral("\\[\\s*(-?[0-9]+(?:\\.[0-9]+)?)\\s*/\\s*(-?[0-9]+(?:\\.[0-9]+)?)\\s*\\]"));

    for (qsizetype i = 0; i < fields.size(); ++i) {
        const Field &f = fields.at(i);
        const bool spamStatus = f.name == QLatin1String("x-spam-status");
        const bool spamFlag = f.name == QLatin1String("x-spam-flag");
        const bool spamd = f.name == QLatin1String("x-spamd-result");
        if (!spamStatus && !spamFlag && !spamd)
            continue;
        if (!addedInTransit(fields, i))
            continue; // forged, or added by a relay we have no reason to trust

        if (spamFlag) {
            if (haveFlag)
                continue;
            haveFlag = true;
            out.present = true;
            out.spam = f.value.trimmed().compare(QLatin1String("yes"),
                                                 Qt::CaseInsensitive) == 0;
            continue;
        }
        if (spamd) {
            if (out.scored)
                continue;
            const auto m = rspamdRe.match(f.value);
            if (!m.hasMatch())
                continue;
            bool okScore = false;
            bool okLimit = false;
            const int score = hundredths(m.captured(1), &okScore);
            const int limit = hundredths(m.captured(2), &okLimit);
            if (!okScore || !okLimit || limit <= 0)
                continue;
            out.present = true;
            out.scored = true;
            out.score = score;
            out.required = limit;
            continue;
        }

        // X-Spam-Status
        out.present = true;
        if (const auto m = statusRe.match(f.value); m.hasMatch() && !haveFlag) {
            haveFlag = true;
            out.spam = m.captured(1).compare(QLatin1String("yes"),
                                             Qt::CaseInsensitive) == 0;
        }
        if (out.scored)
            continue;
        const auto sm = scoreRe.match(f.value);
        const auto rm = requiredRe.match(f.value);
        if (!sm.hasMatch() || !rm.hasMatch())
            continue;
        bool okScore = false;
        bool okReq = false;
        const int score = hundredths(sm.captured(1), &okScore);
        const int required = hundredths(rm.captured(1), &okReq);
        // A non-positive threshold would make every message spam by division;
        // treat it as a server we cannot interpret rather than guessing.
        if (!okScore || !okReq || required <= 0)
            continue;
        out.scored = true;
        out.score = score;
        out.required = required;
    }
    return out;
}

/// Extensions that are executable content wherever they land, and the archive
/// containers spam uses to smuggle them past a scanner.
bool isDangerousAttachment(const QString &name)
{
    static const QStringList danger{
        QStringLiteral("exe"), QStringLiteral("scr"), QStringLiteral("com"),
        QStringLiteral("pif"), QStringLiteral("bat"), QStringLiteral("cmd"),
        QStringLiteral("vbs"), QStringLiteral("vbe"), QStringLiteral("js"),
        QStringLiteral("jse"), QStringLiteral("wsf"), QStringLiteral("wsh"),
        QStringLiteral("hta"), QStringLiteral("lnk"), QStringLiteral("cpl"),
        QStringLiteral("msi"), QStringLiteral("jar"), QStringLiteral("ps1"),
        QStringLiteral("iso"), QStringLiteral("img"), QStringLiteral("vhd"),
    };
    const QString n = name.trimmed().toLower();
    const int dot = n.lastIndexOf(QLatin1Char('.'));
    if (dot < 0)
        return false;
    return danger.contains(n.mid(dot + 1));
}

/// "invoice.pdf.exe" — a second extension whose only purpose is to be the one
/// the reader sees. Only counted when the *last* extension is a dangerous one,
/// so ordinary names like "report.2026.pdf" or "archive.tar.gz" say nothing.
bool hasDoubleExtension(const QString &name)
{
    const QString n = name.trimmed().toLower();
    const QStringList parts = n.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (parts.size() < 3)
        return false;
    static const QStringList document{
        QStringLiteral("pdf"),  QStringLiteral("doc"),  QStringLiteral("docx"),
        QStringLiteral("xls"),  QStringLiteral("xlsx"), QStringLiteral("ppt"),
        QStringLiteral("pptx"), QStringLiteral("txt"),  QStringLiteral("rtf"),
        QStringLiteral("jpg"),  QStringLiteral("jpeg"), QStringLiteral("png"),
        QStringLiteral("gif"),  QStringLiteral("csv"),  QStringLiteral("htm"),
        QStringLiteral("html"),
    };
    return isDangerousAttachment(n) && document.contains(parts.at(parts.size() - 2));
}

/// Office formats that can carry macros. Real, but far more often a colleague's
/// spreadsheet than an attack, which is why the weight attached to this is a
/// fraction of the executable one.
bool isMacroDocument(const QString &name)
{
    static const QStringList macro{
        QStringLiteral("docm"), QStringLiteral("xlsm"), QStringLiteral("pptm"),
        QStringLiteral("dotm"), QStringLiteral("xltm"), QStringLiteral("xlam"),
    };
    const QString n = name.trimmed().toLower();
    const int dot = n.lastIndexOf(QLatin1Char('.'));
    return dot >= 0 && macro.contains(n.mid(dot + 1));
}

/// A domain that is really an address literal: "[192.0.2.1]", "192.0.2.1", or
/// the bracketed IPv6 form. Anchored, so a hostname that merely contains digits
/// ("mail4.example.com") is untouched.
const QRegularExpression &ipLiteralRe()
{
    static const QRegularExpression re(
        QStringLiteral("^\\[?(?:[0-9]{1,3}(?:\\.[0-9]{1,3}){3}|IPv6:[0-9A-Fa-f:]+)\\]?$"));
    return re;
}

const QRegularExpression &addressRe()
{
    static const QRegularExpression re(
        QStringLiteral("[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"));
    return re;
}

/// The script of a letter, reduced to the three alphabets that matter for
/// homograph attacks. Everything else — CJK, Arabic, Hebrew — is left alone:
/// those are not confusable with Latin, and treating a Japanese subject line as
/// evidence of fraud would be both wrong and offensive.
enum class Script { Other, Latin, Cyrillic, Greek };

Script scriptOf(QChar c)
{
    if (!c.isLetter())
        return Script::Other;
    switch (c.script()) {
    case QChar::Script_Latin:
        return Script::Latin;
    case QChar::Script_Cyrillic:
        return Script::Cyrillic;
    case QChar::Script_Greek:
        return Script::Greek;
    default:
        return Script::Other;
    }
}

/// True when a single word mixes Latin with Cyrillic or Greek letters. Mixing
/// across a whole subject is ordinary in multilingual mail; mixing *inside one
/// word* is how "PayPaI" and "аpple.com" are built, and essentially never
/// happens by accident.
bool hasConfusableWord(const QString &s)
{
    const QStringList words = s.split(QRegularExpression(QStringLiteral("\\s+")),
                                      Qt::SkipEmptyParts);
    for (const QString &word : words) {
        QSet<int> scripts;
        for (const QChar c : word) {
            const Script sc = scriptOf(c);
            if (sc != Script::Other)
                scripts.insert(static_cast<int>(sc));
        }
        if (scripts.size() > 1)
            return true;
    }
    return false;
}

/// True when one dot-separated label mixes Latin with Cyrillic or Greek.
///
/// Deliberately narrower than "contains non-ASCII": internationalised domains
/// are ordinary mail, and treating a Slovak, Czech or Russian domain as fraud
/// because it is not ASCII would be both wrong and insulting. Punycode alone
/// says nothing either — what has no legitimate use is a *single label* built
/// from two alphabets, which is how "раypal.com" is made.
bool hasConfusableLabel(const QString &domain)
{
    const QStringList labels = domain.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    for (const QString &label : labels) {
        QSet<int> scripts;
        for (const QChar c : label) {
            const Script sc = scriptOf(c);
            if (sc != Script::Other)
                scripts.insert(static_cast<int>(sc));
        }
        if (scripts.size() > 1)
            return true;
    }
    return false;
}

/// Strips tags and collapses whitespace, to estimate how much text a reader
/// actually sees in an HTML part.
QString visibleText(const QString &html)
{
    QString s = html;
    s.remove(QRegularExpression(QStringLiteral("<(script|style)[^>]*>.*?</\\1>"),
                                QRegularExpression::CaseInsensitiveOption
                                    | QRegularExpression::DotMatchesEverythingOption));
    s.remove(QRegularExpression(QStringLiteral("<[^>]*>")));
    s.replace(QRegularExpression(QStringLiteral("&nbsp;?"), QRegularExpression::CaseInsensitiveOption),
              QStringLiteral(" "));
    return s.simplified();
}

QString hostOfUrl(const QString &url)
{
    QString s = url;
    const int scheme = s.indexOf(QStringLiteral("://"));
    if (scheme >= 0)
        s = s.mid(scheme + 3);
    s = s.section(QLatin1Char('/'), 0, 0).section(QLatin1Char('?'), 0, 0);
    s = s.section(QLatin1Char('@'), -1);          // strip userinfo
    s = s.section(QLatin1Char(':'), 0, 0);        // strip port
    return s.toLower();
}

QString orgOfDomain(const QString &domain)
{
    if (domain.isEmpty())
        return {};
    const QString org = PublicSuffixList::instance().organizationalDomain(domain);
    // Falling back to the full domain can only make two names look less
    // related than they are. That direction produces a missed rule, never a
    // false accusation, which is the trade we want when the list is absent.
    return org.isEmpty() ? domain : org;
}

/// Brands worth imitating, and the org domains each one legitimately sends
/// from. Deliberately short: every entry is a name whose mail is transactional,
/// carries money or credentials, and is forged constantly. A long list is worse
/// than a short one here — each extra brand is another word that might appear
/// innocently in a display name, and the rule's whole value rests on the token
/// being one nobody uses casually.
///
/// The domains are not an exhaustive list of each brand's estate; they are the
/// ones its user-facing mail comes from. A brand mailing from an outsourced
/// domain not listed here scores the rule and needs a passing authentication or
/// a familiar domain to clear it, which is why both of those suppress it.
struct Brand {
    QLatin1String token;   ///< lowercase, matched as a whole word
    QLatin1String domains; ///< space-separated org domains that may use it
};

const QList<Brand> &brands()
{
    static const QList<Brand> list{
        {QLatin1String("paypal"), QLatin1String("paypal.com paypal.co.uk paypal-communication.com")},
        {QLatin1String("apple"), QLatin1String("apple.com icloud.com apple.co cdn-apple.com")},
        {QLatin1String("icloud"), QLatin1String("apple.com icloud.com")},
        {QLatin1String("microsoft"), QLatin1String("microsoft.com microsoftonline.com live.com aka.ms msftauth.net office365.com office.net office.com")},
        {QLatin1String("outlook"), QLatin1String("microsoft.com outlook.com live.com office365.com office.net office.com")},
        {QLatin1String("onedrive"), QLatin1String("microsoft.com")},
        {QLatin1String("office365"), QLatin1String("microsoft.com microsoftonline.com office365.com office.net office.com")},
        {QLatin1String("amazon"), QLatin1String("amazon.com amazon.co.uk amazon.de amazonses.com amzn.to a.co")},
        {QLatin1String("netflix"), QLatin1String("netflix.com nflx.it nflxext.com")},
        {QLatin1String("google"), QLatin1String("google.com gmail.com youtube.com c.gle goo.gle goo.gl googleusercontent.com googlemail.com withgoogle.com")},
        {QLatin1String("facebook"), QLatin1String("facebook.com facebookmail.com meta.com fb.me fb.com")},
        {QLatin1String("instagram"), QLatin1String("instagram.com facebookmail.com meta.com")},
        {QLatin1String("whatsapp"), QLatin1String("whatsapp.com meta.com")},
        {QLatin1String("linkedin"), QLatin1String("linkedin.com lnkd.in licdn.com")},
        {QLatin1String("dropbox"), QLatin1String("dropbox.com dropboxmail.com db.tt")},
        {QLatin1String("docusign"), QLatin1String("docusign.com docusign.net")},
        {QLatin1String("dhl"), QLatin1String("dhl.com dhl.de")},
        {QLatin1String("fedex"), QLatin1String("fedex.com")},
        {QLatin1String("ups"), QLatin1String("ups.com")},
        {QLatin1String("coinbase"), QLatin1String("coinbase.com")},
        {QLatin1String("binance"), QLatin1String("binance.com")},
        {QLatin1String("revolut"), QLatin1String("revolut.com")},
        {QLatin1String("wise"), QLatin1String("wise.com transferwise.com")},
        {QLatin1String("stripe"), QLatin1String("stripe.com stripecdn.com")},
        {QLatin1String("steam"), QLatin1String("steampowered.com valvesoftware.com")},
        {QLatin1String("spotify"), QLatin1String("spotify.com")},
        {QLatin1String("ebay"), QLatin1String("ebay.com ebay.co.uk ebay.de ebay.to ebayimg.com")},
        {QLatin1String("bitcoin"), QLatin1String("")},
        {QLatin1String("visa"), QLatin1String("visa.com")},
        {QLatin1String("mastercard"), QLatin1String("mastercard.com")},
    };
    return list;
}

/// The brand a name claims to be, or nullptr. Matched on whole lowercase words
/// so that "Apple" hits and "pineapple" does not — substring matching here
/// would fire on ordinary words and is not worth the recall.
const Brand *brandClaimedBy(const QString &text)
{
    static const QRegularExpression wordRe(QStringLiteral("[a-z0-9]+"));
    const QString lower = text.toLower();
    QSet<QString> words;
    auto it = wordRe.globalMatch(lower);
    while (it.hasNext())
        words.insert(it.next().captured(0));
    for (const Brand &b : brands()) {
        if (words.contains(QString(b.token)))
            return &b;
    }
    return nullptr;
}

/// True when \a host is one the brand really uses — the domain itself or
/// anything under it.
///
/// Matched on label boundaries rather than as a bare substring, and rather
/// than by exact equality. Exact equality was wrong in both directions: it
/// missed "www.google.com" whenever the Public Suffix List had not loaded and
/// the caller therefore passed a full host instead of a registrable domain,
/// which is precisely when this needs to work. A bare substring would be far
/// worse — "google.com.evil.test" would read as Google, which is the attack.
bool brandOwns(const Brand &b, const QString &host)
{
    if (host.isEmpty())
        return false;
    const QString domains = QString(b.domains);
    if (domains.isEmpty())
        return false;
    const QStringList list = domains.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    for (const QString &d : list) {
        if (host == d || host.endsWith(QLatin1Char('.') + d))
            return true;
    }
    return false;
}

/// True when two organizational domains belong to the same brand.
///
/// Large senders do not put everything on one domain. Google's links go to
/// c.gle, Microsoft's to aka.ms, LinkedIn's to lnkd.in — official shorteners
/// and asset domains, all of them a different registrable domain from the one
/// in the From line. Reading a google.com message's link to c.gle as "the text
/// says one site and the link goes to another" is the textbook phishing
/// signal and, here, entirely wrong.
///
/// The table is the authority for this, so every entry added to a brand's
/// domain list widens what counts as that brand — which is why the list holds
/// only domains the brand demonstrably sends or links from.
bool sameBrandFamily(const QString &a, const QString &b)
{
    if (a.isEmpty() || b.isEmpty())
        return false;
    if (a == b)
        return true;
    for (const Brand &brand : brands()) {
        if (brandOwns(brand, a) && brandOwns(brand, b))
            return true;
    }
    return false;
}

/// Consumer mailbox providers. A person mailing from one of these is ordinary;
/// a *company role* mailing from one is not, which is the only way this is
/// used.
bool isFreemail(const QString &org)
{
    static const QSet<QString> set{
        QStringLiteral("gmail.com"),    QStringLiteral("googlemail.com"),
        QStringLiteral("yahoo.com"),    QStringLiteral("yahoo.co.uk"),
        QStringLiteral("hotmail.com"),  QStringLiteral("outlook.com"),
        QStringLiteral("live.com"),     QStringLiteral("msn.com"),
        QStringLiteral("aol.com"),      QStringLiteral("gmx.net"),
        QStringLiteral("gmx.com"),      QStringLiteral("gmx.de"),
        QStringLiteral("mail.ru"),      QStringLiteral("yandex.ru"),
        QStringLiteral("proton.me"),    QStringLiteral("protonmail.com"),
        QStringLiteral("zoho.com"),     QStringLiteral("icloud.com"),
        QStringLiteral("me.com"),       QStringLiteral("seznam.cz"),
        QStringLiteral("centrum.sk"),   QStringLiteral("azet.sk"),
        QStringLiteral("zoznam.sk"),    QStringLiteral("post.cz"),
    };
    return set.contains(org);
}

/// URL shorteners. Legitimate senders use them too, which is why the rule that
/// reads this is weighted so it can never mark anything on its own.
bool isShortener(const QString &host)
{
    static const QSet<QString> set{
        QStringLiteral("bit.ly"),     QStringLiteral("tinyurl.com"),
        QStringLiteral("t.co"),       QStringLiteral("goo.gl"),
        QStringLiteral("ow.ly"),      QStringLiteral("is.gd"),
        QStringLiteral("buff.ly"),    QStringLiteral("cutt.ly"),
        QStringLiteral("rb.gy"),      QStringLiteral("shorturl.at"),
        QStringLiteral("rebrand.ly"), QStringLiteral("t.ly"),
        QStringLiteral("bl.ink"),     QStringLiteral("s.id"),
        QStringLiteral("tiny.cc"),    QStringLiteral("lnkd.in"),
    };
    return set.contains(host);
}

/// A company function rather than a person: the display name a BEC attempt
/// wears when it mails from a free mailbox.
bool isRoleName(const QString &displayName)
{
    static const QStringList roles{
        QStringLiteral("support"),    QStringLiteral("billing"),
        QStringLiteral("invoice"),    QStringLiteral("invoicing"),
        QStringLiteral("accounts"),   QStringLiteral("accounting"),
        QStringLiteral("payroll"),    QStringLiteral("helpdesk"),
        QStringLiteral("security"),   QStringLiteral("customer service"),
        QStringLiteral("no-reply"),   QStringLiteral("noreply"),
        QStringLiteral("admin"),      QStringLiteral("administrator"),
        QStringLiteral("it department"), QStringLiteral("service desk"),
    };
    const QString lower = displayName.toLower();
    for (const QString &r : roles) {
        if (lower.contains(r))
            return true;
    }
    return false;
}

/// True when a mailing list, group or forwarder took delivery of this message
/// and re-sent it under its own domain.
///
/// This matters because a relay breaks the connection between the From line
/// and the domain the message arrives from, which is the assumption underneath
/// half the rules here. Google Groups sends "Google Ads via mcc"
/// <mcc@company.test>: the display name is the *original* author's and the
/// address is the *list's*, so reading the two together says the company is
/// impersonating Google, when nothing of the sort has happened.
///
/// Two signals, both of them things a relay writes about itself: the List-*
/// headers, and the "X via Y" display-name convention that exists precisely to
/// tell the reader a rewrite happened. A spammer can of course write either —
/// but doing so buys them nothing except the suppression of rules that were
/// about to misfire on legitimate list mail, and the rules that actually catch
/// a phish (its links, its password form, its attachment) are untouched by it.
bool relayedMail(const QList<Field> &fields, const QString &displayName)
{
    if (hasField(fields, QLatin1String("list-id"))
        || hasField(fields, QLatin1String("list-unsubscribe"))
        || hasField(fields, QLatin1String("list-post"))) {
        return true;
    }
    // "Alice via Some Group" — the whole point of the convention is that the
    // name before "via" is not the sender.
    static const QRegularExpression viaRe(QStringLiteral("\\bvia\\s+\\S"),
                                          QRegularExpression::CaseInsensitiveOption);
    return viaRe.match(displayName).hasMatch();
}

/// Characters that occupy no space and so can hide inside a word: zero-width
/// space/non-joiner/joiner, soft hyphen, word joiner, byte-order mark. Used to
/// break up a brand name so that neither a human nor a substring match sees it
/// ("Pay\u200bPal").
bool hasInvisibleInsideWord(const QString &s)
{
    static const QString invisible = QStringLiteral("\u200B\u200C\u200D\u00AD\u2060\uFEFF");
    for (qsizetype i = 1; i + 1 < s.size(); ++i) {
        if (!invisible.contains(s.at(i)))
            continue;
        // Only inside a word: a stray BOM at either end of a header is a
        // transcoding artefact, not obfuscation.
        if (s.at(i - 1).isLetterOrNumber() && s.at(i + 1).isLetterOrNumber())
            return true;
    }
    return false;
}

/// The charset named by the first RFC 2047 encoded-word in \a value, lowercase,
/// or empty when the value carries none.
QString encodedWordCharset(const QString &value)
{
    static const QRegularExpression re(QStringLiteral("=\\?([A-Za-z0-9_.:-]+)\\?[BbQq]\\?"));
    const auto m = re.match(value);
    return m.hasMatch() ? m.captured(1).toLower() : QString();
}

/// RFC 2047 encoded-words, decoded to the text the reader sees.
///
/// The scorer parses the raw head, and any header with a non-ASCII character
/// arrives as "=?charset?B?...?=" — so without this, every rule that judges a
/// subject or a display name was judging base64. A Cyrillic-homoglyph subject
/// was *invisible* to the homoglyph rule, which is precisely the mail that
/// rule exists for; measured over a real junk folder, subject-confusable had
/// never fired once.
///
/// Deliberately tolerant, like parseHead(): spam is frequently malformed, and
/// refusing to decode it is a way of not noticing it. Anything that fails to
/// decode is left as it was, which can only cost a rule that would have fired.
///
/// Charsets: UTF-8 and ASCII are decoded properly; everything else falls back
/// to Latin-1, because Qt 6 ships no legacy codecs. That is mojibake for a
/// genuine gb2312 subject, but the safe kind: high bytes stay non-ASCII (which
/// is what charset-mismatch needs to know) and the mojibake is all Latin
/// script, so the confusable rules — which require two scripts inside one
/// word — cannot misfire on it.
QString decodeEncodedWords(const QString &raw)
{
    if (!raw.contains(QLatin1String("=?")))
        return raw;
    static const QRegularExpression wordRe(
        QStringLiteral("=\\?([A-Za-z0-9_.:-]+)\\?([BbQq])\\?([^? \\t]*)\\?="));
    QString out;
    qsizetype last = 0;
    bool prevWasWord = false;
    auto it = wordRe.globalMatch(raw);
    while (it.hasNext()) {
        const auto m = it.next();
        const QString between = raw.mid(last, m.capturedStart() - last);
        // Whitespace between two encoded-words is transport padding, not text
        // (RFC 2047 §6.2) — a long name is split across words mid-letter, and
        // keeping the space would break the very word the rules examine.
        if (!(prevWasWord && between.trimmed().isEmpty()))
            out += between;

        const QString charset = m.captured(1).toLower();
        const bool base64 = m.captured(2).at(0).toLower() == QLatin1Char('b');
        QByteArray bytes;
        if (base64) {
            bytes = QByteArray::fromBase64(m.captured(3).toLatin1());
        } else {
            // Q encoding: quoted-printable with '_' standing for space.
            const QByteArray q = m.captured(3).toLatin1();
            for (qsizetype i = 0; i < q.size(); ++i) {
                if (q.at(i) == '_') {
                    bytes += ' ';
                } else if (q.at(i) == '=' && i + 2 < q.size()) {
                    bool ok = false;
                    const char c = char(QByteArray(q.constData() + i + 1, 2).toInt(&ok, 16));
                    if (ok) {
                        bytes += c;
                        i += 2;
                    } else {
                        bytes += q.at(i);
                    }
                } else {
                    bytes += q.at(i);
                }
            }
        }
        if (charset.startsWith(QLatin1String("utf-8")) || charset == QLatin1String("utf8"))
            out += QString::fromUtf8(bytes);
        else
            out += QString::fromLatin1(bytes); // see the charset note above
        last = m.capturedEnd();
        prevWasWord = true;
    }
    out += raw.mid(last);
    return out;
}

/// True when the topmost Received line names no resolvable sending host: the
/// "from" clause is missing, or says "unknown", or offers nothing but an IP.
/// The shape of a message injected straight into a relay by a script.
bool receivedFromUnknownHost(const QString &received)
{
    static const QRegularExpression fromRe(
        QStringLiteral("\\bfrom\\s+([^\\s;]+)"), QRegularExpression::CaseInsensitiveOption);
    const auto m = fromRe.match(received);
    if (!m.hasMatch())
        return true;
    const QString host = m.captured(1).toLower();
    if (host == QLatin1String("unknown"))
        return true;
    if (ipLiteralRe().match(host).hasMatch())
        return true;
    // "from unknown (HELO x) ([1.2.3.4])" — a named host has a dot and letters.
    return !host.contains(QLatin1Char('.')) || !std::any_of(host.cbegin(), host.cend(),
                                                            [](QChar c) { return c.isLetter(); });
}

/// Every http(s) URL in an HTML part, in document order. Deliberately naive:
/// this reads what the message *contains*, and a URL a parser would reject is
/// still a URL a mail client might render.
QStringList urlsIn(const QString &html)
{
    static const QRegularExpression re(
        QStringLiteral("(?:href|src)\\s*=\\s*[\"']?(https?://[^\"'\\s>]+)"),
        QRegularExpression::CaseInsensitiveOption);
    QStringList out;
    auto it = re.globalMatch(html);
    while (it.hasNext())
        out.append(it.next().captured(1));
    return out;
}

/// The userinfo-before-host trick: "https://paypal.com@evil.test/". Everything
/// left of the '@' is credentials the browser discards, so what the reader sees
/// is not where the link goes. No legitimate mail does this.
bool urlHasUserinfo(const QString &url)
{
    QString s = url;
    const int scheme = s.indexOf(QStringLiteral("://"));
    if (scheme >= 0)
        s = s.mid(scheme + 3);
    const int slash = s.indexOf(QLatin1Char('/'));
    const QString authority = slash >= 0 ? s.left(slash) : s;
    return authority.contains(QLatin1Char('@'));
}

} // namespace

QString normalizeAddress(const QString &address)
{
    QString a = address.trimmed().toLower();
    const int at = a.lastIndexOf(QLatin1Char('@'));
    if (at <= 0)
        return a;
    QString local = a.left(at);
    const int plus = local.indexOf(QLatin1Char('+'));
    if (plus > 0)
        local = local.left(plus);
    return local + a.mid(at);
}

namespace
{

/// Splits a mailbox header value into display name and addr-spec, honouring
/// quoting and taking the *last* angle-addr.
///
/// Getting this wrong is a security bug rather than a cosmetic one. Given
///
///     From: "Alice <alice@known.example>" <thief@evil.test>
///
/// the naive answer — first address anywhere in the value — is
/// alice@known.example, which is both the wrong sender and, far worse, an
/// allowlist lookup the sender got to choose the result of. Rule 0 would then
/// exempt any message whose display name names someone the user has written
/// to, which is a string anybody can type.
void splitMailbox(const QString &value, QString *name, QString *addr)
{
    bool inQuotes = false;
    int open = -1;
    int close = -1;
    for (int i = 0; i < value.size(); ++i) {
        const QChar c = value.at(i);
        if (c == QLatin1Char('\\')) {
            ++i; // escaped character, whatever it is
            continue;
        }
        if (c == QLatin1Char('"')) {
            inQuotes = !inQuotes;
            continue;
        }
        if (inQuotes)
            continue;
        if (c == QLatin1Char('<')) {
            open = i;
            close = -1;
        } else if (c == QLatin1Char('>') && open >= 0 && close < 0) {
            close = i;
        }
    }

    if (open < 0) {
        // Bare addr-spec, no angle brackets and so no display name.
        *name = QString();
        const auto m = addressRe().match(value);
        *addr = m.hasMatch() ? m.captured(0) : QString();
        return;
    }

    const QString inner = close > open ? value.mid(open + 1, close - open - 1)
                                       : value.mid(open + 1);
    const auto m = addressRe().match(inner);
    *addr = m.hasMatch() ? m.captured(0) : QString();

    QString shown = value.left(open).trimmed();
    if (shown.size() >= 2 && shown.startsWith(QLatin1Char('"'))
        && shown.endsWith(QLatin1Char('"'))) {
        shown = shown.mid(1, shown.size() - 2);
    }
    *name = shown.trimmed();
}

} // namespace

QString addressOf(const QString &headerValue)
{
    QString name;
    QString addr;
    splitMailbox(headerValue, &name, &addr);
    return addr.isEmpty() ? QString() : normalizeAddress(addr);
}

QString displayNameOf(const QString &headerValue)
{
    QString name;
    QString addr;
    splitMailbox(headerValue, &name, &addr);
    return name;
}

QString organizationalDomainOf(const QString &address)
{
    const int at = address.lastIndexOf(QLatin1Char('@'));
    if (at < 0)
        return {};
    return orgOfDomain(address.mid(at + 1).toLower());
}

QString Score::explanation() const
{
    if (hits.isEmpty())
        return {};

    // One row per rule that fired, in the order they fired, with the signed
    // weight first so the column reads as arithmetic and the last row is the
    // sum the verdict was made from. Rules that argued *for* the message are
    // listed too: a tooltip that shows only the accusations makes the total
    // look wrong, and a reader who cannot check the arithmetic has been told
    // nothing they can act on.
    QStringList weights;
    int width = 0;
    for (const Hit &h : hits) {
        const QString w = QStringLiteral("%1%2")
                              .arg(h.weight > 0 ? QStringLiteral("+") : QString())
                              .arg(h.weight);
        weights.append(w);
        width = qMax(width, int(w.size()));
    }
    width = qMax(width, int(QString::number(total).size()));

    QStringList lines;
    for (qsizetype i = 0; i < hits.size(); ++i) {
        lines.append(QStringLiteral("%1  %2")
                         .arg(weights.at(i), width)
                         .arg(hits.at(i).detail));
    }
    lines.append(QString(width + 2 + 8, QLatin1Char('-')));
    const QString verdictLine = verdict == Verdict::Spam
        ? QStringLiteral("Marked as spam (threshold %1)").arg(spamThreshold())
        : verdict == Verdict::Unsure
        ? QStringLiteral("Not marked — below the spam threshold of %1").arg(spamThreshold())
        : QStringLiteral("Not spam (threshold %1)").arg(spamThreshold());
    lines.append(QStringLiteral("%1  %2").arg(QString::number(total), width).arg(verdictLine));
    return lines.join(QLatin1Char('\n'));
}

Score score(const Message &msg, const Context &ctx)
{
    Score out;
    const QList<Field> fields = parseHead(msg.head);

    // Decoded first: everything below that reads a display name or a subject
    // must judge what the reader sees, not the encoded-word transport form.
    // The addr-spec side is unaffected — addresses are never encoded, and the
    // last angle-addr is the last angle-addr in either form.
    const QString fromValue =
        decodeEncodedWords(firstValue(fields, QLatin1String("from")));
    const QString fromAddr = addressOf(fromValue);
    const QString fromOrg = organizationalDomainOf(fromAddr);
    const QString displayName = displayNameOf(fromValue);
    const bool relayed = relayedMail(fields, displayName);

    // A message that crossed a mailing list fails SPF, and fails DKIM too if
    // the list touched the subject or the body. That is not a forgery, it is
    // what a relay does, and ARC exists to carry the verdict from before it
    // happened. So an authentication failure our own server reported alongside
    // arc=pass is evidence of a relay and of nothing else.
    //
    // Every rule below reads this rather than the raw context flag. Without it
    // the scorer marks the mailing lists a user is subscribed to — +35 for the
    // failure, or +60 where they have written to the list before and Rule 0's
    // exemption gets revoked for it, which is the worst false positive this
    // filter is capable of.
    const bool authFailed = ctx.authFailed && !ctx.arcPassed;

    auto hit = [&out](const char *id, int weight, const QString &detail) {
        out.hits.append({QString::fromLatin1(id), weight, detail});
        out.total += weight;
    };

    // ------------------------------------------------------------------
    // Rule -1: the message is in the junk folder. Evaluated before Rule 0,
    // because it beats it: a known correspondent whose mail the user moved to
    // Junk anyway has been judged by the person the exemption exists to serve.
    // ------------------------------------------------------------------
    if (ctx.inJunkFolder) {
        hit("junk-folder", JunkFolderWeight,
            QStringLiteral("This message is in your Junk folder — you or your mail server "
                           "put it there"));
    }

    // ------------------------------------------------------------------
    // Rule 0: someone the user has written to is not a spammer.
    //
    // The one thing that can revoke it is the message failing authentication
    // at our own receiving server. That is not a weakening of the rule — a
    // message claiming to be from a known contact while failing SPF/DKIM/DMARC
    // is precisely *not* from that contact, and an unconditional allowlist
    // would hand a free pass to anyone who guesses an address the user has
    // mailed. Absent auth data (no trusted Authentication-Results at all) the
    // exemption stands: no evidence is not evidence of forgery.
    // ------------------------------------------------------------------
    if (ctx.knownCorrespondent && !authFailed && !ctx.alwaysScore && !ctx.inJunkFolder) {
        out.exempt = true;
        out.verdict = Verdict::Ham;
        out.exemptReason = QStringLiteral("You have sent mail to %1.").arg(fromAddr);
        return out;
    }

    // --- Authentication ------------------------------------------------
    if (ctx.knownCorrespondent && authFailed) {
        // Decisive on its own: forging an address the user actually corresponds
        // with is targeted, not incidental.
        hit("known-contact-spoofed", 60,
            QStringLiteral("Claims to be %1, whom you have written to, but sender "
                           "authentication failed — the address is probably forged")
                .arg(fromAddr));
    } else if (authFailed) {
        hit("auth-fail", 35,
            QStringLiteral("Receiving server reported an SPF/DKIM/DMARC failure"));
    }
    // --- Familiarity ---------------------------------------------------
    // "We have had mail from this domain for a long time" — the signal that
    // covers everything knownCorrespondent cannot, because the user never
    // writes back to their bank. Volume *and* age are both required: a single
    // spam run can put fifty messages from one domain in the cache in an
    // afternoon, but it cannot make them two months old.
    const int familiarCount = AdvancedConfig::i("spam/familiarCount");
    const int familiarDays = AdvancedConfig::i("spam/familiarDays");
    const bool familiarOrg = ctx.seenFromOrg >= familiarCount
        && ctx.daysKnownOrg >= familiarDays;
    const QString familiarDetail =
        QStringLiteral("You have had %1 messages from %2 over %3 days")
            .arg(ctx.seenFromOrg)
            .arg(fromOrg)
            .arg(ctx.daysKnownOrg);

    // Authentication proves a message really came from the domain it claims —
    // not that the domain is one worth hearing from. A spam operation registers
    // a domain and publishes SPF and DKIM in an afternoon, so a bare pass is
    // worth much less than it looks; it is only strong evidence when the domain
    // it authenticates is one with a history here. That is why the credit is
    // split rather than flat.
    if (ctx.authPassed && !authFailed) {
        if (familiarOrg) {
            hit("auth-pass-familiar", -25,
                QStringLiteral("Sender authentication passed, and %1").arg(familiarDetail));
        } else {
            hit("auth-pass", -8,
                QStringLiteral("Sender authentication passed, but %1 is not a domain "
                               "you have heard from before").arg(fromOrg));
        }
    } else if (familiarOrg && !authFailed) {
        // No verdict either way, but the history stands on its own.
        hit("familiar-domain", -15, familiarDetail);
    } else if (familiarOrg && authFailed) {
        // The domain is one the user really does get mail from, and this
        // message failed authentication while claiming to be it. Together with
        // auth-fail above this reaches the threshold, which is the intent:
        // forging a domain someone actually receives from is targeted.
        hit("familiar-domain-spoofed", 25,
            QStringLiteral("Claims to be %1, which you do have a history with, but "
                           "sender authentication failed").arg(fromOrg));
    }

    // --- Conversation --------------------------------------------------
    // A reply to something already in the mailbox. Weighted like a strong ham
    // signal because claiming it requires knowing a Message-ID the user
    // received, which a bulk sender cannot: References is the one header a
    // stranger structurally cannot fill in correctly.
    if (ctx.inReplyToKnown) {
        hit("thread-reply", -30,
            QStringLiteral("This is a reply within a conversation already in your mailbox"));
    }

    // --- What our own server's filter concluded -------------------------
    // Everything a header-only scorer structurally cannot do — DNS blocklists,
    // URI blocklists, IP reputation, the server's own corpus — has already been
    // done by the machine that accepted the message, and the answer is sitting
    // in the head. Read relative to the server's own required= value, never as
    // an absolute: every deployment tunes that number differently.
    const Upstream up = readUpstream(fields);
    if (up.scored) {
        const QString detail =
            QStringLiteral("Your mail server's own filter scored this %1 against its "
                           "threshold of %2")
                .arg(up.score / 100.0, 0, 'f', 2)
                .arg(up.required / 100.0, 0, 'f', 2);
        if (up.score >= 2 * up.required) {
            // Twice the server's own threshold. Decisive on its own, in the
            // same way a spoofed known contact is: this is not a weak signal
            // being stacked, it is a filter with evidence we cannot see saying
            // it is certain.
            hit("upstream-spam-high", 50, detail);
        } else if (up.score >= up.required) {
            hit("upstream-spam", 40, detail);
        } else if (up.score * 5 >= up.required * 3) {
            // Within striking distance of the server's threshold: real
            // evidence, but the server itself declined to call it, so this can
            // only ever corroborate.
            hit("upstream-near-threshold", 12, detail);
        } else if (up.score <= 0) {
            hit("upstream-ham", -15, detail);
        }
    } else if (up.present && up.spam) {
        // A flag with no score behind it — X-Spam-Flag: YES, or a status line
        // we could not parse the numbers out of.
        hit("upstream-spam", 40,
            QStringLiteral("Your mail server's own filter marked this as spam"));
    }

    // --- OpenPGP -------------------------------------------------------
    // No key is checked here; the MIME shape alone is enough. Spam does not
    // arrive signed or encrypted, so this is a reliable ham signal even before
    // any signature has been verified.
    if (ctx.crypto == 2 || ctx.crypto == 3)
        hit("pgp-signed", -50, QStringLiteral("Message is OpenPGP signed"));
    else if (ctx.crypto == 1)
        hit("pgp-encrypted", -40, QStringLiteral("Message is OpenPGP encrypted"));

    // --- From / display name -------------------------------------------
    if (!displayName.isEmpty() && !fromOrg.isEmpty()) {
        const auto m = addressRe().match(displayName);
        if (m.hasMatch()) {
            const QString shownOrg = organizationalDomainOf(normalizeAddress(m.captured(0)));
            if (!shownOrg.isEmpty() && shownOrg != fromOrg) {
                hit("display-name-address", 30,
                    QStringLiteral("Sender name shows %1 but the message is from %2")
                        .arg(m.captured(0), fromAddr));
            }
        }
        if (hasConfusableWord(displayName)) {
            hit("display-name-confusable", 30,
                QStringLiteral("Sender name mixes alphabets within a word: \"%1\"")
                    .arg(displayName));
        }
    }

    // A name claiming to be a brand, sent from somewhere that brand does not
    // mail from. Suppressed by familiarity — a brand mailing through an
    // outsourced domain stops scoring once the user has a history with it —
    // and by the message having been relayed, for which see relayedMail().
    //
    // Deliberately *not* suppressed by a passing authentication. SPF and DKIM
    // say the message really came from the domain it claims; they say nothing
    // about whether that domain is entitled to the name in the From line, and a
    // phisher signs their own throwaway domain as a matter of course.
    if (!displayName.isEmpty() && !fromOrg.isEmpty() && !familiarOrg && !relayed) {
        if (const Brand *b = brandClaimedBy(displayName); b && !brandOwns(*b, fromOrg)) {
            // A brand's own domain passing authentication is the one case this
            // must never touch, and brandOwns() above already covers it. What
            // is left is a name saying "PayPal" from a domain that is not
            // PayPal's, which is the entire fraud in one line.
            hit("brand-impersonation", 30,
                QStringLiteral("Calls itself \"%1\" but the message comes from %2, which is "
                               "not a domain %3 sends from")
                    .arg(displayName, fromOrg, QString(b->token)));
        }
    }

    // A free mailbox wearing a company's clothes: "Acme Billing" from a gmail
    // address. Ordinary people mail from freemail all the time — what does not
    // happen is a company function doing it.
    if (!displayName.isEmpty() && isFreemail(fromOrg) && !relayed
        && (isRoleName(displayName) || brandClaimedBy(displayName))) {
        hit("freemail-brand-name", 25,
            QStringLiteral("\"%1\" reads as a company address, but the mail comes from a "
                           "personal %2 mailbox").arg(displayName, fromOrg));
    }

    // Invisible characters wedged inside a word. There is no way to type this
    // by accident and no reason to: it exists to break up a brand name so that
    // neither the reader nor a filter sees the word that is there.
    if (hasInvisibleInsideWord(fromValue)) {
        hit("zero-width-obfuscation", 25,
            QStringLiteral("The sender's name hides invisible characters inside a word, "
                           "which is done to disguise it"));
    }

    // --- From domain ----------------------------------------------------
    // Taken from the raw header rather than from fromAddr, because the case
    // this most needs to see is the one addressOf() cannot parse: an address
    // literal ("admin@[203.0.113.55]") does not match the addr-spec pattern, so
    // going through the parsed address would leave the rule below unreachable.
    QString fromDomain = fromValue.section(QLatin1Char('@'), -1);
    fromDomain = fromDomain.remove(QLatin1Char('>')).remove(QLatin1Char('"')).trimmed().toLower();
    if (fromDomain == fromValue.trimmed().toLower())
        fromDomain.clear(); // no '@' at all — not an address
    if (!fromDomain.isEmpty()) {
        // A domain reaches us punycoded as often as not, and the whole point of
        // a homograph is how it looks once decoded — so decode before judging.
        // IgnoreIDNWhitelist because Qt otherwise leaves domains in TLDs it does
        // not vouch for in their ASCII form, which is exactly the case we are
        // trying to see through.
        const QString shown =
            QUrl::fromAce(fromDomain.toLatin1(), QUrl::IgnoreIDNWhitelist);
        if (hasConfusableLabel(shown.isEmpty() ? fromDomain : shown)) {
            hit("from-domain-confusable", 30,
                QStringLiteral("The sender's domain mixes alphabets within one name: "
                               "\"%1\" — a way of imitating a domain you trust")
                    .arg(shown.isEmpty() ? fromDomain : shown));
        }
        // A bare address literal as the sender's domain. Legitimate mail is
        // sent from named hosts; this is either a broken script or someone with
        // no domain to lose.
        if (fromDomain.startsWith(QLatin1Char('[')) || ipLiteralRe().match(fromDomain).hasMatch()) {
            hit("from-ip-literal", 25,
                QStringLiteral("The sender's address uses a bare IP address (%1) instead "
                               "of a domain name").arg(fromDomain));
        }
    }

    // --- Reply-To ------------------------------------------------------
    // Where a reply would go, which is the one thing here SPF has no opinion
    // about. Weak: measured over a real inbox it fires on 9% of ordinary mail,
    // because support desks, ticketing systems and mailing platforms all route
    // replies somewhere other than the From address. Weighted so it can only
    // ever corroborate — the case it is really reaching for is the one below,
    // where the reply lands in a personal mailbox.
    //
    // Silent when authentication passed: a message that proved it came from
    // where it claims has already answered this better than a header can.
    const QString listIdValue = firstValue(fields, QLatin1String("list-id"));
    const QString replyTo = firstValue(fields, QLatin1String("reply-to"));
    if (!replyTo.isEmpty() && !ctx.authPassed) {
        const QString replyOrg = organizationalDomainOf(addressOf(replyTo));
        if (!replyOrg.isEmpty() && !fromOrg.isEmpty() && replyOrg != fromOrg) {
            hit("reply-to-mismatch", 8,
                QStringLiteral("Replies would go to %1, not %2").arg(replyOrg, fromOrg));
        }
        // The business-email-compromise shape: the message presents as a
        // company, but a reply lands in a personal mailbox the attacker owns.
        // Stacked on the mismatch above it reaches Unsure, never Spam alone —
        // a small firm really does sometimes route replies to a gmail address.
        if (!replyOrg.isEmpty() && !fromOrg.isEmpty() && replyOrg != fromOrg
            && isFreemail(replyOrg) && !isFreemail(fromOrg)) {
            hit("freemail-reply-to", 20,
                QStringLiteral("The message presents as %1, but replies would go to a "
                               "personal %2 mailbox").arg(fromOrg, replyOrg));
        }
    }

    // Deliberately absent: "Return-Path names a different domain than From".
    //
    // It reads as the strongest of these rules — the envelope is written by the
    // receiving server and is not the sender's to choose — and it is the most
    // useless. A domain that lets a platform send for it says so in its own SPF
    // record, so mailin.fr posting for phish.id is that domain's published
    // policy being followed, not a discrepancy. The rule was asking a question
    // SPF had already answered, and answering it worse: it fired on 6% of a
    // real inbox, all of it ordinary platform mail.
    //
    // What it was meant to catch — a forged From over an envelope the attacker
    // could not forge — is exactly the case where SPF or DMARC fails, and
    // auth-fail already scores that at +35 on evidence rather than on inference.

    // --- Message-ID ----------------------------------------------------
    const QString msgid = firstValue(fields, QLatin1String("message-id"));
    if (msgid.isEmpty()) {
        hit("no-message-id", 18,
            QStringLiteral("No Message-ID — normal mail software always writes one"));
    } else {
        const int at = msgid.lastIndexOf(QLatin1Char('@'));
        QString midHostRaw = at > 0 ? msgid.mid(at + 1) : QString();
        midHostRaw.remove(QLatin1Char('>')).remove(QLatin1Char('"'));
        midHostRaw = midHostRaw.trimmed().toLower();
        // A Message-ID is supposed to be globally unique, which is why the
        // right-hand side is a domain. "@localhost" or a bare IP means it was
        // minted by something that never expected to leave the machine —
        // typically a script on a compromised host.
        if (at <= 0) {
            hit("msgid-malformed", 15,
                QStringLiteral("Message-ID has no domain part, which no normal mail "
                               "software produces"));
        } else if (midHostRaw == QLatin1String("localhost")
                   || midHostRaw.startsWith(QLatin1String("localhost."))
                   || ipLiteralRe().match(midHostRaw).hasMatch()) {
            hit("msgid-local", 15,
                QStringLiteral("Message-ID was issued by \"%1\" rather than a real "
                               "domain").arg(midHostRaw));
        }
        // Deliberately absent: "the Message-ID names a different domain than
        // From". Measured over a real mailbox it fired on 61% of ordinary
        // messages — every mailing platform mints ids on its own domain while
        // the sending domain authorises it in SPF, so mandrillapp.com issuing
        // an id for chcemvediet.sk is the system working, not a discrepancy.
        // A rule that fires on the majority of ham carries no information at
        // any weight, which is a reason to delete it rather than lower it.
    }

    // --- Relay chain ---------------------------------------------------
    const int received = countFields(fields, QLatin1String("received"));
    if (received == 0) {
        hit("no-received", 20,
            QStringLiteral("No Received headers — the message did not travel through "
                           "any mail server we can see"));
    } else if (received == 1 && receivedFromUnknownHost(firstValue(fields, QLatin1String("received")))) {
        // One hop, and the machine that handed it over had no name to give.
        // Legitimate mail crosses at least the sender's own outbound server
        // and ours, and that server introduces itself; this is the shape of a
        // script talking straight to a relay.
        hit("single-hop-unknown", 12,
            QStringLiteral("Delivered in one hop from a machine with no host name, "
                           "rather than through a sender's mail server"));
    }

    // --- Date skew -----------------------------------------------------
    // Compared against the topmost Received, which our own server wrote: a
    // sender can lie about Date but not about when we took delivery.
    const QString dateValue = firstValue(fields, QLatin1String("date"));
    const QString topReceived = firstValue(fields, QLatin1String("received"));
    // Date is mandatory in RFC 5322 and every mail client writes one. Weighted
    // like the missing Message-ID it usually travels with, rather than higher:
    // the two share a cause (a script that speaks just enough SMTP), so letting
    // both fire at full strength would be counting one fault twice.
    if (dateValue.isEmpty())
        hit("no-date", 15, QStringLiteral("No Date header, which every mail client writes"));
    if (!dateValue.isEmpty() && !topReceived.isEmpty()) {
        const QDateTime claimed = QDateTime::fromString(dateValue, Qt::RFC2822Date);
        const QString stamp = topReceived.section(QLatin1Char(';'), -1).trimmed();
        const QDateTime actual = QDateTime::fromString(stamp, Qt::RFC2822Date);
        if (claimed.isValid() && actual.isValid()) {
            const qint64 skewHours = qAbs(claimed.secsTo(actual)) / 3600;
            // Two days of slack: clock drift, batch senders and timezone-naive
            // software all produce small skews on perfectly good mail.
            if (skewHours > 48) {
                hit("date-skew", 15,
                    QStringLiteral("Date header is %1 hours away from when the message "
                                   "actually arrived").arg(skewHours));
            }
        }
    }

    // --- Subject -------------------------------------------------------
    // The raw value is kept alongside the decoded one for exactly one reader:
    // charset-mismatch needs the encoded-word's declared charset, and decoding
    // erases the declaration.
    const QString rawSubject = firstValue(fields, QLatin1String("subject"));
    const QString subject = decodeEncodedWords(rawSubject);
    if (!subject.isEmpty()) {
        // Bidi overrides let a subject render as something other than what it
        // says. There is no legitimate use of these in a subject line.
        static const QString bidiControls = QStringLiteral("\u202A\u202B\u202D\u202E\u2066\u2067\u2068\u202C\u2069");
        for (const QChar c : subject) {
            if (bidiControls.contains(c)) {
                hit("subject-bidi-override", 30,
                    QStringLiteral("Subject contains a text-direction override, which "
                                   "makes it display differently from what it says"));
                break;
            }
        }
        // Deliberate: this can pair with display-name-confusable (30+25), and
        // zero-width-obfuscation can fire in both the From line and here
        // (25+25) — the only combinations of non-decisive rules that reach the
        // threshold. Both are the same trick executed twice, and a sender who
        // obfuscates their name AND their subject has answered the question of
        // intent; ordinary multilingual mail cannot produce either pair, since
        // each side requires mixing scripts INSIDE one word or hiding
        // invisible characters inside one.
        if (hasConfusableWord(subject)) {
            hit("subject-confusable", 25,
                QStringLiteral("Subject mixes alphabets within a word — a common way to "
                               "imitate a brand name"));
        }
        // Shouting alone is tacky, not criminal; weighted so it can only ever
        // push something already suspicious over the line.
        int letters = 0;
        int upper = 0;
        for (const QChar c : subject) {
            if (!c.isLetter())
                continue;
            ++letters;
            if (c.isUpper())
                ++upper;
        }
        if (letters >= 12 && upper * 10 >= letters * 8)
            hit("subject-shouting", 6, QStringLiteral("Subject is almost entirely capitals"));
        if (hasInvisibleInsideWord(subject)) {
            hit("zero-width-obfuscation", 25,
                QStringLiteral("The subject hides invisible characters inside a word, which "
                               "is done to slip a word past a filter"));
        }
        // An encoded-word announcing a legacy code page while the text it
        // carries is plain ASCII. Encoding is pointless there — the only reason
        // to do it is that the raw words would be read by something on the way.
        // Only legacy charsets count: UTF-8 encoded-words around ASCII are
        // written by ordinary mail software all the time.
        const QString charset = encodedWordCharset(rawSubject);
        static const QSet<QString> legacy{
            QStringLiteral("gb2312"), QStringLiteral("gbk"),   QStringLiteral("big5"),
            QStringLiteral("koi8-r"), QStringLiteral("koi8-u"), QStringLiteral("euc-kr"),
            QStringLiteral("iso-2022-jp"), QStringLiteral("windows-1251"),
        };
        if (legacy.contains(charset)) {
            // Over the DECODED text. The raw form of an encoded word is ASCII
            // by construction, so testing it answered yes for every gb2312
            // subject including genuinely Chinese ones — the rule as first
            // written would have fired on ordinary mail in its own language.
            bool ascii = true;
            for (const QChar c : subject) {
                if (c.unicode() > 127) {
                    ascii = false;
                    break;
                }
            }
            if (ascii) {
                hit("charset-mismatch", 8,
                    QStringLiteral("Subject was encoded as %1 despite containing only plain "
                                   "text, which hides it from simple filters").arg(charset));
            }
        }
    }

    // --- Who it was addressed to ----------------------------------------
    // Both rules below are weak on purpose. Legitimate mail arrives bcc'd, via
    // aliases the account list does not know, and through mailing lists, so
    // neither may ever mark anything by itself.
    const QString toValue = firstValue(fields, QLatin1String("to"));
    const QString ccValue = firstValue(fields, QLatin1String("cc"));
    // An empty To, or the empty group ("undisclosed-recipients:;") that means
    // the same thing: no address at all, so there is nothing to be empty of.
    const bool noRecipient = !toValue.contains(QLatin1Char('@'));
    if (noRecipient && listIdValue.isEmpty()) {
        hit("undisclosed-recipients", 6,
            QStringLiteral("The message names no recipient at all"));
    } else if (!ctx.ownAddresses.isEmpty() && listIdValue.isEmpty()) {
        // Delivered-To is written by our own server with the address the
        // message was actually delivered for, so it answers the alias case that
        // the account list cannot.
        const QString delivered =
            normalizeAddress(addressOf(firstValue(fields, QLatin1String("delivered-to"))));
        const QString recipients = (toValue + QLatin1Char(' ') + ccValue).toLower();
        bool addressed = ctx.ownAddresses.contains(delivered);
        if (!addressed) {
            for (const QString &own : ctx.ownAddresses) {
                // Substring rather than a parse: the local part before any +tag
                // is what a To line spells, and getting this wrong only ever
                // costs a rule that should not have fired.
                if (!own.isEmpty() && recipients.contains(own)) {
                    addressed = true;
                    break;
                }
            }
        }
        if (!addressed) {
            hit("not-addressed-to-you", 8,
                QStringLiteral("None of your addresses appear in To or Cc"));
        }
    }

    // --- Bulk mail shape -----------------------------------------------
    // Read by the link rules below, where "this is list mail" changes what a
    // click-tracked link means.
    //
    // Deliberately absent: "bulk mail without a List-Unsubscribe" as a rule of
    // its own. Measured over a real mailbox it fired on 1.9% of ordinary mail
    // and 0% of junk — spam does not claim List-Id at all, while old but
    // legitimate notification systems send Precedence: bulk with no
    // unsubscribe header. A rule that fires only on ham is not weak, it is
    // inverted.
    const bool listId = hasField(fields, QLatin1String("list-id"));
    const bool unsub = hasField(fields, QLatin1String("list-unsubscribe"));
    const bool listMail = listId || unsub;

    // --- Attachments ----------------------------------------------------
    // Only reachable once a body has been parsed; at list-build time the head
    // says an attachment exists but not what it is called.
    if (msg.encryptedArchive) {
        // A password-protected archive exists to get past the scanner on the
        // way in, with the password in the message body for the reader. There
        // is no benign version of this in mail from a stranger, which is why it
        // is decisive where the rest of this section is not.
        hit("encrypted-archive", 50,
            QStringLiteral("Attached archive is password-protected, which hides its "
                           "contents from virus scanning"));
    }
    for (const QString &name : msg.attachmentNames) {
        if (hasDoubleExtension(name)) {
            hit("attachment-double-extension", 50,
                QStringLiteral("\"%1\" is a program named to look like a document")
                    .arg(name));
            break;
        }
        if (isDangerousAttachment(name)) {
            hit("attachment-executable", 45,
                QStringLiteral("\"%1\" is a program or disk image, not a document")
                    .arg(name));
            break;
        }
    }
    for (const QString &name : msg.attachmentNames) {
        // A web page delivered as a file. It is a credential-harvest form that
        // never travels over a link, so nothing on the way in gets to look at
        // the URL — the page only exists once the reader opens the attachment.
        // SVG belongs here too: it is markup that can carry script.
        static const QStringList pageExt{
            QStringLiteral("html"), QStringLiteral("htm"), QStringLiteral("shtml"),
            QStringLiteral("xhtml"), QStringLiteral("svg"), QStringLiteral("mhtml"),
        };
        const QString lower = name.trimmed().toLower();
        const int dot = lower.lastIndexOf(QLatin1Char('.'));
        if (dot >= 0 && pageExt.contains(lower.mid(dot + 1))) {
            hit("html-attachment", 30,
                QStringLiteral("\"%1\" is a web page sent as a file, which is how a fake "
                               "sign-in form avoids being checked as a link").arg(name));
            break;
        }
    }
    for (const QString &name : msg.attachmentNames) {
        if (isMacroDocument(name)) {
            // Real, but a colleague's spreadsheet far more often than an
            // attack, so it may corroborate and never mark on its own.
            hit("attachment-macro", 15,
                QStringLiteral("\"%1\" is an Office file that can contain macros")
                    .arg(name));
            break;
        }
    }

    // --- Body ----------------------------------------------------------
    // Every rule below is skipped when no body is available, which is the
    // normal case while the message list is being built. Nothing here is
    // load-bearing on its own.
    //
    // Deliberately absent: hidden text (font-size:0, display:none). It is the
    // textbook spam signal and also exactly how every marketing platform on
    // earth hides an inbox preheader, so it fires on a large fraction of
    // perfectly wanted mail. There is no weight at which it is worth having.
    if (!msg.html.isEmpty()) {
        const QString seen = visibleText(msg.html);
        static const QRegularExpression imgRe(QStringLiteral("<img\\b"),
                                              QRegularExpression::CaseInsensitiveOption);
        if (seen.size() < 80 && msg.html.contains(imgRe)) {
            hit("image-only", 12,
                QStringLiteral("Almost all of the message is one image, with no text a "
                               "filter could read"));
        }

        // A form asking for a password, inside an email. Whatever the sender
        // believes they are doing, no legitimate organisation collects a
        // password in a message body — the reader cannot see where it is being
        // sent and no browser address bar is involved.
        static const QRegularExpression passwordRe(
            QStringLiteral("<input\\b[^>]*type\\s*=\\s*[\"']?password"),
            QRegularExpression::CaseInsensitiveOption);
        if (msg.html.contains(passwordRe)) {
            hit("html-password-form", 40,
                QStringLiteral("The message contains a password box — a real sign-in page "
                               "is never inside an email"));
        }

        // --- Links -----------------------------------------------------
        // A brand cannot impersonate itself. Every link rule below asks some
        // form of "does this link name a brand it does not belong to", and the
        // answer is always no when the *sender* is that brand: Stripe linking
        // to stripecdn.com, Google to c.gle, whoever to whatever they call
        // their asset domain next year.
        //
        // This is the general form of the fix, and the table of alias domains
        // is only a fallback for the case it cannot cover — a brand's mail
        // arriving from a domain the table does not list either. An alias list
        // can never be complete, so nothing important may depend on it.
        //
        // Conditioned on authentication not having failed, which is what keeps
        // it from being a way in: a forged From claiming to be the brand is
        // exactly what auth-fail scores, and the exemption does not apply to it.
        const Brand *senderBrand = authFailed ? nullptr : brandClaimedBy(fromOrg);
        const auto linkBelongsToSender = [&](const QString &linkHost) {
            if (sameBrandFamily(fromOrg, linkHost))
                return true;
            if (!senderBrand)
                return false;
            // The test is on where the link *goes*, never on what it claims —
            // otherwise mail from a brand would exempt links to anywhere, which
            // is the opposite of what this is for. The name that decides is the
            // one label nobody but the domain's owner can choose: the label to
            // the left of the public suffix.
            //
            //   stripe.assets.stripecdn.test -> "stripecdn", starts with
            //     "stripe": Stripe's own infrastructure, whatever they named it
            //   google.com.evil-x1z.test     -> "evil-x1z": not Google's, no
            //     matter how much of "google.com" appears to its left
            //
            // Estimated as the second-to-last label rather than taken from the
            // Public Suffix List, because this has to hold when the list has
            // not loaded. On a two-part suffix ("stripecdn.co.uk") the estimate
            // is "co" and nothing is exempted — an under-report, which is the
            // direction that costs a missed exemption rather than a missed
            // phish.
            const QStringList labels = linkHost.split(QLatin1Char('.'), Qt::SkipEmptyParts);
            if (labels.size() < 2)
                return false;
            return labels.at(labels.size() - 2).startsWith(QString(senderBrand->token));
        };
        // Every link rule below feeds one capped group rather than scoring
        // directly. A message with two hundred links is not two hundred times
        // as suspicious as one with a single bad link, and letting these
        // accumulate freely would make any large newsletter reachable.
        QList<Hit> linkHits;
        QSet<QString> seenIds;
        auto linkHit = [&linkHits, &seenIds](const char *id, int weight, const QString &detail) {
            const QString key = QString::fromLatin1(id);
            if (seenIds.contains(key))
                return; // one instance of each kind is the whole evidence
            seenIds.insert(key);
            linkHits.append({key, weight, detail});
        };

        // An anchor whose *text* names a domain different from where it goes.
        // Only counted when the text is domain-shaped: ordinary link text
        // ("click here", a product name) says nothing either way.
        static const QRegularExpression anchorRe(
            QStringLiteral("<a\\b[^>]*href\\s*=\\s*[\"']?(https?://[^\"'\\s>]+)[\"']?[^>]*>(.*?)</a>"),
            QRegularExpression::CaseInsensitiveOption
                | QRegularExpression::DotMatchesEverythingOption);
        static const QRegularExpression domainTextRe(
            QStringLiteral("^(?:https?://)?([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)/?$"));
        // Not in list mail. Every mailing platform rewrites its links through
        // a click tracker, so in a newsletter "the text names one domain, the
        // href another" is how the mail was *built*, not a deception: measured
        // over a real inbox this pair of rules was 82%% of all residual noise
        // (gov.uk mail through Brevo's tracker, and so on), against zero
        // catches in the junk corpus that carried list headers. A phish that
        // adds fake list headers to buy this exemption gives up nothing it
        // was caught by — the password-form, attachment and credential-trick
        // rules do not read it.
        auto it = anchorRe.globalMatch(msg.html);
        while (!listMail && it.hasNext()) {
            const auto m = it.next();
            const QString shown = visibleText(m.captured(2));
            const auto dm = domainTextRe.match(shown);
            if (!dm.hasMatch())
                continue;
            const QString shownHost = dm.captured(1).toLower();
            const QString realHost = hostOfUrl(m.captured(1));
            const QString shownOrg = orgOfDomain(shownHost);
            const QString realOrg = orgOfDomain(realHost);
            if (!shownOrg.isEmpty() && !realOrg.isEmpty() && shownOrg != realOrg
                && !sameBrandFamily(shownHost, realHost)
                && !linkBelongsToSender(realHost)) {
                linkHit("link-text-mismatch", 25,
                        QStringLiteral("A link reading \"%1\" actually goes to %2")
                            .arg(shown, realOrg));
                break; // one is enough; ten of them is not ten times the evidence
            }
        }

        const QStringList urls = urlsIn(msg.html);
        for (const QString &url : urls) {
            if (urlHasUserinfo(url)) {
                linkHit("url-credential-trick", 30,
                        QStringLiteral("A link is written so that it appears to go somewhere "
                                       "other than %1").arg(orgOfDomain(hostOfUrl(url))));
            }
            const QString host = hostOfUrl(url);
            if (host.isEmpty())
                continue;
            if (ipLiteralRe().match(host).hasMatch()) {
                linkHit("url-ip-host", 20,
                        QStringLiteral("A link points at a bare IP address (%1) rather than a "
                                       "named site").arg(host));
                continue; // an IP has no org domain; the rules below need one
            }
            if (host.contains(QLatin1String("xn--"))) {
                const QString shown = QUrl::fromAce(host.toLatin1(), QUrl::IgnoreIDNWhitelist);
                if (!shown.isEmpty() && hasConfusableLabel(shown)) {
                    linkHit("url-punycode-brand", 25,
                            QStringLiteral("A link goes to \"%1\", a name built from two "
                                           "alphabets to look like one you trust").arg(shown));
                }
            }
            const QString linkOrg = orgOfDomain(host);
            if (isShortener(linkOrg) && !listMail && !sameBrandFamily(fromOrg, linkOrg)) {
                // Bulk senders use shorteners constantly, so this only counts
                // outside list mail, and even there it can never mark alone.
                linkHit("url-shortener", 8,
                        QStringLiteral("A link is hidden behind the %1 shortener, so where it "
                                       "goes cannot be seen").arg(linkOrg));
            }
            // A brand's name in the part of the host anyone can choose:
            // "paypal.com.secure-login.test" is not PayPal, and the label that
            // decides that is the registrable domain, not the prettiest one.
            if (host != linkOrg && !listMail) { // list mail: see the anchor loop
                const QString subdomain = host.left(host.size() - linkOrg.size());
                if (const Brand *b = brandClaimedBy(subdomain);
                    b && !brandOwns(*b, linkOrg) && !linkBelongsToSender(host)) {
                    linkHit("url-brand-subdomain", 25,
                            QStringLiteral("A link spells \"%1\" in its address but actually "
                                           "goes to %2").arg(QString(b->token), linkOrg));
                }
            }
        }

        // Strongest first, then at most two of them, then a ceiling. Three
        // separate link problems in one message is a strong signal; it is not
        // three times the signal of one.
        std::stable_sort(linkHits.begin(), linkHits.end(),
                         [](const Hit &a, const Hit &b) { return a.weight > b.weight; });
        const int linkGroupCap = AdvancedConfig::i("spam/linkGroupCap");
        int linkTotal = 0;
        for (qsizetype i = 0; i < linkHits.size() && i < 2; ++i) {
            const Hit &h = linkHits.at(i);
            const int room = linkGroupCap - linkTotal;
            if (room <= 0)
                break;
            const int weight = qMin(h.weight, room);
            out.hits.append({h.id, weight, h.detail});
            out.total += weight;
            linkTotal += weight;
        }
    }

    // A message whose plain-text alternative says nothing while the HTML says
    // everything. Real multipart mail keeps the two in step; splitting them is
    // a way of showing a filter one message and the reader another.
    if (!msg.html.isEmpty() && !msg.text.isEmpty()) {
        const QString seenHtml = visibleText(msg.html);
        if (msg.text.simplified().size() < 40 && seenHtml.size() > 400) {
            hit("text-html-divergence", 10,
                QStringLiteral("The plain-text copy of this message is nearly empty while "
                               "the formatted one is not"));
        }
    }

    out.verdict = out.total >= spamThreshold()  ? Verdict::Spam
        : out.total >= UnsureThreshold        ? Verdict::Unsure
                                              : Verdict::Ham;
    return out;
}

} // namespace SpamHeuristics
