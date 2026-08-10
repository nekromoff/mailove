// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "spamheuristics.h"

#include "publicsuffixlist.h"

#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QUrl>

namespace SpamHeuristics
{

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
    QStringList lines;
    for (const Hit &h : hits)
        lines.append(QStringLiteral("%1 (%2)").arg(h.detail).arg(h.weight, 0, 10));
    return lines.join(QLatin1Char('\n'));
}

Score score(const Message &msg, const Context &ctx)
{
    Score out;
    const QList<Field> fields = parseHead(msg.head);

    const QString fromValue = firstValue(fields, QLatin1String("from"));
    const QString fromAddr = addressOf(fromValue);
    const QString fromOrg = organizationalDomainOf(fromAddr);

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
    if (ctx.knownCorrespondent && !ctx.authFailed && !ctx.alwaysScore) {
        out.exempt = true;
        out.verdict = Verdict::Ham;
        out.exemptReason = QStringLiteral("You have sent mail to %1.").arg(fromAddr);
        return out;
    }

    auto hit = [&out](const char *id, int weight, const QString &detail) {
        out.hits.append({QString::fromLatin1(id), weight, detail});
        out.total += weight;
    };

    // --- Authentication ------------------------------------------------
    if (ctx.knownCorrespondent && ctx.authFailed) {
        // Decisive on its own: forging an address the user actually corresponds
        // with is targeted, not incidental.
        hit("known-contact-spoofed", 60,
            QStringLiteral("Claims to be %1, whom you have written to, but sender "
                           "authentication failed — the address is probably forged")
                .arg(fromAddr));
    } else if (ctx.authFailed) {
        hit("auth-fail", 35,
            QStringLiteral("Receiving server reported an SPF/DKIM/DMARC failure"));
    }
    // --- Familiarity ---------------------------------------------------
    // "We have had mail from this domain for a long time" — the signal that
    // covers everything knownCorrespondent cannot, because the user never
    // writes back to their bank. Volume *and* age are both required: a single
    // spam run can put fifty messages from one domain in the cache in an
    // afternoon, but it cannot make them two months old.
    constexpr int familiarCount = 20;
    constexpr int familiarDays = 60;
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
    if (ctx.authPassed && !ctx.authFailed) {
        if (familiarOrg) {
            hit("auth-pass-familiar", -25,
                QStringLiteral("Sender authentication passed, and %1").arg(familiarDetail));
        } else {
            hit("auth-pass", -8,
                QStringLiteral("Sender authentication passed, but %1 is not a domain "
                               "you have heard from before").arg(fromOrg));
        }
    } else if (familiarOrg && !ctx.authFailed) {
        // No verdict either way, but the history stands on its own.
        hit("familiar-domain", -15, familiarDetail);
    } else if (familiarOrg && ctx.authFailed) {
        // The domain is one the user really does get mail from, and this
        // message failed authentication while claiming to be it. Together with
        // auth-fail above this reaches the threshold, which is the intent:
        // forging a domain someone actually receives from is targeted.
        hit("familiar-domain-spoofed", 25,
            QStringLiteral("Claims to be %1, which you do have a history with, but "
                           "sender authentication failed").arg(fromOrg));
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
    const QString displayName = displayNameOf(fromValue);
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
    // Only meaningful when authentication did not pass: plenty of legitimate
    // senders route replies elsewhere (support desks, mailing lists), so on its
    // own this is weak and must never be able to mark anything.
    const QString replyTo = firstValue(fields, QLatin1String("reply-to"));
    if (!replyTo.isEmpty() && !ctx.authPassed) {
        const QString replyOrg = organizationalDomainOf(addressOf(replyTo));
        if (!replyOrg.isEmpty() && !fromOrg.isEmpty() && replyOrg != fromOrg) {
            hit("reply-to-mismatch", 12,
                QStringLiteral("Replies would go to %1, not %2").arg(replyOrg, fromOrg));
        }
    }

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
        if (at > 0) {
            const QString midOrg = orgOfDomain(midHostRaw);
            if (!midOrg.isEmpty() && !fromOrg.isEmpty() && midOrg != fromOrg && !ctx.authPassed) {
                hit("msgid-domain-mismatch", 8,
                    QStringLiteral("Message-ID was issued by %1, not %2").arg(midOrg, fromOrg));
            }
        }
    }

    // --- Relay chain ---------------------------------------------------
    const int received = countFields(fields, QLatin1String("received"));
    if (received == 0) {
        hit("no-received", 20,
            QStringLiteral("No Received headers — the message did not travel through "
                           "any mail server we can see"));
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
    const QString subject = firstValue(fields, QLatin1String("subject"));
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
    }

    // --- Bulk mail shape -----------------------------------------------
    const bool listId = hasField(fields, QLatin1String("list-id"));
    const bool unsub = hasField(fields, QLatin1String("list-unsubscribe"));
    const QString precedence = firstValue(fields, QLatin1String("precedence")).toLower();
    if ((listId || precedence == QLatin1String("bulk")) && !unsub) {
        hit("bulk-no-unsubscribe", 10,
            QStringLiteral("Sent as bulk mail but offers no List-Unsubscribe header"));
    }

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

        // An anchor whose *text* names a domain different from where it goes.
        // Only counted when the text is domain-shaped: ordinary link text
        // ("click here", a product name) says nothing either way.
        static const QRegularExpression anchorRe(
            QStringLiteral("<a\\b[^>]*href\\s*=\\s*[\"']?(https?://[^\"'\\s>]+)[\"']?[^>]*>(.*?)</a>"),
            QRegularExpression::CaseInsensitiveOption
                | QRegularExpression::DotMatchesEverythingOption);
        static const QRegularExpression domainTextRe(
            QStringLiteral("^(?:https?://)?([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)/?$"));
        auto it = anchorRe.globalMatch(msg.html);
        while (it.hasNext()) {
            const auto m = it.next();
            const QString shown = visibleText(m.captured(2));
            const auto dm = domainTextRe.match(shown);
            if (!dm.hasMatch())
                continue;
            const QString shownOrg = orgOfDomain(dm.captured(1).toLower());
            const QString realOrg = orgOfDomain(hostOfUrl(m.captured(1)));
            if (!shownOrg.isEmpty() && !realOrg.isEmpty() && shownOrg != realOrg) {
                hit("link-text-mismatch", 25,
                    QStringLiteral("A link reading \"%1\" actually goes to %2")
                        .arg(shown, realOrg));
                break; // one is enough; ten of them is not ten times the evidence
            }
        }
    }

    out.verdict = out.total >= SpamThreshold  ? Verdict::Spam
        : out.total >= UnsureThreshold        ? Verdict::Unsure
                                              : Verdict::Ham;
    return out;
}

} // namespace SpamHeuristics
