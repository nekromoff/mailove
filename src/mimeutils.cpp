// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "mimeutils.h"

#include "attachmentstore.h"

#include <QHash>
#include <QLocale>
#include <QRegularExpression>
#include <QTimeZone>
#include <QStringDecoder>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextFragment>
#include <QUrl>
#include <QUuid>

#include <kmime/content.h>
#include <kmime/headers.h>
#include <kmime/message.h>
#include <kmime/util.h>

#include <utility>

namespace MimeUtils
{

KMime::Content *findPartByType(KMime::Content *root, const char *mimeType)
{
    if (const auto *ct = std::as_const(*root).contentType(); ct && ct->isMimeType(mimeType))
        return root;
    const auto children = root->contents();
    for (KMime::Content *child : children) {
        if (KMime::Content *found = findPartByType(child, mimeType))
            return found;
    }
    return nullptr;
}

void walkParts(KMime::Content *node, const QString &prefix,
               const std::function<void(KMime::Content *, const QString &)> &fn)
{
    const auto children = node->contents();
    for (int i = 0; i < children.size(); ++i) {
        const QString id = prefix.isEmpty() ? QString::number(i + 1)
                                            : prefix + QLatin1Char('.') + QString::number(i + 1);
        fn(children.at(i), id);
        walkParts(children.at(i), id, fn);
    }
}

bool isAttachmentPart(KMime::Content *part)
{
    if (!part->contents().isEmpty())
        return false; // a container, not a payload
    const auto *cd = std::as_const(*part).contentDisposition();
    if (cd && cd->disposition() == KMime::Headers::CDattachment)
        return true;
    // Inline images referenced by HTML mail are attachments for our purposes:
    // they are big, binary, and repeat across every message in a newsletter.
    return cd && !cd->filename().isEmpty();
}

QList<MailStore::PartRef> stripAttachments(KMime::Message *msg)
{
    QList<MailStore::PartRef> lifted;
    walkParts(msg, QString(), [&lifted](KMime::Content *part, const QString &id) {
        if (!isAttachmentPart(part))
            return;
        const QByteArray decoded = part->decodedBody();
        if (decoded.size() < AttachmentStore::externalizeThreshold())
            return; // small enough that a file of its own would cost more
        const AttachmentStore::Stored stored = AttachmentStore::put(decoded);
        if (stored.hash.isEmpty())
            return; // could not write it; leave the payload where it is
        MailStore::PartRef ref;
        ref.partId = id;
        ref.hash = stored.hash;
        ref.size = stored.size;
        ref.stored = stored.stored;
        ref.codec = stored.codec;
        const auto *cd = std::as_const(*part).contentDisposition();
        ref.filename = cd ? cd->filename() : QString();
        if (const auto *ct = std::as_const(*part).contentType())
            ref.mime = QString::fromLatin1(ct->mimeType());
        lifted.append(ref);
        part->setBody({});
        lifted.last().partId = id;
    });
    return lifted;
}

bool restoreAttachments(KMime::Message *msg, const QList<MailStore::PartRef> &parts)
{
    if (parts.isEmpty())
        return true;
    QHash<QString, const MailStore::PartRef *> byId;
    for (const auto &p : parts)
        byId.insert(p.partId, &p);
    bool complete = true;
    walkParts(msg, QString(), [&byId, &complete](KMime::Content *part, const QString &id) {
        const auto it = byId.constFind(id);
        if (it == byId.cend())
            return;
        const QByteArray payload = AttachmentStore::get((*it)->hash, (*it)->codec);
        if (payload.isEmpty()) {
            complete = false;
            return;
        }
        if (auto *cte = part->contentTransferEncoding())
            cte->setEncoding(KMime::Headers::CEbinary);
        part->setBody(payload);
    });
    return complete;
}

/// True when the leading run of the body (whitespace aside) is drawn from the
/// base64 alphabet. Only the first 512 significant bytes are read: raw text
/// or HTML fails within the first line, and a genuine base64 body cannot
/// contain anything else at any point, so nothing is gained by reading on.
static bool looksLikeBase64(const QByteArray &body)
{
    int seen = 0;
    for (const char c : body) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            continue;
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        if (!ok)
            return false;
        if (++seen >= 512)
            break;
    }
    return true;
}

void repairTransferEncodings(KMime::Content *node)
{
    if (!node)
        return;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children)
            repairTransferEncodings(child);
        return;
    }
    if (!node->hasHeader("Content-Transfer-Encoding"))
        return;
    auto *cte = node->contentTransferEncoding();
    if (!cte || cte->encoding() != KMime::Headers::CEbase64)
        return;
    const QByteArray body = node->body();
    if (body.isEmpty() || looksLikeBase64(body))
        return;
    // Two things, because KMime undoes each on its own: the header object,
    // and then setBody() with the very same bytes, which drops the decoded
    // body KMime keeps from the first read. Both allowed on a frozen message,
    // whose encodedContent() still answers with the wire — the head text is
    // deliberately not rewritten, because that IS the wire for the DKIM
    // verdict and the cache. The price is that parse() would rebuild the
    // header from the head text and undo this; parseIfNeeded() exists so no
    // consumer parses an already-parsed message.
    cte->setEncoding(KMime::Headers::CEbinary);
    node->setBody(body);
}

/// The raw, unfolded value of \a field from a message's own head text — the
/// bytes as they arrived, before KMime read a charset off them. Empty when the
/// head does not carry the field.
static QByteArray rawHeaderValue(const QByteArray &head, QByteArrayView field)
{
    int pos = 0;
    while (pos < head.size()) {
        int end = head.indexOf('\n', pos);
        if (end < 0)
            end = head.size();
        const QByteArrayView line = QByteArrayView(head).sliced(pos, end - pos);
        // "Subject:" at the start of a line, case-insensitively — a folded
        // continuation begins with whitespace and can never match.
        if (line.size() > field.size()
            && QByteArrayView(line).first(field.size()).compare(field, Qt::CaseInsensitive) == 0
            && line.at(field.size()) == ':') {
            QByteArray value = line.sliced(field.size() + 1).toByteArray();
            // Unfold: a continuation line is joined with the space that folded
            // it, which is what keeps an encoded word split across two lines
            // readable as one.
            int next = end + 1;
            while (next < head.size() && (head.at(next) == ' ' || head.at(next) == '\t')) {
                int lineEnd = head.indexOf('\n', next);
                if (lineEnd < 0)
                    lineEnd = head.size();
                value += QByteArrayView(head).sliced(next, lineEnd - next).toByteArray();
                next = lineEnd + 1;
            }
            return value.trimmed();
        }
        pos = end + 1;
    }
    return {};
}

/// The bytes an encoded word carries, whichever of the two encodings it used.
static QByteArray encodedWordPayload(QChar encoding, const QByteArray &text)
{
    if (encoding == QLatin1Char('B') || encoding == QLatin1Char('b'))
        return QByteArray::fromBase64(text);
    // Q: "_" is a space, "=XX" is a byte, everything else stands for itself.
    QByteArray out;
    out.reserve(text.size());
    for (int i = 0; i < text.size(); ++i) {
        const char c = text.at(i);
        if (c == '_') {
            out += ' ';
        } else if (c == '=' && i + 2 < text.size()) {
            bool ok = false;
            const int byte = text.mid(i + 1, 2).toInt(&ok, 16);
            if (!ok)
                return {};
            out += char(byte);
            i += 2;
        } else {
            out += c;
        }
    }
    return out;
}

/// Whether \a bytes are UTF-8 and say something a label of \a charset could
/// not: at least one multi-byte sequence. Pure ASCII is left alone — every
/// charset agrees about it, so there is nothing to correct and no evidence
/// that anything is wrong.
static bool looksLikeUtf8(const QByteArray &bytes)
{
    bool highBytes = false;
    for (const char c : bytes) {
        if (uchar(c) >= 0x80) {
            highBytes = true;
            break;
        }
    }
    if (!highBytes)
        return false;
    QStringDecoder decoder(QStringDecoder::Utf8, QStringDecoder::Flag::Stateless);
    const QString text = decoder(bytes);
    return !decoder.hasError() && !text.contains(QChar::ReplacementCharacter);
}

/// Rewrites the charset of every encoded word in \a value that lies about what
/// it carries. Returns an empty array when none does — the ordinary case,
/// which the caller answers without re-decoding anything.
static QByteArray repairEncodedWordCharsets(const QByteArray &value)
{
    // charset (with an optional *language suffix), encoding, payload.
    static const QRegularExpression wordRe(
        QStringLiteral("=\\?([^?\\s]+)\\?([QqBb])\\?([^?]*)\\?="));
    QString text = QString::fromLatin1(value); // ASCII by construction
    bool changed = false;
    QString out;
    int last = 0;
    auto it = wordRe.globalMatch(text);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        const QString label = m.captured(1);
        const QString charset = label.section(QLatin1Char('*'), 0, 0).toLower();
        // A word that already says UTF-8 has nothing to correct, and one whose
        // charset KMime does not know already falls back to UTF-8 on its own.
        if (charset == QLatin1String("utf-8") || charset == QLatin1String("utf8"))
            continue;
        if (!QStringDecoder(charset.toLatin1().constData()).isValid())
            continue;
        const QByteArray payload =
            encodedWordPayload(m.captured(2).at(0), m.captured(3).toLatin1());
        if (payload.isEmpty() || !looksLikeUtf8(payload))
            continue;
        // The bytes are UTF-8 and the label says otherwise. Decoded under the
        // label they are either mojibake or replacement characters; decoded as
        // what they are, they are the words the sender wrote.
        const QString lang = label.contains(QLatin1Char('*'))
            ? QLatin1Char('*') + label.section(QLatin1Char('*'), 1)
            : QString();
        out += text.sliced(last, m.capturedStart(1) - last);
        out += QStringLiteral("utf-8") + lang;
        last = m.capturedEnd(1);
        changed = true;
    }
    if (!changed)
        return {};
    out += text.sliced(last);
    return out.toLatin1();
}

QString repairedHeaderText(const KMime::Message *msg, QByteArrayView field,
                           const QString &decoded)
{
    if (!msg)
        return decoded;
    const QByteArray raw = rawHeaderValue(msg->head(), field);
    if (raw.isEmpty())
        return decoded;
    const QByteArray repaired = repairEncodedWordCharsets(raw);
    if (repaired.isEmpty())
        return decoded;
    // Decoded by KMime again rather than by hand: the whitespace rules between
    // adjacent encoded words are its business, and this way a repaired header
    // reads exactly as an honestly labelled one would.
    KMime::Headers::Generics::Unstructured header;
    header.from7BitString(repaired);
    const QString text = header.asUnicodeString();
    return text.isEmpty() ? decoded : text;
}

void parseIfNeeded(KMime::Content *node)
{
    if (!node)
        return;
    if (!node->contents().isEmpty())
        return;
    const auto *ct = std::as_const(*node).contentType();
    const bool container = ct && (ct->isMultipart() || ct->isMimeType("message/rfc822"));
    if (container)
        node->parse();
}

void collectBodies(KMime::Content *node, QString *text, QString *html)
{
    if (!node)
        return;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children)
            collectBodies(child, text, html);
        return;
    }
    const QByteArray mime =
        node->contentType() ? node->contentType()->mimeType().toLower() : QByteArray();
    if (mime == "text/html" && html->isEmpty())
        *html = node->decodedText();
    else if (mime == "text/plain" && text->isEmpty())
        *text = node->decodedText();
}

void collectAttachments(KMime::Content *node, QStringList *names)
{
    if (!node)
        return;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children)
            collectAttachments(child, names);
        return;
    }
    QString name;
    if (auto *cd = node->contentDisposition(); cd && !cd->filename().isEmpty())
        name = cd->filename();
    else if (auto *ct = node->contentType(); ct && !ct->name().isEmpty())
        name = ct->name();
    // A nameless calendar part is still the invitation the reader is being
    // asked to accept — listed under the name the reading pane gives it.
    if (name.isEmpty() && isCalendarPart(node))
        name = QStringLiteral("invitation.ics");
    if (!name.isEmpty())
        names->append(name);
}

bool isCalendarPart(KMime::Content *part)
{
    if (!part || !part->contents().isEmpty())
        return false;
    if (const auto *ct = std::as_const(*part).contentType()) {
        const QByteArray mime = ct->mimeType().toLower();
        if (mime == "text/calendar" || mime == "application/ics")
            return true;
    }
    QString name;
    if (const auto *cd = std::as_const(*part).contentDisposition())
        name = cd->filename();
    if (name.isEmpty()) {
        if (const auto *ct = std::as_const(*part).contentType())
            name = ct->name();
    }
    return name.endsWith(QLatin1String(".ics"), Qt::CaseInsensitive);
}

KMime::Content *findCalendarPart(KMime::Content *root)
{
    if (!root)
        return nullptr;
    if (isCalendarPart(root))
        return root;
    const auto children = root->contents();
    for (KMime::Content *child : children) {
        if (KMime::Content *found = findCalendarPart(child))
            return found;
    }
    return nullptr;
}

QList<KMime::Content *> attachmentParts(KMime::Content *root)
{
    QList<KMime::Content *> out;
    if (!root)
        return out;
    const auto listed = root->attachments();
    // Walk the tree rather than appending to KMime's list, so a calendar
    // part keeps its place among the files around it.
    std::function<void(KMime::Content *)> walk = [&](KMime::Content *node) {
        const auto children = node->contents();
        if (!children.isEmpty()) {
            for (KMime::Content *child : children)
                walk(child);
            return;
        }
        if (listed.contains(node) || isCalendarPart(node))
            out.append(node);
    };
    walk(root);
    return out;
}

namespace
{
/// One iCalendar content line, unfolded: NAME;PARAM=V;PARAM="q:v":VALUE.
struct IcsLine {
    QString name;
    QHash<QString, QString> params; // upper-case names
    QString value;
};

/// Splits a content line at the first ':' outside double quotes; parameter
/// values may be quoted and carry ':' ("CN="Room: 2nd floor"").
IcsLine parseIcsLine(const QString &line)
{
    IcsLine out;
    bool quoted = false;
    int colon = -1;
    for (int i = 0; i < line.size(); ++i) {
        const QChar c = line.at(i);
        if (c == QLatin1Char('"'))
            quoted = !quoted;
        else if (c == QLatin1Char(':') && !quoted) {
            colon = i;
            break;
        }
    }
    const QString head = colon < 0 ? line : line.left(colon);
    out.value = colon < 0 ? QString() : line.mid(colon + 1);
    // NAME;P=V;P=V — the same quote rule for the ';' between parameters.
    QStringList pieces;
    QString cur;
    quoted = false;
    for (const QChar c : head) {
        if (c == QLatin1Char('"'))
            quoted = !quoted;
        if (c == QLatin1Char(';') && !quoted) {
            pieces.append(cur);
            cur.clear();
        } else {
            cur.append(c);
        }
    }
    pieces.append(cur);
    out.name = pieces.takeFirst().trimmed().toUpper();
    for (const QString &p : std::as_const(pieces)) {
        const int eq = p.indexOf(QLatin1Char('='));
        if (eq <= 0)
            continue;
        QString v = p.mid(eq + 1);
        if (v.size() >= 2 && v.startsWith(QLatin1Char('"')) && v.endsWith(QLatin1Char('"')))
            v = v.mid(1, v.size() - 2);
        out.params.insert(p.left(eq).trimmed().toUpper(), v);
    }
    return out;
}

/// RFC 5545 §3.3.11 text unescaping.
QString unescapeIcsText(const QString &text)
{
    QString out;
    out.reserve(text.size());
    for (int i = 0; i < text.size(); ++i) {
        const QChar c = text.at(i);
        if (c != QLatin1Char('\\') || i + 1 >= text.size()) {
            out.append(c);
            continue;
        }
        const QChar n = text.at(++i);
        if (n == QLatin1Char('n') || n == QLatin1Char('N'))
            out.append(QLatin1Char('\n'));
        else
            out.append(n); // \, \; \\ — the character itself
    }
    return out;
}

/// "CN=Name:mailto:addr" → "Name <addr>"; a bare address stays itself.
QString icsPerson(const IcsLine &line)
{
    QString addr = line.value.trimmed();
    if (addr.startsWith(QLatin1String("mailto:"), Qt::CaseInsensitive))
        addr = addr.mid(7);
    const QString name = line.params.value(QStringLiteral("CN")).trimmed();
    if (name.isEmpty() || name.compare(addr, Qt::CaseInsensitive) == 0)
        return addr;
    if (addr.isEmpty())
        return name;
    return name + QLatin1String(" <") + addr + QLatin1Char('>');
}

/// The zone a TZID names: IANA first, then Exchange's Windows names.
QTimeZone zoneFor(const QString &tzid)
{
    if (tzid.isEmpty())
        return {};
    QTimeZone zone(tzid.toUtf8());
    if (zone.isValid())
        return zone;
    const QByteArray iana = QTimeZone::windowsIdToDefaultIanaId(tzid.toUtf8());
    if (!iana.isEmpty()) {
        zone = QTimeZone(iana);
        if (zone.isValid())
            return zone;
    }
    return {};
}

/// DTSTART/DTEND in any of their shapes: 20261014T100000Z (UTC),
/// 20261014T100000 with a TZID or floating, 20261014 (date only).
QDateTime icsDateTime(const IcsLine &line, bool *allDay, QString *tzid)
{
    const QString v = line.value.trimmed();
    if (line.params.value(QStringLiteral("VALUE")).compare(QLatin1String("DATE"),
                                                           Qt::CaseInsensitive) == 0
        || (v.size() == 8 && !v.contains(QLatin1Char('T')))) {
        const QDate d = QDate::fromString(v.left(8), QStringLiteral("yyyyMMdd"));
        if (allDay)
            *allDay = true;
        return d.isValid() ? QDateTime(d, QTime(0, 0)) : QDateTime();
    }
    const bool utc = v.endsWith(QLatin1Char('Z'));
    const QDateTime naive = QDateTime::fromString(utc ? v.chopped(1) : v,
                                                  QStringLiteral("yyyyMMddTHHmmss"));
    if (!naive.isValid())
        return {};
    if (utc)
        return QDateTime(naive.date(), naive.time(), QTimeZone::UTC).toLocalTime();
    const QString id = line.params.value(QStringLiteral("TZID"));
    if (tzid && !id.isEmpty())
        *tzid = id;
    const QTimeZone zone = zoneFor(id);
    if (zone.isValid())
        return QDateTime(naive.date(), naive.time(), zone).toLocalTime();
    return QDateTime(naive.date(), naive.time()); // floating, or a zone nobody knows
}

QString whenText(const CalendarInvite &invite)
{
    const QLocale locale;
    if (!invite.start.isValid())
        return {};
    if (invite.allDay) {
        // DTEND of an all-day event is the day after the last one.
        const QDate last = invite.end.isValid() ? invite.end.date().addDays(-1)
                                                : invite.start.date();
        if (last <= invite.start.date())
            return locale.toString(invite.start.date(), QLocale::LongFormat);
        return locale.toString(invite.start.date(), QLocale::LongFormat)
            + QStringLiteral(" \u2013 ") + locale.toString(last, QLocale::LongFormat);
    }
    const QString day = locale.toString(invite.start.date(), QLocale::LongFormat);
    const QString from = locale.toString(invite.start.time(), QLocale::ShortFormat);
    if (!invite.end.isValid())
        return day + QStringLiteral(", ") + from;
    const QString to = locale.toString(invite.end.time(), QLocale::ShortFormat);
    if (invite.end.date() == invite.start.date())
        return day + QStringLiteral(", ") + from + QStringLiteral(" \u2013 ") + to;
    return day + QStringLiteral(", ") + from + QStringLiteral(" \u2013 ")
        + locale.toString(invite.end.date(), QLocale::LongFormat) + QStringLiteral(", ") + to;
}

QString inviteHeading(const CalendarInvite &invite)
{
    if (invite.method == QLatin1String("CANCEL"))
        return QStringLiteral("Cancelled: ");
    if (invite.method == QLatin1String("REPLY"))
        return QStringLiteral("Reply to invitation: ");
    if (invite.method == QLatin1String("REQUEST"))
        return QStringLiteral("Invitation: ");
    return QStringLiteral("Event: ");
}

/// A person as "Name <addr>" → "Name" linked to mailto:addr, escaped.
QString personHtml(const QString &person)
{
    const int lt = person.lastIndexOf(QLatin1Char('<'));
    QString name = person;
    QString addr;
    if (lt >= 0 && person.endsWith(QLatin1Char('>'))) {
        name = person.left(lt).trimmed();
        addr = person.mid(lt + 1, person.size() - lt - 2).trimmed();
    } else if (person.contains(QLatin1Char('@')) && !person.contains(QLatin1Char(' '))) {
        addr = person;
    }
    QString suffix;
    if (name.endsWith(QLatin1String(" (optional)"))) {
        name.chop(11);
        suffix = QStringLiteral(" <span style=\"opacity:0.7\">(optional)</span>");
    }
    if (addr.isEmpty() || !addr.contains(QLatin1Char('@')))
        return name.toHtmlEscaped() + suffix;
    return QStringLiteral("<a href=\"mailto:%1\">%2</a>%3")
        .arg(QString::fromLatin1(QUrl::toPercentEncoding(addr, "@.+-_")), name.toHtmlEscaped(),
             suffix);
}
} // namespace

CalendarInvite parseCalendarInvite(const QByteArray &ics)
{
    CalendarInvite out;
    // Unfold: a line starting with a space or tab continues the previous one.
    QString text = QString::fromUtf8(ics);
    text.replace(QLatin1String("\r\n"), QLatin1String("\n"));
    text.replace(QLatin1String("\n "), QString());
    text.replace(QLatin1String("\n\t"), QString());
    bool inEvent = false;
    bool done = false;
    for (const QString &raw : text.split(QLatin1Char('\n'))) {
        if (raw.isEmpty() || done)
            continue;
        const IcsLine line = parseIcsLine(raw);
        if (!inEvent) {
            if (line.name == QLatin1String("METHOD"))
                out.method = line.value.trimmed().toUpper();
            else if (line.name == QLatin1String("BEGIN")
                     && line.value.trimmed().compare(QLatin1String("VEVENT"),
                                                     Qt::CaseInsensitive) == 0) {
                inEvent = true;
                out.valid = true;
            }
            continue;
        }
        if (line.name == QLatin1String("END")
            && line.value.trimmed().compare(QLatin1String("VEVENT"), Qt::CaseInsensitive) == 0) {
            done = true; // the first event only; METHOD may still follow, rarely
            inEvent = false;
            continue;
        }
        if (line.name == QLatin1String("SUMMARY"))
            out.summary = unescapeIcsText(line.value).trimmed();
        else if (line.name == QLatin1String("LOCATION"))
            out.location = unescapeIcsText(line.value).trimmed();
        else if (line.name == QLatin1String("DESCRIPTION"))
            out.description = unescapeIcsText(line.value).trimmed();
        else if (line.name == QLatin1String("ORGANIZER"))
            out.organizer = icsPerson(line);
        else if (line.name == QLatin1String("ATTENDEE")) {
            QString who = icsPerson(line);
            if (line.params.value(QStringLiteral("ROLE")).compare(QLatin1String("OPT-PARTICIPANT"),
                                                                  Qt::CaseInsensitive) == 0)
                who += QStringLiteral(" (optional)");
            if (!who.isEmpty())
                out.attendees.append(who);
        } else if (line.name == QLatin1String("DTSTART"))
            out.start = icsDateTime(line, &out.allDay, &out.timeZone);
        else if (line.name == QLatin1String("DTEND"))
            out.end = icsDateTime(line, nullptr, nullptr);
    }
    return out;
}

QString calendarInviteHtml(const CalendarInvite &invite)
{
    if (!invite.valid)
        return {};
    const QString title = inviteHeading(invite)
        + (invite.summary.isEmpty() ? QStringLiteral("(no title)") : invite.summary);
    QString rows;
    auto row = [&rows](const QString &label, const QString &valueHtml) {
        if (valueHtml.isEmpty())
            return;
        rows += QStringLiteral("<tr><td style=\"color:#666;padding:2px 1em 2px 0;"
                               "vertical-align:top;white-space:nowrap\">%1</td>"
                               "<td style=\"padding:2px 0\">%2</td></tr>")
                    .arg(label, valueHtml);
    };
    row(QStringLiteral("When"), whenText(invite).toHtmlEscaped());
    row(QStringLiteral("Where"), invite.location.toHtmlEscaped());
    row(QStringLiteral("Organizer"), invite.organizer.isEmpty() ? QString()
                                                                 : personHtml(invite.organizer));
    QStringList people;
    for (const QString &a : invite.attendees)
        people.append(personHtml(a));
    row(QStringLiteral("Attendees"), people.join(QStringLiteral("<br>")));
    QString html = QStringLiteral(
        "<div style=\"font-family:sans-serif;border:1px solid #c8c8c8;border-radius:6px;"
        "padding:12px 14px;margin:0 0 14px 0;max-width:44em\">"
        "<div style=\"font-size:1.1em;font-weight:bold;margin-bottom:8px\">%1</div>"
        "<table style=\"border-collapse:collapse\">%2</table>")
        .arg(title.toHtmlEscaped(), rows);
    if (!invite.description.isEmpty()) {
        html += QStringLiteral("<div style=\"margin-top:10px;white-space:pre-wrap\">%1</div>")
            .arg(invite.description.toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    return html;
}

QString calendarInviteText(const CalendarInvite &invite)
{
    if (!invite.valid)
        return {};
    QStringList lines;
    lines << inviteHeading(invite)
            + (invite.summary.isEmpty() ? QStringLiteral("(no title)") : invite.summary);
    if (const QString when = whenText(invite); !when.isEmpty())
        lines << QStringLiteral("When: ") + when;
    if (!invite.location.isEmpty())
        lines << QStringLiteral("Where: ") + invite.location;
    if (!invite.organizer.isEmpty())
        lines << QStringLiteral("Organizer: ") + invite.organizer;
    if (!invite.attendees.isEmpty())
        lines << QStringLiteral("Attendees: ") + invite.attendees.join(QStringLiteral(", "));
    if (!invite.description.isEmpty())
        lines << QString() << invite.description;
    return lines.join(QLatin1Char('\n'));
}

bool htmlIsBlank(const QString &html)
{
    if (html.trimmed().isEmpty())
        return true;
    // Parse only, never laid out — see plainTextWithLinks().
    QTextDocument doc;
    doc.setHtml(html);
    const QString text = doc.toPlainText();
    for (const QChar c : text) {
        if (!c.isSpace() && c != QChar(0xFFFC)) // object replacement = an image
            return false;
    }
    // Images are content: a blank-text page with a picture is not blank.
    return !text.contains(QChar(0xFFFC));
}

QString prependToHtmlBody(const QString &html, const QString &card)
{
    static const QRegularExpression bodyTag(QStringLiteral("<body\\b[^>]*>"),
                                            QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch m = bodyTag.match(html);
    if (!m.hasMatch())
        return card + html;
    return html.left(m.capturedEnd()) + card + html.mid(m.capturedEnd());
}

namespace
{

/// True when the ZIP in \a data has at least one entry with the encryption bit
/// set. Walks local file headers from the front rather than reading the central
/// directory: an attachment may be truncated in the cache, and the first entry
/// is enough to answer the question.
bool zipIsEncrypted(const QByteArray &data)
{
    constexpr int localHeader = 30; // fixed part of a local file header
    qsizetype pos = 0;
    while (pos + localHeader <= data.size()) {
        if (static_cast<uchar>(data.at(pos)) != 'P'
            || static_cast<uchar>(data.at(pos + 1)) != 'K'
            || static_cast<uchar>(data.at(pos + 2)) != 0x03
            || static_cast<uchar>(data.at(pos + 3)) != 0x04) {
            return false; // not (or no longer) at a local file header
        }
        const auto u16 = [&data](qsizetype at) {
            return static_cast<quint16>(static_cast<uchar>(data.at(at))
                                        | (static_cast<uchar>(data.at(at + 1)) << 8));
        };
        const quint16 flags = u16(pos + 6);
        if (flags & 0x0001)
            return true; // bit 0: this entry needs a password
        // Sizes live in the data descriptor after the payload when bit 3 is
        // set, which makes the next header unfindable from here. One entry
        // answered is enough; stop rather than guess.
        if (flags & 0x0008)
            return false;
        const quint32 compressed = static_cast<quint32>(u16(pos + 18))
            | (static_cast<quint32>(u16(pos + 20)) << 16);
        pos += localHeader + u16(pos + 26) + u16(pos + 28) + compressed;
    }
    return false;
}

} // namespace

bool hasEncryptedArchive(KMime::Content *node)
{
    if (!node)
        return false;
    const auto children = node->contents();
    if (!children.isEmpty()) {
        for (KMime::Content *child : children) {
            if (hasEncryptedArchive(child))
                return true;
        }
        return false;
    }
    QString name;
    if (auto *cd = node->contentDisposition(); cd && !cd->filename().isEmpty())
        name = cd->filename();
    else if (auto *ct = node->contentType(); ct && !ct->name().isEmpty())
        name = ct->name();
    if (!name.trimmed().toLower().endsWith(QLatin1String(".zip")))
        return false;
    return zipIsEncrypted(node->decodedBody());
}

bool verifyRoundTrip(const QByteArray &stub, const QList<MailStore::PartRef> &parts,
                     QString *reason)
{
    KMime::Message check;
    check.setContent(KMime::CRLFtoLF(stub));
    check.parse();
    if (!restoreAttachments(&check, parts)) {
        *reason = QStringLiteral("a payload could not be read back from disk");
        return false;
    }
    QHash<QString, qint64> expect;
    for (const auto &p : parts)
        expect.insert(p.partId, p.size);
    bool ok = true;
    walkParts(&check, QString(), [&expect, &ok, reason](KMime::Content *part, const QString &id) {
        const auto it = expect.constFind(id);
        if (it == expect.cend())
            return;
        const qint64 got = part->decodedBody().size();
        if (got != it.value()) {
            // Back, but not with the bytes we stored.
            *reason = QStringLiteral("part %1 came back %2 bytes, expected %3")
                          .arg(id).arg(got).arg(it.value());
            ok = false;
        }
    });
    return ok;
}

QList<InlineImage> takeInlineImages(QString &html, const QString &idDomain)
{
    // Attribute-level, not tag-level: an <img> written by QTextDocument carries
    // width, height and style attributes in an order that is not ours to
    // predict, and the src is the only part of it this rewrite touches.
    static const QRegularExpression imgRe(
        QStringLiteral("<img\\b[^>]*>"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression srcRe(
        QStringLiteral("(\\bsrc\\s*=\\s*)([\"'])(file:[^\"']*)\\2"),
        QRegularExpression::CaseInsensitiveOption);

    const QString domain = idDomain.isEmpty() ? QStringLiteral("mailove.invalid") : idDomain;
    QList<InlineImage> images;
    QHash<QString, QByteArray> idForPath; // one part per file, however often used

    QString out;
    out.reserve(html.size());
    qsizetype copied = 0;
    auto tags = imgRe.globalMatch(html);
    while (tags.hasNext()) {
        const auto tag = tags.next();
        const auto src = srcRe.match(tag.captured());
        if (!src.hasMatch())
            continue;
        const QUrl url(src.captured(3));
        const QString path = url.toLocalFile();
        if (path.isEmpty())
            continue;

        QByteArray cid = idForPath.value(path);
        if (cid.isEmpty()) {
            cid = QUuid::createUuid().toByteArray(QUuid::WithoutBraces) + '@' + domain.toUtf8();
            idForPath.insert(path, cid);
            images.append({path, cid});
        }
        // Offsets inside the tag are relative to it; the copy below works in
        // whole-document coordinates.
        const qsizetype from = tag.capturedStart() + src.capturedStart(0);
        const qsizetype to = tag.capturedStart() + src.capturedEnd(0);
        out += QStringView(html).sliced(copied, from - copied);
        out += src.captured(1) + QLatin1Char('"') + QLatin1String("cid:")
            + QString::fromUtf8(cid) + QLatin1Char('"');
        copied = to;
    }
    if (images.isEmpty())
        return {};
    out += QStringView(html).sliced(copied);
    html = out;
    return images;
}

int dropFileImages(QString &html, const std::function<bool(const QString &path)> &drop)
{
    static const QRegularExpression imgRe(
        QStringLiteral("<img\\b[^>]*>"), QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression srcRe(
        QStringLiteral("\\bsrc\\s*=\\s*([\"'])(file:[^\"']*)\\1"),
        QRegularExpression::CaseInsensitiveOption);
    if (!html.contains(QLatin1String("file:"), Qt::CaseInsensitive))
        return 0;

    QString out;
    qsizetype copied = 0;
    int dropped = 0;
    auto tags = imgRe.globalMatch(html);
    while (tags.hasNext()) {
        const auto tag = tags.next();
        const auto src = srcRe.match(tag.captured());
        if (!src.hasMatch())
            continue;
        if (!drop(QUrl(src.captured(2)).toLocalFile()))
            continue;
        if (dropped == 0)
            out.reserve(html.size());
        out += QStringView(html).sliced(copied, tag.capturedStart() - copied);
        copied = tag.capturedEnd();
        ++dropped;
    }
    if (dropped == 0)
        return 0;
    out += QStringView(html).sliced(copied);
    html = out;
    return dropped;
}

QString plainTextWithLinks(const QString &html)
{
    // A bare QTextDocument, parse only: resources (images, stylesheets) are
    // requested at layout time, and nothing here ever lays out — so hostile
    // markup cannot make this fetch anything.
    QTextDocument doc;
    doc.setHtml(html);

    QString out;
    out.reserve(doc.characterCount() + doc.characterCount() / 8);
    QString anchorHref;  // href of the anchor span currently open
    QString anchorText;  // its accumulated visible text

    // The visible text already says where the link goes: a bare URL, the
    // mailto: of the shown address, or the URL minus its scheme ("www.x.y"
    // shown for "https://www.x.y"). Printing the target again is noise.
    // Empty visible text is an image-only link — silent, see the header.
    auto targetShown = [](const QString &href, const QString &shown) {
        if (shown.isEmpty() || href == shown)
            return true;
        if (href.startsWith(QLatin1String("mailto:")) && href.mid(7) == shown)
            return true;
        return href.endsWith(shown) && href.size() - shown.size() <= 8;
    };
    auto closeAnchor = [&] {
        if (anchorHref.isEmpty())
            return;
        out += anchorText;
        if (!targetShown(anchorHref, anchorText.trimmed()))
            out += QStringLiteral(" (") + anchorHref + QLatin1Char(')');
        anchorHref.clear();
        anchorText.clear();
    };

    for (QTextBlock block = doc.begin(); block != doc.end(); block = block.next()) {
        for (auto it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            if (!fragment.isValid())
                continue;
            QString text = fragment.text();
            text.replace(QChar::LineSeparator, QLatin1Char('\n')); // <br>
            const QTextCharFormat format = fragment.charFormat();
            const QString href = format.isAnchor() ? format.anchorHref() : QString();
            // One link arrives as several fragments when its text changes
            // formatting mid-way ("click <b>here</b>") — the URL is emitted
            // once, where the anchor span ends, not per fragment.
            if (href != anchorHref)
                closeAnchor();
            if (href.isEmpty()) {
                out += text;
            } else {
                anchorHref = href;
                anchorText += text;
            }
        }
        closeAnchor(); // an anchor ends with its block
        out += QLatin1Char('\n');
    }
    if (!out.isEmpty())
        out.chop(1); // the loop's trailing block separator
    return out;
}

QString htmlToMarkdown(const QString &html)
{
    QTextDocument doc;
    doc.setHtml(html);
    // Images out — on the parsed document, not with a regex over the markup.
    // toMarkdown() would emit "![](cid:…)", a reference to a part of a message
    // the paste target has never seen. The parser keeps the author's alt text
    // as ImageAltText, and alt is written for a reader who cannot see the
    // picture — which is exactly the reader of the pasted text.
    QList<std::pair<QTextFragment, std::pair<QString, QTextCharFormat>>> images;
    for (QTextBlock block = doc.begin(); block.isValid(); block = block.next()) {
        for (QTextBlock::iterator it = block.begin(); !it.atEnd(); ++it) {
            const QTextFragment fragment = it.fragment();
            const QTextCharFormat format = fragment.charFormat();
            if (!fragment.isValid() || !format.isImageFormat())
                continue;
            const QString alt = format.property(QTextFormat::ImageAltText).toString().trimmed();
            const QString href = format.isAnchor() ? format.anchorHref().trimmed() : QString();
            // Alt inside a link keeps the link and becomes its label. Alt with
            // no link is plain text. And the newsletter button — an image that
            // is the whole content of a link, no alt — would otherwise take
            // the href with it when it goes, or leave "[ ](https://…)", a
            // label nobody can read or click; the address itself is the honest
            // thing to leave behind, as text rather than as a link labelled
            // with its own address.
            QTextCharFormat replacementFormat;
            if (!alt.isEmpty() && !href.isEmpty()) {
                replacementFormat.setAnchor(true);
                replacementFormat.setAnchorHref(href);
            }
            images.append({fragment, {alt.isEmpty() ? href : alt, replacementFormat}});
        }
    }
    // Back to front: each edit shifts every position after it.
    for (auto it = images.crbegin(); it != images.crend(); ++it) {
        QTextCursor cursor(&doc);
        cursor.setPosition(it->first.position());
        cursor.setPosition(it->first.position() + it->first.length(), QTextCursor::KeepAnchor);
        // insertText on a selection replaces it; an empty string deletes.
        cursor.insertText(it->second.first, it->second.second);
    }
    // <br> parses to line-separator characters, which toMarkdown() emits as
    // bare newlines — soft breaks that renderers join into one line. Promoted
    // to real paragraph breaks, they survive as the separate lines the reader
    // saw. (The writer's own 80-column prose wrapping also emits bare
    // newlines, so this cannot be fixed after the fact — only here, where the
    // two are still distinguishable.)
    for (QTextCursor cursor(&doc);;) {
        cursor = doc.find(QString(QChar::LineSeparator), cursor);
        if (cursor.isNull())
            break;
        cursor.insertBlock();
    }
    // Layout-table furniture stripped (with blank runs capped) — the paste
    // target gets content, not a diagram of the newsletter's grid.
    QString markdown =
        flattenMarkdownTables(doc.toMarkdown(QTextDocument::MarkdownDialectGitHub)).trimmed();
    // A link whose only content was an image has no label left once the image
    // is gone, and Qt writes it as "[ ](https://…)" — a link that renders as
    // a blank you cannot click and cannot read. Every tracking-link button in
    // a newsletter is one of these. Emitted as the bare URL instead: still
    // the whole address, still one click in anything that autolinks, and it
    // says where it goes. (Over generated Markdown, not over the message's
    // markup — the house rule is about parsing mail, and this is our own
    // output, line-oriented like flattenMarkdownTables above.)
    static const QRegularExpression emptyLinkRe(
        QStringLiteral("(?<!!)\\[[ \\t]*\\]\\(\\s*([^()\\s]+)\\s*\\)"));
    markdown.replace(emptyLinkRe, QStringLiteral("\\1"));
    return markdown;
}

QString flattenMarkdownTables(const QString &markdown)
{
    // Row furniture: only pipes, dashes, colons and spaces (separator rows,
    // empty rows). Anything else starting with a pipe is a row whose cells
    // may hold content worth keeping.
    static const QRegularExpression furnitureRe(QStringLiteral("^[|\\-:\\s]*$"));
    const QStringList lines = markdown.split(QLatin1Char('\n'));
    QStringList out;
    int blanks = 0;
    auto append = [&](const QString &line) {
        blanks = line.trimmed().isEmpty() ? blanks + 1 : 0;
        // Dropped furniture merges the blank gaps around it; cap the runs
        // here so the caller does not need condenseBlankLines() — which
        // strips trailing whitespace and would eat the hard breaks below.
        if (blanks <= 2)
            out.append(line);
    };
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (!trimmed.startsWith(QLatin1Char('|'))) {
            append(line); // not a table row; pipes mid-text stay untouched
            continue;
        }
        if (furnitureRe.match(trimmed).hasMatch())
            continue;
        // Unwrap the cells: non-empty ones joined by a space, as one line —
        // with a trailing double space, Markdown's hard line break, so
        // stacked rows render as the separate lines they visually were.
        // Heading cells ("## …") break out onto lines of their own with
        // blank lines around them: heading syntax only counts at the start
        // of a line, glued mid-line it renders as literal hashes.
        const QStringList cells = trimmed.split(QLatin1Char('|'));
        QStringList kept;
        auto flushKept = [&] {
            if (kept.isEmpty())
                return;
            append(kept.join(QLatin1Char(' ')) + QStringLiteral("  "));
            kept.clear();
        };
        // List items land one per cell when a list sat in a table cell —
        // joined by spaces they degrade to prose, so they too get lines of
        // their own; consecutive ones re-form the list.
        static const QRegularExpression listCellRe(
            QStringLiteral("^([-*+]|\\d{1,3}[.)])\\s"));
        for (const QString &cell : cells) {
            const QString content = cell.trimmed();
            if (content.isEmpty() || furnitureRe.match(content).hasMatch())
                continue;
            if (content.startsWith(QLatin1Char('#'))) {
                flushKept();
                append(QString());
                append(content);
                append(QString());
            } else if (listCellRe.match(content).hasMatch()) {
                flushKept();
                append(content);
            } else {
                kept.append(content);
            }
        }
        flushKept();
    }
    return out.join(QLatin1Char('\n'));
}

QString condenseBlankLines(QString text)
{
    // Object-replacement characters are where images sat in text extracted
    // from HTML — invisible-but-not-blank, they defeat the collapse below
    // and render as nothing (or a stray box). A text rendering has no use
    // for them anywhere in a line.
    text.remove(QChar::ObjectReplacementCharacter);
    // Lines holding only invisible ink become truly empty, so they count
    // toward the run: whitespace, no-break spaces (the &nbsp; spacer lines
    // of layout-table mail), zero-width spaces and joiners, BOMs.
    static const QRegularExpression invisibleTail(QStringLiteral(
        "[ \\t\\x{00A0}\\x{200B}\\x{200C}\\x{2060}\\x{FEFF}]+\\n"));
    text.replace(invisibleTail, QStringLiteral("\n"));
    // Then anything past two consecutive empty lines collapses.
    static const QRegularExpression blankRuns(QStringLiteral("\\n{4,}"));
    text.replace(blankRuns, QStringLiteral("\n\n\n"));
    return text;
}

} // namespace MimeUtils
