// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "viewersecurity.h"

#include <QBuffer>
#include <QQuickWebEngineProfile>
#include <QRegularExpression>
#include <QHash>
#include <QSet>
#include <QStringView>
#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlScheme>

#include <KCharsets>

QByteArray messageCsp(bool allowRemote)
{
    // 'unsafe-inline' for styles is not optional: HTML mail is built almost
    // entirely from inline style attributes and <style> blocks. It is safe here
    // only because script-src is 'none' and scripting is off in the view.
    //
    // The remote opt-in covers images, and only images. A *remote stylesheet*
    // — <link>, or @import from inside an inline block — is a different thing
    // from a picture: the sender keeps serving it, so the CSS that renders can
    // change after the message was delivered, filed and scanned, and can differ
    // per open. That is the footing every attack in PortSwigger's "CSS: the
    // bomb inside your inbox" stands on (doc/research/). Remote *fonts* go with
    // them: @font-face carries descent-override and unicode-range, which turn
    // the height of a rendered line into an oracle for the text on screen, and
    // that only works if the sender can serve the font. Neither costs us
    // anything to refuse — no major client honors <link>, @import or web fonts
    // in mail, so senders do not rely on them. Inline <style>, style attributes
    // and cid:/data: fonts are untouched.
    const QByteArray remoteImages =
        allowRemote ? QByteArrayLiteral(" https: http:") : QByteArray();
    return QByteArrayLiteral("<meta http-equiv=\"Content-Security-Policy\" content=\""
                             "default-src 'none'; ")
        + QByteArrayLiteral("img-src mailove: data:") + remoteImages + QByteArrayLiteral("; ")
        + QByteArrayLiteral("style-src 'unsafe-inline' mailove: data:; ")
        + QByteArrayLiteral("font-src mailove: data:; ")
        // Remote media was already refused by the interceptor; say so here too,
        // so the policy and the interceptor cannot drift apart.
        + QByteArrayLiteral("media-src mailove: data:; ")
        + QByteArrayLiteral("script-src 'none'; object-src 'none'; frame-src 'none'; "
                            "child-src 'none'; worker-src 'none'; form-action 'none'; "
                            "base-uri 'none'; connect-src 'none'\">");
}

static bool isAsciiDigit(QChar c)
{
    return c >= QLatin1Char('0') && c <= QLatin1Char('9');
}

static bool isAsciiHexDigit(QChar c)
{
    return isAsciiDigit(c) || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))
        || (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
}

static bool isAsciiAlpha(QChar c)
{
    return (c >= QLatin1Char('a') && c <= QLatin1Char('z'))
        || (c >= QLatin1Char('A') && c <= QLatin1Char('Z'));
}

/// Resolves the character references a browser resolves inside an attribute
/// value. Without this, a scheme check reads the source and the engine reads
/// something else: "&#106;avascript:" and "java&Tab;script:" are both
/// "javascript:" by the time Chromium has an URL, and neither contains the
/// string a pattern would look for.
///
/// One pass, deliberately. To a browser "&amp;#106;" is the literal text
/// "&#106;", not "j" — a decoder that runs twice invents an attack that is not
/// there and blocks mail that was fine. The trailing semicolon is optional for
/// numeric references, because it is optional to the HTML parser too, and that
/// is precisely where a bypass would sit.
static QString decodeCharacterReferences(const QString &value)
{
    if (!value.contains(QLatin1Char('&')))
        return value;
    QString out;
    out.reserve(value.size());
    for (qsizetype i = 0; i < value.size();) {
        if (value.at(i) != QLatin1Char('&')) {
            out.append(value.at(i));
            ++i;
            continue;
        }
        qsizetype j = i + 1;
        if (j < value.size() && value.at(j) == QLatin1Char('#')) {
            ++j;
            int base = 10;
            if (j < value.size()
                && (value.at(j) == QLatin1Char('x') || value.at(j) == QLatin1Char('X'))) {
                base = 16;
                ++j;
            }
            const qsizetype digits = j;
            while (j < value.size()
                   && (base == 16 ? isAsciiHexDigit(value.at(j)) : isAsciiDigit(value.at(j))))
                ++j;
            if (j > digits) {
                bool ok = false;
                const char32_t code =
                    QStringView{value}.mid(digits, j - digits).toUInt(&ok, base);
                if (j < value.size() && value.at(j) == QLatin1Char(';'))
                    ++j;
                if (ok && code != 0 && code <= 0x10FFFF) {
                    out.append(QString::fromUcs4(&code, 1));
                    i = j;
                    continue;
                }
            }
        } else {
            while (j < value.size() && (isAsciiAlpha(value.at(j)) || isAsciiDigit(value.at(j))))
                ++j;
            if (j > i + 1 && j < value.size() && value.at(j) == QLatin1Char(';')) {
                const QString name = value.mid(i + 1, j - i - 1);
                // KCharsets carries the HTML 4 table, and the names that can
                // build a scheme are HTML 5 additions that are simply not in
                // it — "java&Tab;script:" survived a KCharsets-only decoder.
                //
                // The list is short because it is closed, not because it is a
                // sample: a scheme is [a-zA-Z][a-zA-Z0-9+.-]* followed by ':',
                // no named reference produces an ASCII letter or digit, so the
                // only ones that can help build a scheme are ':' itself and the
                // two whitespace characters a URL parser strips. Every other
                // entity can only *break* a scheme, which already lands on the
                // safe side. The rest are here so the decoded value is honest,
                // not because they are dangerous.
                static const QHash<QString, QChar> html5Names = {
                    {QStringLiteral("colon"), QLatin1Char(':')},
                    {QStringLiteral("Tab"), QLatin1Char('\t')},
                    {QStringLiteral("NewLine"), QLatin1Char('\n')},
                    {QStringLiteral("semi"), QLatin1Char(';')},
                    {QStringLiteral("sol"), QLatin1Char('/')},
                    {QStringLiteral("num"), QLatin1Char('#')},
                    {QStringLiteral("quest"), QLatin1Char('?')},
                    {QStringLiteral("commat"), QLatin1Char('@')},
                    {QStringLiteral("period"), QLatin1Char('.')},
                    {QStringLiteral("lpar"), QLatin1Char('(')},
                    {QStringLiteral("rpar"), QLatin1Char(')')},
                };
                if (const auto extra = html5Names.constFind(name);
                    extra != html5Names.constEnd()) {
                    out.append(*extra);
                    i = j + 1;
                    continue;
                }
                // Everything else goes to KCharsets, one token at a time —
                // handing it the whole value would decode references that a
                // previous pass produced, which is not what a browser does.
                const QString token = value.mid(i, j + 1 - i);
                const QString decoded = KCharsets::resolveEntities(token);
                if (decoded != token) {
                    out.append(decoded);
                    i = j + 1;
                    continue;
                }
            }
        }
        out.append(QLatin1Char('&'));
        ++i;
    }
    return out;
}

/// \a rawValue as an URL parser would see it: references resolved, then the
/// characters the parser discards before it ever reaches the scheme — tab,
/// newline and carriage return anywhere at all, NUL, and leading spaces and
/// control characters.
static QString normalizedUrl(const QString &rawValue)
{
    QString url = decodeCharacterReferences(rawValue);
    url.removeIf([](QChar c) {
        return c == QLatin1Char('\t') || c == QLatin1Char('\n') || c == QLatin1Char('\r')
            || c.unicode() == 0;
    });
    qsizetype start = 0;
    while (start < url.size() && url.at(start).unicode() <= u' ')
        ++start;
    return url.mid(start);
}

/// The scheme of an already-normalized URL, lowercased. Empty when there is
/// none to judge: a relative path, a "#fragment", a protocol-relative "//host".
static QString schemeOf(const QString &url)
{
    if (url.isEmpty() || !isAsciiAlpha(url.at(0)))
        return {};
    qsizetype i = 0;
    while (i < url.size()
           && (isAsciiAlpha(url.at(i)) || isAsciiDigit(url.at(i)) || url.at(i) == QLatin1Char('+')
               || url.at(i) == QLatin1Char('-') || url.at(i) == QLatin1Char('.')))
        ++i;
    if (i >= url.size() || url.at(i) != QLatin1Char(':'))
        return {};
    return url.left(i).toLower();
}

/// Whether a URL-bearing attribute may keep its value.
///
/// An allowlist rather than a list of known-bad schemes: the bad list has to be
/// right about every scheme a browser will ever invent, and the good list only
/// has to be right about the handful mail actually uses. Anything unlisted is
/// neutralized rather than passed through and refused later.
static bool urlAllowedInMessage(const QString &rawValue)
{
    const QString url = normalizedUrl(rawValue);
    const QString scheme = schemeOf(url);
    if (scheme.isEmpty())
        return true; // nothing to abuse: relative, fragment or protocol-relative

    // data: stays usable — inline images are the normal case — except for the
    // document types, which would render sender markup with a context of their
    // own. Checked on the normalized value, so "data:&Tab;text/html" is the
    // same answer as "data:text/html".
    if (scheme == QLatin1String("data")) {
        const QStringView rest = QStringView{url}.mid(5).trimmed();
        return !rest.startsWith(QLatin1String("text/html"), Qt::CaseInsensitive)
            && !rest.startsWith(QLatin1String("application/xhtml"), Qt::CaseInsensitive);
    }

    // Note what is *absent*: "mailove:". That scheme is ours, it is registered
    // as a SecureScheme, and the only thing allowed to produce one is our own
    // cid: rewriting, which runs after this. A sender-authored mailove: URL
    // would be a way to name another open message's context and pull its inline
    // parts into this one.
    static const QSet<QString> allowed = {
        QStringLiteral("http"),   QStringLiteral("https"), QStringLiteral("mailto"),
        QStringLiteral("cid"),    QStringLiteral("tel"),   QStringLiteral("sms"),
        QStringLiteral("callto"), QStringLiteral("xmpp"),  QStringLiteral("geo"),
        QStringLiteral("webcal"), QStringLiteral("ftp"),   QStringLiteral("ftps"),
        QStringLiteral("news"),   QStringLiteral("nntp"),  QStringLiteral("irc"),
        QStringLiteral("ircs"),   QStringLiteral("matrix")};
    return allowed.contains(scheme);
}

/// Index just past the '>' that closes the tag opening at \a start, honoring
/// quoted attribute values. A browser does not end a tag on a '>' that sits
/// inside quotes, so neither may this: scanning to the first '>' turns
/// <a href="data:text/html,<b>hi"> into a truncated tag whose value no longer
/// looks like a URL, and the attribute check then has nothing to judge.
/// Returns -1 when the tag never closes.
static qsizetype tagEnd(const QString &html, qsizetype start)
{
    QChar quote;
    for (qsizetype i = start + 1; i < html.size(); ++i) {
        const QChar c = html.at(i);
        if (!quote.isNull()) {
            if (c == quote)
                quote = QChar();
        } else if (c == QLatin1Char('"') || c == QLatin1Char('\'')) {
            quote = c;
        } else if (c == QLatin1Char('>')) {
            return i + 1;
        }
    }
    return -1;
}

/// Neutralizes the URL-bearing attributes of one tag. Values are judged after
/// normalization but rewritten by position, so a value that passes is left
/// exactly as the sender wrote it — this decides, it does not reformat.
static QString sanitizeUrlAttributes(const QString &tag)
{
    static const QRegularExpression urlAttrRe(
        QStringLiteral("\\b(?:href|src|action|formaction|background)\\s*=\\s*"
                       "(\"([^\"]*)\"|'([^']*)'|([^\\s>]*))"),
        QRegularExpression::CaseInsensitiveOption);

    QString out;
    out.reserve(tag.size());
    qsizetype pos = 0;
    auto it = urlAttrRe.globalMatch(tag);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        QString value = m.captured(2);
        if (value.isNull())
            value = m.captured(3);
        if (value.isNull())
            value = m.captured(4);
        // An unquoted value cannot legitimately open with a quote character.
        // If one does, the tag was malformed enough that the quoted branches
        // did not match, and a leading quote would hide the scheme behind a
        // character that makes normalizedUrl() see no scheme at all.
        while (!value.isEmpty()
               && (value.startsWith(QLatin1Char('"')) || value.startsWith(QLatin1Char('\''))))
            value.remove(0, 1);
        out.append(QStringView{tag}.mid(pos, m.capturedStart(1) - pos));
        out.append(urlAllowedInMessage(value) ? m.captured(1)
                                              : QStringLiteral("\"blocked:\""));
        pos = m.capturedEnd(1);
    }
    out.append(QStringView{tag}.mid(pos));
    return out;
}

QString sanitizeMessageHtml(QString html)
{
    // Elements that bring their own execution or document context, taken out
    // with whatever they contain. <style> is deliberately NOT in this list:
    // email depends on it, and CSP already forbids scripting.
    static const QRegularExpression scriptedBlockRe(
        QStringLiteral("<(script|iframe|frame|frameset|object|embed|applet)\\b[^>]*>.*?</\\1\\s*>"),
        QRegularExpression::DotMatchesEverythingOption
            | QRegularExpression::CaseInsensitiveOption);
    // The same tags left unclosed, which a parser still honors, plus <base>,
    // which would repoint every relative URL in the message.
    static const QRegularExpression scriptedTagRe(
        QStringLiteral("</?(script|iframe|frame|frameset|object|embed|applet|base)\\b[^>]*>"),
        QRegularExpression::CaseInsensitiveOption);
    // <meta http-equiv="refresh"> navigates the viewer with no click at all.
    static const QRegularExpression metaRefreshRe(
        QStringLiteral("<meta\\b[^>]*http-equiv\\s*=\\s*[\"']?\\s*refresh[^>]*>"),
        QRegularExpression::CaseInsensitiveOption);

    html.remove(scriptedBlockRe);
    html.remove(scriptedTagRe);
    html.remove(metaRefreshRe);

    // Attribute cleanup runs per tag rather than over the whole document, so
    // body text such as "the one=1 case" is not mistaken for a handler.
    static const QRegularExpression eventAttrRe(
        QStringLiteral("\\son[a-z]+\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)"),
        QRegularExpression::CaseInsensitiveOption);

    QString out;
    out.reserve(html.size());
    qsizetype pos = 0;
    while (pos < html.size()) {
        const qsizetype lt = html.indexOf(QLatin1Char('<'), pos);
        if (lt < 0)
            break;
        if (lt + 1 >= html.size() || !isAsciiAlpha(html.at(lt + 1))) {
            out.append(QStringView{html}.mid(pos, lt + 1 - pos));
            pos = lt + 1;
            continue;
        }
        const qsizetype end = tagEnd(html, lt);
        if (end < 0)
            break; // never closed: a browser has no tag here either
        out.append(QStringView{html}.mid(pos, lt - pos));
        QString tag = html.mid(lt, end - lt);
        tag.remove(eventAttrRe);
        tag = sanitizeUrlAttributes(tag);
        out.append(tag);
        pos = end;
    }
    out.append(QStringView{html}.mid(pos));
    return out;
}

/// The resource types a message body may legitimately pull in: things that are
/// painted, never things that are *documents*. Anything outside this set —
/// subframes above all — can host markup and forms of its own.
static bool isPassiveSubresource(QWebEngineUrlRequestInfo::ResourceType type)
{
    switch (type) {
    case QWebEngineUrlRequestInfo::ResourceTypeImage:
    case QWebEngineUrlRequestInfo::ResourceTypeStylesheet:
    case QWebEngineUrlRequestInfo::ResourceTypeFontResource:
        return true;
    default:
        return false;
    }
}

void ViewerRequestInterceptor::interceptRequest(QWebEngineUrlRequestInfo &info)
{
    const QString scheme = info.requestUrl().scheme();
    const QWebEngineUrlRequestInfo::ResourceType type = info.resourceType();

    // Our own scheme carries the message document and its inline parts. Framing
    // it is not one of those jobs: a message that frames itself, or an inline
    // part, gets a document rendered inside this scheme's origin.
    if (scheme == QLatin1String("mailove")
        && (type == QWebEngineUrlRequestInfo::ResourceTypeMainFrame
            || isPassiveSubresource(type)))
        return;
    // about:blank is what the viewer resets to between messages.
    if (scheme == QLatin1String("about"))
        return;
    // data: is how inline images usually arrive, but a data: *subframe* is just
    // another way to get sender markup rendered as a document.
    if (scheme == QLatin1String("data") && isPassiveSubresource(type))
        return;

    // Per-message opt-in, and narrower than the set above: images only. What
    // the toggle promises is that the pictures show up, and a remote stylesheet
    // or web font is not a picture — it is markup the sender can still be
    // rewriting when the message is opened, which is what makes the CSS attacks
    // in doc/research/css-the-bomb-inside-your-inbox.md work. messageCsp()
    // refuses those too; this is the half that holds if a policy is ever
    // dropped or mis-assembled.
    //
    // Excluding only MainFrame would still let <iframe src="https://…"> load a
    // live remote page inside the message — a phishing surface that does not
    // need JavaScript to work, since a plain HTML form posts just fine.
    if (m_allowRemote.load()
        && (scheme == QLatin1String("https") || scheme == QLatin1String("http"))
        && type == QWebEngineUrlRequestInfo::ResourceTypeImage)
        return;

    info.block(true);
}

/// The MIME type an inline part is served as. The sender chooses the part's
/// declared Content-Type, so it cannot be passed through: a part declared
/// text/html and referenced as <iframe src="mailove:cid/…"> would render sender
/// markup as a document inside our own scheme's origin, which is registered as
/// a SecureScheme. Only the passive types a cid: reference legitimately
/// resolves to keep their declared type; everything else becomes an opaque
/// blob that Chromium will not treat as a document.
static QByteArray safeInlineMimeType(const QByteArray &declared)
{
    const QByteArray type = declared.toLower().trimmed();
    if (type.startsWith("image/") || type.startsWith("audio/") || type.startsWith("video/")
        || type.startsWith("font/") || type == "application/font-woff"
        || type == "application/vnd.ms-fontobject")
        return type;
    return QByteArrayLiteral("application/octet-stream");
}

// "<ctx>/rest" → context id; \a rest gets everything after the slash.
static bool splitContextPath(const QString &path, quint64 *context, QString *rest)
{
    const int slash = path.indexOf(QLatin1Char('/'));
    if (slash <= 0)
        return false;
    bool ok = false;
    *context = path.left(slash).toULongLong(&ok);
    // Content-IDs may themselves contain slashes, so take the remainder whole.
    *rest = path.mid(slash + 1);
    return ok;
}

void ViewerSchemeHandler::requestStarted(QWebEngineUrlRequestJob *job)
{
    const QString path = job->requestUrl().path();

    // Inline attachments: mailove:cid/<context>/<contentId>
    if (path.startsWith(QLatin1String("cid/"))) {
        quint64 context = 0;
        QString cid;
        if (!splitContextPath(path.mid(4), &context, &cid)) {
            job->fail(QWebEngineUrlRequestJob::UrlNotFound);
            return;
        }
        const auto ctxIt = m_contexts.constFind(context);
        if (ctxIt == m_contexts.constEnd()) {
            job->fail(QWebEngineUrlRequestJob::UrlNotFound);
            return;
        }
        const auto it = ctxIt->inlineParts.constFind(cid);
        if (it == ctxIt->inlineParts.constEnd()) {
            job->fail(QWebEngineUrlRequestJob::UrlNotFound);
            return;
        }
        auto *buffer = new QBuffer(job);
        buffer->setData(it->data);
        job->reply(it->mimeType, buffer);
        return;
    }

    // Only the document URL itself gets the body. Mail that references
    // root-relative assets ("/packs/assets/x.woff2") resolves them against
    // this scheme, and answering those with the message HTML made Chromium
    // try to parse an email as a font. Those requests have no answer here.
    if (!path.startsWith(QLatin1String("message/"))) {
        job->fail(QWebEngineUrlRequestJob::UrlNotFound);
        return;
    }
    quint64 context = 0;
    QString serial;
    if (!splitContextPath(path.mid(8), &context, &serial)) {
        job->fail(QWebEngineUrlRequestJob::UrlNotFound);
        return;
    }
    const auto ctxIt = m_contexts.constFind(context);
    if (ctxIt == m_contexts.constEnd()) {
        // The window this body belonged to is gone.
        job->fail(QWebEngineUrlRequestJob::UrlNotFound);
        return;
    }

    // reply() wants a bare MIME type — a "; charset=" suffix can make
    // Chromium treat the response as unknown and render a blank page.
    // Charset is declared via a <meta> tag in the served HTML instead.
    auto *buffer = new QBuffer(job);
    buffer->setData(ctxIt->html);
    job->reply(QByteArrayLiteral("text/html"), buffer);
}

quint64 ViewerSchemeHandler::allocateContext()
{
    const quint64 context = ++m_nextContext;
    m_contexts.insert(context, {});
    return context;
}

void ViewerSchemeHandler::releaseContext(quint64 context)
{
    m_contexts.remove(context);
}

void ViewerSchemeHandler::setInlinePart(quint64 context, const QString &contentId,
                                        const QByteArray &mimeType, const QByteArray &data)
{
    const auto it = m_contexts.find(context);
    if (it == m_contexts.end())
        return;
    it->inlineParts.insert(contentId, {safeInlineMimeType(mimeType), data});
}

void ViewerSchemeHandler::clearInlineParts(quint64 context)
{
    const auto it = m_contexts.find(context);
    if (it != m_contexts.end())
        it->inlineParts.clear();
}

void ViewerSchemeHandler::setRemoteContentAllowed(bool allow)
{
    if (m_interceptor)
        m_interceptor->setRemoteContentAllowed(allow);
}

QString ViewerSchemeHandler::setMessageHtml(quint64 context, const QByteArray &html)
{
    const auto it = m_contexts.find(context);
    if (it == m_contexts.end())
        return {};
    it->html = html;
    // The serial only busts WebEngine's cache — the context id is what picks
    // the body.
    return QStringLiteral("mailove:message/%1/%2").arg(context).arg(++m_serial);
}

void ViewerSchemeHandler::registerScheme()
{
    QWebEngineUrlScheme scheme(QByteArrayLiteral("mailove"));
    scheme.setSyntax(QWebEngineUrlScheme::Syntax::Path);
    scheme.setFlags(QWebEngineUrlScheme::SecureScheme);
    QWebEngineUrlScheme::registerScheme(scheme);
}

ViewerSchemeHandler *ViewerSchemeHandler::install()
{
    QQuickWebEngineProfile *profile = QQuickWebEngineProfile::defaultProfile();
    profile->setOffTheRecord(true);
    auto *interceptor = new ViewerRequestInterceptor(profile);
    profile->setUrlRequestInterceptor(interceptor);
    auto *handler = new ViewerSchemeHandler(profile);
    handler->m_interceptor = interceptor;
    profile->installUrlSchemeHandler(QByteArrayLiteral("mailove"), handler);
    return handler;
}
