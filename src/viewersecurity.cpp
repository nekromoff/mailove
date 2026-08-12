// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "viewersecurity.h"

#include <QBuffer>
#include <QQuickWebEngineProfile>
#include <QRegularExpression>
#include <QStringView>
#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlScheme>

QByteArray messageCsp(bool allowRemote)
{
    // 'unsafe-inline' for styles is not optional: HTML mail is built almost
    // entirely from inline style attributes and <style> blocks. It is safe here
    // only because script-src is 'none' and scripting is off in the view.
    const QByteArray remote = allowRemote ? QByteArrayLiteral(" https: http:") : QByteArray();
    return QByteArrayLiteral("<meta http-equiv=\"Content-Security-Policy\" content=\""
                             "default-src 'none'; ")
        + QByteArrayLiteral("img-src mailove: data:") + remote + QByteArrayLiteral("; ")
        + QByteArrayLiteral("style-src 'unsafe-inline' mailove: data:") + remote
        + QByteArrayLiteral("; ")
        + QByteArrayLiteral("font-src mailove: data:") + remote + QByteArrayLiteral("; ")
        + QByteArrayLiteral("media-src mailove: data:") + remote + QByteArrayLiteral("; ")
        + QByteArrayLiteral("script-src 'none'; object-src 'none'; frame-src 'none'; "
                            "child-src 'none'; worker-src 'none'; form-action 'none'; "
                            "base-uri 'none'; connect-src 'none'\">");
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
    static const QRegularExpression tagRe(QStringLiteral("<[a-zA-Z][^>]*>"));
    static const QRegularExpression eventAttrRe(
        QStringLiteral("\\son[a-z]+\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression scriptUrlRe(
        QStringLiteral("((?:href|src|action|formaction|background)\\s*=\\s*[\"']?)\\s*"
                       "(?:javascript|vbscript|livescript)\\s*:"),
        QRegularExpression::CaseInsensitiveOption);
    // data: stays usable — inline images are the normal case — except for the
    // document types, which would render sender markup with its own context.
    static const QRegularExpression dataDocUrlRe(
        QStringLiteral("((?:href|src|action|formaction|background)\\s*=\\s*[\"']?)\\s*"
                       "data\\s*:\\s*(?:text/html|application/xhtml)"),
        QRegularExpression::CaseInsensitiveOption);

    QString out;
    out.reserve(html.size());
    qsizetype pos = 0;
    auto it = tagRe.globalMatch(html);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out.append(QStringView{html}.mid(pos, m.capturedStart() - pos));
        QString tag = m.captured();
        tag.remove(eventAttrRe);
        tag.replace(scriptUrlRe, QStringLiteral("\\1blocked:"));
        tag.replace(dataDocUrlRe, QStringLiteral("\\1blocked:"));
        out.append(tag);
        pos = m.capturedEnd();
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

    // Per-message opt-in. Deliberately an allowlist of passive types, matching
    // what the toggle promises (images, styles, fonts). Excluding only
    // MainFrame would still let <iframe src="https://…"> load a live remote
    // page inside the message — a phishing surface that does not need
    // JavaScript to work, since a plain HTML form posts just fine.
    if (m_allowRemote.load()
        && (scheme == QLatin1String("https") || scheme == QLatin1String("http"))
        && isPassiveSubresource(type))
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
