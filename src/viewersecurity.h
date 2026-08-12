// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QHash>
#include <QWebEngineUrlRequestInterceptor>
#include <QWebEngineUrlSchemeHandler>

#include <atomic>

/**
 * Removes the constructs in a sender's HTML that would otherwise make every
 * other defense load-bearing on its own: scripting hooks, embedded documents,
 * and redirects that need no click.
 *
 * This is the *secondary* layer and is written to be understood as one. The
 * controls that actually hold are JavaScript being disabled in the view, the
 * request interceptor's allowlist, and the Content-Security-Policy from
 * messageCsp(). A regex pass over hostile HTML cannot be complete — entity and
 * encoding tricks get past it — so nothing here should be the only thing
 * standing between a message and code execution.
 */
QString sanitizeMessageHtml(QString html);

/**
 * A <meta> Content-Security-Policy to prepend to a served message body.
 * \a allowRemote mirrors the per-message remote-content opt-in.
 *
 * Browser-enforced, so unlike sanitizeMessageHtml() it holds against encoding
 * tricks. A message that carries its own CSP meta can only narrow this further
 * — CSP policies intersect, they never widen.
 */
QByteArray messageCsp(bool allowRemote);

/**
 * Blocks every network request from the message viewer except inline data
 * and our own mailove: message scheme. Remote content (tracking pixels,
 * external images) never leaves the machine. A per-message "load remote
 * images" opt-in can relax this later.
 */
class ViewerRequestInterceptor : public QWebEngineUrlRequestInterceptor
{
    Q_OBJECT

public:
    using QWebEngineUrlRequestInterceptor::QWebEngineUrlRequestInterceptor;

    void interceptRequest(QWebEngineUrlRequestInfo &info) override;

    /// Per-message opt-in: when true, http(s) subresources (images, CSS,
    /// fonts) are allowed through. JavaScript stays disabled regardless —
    /// that is a WebEngineView setting, not the interceptor's.
    void setRemoteContentAllowed(bool allow) { m_allowRemote.store(allow); }

private:
    std::atomic<bool> m_allowRemote{false}; // interceptRequest runs on the IO thread
};

/**
 * Serves message bodies under mailove:message/<context>/<n>.
 *
 * WebEngineView.loadHtml() routes through a data: URL, which Chromium caps
 * at ~2 MB — larger HTML mails render as a blank page. Serving the bytes
 * through a scheme handler has no size limit and gives us a place to serve
 * cid: inline attachments (mailove:cid/<context>/<contentId>).
 *
 * Bodies are keyed by a context id so several messages can be on screen at
 * once — the reading pane plus any number of detached message windows. Each
 * context holds one body and its inline parts; releasing the context frees
 * both.
 */
class ViewerSchemeHandler : public QWebEngineUrlSchemeHandler
{
    Q_OBJECT

public:
    using QWebEngineUrlSchemeHandler::QWebEngineUrlSchemeHandler;

    void requestStarted(QWebEngineUrlRequestJob *job) override;

    /// Reserves a context id for one on-screen message view.
    quint64 allocateContext();
    /// Frees the context's body and inline parts (window closed).
    void releaseContext(quint64 context);

    /// Stores the body to serve for \a context and returns the
    /// (cache-busting) URL for it.
    QString setMessageHtml(quint64 context, const QByteArray &html);

    /// Registers an inline MIME part served as mailove:cid/<context>/<contentId>.
    void setInlinePart(quint64 context, const QString &contentId,
                       const QByteArray &mimeType, const QByteArray &data);
    /// Drops \a context's inline parts (call before loading a new message).
    void clearInlineParts(quint64 context);

    /// Forwards the remote-content opt-in to the profile's interceptor.
    void setRemoteContentAllowed(bool allow);

    /// Call before the QGuiApplication is constructed.
    static void registerScheme();

    /// Installs interceptor + handler on the default profile; returns the handler.
    static ViewerSchemeHandler *install();

private:
    struct InlinePart {
        QByteArray mimeType;
        QByteArray data;
    };
    struct ContextData {
        QByteArray html;
        QHash<QString, InlinePart> inlineParts;
    };

    QHash<quint64, ContextData> m_contexts;
    quint64 m_nextContext = 0;
    ViewerRequestInterceptor *m_interceptor = nullptr;
    quint64 m_serial = 0;
};
