// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "jmaprequest.h"

#include "advancedconfig.h"

#include "jmapsession.h"

#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace
{
/// A method call is the three-element array [name, arguments, callId]
/// (RFC 8620 §3.2) — positional, not an object, which is why every access here
/// is by index.
constexpr int kMethodNameIndex = 0;
constexpr int kArgumentsIndex = 1;
constexpr int kCallIdIndex = 2;
constexpr int kMethodCallSize = 3;

/// Responses are small next to message bodies — the bodies come from
/// downloadUrl, not from here — so a ceiling well above any plausible batch
/// still catches a proxy error page or a redirect to a login form.
constexpr qint64 kMaxResponseBytes = 64 * 1024 * 1024;
int kRequestTimeoutMs() { return AdvancedConfig::i("jmap/requestTimeoutMs"); }
} // namespace

QString JmapRequest::Response::errorType() const
{
    if (!isError())
        return {};
    return arguments.value(QLatin1String("type")).toString();
}

JmapRequest::JmapRequest(JmapSession *session, QObject *parent)
    : QObject(parent)
    , m_session(session)
{
    // Every batch this client sends is mail over core; naming them here means
    // no caller can forget and get a puzzling unknownMethod back.
    m_capabilities = {JmapSession::coreCapability(), JmapSession::mailCapability()};
}

JmapRequest::~JmapRequest() = default;

void JmapRequest::useCapability(const QString &uri)
{
    if (!uri.isEmpty() && !m_capabilities.contains(uri))
        m_capabilities.append(uri);
}

bool JmapRequest::isFull() const
{
    if (!m_session)
        return false;
    const qint64 limit = m_session->limits().maxCallsInRequest;
    return limit > 0 && m_calls.size() >= limit;
}

QString JmapRequest::addCall(const QString &method, const QJsonObject &arguments)
{
    if (isFull())
        return {};

    const QString callId = QStringLiteral("c%1").arg(m_nextCallId++);
    m_calls.append(QJsonArray{method, arguments, callId});
    return callId;
}

QJsonObject JmapRequest::resultReference(const QString &callId, const QString &method,
                                         const QString &path)
{
    return QJsonObject{{QStringLiteral("resultOf"), callId},
                       {QStringLiteral("name"), method},
                       {QStringLiteral("path"), path}};
}

QJsonObject JmapRequest::requestObject() const
{
    QJsonArray using_;
    for (const QString &uri : m_capabilities)
        using_.append(uri);

    return QJsonObject{{QStringLiteral("using"), using_},
                       {QStringLiteral("methodCalls"), m_calls}};
}

void JmapRequest::send(const Callback &done)
{
    m_done = done;

    if (m_calls.isEmpty()) {
        finish(MailBackend::Error::Protocol, {},
               tr("A JMAP request was sent with no method calls in it."));
        return;
    }
    if (!m_session || !m_session->isValid()) {
        finish(MailBackend::Error::Auth,
               {}, tr("There is no JMAP session to send this request over."));
        return;
    }
    post(false);
}

void JmapRequest::post(bool isRetry)
{
    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QNetworkRequest request(m_session->apiUrl());
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/json; charset=utf-8"));
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    m_session->authorize(request);
    request.setTransferTimeout(kRequestTimeoutMs());

    const QByteArray body = QJsonDocument(requestObject()).toJson(QJsonDocument::Compact);
    m_reply = m_net->post(request, body);
    m_session->guardRedirects(m_reply);
    connect(m_reply, &QNetworkReply::finished, this, [this, isRetry] {
        QNetworkReply *reply = m_reply;
        if (!reply)
            return;
        m_reply = nullptr;
        reply->deleteLater();
        handleReply(reply, isRetry);
    });
}

void JmapRequest::cancel()
{
    m_done = nullptr;
    if (!m_reply)
        return;
    QNetworkReply *reply = m_reply;
    m_reply = nullptr;
    reply->disconnect(this);
    reply->abort();
    reply->deleteLater();
}

void JmapRequest::handleReply(QNetworkReply *reply, bool isRetry)
{
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    if (status == 401 && !isRetry) {
        // Not a failed request: an expired session. Re-discover and send the
        // same batch once, so the caller never learns this happened. A second
        // 401 is a real credential problem and is reported.
        auto *session = m_session;
        auto ready = std::make_shared<QMetaObject::Connection>();
        auto failedConn = std::make_shared<QMetaObject::Connection>();
        *ready = connect(session, &JmapSession::ready, this, [this, ready, failedConn] {
            disconnect(*ready);
            disconnect(*failedConn);
            post(true);
        });
        *failedConn = connect(session, &JmapSession::failed, this,
                              [this, ready, failedConn](MailBackend::Error error,
                                                        const QString &message) {
                                  disconnect(*ready);
                                  disconnect(*failedConn);
                                  finish(error, {}, message);
                              });
        session->refresh();
        return;
    }
    if (status == 401 || status == 403) {
        finish(MailBackend::Error::Auth, {}, tr("The server rejected these credentials."));
        return;
    }
    if (status == 429 || status == 503) {
        finish(MailBackend::Error::Throttled, {},
               tr("The server is asking for a slower pace; try again shortly."));
        return;
    }
    if (reply->error() != QNetworkReply::NoError && status < 400) {
        finish(MailBackend::Error::Connection, {}, reply->errorString());
        return;
    }
    if (status != 200) {
        finish(MailBackend::Error::Protocol, {},
               tr("The server answered the JMAP request with HTTP %1.").arg(status));
        return;
    }

    const QByteArray body = reply->read(kMaxResponseBytes + 1);
    if (body.size() > kMaxResponseBytes) {
        finish(MailBackend::Error::Protocol, {},
               tr("The JMAP response is implausibly large."));
        return;
    }

    QList<Response> responses;
    QString sessionState;
    QString error;
    if (!parseResponse(body, responses, sessionState, &error)) {
        finish(MailBackend::Error::Protocol, {}, error);
        return;
    }

    finish(MailBackend::Error::None, responses, QString());
}

void JmapRequest::finish(MailBackend::Error error, const QList<Response> &responses,
                         const QString &message)
{
    // Cleared first: a callback that starts the next request must not be
    // reachable through this one's state.
    const Callback done = m_done;
    m_done = nullptr;
    if (done)
        done(error, responses, message);
}

bool JmapRequest::parseResponse(const QByteArray &json, QList<Response> &responses,
                                QString &sessionState, QString *error)
{
    const auto fail = [error](const QString &what) {
        if (error)
            *error = what;
        return false;
    };

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError)
        return fail(tr("The JMAP response is not valid JSON: %1")
                        .arg(parseError.errorString()));
    if (!doc.isObject())
        return fail(tr("The JMAP response is not a JSON object."));

    const QJsonObject root = doc.object();
    const QJsonValue methodResponses = root.value(QLatin1String("methodResponses"));
    if (!methodResponses.isArray())
        return fail(tr("The JMAP response carries no methodResponses array."));

    QList<Response> parsed;
    const QJsonArray array = methodResponses.toArray();
    for (const QJsonValue &value : array) {
        const QJsonArray triple = value.toArray();
        if (triple.size() != kMethodCallSize)
            return fail(tr("A JMAP method response is not a three-element array."));
        Response response;
        response.method = triple.at(kMethodNameIndex).toString();
        response.arguments = triple.at(kArgumentsIndex).toObject();
        response.callId = triple.at(kCallIdIndex).toString();
        parsed.append(response);
    }

    responses = parsed;
    sessionState = root.value(QLatin1String("sessionState")).toString();
    if (error)
        error->clear();
    return true;
}

MailBackend::Error JmapRequest::errorForType(const QString &type)
{
    // RFC 8620 §3.6.2. Only the distinctions the application acts on are made
    // here; everything else is Protocol, and the type itself travels in the
    // human-readable message.
    if (type == QLatin1String("rateLimit"))
        return MailBackend::Error::Throttled;
    if (type == QLatin1String("serverUnavailable"))
        return MailBackend::Error::Throttled;
    if (type == QLatin1String("forbidden") || type == QLatin1String("accountReadOnly"))
        return MailBackend::Error::Auth;
    if (type == QLatin1String("accountNotFound") || type == QLatin1String("notFound"))
        return MailBackend::Error::NotFound;
    return MailBackend::Error::Protocol;
}

JmapRequest::Response JmapRequest::firstError(const QList<Response> &responses)
{
    for (const Response &response : responses) {
        if (response.isError())
            return response;
    }
    return {};
}
