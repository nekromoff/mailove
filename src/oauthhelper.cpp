// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "oauthhelper.h"

#include <QCryptographicHash>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>

#include <chrono>
#include <memory>

OAuthHelper::OAuthHelper(QObject *parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
{
}

OAuthHelper::Endpoints OAuthHelper::endpointsFor(Provider provider)
{
    if (provider == Gmail) {
        return {QStringLiteral("https://accounts.google.com/o/oauth2/v2/auth"),
                QStringLiteral("https://oauth2.googleapis.com/token"),
                QStringLiteral("https://mail.google.com/")};
    }
    return {QStringLiteral("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
            QStringLiteral("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
            QStringLiteral("https://outlook.office365.com/IMAP.AccessAsUser.All "
                           "https://outlook.office365.com/SMTP.Send offline_access")};
}

static QByteArray base64Url(const QByteArray &data)
{
    return data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

static QString randomString(int length)
{
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    QString out;
    out.reserve(length);
    for (int i = 0; i < length; ++i)
        out.append(QLatin1Char(chars[QRandomGenerator::system()->bounded(
            int(sizeof(chars)) - 1)]));
    return out;
}

void OAuthHelper::authorize(Provider provider, const QString &clientId,
                            const QString &clientSecret)
{
    if (clientId.isEmpty()) {
        Q_EMIT failed(tr("No OAuth client ID configured for this account."));
        return;
    }
    endRedirectListener(); // abandon any sign-in still in flight
    m_server = new QTcpServer(this);
    if (!m_server->listen(QHostAddress::LocalHost, 0)) {
        Q_EMIT failed(tr("Could not open a local port for the OAuth redirect."));
        return;
    }
    // "localhost", not 127.0.0.1 — the shipped client IDs are registered with
    // a localhost redirect and Google rejects other loopback spellings (400).
    const QString redirect =
        QStringLiteral("http://localhost:%1/").arg(m_server->serverPort());

    m_codeVerifier = randomString(64);
    // CSRF nonce. Without it the loopback listener redeems any code posted to
    // it, so any local process — or any web page the user happens to visit,
    // which can navigate to http://localhost:<port>/?code=… — could bind this
    // client to an account of the attacker's choosing (RFC 8252 §8.9).
    m_state = randomString(32);
    const QByteArray challenge = base64Url(
        QCryptographicHash::hash(m_codeVerifier.toLatin1(), QCryptographicHash::Sha256));

    const Endpoints ep = endpointsFor(provider);
    QUrl url(ep.authUrl);
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("client_id"), clientId);
    q.addQueryItem(QStringLiteral("redirect_uri"), redirect);
    q.addQueryItem(QStringLiteral("response_type"), QStringLiteral("code"));
    q.addQueryItem(QStringLiteral("scope"), ep.scope);
    q.addQueryItem(QStringLiteral("code_challenge"), QString::fromLatin1(challenge));
    q.addQueryItem(QStringLiteral("code_challenge_method"), QStringLiteral("S256"));
    q.addQueryItem(QStringLiteral("state"), m_state);
    q.addQueryItem(QStringLiteral("access_type"), QStringLiteral("offline")); // Google
    q.addQueryItem(QStringLiteral("prompt"), QStringLiteral("consent"));      // force refresh token
    url.setQuery(q);

    connect(m_server, &QTcpServer::newConnection, this,
            [this, provider, clientId, clientSecret, redirect] {
        QTcpSocket *sock = m_server->nextPendingConnection();
        if (!sock)
            return;
        // Outlive the listener: endRedirectListener() deletes the server while
        // this socket may still be draining its reply.
        sock->setParent(this);
        connect(sock, &QTcpSocket::disconnected, sock, &QObject::deleteLater);
        auto buffer = std::make_shared<QByteArray>();
        connect(sock, &QTcpSocket::readyRead, this,
                [this, sock, buffer, provider, clientId, clientSecret, redirect] {
            buffer->append(sock->readAll());
            // Only the request line matters; wait for it to arrive whole rather
            // than assuming it fits in the first read.
            const int lineEnd = buffer->indexOf("\r\n");
            if (lineEnd < 0) {
                if (buffer->size() > 8192)
                    sock->disconnectFromHost(); // not a browser redirect
                return;
            }
            const QByteArray requestLine = buffer->left(lineEnd);
            const int pathStart = requestLine.indexOf(' ') + 1;
            const int pathEnd = requestLine.indexOf(' ', pathStart);
            if (pathStart <= 0 || pathEnd < 0) {
                sock->disconnectFromHost();
                return;
            }
            const QUrl reqUrl(QStringLiteral("http://127.0.0.1")
                              + QString::fromLatin1(
                                  requestLine.mid(pathStart, pathEnd - pathStart)));
            const QUrlQuery query(reqUrl);
            const QString code = query.queryItemValue(QStringLiteral("code"));
            const QString error = query.queryItemValue(QStringLiteral("error"));
            const QString state = query.queryItemValue(QStringLiteral("state"));

            auto respond = [sock](const char *status, const QByteArray &body) {
                sock->write(QByteArray("HTTP/1.1 ") + status
                            + "\r\nContent-Type: text/html; charset=utf-8"
                              "\r\nCache-Control: no-store\r\nConnection: close"
                              "\r\nContent-Length: " + QByteArray::number(body.size())
                            + "\r\n\r\n" + body);
                sock->flush();
                sock->disconnectFromHost();
            };

            // Anything that is not our redirect — favicon probes, port scans, a
            // page poking at localhost — is answered and ignored. It must not
            // end a sign-in the user is still completing.
            if (code.isEmpty() && error.isEmpty()) {
                respond("404 Not Found", QByteArrayLiteral("<h2>Not found.</h2>"));
                return;
            }
            // The nonce is what proves this redirect belongs to the sign-in we
            // started. A replayed or injected one has nothing to match against.
            if (m_state.isEmpty() || state != m_state) {
                respond("400 Bad Request",
                        QByteArrayLiteral("<h2>Sign-in rejected.</h2>This redirect did not "
                                          "come from the sign-in Mailove started."));
                return;
            }
            endRedirectListener(); // one-shot

            if (code.isEmpty()) {
                respond("200 OK", QByteArrayLiteral("<h2>Sign-in failed.</h2>"
                                                    "You can close this tab."));
                Q_EMIT failed(tr("Browser sign-in failed: %1").arg(error));
                return;
            }
            respond("200 OK", QByteArrayLiteral("<h2>Signed in.</h2>You can return to "
                                                "Mailove and close this tab."));
            requestToken(provider, clientId, clientSecret,
                         {{QStringLiteral("grant_type"), QStringLiteral("authorization_code")},
                          {QStringLiteral("code"), code},
                          {QStringLiteral("redirect_uri"), redirect},
                          {QStringLiteral("code_verifier"), m_codeVerifier}});
        });
    });

    // Don't keep a loopback port open indefinitely when the user abandons the
    // browser tab — that is the window in which an injected code would land.
    QTimer::singleShot(std::chrono::minutes(5), this, [this] {
        if (m_state.isEmpty())
            return; // already finished
        endRedirectListener();
        Q_EMIT failed(tr("Browser sign-in timed out."));
    });

    QDesktopServices::openUrl(url);
}

void OAuthHelper::endRedirectListener()
{
    m_state.clear();
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
    }
}

void OAuthHelper::refresh(Provider provider, const QString &clientId,
                          const QString &clientSecret, const QString &refreshToken)
{
    if (clientId.isEmpty() || refreshToken.isEmpty()) {
        Q_EMIT failed(tr("No stored OAuth sign-in for this account."));
        return;
    }
    requestToken(provider, clientId, clientSecret,
                 {{QStringLiteral("grant_type"), QStringLiteral("refresh_token")},
                  {QStringLiteral("refresh_token"), refreshToken}});
}

void OAuthHelper::requestToken(Provider provider, const QString &clientId,
                               const QString &clientSecret,
                               const QList<std::pair<QString, QString>> &grant)
{
    QUrlQuery form;
    form.addQueryItem(QStringLiteral("client_id"), clientId);
    if (!clientSecret.isEmpty())
        form.addQueryItem(QStringLiteral("client_secret"), clientSecret);
    for (const auto &[key, value] : grant)
        form.addQueryItem(key, QUrl::toPercentEncoding(value));

    QNetworkRequest req{QUrl(endpointsFor(provider).tokenUrl)};
    req.setHeader(QNetworkRequest::ContentTypeHeader,
                  QStringLiteral("application/x-www-form-urlencoded"));
    QNetworkReply *reply =
        m_nam->post(req, form.toString(QUrl::FullyEncoded).toLatin1());
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        reply->deleteLater();
        const QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
        const QString accessToken = obj.value(QStringLiteral("access_token")).toString();
        if (accessToken.isEmpty()) {
            const QString desc = obj.value(QStringLiteral("error_description")).toString();
            const QString err = obj.value(QStringLiteral("error")).toString();
            Q_EMIT failed(tr("OAuth token request failed: %1")
                              .arg(!desc.isEmpty() ? desc
                                                   : !err.isEmpty() ? err
                                                                    : reply->errorString()));
            return;
        }
        const int expiresIn = obj.value(QStringLiteral("expires_in")).toInt(3600);
        Q_EMIT tokensReady(accessToken,
                           obj.value(QStringLiteral("refresh_token")).toString(),
                           QDateTime::currentDateTimeUtc().addSecs(expiresIn - 60));
    });
}
