// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QDateTime>
#include <QObject>
#include <QString>
#include <QUrl>

class QNetworkAccessManager;
class QTcpServer;

/**
 * Minimal OAuth2 authorization-code flow with PKCE for mail providers.
 *
 * authorize() opens the system browser and captures the redirect on a
 * loopback TCP port; refresh() trades a stored refresh token for a fresh
 * access token. No QtNetworkAuth dependency.
 *
 * The client id (and, for Google desktop clients, the client "secret" —
 * which is not actually confidential for installed apps) must be created by
 * the user in the provider's developer console.
 */
class OAuthHelper : public QObject
{
    Q_OBJECT

public:
    enum Provider { Gmail = 1, Microsoft = 2 };

    explicit OAuthHelper(QObject *parent = nullptr);

    /// Interactive browser sign-in. Emits tokensReady() or failed().
    /// \a loginHint (the account's address) preselects that account on the
    /// provider's page, so a browser signed in as somebody else does not
    /// quietly authorize the wrong one. With \a openBrowser false nothing is
    /// launched: the listener waits all the same, and authorizationUrl() is
    /// the only way in — for pasting into a different browser or profile.
    void authorize(Provider provider, const QString &clientId, const QString &clientSecret,
                   const QString &loginHint = QString(), bool openBrowser = true);
    /// Where the sign-in in flight asks the user to go; empty when none is.
    QUrl authorizationUrl() const { return m_authUrl; }
    /// Silent renewal from a refresh token. Emits tokensReady() or failed().
    void refresh(Provider provider, const QString &clientId, const QString &clientSecret,
                 const QString &refreshToken);

Q_SIGNALS:
    /// refreshToken may be empty on a refresh() that did not rotate it.
    void tokensReady(const QString &accessToken, const QString &refreshToken,
                     const QDateTime &expiry);
    void failed(const QString &message);
    /// authorizationUrl() changed: a sign-in started, or the one in flight ended.
    void authorizationUrlChanged();

private:
    struct Endpoints {
        QString authUrl;
        QString tokenUrl;
        QString scope;
    };
    static Endpoints endpointsFor(Provider provider);

    void requestToken(Provider provider, const QString &clientId,
                      const QString &clientSecret, const QList<std::pair<QString, QString>> &grant);

    /// Tears the loopback listener down and forgets the one-shot flow state,
    /// so a late or replayed redirect cannot be redeemed.
    void endRedirectListener();

    QNetworkAccessManager *m_nam = nullptr;
    QTcpServer *m_server = nullptr;
    QString m_codeVerifier;
    /// CSRF nonce tying the redirect back to the authorize() we started.
    /// Empty whenever no sign-in is in flight.
    QString m_state;
    QUrl m_authUrl;
};
