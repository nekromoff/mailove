// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QUrl>

#include "mailbackend.h"

class QNetworkAccessManager;
class QNetworkReply;
class QNetworkRequest;

/**
 * The JMAP session object (RFC 8620 §2) and the discovery that fetches it.
 *
 * Everything else in the JMAP backend needs this first: it is the only place
 * an endpoint URL comes from. A JMAP account is configured with an address and
 * a credential and nothing else — no host, no port, no security setting —
 * because `https://<domain>/.well-known/jmap` answers with the API, download,
 * upload and EventSource URLs, the account ids, and the server's limits. That
 * is why AccountSheet.qml can hide most of its rows for JMAP.
 *
 * Parsing is deliberately separate from fetching. ingest() takes the bytes of a
 * session object and the URL they came from, and is a pure function of the two;
 * discover() is the network leg that calls it. The split is what lets the whole
 * of RFC 8620 §2 — relative URLs, URI templates, primary-account selection,
 * capability limits — be tested offline against recorded JSON, with the live
 * server reserved for confirming that real ones look like the recordings.
 *
 * One instance is one account. Sessions expire: the `state` string changes when
 * the server's answer would differ, and a 401 on any later request means this
 * object is stale and discover() must run again.
 */
class JmapSession : public QObject
{
    Q_OBJECT

public:
    /// The capability URIs this client cares about. Registered names, not ours
    /// to choose; a server advertising none of them is not a mail server we can
    /// use.
    static QString coreCapability();       ///< urn:ietf:params:jmap:core
    static QString mailCapability();       ///< urn:ietf:params:jmap:mail
    static QString submissionCapability(); ///< urn:ietf:params:jmap:submission

    /// One account the session grants access to. Only the fields that change
    /// what the client may do are kept: the rest of RFC 8620's Account object
    /// is display material we take from the user's own settings instead.
    struct Account {
        QString id;
        QString name;
        bool isPersonal = false;
        bool isReadOnly = false;
        QStringList capabilities; ///< keys of accountCapabilities
    };

    /// The server's own ceilings, from the core capability object. Honouring
    /// these is not optional: a batch over maxCallsInRequest is refused
    /// wholesale, so JmapRequest splits by them rather than discovering the
    /// limit by being rejected. Zero means the server did not say.
    struct Limits {
        qint64 maxSizeUpload = 0;
        qint64 maxConcurrentUpload = 0;
        qint64 maxSizeRequest = 0;
        qint64 maxCallsInRequest = 0;
        qint64 maxObjectsInGet = 0;
        qint64 maxObjectsInSet = 0;
        qint64 maxConcurrentRequests = 0;
    };

    explicit JmapSession(QObject *parent = nullptr);
    ~JmapSession() override;

    /// Fetches the session object for \a credentials and ingests it. The host
    /// is taken from Credentials::host when set and from the domain of
    /// Credentials::user otherwise, so an address alone is enough to configure
    /// an account. Answered by ready() or failed(); safe to call again to
    /// refresh a session the server has aged out.
    void discover(const MailBackend::Credentials &credentials);
    /// Runs discovery again with the credentials of the last discover(). What
    /// a 401 on an ordinary request means: sessions expire, and the answer is
    /// a new session object rather than a new password. Does nothing and emits
    /// failed(Error::Auth) if discover() was never called.
    void refresh();
    /// Swaps in a freshly minted OAuth access token, so the next request — and
    /// any refresh() after it — authenticates with the live one rather than
    /// the token discover() was handed. Does nothing before discover(): there
    /// are no credentials to amend yet.
    void setAccessToken(const QString &accessToken);
    /// Abandons a discovery in flight. Emits nothing — the caller asked.
    void cancel();

    /// The Authorization header value every request to this session carries.
    QByteArray authorization() const { return m_authorization; }

    /// Puts the credential and the redirect policy on a request to one of this
    /// session's own endpoints. Every authenticated JMAP request goes through
    /// here rather than setting the header itself: the credential must reach
    /// this session's origin and nowhere else, and that is two decisions — what
    /// the request is addressed to (checked when the session object is
    /// ingested) and where a redirect may take it (guardRedirects(), below).
    void authorize(QNetworkRequest &request) const;
    /// Refuses redirects that leave the session's origin. Qt re-sends raw
    /// headers to the redirect target and only stops at an https-to-http
    /// downgrade, so without this a 302 from the server hands the account's
    /// token to whatever host the Location names. Call on every reply whose
    /// request went through authorize().
    void guardRedirects(QNetworkReply *reply) const;
    /// Scheme, host and effective port of the URL the session object came
    /// from — the one origin this session's credential is for.
    QUrl origin() const { return m_origin; }

    /// Parses a session object. \a from is the URL the bytes were served from,
    /// against which relative endpoint URLs are resolved (RFC 8620 §2 permits
    /// them, and Cyrus emits them). Returns false and sets \a error without
    /// touching any existing state, so a failed refresh leaves a working
    /// session working.
    bool ingest(const QByteArray &json, const QUrl &from, QString *error);

    /// True once a session object has been ingested and named a mail account.
    bool isValid() const { return m_valid; }
    /// Discards everything ingested, back to the state of a fresh instance.
    void clear();

    QUrl apiUrl() const { return m_apiUrl; }
    QUrl downloadUrlTemplate() const { return m_downloadUrl; }
    QUrl uploadUrlTemplate() const { return m_uploadUrl; }
    QUrl eventSourceUrlTemplate() const { return m_eventSourceUrl; }

    /// The session's own version marker. A changed one means anything cached
    /// from the session object — endpoints, account ids, limits — may have
    /// moved.
    QString state() const { return m_state; }
    /// The login name the server says these credentials belong to, which need
    /// not be the address the user typed.
    QString username() const { return m_username; }

    /// The account mail operations address: `primaryAccounts` for the mail
    /// capability, or — for servers that omit it — the first account offering
    /// mail, personal ones first. Empty when none does.
    QString mailAccountId() const { return m_mailAccountId; }
    /// The account submissions are made from. Usually the mail account, but a
    /// server may separate them, and EmailSubmission/set is rejected against
    /// the wrong one.
    QString submissionAccountId() const { return m_submissionAccountId; }

    QList<Account> accounts() const { return m_accounts; }
    Limits limits() const { return m_limits; }
    /// True when the server advertises \a uri at session level.
    bool hasCapability(const QString &uri) const;
    /// True when \a accountId does. A server may speak submission without
    /// every account being allowed to submit.
    bool accountHasCapability(const QString &accountId, const QString &uri) const;

    /// Expands an RFC 6570 level-1 template — the only kind JMAP's URLs use.
    /// Every `{name}` is replaced by the percent-encoded \a variables value,
    /// and a name with no value becomes empty, which is what the spec's
    /// optional EventSource parameters want.
    static QUrl expandTemplate(const QUrl &tpl, const QHash<QString, QString> &variables);
    /// The blob download URL for one attachment or message body.
    QUrl downloadUrl(const QString &accountId, const QString &blobId,
                     const QString &type, const QString &name) const;
    QUrl uploadUrl(const QString &accountId) const;
    /// The push channel. \a types is the JMAP type list to subscribe to (empty
    /// means all), \a pingSeconds the keepalive interval the server should send
    /// at, 0 for none.
    QUrl eventSourceUrl(const QStringList &types, int pingSeconds) const;

    /// The value for the Authorization header these credentials imply: Bearer
    /// when an OAuth token is present, Basic otherwise. Every JMAP request
    /// carries it — there is no session cookie in the protocol.
    static QByteArray authorizationHeader(const MailBackend::Credentials &credentials);
    /// The session resource to try first for \a credentials.
    static QUrl wellKnownUrl(const MailBackend::Credentials &credentials);

Q_SIGNALS:
    /// The session object was fetched and understood; every accessor above is
    /// now populated.
    void ready();
    /// Discovery failed. Error::Auth means the credentials were refused,
    /// Error::Protocol that the server answered with something that is not a
    /// usable JMAP session.
    void failed(MailBackend::Error error, const QString &message);

private:
    void handleReply(QNetworkReply *reply);

    QNetworkAccessManager *m_net = nullptr;
    QPointer<QNetworkReply> m_reply;
    QByteArray m_authorization;
    /// Kept for refresh() alone. A JMAP session is re-established by
    /// re-authenticating, so the credential has to outlive the first discovery
    /// exactly as ImapBackend's does for its reconnects.
    MailBackend::Credentials m_credentials;
    bool m_haveCredentials = false;

    bool m_valid = false;
    QUrl m_origin; ///< where the session object came from; see authorize()
    QUrl m_apiUrl;
    QUrl m_downloadUrl;
    QUrl m_uploadUrl;
    QUrl m_eventSourceUrl;
    QString m_state;
    QString m_username;
    QString m_mailAccountId;
    QString m_submissionAccountId;
    QList<Account> m_accounts;
    QStringList m_capabilities;
    Limits m_limits;
};
