// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "jmapsession.h"

#include "publicsuffixlist.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace
{
/// A session object is a few kilobytes; a megabyte is already a sign the URL
/// answered with something else entirely (a login page, a proxy error). Refuse
/// it rather than parse it.
constexpr qint64 kMaxSessionBytes = 1024 * 1024;
/// Discovery blocks the account coming up, so it fails fast enough that a
/// wrong hostname is a visible error rather than a spinner.
constexpr int kDiscoveryTimeoutMs = 30000;

/// The template with its braces readable. QUrl percent-encodes `{` and `}`
/// because they are not legal URL characters, which is harmless for transport
/// but hides the variables from a plain string replace — so undo exactly that
/// much before expanding.
QString templateString(const QUrl &url)
{
    QString s = url.toString(QUrl::FullyEncoded);
    s.replace(QLatin1String("%7B"), QLatin1String("{"), Qt::CaseInsensitive);
    s.replace(QLatin1String("%7D"), QLatin1String("}"), Qt::CaseInsensitive);
    return s;
}

/// A URL from the session object, resolved against \a base so that the
/// relative forms RFC 8620 permits work. Tolerant parsing keeps the URI
/// template braces from being rejected outright.
QUrl sessionUrl(const QJsonObject &obj, const char *key, const QUrl &base)
{
    const QString raw = obj.value(QLatin1String(key)).toString();
    if (raw.isEmpty())
        return {};
    const QUrl parsed(raw, QUrl::TolerantMode);
    if (!parsed.isValid())
        return {};
    return parsed.isRelative() ? base.resolved(parsed) : parsed;
}

/// Same scheme, same host, same effective port. Ports are compared resolved
/// rather than as written, so ":443" and an omitted port are one origin.
bool sameOrigin(const QUrl &a, const QUrl &b)
{
    if (a.scheme().compare(b.scheme(), Qt::CaseInsensitive) != 0)
        return false;
    if (a.host().compare(b.host(), Qt::CaseInsensitive) != 0 || a.host().isEmpty())
        return false;
    const int defaultPort = a.scheme().compare(QLatin1String("http"), Qt::CaseInsensitive) == 0
        ? 80
        : 443;
    return a.port(defaultPort) == b.port(defaultPort);
}

/// Same site: the same origin, or two hosts under one registrable domain.
///
/// Same-origin alone would be the tighter rule, and it is the wrong one here:
/// RFC 8620 §2 lets a session object name absolute URLs, and a hosted provider
/// legitimately answers `example.com/.well-known/jmap` with endpoints on
/// `api.example.com`. What must not be allowed is an endpoint on a domain the
/// account has nothing to do with, because the credential goes with it.
///
/// The registrable domain comes from the Public Suffix List, so when that has
/// not loaded yet this falls back to exact or parent/child matching — stricter,
/// never looser, which is the safe way to be wrong. The scheme must match
/// either way: an https session may not send its credential over http.
bool sameSite(const QUrl &a, const QUrl &b)
{
    if (sameOrigin(a, b))
        return true;
    if (a.scheme().compare(b.scheme(), Qt::CaseInsensitive) != 0)
        return false;
    const QString ha = a.host().toLower();
    const QString hb = b.host().toLower();
    if (ha.isEmpty() || hb.isEmpty())
        return false;
    if (ha == hb)
        return true;

    const PublicSuffixList &psl = PublicSuffixList::instance();
    if (psl.isLoaded()) {
        const QString orgA = psl.organizationalDomain(ha);
        const QString orgB = psl.organizationalDomain(hb);
        // Empty means the host is itself a public suffix; "somewhere under
        // .co.uk" is not a relationship worth trusting a credential to.
        return !orgA.isEmpty() && orgA == orgB;
    }
    return ha.endsWith(QLatin1Char('.') + hb) || hb.endsWith(QLatin1Char('.') + ha);
}

/// JSON numbers arrive as doubles; the limits are byte counts and object
/// counts that a double represents exactly at any size a server will state.
qint64 limitValue(const QJsonObject &obj, const char *key)
{
    const QJsonValue v = obj.value(QLatin1String(key));
    return v.isDouble() ? static_cast<qint64>(v.toDouble()) : 0;
}
} // namespace

QString JmapSession::coreCapability()
{
    return QStringLiteral("urn:ietf:params:jmap:core");
}

QString JmapSession::mailCapability()
{
    return QStringLiteral("urn:ietf:params:jmap:mail");
}

QString JmapSession::submissionCapability()
{
    return QStringLiteral("urn:ietf:params:jmap:submission");
}

JmapSession::JmapSession(QObject *parent)
    : QObject(parent)
{
}

JmapSession::~JmapSession() = default;

void JmapSession::authorize(QNetworkRequest &request) const
{
    if (!m_authorization.isEmpty())
        request.setRawHeader(QByteArrayLiteral("Authorization"), m_authorization);
    // Not NoLessSafeRedirectPolicy: that one only refuses the https-to-http
    // downgrade and follows everything else, raw headers and all. Verified
    // means Qt stops and asks — guardRedirects() is what answers.
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QVariant::fromValue(QNetworkRequest::UserVerifiedRedirectPolicy));
}

void JmapSession::guardRedirects(QNetworkReply *reply) const
{
    if (!reply)
        return;
    const QUrl origin = m_origin;
    connect(reply, &QNetworkReply::redirected, reply, [reply, origin](const QUrl &target) {
        if (sameSite(target, origin)) {
            Q_EMIT reply->redirectAllowed();
            return;
        }
        // Aborting rather than following without the header: a request the
        // server answers with somebody else's URL is not one whose answer can
        // be trusted either, and the caller's error path already knows what to
        // do with a connection that ended early.
        qWarning() << "mailove: refusing JMAP redirect off-origin:" << target.host()
                   << "is not" << origin.host();
        reply->abort();
    });
}

void JmapSession::clear()
{
    m_valid = false;
    m_origin.clear();
    m_apiUrl.clear();
    m_downloadUrl.clear();
    m_uploadUrl.clear();
    m_eventSourceUrl.clear();
    m_state.clear();
    m_username.clear();
    m_mailAccountId.clear();
    m_submissionAccountId.clear();
    m_accounts.clear();
    m_capabilities.clear();
    m_limits = {};
}

QByteArray JmapSession::authorizationHeader(const MailBackend::Credentials &credentials)
{
    if (!credentials.accessToken.isEmpty())
        return QByteArrayLiteral("Bearer ") + credentials.accessToken.toUtf8();
    if (credentials.user.isEmpty() && credentials.password.isEmpty())
        return {};
    const QByteArray pair = credentials.user.toUtf8() + ':' + credentials.password.toUtf8();
    return QByteArrayLiteral("Basic ") + pair.toBase64();
}

QUrl JmapSession::wellKnownUrl(const MailBackend::Credentials &credentials)
{
    QString host = credentials.host.trimmed();
    if (host.isEmpty()) {
        // Address-only configuration: the domain of the login name is the
        // service, which is what .well-known exists to make true.
        const int at = credentials.user.lastIndexOf(QLatin1Char('@'));
        if (at >= 0)
            host = credentials.user.mid(at + 1).trimmed();
    }
    if (host.isEmpty())
        return {};

    if (!host.startsWith(QLatin1String("http://"), Qt::CaseInsensitive)
        && !host.startsWith(QLatin1String("https://"), Qt::CaseInsensitive)) {
        host.prepend(QLatin1String("https://"));
    }
    QUrl url(host, QUrl::TolerantMode);
    if (!url.isValid() || url.host().isEmpty())
        return {};

    // A host with a path is someone naming the session resource outright (a
    // test server on a port, a server that does not serve .well-known); take
    // them at their word.
    const QString path = url.path();
    if (path.isEmpty() || path == QLatin1String("/"))
        url.setPath(QStringLiteral("/.well-known/jmap"));
    return url;
}

void JmapSession::discover(const MailBackend::Credentials &credentials)
{
    cancel();

    const QUrl url = wellKnownUrl(credentials);
    if (!url.isValid()) {
        Q_EMIT failed(MailBackend::Error::Connection,
                      tr("No JMAP server to contact: the account has neither a host nor an "
                         "address to take one from."));
        return;
    }

    m_authorization = authorizationHeader(credentials);
    m_credentials = credentials;
    m_haveCredentials = true;

    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QNetworkRequest request(url);
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    if (!m_authorization.isEmpty())
        request.setRawHeader(QByteArrayLiteral("Authorization"), m_authorization);
    // RFC 8620 §2.2: /.well-known/jmap may redirect to where the session
    // object actually lives — including onto another host, which is how hosted
    // providers autodiscover. So this one request follows redirects across
    // origins, and the URL it ends on becomes the origin every later request is
    // pinned to (see ingest()). Qt's default policy follows that, but not from
    // https down to http, which would leak the credential above.
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QVariant::fromValue(QNetworkRequest::NoLessSafeRedirectPolicy));
    request.setTransferTimeout(kDiscoveryTimeoutMs);

    m_reply = m_net->get(request);
    connect(m_reply, &QNetworkReply::finished, this, [this] {
        QNetworkReply *reply = m_reply;
        if (!reply)
            return;
        m_reply = nullptr;
        reply->deleteLater();
        handleReply(reply);
    });
}

void JmapSession::refresh()
{
    if (!m_haveCredentials) {
        Q_EMIT failed(MailBackend::Error::Auth,
                      tr("There is no JMAP session to refresh."));
        return;
    }
    discover(m_credentials);
}

void JmapSession::cancel()
{
    if (!m_reply)
        return;
    QNetworkReply *reply = m_reply;
    m_reply = nullptr;
    reply->disconnect(this);
    reply->abort();
    reply->deleteLater();
}

void JmapSession::handleReply(QNetworkReply *reply)
{
    const int status =
        reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    if (status == 401 || status == 403) {
        Q_EMIT failed(MailBackend::Error::Auth,
                      tr("The server rejected these credentials."));
        return;
    }
    if (status == 429) {
        Q_EMIT failed(MailBackend::Error::Throttled,
                      tr("The server is asking for a slower pace; try again shortly."));
        return;
    }
    if (reply->error() != QNetworkReply::NoError && status < 400) {
        // No HTTP status at all: it never got as far as an answer.
        Q_EMIT failed(MailBackend::Error::Connection, reply->errorString());
        return;
    }
    if (status != 200) {
        Q_EMIT failed(MailBackend::Error::Protocol,
                      tr("The server answered the JMAP session request with HTTP %1.")
                          .arg(status));
        return;
    }

    const QByteArray body = reply->read(kMaxSessionBytes + 1);
    if (body.size() > kMaxSessionBytes) {
        Q_EMIT failed(MailBackend::Error::Protocol,
                      tr("The JMAP session object is implausibly large; this does not look "
                         "like a JMAP server."));
        return;
    }

    QString error;
    if (!ingest(body, reply->url(), &error)) {
        Q_EMIT failed(MailBackend::Error::Protocol, error);
        return;
    }
    Q_EMIT ready();
}

bool JmapSession::ingest(const QByteArray &json, const QUrl &from, QString *error)
{
    const auto fail = [error](const QString &what) {
        if (error)
            *error = what;
        return false;
    };

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError)
        return fail(tr("The JMAP session object is not valid JSON: %1")
                        .arg(parseError.errorString()));
    if (!doc.isObject())
        return fail(tr("The JMAP session object is not a JSON object."));

    const QJsonObject root = doc.object();

    // Parsed into locals throughout: a refresh that turns out to be nonsense
    // must leave the session that is already working untouched.
    // Every endpoint here is a URL the *server* chose, and every request to one
    // carries the account's password or access token. An absolute URL naming
    // another host would therefore hand the credential to that host, so the
    // session may only point at the origin it was itself served from — which,
    // after any .well-known redirect, is `from`. Relative URLs (what RFC 8620
    // §2 expects, and what Cyrus emits) resolve to it by definition and always
    // pass. `wrongOrigin` is empty for a URL that may be used.
    QString wrongOrigin;
    const auto endpoint = [&](const char *key) {
        const QUrl url = sessionUrl(root, key, from);
        if (!url.isEmpty() && !sameSite(url, from) && wrongOrigin.isEmpty()) {
            wrongOrigin =
                tr("The JMAP session object points %1 at %2, which belongs to neither the "
                   "server it came from nor that server's domain. Refusing to send this "
                   "account's credentials there.")
                    .arg(QString::fromLatin1(key), url.host());
            return QUrl();
        }
        return url;
    };
    const QUrl apiUrl = endpoint("apiUrl");
    const QUrl downloadUrl = endpoint("downloadUrl");
    const QUrl uploadUrl = endpoint("uploadUrl");
    const QUrl eventSourceUrl = endpoint("eventSourceUrl");
    if (!wrongOrigin.isEmpty())
        return fail(wrongOrigin);
    if (!apiUrl.isValid() || apiUrl.isEmpty())
        return fail(tr("The JMAP session object names no apiUrl."));

    QStringList capabilities;
    const QJsonObject capsObject = root.value(QLatin1String("capabilities")).toObject();
    capabilities = capsObject.keys();

    Limits limits;
    const QJsonObject core = capsObject.value(coreCapability()).toObject();
    limits.maxSizeUpload = limitValue(core, "maxSizeUpload");
    limits.maxConcurrentUpload = limitValue(core, "maxConcurrentUpload");
    limits.maxSizeRequest = limitValue(core, "maxSizeRequest");
    limits.maxCallsInRequest = limitValue(core, "maxCallsInRequest");
    limits.maxObjectsInGet = limitValue(core, "maxObjectsInGet");
    limits.maxObjectsInSet = limitValue(core, "maxObjectsInSet");
    limits.maxConcurrentRequests = limitValue(core, "maxConcurrentRequests");

    QList<Account> accounts;
    const QJsonObject accountsObject = root.value(QLatin1String("accounts")).toObject();
    for (auto it = accountsObject.constBegin(); it != accountsObject.constEnd(); ++it) {
        const QJsonObject value = it.value().toObject();
        Account account;
        account.id = it.key();
        account.name = value.value(QLatin1String("name")).toString();
        account.isPersonal = value.value(QLatin1String("isPersonal")).toBool();
        account.isReadOnly = value.value(QLatin1String("isReadOnly")).toBool();
        account.capabilities =
            value.value(QLatin1String("accountCapabilities")).toObject().keys();
        accounts.append(account);
    }

    const QJsonObject primary = root.value(QLatin1String("primaryAccounts")).toObject();
    const auto known = [&accounts](const QString &id) {
        if (id.isEmpty())
            return false;
        for (const Account &account : std::as_const(accounts)) {
            if (account.id == id)
                return true;
        }
        return false;
    };
    // primaryAccounts is the server's own answer and wins; the scan behind it
    // is for servers that omit it (the spec allows an empty object) and for
    // ones that name an account they then do not list.
    const auto pick = [&](const QString &capability) {
        const QString stated = primary.value(capability).toString();
        if (known(stated))
            return stated;
        QString fallback;
        for (const Account &account : std::as_const(accounts)) {
            if (!account.capabilities.contains(capability))
                continue;
            if (account.isPersonal)
                return account.id;
            if (fallback.isEmpty())
                fallback = account.id;
        }
        return fallback;
    };

    const QString mailAccountId = pick(mailCapability());
    if (mailAccountId.isEmpty())
        return fail(tr("The JMAP server offers no account with mail access."));

    QString submissionAccountId = pick(submissionCapability());
    if (submissionAccountId.isEmpty()) {
        // A server that cannot submit is still worth reading mail from, so
        // this is recorded, never fatal; sendMessage() is where the absence
        // is finally reported, and only to someone actually trying to send.
        submissionAccountId.clear();
    }

    // Origin first: it is what authorize() and guardRedirects() enforce, and
    // every endpoint below has just been checked against it.
    m_origin = from;
    m_apiUrl = apiUrl;
    m_downloadUrl = downloadUrl;
    m_uploadUrl = uploadUrl;
    m_eventSourceUrl = eventSourceUrl;
    m_state = root.value(QLatin1String("state")).toString();
    m_username = root.value(QLatin1String("username")).toString();
    m_capabilities = capabilities;
    m_limits = limits;
    m_accounts = accounts;
    m_mailAccountId = mailAccountId;
    m_submissionAccountId = submissionAccountId;
    m_valid = true;

    if (error)
        error->clear();
    return true;
}

bool JmapSession::hasCapability(const QString &uri) const
{
    return m_capabilities.contains(uri);
}

bool JmapSession::accountHasCapability(const QString &accountId, const QString &uri) const
{
    for (const Account &account : m_accounts) {
        if (account.id == accountId)
            return account.capabilities.contains(uri);
    }
    return false;
}

QUrl JmapSession::expandTemplate(const QUrl &tpl, const QHash<QString, QString> &variables)
{
    if (tpl.isEmpty())
        return {};

    QString text = templateString(tpl);
    // Walk the template rather than iterating the variables: a name the caller
    // did not supply has to become empty (JMAP's EventSource parameters are
    // optional), and a value that happens to contain braces must not then be
    // rescanned as a template of its own.
    QString expanded;
    expanded.reserve(text.size());
    int i = 0;
    while (i < text.size()) {
        const int open = text.indexOf(QLatin1Char('{'), i);
        if (open < 0) {
            expanded += QStringView(text).mid(i);
            break;
        }
        const int close = text.indexOf(QLatin1Char('}'), open + 1);
        if (close < 0) {
            expanded += QStringView(text).mid(i);
            break;
        }
        expanded += QStringView(text).mid(i, open - i);
        const QString name = text.mid(open + 1, close - open - 1);
        const QString value = variables.value(name);
        if (!value.isEmpty())
            expanded += QString::fromLatin1(QUrl::toPercentEncoding(value));
        i = close + 1;
    }

    return QUrl(expanded, QUrl::StrictMode);
}

QUrl JmapSession::downloadUrl(const QString &accountId, const QString &blobId,
                              const QString &type, const QString &name) const
{
    return expandTemplate(m_downloadUrl,
                          {{QStringLiteral("accountId"), accountId},
                           {QStringLiteral("blobId"), blobId},
                           {QStringLiteral("type"), type},
                           {QStringLiteral("name"), name}});
}

QUrl JmapSession::uploadUrl(const QString &accountId) const
{
    return expandTemplate(m_uploadUrl, {{QStringLiteral("accountId"), accountId}});
}

QUrl JmapSession::eventSourceUrl(const QStringList &types, int pingSeconds) const
{
    return expandTemplate(
        m_eventSourceUrl,
        {{QStringLiteral("types"), types.isEmpty() ? QStringLiteral("*") : types.join(QLatin1Char(','))},
         {QStringLiteral("closeafter"), QStringLiteral("no")},
         {QStringLiteral("ping"), QString::number(qMax(0, pingSeconds))}});
}
