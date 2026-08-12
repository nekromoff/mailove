// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "keydiscovery.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

#ifdef MAILOVE_HAVE_OPENPGP
#include <gpgme++/data.h>
#include <gpgme++/error.h>
#include <qgpgme/protocol.h>
#include <qgpgme/wkdlookupjob.h>
#include <qgpgme/wkdlookupresult.h>

#include <gpg-error.h>
#endif

namespace
{
/// The only keyserver mailove will talk to. Address-verified, does not serve
/// flooded keys; see doc/openpgp.md §7 for why the SKS pool is not an option.
const char kVksHost[] = "keys.openpgp.org";

/// A public key that does not fit in this is not a key we want: keyservers
/// have historically been used to serve megabyte-sized certificate floods,
/// and importing one wedges gpg rather than failing cleanly.
constexpr qint64 kMaxKeyBytes = 512 * 1024;
}

KeyDiscovery::KeyDiscovery(QObject *parent)
    : QObject(parent)
{
}

void KeyDiscovery::lookupWkd(const QString &address)
{
#ifdef MAILOVE_HAVE_OPENPGP
    QGpgME::WKDLookupJob *job = QGpgME::openpgp()->wkdLookupJob();
    if (!job) {
        Q_EMIT finished(address, {}, QStringLiteral("WKD"),
                        tr("This installation of GnuPG cannot look up keys."));
        return;
    }
    connect(job, &QGpgME::WKDLookupJob::result, this,
            [this, address](const QGpgME::WKDLookupResult &result) {
                const GpgME::Error err = result.error();
                // "No data" is dirmngr's way of saying the domain publishes
                // nothing for this address — the common case, and not a fault
                // to report as one.
                if (err && err.code() != GPG_ERR_NO_DATA) {
                    Q_EMIT finished(address, {}, QStringLiteral("WKD"),
                                    QString::fromStdString(err.asStdString()));
                    return;
                }
                // A lookup that found nothing comes back with a null Data, and
                // toString() on one of those does not return an empty string —
                // it tries to allocate a string of garbage length and throws.
                // The null check has to come first.
                GpgME::Data data = result.keyData();
                const std::string bytes = data.isNull() ? std::string() : data.toString();
                if (bytes.empty()) {
                    Q_EMIT finished(address, {}, QStringLiteral("WKD"), QString());
                    return;
                }
                const QString source = result.source().empty()
                    ? QStringLiteral("WKD")
                    : QStringLiteral("WKD (%1)")
                          .arg(QString::fromStdString(result.source()));
                Q_EMIT finished(address, QByteArray::fromStdString(bytes), source,
                                QString());
            });
    const GpgME::Error err = job->start(address);
    if (err) {
        Q_EMIT finished(address, {}, QStringLiteral("WKD"),
                        QString::fromStdString(err.asStdString()));
        job->deleteLater();
    }
#else
    Q_EMIT finished(address, {}, QStringLiteral("WKD"),
                    tr("Mailove was built without OpenPGP support."));
#endif
}

void KeyDiscovery::lookupKeyserver(const QString &address)
{
    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(QString::fromLatin1(kVksHost));
    url.setPath(QStringLiteral("/vks/v1/by-email/") + address);

    QNetworkRequest req(url);
    // No redirects at all. The point of naming one keyserver is that the query
    // reaches that host and nowhere else; a redirect would quietly undo it.
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QVariant::fromValue(QNetworkRequest::ManualRedirectPolicy));
    req.setTransferTimeout(15000);
    req.setRawHeader("Accept", "application/pgp-keys");

    QNetworkReply *reply = m_net->get(req);
    const QString source = QStringLiteral("keys.openpgp.org");
    connect(reply, &QNetworkReply::downloadProgress, reply,
            [reply](qint64 received, qint64) {
                if (received > kMaxKeyBytes)
                    reply->abort();
            });
    connect(reply, &QNetworkReply::finished, this, [this, reply, address, source] {
        reply->deleteLater();
        const int status =
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status == 404) {
            Q_EMIT finished(address, {}, source, QString());
            return;
        }
        if (reply->error() != QNetworkReply::NoError) {
            Q_EMIT finished(address, {}, source, reply->errorString());
            return;
        }
        const QByteArray body = reply->readAll();
        if (body.size() > kMaxKeyBytes) {
            Q_EMIT finished(address, {}, source, tr("The published key is too large."));
            return;
        }
        Q_EMIT finished(address, body, source, QString());
    });
}
