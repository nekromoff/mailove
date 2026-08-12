// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "avatarprovider.h"

#include <QBuffer>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QImageReader>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>

#include <chrono>

/// How long a fetched picture is reused before asking again. Avatars change
/// rarely and a stale one is a cosmetic problem, so this is generous: the
/// point of the cache is that opening a thread of twenty messages from the
/// same person is one request, not twenty.
static constexpr qint64 kHitDays = 30;
/// And how long "this address has no picture" is remembered. Shorter: someone
/// who signs up for Gravatar should show up within the week.
static constexpr qint64 kMissDays = 7;
/// Refuse anything implausible for a small square avatar. Gravatar sends a few
/// KB; this is only here so a hostile or broken response cannot be read into
/// memory unbounded.
static constexpr qint64 kMaxBytes = 2 * 1024 * 1024;

AvatarFetcher::AvatarFetcher(QObject *parent)
    : QObject(parent)
{
    // Not created here: the object is constructed on the GUI thread and then
    // moved, and the directory (like the QNetworkAccessManager) is only ever
    // touched from the worker.
}

QString AvatarFetcher::cacheFile(const QString &hash, int size, bool miss) const
{
    return m_dir + QLatin1Char('/') + hash + QLatin1Char('-') + QString::number(size)
        + (miss ? QLatin1String(".none") : QLatin1String(".png"));
}

QImage AvatarFetcher::cached(const QString &hash, int size, bool *known) const
{
    *known = false;
    const QDateTime now = QDateTime::currentDateTimeUtc();

    const QFileInfo miss(cacheFile(hash, size, true));
    if (miss.exists() && miss.lastModified().daysTo(now) < kMissDays) {
        *known = true;
        return QImage();
    }

    const QFileInfo hit(cacheFile(hash, size, false));
    if (hit.exists() && hit.lastModified().daysTo(now) < kHitDays) {
        QImage image;
        if (image.load(hit.absoluteFilePath())) {
            *known = true;
            return image;
        }
    }
    return QImage();
}

void AvatarFetcher::store(const QString &hash, int size, const QImage &image)
{
    if (m_dir.isEmpty())
        return;
    // Both files are rewritten so the timestamps say what the last answer was:
    // a picture that has been removed upstream must stop being served, and an
    // address that has just acquired one must stop counting as a miss.
    const QString hitPath = cacheFile(hash, size, false);
    const QString missPath = cacheFile(hash, size, true);
    if (image.isNull()) {
        QFile::remove(hitPath);
        QFile marker(missPath);
        if (marker.open(QIODevice::WriteOnly | QIODevice::Truncate))
            marker.close();
    } else {
        QFile::remove(missPath);
        image.save(hitPath, "PNG");
    }
}

void AvatarFetcher::fetch(const QString &hash, int size)
{
    if (m_dir.isEmpty()) {
        m_dir = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
            + QLatin1String("/avatars");
        QDir().mkpath(m_dir);
    }

    bool known = false;
    const QImage hit = cached(hash, size, &known);
    if (known) {
        Q_EMIT fetched(hash, size, hit);
        return;
    }

    if (!m_net) {
        m_net = new QNetworkAccessManager(this);
        // Nothing here needs a session, and an avatar request must not carry
        // one: no cookie should tie two addresses looked up here together.
        m_net->setCookieJar(nullptr);
    }

    // d=404 rather than a generated identicon: this one request is also the
    // existence check — 200 means there is a picture and it is already in
    // hand, 404 means this address has none and nothing is shown. Asking for
    // an identicon instead would always answer 200 with a machine-generated
    // pattern that says nothing about the sender, and a separate probe (a HEAD
    // request, or the .json profile) would be a second round trip to learn
    // what the status code of this one already says.
    QUrl url(QStringLiteral("https://gravatar.com/avatar/") + hash);
    url.setQuery(QStringLiteral("s=%1&d=404").arg(size));

    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::NoLessSafeRedirectPolicy);
    req.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("mailove"));
    req.setTransferTimeout(std::chrono::seconds(15));

    QNetworkReply *reply = m_net->get(req);
    connect(reply, &QNetworkReply::downloadProgress, reply,
            [reply](qint64 received, qint64 total) {
                if (received > kMaxBytes || total > kMaxBytes)
                    reply->abort();
            });
    connect(reply, &QNetworkReply::finished, this, [this, reply, hash, size] {
        reply->deleteLater();
        QImage image;
        // A network error (offline, timeout) is not an answer about this
        // address, so it is not cached as one — only a clean 404 or a clean
        // picture is. Retrying next time the message is opened is cheap.
        const bool transportOk = reply->error() == QNetworkReply::NoError;
        const int status =
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (transportOk && status == 200) {
            const QByteArray body = reply->readAll();
            if (body.size() <= kMaxBytes) {
                // Decode by sniffing the data, never by the server's say-so
                // about its type or the URL's extension.
                QBuffer buffer;
                buffer.setData(body);
                buffer.open(QIODevice::ReadOnly);
                QImageReader reader(&buffer);
                reader.setAutoTransform(true);
                image = reader.read();
            }
            if (!image.isNull() && (image.width() > size || image.height() > size)) {
                image = image.scaled(size, size, Qt::KeepAspectRatio,
                                     Qt::SmoothTransformation);
            }
            store(hash, size, image);
        } else if (status == 404) {
            store(hash, size, QImage());
        }
        Q_EMIT fetched(hash, size, image);
    });
}

/// One pending Image.source. Created on the thread that asked for it (the QML
/// engine's), completed from the worker's fetched() through a queued
/// connection.
class AvatarResponse : public QQuickImageResponse
{
    Q_OBJECT
public:
    AvatarResponse(const QString &hash, int size)
        : m_hash(hash)
        , m_size(size)
    {
    }

    QQuickTextureFactory *textureFactory() const override
    {
        return QQuickTextureFactory::textureFactoryForImage(m_image);
    }

    /// A non-empty error is what makes the Image go to Image.Error rather than
    /// Image.Ready with nothing in it, which is how the viewer tells "no
    /// picture for this sender" from "picture on its way".
    QString errorString() const override
    {
        return m_image.isNull() ? QStringLiteral("no avatar") : QString();
    }

public Q_SLOTS:
    void handle(const QString &hash, int size, const QImage &image)
    {
        // The fetcher answers every listener; this one only wants its own.
        if (hash != m_hash || size != m_size)
            return;
        m_image = image;
        Q_EMIT finished();
    }

private:
    QString m_hash;
    int m_size;
    QImage m_image;
};

AvatarProvider::AvatarProvider()
    : m_fetcher(new AvatarFetcher)
{
    m_thread.setObjectName(QStringLiteral("avatars"));
    m_fetcher->moveToThread(&m_thread);
    connect(&m_thread, &QThread::finished, m_fetcher, &QObject::deleteLater);
    connect(this, &AvatarProvider::request, m_fetcher, &AvatarFetcher::fetch);
    m_thread.start();
}

AvatarProvider::~AvatarProvider()
{
    m_thread.quit();
    m_thread.wait();
}

QQuickImageResponse *AvatarProvider::requestImageResponse(const QString &id,
                                                          const QSize &requestedSize)
{
    Q_UNUSED(requestedSize)

    // "<pixels>/<hex sha-256>", as built by MailClient::avatarSource().
    const qsizetype slash = id.indexOf(QLatin1Char('/'));
    const int size = slash > 0 ? id.left(slash).toInt() : 0;
    const QString hash = slash > 0 ? id.mid(slash + 1) : QString();
    // The hash goes into a URL, so it is checked rather than trusted: only
    // 64 hex digits, which is the one thing a SHA-256 can look like.
    static const QRegularExpression hex(QStringLiteral("\\A[0-9a-f]{64}\\z"));
    auto *response = new AvatarResponse(hash, size);
    if (size < 8 || size > 512 || !hex.match(hash).hasMatch()) {
        // Queued, not immediate: the engine connects to finished() only after
        // this returns, and a response that has already finished by then would
        // never be collected.
        QTimer::singleShot(0, response,
                           [response, hash, size] { response->handle(hash, size, QImage()); });
        return response;
    }

    connect(m_fetcher, &AvatarFetcher::fetched, response, &AvatarResponse::handle);
    Q_EMIT request(hash, size);
    return response;
}

#include "avatarprovider.moc"
