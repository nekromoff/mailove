// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QImage>
#include <QObject>
#include <QQuickAsyncImageProvider>
#include <QString>
#include <QThread>

class QNetworkAccessManager;

/**
 * Gravatar sender pictures, fetched off the GUI thread.
 *
 * Off unless the reader turns it on (advanced.conf, avatars/enabled): asking
 * gravatar.com for a picture tells gravatar.com that this address was seen, so
 * nothing is requested — or cached — until that is agreed to. The switch is
 * read where the source URL is built and again here, because this is the class
 * that would make the request.
 *
 * How long an answer is kept is avatars/cacheDays (a year by default, since a
 * stale avatar costs nothing and every re-ask is another request gravatar.com
 * sees) and avatars/missCacheDays for "this address has none", a month.
 *
 * The address itself never leaves the machine — what goes out is its SHA-256,
 * which is what Gravatar keys avatars by, and the provider is handed the hash
 * rather than the address (see MailClient::avatarSource()).
 *
 * Image source URLs are image://gravatar/<pixels>/<hex sha-256>.
 */

/// Downloads and caches one avatar at a time on its own thread. Lives on
/// AvatarProvider's worker thread — every method here runs there, including
/// the network replies, so neither the request nor the PNG decode touches the
/// GUI thread.
class AvatarFetcher : public QObject
{
    Q_OBJECT
public:
    explicit AvatarFetcher(QObject *parent = nullptr);

public Q_SLOTS:
    /// Answers with fetched() exactly once per call — from the disk cache when
    /// it can, from gravatar.com otherwise. A null image means "no picture for
    /// this address", which is not an error: most addresses have none.
    void fetch(const QString &hash, int size);

Q_SIGNALS:
    void fetched(const QString &hash, int size, const QImage &image);

private:
    /// <cache>/avatars/<hash>-<size>.png for a picture, .none for a miss.
    QString cacheFile(const QString &hash, int size, bool miss) const;
    /// Cached answer for this hash/size, or a null QImage when there is none
    /// worth reusing. \a known says a cached miss was found, so the answer is
    /// "no picture" and no request is due.
    QImage cached(const QString &hash, int size, bool *known) const;
    void store(const QString &hash, int size, const QImage &image);

    QNetworkAccessManager *m_net = nullptr; ///< created lazily, on this thread
    QString m_dir;                          ///< avatar cache directory
};

/// The image provider QML talks to. Owns the fetcher thread; the engine owns
/// the provider.
/// (QQmlImageProviderBase, which QQuickAsyncImageProvider derives from, is
/// already a QObject — hence the signal without a second QObject base.)
class AvatarProvider : public QQuickAsyncImageProvider
{
    Q_OBJECT
public:
    AvatarProvider();
    ~AvatarProvider() override;

    QQuickImageResponse *requestImageResponse(const QString &id,
                                              const QSize &requestedSize) override;

Q_SIGNALS:
    /// Queued into the worker thread — never call AvatarFetcher directly.
    void request(const QString &hash, int size);

private:
    QThread m_thread;
    AvatarFetcher *m_fetcher = nullptr;
};
