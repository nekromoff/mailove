// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "updatecheck.h"

#include "advancedconfig.h"

#include <QDateTime>
#include <QLoggingCategory>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSettings>
#include <QTimer>
#include <QUrl>

#include <chrono>

namespace {
Q_LOGGING_CATEGORY(logUpdate, "mailove.update")

/// Opening Settings asks for a fresh answer, but opening it five times in a
/// minute does not ask for five requests.
constexpr qint64 kUserAskedFloorSeconds = 300;

QSettings appSettings()
{
    return QSettings(QStringLiteral("mailove"), QStringLiteral("mailove"));
}

} // namespace

namespace UpdateCheckLogic {

QString versionFromTag(const QString &tag)
{
    static const QRegularExpression re(
        QStringLiteral("^v?(\\d{1,4}(?:\\.\\d{1,4}){0,3})$"));
    const QRegularExpressionMatch m = re.match(tag.trimmed());
    return m.hasMatch() ? m.captured(1) : QString();
}

QString tagFromLocation(const QString &location, const QString &expectedHost)
{
    const QUrl target(location.trimmed());
    if (!target.isValid() || target.scheme() != QLatin1String("https"))
        return {};
    // Same host, or the redirect is answering a different question than the
    // one we asked. Without this the version could be read out of wherever a
    // hijacked Location happened to point.
    if (target.host().compare(expectedHost, Qt::CaseInsensitive) != 0)
        return {};
    return target.path().section(QLatin1Char('/'), -1);
}

bool isNewer(const QString &candidate, const QString &running)
{
    const QStringList a = candidate.split(QLatin1Char('.'));
    const QStringList b = running.split(QLatin1Char('.'));
    for (qsizetype i = 0; i < std::max(a.size(), b.size()); ++i) {
        const int lhs = i < a.size() ? a.at(i).toInt() : 0;
        const int rhs = i < b.size() ? b.at(i).toInt() : 0;
        if (lhs != rhs)
            return lhs > rhs;
    }
    return false;
}

} // namespace UpdateCheckLogic

namespace {
/// Empty until --force-version= sets it; see UpdateCheck::runningVersion().
QString g_forcedVersion;

/// Whether this run is a forced one. Such a run is a test of the marker, so it
/// always asks and never records: the rate limit would defeat the point, and
/// writing what a pretend version concluded would leave the real app reading
/// state no real check produced.
bool forced()
{
    return !g_forcedVersion.isEmpty();
}
} // namespace

QString UpdateCheck::runningVersion()
{
    return g_forcedVersion.isEmpty() ? QStringLiteral(MAILOVE_VERSION) : g_forcedVersion;
}

void UpdateCheck::setRunningVersion(const QString &version)
{
    // Through the same validator the network answer goes through: a typo on
    // the command line should not be able to do what a hostile header cannot.
    const QString clean = UpdateCheckLogic::versionFromTag(version);
    if (clean.isEmpty()) {
        qCWarning(logUpdate, "--force-version needs a version like 2.9; ignoring \"%s\"",
                  qUtf8Printable(version));
        return;
    }
    g_forcedVersion = clean;
    qCInfo(logUpdate, "comparing against forced version %s (really %s)",
           qUtf8Printable(clean), MAILOVE_VERSION);
}

UpdateCheck &UpdateCheck::instance()
{
    static UpdateCheck self;
    return self;
}

UpdateCheck::UpdateCheck(QObject *parent)
    : QObject(parent)
{
    // What the last completed check found, so the marker is on screen at once
    // instead of thirty seconds in — and so it survives the days the daily
    // interval means no request is made at all. Without this the answer would
    // only ever be visible during the run that happened to fetch it.
    //
    // Re-judged rather than trusted: measured against the version running now,
    // so upgrading to the release this once pointed at makes it disappear on
    // the next start, and re-validated because it has been sitting in a file
    // that anything could have edited meanwhile.
    const QString cached = UpdateCheckLogic::versionFromTag(
        appSettings().value(QStringLiteral("update/latestSeen")).toString());
    if (!cached.isEmpty() && UpdateCheckLogic::isNewer(cached, runningVersion()))
        m_latest = cached;
}

void UpdateCheck::start()
{
    // Thirty seconds, and a single shot. Launch is when the client is
    // connecting an account and pulling a folder list; this is the least
    // urgent thing in the process and waits its turn. Never on open, never
    // when a sheet is built — only here, and when asked.
    QTimer::singleShot(std::chrono::seconds(30), this, &UpdateCheck::maybeCheck);
}

void UpdateCheck::maybeCheck()
{
    check(false);
}

void UpdateCheck::checkNow()
{
    check(true);
}

QString UpdateCheck::releaseUrl() const
{
    if (m_latest.isEmpty())
        return {};
    return AdvancedConfig::s("update/releaseUrl").arg(m_latest);
}

void UpdateCheck::check(bool userAsked)
{
    if (!AdvancedConfig::b("update/checkEnabled"))
        return;
    if (m_inFlight)
        return;

    // --force-version is there to put the marker on screen on demand. A gate
    // that silently skips the request would make it do nothing in exactly the
    // situation it exists for — which is how it first failed.
    if (!forced()) {
        const QSettings settings = appSettings();
        // The gate is on (when, against what) — not on when alone. An answer
        // is only about the version that asked for it, so upgrading makes the
        // stored one stale no matter how recent it is: without this, installing
        // the release the marker pointed at leaves a day in which nothing
        // re-asks and the last answer is the wrong one.
        const QString askedAs =
            settings.value(QStringLiteral("update/checkedVersion")).toString();
        const bool sameVersion = askedAs == runningVersion();
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const qint64 last = settings.value(QStringLiteral("update/lastCheck")).toLongLong();
        const qint64 floor = userAsked
            ? kUserAskedFloorSeconds
            : qint64(AdvancedConfig::i("update/checkIntervalHours")) * 3600;
        if (sameVersion && last > 0 && now - last < floor) {
            qCDebug(logUpdate, "checked %lld s ago as %s, floor is %lld s: skipping",
                    now - last, qUtf8Printable(askedAs), floor);
            return;
        }
        if (!sameVersion && last > 0) {
            qCDebug(logUpdate, "last check was against %s, now running %s: asking again",
                    qUtf8Printable(askedAs), qUtf8Printable(runningVersion()));
        }
    }

    const QUrl url(AdvancedConfig::s("update/checkUrl"));
    // https only. Over plain http anyone on the path could invent a release,
    // and this ends in a label the user is invited to click.
    if (!url.isValid() || url.scheme() != QLatin1String("https")) {
        qCWarning(logUpdate, "refusing a non-https update URL: %s",
                  qUtf8Printable(url.toString()));
        return;
    }

    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QNetworkRequest req(url);
    // The version is in the redirect, so the redirect must not be followed:
    // chasing it would fetch an HTML release page we have no use for and throw
    // away the one header we came for.
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::ManualRedirectPolicy);
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QStringLiteral("mailove/" MAILOVE_VERSION));
    req.setTransferTimeout(std::chrono::seconds(5));

    m_inFlight = true;
    QNetworkReply *reply = m_net->head(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply] { finished(reply); });
}

void UpdateCheck::finished(QNetworkReply *reply)
{
    reply->deleteLater();
    m_inFlight = false;

    // Only a completed answer counts as "checked". A timeout or a dead network
    // must not start the clock, or one bad moment costs a whole day.
    if (reply->error() != QNetworkReply::NoError) {
        qCDebug(logUpdate, "update check did not complete: %s",
                qUtf8Printable(reply->errorString()));
        return;
    }
    if (!forced()) {
        QSettings settings = appSettings();
        settings.setValue(QStringLiteral("update/lastCheck"),
                          QDateTime::currentSecsSinceEpoch());
        // Which version this answer is about. Read back by the gate above.
        settings.setValue(QStringLiteral("update/checkedVersion"), runningVersion());
    }

    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    // 404 is the ordinary answer for a project with no release yet.
    if (status < 300 || status > 399) {
        qCDebug(logUpdate, "no release information (HTTP %d)", status);
        return;
    }

    // The version is the tag the redirect points at, and it has to still be on
    // the host we asked.
    const QString tag = UpdateCheckLogic::tagFromLocation(
        QString::fromLatin1(reply->rawHeader("Location")),
        reply->request().url().host());
    const QString version = UpdateCheckLogic::versionFromTag(tag);
    if (version.isEmpty()) {
        qCWarning(logUpdate, "ignoring a redirect that does not name a version");
        return;
    }

    const QString running = runningVersion();
    if (!UpdateCheckLogic::isNewer(version, running)) {
        qCDebug(logUpdate, "running %s, latest %s: up to date", qUtf8Printable(running),
                qUtf8Printable(version));
        // Forget an older answer: whoever was behind has caught up, and a
        // marker left in the file would come back on the next start.
        if (!forced())
            appSettings().remove(QStringLiteral("update/latestSeen"));
        if (!m_latest.isEmpty()) {
            m_latest.clear();
            Q_EMIT changed();
        }
        return;
    }

    qCInfo(logUpdate, "update available: %s (running %s)", qUtf8Printable(version),
           qUtf8Printable(running));
    // Remembered so the next start can show it without waiting for a request,
    // and so the days no request is made still show what the last one found.
    if (!forced())
        appSettings().setValue(QStringLiteral("update/latestSeen"), version);
    if (m_latest == version)
        return;
    m_latest = version;
    // The GUI has been doing whatever it liked this whole time; this is the
    // moment it finds out.
    Q_EMIT changed();
}

