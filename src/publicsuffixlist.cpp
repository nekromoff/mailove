// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "publicsuffixlist.h"

#include "advancedconfig.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLoggingCategory>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>
#include <QUrl>

#include <chrono>

namespace
{
Q_LOGGING_CATEGORY(logPsl, "mailove.psl")

auto kRefreshInterval() { return std::chrono::hours(AdvancedConfig::i("psl/refreshHours")); }
/// How often we wake up to notice the list has gone stale. The list changes a
/// few times a week and nothing breaks if we are a day late, so this is a cheap
/// tick rather than a precise schedule.
auto kCheckInterval() { return std::chrono::hours(AdvancedConfig::i("psl/checkHours")); }
/// Deferred so it never competes with startup, like the message-id backfill and
/// the attachment migration next to it in MailClient's constructor.
auto kStartupDelay() { return std::chrono::seconds(AdvancedConfig::i("psl/startupDelaySeconds")); }
/// Full jitter on top of a scheduled fetch, so clients launched together do not
/// arrive at the server in lockstep. Breaking the tie is all it has to do —
/// same 1 s spread the connection backoff in mailclient.cpp uses.
constexpr int kJitterMs = 1000;

std::chrono::milliseconds withJitter(std::chrono::milliseconds base)
{
    return base + std::chrono::milliseconds(QRandomGenerator::global()->bounded(kJitterMs + 1));
}

QString listUrl() { return AdvancedConfig::s("psl/listUrl"); }

/// A download that lost its way — a captive portal's login page, an error page,
/// a truncated transfer — must never replace a good list. The real file is
/// ~250 kB and always carries the ICANN section marker.
bool looksLikeTheList(const QByteArray &data)
{
    return data.size() > 50000 && data.contains("===BEGIN ICANN DOMAINS===");
}

/// Rules may be written in Unicode; the domains we compare them against arrive
/// as punycode, so normalize at parse time rather than on every lookup.
QString normalizedRule(const QString &rule)
{
    for (const QChar c : rule) {
        if (c.unicode() > 127)
            return QString::fromLatin1(QUrl::toAce(rule)).toLower();
    }
    return rule.toLower();
}
} // namespace

PublicSuffixList &PublicSuffixList::instance()
{
    static PublicSuffixList list;
    return list;
}

QString PublicSuffixList::cachePath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/public_suffix_list.dat");
}

void PublicSuffixList::start()
{
    if (m_nam)
        return; // already started
    // Not parented to this object: the instance may have been created from
    // whichever thread first asked for a lookup, while everything here runs on
    // the thread that calls start(). Ownership is the process lifetime.
    m_nam = new QNetworkAccessManager;

    loadFromDisk();

    // psl/enabled off means the cached (or built-in) list is all there is:
    // no timer, no request. This is one of the few outbound requests that does
    // not go to the user's own mail server, so it has an off switch.
    if (!AdvancedConfig::b("psl/enabled"))
        return;

    // Re-jittered on every tick rather than left on a fixed period, so a
    // long-running client does not settle into hitting the server at the same
    // minute each time.
    auto *timer = new QTimer(m_nam);
    timer->setSingleShot(true);
    QObject::connect(timer, &QTimer::timeout, m_nam, [this, timer] {
        download();
        timer->start(withJitter(kCheckInterval()));
    });

    // Not at launch: the first seconds belong to opening the window and getting
    // the mailbox on screen, and nothing here is needed until a message is
    // opened. The cached copy is already in memory by now; this only refreshes
    // it, and a week-old list is fine for another few seconds.
    timer->start(withJitter(kStartupDelay()));
}

void PublicSuffixList::loadFromDisk()
{
    QFile f(cachePath());
    if (!f.open(QIODevice::ReadOnly))
        return;
    const QByteArray data = f.readAll();
    if (!looksLikeTheList(data)) {
        qCWarning(logPsl) << "cached public suffix list is not usable; ignoring it";
        return;
    }
    setRulesFromData(data);
    qCDebug(logPsl) << "loaded public suffix list from" << cachePath();
}

void PublicSuffixList::download()
{
    if (m_downloading)
        return;
    const QFileInfo cached(cachePath());
    if (cached.exists()
        && cached.lastModified().secsTo(QDateTime::currentDateTime())
            < std::chrono::duration_cast<std::chrono::seconds>(kRefreshInterval()).count()) {
        return; // still fresh
    }

    m_downloading = true;
    QNetworkRequest request{QUrl(listUrl())};
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    QNetworkReply *reply = m_nam->get(request);
    QObject::connect(reply, &QNetworkReply::finished, m_nam, [this, reply] {
        reply->deleteLater();
        m_downloading = false;
        if (reply->error() != QNetworkReply::NoError) {
            // Never fatal: an old list is still a good list, and no list at all
            // only costs us the stricter fallback in domainsAligned().
            qCWarning(logPsl) << "public suffix list download failed:" << reply->errorString();
            return;
        }
        const QByteArray data = reply->readAll();
        if (!looksLikeTheList(data)) {
            qCWarning(logPsl) << "public suffix list download did not look like the list;"
                              << "keeping the previous one";
            return;
        }
        setRulesFromData(data);

        QDir().mkpath(QFileInfo(cachePath()).absolutePath());
        // QSaveFile so an interrupted write cannot leave a half a list behind:
        // its mtime is also what "is it stale" is measured from.
        QSaveFile out(cachePath());
        if (out.open(QIODevice::WriteOnly)) {
            out.write(data);
            out.commit();
        }
        qCDebug(logPsl) << "public suffix list updated";
    });
}

void PublicSuffixList::setRulesFromData(const QByteArray &data)
{
    QSet<QString> rules;
    QSet<QString> wildcards;
    QSet<QString> exceptions;

    const QList<QByteArray> lines = data.split('\n');
    for (const QByteArray &rawLine : lines) {
        const QByteArray line = rawLine.trimmed();
        if (line.isEmpty() || line.startsWith("//"))
            continue;
        // Only the first token is the rule; anything after it is commentary.
        const QByteArray token = line.split(' ').first().trimmed();
        if (token.isEmpty())
            continue;
        QString rule = normalizedRule(QString::fromUtf8(token));

        if (rule.startsWith(QLatin1Char('!'))) {
            exceptions.insert(rule.mid(1));
        } else if (rule.startsWith(QLatin1String("*."))) {
            // Stored by parent: "*.ck" matches any single label under "ck".
            wildcards.insert(rule.mid(2));
        } else {
            rules.insert(rule);
        }
    }

    QWriteLocker locker(&m_lock);
    m_rules = std::move(rules);
    m_wildcards = std::move(wildcards);
    m_exceptions = std::move(exceptions);
}

bool PublicSuffixList::isLoaded() const
{
    QReadLocker locker(&m_lock);
    return !m_rules.isEmpty();
}

QString PublicSuffixList::organizationalDomain(const QString &domain) const
{
    QString name = domain.toLower();
    while (name.endsWith(QLatin1Char('.')))
        name.chop(1);
    if (name.isEmpty())
        return {};

    const QStringList labels = name.split(QLatin1Char('.'));
    if (labels.size() < 2)
        return {}; // a bare TLD has no organization behind it

    QReadLocker locker(&m_lock);
    if (m_rules.isEmpty())
        return {};

    // Walk the candidate suffixes longest first, so the first hit is the
    // longest match — which is the rule the algorithm calls for. Exceptions
    // are checked before ordinary rules at each length: "!city.kobe.jp" exists
    // precisely to overrule the "*.kobe.jp" that would otherwise apply.
    QString suffix;
    for (int i = 0; i < labels.size(); ++i) {
        const QString candidate = QStringList(labels.mid(i)).join(QLatin1Char('.'));
        if (m_exceptions.contains(candidate)) {
            // The exception's own leftmost label is registrable, so the public
            // suffix is what remains after removing it.
            suffix = QStringList(labels.mid(i + 1)).join(QLatin1Char('.'));
            break;
        }
        if (m_rules.contains(candidate)) {
            suffix = candidate;
            break;
        }
        if (i + 1 < labels.size()) {
            const QString parent = QStringList(labels.mid(i + 1)).join(QLatin1Char('.'));
            if (m_wildcards.contains(parent)) {
                suffix = candidate;
                break;
            }
        }
    }
    // "If no rules match, the prevailing rule is '*'": the last label.
    if (suffix.isEmpty())
        suffix = labels.last();

    const int suffixLabels = suffix.split(QLatin1Char('.')).size();
    if (labels.size() <= suffixLabels)
        return {}; // the name *is* a public suffix — nobody owns it
    return QStringList(labels.mid(labels.size() - suffixLabels - 1)).join(QLatin1Char('.'));
}
