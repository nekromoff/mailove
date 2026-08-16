// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "advancedconfig.h"

#include <QDir>
#include <QElapsedTimer>
#include <QLoggingCategory>
#include <QReadLocker>
#include <QFileInfo>
#include <QSaveFile>
#include <QSettings>
#include <QWriteLocker>
#include <QStringList>

namespace
{
/// Same category as the rest of the client's tracing, so
/// QT_LOGGING_RULES='mailove.trace.debug=true' (or the Settings toggle) turns
/// these on with everything else. Its own object because advancedconfig.cpp
/// links into the test binaries, which have no logTrace to extern.
Q_LOGGING_CATEGORY(logAdvanced, "mailove.trace")

using Type = AdvancedConfig::Type;
using Reload = AdvancedConfig::Reload;

/// The only value a Secret key may hold in the file. Everything else on such
/// a line is a secret in the clear, and is moved to the wallet rather than
/// written back.
constexpr auto kWalletPlaceholder = QLatin1String("@wallet");
/// Where scrubbed secrets go; installed by main(). Written once at startup
/// and read on the GUI thread only, which is where every save happens.
AdvancedConfig::SecretSink gSecretSink;

/// Bumped whenever a key is added, removed or its default changes, so a
/// template seeded by an older build can be spotted and offered a refresh.
constexpr int kSchemaVersion = 1;

/// The one place a default, a range and a description are written down.
///
/// Ranges are clamps, not validation: a value outside them is corrected and
/// reported, never refused, because the alternative is a config file that
/// stops the client from starting. Reload::Restart marks the keys read once
/// while something is being built — a timer's interval, a connection — where
/// saving cannot reach the object that already exists.
const AdvancedConfig::Knob kSchema[] = {
    // --- sync pacing ---------------------------------------------------
    {"sync/headerWindow", Type::Int, 200, 10, 1000, Reload::Live,
     "Headers fetched per request in the folder on screen."},
    {"sync/backfillFolderWindow", Type::Int, 250, 10, 1000, Reload::Live,
     "Headers per request for folders nobody is looking at."},
    {"sync/headerPauseMs", Type::Int, 400, 0, 60000, Reload::Live,
     "Pause between header windows. Raise it for a server that rate-limits."},
    {"sync/bodyPauseMs", Type::Int, 600, 0, 60000, Reload::Live,
     "Pause between body-fetch batches."},
    {"sync/backfillIdleMs", Type::Int, 4000, 100, 600000, Reload::Restart,
     "How long the backfill waits after going idle before resuming."},
    {"sync/backoffBaseMs", Type::Int, 1000, 100, 60000, Reload::Live,
     "First wait after the server throttles; doubles per attempt."},
    {"sync/backoffCapMs", Type::Int, 64000, 1000, 600000, Reload::Live,
     "Ceiling for one backoff wait."},
    {"sync/backoffJitterMs", Type::Int, 1000, 0, 60000, Reload::Live,
     "Random spread added to each backoff wait."},
    {"sync/backoffMaxAttempts", Type::Int, 8, 1, 100, Reload::Live,
     "Throttled attempts before the backfill pauses until the next connect."},

    // --- IMAP ------------------------------------------------------------
    {"imap/keepAliveSeconds", Type::Int, 180, 30, 3600, Reload::Restart,
     "How often an idle connection sends CAPABILITY so the server keeps it."},
    {"imap/bodyPoolSize", Type::Int, 2, 0, 8, Reload::Restart,
     "Extra connections for body fetches. Gmail caps ~15; some servers throttle at 3."},

    // --- JMAP ------------------------------------------------------------
    {"jmap/maxConcurrentBodies", Type::Int, 4, 1, 16, Reload::Live,
     "Blob downloads in flight. Capped by the server's maxConcurrentRequests."},
    {"jmap/maxBodyBytes", Type::Int, 134217728, 1048576, 2000000000, Reload::Live,
     "Largest single message body accepted from a blob download."},
    {"jmap/bodyTimeoutMs", Type::Int, 120000, 1000, 3600000, Reload::Live,
     "Timeout for one blob download."},
    {"jmap/requestTimeoutMs", Type::Int, 60000, 1000, 3600000, Reload::Live,
     "Timeout for one JMAP method call."},
    {"jmap/discoveryTimeoutMs", Type::Int, 30000, 1000, 600000, Reload::Live,
     "Timeout for session discovery, which blocks the account coming up."},
    {"jmap/maxSessionBytes", Type::Int, 1048576, 4096, 67108864, Reload::Live,
     "Largest session object accepted; a bigger reply is a login page, not JMAP."},
    {"jmap/maxUploadReplyBytes", Type::Int, 65536, 1024, 16777216, Reload::Live,
     "Largest reply accepted from a blob upload."},
    {"jmap/maxChangesPerCall", Type::Int, 500, 10, 4096, Reload::Live,
     "Changes asked for per Email/changes call."},
    {"jmap/pushPingSeconds", Type::Int, 300, 30, 3600, Reload::Restart,
     "Keepalive the server sends down the push stream, so proxies keep it open."},
    {"jmap/maxPushBufferBytes", Type::Int, 262144, 4096, 16777216, Reload::Restart,
     "Cap on the push stream's read buffer."},
    {"jmap/pushBaseRetryMs", Type::Int, 2000, 100, 600000, Reload::Live,
     "First wait before reconnecting a dropped push stream."},
    {"jmap/pushMaxBackoffShift", Type::Int, 7, 0, 16, Reload::Live,
     "Doublings of the push retry wait before the cap applies."},
    {"jmap/pushMaxRetryMs", Type::Int, 300000, 1000, 3600000, Reload::Live,
     "Ceiling for the push reconnect wait."},

    // --- OAuth 2 ---------------------------------------------------------
    {"oauth/googleClientId", Type::String, QString(), {}, {}, Reload::Live,
     "Your own Google client ID. Empty uses the one shipped with Mailove."},
    {"oauth/googleClientSecret", Type::Secret, QString(), {}, {}, Reload::Live,
     "Client secret for the ID above. Type it here once: on save it moves to "
     "the system wallet and this line keeps only @wallet."},
    {"oauth/googleAuthUrl", Type::String,
     QStringLiteral("https://accounts.google.com/o/oauth2/v2/auth"), {}, {}, Reload::Live,
     "Google authorization endpoint."},
    {"oauth/googleTokenUrl", Type::String,
     QStringLiteral("https://oauth2.googleapis.com/token"), {}, {}, Reload::Live,
     "Google token endpoint."},
    {"oauth/googleScope", Type::String, QStringLiteral("https://mail.google.com/"), {}, {},
     Reload::Live, "Scopes requested from Google, space separated."},
    {"oauth/microsoftClientId", Type::String, QString(), {}, {}, Reload::Live,
     "Your own Microsoft application (client) ID. Empty uses the shipped one."},
    {"oauth/microsoftClientSecret", Type::Secret, QString(), {}, {}, Reload::Live,
     "Client secret for the ID above. Type it here once: on save it moves to "
     "the system wallet and this line keeps only @wallet."},
    {"oauth/microsoftAuthUrl", Type::String,
     QStringLiteral("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"), {}, {},
     Reload::Live, "Microsoft authorization endpoint. Replace 'common' for a single tenant."},
    {"oauth/microsoftTokenUrl", Type::String,
     QStringLiteral("https://login.microsoftonline.com/common/oauth2/v2.0/token"), {}, {},
     Reload::Live, "Microsoft token endpoint. Replace 'common' for a single tenant."},
    {"oauth/microsoftScope", Type::String,
     QStringLiteral("https://outlook.office365.com/IMAP.AccessAsUser.All "
                    "https://outlook.office365.com/SMTP.Send offline_access"),
     {}, {}, Reload::Live, "Scopes requested from Microsoft, space separated."},
    {"oauth/authTimeoutMinutes", Type::Int, 5, 1, 60, Reload::Live,
     "How long the loopback listener waits for the browser before giving up."},
    {"oauth/tokenExpirySkewSeconds", Type::Int, 60, 0, 600, Reload::Live,
     "Refresh this long before the token actually expires."},
    {"oauth/defaultExpiresIn", Type::Int, 3600, 60, 86400, Reload::Live,
     "Assumed token lifetime when the server does not state one."},

    // --- spam --------------------------------------------------------------
    {"spam/threshold", Type::Int, 50, 0, 1000, Reload::Live,
     "Score at which a message is marked spam. Lower catches more and errs more."},
    {"spam/familiarCount", Type::Int, 20, 1, 10000, Reload::Live,
     "Messages from a domain before it counts as familiar and is trusted more."},
    {"spam/familiarDays", Type::Int, 60, 1, 3650, Reload::Live,
     "How far back the familiarity count looks."},
    {"spam/linkGroupCap", Type::Int, 40, 1, 10000, Reload::Live,
     "Links examined per message by the link rules."},

    // --- sender pictures ---------------------------------------------------
    // Off by default and deliberately so: asking gravatar.com for a picture
    // tells gravatar.com that this address was seen by this reader, which is
    // not a request anyone should make on the reader's behalf without being
    // asked. Nothing is fetched, cached or shown until this is turned on.
    {"avatars/enabled", Type::Bool, false, {}, {}, Reload::Restart,
     "Show sender pictures from gravatar.com. Off means no request is ever made."},
    {"avatars/cacheDays", Type::Int, 365, 1, 3650, Reload::Live,
     "How long a fetched picture is reused before it is asked for again."},
    {"avatars/missCacheDays", Type::Int, 30, 1, 3650, Reload::Live,
     "How long 'this address has no picture' is remembered."},
    {"avatars/sizePixels", Type::Int, 40, 8, 512, Reload::Live,
     "Pixel size a picture is fetched and shown at."},

    // --- reading -----------------------------------------------------------
    {"view/markReadSeconds", Type::Double, 0.1, 0.0, 86400.0, Reload::Live,
     "Seconds an open message stays unread before it is marked read; decimals "
     "fine. 0 leaves it unread until marked read by hand."},
    {"view/maxHtmlPreviewChars", Type::Int, 500000, 1000, 10000000, Reload::Live,
     "HTML taken for the text preview before it is truncated."},
    {"view/maxTextBodyBytes", Type::Int, 1048576, 4096, 67108864, Reload::Live,
     "Largest plain-text body rendered whole."},

    // --- composing ---------------------------------------------------------
    {"compose/maxPastedImageBytes", Type::Int, 20971520, 65536, 268435456, Reload::Live,
     "Largest image accepted from a paste or drop."},
    {"compose/pastedImageDisplayWidth", Type::Int, 640, 64, 4096, Reload::Live,
     "Width a pasted image is displayed at; the sent file keeps its own size."},
    {"compose/remoteImagePrefetch", Type::Int, 40, 0, 1000, Reload::Live,
     "Remote images fetched per message once remote content is allowed."},
    {"compose/maxRemoteImageBytes", Type::Int, 10485760, 65536, 268435456, Reload::Live,
     "Largest single remote image accepted."},

    // --- attachments -------------------------------------------------------
    {"attachments/externalizeThresholdBytes", Type::Int, 32768, 0, 1073741824, Reload::Live,
     "Attachments at least this big are stored outside the database."},
    {"attachments/zstdLevel", Type::Int, 3, 1, 19, Reload::Live,
     "zstd compression level for stored attachments."},
    {"attachments/compressionSampleBytes", Type::Int, 65536, 1024, 16777216, Reload::Live,
     "Sample compressed first to decide whether compressing the whole file pays."},
    {"attachments/worthwhileRatio", Type::Double, 0.90, 0.10, 1.0, Reload::Live,
     "Compress only when the sample shrinks below this fraction of its size."},
    {"attachments/maxPayloadBytes", Type::Int, 1073741824, 1048576, 2000000000, Reload::Live,
     "Largest attachment payload decompressed into memory."},

    // --- DKIM / DNS --------------------------------------------------------
    {"dkim/dnsCacheMinTtl", Type::Int, 1800, 0, 86400, Reload::Live,
     "Shortest time a DKIM key record is cached, whatever its TTL says."},
    {"dkim/dnsCacheMaxTtl", Type::Int, 86400, 60, 604800, Reload::Live,
     "Longest time a DKIM key record is cached."},
    {"dkim/dnsNegativeTtl", Type::Int, 600, 0, 86400, Reload::Live,
     "How long a failed DKIM key lookup is remembered."},

    // --- public suffix list ------------------------------------------------
    {"psl/enabled", Type::Bool, true, {}, {}, Reload::Restart,
     "Fetch the public suffix list. 0 keeps the built-in copy and makes no request."},
    {"psl/listUrl", Type::String,
     QStringLiteral("https://publicsuffix.org/list/public_suffix_list.dat"), {}, {},
     Reload::Restart, "Where the public suffix list is fetched from."},
    {"psl/refreshHours", Type::Int, 168, 1, 8760, Reload::Restart,
     "How old the list may get before it is refetched."},
    {"psl/checkHours", Type::Int, 6, 1, 720, Reload::Restart,
     "How often staleness is checked."},
    {"psl/startupDelaySeconds", Type::Int, 10, 0, 3600, Reload::Restart,
     "Delay before the first check, so it never competes with startup."},

    // --- database ----------------------------------------------------------
    {"db/busyTimeoutMs", Type::Int, 15000, 1000, 300000, Reload::Restart,
     "How long a query waits for another writer before failing."},
    {"db/rebuildBusyTimeoutMs", Type::Int, 30000, 1000, 600000, Reload::Restart,
     "The same, on the index-rebuild connection, which waits behind the GUI."},
};

constexpr int kSchemaCount = int(std::size(kSchema));

/// "sync/headerWindow" -> "sync". The INI section a key belongs to.
QString groupOf(const QString &key)
{
    const qsizetype slash = key.indexOf(u'/');
    return slash < 0 ? QString() : key.left(slash);
}

QString nameOf(const QString &key)
{
    const qsizetype slash = key.indexOf(u'/');
    return slash < 0 ? key : key.mid(slash + 1);
}

/// \a text with the blank lines at its top and bottom removed, ending in
/// exactly one newline. Only the ends: blank lines *between* sections are the
/// user's layout — they are what makes the file readable — and nothing here
/// reflows them.
QString trimBlankEnds(const QString &text)
{
    QStringList lines = text.split(u'\n');
    while (!lines.isEmpty() && lines.first().trimmed().isEmpty())
        lines.removeFirst();
    while (!lines.isEmpty() && lines.last().trimmed().isEmpty())
        lines.removeLast();
    return lines.isEmpty() ? QString() : lines.join(u'\n') + u'\n';
}

QString asText(const QVariant &v, Type type)
{
    if (type == Type::Bool)
        return v.toBool() ? QStringLiteral("1") : QStringLiteral("0");
    if (type == Type::Double)
        return QString::number(v.toDouble(), 'g', 6);
    // A secret has no text form here by construction: the template, the
    // reference and withKey() all show the placeholder, never a value.
    if (type == Type::Secret)
        return kWalletPlaceholder;
    return v.toString();
}
} // namespace

AdvancedConfig::AdvancedConfig(QObject *parent)
    : QObject(parent)
{
    load();
}

AdvancedConfig &AdvancedConfig::instance()
{
    static AdvancedConfig config;
    return config;
}

QString AdvancedConfig::filePath()
{
    // Derived from where QSettings actually put mailove.conf rather than
    // rebuilt from QStandardPaths, so the two files always sit together even
    // if Qt's idea of the config location changes under us.
    const QSettings probe(QStringLiteral("mailove"), QStringLiteral("mailove"));
    return QFileInfo(probe.fileName()).dir().filePath(QStringLiteral("advanced.conf"));
}

QString AdvancedConfig::walletPlaceholder()
{
    return kWalletPlaceholder;
}

QString AdvancedConfig::walletKeyFor(const QString &key)
{
    return QStringLiteral("advanced/") + key;
}

void AdvancedConfig::setSecretSink(SecretSink sink)
{
    gSecretSink = std::move(sink);
}

QString AdvancedConfig::scrubSecrets(const QString &text, QHash<QString, QString> *relayed)
{
    QStringList lines = text.split(u'\n');
    QString group;
    bool changed = false;
    for (QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith(u'#') || trimmed.startsWith(u';'))
            continue;
        if (trimmed.startsWith(u'[') && trimmed.endsWith(u']')) {
            group = trimmed.mid(1, trimmed.size() - 2).trimmed();
            continue;
        }
        const qsizetype eq = line.indexOf(u'=');
        if (eq < 0 || group.isEmpty())
            continue;
        const QString name = line.left(eq).trimmed();
        const Knob *k = knob(group + u'/' + name);
        if (!k || k->type != Type::Secret)
            continue;
        QString value = line.mid(eq + 1).trimmed();
        if (value.size() >= 2 && value.startsWith(u'"') && value.endsWith(u'"'))
            value = value.mid(1, value.size() - 2);
        if (value == kWalletPlaceholder)
            continue; // already a pointer at the wallet
        // An emptied line is a deletion, not a secret: it has to reach the
        // wallet too, or clearing it here would leave the value stored there.
        // The line itself stays empty — writing the placeholder over it would
        // claim a secret that is no longer anywhere.
        if (relayed)
            relayed->insert(walletKeyFor(group + u'/' + name), value);
        if (value.isEmpty())
            continue;
        // Only the value changes; the indentation and spacing the user typed
        // on the left of the '=' are theirs.
        line = line.left(eq + 1) + u' ' + kWalletPlaceholder;
        changed = true;
    }
    return changed ? lines.join(u'\n') : text;
}

void AdvancedConfig::sweepSecrets()
{
    // From the file, not from what was loaded earlier: the point of the sweep
    // is a file edited outside the client, so what is in memory may predate
    // the secret being typed into it.
    load();
    QHash<QString, QString> relayed;
    const QString scrubbed = scrubSecrets(m_text, &relayed);
    if (relayed.isEmpty())
        return;
    if (!gSecretSink) {
        qCWarning(logAdvanced, "advanced: %d secret(s) in the file and no wallet to move them to",
                  int(relayed.size()));
        return;
    }
    for (auto it = relayed.cbegin(); it != relayed.cend(); ++it)
        gSecretSink(it.key(), it.value());
    if (scrubbed == m_text)
        return;
    const QString path = filePath();
    QSaveFile file(path);
    bool written = file.open(QIODevice::WriteOnly | QIODevice::Text);
    if (written) {
        file.write(scrubbed.toUtf8());
        written = file.commit();
    }
    if (!written) {
        qCWarning(logAdvanced, "advanced: cannot rewrite %s without its secrets: %s",
                  qUtf8Printable(path), qUtf8Printable(file.errorString()));
        return;
    }
    qCDebug(logAdvanced, "advanced: moved %d secret(s) out of the file into the wallet",
            int(relayed.size()));
    m_text = scrubbed;
    Q_EMIT textChanged();
}

const AdvancedConfig::Knob *AdvancedConfig::knob(const QString &key)
{
    for (int i = 0; i < kSchemaCount; ++i) {
        if (QLatin1String(kSchema[i].key) == key)
            return &kSchema[i];
    }
    return nullptr;
}

void AdvancedConfig::load()
{
    QElapsedTimer elapsed;
    elapsed.start();
    m_text.clear();
    QFile file(filePath());
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        m_text = QString::fromUtf8(file.readAll());
    const Parsed parsed = parse(m_text);
    apply(resolve(parsed.raw, nullptr, nullptr));
    qCDebug(logAdvanced, "advanced: load %lld ms (%lld bytes, %d set)", elapsed.elapsed(),
            qint64(m_text.size()), int(m_values.size()));
}

void AdvancedConfig::apply(const QHash<QString, QVariant> &overrides)
{
    QList<QVariant> effective;
    effective.reserve(kSchemaCount);
    for (int n = 0; n < kSchemaCount; ++n) {
        effective.append(
            overrides.value(QString::fromLatin1(kSchema[n].key), kSchema[n].def));
    }
    const QWriteLocker locked(&m_lock);
    m_values = overrides;
    m_effective = std::move(effective);
}

int AdvancedConfig::indexOf(const char *key)
{
    // Keyed by the pointer, not the text: every call site is a string literal
    // with a stable address, so the schema is walked once per call site for
    // the life of the process. Per thread, because the map is written on
    // first use and reads come from several.
    static thread_local QHash<const char *, int> cache;
    const auto it = cache.constFind(key);
    if (it != cache.cend())
        return *it;
    int found = -1;
    for (int n = 0; n < kSchemaCount; ++n) {
        if (qstrcmp(kSchema[n].key, key) == 0) {
            found = n;
            break;
        }
    }
    cache.insert(key, found);
    return found;
}

AdvancedConfig::Parsed AdvancedConfig::parse(const QString &text)
{
    Parsed out;
    QString group;
    QHash<QString, int> seen; ///< key -> line, for the duplicate warning
    const QStringList lines = text.split(u'\n');
    for (int n = 0; n < lines.size(); ++n) {
        const QString line = lines.at(n).trimmed();
        const int lineNo = n + 1;
        // Whole-line comments only: a '#' inside a value is part of the value,
        // which is what keeps a URL fragment from being eaten.
        if (line.isEmpty() || line.startsWith(u'#') || line.startsWith(u';'))
            continue;
        if (line.startsWith(u'[')) {
            if (!line.endsWith(u']')) {
                out.errors.append({lineNo, QStringLiteral("unterminated [group] header")});
                continue;
            }
            group = line.mid(1, line.size() - 2).trimmed();
            if (group.isEmpty())
                out.errors.append({lineNo, QStringLiteral("empty [group] name")});
            continue;
        }
        const qsizetype eq = line.indexOf(u'=');
        if (eq < 0) {
            out.errors.append(
                {lineNo, QStringLiteral("not a 'key = value' line, a [group] or a # comment")});
            continue;
        }
        const QString name = line.left(eq).trimmed();
        if (name.isEmpty()) {
            out.errors.append({lineNo, QStringLiteral("no key before '='")});
            continue;
        }
        if (group.isEmpty()) {
            out.errors.append({lineNo, QStringLiteral("'%1' sits outside any [group]").arg(name)});
            continue;
        }
        QString value = line.mid(eq + 1).trimmed();
        // Quotes are optional and only ever a way to keep leading or trailing
        // spaces; strip one matching pair and nothing else.
        if (value.size() >= 2 && value.startsWith(u'"') && value.endsWith(u'"'))
            value = value.mid(1, value.size() - 2);
        const QString key = group + u'/' + name;
        if (!knob(key)) {
            out.warnings.append({lineNo,
                                 QStringLiteral("unknown key '%1' — ignored, the rest of the "
                                                "file still applies")
                                     .arg(key)});
            continue;
        }
        const auto dup = seen.constFind(key);
        if (dup != seen.cend()) {
            out.warnings.append({lineNo, QStringLiteral("'%1' was already set on line %2; this "
                                                        "one wins")
                                             .arg(key)
                                             .arg(*dup)});
        }
        seen.insert(key, lineNo);
        if (knob(key)->type == Type::Secret && !value.isEmpty()
            && value != kWalletPlaceholder) {
            out.warnings.append(
                {lineNo, QStringLiteral("'%1' is a secret: it is moved to the system wallet on "
                                        "save and this line keeps only %2")
                             .arg(key, kWalletPlaceholder)});
        }
        out.raw.insert(key, value);
    }
    return out;
}

QHash<QString, QVariant> AdvancedConfig::resolve(const QHash<QString, QString> &raw,
                                                 const QHash<QString, int> *lines,
                                                 QList<Issue> *warnings)
{
    QHash<QString, QVariant> out;
    const auto warn = [&](const QString &key, const QString &text) {
        if (!warnings)
            return;
        warnings->append({lines ? lines->value(key, 0) : 0, text});
    };
    for (auto it = raw.cbegin(); it != raw.cend(); ++it) {
        const Knob *k = knob(it.key());
        if (!k)
            continue; // parse() already warned
        const QString &text = it.value();
        QVariant value;
        switch (k->type) {
        case Type::Int: {
            bool ok = false;
            const qlonglong n = text.toLongLong(&ok);
            if (!ok) {
                warn(it.key(), QStringLiteral("'%1' is not a whole number; using the default %2")
                                   .arg(text, asText(k->def, k->type)));
                continue;
            }
            value = int(qBound(qlonglong(k->min.toInt()), n, qlonglong(k->max.toInt())));
            if (value.toInt() != n) {
                warn(it.key(), QStringLiteral("%1 is outside %2–%3; using %4")
                                   .arg(n)
                                   .arg(k->min.toInt())
                                   .arg(k->max.toInt())
                                   .arg(value.toInt()));
            }
            break;
        }
        case Type::Double: {
            bool ok = false;
            const double n = text.toDouble(&ok);
            if (!ok) {
                warn(it.key(), QStringLiteral("'%1' is not a number; using the default %2")
                                   .arg(text, asText(k->def, k->type)));
                continue;
            }
            value = qBound(k->min.toDouble(), n, k->max.toDouble());
            if (!qFuzzyCompare(value.toDouble(), n)) {
                warn(it.key(), QStringLiteral("%1 is outside %2–%3; using %4")
                                   .arg(n)
                                   .arg(k->min.toDouble())
                                   .arg(k->max.toDouble())
                                   .arg(value.toDouble()));
            }
            break;
        }
        case Type::Bool: {
            const QString v = text.toLower();
            if (v == QLatin1String("1") || v == QLatin1String("true")
                || v == QLatin1String("yes") || v == QLatin1String("on")) {
                value = true;
            } else if (v == QLatin1String("0") || v == QLatin1String("false")
                       || v == QLatin1String("no") || v == QLatin1String("off")) {
                value = false;
            } else {
                warn(it.key(), QStringLiteral("'%1' is not 1/0; using the default %2")
                                   .arg(text, asText(k->def, k->type)));
                continue;
            }
            break;
        }
        case Type::String:
            value = text;
            break;
        case Type::Secret:
            // A secret never becomes a value in memory either: whatever the
            // file says, what is in force is "look in the wallet". A file
            // hand-edited to hold one is scrubbed by sweepSecrets(), and until
            // it is, nothing here can hand the plaintext back out.
            value = text.isEmpty() ? QString() : QString(kWalletPlaceholder);
            break;
        }
        out.insert(it.key(), value);
    }
    return out;
}

QVariant AdvancedConfig::value(const char *key) const
{
    const int index = indexOf(key);
    Q_ASSERT_X(index >= 0, "AdvancedConfig", key); // not in kSchema: a typo in the caller
    if (index < 0)
        return {};
    const QReadLocker locked(&m_lock);
    return m_effective.at(index);
}

int AdvancedConfig::i(const char *key)
{
    return instance().value(key).toInt();
}

double AdvancedConfig::d(const char *key)
{
    return instance().value(key).toDouble();
}

bool AdvancedConfig::b(const char *key)
{
    return instance().value(key).toBool();
}

QString AdvancedConfig::s(const char *key)
{
    // A Secret is never readable from here — the value is in the wallet and
    // this would only ever hand back the placeholder. Reading one is a bug in
    // the caller, which wants walletKeyFor() and an async wallet lookup.
    const int index = indexOf(key);
    Q_ASSERT_X(index < 0 || kSchema[index].type != Type::Secret, "AdvancedConfig::s", key);
    return instance().value(key).toString();
}

QString AdvancedConfig::text() const
{
    return m_text;
}

QVariantList AdvancedConfig::problems(const QString &candidate) const
{
    QElapsedTimer elapsed;
    elapsed.start();
    Parsed parsed = parse(candidate);
    // Line numbers for the clamp warnings, which resolve() cannot know itself.
    QHash<QString, int> lines;
    {
        QString group;
        const QStringList raw = candidate.split(u'\n');
        for (int n = 0; n < raw.size(); ++n) {
            const QString line = raw.at(n).trimmed();
            if (line.isEmpty() || line.startsWith(u'#') || line.startsWith(u';'))
                continue;
            if (line.startsWith(u'[') && line.endsWith(u']')) {
                group = line.mid(1, line.size() - 2).trimmed();
                continue;
            }
            const qsizetype eq = line.indexOf(u'=');
            if (eq > 0 && !group.isEmpty())
                lines.insert(group + u'/' + line.left(eq).trimmed(), n + 1);
        }
    }
    QList<Issue> clamped;
    resolve(parsed.raw, &lines, &clamped);
    parsed.warnings += clamped;

    const auto sortByLine = [](const Issue &a, const Issue &b) { return a.line < b.line; };
    std::sort(parsed.errors.begin(), parsed.errors.end(), sortByLine);
    std::sort(parsed.warnings.begin(), parsed.warnings.end(), sortByLine);

    QVariantList out;
    for (const Issue &e : std::as_const(parsed.errors)) {
        out.append(QVariantMap{{QStringLiteral("line"), e.line},
                               {QStringLiteral("fatal"), true},
                               {QStringLiteral("text"), e.text}});
    }
    for (const Issue &w : std::as_const(parsed.warnings)) {
        out.append(QVariantMap{{QStringLiteral("line"), w.line},
                               {QStringLiteral("fatal"), false},
                               {QStringLiteral("text"), w.text}});
    }
    qCDebug(logAdvanced, "advanced: problems() %lld ms (%d issues)", elapsed.elapsed(),
            int(out.size()));
    return out;
}

QStringList AdvancedConfig::restartKeys(const QString &candidate) const
{
    QElapsedTimer elapsed;
    elapsed.start();
    const Parsed parsed = parse(candidate);
    const QHash<QString, QVariant> next = resolve(parsed.raw, nullptr, nullptr);
    const QReadLocker locked(&m_lock);
    QStringList out;
    for (int n = 0; n < kSchemaCount; ++n) {
        const Knob &k = kSchema[n];
        if (k.reload != Reload::Restart)
            continue;
        const QString key = QString::fromLatin1(k.key);
        const QVariant before = m_values.value(key, k.def);
        const QVariant after = next.value(key, k.def);
        if (before != after)
            out.append(key);
    }
    qCDebug(logAdvanced, "advanced: restartKeys() %lld ms", elapsed.elapsed());
    return out;
}

QString AdvancedConfig::save(const QString &candidate)
{
    const Parsed parsed = parse(candidate);
    if (!parsed.errors.isEmpty()) {
        const Issue &first = parsed.errors.first();
        return QStringLiteral("line %1: %2").arg(first.line).arg(first.text);
    }
    // Secrets are taken out before anything is written, so the plaintext the
    // user typed never reaches the disk at all — not even for the moment
    // between writing it and rewriting it.
    QHash<QString, QString> relayed;
    // Trimmed at the ends only — see trimBlankEnds(). A file that grew a
    // trailing blank line on every visit is the reason, and an empty one is
    // then simply the case where nothing is left.
    const QString text = trimBlankEnds(scrubSecrets(candidate, &relayed));
    if (!relayed.isEmpty() && !gSecretSink) {
        // Refused rather than silently dropped: saving the file with the
        // secret blanked would look like it had been stored somewhere.
        return QStringLiteral("no system wallet available to store the secret in; "
                              "nothing was saved");
    }
    const QString path = filePath();

    // Nothing left: the file goes rather than being left behind as a blank
    // one. A text cleared by selecting all and deleting often keeps a newline
    // or three, and a file kept for those would say "there are settings here"
    // to anyone who looks. No file is also exactly the state a fresh install
    // is in, so "cleared it" and "never touched it" end up the same.
    if (text.isEmpty()) {
        if (QFile::exists(path) && !QFile::remove(path))
            return QStringLiteral("cannot remove %1").arg(path);
        // The wallet entries go with it. Nothing can reach them once the keys
        // that named them are gone — the client id beside a secret went with
        // the same delete — so leaving them would only be a secret nobody can
        // use and nobody knows is there.
        if (gSecretSink) {
            for (int n = 0; n < kSchemaCount; ++n) {
                if (kSchema[n].type == Type::Secret)
                    gSecretSink(walletKeyFor(QString::fromLatin1(kSchema[n].key)), QString());
            }
        }
        m_text.clear();
        apply({});
        qCDebug(logAdvanced, "advanced: save() emptied — %s removed", qUtf8Printable(path));
        Q_EMIT textChanged();
        Q_EMIT reloaded();
        return {};
    }

    QDir().mkpath(QFileInfo(path).path());
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return QStringLiteral("cannot write %1: %2").arg(path, file.errorString());
    // Verbatim, comments and all: this file is the user's, and nothing here
    // ever regenerates it from the parsed values. The one edit is the secrets
    // above, which are replaced by their placeholder.
    file.write(text.toUtf8());
    if (!file.commit())
        return QStringLiteral("cannot write %1: %2").arg(path, file.errorString());

    for (auto it = relayed.cbegin(); it != relayed.cend(); ++it)
        gSecretSink(it.key(), it.value());

    m_text = text;
    apply(resolve(parse(text).raw, nullptr, nullptr));
    qCDebug(logAdvanced, "advanced: save() %lld bytes (%d secret(s) to the wallet)",
            qint64(text.size()), int(relayed.size()));
    Q_EMIT textChanged();
    Q_EMIT reloaded();
    return {};
}

QString AdvancedConfig::withKey(const QString &text, const QString &key) const
{
    const Knob *k = knob(key);
    if (!k)
        return text;
    const QString group = groupOf(key);
    const QString line = QStringLiteral("%1 = %2").arg(nameOf(key), asText(k->def, k->type));

    QStringList lines = text.split(u'\n');
    QString current;
    int lastOfGroup = -1; ///< last line that still belongs to [group]
    for (int n = 0; n < lines.size(); ++n) {
        const QString trimmed = lines.at(n).trimmed();
        if (trimmed.startsWith(u'[') && trimmed.endsWith(u']')) {
            current = trimmed.mid(1, trimmed.size() - 2).trimmed();
            if (current == group)
                lastOfGroup = n;
            continue;
        }
        if (current != group)
            continue;
        lastOfGroup = n;
        // Already there: leave the file alone rather than setting it twice.
        const qsizetype eq = trimmed.indexOf(u'=');
        if (eq > 0 && trimmed.left(eq).trimmed() == nameOf(key)
            && !trimmed.startsWith(u'#') && !trimmed.startsWith(u';')) {
            return text;
        }
    }

    if (lastOfGroup < 0) {
        // No such section yet: start one at the end, with a blank line before
        // it unless the file is empty or already ends in one.
        QString out = text;
        if (!out.isEmpty() && !out.endsWith(u'\n'))
            out += u'\n';
        if (!out.isEmpty() && !out.endsWith(QLatin1String("\n\n")))
            out += u'\n';
        return out + QStringLiteral("[%1]\n").arg(group) + line + u'\n';
    }

    // Into the existing section, after its last line — skipping back over the
    // blank lines that separate it from whatever follows.
    int at = lastOfGroup;
    while (at > 0 && lines.at(at).trimmed().isEmpty())
        --at;
    lines.insert(at + 1, line);
    return lines.join(u'\n');
}

QVariantList AdvancedConfig::reference() const
{
    QElapsedTimer elapsed;
    elapsed.start();
    const QReadLocker locked(&m_lock);
    QVariantList out;
    for (int n = 0; n < kSchemaCount; ++n) {
        const Knob &k = kSchema[n];
        const QString key = QString::fromLatin1(k.key);
        QString range;
        if (k.min.isValid() && k.max.isValid()) {
            range = k.type == Type::Double
                ? QStringLiteral("%1–%2").arg(k.min.toDouble()).arg(k.max.toDouble())
                : QStringLiteral("%1–%2").arg(k.min.toInt()).arg(k.max.toInt());
        } else if (k.type == Type::Bool) {
            range = QStringLiteral("1 or 0");
        } else if (k.type == Type::Secret) {
            range = QStringLiteral("kept in the system wallet");
        }
        out.append(QVariantMap{
            {QStringLiteral("key"), key},
            {QStringLiteral("group"), groupOf(key)},
            {QStringLiteral("name"), nameOf(key)},
            {QStringLiteral("def"), asText(k.def, k.type)},
            {QStringLiteral("range"), range},
            {QStringLiteral("doc"), QString::fromUtf8(k.doc)},
            {QStringLiteral("restart"), k.reload == Reload::Restart},
            {QStringLiteral("set"), m_values.contains(key)},
        });
    }
    qCDebug(logAdvanced, "advanced: reference() %lld ms (%d rows)", elapsed.elapsed(),
            int(out.size()));
    return out;
}

QString AdvancedConfig::defaultTemplate() const
{
    QElapsedTimer elapsed;
    elapsed.start();
    QString out;
    out += QStringLiteral("# Mailove advanced settings (schema %1)\n").arg(kSchemaVersion);
    out += QStringLiteral("#\n");
    out += QStringLiteral("# Every key below is commented out and shows its default. Uncomment\n"
                          "# a line to change it. Values outside the stated range are corrected\n"
                          "# on save, and an unknown key is ignored with a warning — neither\n"
                          "# stops the rest of the file from applying.\n");
    out += QStringLiteral("#\n");
    out += QStringLiteral("# Comments run to the end of a line only when the line starts with\n"
                          "# '#' or ';', so a '#' inside a URL stays part of the value.\n");
    out += QStringLiteral("#\n");
    out += QStringLiteral("# No secret is ever stored in this file. A key marked as kept in the\n"
                          "# system wallet takes its value once — type it, save, and the line is\n"
                          "# rewritten to '%1' with the value in the wallet. Clear the line to\n"
                          "# forget it.\n")
               .arg(kWalletPlaceholder);

    QString group;
    for (int n = 0; n < kSchemaCount; ++n) {
        const Knob &k = kSchema[n];
        const QString key = QString::fromLatin1(k.key);
        if (groupOf(key) != group) {
            group = groupOf(key);
            out += QStringLiteral("\n[%1]\n").arg(group);
        }
        out += QStringLiteral("# %1\n").arg(QString::fromUtf8(k.doc));
        QStringList notes;
        if (k.min.isValid() && k.max.isValid()) {
            notes << (k.type == Type::Double
                          ? QStringLiteral("range %1–%2").arg(k.min.toDouble()).arg(k.max.toDouble())
                          : QStringLiteral("range %1–%2").arg(k.min.toInt()).arg(k.max.toInt()));
        }
        if (k.type == Type::Secret)
            notes << QStringLiteral("moved to the system wallet on save");
        if (k.reload == Reload::Restart)
            notes << QStringLiteral("takes effect on restart");
        if (!notes.isEmpty())
            out += QStringLiteral("# (%1)\n").arg(notes.join(QStringLiteral(", ")));
        out += QStringLiteral("# %1 = %2\n").arg(nameOf(key), asText(k.def, k.type));
    }
    qCDebug(logAdvanced, "advanced: defaultTemplate() %lld ms", elapsed.elapsed());
    return out;
}
