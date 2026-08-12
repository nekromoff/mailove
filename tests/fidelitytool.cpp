// Diagnostic, not a pass/fail test: measures where the octets of a stored
// message diverge from the octets that arrived.
//
// For each sampled UID it obtains four byte strings and compares them:
//
//   WIRE     the literal returned by `UID FETCH <uid> BODY.PEEK[]`, read
//            straight off the socket by this tool — no KIMAP, no KMime. This
//            is the ground truth the sender signed.
//   CACHED   bodies.raw for that UID, exactly as mailove stored it, lifted to
//            CRLF the way MailClient::rawMessageForDkim() does before
//            verification.
//   KMIME    setContent(CRLFtoLF(WIRE)) -> parse() -> encodedContent() ->
//            LFtoCRLF. What a *pristine* KMime round-trip costs, with no IMAP
//            stack involved. (setContent takes LF; handing it CRLF is itself
//            lossy, so the conversion is not optional.)
//   KIMAP    encodedContent() of the message KIMAP::FetchJob hands back for
//            the same UID — exactly what storeFetchedBody() writes. This is
//            the column that separates "KMime re-encodes" from "KIMAP never
//            gave us the original in the first place".
//
// and runs the real DkimVerifier over WIRE, KMIME and CACHED, so a divergence
// can be read directly against the verdict it produces.
//
//   ./fidelitytool --account 0 --folder INBOX --count 30 --out testdata/fidelity
//
// Needs the account password in the wallet and working DNS. Read-only against
// the cache and against the server (BODY.PEEK never sets \Seen).

#include "../src/dkimverifier.h"

#include <qt6keychain/keychain.h>

#include <KIMAP/FetchJob>
#include <KIMAP/LoginJob>
#include <KIMAP/SelectJob>
#include <KIMAP/Session>

#include <KMime/Message>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSslSocket>
#include <QStandardPaths>
#include <QTextStream>

#include <cstdio>

namespace
{

constexpr int kSocketTimeoutMs = 30000;

struct Account {
    QString host, user, email;
    int port = 993;
    int security = 0; ///< 0 = SSL/TLS, 1 = STARTTLS, 2 = none
    int authType = 0; ///< non-zero = OAuth, unsupported here
    QString cacheKey;

    QString key() const
    {
        return cacheKey.isEmpty() ? user + QLatin1Char('@') + host : cacheKey;
    }
};

const char *statusName(DkimResult::Status s)
{
    switch (s) {
    case DkimResult::None: return "NONE";
    case DkimResult::Pass: return "PASS";
    case DkimResult::Fail: return "FAIL";
    case DkimResult::TempError: return "TEMPERROR";
    case DkimResult::PermError: return "PERMERROR";
    case DkimResult::BodyMismatch: return "UNVERIFIED";
    case DkimResult::Unsupported: return "UNSUPPORTED";
    }
    return "?";
}

Account readAccount(int index)
{
    Account a;
    QSettings s(QStringLiteral("mailove"), QStringLiteral("mailove"));
    const int count = s.beginReadArray(QStringLiteral("accounts"));
    if (index < 0 || index >= count) {
        s.endArray();
        return a;
    }
    s.setArrayIndex(index);
    a.host = s.value(QStringLiteral("host")).toString();
    a.user = s.value(QStringLiteral("user")).toString();
    a.email = s.value(QStringLiteral("email")).toString();
    a.port = s.value(QStringLiteral("port"), 993).toInt();
    a.security = s.value(QStringLiteral("security"), 0).toInt();
    a.authType = s.value(QStringLiteral("authType"), 0).toInt();
    a.cacheKey = s.value(QStringLiteral("cacheKey")).toString();
    s.endArray();
    return a;
}

/// Same wallet service and key layout MailClient uses.
QString walletPassword(const Account &a)
{
    QKeychain::ReadPasswordJob job(QStringLiteral("mailove"));
    job.setAutoDelete(false);
    job.setKey(QStringLiteral("imap-password:") + a.user + QLatin1Char('@') + a.host);
    QEventLoop loop;
    QObject::connect(&job, &QKeychain::Job::finished, &loop, &QEventLoop::quit);
    job.start();
    loop.exec();
    if (job.error()) {
        fprintf(stderr, "wallet: %s\n", qPrintable(job.errorString()));
        return {};
    }
    return job.textData();
}

QString cacheDbPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/mailove.db");
}

/// Scoped folder key, matching MailStore::scoped().
QString scopedFolder(const Account &a, const QString &mailBox)
{
    return a.key() + QChar(0x1f) + mailBox;
}

/// Picks \a want UIDs that actually have a cached body, without scanning the
/// table: each pick is one indexed seek from a random point in the UID range.
QList<qint64> sampleUids(QSqlDatabase &db, const QString &folder, int want)
{
    qint64 maxUid = 0;
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("SELECT max(uid) FROM bodies WHERE folder = ?"));
        q.addBindValue(folder);
        if (q.exec() && q.next())
            maxUid = q.value(0).toLongLong();
    }
    if (maxUid <= 0)
        return {};

    QSet<qint64> picked;
    QSqlQuery seek(db);
    // length(raw) rather than raw: we only want to know it is there, and the
    // blobs run to megabytes.
    seek.prepare(QStringLiteral(
        "SELECT uid FROM bodies WHERE folder = ? AND uid >= ? AND length(raw) > 0 "
        "ORDER BY uid LIMIT 1"));
    for (int attempt = 0; attempt < want * 20 && picked.size() < want; ++attempt) {
        const qint64 from = QRandomGenerator::global()->bounded(qint64(1), maxUid + 1);
        seek.addBindValue(folder);
        seek.addBindValue(from);
        if (seek.exec() && seek.next())
            picked.insert(seek.value(0).toLongLong());
    }
    QList<qint64> out(picked.cbegin(), picked.cend());
    std::sort(out.begin(), out.end());
    return out;
}

QByteArray cachedBody(QSqlDatabase &db, const QString &folder, qint64 uid)
{
    QSqlQuery q(db);
    q.prepare(QStringLiteral("SELECT raw FROM bodies WHERE folder = ? AND uid = ?"));
    q.addBindValue(folder);
    q.addBindValue(uid);
    if (q.exec() && q.next())
        return q.value(0).toByteArray();
    return {};
}

/// A deliberately small IMAP client: enough to LOGIN, SELECT and read the
/// literal of a BODY.PEEK[] fetch verbatim. Using KIMAP here would beg the
/// question — KIMAP hands back a parsed message, and whether that parse is
/// lossless is precisely what we are measuring.
class RawImap
{
public:
    bool connectTo(const Account &a)
    {
        if (a.security == 1) {
            m_sock.connectToHost(a.host, quint16(a.port));
            if (!m_sock.waitForConnected(kSocketTimeoutMs))
                return fail(QStringLiteral("connect: ") + m_sock.errorString());
            if (!readGreeting())
                return false;
            if (!command(QStringLiteral("STARTTLS")))
                return false;
            m_sock.startClientEncryption();
            if (!m_sock.waitForEncrypted(kSocketTimeoutMs))
                return fail(QStringLiteral("starttls: ") + m_sock.errorString());
            return true;
        }
        m_sock.connectToHostEncrypted(a.host, quint16(a.port));
        if (!m_sock.waitForEncrypted(kSocketTimeoutMs))
            return fail(QStringLiteral("tls: ") + m_sock.errorString());
        return readGreeting();
    }

    bool login(const QString &user, const QString &password)
    {
        return command(QStringLiteral("LOGIN %1 %2").arg(quoted(user), quoted(password)));
    }

    bool select(const QString &mailBox)
    {
        return command(QStringLiteral("SELECT %1").arg(quoted(mailBox)));
    }

    /// The message octets exactly as the server sent them. Empty on any miss.
    QByteArray fetchRaw(qint64 uid)
    {
        const QByteArray tag = nextTag();
        write(tag + " UID FETCH " + QByteArray::number(uid) + " BODY.PEEK[]\r\n");

        // Untagged response first: "* n FETCH (UID u BODY[] {size}\r\n<size bytes>"
        QByteArray payload;
        forever {
            const QByteArray line = readLine();
            if (line.isEmpty())
                return {};
            if (line.startsWith(tag + ' ')) // tagged: fetch produced nothing
                return payload;
            const int brace = line.lastIndexOf('{');
            if (brace < 0 || !line.endsWith("}\r\n"))
                continue; // some other untagged line
            const int size = line.mid(brace + 1, line.size() - brace - 4).toInt();
            if (size <= 0)
                continue;
            payload = readExactly(size);
            // Drain the rest of the response, up to and including the tag.
            forever {
                const QByteArray tail = readLine();
                if (tail.isEmpty() || tail.startsWith(tag + ' '))
                    return payload;
            }
        }
    }

    void logout()
    {
        command(QStringLiteral("LOGOUT"));
        m_sock.disconnectFromHost();
    }

    QString error() const { return m_error; }

private:
    static QString quoted(const QString &s)
    {
        QString e = s;
        e.replace(QLatin1Char('\\'), QLatin1String("\\\\"));
        e.replace(QLatin1Char('"'), QLatin1String("\\\""));
        return QLatin1Char('"') + e + QLatin1Char('"');
    }

    bool fail(const QString &why)
    {
        m_error = why;
        return false;
    }

    QByteArray nextTag() { return "a" + QByteArray::number(++m_tag).rightJustified(4, '0'); }

    void write(const QByteArray &data)
    {
        m_sock.write(data);
        m_sock.waitForBytesWritten(kSocketTimeoutMs);
    }

    QByteArray readLine()
    {
        while (!m_buf.contains("\r\n")) {
            if (!m_sock.waitForReadyRead(kSocketTimeoutMs))
                return {};
            m_buf += m_sock.readAll();
        }
        const int end = m_buf.indexOf("\r\n") + 2;
        const QByteArray line = m_buf.left(end);
        m_buf.remove(0, end);
        return line;
    }

    QByteArray readExactly(int size)
    {
        while (m_buf.size() < size) {
            if (!m_sock.waitForReadyRead(kSocketTimeoutMs))
                return {};
            m_buf += m_sock.readAll();
        }
        const QByteArray out = m_buf.left(size);
        m_buf.remove(0, size);
        return out;
    }

    bool readGreeting()
    {
        const QByteArray line = readLine();
        return line.startsWith("* OK") || line.startsWith("* PREAUTH");
    }

    bool command(const QString &cmd)
    {
        const QByteArray tag = nextTag();
        write(tag + ' ' + cmd.toUtf8() + "\r\n");
        forever {
            const QByteArray line = readLine();
            if (line.isEmpty())
                return fail(QStringLiteral("timeout on: ") + cmd.section(QLatin1Char(' '), 0, 0));
            if (!line.startsWith(tag + ' '))
                continue;
            if (line.mid(tag.size() + 1).startsWith("OK"))
                return true;
            return fail(QString::fromUtf8(line).trimmed());
        }
    }

    QSslSocket m_sock;
    QByteArray m_buf;
    int m_tag = 0;
    QString m_error;
};

/// Fetches the same UIDs the way MailClient does — KIMAP, FetchScope::Full —
/// and returns encodedContent() per UID, i.e. the exact bytes
/// storeFetchedBody() would hand to the body writer.
QHash<qint64, QByteArray> fetchViaKimap(const Account &a, const QString &password,
                                        const QString &mailBox, const QList<qint64> &uids,
                                        QString *error)
{
    QHash<qint64, QByteArray> out;
    KIMAP::Session session(a.host, quint16(a.port));
    QEventLoop loop;

    auto run = [&loop, error](KJob *job) {
        bool ok = true;
        QObject::connect(job, &KJob::result, &loop, [&loop, &ok, error](KJob *j) {
            if (j->error()) {
                ok = false;
                *error = j->errorString();
            }
            loop.quit();
        });
        job->start();
        loop.exec();
        return ok;
    };

    auto *login = new KIMAP::LoginJob(&session);
    login->setUserName(a.user);
    login->setPassword(password);
    login->setEncryptionMode(a.security == 1 ? KIMAP::LoginJob::STARTTLS
                                             : KIMAP::LoginJob::SSLorTLS);
    if (!run(login))
        return out;

    auto *select = new KIMAP::SelectJob(&session);
    select->setMailBox(mailBox);
    if (!run(select))
        return out;

    KIMAP::ImapSet set;
    for (const qint64 uid : uids)
        set.add(KIMAP::ImapInterval(uid, uid));

    KIMAP::FetchJob::FetchScope scope;
    scope.mode = KIMAP::FetchJob::FetchScope::Full;

    auto *fetch = new KIMAP::FetchJob(&session);
    fetch->setSequenceSet(set);
    fetch->setUidBased(true);
    fetch->setScope(scope);
    QObject::connect(fetch, &KIMAP::FetchJob::messagesAvailable, &loop,
                     [&out](const QMap<qint64, KIMAP::Message> &messages) {
                         for (const KIMAP::Message &m : messages) {
                             if (!m.message)
                                 continue;
                             // Exactly what storeFetchedBody() does.
                             if (m.message->contents().isEmpty())
                                 m.message->parse();
                             out.insert(m.uid, m.message->encodedContent());
                         }
                     });
    run(fetch);
    return out;
}

QString fromDomainOf(const QByteArray &wire)
{
    static const QRegularExpression fromRe(
        QStringLiteral("^From:.*?([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+)"),
        QRegularExpression::MultilineOption);
    const auto m = fromRe.match(QString::fromLatin1(wire.left(20000)));
    return m.hasMatch() ? m.captured(2).toLower() : QString();
}

DkimResult verifyOnce(DkimVerifier &v, const QByteArray &crlf, const QString &fromDomain)
{
    DkimResult result;
    auto conn = QObject::connect(&v, &DkimVerifier::finished,
                                 [&result](quint64, const DkimResult &r) { result = r; });
    v.verify(1, crlf, fromDomain);
    QObject::disconnect(conn);
    return result;
}

/// Where two byte strings first differ, with a little context — the actual
/// point of the exercise once the counts say something diverged.
QString firstDifference(const QByteArray &a, const QByteArray &b)
{
    const int n = qMin(a.size(), b.size());
    int i = 0;
    while (i < n && a.at(i) == b.at(i))
        ++i;
    if (i == n && a.size() == b.size())
        return QStringLiteral("identical");
    const int from = qMax(0, i - 40);
    auto show = [from, i](const QByteArray &s) {
        return QString::fromLatin1(s.mid(from, (i - from) + 40).toPercentEncoding(" "));
    };
    return QStringLiteral("offset %1 (a=%2 b=%3)\n      a: %4\n      b: %5")
        .arg(i)
        .arg(a.size())
        .arg(b.size())
        .arg(show(a), show(b));
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("mailove"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove"));

    int accountIndex = 0;
    QString mailBox = QStringLiteral("INBOX");
    int count = 30;
    QString outDir = QStringLiteral("testdata/fidelity");
    /// Named UIDs instead of a random sample — for re-measuring the same
    /// messages after the cache has been made to refetch them.
    QString explicitUids;
    for (int i = 1; i + 1 < argc; i += 2) {
        const QString flag = QString::fromLocal8Bit(argv[i]);
        const QString value = QString::fromLocal8Bit(argv[i + 1]);
        if (flag == QLatin1String("--account"))
            accountIndex = value.toInt();
        else if (flag == QLatin1String("--folder"))
            mailBox = value;
        else if (flag == QLatin1String("--count"))
            count = value.toInt();
        else if (flag == QLatin1String("--out"))
            outDir = value;
        else if (flag == QLatin1String("--uids"))
            explicitUids = value;
    }

    const Account account = readAccount(accountIndex);
    if (account.host.isEmpty()) {
        fprintf(stderr, "no account at index %d\n", accountIndex);
        return 2;
    }
    if (account.authType != 0) {
        fprintf(stderr, "account %d uses OAuth; this tool only does password login\n",
                accountIndex);
        return 2;
    }
    const QString password = walletPassword(account);
    if (password.isEmpty()) {
        fprintf(stderr, "no password in the wallet for %s\n", qPrintable(account.user));
        return 2;
    }

    QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"));
    db.setDatabaseName(cacheDbPath());
    db.setConnectOptions(QStringLiteral("QSQLITE_OPEN_READONLY"));
    if (!db.open()) {
        fprintf(stderr, "cache: %s\n", qPrintable(db.lastError().text()));
        return 2;
    }

    const QString folder = scopedFolder(account, mailBox);
    QList<qint64> uids;
    if (!explicitUids.isEmpty()) {
        const auto fields = explicitUids.split(QLatin1Char(','), Qt::SkipEmptyParts);
        for (const QString &f : fields)
            uids.append(f.trimmed().toLongLong());
        std::sort(uids.begin(), uids.end());
    } else {
        uids = sampleUids(db, folder, count);
    }
    if (uids.isEmpty()) {
        fprintf(stderr, "no cached bodies in %s\n", qPrintable(mailBox));
        return 2;
    }
    printf("sampled %lld UIDs from %s (%s)\n\n", qint64(uids.size()),
           qPrintable(mailBox), qPrintable(account.key()));

    QDir().mkpath(outDir);

    RawImap imap;
    if (!imap.connectTo(account) || !imap.login(account.user, password)
        || !imap.select(mailBox)) {
        fprintf(stderr, "imap: %s\n", qPrintable(imap.error()));
        return 2;
    }

    // Collect the wire octets first, then close the raw connection: the KIMAP
    // pass logs in again as a normal client would.
    QHash<qint64, QByteArray> wireByUid;
    int gone = 0;
    for (const qint64 uid : uids) {
        const QByteArray wire = imap.fetchRaw(uid);
        if (wire.isEmpty())
            ++gone;
        else
            wireByUid.insert(uid, wire);
    }
    imap.logout();

    QString kimapError;
    const QHash<qint64, QByteArray> kimapByUid =
        fetchViaKimap(account, password, mailBox, uids, &kimapError);
    if (kimapByUid.isEmpty() && !kimapError.isEmpty())
        fprintf(stderr, "kimap: %s\n", qPrintable(kimapError));

    DkimVerifier verifier;
    int wireEqCached = 0, wireEqKmime = 0, wireEqKimap = 0, lfOnly = 0, kimapSeen = 0;
    QMap<QString, int> wireVerdicts, kimapVerdicts, cachedVerdicts;
    QStringList divergences;

    printf("%-7s %-11s %-11s %-11s  %s\n", "UID", "DKIM(wire)", "DKIM(kimap)",
           "DKIM(cache)", "octets vs wire");
    printf("%s\n", QByteArray(78, '-').constData());

    for (const qint64 uid : uids) {
        if (!wireByUid.contains(uid)) {
            printf("%-7lld (not on the server any more)\n", uid);
            continue;
        }
        const QByteArray wire = wireByUid.value(uid);
        const QByteArray cached = cachedBody(db, folder, uid);
        const QByteArray cachedCrlf = KMime::LFtoCRLF(cached);

        // Pristine KMime round-trip. setContent() takes LF, so the message must
        // be lowered on the way in and lifted on the way out — anything else
        // measures our own conversion rather than KMime's.
        KMime::Message parsed;
        parsed.setContent(KMime::CRLFtoLF(wire));
        if (parsed.contents().isEmpty())
            parsed.parse();
        const QByteArray kmime = KMime::LFtoCRLF(parsed.encodedContent());

        const QByteArray kimapRaw = kimapByUid.value(uid);
        const QByteArray kimap = KMime::LFtoCRLF(kimapRaw);
        const bool haveKimap = !kimapRaw.isEmpty();

        auto dump = [&outDir, uid](const char *suffix, const QByteArray &data) {
            if (data.isEmpty())
                return;
            QFile f(outDir + QStringLiteral("/%1.%2.eml").arg(uid).arg(QLatin1String(suffix)));
            if (f.open(QIODevice::WriteOnly))
                f.write(data);
        };
        dump("wire", wire);
        dump("cached", cached);
        dump("kmime", kmime);
        dump("kimap", kimapRaw);

        const bool eqCached = (wire == cachedCrlf);
        const bool eqKmime = (wire == kmime);
        const bool eqKimap = haveKimap && (wire == kimap);
        wireEqCached += eqCached;
        wireEqKmime += eqKmime;
        kimapSeen += haveKimap;
        wireEqKimap += eqKimap;
        // Did CRLF->LF->CRLF alone account for it? If the cached copy matches
        // once lifted but the stored bytes differ from the wire, the newline
        // normalisation is lossless here and the loss is elsewhere.
        if (eqCached && wire != cached)
            ++lfOnly;

        const QString fromDomain = fromDomainOf(wire);
        const DkimResult rWire = verifyOnce(verifier, wire, fromDomain);
        const DkimResult rCached = verifyOnce(verifier, cachedCrlf, fromDomain);
        ++wireVerdicts[QLatin1String(statusName(rWire.status))];
        ++cachedVerdicts[QLatin1String(statusName(rCached.status))];
        QString kimapVerdict = QStringLiteral("-");
        if (haveKimap) {
            const DkimResult r = verifyOnce(verifier, kimap, fromDomain);
            kimapVerdict = QLatin1String(statusName(r.status));
            ++kimapVerdicts[kimapVerdict];
        }

        QStringList octets;
        octets << (eqKmime ? QStringLiteral("kmime=same") : QStringLiteral("kmime=DIFF"));
        octets << (!haveKimap ? QStringLiteral("kimap=?")
                              : eqKimap ? QStringLiteral("kimap=same")
                                        : QStringLiteral("kimap=DIFF"));
        octets << (eqCached ? QStringLiteral("cache=same") : QStringLiteral("cache=DIFF"));

        printf("%-7lld %-11s %-11s %-11s  %s\n", uid, statusName(rWire.status),
               qPrintable(kimapVerdict), statusName(rCached.status),
               qPrintable(octets.join(QLatin1Char(' '))));

        if (haveKimap && !eqKimap && divergences.size() < 5) {
            divergences << QStringLiteral("uid %1  wire vs KIMAP: %2")
                               .arg(uid)
                               .arg(firstDifference(wire, kimap));
        }
    }

    const int checked = int(uids.size()) - gone;
    printf("\n%s\n", QByteArray(78, '=').constData());
    printf("checked %d of %lld sampled (%d no longer on the server)\n", checked,
           qint64(uids.size()), gone);
    if (checked > 0) {
        printf("  wire == pristine KMime round-trip : %d/%d\n", wireEqKmime, checked);
        printf("  wire == what KIMAP hands us       : %d/%d\n", wireEqKimap, kimapSeen);
        printf("  wire == cached (lifted)           : %d/%d\n", wireEqCached, checked);
        printf("  of the cache matches, %d needed the LF->CRLF lift\n", lfOnly);
    }
    auto printVerdicts = [](const char *label, const QMap<QString, int> &v) {
        QStringList parts;
        for (auto it = v.cbegin(); it != v.cend(); ++it)
            parts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        printf("  DKIM %-16s %s\n", label, qPrintable(parts.join(QStringLiteral("  "))));
    };
    printVerdicts("on wire:", wireVerdicts);
    printVerdicts("on KIMAP:", kimapVerdicts);
    printVerdicts("on cached:", cachedVerdicts);

    if (!divergences.isEmpty()) {
        printf("\nfirst divergences:\n");
        for (const QString &d : std::as_const(divergences))
            printf("  %s\n", qPrintable(d));
    }
    printf("\nraw copies written to %s/\n", qPrintable(outDir));
    return 0;
}
