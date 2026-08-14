// Diagnostic, not a pass/fail test: runs the real spam heuristics over .eml
// files and prints the score with every rule that fired. This is how the
// weights in spamheuristics.cpp get tuned — without a corpus to measure
// against, a spam filter's false-positive rate is a guess.
//
//   ./spamtool msg.eml ...                  score each message
//   ./spamtool --dir mail/                  score every .eml under a directory
//   ./spamtool --ham ham/ --spam spam/      confusion matrix over two corpora
//   ./spamtool --known alice@example.com    treat these senders as allowlisted
//   ./spamtool --auth-fail msg.eml          score as if SPF/DKIM/DMARC failed
//   ./spamtool --auth-pass msg.eml          ...or passed
//   ./spamtool --arc-pass msg.eml           ...or failed only because of a relay (ARC)
//   ./spamtool --junk msg.eml               score as if it sat in the Junk folder
//   ./spamtool --crypto 2 msg.eml           score as OpenPGP signed (1 enc, 2 sig, 3 both)
//   ./spamtool --quiet ...                  totals only, no per-message lines
//   ./spamtool --cache                      score your own cached inbox, no export
//   ./spamtool --cache --folder Junk        ...some other folder instead
//   ./spamtool --cache --limit 500          ...how many, newest first (default 200)
//   ./spamtool --msgid '<abc@host>'         score a message straight from the cache
//   ./spamtool --db PATH                    ...from a cache other than the default
//
// --cache is the normal way to try the filter against real mail: it reads the
// messages mailove has already cached and, unlike every other mode, fills the
// scoring context from the cache too. It sweeps the INBOX only, because that is
// the only folder the client scores (MailClient::scoresSpamIn) — measuring Sent
// or Junk would be measuring a filter that never runs there — who you have written to, and how long
// each sending domain has been writing to you. Those are the two strongest ham
// rules in the scorer, so a corpus scored without them comes out pessimistic.
// Only messages whose body is cached are scored, and the count of those that
// were skipped for want of one is printed with the totals.
//
// --msgid saves exporting an .eml by hand: it looks the message up in mailove's
// own cache by Message-ID (an indexed lookup, idx_messages_msgid) and scores
// the stored bytes. The cache is opened strictly read-only and no migration is
// run, so pointing this at the database a running mailove is using cannot alter
// it. The same Message-ID may be cached in several folders or accounts; every
// copy is scored and located in the output.
//
// Bodies are used when the file has them, so the same message can score
// differently here and in the message list, which only ever sees headers.
#include "../src/mimeutils.h"
#include "../src/publicsuffixlist.h"
#include "../src/spamheuristics.h"

#include <KMime/Message>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QStandardPaths>
#include <cstdio>

namespace
{

const char *verdictName(SpamHeuristics::Verdict v)
{
    switch (v) {
    case SpamHeuristics::Verdict::Ham: return "HAM";
    case SpamHeuristics::Verdict::Unsure: return "UNSURE";
    case SpamHeuristics::Verdict::Spam: return "SPAM";
    }
    return "?";
}

struct Totals {
    int ham = 0;
    int unsure = 0;
    int spam = 0;
    int exempt = 0;
    void count(const SpamHeuristics::Score &s)
    {
        if (s.exempt)
            ++exempt;
        switch (s.verdict) {
        case SpamHeuristics::Verdict::Ham: ++ham; break;
        case SpamHeuristics::Verdict::Unsure: ++unsure; break;
        case SpamHeuristics::Verdict::Spam: ++spam; break;
        }
    }
    int total() const { return ham + unsure + spam; }
};

/// Scores one file. Returns false when it could not be read.
/// Scores one message that is already in memory. \a label names it in the
/// output — a file name, or a cache location for --msgid.
/// \a base carries everything the caller simulates for the whole run — the
/// authentication verdict, the crypto kind, the sender-domain history. Only
/// knownCorrespondent is per-message, because only it can be answered from the
/// message itself plus the allowlist.
///
/// The message's own Authentication-Results is deliberately NOT read. In the
/// client only a header stamped by our own receiving server counts, and here
/// there is no "our server" to compare an authserv-id against — trusting the
/// file's own header would measure the filter against a value the sender
/// controls. --auth-fail / --auth-pass simulate the verdict instead, which is
/// the only way to exercise the known-contact-spoofed rule offline.
///
/// X-Spam-Status is different and *is* read, by the scorer itself: its
/// provenance test is positional (above the topmost Received), so it needs no
/// knowledge of which server we trust and holds just as well on a file.
bool scoreRaw(const QByteArray &raw, const QString &label, const QSet<QString> &known,
              const SpamHeuristics::Context &base, bool quiet, Totals *totals)
{
    KMime::Message msg;
    msg.setContent(KMime::CRLFtoLF(raw));
    msg.parse();

    SpamHeuristics::Message m;
    m.head = msg.head();
    MimeUtils::collectBodies(&msg, &m.text, &m.html);
    MimeUtils::collectAttachments(&msg, &m.attachmentNames);
    m.encryptedArchive = MimeUtils::hasEncryptedArchive(&msg);

    SpamHeuristics::Context ctx = base;
    const QString from = msg.from() ? msg.from()->asUnicodeString() : QString();
    const QString addr = SpamHeuristics::addressOf(from);
    // Only when the caller supplied an allowlist. --cache answers this from the
    // recipients table and passes the answer in the context; overwriting it
    // from an empty --known set here reported every message as unexempt and
    // made Rule 0 — the strongest ham rule there is — look like it never fires.
    if (!known.isEmpty())
        ctx.knownCorrespondent = known.contains(addr);

    const SpamHeuristics::Score s = SpamHeuristics::score(m, ctx);
    totals->count(s);

    if (quiet)
        return true;

    std::printf("%-40s %-7s %4d  %s\n", qPrintable(label), verdictName(s.verdict),
                s.total, qPrintable(addr));
    if (s.exempt) {
        std::printf("      exempt: %s\n", qPrintable(s.exemptReason));
        return true;
    }
    for (const SpamHeuristics::Hit &h : s.hits) {
        std::printf("      %+4d %-26s %s\n", h.weight, qPrintable(h.id),
                    qPrintable(h.detail));
    }
    return true;
}

bool scoreFile(const QString &path, const QSet<QString> &known,
               const SpamHeuristics::Context &base, bool quiet, Totals *totals)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "cannot open %s\n", qPrintable(path));
        return false;
    }
    return scoreRaw(f.readAll(), QFileInfo(path).fileName(), known, base, quiet, totals);
}

QStringList emlsUnder(const QString &dir)
{
    QStringList out;
    QDirIterator it(dir, {QStringLiteral("*.eml")}, QDir::Files,
                    QDirIterator::Subdirectories);
    while (it.hasNext())
        out.append(it.next());
    out.sort();
    return out;
}

/// mailove's own cache, opened read-only. Deliberately not via MailStore: open()
/// there runs the schema migrations, and a diagnostic must not be able to write
/// to the database the running client is using.
QSqlDatabase openCacheReadOnly(const QString &explicitPath)
{
    QString path = explicitPath;
    if (path.isEmpty()) {
        path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
            + QStringLiteral("/mailove.db");
    }
    if (!QFile::exists(path)) {
        std::fprintf(stderr, "no cache at %s\n", qPrintable(path));
        return {};
    }
    QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"),
                                                QStringLiteral("spamtool"));
    db.setDatabaseName(path);
    // QSQLITE_OPEN_READONLY is the guarantee, not a convention: mailove may well
    // be running against this file, and its WAL is shared.
    db.setConnectOptions(QStringLiteral("QSQLITE_OPEN_READONLY"));
    if (!db.open()) {
        std::fprintf(stderr, "cannot open %s: %s\n", qPrintable(path),
                     qPrintable(db.lastError().text()));
        return {};
    }
    return db;
}

/// The real scoring context for one message, read out of the cache the client
/// uses — not simulated the way --auth-pass and --seen-from-org are.
///
/// This is what makes --cache worth having over a folder of exported files: the
/// familiarity and allowlist signals are the strongest ham rules in the scorer,
/// and a corpus on disk has no history behind it to trigger them. Scored
/// without that, perfectly ordinary mail reads as "first contact from a domain
/// I have never heard of" and the numbers come out pessimistic.
///
/// The authentication verdict is the one part still left to the caller. It
/// depends on which authserv-id this account's server stamps, which lives in
/// the account settings rather than the cache, and reading a message's own
/// Authentication-Results here would be trusting a header the sender wrote.
SpamHeuristics::Context cacheContext(QSqlDatabase &db, const SpamHeuristics::Context &base,
                                     const QString &fromValue)
{
    SpamHeuristics::Context ctx = base;
    const QString addr = SpamHeuristics::addressOf(fromValue);
    if (addr.isEmpty())
        return ctx;

    QSqlQuery r(db);
    r.prepare(QStringLiteral("SELECT 1 FROM recipients WHERE addr_norm = ? LIMIT 1"));
    r.addBindValue(SpamHeuristics::normalizeAddress(addr));
    if (r.exec() && r.next())
        ctx.knownCorrespondent = true;

    const QString org = SpamHeuristics::organizationalDomainOf(addr);
    if (!org.isEmpty()) {
        QSqlQuery h(db);
        h.prepare(QStringLiteral("SELECT seen, first_seen FROM sender_domains WHERE org = ?"));
        h.addBindValue(org);
        if (h.exec() && h.next()) {
            ctx.seenFromOrg = h.value(0).toInt();
            const qint64 first = h.value(1).toLongLong();
            const qint64 now = QDateTime::currentSecsSinceEpoch();
            // Same measure MailStore::senderDomainHistory() uses: age to now,
            // not to the last message, so a burst last Tuesday is not "old".
            ctx.daysKnownOrg =
                first > 0 && now > first ? static_cast<int>((now - first) / 86400) : 0;
        }
    }
    return ctx;
}

/// Scores what is already cached, without anything being exported first.
///
/// Only messages whose body is cached are scored: the header-only ones are the
/// majority in a large mailbox and would score systematically lower (every
/// body and attachment rule stays silent), which would quietly make the
/// false-positive rate look better than it is. They are counted and reported
/// as skipped rather than folded into the totals.
///
/// \a folderLike, when set, restricts the sweep to folder keys containing it —
/// "INBOX", or an account name. \a limit caps how many are scored, newest
/// first, because a full mailbox is a lot of output to read.
int scoreCache(QSqlDatabase &db, const QString &folderLike, int limit,
               const SpamHeuristics::Context &base, bool quiet, Totals *totals)
{
    QString sql = QStringLiteral(
        "SELECT m.folder, m.uid, m.sender, b.raw FROM messages m"
        " JOIN bodies b ON b.folder = m.folder AND b.uid = m.uid");
    // The inbox and nothing else, matching MailClient::scoresSpamIn(). Sweeping
    // everything scored the user's own Sent mail, their Drafts, and a Junk
    // folder the server had already judged — none of which the client scores,
    // so the numbers described a filter that does not exist. The folder key is
    // "account\x1fmailbox", hence the suffix match.
    if (folderLike.isEmpty())
        sql += QStringLiteral(" WHERE m.folder LIKE '%INBOX'");
    else
        sql += QStringLiteral(" WHERE m.folder LIKE ?");
    sql += QStringLiteral(" ORDER BY m.date DESC");
    if (limit > 0)
        sql += QStringLiteral(" LIMIT %1").arg(limit);

    QSqlQuery q(db);
    q.prepare(sql);
    if (!folderLike.isEmpty())
        q.addBindValue(QStringLiteral("%%%1%%").arg(folderLike));
    if (!q.exec()) {
        std::fprintf(stderr, "cache sweep failed: %s\n", qPrintable(q.lastError().text()));
        return 0;
    }

    int scored = 0;
    while (q.next()) {
        const QByteArray raw = q.value(3).toByteArray();
        if (raw.isEmpty())
            continue;
        QString where = q.value(0).toString();
        where.replace(QChar(0x1f), QLatin1String(" / "));
        where += QStringLiteral(":%1").arg(q.value(1).toLongLong());
        SpamHeuristics::Context ctx = cacheContext(db, base, q.value(2).toString());
        // Same rule the client applies: everything in a junk folder is spam by
        // definition. Named by the same generous test MailClient::isJunkFolder
        // uses, reduced to the few names that matter for a diagnostic.
        const QString path = q.value(0).toString().section(QChar(0x1f), -1).toLower();
        for (const auto &name : {"junk", "spam", "bulk", "quarantine"}) {
            if (path.contains(QLatin1String(name))) {
                ctx.inJunkFolder = true;
                break;
            }
        }
        // knownCorrespondent comes from the context now, so the --known list
        // has nothing left to add; pass it empty rather than have two sources
        // of the same answer disagree.
        scoreRaw(raw, where, {}, ctx, quiet, totals);
        ++scored;
    }
    return scored;
}

/// How many cached headers have no body, so the sweep's coverage can be stated
/// rather than left to be guessed at from the totals.
int countBodyless(QSqlDatabase &db, const QString &folderLike)
{
    QString sql = QStringLiteral(
        "SELECT COUNT(*) FROM messages m LEFT JOIN bodies b"
        " ON b.folder = m.folder AND b.uid = m.uid"
        " WHERE (b.raw IS NULL OR b.raw = x'')");
    if (folderLike.isEmpty())
        sql += QStringLiteral(" AND m.folder LIKE '%INBOX'");
    else
        sql += QStringLiteral(" AND m.folder LIKE ?");
    QSqlQuery q(db);
    q.prepare(sql);
    if (!folderLike.isEmpty())
        q.addBindValue(QStringLiteral("%%%1%%").arg(folderLike));
    return (q.exec() && q.next()) ? q.value(0).toInt() : 0;
}

/// Every cached copy of \a msgid, scored. Returns how many were found.
int scoreByMessageId(QSqlDatabase &db, const QString &rawMsgid, const QSet<QString> &known,
                     const SpamHeuristics::Context &base, bool quiet, Totals *totals)
{
    // Stored with the angle brackets stripped (MessageListModel::Header::msgid),
    // but people paste them in, so accept either form.
    QString msgid = rawMsgid.trimmed();
    if (msgid.startsWith(QLatin1Char('<')) && msgid.endsWith(QLatin1Char('>')))
        msgid = msgid.mid(1, msgid.size() - 2);

    QSqlQuery q(db);
    q.prepare(QStringLiteral("SELECT folder, uid FROM messages WHERE msgid = ?"));
    q.addBindValue(msgid);
    if (!q.exec()) {
        std::fprintf(stderr, "lookup failed: %s\n", qPrintable(q.lastError().text()));
        return 0;
    }
    QList<QPair<QString, qint64>> hits;
    while (q.next())
        hits.append({q.value(0).toString(), q.value(1).toLongLong()});

    if (hits.isEmpty()) {
        std::fprintf(stderr, "no cached message with Message-ID %s\n", qPrintable(msgid));
        return 0;
    }

    int scored = 0;
    for (const auto &hit : std::as_const(hits)) {
        QSqlQuery b(db);
        b.prepare(QStringLiteral("SELECT raw FROM bodies WHERE folder = ? AND uid = ?"));
        b.addBindValue(hit.first);
        b.addBindValue(hit.second);
        // The folder key is "account\x1ffolder"; show it the way a person reads it.
        QString where = hit.first;
        where.replace(QChar(0x1f), QLatin1String(" / "));
        where += QStringLiteral(":%1").arg(hit.second);

        if (!b.exec() || !b.next() || b.value(0).toByteArray().isEmpty()) {
            std::fprintf(stderr, "%s: header cached but no body yet — open it once "
                                 "in mailove, or export it\n", qPrintable(where));
            continue;
        }
        // A cached body whose large attachments were lifted into the file store
        // is a stub. The text and HTML parts stay inline, so the body rules see
        // what they need. The attachment rules are the exception: they read the
        // declared filename, and a lifted part leaves only a stub behind — so a
        // message scored from the cache can score lower here than the same
        // message scored from its .eml. Tune those weights against files.
        scoreRaw(b.value(0).toByteArray(), where, known, base, quiet, totals);
        ++scored;
    }
    return scored;
}

void printTotals(const char *label, const Totals &t)
{
    if (t.total() == 0)
        return;
    std::printf("%s: %d messages — ham %d, unsure %d, spam %d (%d exempt under Rule 0)\n",
                label, t.total(), t.ham, t.unsure, t.spam, t.exempt);
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // The same identity src/main.cpp gives the client, so QStandardPaths lands
    // on mailove's own data directory. Both the cached Public Suffix List and the
    // message cache live there, so this has to come before either is looked up.
    QCoreApplication::setOrganizationName(QStringLiteral("mailove"));
    QCoreApplication::setApplicationName(QStringLiteral("mailove"));
    // Loads the cached Public Suffix List and refreshes it if stale. Without it
    // organizationalDomainOf() falls back to the full domain, which only makes
    // the alignment rules fire less often — the tool still runs, it just
    // under-reports, so say so rather than silently producing softer numbers.
    PublicSuffixList::instance().start();

    QStringList files;
    QStringList hamDirs;
    QStringList spamDirs;
    QSet<QString> known;
    SpamHeuristics::Context base;
    bool quiet = false;
    QStringList msgids;
    QString dbPath;
    bool sweepCache = false;
    QString folderLike;
    int limit = 200;

    for (int i = 1; i < argc; ++i) {
        const QString arg = QString::fromLocal8Bit(argv[i]);
        const auto next = [&]() -> QString {
            return (i + 1 < argc) ? QString::fromLocal8Bit(argv[++i]) : QString();
        };
        if (arg == QLatin1String("--dir"))
            files += emlsUnder(next());
        else if (arg == QLatin1String("--ham"))
            hamDirs.append(next());
        else if (arg == QLatin1String("--spam"))
            spamDirs.append(next());
        else if (arg == QLatin1String("--known"))
            known.insert(SpamHeuristics::normalizeAddress(next()));
        else if (arg == QLatin1String("--always-score"))
            base.alwaysScore = true;
        else if (arg == QLatin1String("--auth-fail"))
            base.authFailed = true;
        else if (arg == QLatin1String("--auth-pass"))
            base.authPassed = true;
        else if (arg == QLatin1String("--arc-pass"))
            base.arcPassed = true;
        else if (arg == QLatin1String("--junk"))
            base.inJunkFolder = true;
        else if (arg == QLatin1String("--crypto"))
            base.crypto = next().toInt();
        // Simulated sender-domain history, the way --auth-pass simulates a
        // verdict: a corpus on disk has no cache behind it to have a history in.
        else if (arg == QLatin1String("--seen-from-org"))
            base.seenFromOrg = next().toInt();
        else if (arg == QLatin1String("--days-known-org"))
            base.daysKnownOrg = next().toInt();
        else if (arg == QLatin1String("--msgid"))
            msgids.append(next());
        else if (arg == QLatin1String("--cache"))
            sweepCache = true;
        else if (arg == QLatin1String("--folder"))
            folderLike = next();
        else if (arg == QLatin1String("--limit"))
            limit = next().toInt();
        else if (arg == QLatin1String("--db"))
            dbPath = next();
        else if (arg == QLatin1String("--quiet"))
            quiet = true;
        else if (arg.startsWith(QLatin1String("--"))) {
            std::fprintf(stderr, "unknown option %s\n", qPrintable(arg));
            return 2;
        } else {
            files.append(arg);
        }
    }

    if (files.isEmpty() && hamDirs.isEmpty() && spamDirs.isEmpty() && msgids.isEmpty()
        && !sweepCache) {
        std::fprintf(stderr,
                     "usage: spamtool [--quiet] [--always-score] [--known ADDR]...\n"
                     "                [--auth-fail|--auth-pass] [--crypto 0|1|2|3]\n"
                     "                [--cache] [--folder NAME] [--limit N]\n"
                     "                [--msgid MESSAGE-ID]... [--db PATH]\n"
                     "                [--dir DIR] [--ham DIR] [--spam DIR] [FILE...]\n");
        return 2;
    }
    if (!PublicSuffixList::instance().isLoaded()) {
        std::fprintf(stderr, "warning: no Public Suffix List — domain-alignment rules "
                             "will under-report\n");
    }

    Totals plain;
    for (const QString &f : std::as_const(files))
        scoreFile(f, known, base, quiet, &plain);

    if (!msgids.isEmpty() || sweepCache) {
        QSqlDatabase db = openCacheReadOnly(dbPath);
        if (!db.isOpen())
            return 2;
        for (const QString &id : std::as_const(msgids)) {
            scoreByMessageId(db, id, known, base, quiet, &plain);
        }
        if (sweepCache) {
            const int scored = scoreCache(db, folderLike, limit, base, quiet, &plain);
            const int skipped = countBodyless(db, folderLike);
            // Said out loud rather than left to be inferred: a sweep that
            // silently ignored two thirds of the mailbox would read as a
            // clean bill of health for the whole of it.
            std::printf("cache: scored %d message(s) with a cached body%s; %d cached "
                        "header(s) have no body yet and were skipped\n",
                        scored, limit > 0 ? " (newest first, --limit)" : "", skipped);
        }
    }

    Totals hamTotals;
    for (const QString &d : std::as_const(hamDirs)) {
        for (const QString &f : emlsUnder(d))
            scoreFile(f, known, base, quiet, &hamTotals);
    }
    Totals spamTotals;
    for (const QString &d : std::as_const(spamDirs)) {
        for (const QString &f : emlsUnder(d))
            scoreFile(f, known, base, quiet, &spamTotals);
    }

    std::printf("\n");
    printTotals("files", plain);
    printTotals("ham corpus", hamTotals);
    printTotals("spam corpus", spamTotals);

    if (hamTotals.total() > 0 && spamTotals.total() > 0) {
        // False positives are reported first and on their own line because they
        // are the only number that matters much: a missed spam costs a delete,
        // a marked good message costs trust in the whole feature.
        const double fp = 100.0 * hamTotals.spam / hamTotals.total();
        const double fn = 100.0 * spamTotals.ham / spamTotals.total();
        std::printf("\nfalse positives: %d/%d (%.2f%% of good mail marked)\n",
                    hamTotals.spam, hamTotals.total(), fp);
        std::printf("false negatives: %d/%d (%.2f%% of spam unmarked)\n",
                    spamTotals.ham, spamTotals.total(), fn);
        std::printf("caught: %d/%d (%.2f%%)\n", spamTotals.spam, spamTotals.total(),
                    100.0 * spamTotals.spam / spamTotals.total());
    }
    return 0;
}
