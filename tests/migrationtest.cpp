// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * The deferred cache migrations: what MailStore::pendingMigrations() reports
 * and what MailStore::runMigration() actually does to the rows.
 *
 * These used to run inside open(), one statement each, on the GUI thread. They
 * now run in chunks on a worker behind a progress modal, which is a rewrite of
 * every one of them — and they are exactly the code that cannot be tried again
 * later: a migration runs once, against mail that only the user has, and a
 * wrong predicate deletes or mislabels it silently. Hence a legacy-shaped
 * database built here row by row, and an assertion per rule.
 *
 * Runs against a throwaway database in its own AppDataLocation — set via
 * QStandardPaths::setTestModeEnabled() plus a test-only application name — so
 * it can never open, let alone write to, the real mail cache.
 */

#include "../src/mailstore.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QSqlError>
#include <QSqlQuery>
#include <QStandardPaths>
#include <QTextStream>

static int failures = 0;

/// Plain stdout rather than qInfo: a diagnostic tool has to print its findings
/// whatever the ambient QT_LOGGING_RULES say, and the default rules drop
/// qInfo() on the floor.
static QTextStream &out()
{
    static QTextStream s(stdout);
    return s;
}

static void check(bool ok, const QString &what)
{
    out() << (ok ? QStringLiteral("  ok   ") : QStringLiteral("  FAIL ")) << what << Qt::endl;
    if (!ok)
        ++failures;
}

static void exec(QSqlDatabase &db, const QString &sql)
{
    QSqlQuery q(db);
    if (!q.exec(sql))
        qWarning() << "setup failed:" << sql << q.lastError().text();
}

static qint64 count(QSqlDatabase &db, const QString &sql)
{
    QSqlQuery q(db);
    return (q.exec(sql) && q.next()) ? q.value(0).toLongLong() : -1;
}

/// The unit separator that joins an account key to a mailbox name. Spelled out
/// rather than pasted as a literal so the SQL below stays readable.
static QString sep()
{
    return QString(QChar(0x1f));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // Both together are what redirect AppDataLocation away from the real cache.
    QCoreApplication::setApplicationName(QStringLiteral("mailove-migrationtest"));
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-migrationtest"));
    QStandardPaths::setTestModeEnabled(true);

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty() || !dir.contains(QLatin1String("mailove-migrationtest"))) {
        qWarning() << "refusing to run: test data location is not isolated:" << dir;
        return 2;
    }
    // Start from nothing, so a rerun is not judging a previous run's rows.
    QDir(dir).removeRecursively();

    MailStore store;
    if (!store.open()) {
        qWarning() << "cannot open test store";
        return 2;
    }
    const QString account = QStringLiteral("tester@example.net");

    // A second handle on the same file: the store's own connection is private,
    // and the worker connection is what the migrations themselves run on.
    QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("migrationtest"));
    if (!db.isOpen()) {
        qWarning() << "cannot open the worker connection";
        return 2;
    }

    // --- a database shaped like one an upgrade finds -----------------------

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 recent = now - 5 * 86400;   // inside the 30-day window
    const qint64 ancient = now - 400 * 86400; // outside it

    // Pre-multi-account rows: an unscoped folder list and unscoped mail.
    exec(db, QStringLiteral("INSERT INTO folders (mailbox, sortkey) VALUES ('INBOX', 0)"));
    exec(db, QStringLiteral("INSERT INTO folders (mailbox, sortkey) VALUES ('Sent', 1)"));

    auto message = [&](const QString &folder, qint64 uid, const QString &subject, qint64 date,
                       const QString &verdict) {
        QSqlQuery q(db);
        q.prepare(QStringLiteral(
            "INSERT INTO messages (folder, uid, subject, sender, date, dkim, spam_score,"
            " spam_state, attach) VALUES (?, ?, ?, 'someone@example.com', ?, ?, ?, ?, 0)"));
        q.addBindValue(folder);
        q.addBindValue(uid);
        q.addBindValue(subject);
        q.addBindValue(date);
        q.addBindValue(verdict);
        q.addBindValue(verdict.isEmpty() ? 0 : 42);
        q.addBindValue(verdict.isEmpty() ? 0 : 2);
        q.exec();
    };
    auto body = [&](const QString &folder, qint64 uid, const QByteArray &raw) {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("INSERT INTO bodies (folder, uid, raw) VALUES (?, ?, ?)"));
        q.addBindValue(folder);
        q.addBindValue(uid);
        q.addBindValue(raw);
        q.exec();
    };

    // Unscoped, recent, carrying a verdict made against a re-assembled body.
    message(QStringLiteral("INBOX"), 1, QStringLiteral("recent"), recent,
            QStringLiteral("pass"));
    // Unscoped, old: its verdict is left alone.
    message(QStringLiteral("INBOX"), 2, QStringLiteral("ancient"), ancient,
            QStringLiteral("pass"));
    // An imported archive: never re-fetchable, so never cleared even though it
    // is recent. Already scoped, and deliberately so — "import:" is an account
    // cache key, and local archives were born after accounts were separated, so
    // an imported row has always carried its key. That is also what keeps the
    // adoption below from prefixing it and hiding it from the 'import:%' test.
    const QString imported = QStringLiteral("import:box") + sep() + QStringLiteral("INBOX");
    message(imported, 3, QStringLiteral("imported"), recent, QStringLiteral("pass"));
    // The ghosts: no uid, and no content at all.
    message(QStringLiteral("INBOX"), 0, QStringLiteral("no uid"), recent, QString());
    exec(db, QStringLiteral(
        "INSERT INTO messages (folder, uid, subject, sender, date) VALUES"
        " ('INBOX', 4, '', '', 0)"));
    // A message the user answered for themselves: spam_state 3 is not a
    // derivation and must survive the sweep.
    message(QStringLiteral("INBOX"), 5, QStringLiteral("user verdict"), recent, QString());
    exec(db, QStringLiteral("UPDATE messages SET spam_state = 3 WHERE uid = 5"));

    const QByteArray withAttachment =
        "Subject: has one\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
        "--b\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nx\r\n--b--\r\n";
    const QByteArray plain = "Subject: plain\r\n\r\nnothing here\r\n";
    body(QStringLiteral("INBOX"), 1, withAttachment);
    body(QStringLiteral("INBOX"), 2, withAttachment);
    body(imported, 3, plain);
    body(QStringLiteral("INBOX"), 0, plain); // ghost body
    body(QStringLiteral("INBOX"), 5, plain);

    // An index keyed the old way (its own rowids, not the messages' ones).
    exec(db, QStringLiteral(
        "INSERT INTO fts (subject, sender, body, folder, uid)"
        " SELECT subject, sender, '', folder, uid FROM messages WHERE uid > 0"));

    const qint64 messagesBefore = count(db, QStringLiteral("SELECT COUNT(*) FROM messages"));

    // --- what is pending ---------------------------------------------------

    out() << "pendingMigrations" << Qt::endl;

    QList<MailStore::Migration> steps = store.pendingMigrations(account);
    QStringList flags;
    for (const auto &s : steps)
        flags.append(s.flag);
    check(flags.contains(QLatin1String("legacy_adopt1")),
          QStringLiteral("a cache with unscoped rows is offered the account adoption"));
    check(flags.indexOf(QLatin1String("legacy_adopt1")) == 0,
          QStringLiteral("…first, before anything reads rows by their scoped key"));
    check(flags.contains(QLatin1String("ghost_sweep1"))
              && flags.contains(QLatin1String("raw_refetch_29"))
              && flags.contains(QLatin1String("attach_backfill")),
          QStringLiteral("every deferred step is listed on a cache that has had none"));
    check(!store.pendingMigrations(QString()).isEmpty()
              && !QStringList(store.pendingMigrations(QString()).first().flag)
                      .contains(QLatin1String("legacy_adopt1")),
          QStringLiteral("a local archive (no account key) is never offered the adoption"));
    for (const auto &s : steps) {
        if (s.label.trimmed().isEmpty())
            check(false, QStringLiteral("step %1 has no label for the modal").arg(s.flag));
    }
    check(true, QStringLiteral("every step carries a label the modal can show"));

    // --- running them ------------------------------------------------------

    out() << "runMigration" << Qt::endl;

    int reports = 0;
    const auto progress = [&reports](int percent) {
        if (percent >= 0 && percent <= 100)
            ++reports;
    };
    const auto never = [] { return false; };
    for (const auto &s : steps)
        MailStore::runMigration(db, s, account, progress, never);

    check(reports > 0,
          QStringLiteral("the steps report progress, so the modal can show a bar and an estimate"));

    const QString prefix = account + sep();
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM messages WHERE instr(folder, char(31)) = 0"))
              == 0,
          QStringLiteral("every message row is scoped to the account afterwards"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM bodies WHERE instr(folder, char(31)) = 0"))
              == 0,
          QStringLiteral("…and every cached body with it"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM account_folders WHERE account = '%1'")
                        .arg(account))
              == 2,
          QStringLiteral("the global folder list is adopted by the account"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM folders")) == 0,
          QStringLiteral("…and the legacy list is emptied, so it cannot be adopted twice"));

    check(count(db, QStringLiteral("SELECT COUNT(*) FROM messages WHERE uid <= 0")) == 0,
          QStringLiteral("rows with no uid are swept"));
    check(count(db, QStringLiteral(
              "SELECT COUNT(*) FROM messages WHERE IFNULL(subject,'') = ''"
              " AND IFNULL(sender,'') = '' AND IFNULL(date,0) <= 0")) == 0,
          QStringLiteral("…and rows with no content at all"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM messages")) == messagesBefore - 2,
          QStringLiteral("…and nothing else is swept with them"));

    check(count(db, QStringLiteral("SELECT COUNT(*) FROM bodies WHERE uid = 1")) == 0,
          QStringLiteral("a recent body is dropped, to be re-fetched octet-faithfully"));
    check(count(db, QStringLiteral("SELECT dkim <> '' FROM messages WHERE uid = 1")) == 0,
          QStringLiteral("…and the verdict made against the old bytes is cleared"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM bodies WHERE uid = 3")) == 1,
          QStringLiteral("an imported archive's body is kept — there is nowhere to re-fetch it"));
    check(count(db, QStringLiteral("SELECT dkim = 'pass' FROM messages WHERE uid = 3")) == 1,
          QStringLiteral("…and its verdict with it"));
    check(count(db, QStringLiteral("SELECT dkim = 'pass' FROM messages WHERE uid = 2")) == 1,
          QStringLiteral("mail older than the window keeps its verdict"));
    check(count(db, QStringLiteral("SELECT spam_state FROM messages WHERE uid = 5")) == 3,
          QStringLiteral("the user's own spam answer survives the sweep"));

    check(count(db, QStringLiteral("SELECT attach FROM messages WHERE uid = 2")) == 1,
          QStringLiteral("a cached body with an attachment sets the attach flag"));
    check(count(db, QStringLiteral("SELECT attach FROM messages WHERE uid = 3")) == 0,
          QStringLiteral("…and one without leaves it alone"));

    check(count(db, QStringLiteral(
              "SELECT COUNT(*) FROM fts f JOIN messages m ON m.rowid = f.rowid")) > 0,
          QStringLiteral("the search index is re-keyed by messages.rowid"));
    check(count(db, QStringLiteral(
              "SELECT sql LIKE '%remove_diacritics 2%' FROM sqlite_master"
              " WHERE type = 'table' AND name = 'fts'")) == 1,
          QStringLiteral("…into an index that folds accents"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM fts_pending")) > 0,
          QStringLiteral("cached bodies are queued for background text indexing"));

    // --- and never again ---------------------------------------------------

    out() << "idempotence" << Qt::endl;

    check(store.pendingMigrations(account).isEmpty(),
          QStringLiteral("nothing is pending once they have run"));
    const qint64 settled = count(db, QStringLiteral("SELECT COUNT(*) FROM messages"));
    for (const auto &s : steps)
        MailStore::runMigration(db, s, account, progress, never);
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM messages")) == settled,
          QStringLiteral("running them a second time changes nothing"));
    check(count(db, QStringLiteral(
              "SELECT COUNT(*) FROM messages WHERE folder LIKE '%1%%1%'").arg(prefix)) == 0,
          QStringLiteral("…in particular the account prefix is not applied twice"));

    // --- an adoption interrupted, with sync writing meanwhile ---------------

    out() << "adoption conflicts" << Qt::endl;

    // The deferred adoption no longer runs before the account can connect, so
    // a scoped row can land (fresh from the server) while its unscoped twin is
    // still waiting. Renaming the twin then collides with the (folder, uid)
    // primary key — and a collision that aborts the step aborts it on every
    // later launch too, because the scoped row is not going anywhere. The
    // migration must drop the unscoped copy instead: the scoped one is what
    // the server just said.
    exec(db, QStringLiteral("DELETE FROM meta_flags WHERE flag = 'legacy_adopt1'"));
    message(QStringLiteral("INBOX"), 7, QStringLiteral("stale unscoped copy"), recent,
            QString());
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral(
            "INSERT INTO messages (folder, uid, subject, sender, date)"
            " VALUES (?, 7, 'fresh scoped copy', 'someone@example.com', ?)"));
        q.addBindValue(prefix + QStringLiteral("INBOX"));
        q.addBindValue(recent);
        q.exec();
    }
    // And one unscoped row with no scoped twin, which must still be renamed.
    message(QStringLiteral("Archive"), 8, QStringLiteral("plain unscoped"), recent, QString());

    const MailStore::Migration adopt{QStringLiteral("legacy_adopt1"),
                                     QStringLiteral("Claiming cached mail for this account")};
    MailStore::runMigration(db, adopt, account, progress, never);

    check(count(db, QStringLiteral(
              "SELECT COUNT(*) FROM meta_flags WHERE flag = 'legacy_adopt1'")) == 1,
          QStringLiteral("an adoption meeting a synced duplicate still completes"));
    check(count(db, QStringLiteral("SELECT COUNT(*) FROM messages WHERE uid = 7")) == 1,
          QStringLiteral("…keeping exactly one copy of the duplicated message"));
    check(count(db, QStringLiteral(
              "SELECT subject = 'fresh scoped copy' FROM messages WHERE uid = 7")) == 1,
          QStringLiteral("…the freshly synced one, not the stale unscoped twin"));
    check(count(db, QStringLiteral(
              "SELECT COUNT(*) FROM messages WHERE uid = 8"
              " AND instr(folder, char(31)) > 0")) == 1,
          QStringLiteral("…while an unscoped row with no twin is still renamed"));

    // --- cancellation -------------------------------------------------------

    out() << "cancellation" << Qt::endl;

    // A step stopped part-way must not record itself done, or the work it did
    // not finish would never be picked up again.
    exec(db, QStringLiteral("DELETE FROM meta_flags WHERE flag = 'attach_backfill'"));
    exec(db, QStringLiteral("UPDATE messages SET attach = 0"));
    const MailStore::Migration backfill{QStringLiteral("attach_backfill"),
                                        QStringLiteral("Finding attachments in cached mail")};
    MailStore::runMigration(db, backfill, account, progress, [] { return true; });
    check(count(db, QStringLiteral(
              "SELECT COUNT(*) FROM meta_flags WHERE flag = 'attach_backfill'")) == 0,
          QStringLiteral("a cancelled step does not record itself done"));
    check(!store.pendingMigrations(account).isEmpty(),
          QStringLiteral("…so the next launch is offered it again"));
    MailStore::runMigration(db, backfill, account, progress, never);
    check(count(db, QStringLiteral("SELECT attach FROM messages WHERE uid = 2")) == 1,
          QStringLiteral("…and the rerun finishes the work"));
    check(store.pendingMigrations(account).isEmpty(),
          QStringLiteral("…and settles the cache"));

    db.close();
    db = QSqlDatabase();
    QSqlDatabase::removeDatabase(QStringLiteral("migrationtest"));

    out() << (failures == 0 ? QStringLiteral("all migration checks passed")
                            : QStringLiteral("%1 check(s) FAILED").arg(failures))
          << Qt::endl;
    return failures == 0 ? 0 : 1;
}
