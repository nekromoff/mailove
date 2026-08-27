// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * The body writer's lifecycle across a pause — the one background writer that
 * every fetched message body goes through.
 *
 * It exists because the writer died silently. Both pause paths (a cache
 * migration run, a disk reclaim) set the stop flag and deliberately do *not*
 * join the thread: a batch mid-statement can run for seconds, and the GUI
 * thread has to keep serving the event loop or the progress modal never
 * paints. That leaves a finished-but-non-null QThread behind, and the restart
 * in queueBodyWrite() was gated on the pointer being null — so it never fired.
 * The stop flag stayed set, the dead thread stayed non-null, and for the rest
 * of the session every fetched body queued up and was never written. Nothing
 * failed loudly; the cache simply stopped filling, and the reading pane went
 * back to the network for messages that should have been on disk.
 *
 * The bug was invisible for as long as pendingMigrations() came back empty on
 * a settled cache, because then the pause never ran at all. Adding one new
 * migration re-armed it. That is precisely the shape of thing a test has to
 * hold down: not the fix, but the invariant the fix restores — a body handed
 * to queueBodyWrite() reaches the cache, whatever the writer has been through.
 *
 * Runs against a throwaway database in its own AppDataLocation — set via
 * QStandardPaths::setTestModeEnabled() plus a test-only application name — so
 * it can never open, let alone write to, the real mail cache.
 */

#include "../src/maintenancescheduler.h"
#include "../src/attachmentstore.h"
#include "../src/mailstore.h"

#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QSqlQuery>
#include <QStandardPaths>
#include <QTextStream>
#include <QThread>
#include <QTimer>

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

/// Spins the event loop until \a done or the deadline passes. Every assertion
/// here is about work that lands on another thread, so "did it happen" is
/// always "did it happen *yet*" — and a bounded wait is what turns the old bug
/// (a body that never lands, ever) into a failing test rather than a hang.
static bool waitFor(const std::function<bool()> &done, int timeoutMs = 15000)
{
    QDeadlineTimer deadline(timeoutMs);
    while (!done()) {
        if (deadline.hasExpired())
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(5);
    }
    return true;
}

/// A minimal RFC 5322 message, distinct per \a uid so a body read back can be
/// told apart from its neighbours — the failure this is guarding against once
/// showed up as several messages sharing one body.
static QByteArray messageFor(qint64 uid)
{
    return "Subject: body " + QByteArray::number(uid) + "\r\n"
        "From: sender@example.net\r\n"
        "Message-ID: <" + QByteArray::number(uid) + "@example.net>\r\n"
        "\r\nThis is the body of message " + QByteArray::number(uid) + ".\r\n";
}

/// A message carrying an attachment of \a base64Chars base64 characters —
/// three decoded bytes per four of them, which is what the externalisation
/// threshold is measured against.
static QByteArray messageWithAttachment(qint64 uid, int base64Chars)
{
    return "Subject: attached " + QByteArray::number(uid) + "\r\n"
        "From: sender@example.net\r\n"
        "Message-ID: <att" + QByteArray::number(uid) + "@example.net>\r\n"
        "Content-Type: multipart/mixed; boundary=b\r\n"
        "\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        "--b\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"payload.bin\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        + QByteArray(base64Chars, 'A') + "\r\n--b--\r\n";
}

/// Base64 characters whose decoded size clears AttachmentStore's threshold with
/// room to spare. Derived from the setting rather than hardcoded, so raising
/// the threshold does not quietly turn this test into a no-op.
static int base64CharsAboveThreshold()
{
    // Four base64 characters per three decoded bytes, aimed at twice the
    // threshold so the margin cannot be eaten by rounding.
    const int bytes = AttachmentStore::externalizeThreshold() * 2 + 1024;
    return (((bytes * 4) / 3) + 3) & ~3;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // Both together are what redirect AppDataLocation away from the real cache.
    QCoreApplication::setApplicationName(QStringLiteral("mailove-bodywritertest"));
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-bodywritertest"));
    QStandardPaths::setTestModeEnabled(true);

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty() || !dir.contains(QLatin1String("mailove-bodywritertest"))) {
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
    store.setAccountKey(account);
    const QString folder = QStringLiteral("INBOX");
    const QString scoped = store.scopedKey(folder);

    MaintenanceScheduler jobs(
        store,
        // The index text a real client derives from the parsed message. The
        // writer only passes it through, so a stub is honest here.
        [](KMime::Message *) { return QStringLiteral("indexed"); },
        [account] { return QStringList{account}; });

    const auto queue = [&](qint64 uid, const QByteArray &raw) {
        jobs.queueBodyWrite({scoped, uid, raw, QStringLiteral("indexed"), {}});
    };

    // --- the ordinary path --------------------------------------------------

    out() << "writing" << Qt::endl;

    queue(1, messageFor(1));
    check(waitFor([&] { return !store.cachedBody(folder, 1).isEmpty(); }),
          QStringLiteral("a queued body reaches the cache"));
    check(store.cachedBody(folder, 1).contains("body of message 1"),
          QStringLiteral("…as its own body, not another message's"));

    // Several at once go through one batch. Distinct bodies, because the
    // symptom that started this was messages sharing one.
    for (qint64 uid = 2; uid <= 6; ++uid)
        queue(uid, messageFor(uid));
    check(waitFor([&] {
              for (qint64 uid = 2; uid <= 6; ++uid) {
                  if (store.cachedBody(folder, uid).isEmpty())
                      return false;
              }
              return true;
          }),
          QStringLiteral("a burst of bodies all reach the cache"));
    bool distinct = true;
    for (qint64 uid = 2; uid <= 6; ++uid) {
        if (!store.cachedBody(folder, uid)
                 .contains("body of message " + QByteArray::number(uid))) {
            distinct = false;
        }
    }
    check(distinct, QStringLiteral("…each under its own uid, none sharing a body"));

    // --- across a migration pause -------------------------------------------

    out() << "across a migration pause" << Qt::endl;

    // The pause only runs when there is a step to run, which on a settled cache
    // there is not — exactly why this went unnoticed. Force one back to
    // pending, the way a new migration does on an upgraded install.
    {
        QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("bodywritertest"));
        if (!db.isOpen()) {
            qWarning() << "cannot open the worker connection";
            return 2;
        }
        QSqlQuery q(db);
        q.exec(QStringLiteral("DELETE FROM meta_flags WHERE flag = 'attach_backfill'"));
        db.close();
        db = QSqlDatabase();
        QSqlDatabase::removeDatabase(QStringLiteral("bodywritertest"));
    }
    check(!store.pendingMigrations(account).isEmpty(),
          QStringLiteral("a step is pending, so the run really does pause the writers"));

    bool migrationsDone = false;
    QObject::connect(&jobs, &MaintenanceScheduler::cacheMigrationsFinished,
                     &app, [&migrationsDone] { migrationsDone = true; });
    jobs.startCacheMigrations(account, [](const QString &) { return false; },
                              // No junk seed in this test: the parser belongs to
                              // MailClient, and the step is covered by
                              // migrationtest. Without one it stays pending,
                              // which is its documented behaviour.
                              {});
    check(waitFor([&] { return migrationsDone; }),
          QStringLiteral("the migration run finishes"));

    // The regression. Before the fix the writer was dead here — non-null, so
    // queueBodyWrite() would not restart it, and stopped, so the old thread had
    // already left its loop. This body would never have been written, and the
    // wait below would have run out.
    queue(7, messageFor(7));
    check(waitFor([&] { return !store.cachedBody(folder, 7).isEmpty(); }),
          QStringLiteral("a body queued after the pause still reaches the cache"));
    check(store.cachedBody(folder, 7).contains("body of message 7"),
          QStringLiteral("…intact, and as its own body"));

    // --- queued *during* the pause ------------------------------------------

    out() << "queued during a pause" << Qt::endl;

    // The other half: a body that arrives while the writer is stopped has
    // nothing left to drain it, and waiting for the next fetch to revive the
    // writer would strand it for as long as no new mail came in. The restore
    // path has to revive the writer itself.
    {
        QSqlDatabase db = MailStore::openWorkerConnection(QStringLiteral("bodywritertest2"));
        QSqlQuery q(db);
        q.exec(QStringLiteral("DELETE FROM meta_flags WHERE flag = 'attach_backfill'"));
        db.close();
        db = QSqlDatabase();
        QSqlDatabase::removeDatabase(QStringLiteral("bodywritertest2"));
    }
    migrationsDone = false;
    jobs.startCacheMigrations(account, [](const QString &) { return false; }, {});
    // Straight after the pause request, before the run reports finished: this
    // is the window the body has to survive.
    queue(8, messageFor(8));
    check(waitFor([&] { return migrationsDone; }),
          QStringLiteral("the second migration run finishes"));
    check(waitFor([&] { return !store.cachedBody(folder, 8).isEmpty(); }),
          QStringLiteral("a body queued during the pause is not stranded"));

    // --- attachments are lifted out -----------------------------------------

    out() << "attachment externalisation" << Qt::endl;

    // Whichever path handled it — the loop's batch or the flush on the way out
    // — a body with a payload over the threshold must reach the cache as a stub
    // plus part refs. The flush used to skip this pass entirely, which only ever
    // ran at quit until the migration pause made it a per-launch path.
    const int big = base64CharsAboveThreshold();
    const QByteArray withPayload = messageWithAttachment(9, big);
    queue(9, withPayload);
    check(waitFor([&] { return !store.cachedBody(folder, 9).isEmpty(); }),
          QStringLiteral("a body with an attachment reaches the cache"));
    check(waitFor([&] { return !store.partsFor(folder, 9).isEmpty(); }),
          QStringLiteral("…with its payload lifted into the file store"));
    check(store.cachedBody(folder, 9).size() < withPayload.size(),
          QStringLiteral("…leaving a stub smaller than what was handed over"));

    // And the other side of the same rule: a payload below the threshold is
    // deliberately left inline, because a file of its own would cost more than
    // it saves. Asserted so that "no parts" is only ever read as a decision.
    const QByteArray smallPayload = messageWithAttachment(12, 64);
    queue(12, smallPayload);
    check(waitFor([&] { return !store.cachedBody(folder, 12).isEmpty(); }),
          QStringLiteral("a body with a small attachment reaches the cache"));
    check(store.partsFor(folder, 12).isEmpty(),
          QStringLiteral("…with its payload left inline, under the threshold"));

    // --- and the stop still flushes -----------------------------------------

    out() << "stopping" << Qt::endl;

    queue(10, messageFor(10));
    // Joins the thread, flushing whatever it still holds — a quit must not lose
    // a fetched body.
    jobs.stopBodyWriter();
    check(!store.cachedBody(folder, 10).isEmpty(),
          QStringLiteral("stopping the writer flushes what it still holds"));

    // And after a full stop it comes back, which is the same reaping path the
    // pause depends on.
    queue(11, messageFor(11));
    check(waitFor([&] { return !store.cachedBody(folder, 11).isEmpty(); }),
          QStringLiteral("…and a write after a full stop revives it"));

    jobs.stopBodyWriter();

    out() << (failures == 0 ? QStringLiteral("all body writer checks passed")
                            : QStringLiteral("%1 check(s) FAILED").arg(failures))
          << Qt::endl;
    return failures == 0 ? 0 : 1;
}
