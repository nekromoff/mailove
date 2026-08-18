// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * The outbox — the storage half of durable sending (doc/OUTBOX_ROADMAP.md).
 *
 * What is checked here is everything that can be checked without a server:
 * that a queued send survives a round trip byte-exact, that rows go out in the
 * order they were queued, the state machine of a failing row (transient
 * backoff vs. permanent failure), the undo-send hold, startup recovery of a
 * row a killed process left mid-send, and account scoping. The drain loop
 * itself needs a backend to answer it and lives in MailClient.
 *
 * Order matters here for the same reason as the journal: AUTOINCREMENT is
 * what keeps a reused rowid from quietly resending mail out of order.
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
#include <QStandardPaths>
#include <QTextStream>

static int failures = 0;

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

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("mailove-outboxtest"));
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-outboxtest"));
    QStandardPaths::setTestModeEnabled(true);

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty() || !dir.contains(QLatin1String("mailove-outboxtest"))) {
        qWarning() << "refusing to run: test data location is not isolated:" << dir;
        return 2;
    }
    QDir(dir).removeRecursively();

    MailStore store;
    if (!store.open()) {
        qWarning() << "cannot open test store";
        return 2;
    }
    const QString account = QStringLiteral("tester@example.net");
    const QString other = QStringLiteral("someone@example.org");
    store.setAccountKey(account);
    const qint64 now = QDateTime::currentSecsSinceEpoch();

    const auto makeRow = [](const QByteArray &wire, const QStringList &envelope) {
        MailStore::OutboxMessage msg;
        msg.wire = wire;
        msg.envelope = envelope;
        msg.sender = QStringLiteral("tester@example.net");
        msg.subject = QStringLiteral("Hello");
        return msg;
    };

    // --- enqueue and read back ----------------------------------------------

    out() << "outbox: queueing" << Qt::endl;
    const QByteArray wire =
        "From: tester@example.net\r\nTo: a@example.com\r\n\r\nbody bytes\r\n";
    const qint64 first = store.enqueueOutbox(
        makeRow(wire, {QStringLiteral("a@example.com"), QStringLiteral("b@example.com")}));
    check(first > 0, QStringLiteral("a queued send gets an id"));
    const qint64 second =
        store.enqueueOutbox(makeRow("second", {QStringLiteral("c@example.com")}));
    check(second > first, QStringLiteral("the next one gets a higher id"));

    const auto rows = store.outboxMessages(account);
    check(rows.size() == 2, QStringLiteral("both come back"));
    check(rows.at(0).id == first && rows.at(1).id == second,
          QStringLiteral("…in the order they were queued"));
    check(rows.at(0).wire == wire,
          QStringLiteral("the wire bytes survive byte-exact"));
    check(rows.at(0).envelope
              == QStringList({QStringLiteral("a@example.com"), QStringLiteral("b@example.com")}),
          QStringLiteral("the envelope survives as a list"));
    check(rows.at(0).created > 0, QStringLiteral("the queue time is stamped"));
    check(rows.at(0).state == MailStore::Queued, QStringLiteral("a new row is Queued"));
    check(store.outboxCount(account) == 2, QStringLiteral("the badge counts both"));

    // --- send order and the undo-send hold ----------------------------------

    out() << "outbox: what is due" << Qt::endl;
    auto next = store.nextOutboxMessage(account, now);
    check(next.id == first, QStringLiteral("the oldest row goes first"));

    MailStore::OutboxMessage held = makeRow("held", {QStringLiteral("d@example.com")});
    held.nextTry = now + 3600; // the undo-send hold: not due yet
    const qint64 third = store.enqueueOutbox(held);
    store.dropOutboxMessage(first);
    store.dropOutboxMessage(second);
    check(store.nextOutboxMessage(account, now).id == 0,
          QStringLiteral("a held row is not due before its time"));
    check(store.nextOutboxMessage(account, now + 3601).id == third,
          QStringLiteral("…and is due after it"));
    check(store.outboxNextTry(account) == now + 3600,
          QStringLiteral("the wake-up time is the hold's end"));

    // --- the state machine ---------------------------------------------------

    out() << "outbox: failing" << Qt::endl;
    store.markOutboxSending(third);
    check(store.nextOutboxMessage(account, now + 3601).id == 0,
          QStringLiteral("a Sending row is never handed out again"));

    // Transient: back to the queue with a later nextTry, one attempt spent.
    store.recordOutboxFailure(third, QStringLiteral("451 try later"), now + 60, false);
    auto row = store.outboxMessage(third);
    check(row.state == MailStore::Queued && row.attempts == 1
              && row.nextTry == now + 60
              && row.lastError == QStringLiteral("451 try later"),
          QStringLiteral("a transient failure re-queues with backoff"));

    // Permanent: failed outright, no nextTry can bring it back.
    store.markOutboxSending(third);
    store.recordOutboxFailure(third, QStringLiteral("550 no such user"), 0, true);
    row = store.outboxMessage(third);
    check(row.state == MailStore::Failed && row.attempts == 2,
          QStringLiteral("a permanent rejection fails the row"));
    check(store.nextOutboxMessage(account, now + 7200).id == 0,
          QStringLiteral("a Failed row is never retried on its own"));
    check(store.outboxCount(account) == 1,
          QStringLiteral("…but still counts: it has not gone out"));

    // Retry now: a clean slate.
    store.reviveOutboxMessage(third);
    row = store.outboxMessage(third);
    check(row.state == MailStore::Queued && row.attempts == 0 && row.nextTry == 0
              && row.lastError.isEmpty(),
          QStringLiteral("revive gives a clean slate"));

    // A deferred row (connection died) spends nothing.
    store.markOutboxSending(third);
    store.deferOutboxMessage(third);
    row = store.outboxMessage(third);
    check(row.state == MailStore::Queued && row.attempts == 0,
          QStringLiteral("a deferred row spends no attempt"));

    // --- startup recovery ----------------------------------------------------

    out() << "outbox: recovery" << Qt::endl;
    store.markOutboxSending(third);
    const QString note = QStringLiteral("may already have been sent");
    check(store.recoverStaleOutbox(account, note) == 1,
          QStringLiteral("a row a killed process left mid-send is found"));
    row = store.outboxMessage(third);
    check(row.state == MailStore::Failed && row.lastError == note,
          QStringLiteral("…and fails with the note, never silently resent"));
    check(store.recoverStaleOutbox(account, note) == 0,
          QStringLiteral("recovery is idempotent"));

    // --- account scoping ------------------------------------------------------

    out() << "outbox: scoping" << Qt::endl;
    MailStore::OutboxMessage theirs = makeRow("theirs", {QStringLiteral("e@example.com")});
    theirs.account = other;
    store.enqueueOutbox(theirs);
    check(store.outboxCount(other) == 1 && store.outboxCount(account) == 1,
          QStringLiteral("accounts see only their own rows"));
    check(store.nextOutboxMessage(account, now + 7200).id == 0,
          QStringLiteral("one account's drain never picks up another's mail"));
    store.dropAccountOutbox(other);
    check(store.outboxCount(other) == 0,
          QStringLiteral("removing an account takes its queue with it"));
    check(store.outboxCount(account) == 1,
          QStringLiteral("…and nobody else's"));

    out() << (failures == 0 ? QStringLiteral("all checks passed")
                            : QStringLiteral("%1 check(s) FAILED").arg(failures))
          << Qt::endl;
    return failures == 0 ? 0 : 1;
}
