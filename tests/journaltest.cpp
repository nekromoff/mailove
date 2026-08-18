// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * The journal and soft delete — the storage half of the offline-first write
 * path (doc/OFFLINE_FIRST_ROADMAP.md).
 *
 * What is checked here is everything that can be checked without a server:
 * replay order, the bookkeeping of a failing op, path and id rewriting after
 * the world moves under a queued change, the age cap, and that a hidden row is
 * invisible to every read that shows or counts mail. What is deliberately not
 * here is the replay loop itself, which needs a backend to answer it —
 * jmapbackendtest shows the shape that would take.
 *
 * The order property is the one worth being paranoid about. Every other rule
 * in the design assumes ops are replayed in the order they were made; SQLite
 * reuses rowids after a delete, so a plain INTEGER PRIMARY KEY would quietly
 * hand a new op an id lower than one already waiting. That is a data-loss bug
 * that would show up as "sometimes my changes come out wrong", which is
 * exactly the kind nobody can reproduce.
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

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // Both together are what redirect AppDataLocation away from the real cache.
    QCoreApplication::setApplicationName(QStringLiteral("mailove-journaltest"));
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-journaltest"));
    QStandardPaths::setTestModeEnabled(true);

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty() || !dir.contains(QLatin1String("mailove-journaltest"))) {
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
    const QString other = QStringLiteral("someone@example.org");
    store.setAccountKey(account);

    const auto flagOp = [&](const QString &folder, const QStringList &ids,
                            const QList<qint64> &uids, bool seen) {
        MailStore::JournalOp op;
        op.op = QStringLiteral("flag");
        op.folder = folder;
        op.remoteIds = ids;
        op.uids = uids;
        (seen ? op.flagsAdd : op.flagsDel).append(QStringLiteral("seen"));
        return op;
    };

    // --- appending and reading back ----------------------------------------

    out() << "journal: appending" << Qt::endl;
    const qint64 first =
        store.appendJournalOp(flagOp(QStringLiteral("INBOX"), {"11"}, {11}, true));
    check(first > 0, QStringLiteral("an appended op gets an id"));

    MailStore::JournalOp move;
    move.op = QStringLiteral("move");
    move.folder = QStringLiteral("INBOX");
    move.target = QStringLiteral("Archive");
    move.remoteIds = QStringList{"12", "13"};
    move.uids = QList<qint64>{12, 13};
    const qint64 second = store.appendJournalOp(move);
    check(second > first, QStringLiteral("the next op gets a higher id"));

    QList<MailStore::JournalOp> ops = store.journalOps(account);
    check(ops.size() == 2, QStringLiteral("both come back live"));
    check(ops.at(0).id == first && ops.at(1).id == second,
          QStringLiteral("…in the order they were made"));
    check(ops.at(0).flagsAdd == QStringList{QStringLiteral("seen")}
              && ops.at(0).flagsDel.isEmpty(),
          QStringLiteral("flag lists survive the round trip"));
    check(ops.at(1).remoteIds == QStringList({"12", "13"})
              && ops.at(1).uids == QList<qint64>({12, 13}),
          QStringLiteral("ids and uids are kept as two separate names"));
    check(ops.at(1).target == QStringLiteral("Archive"),
          QStringLiteral("a move remembers where it was going"));
    check(ops.at(0).queuedAt > 0, QStringLiteral("the queue time is stamped"));

    // The property the whole design rests on. A bare INTEGER PRIMARY KEY would
    // reuse the id of a deleted row here and file the new op *before* one that
    // is still waiting.
    out() << "journal: order after a delete" << Qt::endl;
    const qint64 doomed =
        store.appendJournalOp(flagOp(QStringLiteral("INBOX"), {"14"}, {14}, true));
    store.dropJournalOp(doomed);
    const qint64 afterDelete =
        store.appendJournalOp(flagOp(QStringLiteral("INBOX"), {"15"}, {15}, true));
    check(afterDelete > doomed, QStringLiteral("ids are never reused (AUTOINCREMENT)"));
    ops = store.journalOps(account);
    check(ops.size() == 3 && ops.last().id == afterDelete,
          QStringLiteral("…so the newest op stays last in the queue"));

    // --- scoping -----------------------------------------------------------

    out() << "journal: accounts" << Qt::endl;
    MailStore::JournalOp foreign =
        flagOp(QStringLiteral("INBOX"), {"99"}, {99}, true);
    foreign.account = other;
    store.appendJournalOp(foreign);
    check(store.journalOps(account).size() == 3,
          QStringLiteral("another account's ops stay out of this queue"));
    check(store.journalOps(other).size() == 1, QStringLiteral("…and are in its own"));
    check(store.journalOpCount(account) == 3, QStringLiteral("the count agrees"));

    // --- folders with unreplayed work --------------------------------------

    out() << "journal: which folders are busy" << Qt::endl;
    const QSet<QString> busy = store.journalFolders(account);
    check(busy.contains(QStringLiteral("INBOX")), QStringLiteral("a source folder is busy"));
    check(busy.contains(QStringLiteral("Archive")),
          QStringLiteral("a move's destination is busy too — the mail is not there yet"));
    check(!busy.contains(QStringLiteral("Sent")),
          QStringLiteral("an untouched folder is free to sync"));

    // --- failing, retiring, reviving ---------------------------------------

    out() << "journal: failure bookkeeping" << Qt::endl;
    store.recordJournalFailure(first, QStringLiteral("server said no"));
    ops = store.journalOps(account);
    check(ops.at(0).tries == 1, QStringLiteral("a failed attempt is counted"));
    check(ops.at(0).lastError == QStringLiteral("server said no"),
          QStringLiteral("…and its reason kept"));
    check(!ops.at(0).retired, QStringLiteral("…without giving up on it"));

    store.retireJournalOp(first, QStringLiteral("mailbox does not exist"));
    check(store.journalOps(account).size() == 2,
          QStringLiteral("a retired op leaves the replay queue"));
    check(store.retiredJournalOps(account).size() == 1,
          QStringLiteral("…and appears in the failed list instead"));
    check(store.journalOpCount(account, /*retired=*/true) == 1,
          QStringLiteral("…where the count finds it"));
    check(store.retiredJournalOps(account).first().lastError
              == QStringLiteral("mailbox does not exist"),
          QStringLiteral("…carrying the reason it was given up on"));
    check(!store.journalFolders(account).contains(QStringLiteral("Sent")),
          QStringLiteral("a retired op no longer blocks its folder from syncing"));

    // Retiring without a reason must not blank the one already recorded — the
    // dependent-retire cascade passes the failure that stopped the chain, and
    // an empty string there would erase what the reader needs.
    store.retireJournalOp(first, QString());
    check(store.retiredJournalOps(account).first().lastError
              == QStringLiteral("mailbox does not exist"),
          QStringLiteral("retiring with no reason keeps the recorded one"));

    store.reviveJournalOp(first);
    ops = store.journalOps(account);
    check(ops.size() == 3 && ops.at(0).id == first,
          QStringLiteral("Retry puts it back at its own place in the order"));
    check(ops.at(0).tries == 0 && ops.at(0).lastError.isEmpty(),
          QStringLiteral("…with a clean slate"));

    // --- the age cap -------------------------------------------------------

    out() << "journal: the age cap" << Qt::endl;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    MailStore::JournalOp old = flagOp(QStringLiteral("Sent"), {"7"}, {7}, true);
    old.queuedAt = now - 30 * 86400;
    const qint64 oldId = store.appendJournalOp(old);
    store.retireJournalOp(second, QStringLiteral("stopped"));
    const QList<MailStore::JournalOp> stale =
        store.takeStaleJournalOps(account, now - 7 * 86400);
    check(stale.size() == 1 && stale.first().id == oldId,
          QStringLiteral("an op past the cap is taken out"));
    check(store.retiredJournalOps(account).size() == 1,
          QStringLiteral("…while a retired one is exempt: it is the user's to read"));
    check(store.journalOps(account).size() == 2,
          QStringLiteral("…and the recent ones are untouched"));
    store.reviveJournalOp(second); // put the move back for the rewrites below

    // --- rewriting after a folder rename -----------------------------------

    out() << "journal: following a renamed folder" << Qt::endl;
    const qint64 renameId = store.appendJournalOp([&] {
        MailStore::JournalOp op;
        op.op = QStringLiteral("folder_rename");
        op.folder = QStringLiteral("Work");
        op.target = QStringLiteral("Archive/Work");
        return op;
    }());
    store.appendJournalOp(flagOp(QStringLiteral("Work"), {"21"}, {21}, true));
    store.appendJournalOp(flagOp(QStringLiteral("Work/2025"), {"22"}, {22}, true));
    store.appendJournalOp(flagOp(QStringLiteral("Workshop"), {"23"}, {23}, true));
    store.rewriteJournalFolder(account, renameId, QStringLiteral("Work"),
                               QStringLiteral("Archive/Work"), QLatin1Char('/'));
    QSet<QString> paths;
    for (const MailStore::JournalOp &op : store.journalOps(account))
        paths.insert(op.folder);
    check(paths.contains(QStringLiteral("Archive/Work")),
          QStringLiteral("a later op follows the folder to its new path"));
    check(paths.contains(QStringLiteral("Archive/Work/2025")),
          QStringLiteral("…and so does one in its subtree"));
    check(paths.contains(QStringLiteral("Workshop")),
          QStringLiteral("…while a folder that merely starts the same is left alone"));
    check(paths.contains(QStringLiteral("Work")),
          QStringLiteral("…and the rename op itself still names where it starts"));

    // --- rewriting after a move --------------------------------------------

    out() << "journal: following moved messages" << Qt::endl;
    const qint64 moveId = store.appendJournalOp([&] {
        MailStore::JournalOp op;
        op.op = QStringLiteral("move");
        op.folder = QStringLiteral("Inbox2");
        op.target = QStringLiteral("Done");
        op.remoteIds = QStringList{"31", "32"};
        op.uids = QList<qint64>{31, 32};
        return op;
    }());
    const qint64 followerId =
        store.appendJournalOp(flagOp(QStringLiteral("Inbox2"), {"31"}, {31}, true));
    const qint64 orphanId =
        store.appendJournalOp(flagOp(QStringLiteral("Inbox2"), {"32"}, {32}, true));

    QHash<QString, MailStore::MovedMessage> moved;
    moved.insert(QStringLiteral("31"), {QStringLiteral("501"), 501});
    QList<MailStore::JournalOp> unnameable = store.rewriteJournalIds(
        account, moveId, QStringLiteral("Inbox2"), QStringLiteral("Done"), moved);
    check(unnameable.size() == 1 && unnameable.first().id == orphanId,
          QStringLiteral("a message the server did not rename cannot be addressed again"));
    for (const MailStore::JournalOp &op : store.journalOps(account)) {
        if (op.id != followerId)
            continue;
        check(op.folder == QStringLiteral("Done"),
              QStringLiteral("a later op follows the message to the new folder"));
        check(op.remoteIds == QStringList{QStringLiteral("501")},
              QStringLiteral("…under the name the destination gave it"));
        check(op.uids == QList<qint64>{501},
              QStringLiteral("…and the cache's name for it moves too"));
    }

    // --- discarding --------------------------------------------------------

    out() << "journal: discarding" << Qt::endl;
    store.clearRetiredJournalOps(account);
    check(store.retiredJournalOps(account).isEmpty(),
          QStringLiteral("Discard all clears the failed list"));
    check(!store.journalOps(account).isEmpty(),
          QStringLiteral("…and leaves the queue alone"));
    store.dropAccountJournal(account);
    check(store.journalOps(account).isEmpty(),
          QStringLiteral("removing an account takes its queue with it"));
    check(store.journalOps(other).size() == 1,
          QStringLiteral("…and nobody else's"));

    // --- soft delete -------------------------------------------------------
    //
    // The rule is one sentence — a hidden row is invisible to everything that
    // shows or counts mail — but it has to hold in every reader separately,
    // and each of those is its own SQL statement.

    out() << "soft delete: hidden rows stay out of every read" << Qt::endl;
    const QString folder = QStringLiteral("INBOX");
    QList<MessageListModel::Header> headers;
    for (int i = 1; i <= 4; ++i) {
        MessageListModel::Header h;
        h.uid = 100 + i;
        h.subject = QStringLiteral("message %1").arg(i);
        h.from = QStringLiteral("someone@example.com");
        h.date = QDateTime::currentDateTime().addSecs(-i * 60);
        h.seen = false;
        headers.append(h);
    }
    store.storeHeaders(folder, headers);
    check(store.cachedHeaderCount(folder) == 4, QStringLiteral("four messages cached"));

    store.softDeleteMessages(folder, {102, 103});
    check(store.cachedHeaderCount(folder) == 2,
          QStringLiteral("the header count skips hidden rows"));
    check(store.cachedHeaders(folder).size() == 2,
          QStringLiteral("the folder listing skips them"));
    check(store.unseenMessages(folder).size() == 2,
          QStringLiteral("\"mark all read\" does not name them"));
    check(store.missingBodyCount(folder) == 2,
          QStringLiteral("the body backfill does not queue them"));
    check(store.uidsWithoutBody(folder, 10).size() == 2,
          QStringLiteral("…nor list them as work"));
    check(store.messagesOlderThan(folder, QDateTime::currentSecsSinceEpoch()).size() == 2,
          QStringLiteral("the spam retention sweep leaves them alone"));

    QSqlDatabase probe = MailStore::openWorkerConnection(QStringLiteral("journaltest"));
    if (probe.isOpen()) {
        const QHash<QString, int> unread = MailStore::unreadCountsOn(probe, account);
        check(unread.value(folder) == 2,
              QStringLiteral("the sidebar's unread pill counts only visible mail"));
    }

    out() << "soft delete: the reconcile view" << Qt::endl;
    const QHash<QString, QList<qint64>> hidden = store.softDeletedIn(account);
    check(hidden.value(folder).size() == 2,
          QStringLiteral("hidden rows can be found again by folder"));
    check(!hidden.contains(QStringLiteral("Archive")),
          QStringLiteral("…and a folder with none is not listed"));

    out() << "soft delete: restoring and confirming" << Qt::endl;
    store.restoreSoftDeleted(folder, {102});
    check(store.cachedHeaderCount(folder) == 3,
          QStringLiteral("a rolled-back delete brings the message back"));
    check(store.softDeletedIn(account).value(folder) == QList<qint64>{103},
          QStringLiteral("…and only that one"));

    // A merge must not resurrect what the user has deleted: the server still
    // reports the message, because it has not been told yet.
    MessageListModel::Header again;
    again.uid = 103;
    again.subject = QStringLiteral("message 3");
    again.from = QStringLiteral("someone@example.com");
    again.date = QDateTime::currentDateTime();
    store.storeHeaders(folder, {again});
    check(store.cachedHeaderCount(folder) == 3,
          QStringLiteral("a header sync does not un-hide a pending delete"));

    store.removeMessages(folder, {103});
    check(store.softDeletedIn(account).isEmpty(),
          QStringLiteral("confirming the delete is what finally removes the row"));

    if (probe.isOpen()) {
        probe.close();
        probe = QSqlDatabase();
        QSqlDatabase::removeDatabase(QStringLiteral("journaltest"));
    }

    out() << (failures == 0 ? QStringLiteral("all journal checks passed")
                            : QStringLiteral("%1 check(s) FAILED").arg(failures))
          << Qt::endl;
    return failures == 0 ? 0 : 1;
}
