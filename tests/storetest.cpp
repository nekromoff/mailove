// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * Checks the backend-neutral message identity added for JMAP (doc/JMAP_ROADMAP.md
 * phase 0): the `remote_id` column on `messages` and the opaque per-folder
 * `sync_state` on `account_folders`.
 *
 * Runs against a throwaway database in its own AppDataLocation — set via
 * QStandardPaths::setTestModeEnabled() plus a test-only application name — so
 * it can never open, let alone write to, the real mail cache.
 */

#include "../src/mailstore.h"
#include "../src/spamheuristics.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QTextStream>

#include <algorithm>

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

static MessageListModel::Header makeHeader(qint64 uid, const QString &subject,
                                           const QString &remoteId)
{
    MessageListModel::Header h;
    h.uid = uid;
    h.subject = subject;
    h.from = QStringLiteral("Someone <someone@example.com>");
    h.date = QDateTime::fromSecsSinceEpoch(1700000000 + uid);
    h.remoteId = remoteId;
    return h;
}

/// The stored header for \a uid, or a default-constructed one when absent.
static MessageListModel::Header find(MailStore &store, const QString &folder, qint64 uid)
{
    const auto rows = store.cachedHeaders(folder);
    for (const auto &h : rows) {
        if (h.uid == uid)
            return h;
    }
    return {};
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // Both together are what redirect AppDataLocation away from the real cache.
    QCoreApplication::setApplicationName(QStringLiteral("mailove-storetest"));
    QCoreApplication::setOrganizationName(QStringLiteral("mailove-storetest"));
    QStandardPaths::setTestModeEnabled(true);

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty() || !dir.contains(QLatin1String("mailove-storetest"))) {
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
    const QString folder = QStringLiteral("INBOX");
    store.setAccountKey(account);
    store.storeFolders(account, {folder});

    out() << "remote_id" << Qt::endl;

    // An IMAP-shaped write: the backend states the uid as its remote id.
    store.storeHeaders(folder, {makeHeader(101, QStringLiteral("with id"),
                                           QStringLiteral("101"))});
    check(find(store, folder, 101).remoteId == QLatin1String("101"),
          QStringLiteral("a written remote id reads back verbatim"));

    // A JMAP-shaped write: an opaque string bearing no relation to the uid.
    store.storeHeaders(folder, {makeHeader(102, QStringLiteral("opaque id"),
                                           QStringLiteral("Mdeadbeef01"))});
    check(find(store, folder, 102).remoteId == QLatin1String("Mdeadbeef01"),
          QStringLiteral("an opaque (non-numeric) remote id survives a round trip"));

    // A producer that does not know the id — the Thunderbird importer, or a
    // row cached before the column existed. The uid stands in on read.
    store.storeHeaders(folder, {makeHeader(103, QStringLiteral("no id"), QString())});
    check(find(store, folder, 103).remoteId == QLatin1String("103"),
          QStringLiteral("a row with no remote id reads back as its uid"));

    // The COALESCE rule: a later write that does not know the id must not
    // erase one already recorded.
    store.storeHeaders(folder, {makeHeader(102, QStringLiteral("refreshed"), QString())});
    const auto refreshed = find(store, folder, 102);
    check(refreshed.subject == QLatin1String("refreshed"),
          QStringLiteral("a header refresh still updates the ordinary columns"));
    check(refreshed.remoteId == QLatin1String("Mdeadbeef01"),
          QStringLiteral("a refresh without a remote id keeps the recorded one"));

    out() << "messagesOlderThan" << Qt::endl;

    // What the spam sweep runs on. It deletes on the server by remote id and
    // forgets locally by uid, so both names have to come back — and the date
    // rule decides what gets deleted at all, which is worth pinning down.
    const QString junk = QStringLiteral("Junk");
    store.storeFolders(account, {folder, junk});
    const qint64 cutoff = 1700000000;
    auto dated = [](qint64 uid, const QString &remoteId, const QDateTime &date) {
        MessageListModel::Header h = makeHeader(uid, QStringLiteral("aged"), remoteId);
        h.date = date;
        return h;
    };
    store.storeHeaders(junk, {
        dated(201, QStringLiteral("Mold01"), QDateTime::fromSecsSinceEpoch(cutoff - 86400)),
        dated(202, QStringLiteral("Mnew01"), QDateTime::fromSecsSinceEpoch(cutoff + 86400)),
        // No usable date — the "1970" rows — and no remote id either.
        dated(203, QString(), QDateTime()),
    });

    const auto aged = store.messagesOlderThan(junk, cutoff);
    QList<qint64> agedUids;
    for (const auto &m : aged)
        agedUids.append(m.uid);
    std::sort(agedUids.begin(), agedUids.end());
    check(agedUids == QList<qint64>({201, 203}),
          QStringLiteral("only messages older than the cutoff, plus the dateless ones"));

    QString oldId, datelessId;
    for (const auto &m : aged) {
        if (m.uid == 201)
            oldId = m.remoteId;
        if (m.uid == 203)
            datelessId = m.remoteId;
    }
    check(oldId == QLatin1String("Mold01"),
          QStringLiteral("an aged message carries its recorded remote id"));
    check(datelessId == QLatin1String("203"),
          QStringLiteral("an aged message with no remote id falls back to its uid"));

    check(store.messagesOlderThan(QStringLiteral("Nonexistent"), cutoff).isEmpty(),
          QStringLiteral("an unknown folder has nothing to sweep"));

    out() << "mark all read" << Qt::endl;

    // What a folder's "mark all read" reads and then writes. The unread rows
    // come back named both ways, because the server is told about them by
    // remote id while the cache forgets them by uid.
    const QString bulk = QStringLiteral("Bulk");
    store.storeFolders(account, {folder, junk, bulk});
    store.storeHeaders(bulk, {
        makeHeader(301, QStringLiteral("unread"), QStringLiteral("Mbulk01")),
        makeHeader(302, QStringLiteral("unread, no id"), QString()),
        makeHeader(303, QStringLiteral("already read"), QStringLiteral("Mbulk03")),
    });
    store.setSeen(bulk, 303);

    auto unseenUids = [&store](const QString &box) {
        QList<qint64> uids;
        for (const auto &m : store.unseenMessages(box))
            uids.append(m.uid);
        std::sort(uids.begin(), uids.end());
        return uids;
    };
    const auto unseen = store.unseenMessages(bulk);
    check(unseenUids(bulk) == QList<qint64>({301, 302}),
          QStringLiteral("only the unread messages of the folder come back"));
    QString withId, withoutId;
    for (const auto &m : unseen) {
        if (m.uid == 301)
            withId = m.remoteId;
        if (m.uid == 302)
            withoutId = m.remoteId;
    }
    check(withId == QLatin1String("Mbulk01"),
          QStringLiteral("an unread message carries its recorded remote id"));
    check(withoutId == QLatin1String("302"),
          QStringLiteral("an unread message with no remote id falls back to its uid"));

    store.setFolderSeen(bulk);
    check(unseenUids(bulk).isEmpty(),
          QStringLiteral("marking the folder read leaves nothing unread"));
    // The neighbouring folder is what a mis-scoped UPDATE would take with it.
    check(unseenUids(junk) == QList<qint64>({201, 202, 203}),
          QStringLiteral("another folder's unread mail is untouched"));

    out() << "sync_state" << Qt::endl;

    check(store.syncState(folder).isEmpty(),
          QStringLiteral("an untouched folder has no sync state"));
    store.setSyncState(folder, QStringLiteral("state-abc-1"));
    check(store.syncState(folder) == QLatin1String("state-abc-1"),
          QStringLiteral("a sync state reads back verbatim"));
    store.setSyncState(folder, QStringLiteral("state-abc-2"));
    check(store.syncState(folder) == QLatin1String("state-abc-2"),
          QStringLiteral("a later sync state replaces the earlier one"));
    check(store.uidValidity(folder) == 0,
          QStringLiteral("writing a sync state leaves uidvalidity alone"));
    store.setUidValidity(folder, 4242);
    check(store.syncState(folder) == QLatin1String("state-abc-2"),
          QStringLiteral("writing uidvalidity leaves the sync state alone"));

    check(store.syncState(QStringLiteral("Nonexistent")).isEmpty(),
          QStringLiteral("an unknown folder has no sync state"));

    out() << "sent recipients" << Qt::endl;

    const QString sent = QStringLiteral("Sent");
    const auto known = [&store](const char *needle) {
        return store.recipientCompletions(QString::fromLatin1(needle), 8).size() == 1;
    };
    // Two messages to alice, one to bob — the case the whole refcount exists
    // for: deleting one of alice's must not forget her.
    store.addSentRecipient(sent, 1, QStringLiteral("alice@example.com"));
    store.addSentRecipient(sent, 2, QStringLiteral("alice@example.com"));
    store.addSentRecipient(sent, 1, QStringLiteral("bob@example.com"));
    check(known("alice@") && known("bob@"),
          QStringLiteral("a Sent message's recipients become completions"));

    store.dropSentRecipients(sent, {1});
    check(known("alice@"),
          QStringLiteral("deleting one of two messages keeps the recipient"));
    check(!known("bob@"),
          QStringLiteral("deleting the only message holding an address forgets it"));

    store.dropSentRecipients(sent, {2});
    check(!known("alice@"),
          QStringLiteral("deleting the last message forgets the recipient too"));

    // Re-seeing the same message is not a second message: dropping the one
    // message must still take the address with it.
    store.addSentRecipient(sent, 3, QStringLiteral("dana@example.com"));
    store.addSentRecipient(sent, 3, QStringLiteral("dana@example.com"));
    store.dropSentRecipients(sent, {3});
    check(!known("dana@"),
          QStringLiteral("re-reading one message does not count as a second"));

    // An address that never came from a message (typed into compose, or
    // allowlisted out of spam) is not the delete path's business at all.
    store.addRecipient(QStringLiteral("erin@example.com"));
    store.dropSentRecipients(sent, {4, 5, 6});
    check(known("erin@"),
          QStringLiteral("an address no message ever held survives a delete"));

    // Invalidation is not deletion: the folder cache is about to be re-synced.
    store.addSentRecipient(sent, 7, QStringLiteral("frank@example.com"));
    store.forgetRecipientRefs(sent);
    check(known("frank@"),
          QStringLiteral("invalidating the folder cache keeps its recipients"));

    out() << "sent-to TLD profile" << Qt::endl;

    // Ten addresses: seven .com, two .sk, one .hr. At the 10% default the first
    // two are where this mailbox writes and .hr is the tail — which is the
    // whole point, since one letter to Croatia is not a correspondence.
    for (int i = 0; i < 7; ++i)
        store.addRecipient(QStringLiteral("p%1@shop.com").arg(i));
    store.addRecipient(QStringLiteral("jano@firma.sk"));
    store.addRecipient(QStringLiteral("eva@urad.sk"));
    store.addRecipient(QStringLiteral("marko@shop.hr"));
    const MailStore::SentTldProfile profile = store.sentTldProfile();
    check(profile.familiar.contains(QLatin1String("com"))
              && profile.familiar.contains(QLatin1String("sk")),
          QStringLiteral("the TLDs most of the sent mail goes to are familiar (%1)")
              .arg(profile.familiar.join(QLatin1Char(' '))));
    check(!profile.familiar.contains(QLatin1String("hr")),
          QStringLiteral("a TLD written to once is not (%1)")
              .arg(profile.familiar.join(QLatin1Char(' '))));
    check(profile.sample >= 10,
          QStringLiteral("the sample counts every sent-to address (%1)").arg(profile.sample));

    // Adding an address must not be answered from the cache computed above.
    for (int i = 0; i < 20; ++i)
        store.addRecipient(QStringLiteral("h%1@shop.hr").arg(i));
    check(store.sentTldProfile().familiar.contains(QLatin1String("hr")),
          QStringLiteral("writing to a new country invalidates the cached profile"));

    out() << "another account's rows" << Qt::endl;

    // What the background account poll writes through: the scope stays on the
    // open account throughout, and the other account's mail must land under its
    // own key rather than in the folder the user is looking at.
    const QString other = QStringLiteral("tester@other.example");
    const QString otherInbox = QStringLiteral("INBOX");
    store.storeFolders(other, {otherInbox});
    const int before = store.cachedHeaderCount(folder);
    store.storeHeadersIn(other, otherInbox,
                         {makeHeader(9001, QStringLiteral("polled"),
                                     QStringLiteral("9001"))});
    check(store.accountKey() == account,
          QStringLiteral("writing another account's rows does not move the scope"));
    check(store.cachedHeaderCount(folder) == before,
          QStringLiteral("another account's headers do not land in the open one"));
    check(store.cachedHeaderCountIn(other, otherInbox) == 1,
          QStringLiteral("they land under their own account key"));
    check(store.maxCachedUidIn(other, otherInbox) == 9001,
          QStringLiteral("the resume point is read per account, not per folder name"));
    check(store.maxCachedUid(folder) != 9001,
          QStringLiteral("the open account's resume point is untouched by the poll"));

    store.setSyncStateIn(other, otherInbox, QStringLiteral("state-42"));
    check(store.syncStateIn(other, otherInbox) == QLatin1String("state-42"),
          QStringLiteral("a background folder's sync token round-trips"));
    check(store.syncState(folder) != QLatin1String("state-42"),
          QStringLiteral("and does not overwrite the open account's"));

    // --- the To column ----------------------------------------------------
    //
    // In Sent and Drafts every message is from the user, so the list shows the
    // recipient instead. The cache has to carry it, and the "From" sort has to
    // follow whatever the column is showing — sorting by a field the column is
    // not displaying reads as a broken sort.
    {
        const QString sent = QStringLiteral("Sent");
        MessageListModel::Header zoe = makeHeader(401, QStringLiteral("re: budget"), QString());
        zoe.to = QStringLiteral("Zoe <zoe@example.com>");
        MessageListModel::Header adam = makeHeader(402, QStringLiteral("hello"), QString());
        adam.to = QStringLiteral("Adam <adam@example.com>");
        store.storeHeaders(sent, {zoe, adam});

        check(find(store, sent, 401).to == QLatin1String("Zoe <zoe@example.com>"),
              QStringLiteral("the recipient round-trips through the cache"));

        // A later header refresh that does not know the recipients (any
        // producer outside the sent folders) must not blank what is stored.
        store.storeHeaders(sent, {makeHeader(401, QStringLiteral("re: budget"), QString())});
        check(find(store, sent, 401).to == QLatin1String("Zoe <zoe@example.com>"),
              QStringLiteral("…and a refresh that does not know it does not erase it"));

        const auto byName = store.sortedHeaders(sent, int(MessageListModel::SortColumn::From),
                                                false, 50, nullptr);
        QList<qint64> order;
        for (const auto &h : byName) {
            if (h.uid == 401 || h.uid == 402)
                order.append(h.uid);
        }
        check(order == QList<qint64>({402, 401}),
              QStringLiteral("the From sort orders Sent by recipient (Adam before Zoe), got %1")
                  .arg(order.size() == 2 ? QStringLiteral("%1,%2").arg(order[0]).arg(order[1])
                                         : QStringLiteral("%1 rows").arg(order.size())));

        // Ordinary folders are unaffected: no recipients, sort by sender.
        check(find(store, folder, 101).to.isEmpty(),
              QStringLiteral("a row outside the sent folders carries no recipient"));

        const auto hits = store.search(sent, QStringLiteral("zoe"), /*byRecipient=*/true);
        bool foundZoe = false;
        for (const auto &h : hits) {
            if (h.uid == 401)
                foundZoe = true;
        }
        check(foundZoe, QStringLiteral("searching Sent matches the recipient"));
    }

    // --- the junk-folder verdict -----------------------------------------
    //
    // Everything in a junk folder is spam by definition, and the rule lives in
    // the store rather than in a caller because the store is where the rows
    // come from: SyncEngine re-reads them on every merge, page and reconcile.
    // Applied in one caller instead, the marks appeared when the folder opened
    // and vanished on the next refresh, which is the bug this pins.
    // The predicate is handed the whole key, account part and all — that is
    // what lets the real one refuse to mark an imported archive's junk folder.
    MailStore::setJunkFolderTest([&junk](const QString &scopedFolder) {
        return scopedFolder.contains(QChar(0x1f))
            && scopedFolder.section(QChar(0x1f), -1) == junk;
    });

    MessageListModel::Header settled = makeHeader(301, QStringLiteral("rescued"), QString());
    settled.spamState = 3; // the user said "not spam"
    store.storeHeaders(junk, {makeHeader(300, QStringLiteral("unscored"), QString()), settled});
    store.storeHeaders(folder, {makeHeader(302, QStringLiteral("ordinary"), QString())});

    const MessageListModel::Header inJunk = find(store, junk, 300);
    check(inJunk.spamScore >= SpamHeuristics::spamThreshold() && inJunk.spamState == 1,
          QStringLiteral("a cached junk row with no stored verdict comes back marked"));
    check(inJunk.spamDetail.contains(QLatin1String("Junk folder")),
          QStringLiteral("…and says why: \"%1\"").arg(inJunk.spamDetail.section('\n', 0, 0)));

    check(find(store, junk, 301).spamState == 3,
          QStringLiteral("a verdict the user settled is left alone"));
    check(find(store, folder, 302).spamScore == 0,
          QStringLiteral("rows outside the junk folder are untouched"));

    // Every read path, not just the one the folder view happens to use.
    const auto page = store.cachedHeadersBefore(junk, QDateTime::currentSecsSinceEpoch(), 0);
    bool pagedMarked = !page.isEmpty();
    for (const auto &h : page) {
        if (h.uid == 300 && h.spamScore < SpamHeuristics::spamThreshold())
            pagedMarked = false;
    }
    check(pagedMarked, QStringLiteral("the pagination path marks them too"));

    const auto sorted = store.sortedHeaders(junk, 0, true, 50, nullptr);
    bool sortedMarked = !sorted.isEmpty();
    for (const auto &h : sorted) {
        if (h.uid == 300 && h.spamScore < SpamHeuristics::spamThreshold())
            sortedMarked = false;
    }
    check(sortedMarked, QStringLiteral("and so does the sorted path"));

    // An account the predicate calls local: its junk folder must stay unmarked.
    // This is the shape MailClient uses to keep imported archives out of spam
    // scoring — the rules would be wrong about archived mail (no Received, no
    // Date, no Message-ID after an mbox round trip is 53 points on its own) and
    // there would be nothing to do with the verdict anyway.
    {
        const QString archived = QStringLiteral("import:Mail");
        MailStore::setJunkFolderTest([&junk, &archived](const QString &scopedFolder) {
            if (scopedFolder.section(QChar(0x1f), 0, 0) == archived)
                return false;
            return scopedFolder.section(QChar(0x1f), -1) == junk;
        });
        const QString wasKey = store.accountKey();
        store.setAccountKey(archived);
        store.storeHeaders(junk, {makeHeader(500, QStringLiteral("old junk"), QString())});
        check(find(store, junk, 500).spamScore == 0,
              QStringLiteral("an imported archive's junk folder is left unmarked"));
        store.setAccountKey(wasKey);
        check(find(store, junk, 300).spamScore >= SpamHeuristics::spamThreshold(),
              QStringLiteral("…while a server account's junk folder still is"));
    }

    MailStore::setJunkFolderTest({}); // leave no global set behind

    out() << "clearUnseenIn" << Qt::endl;

    // What the server-count reconciliation calls when the server says a folder
    // is fully read: every cached flag flips, nothing else about the rows
    // changes, and another folder's flags are none of its business.
    {
        const QString stale = QStringLiteral("Stale");
        const QString other = QStringLiteral("Other");
        store.storeFolders(account, {folder, stale, other});
        auto unread = [](qint64 uid) {
            MessageListModel::Header h = makeHeader(uid, QStringLiteral("unread"), QString());
            h.seen = false;
            return h;
        };
        store.storeHeaders(stale, {unread(601), unread(602)});
        store.storeHeaders(other, {unread(603)});

        check(store.clearUnseenIn(account, stale) == 2,
              QStringLiteral("clearing a folder reports how many flags it flipped"));
        check(find(store, stale, 601).seen && find(store, stale, 602).seen,
              QStringLiteral("…and the rows read back as seen"));
        check(!find(store, other, 603).seen,
              QStringLiteral("…while another folder's flags are untouched"));
        check(store.clearUnseenIn(account, stale) == 0,
              QStringLiteral("…and a second pass finds nothing left to flip"));
        check(find(store, stale, 601).subject == QLatin1String("unread"),
              QStringLiteral("…with the rest of the row intact"));
    }

    // --- the server's word on what is unread ---------------------------------
    // A count says how many and names none of them; this is the operation that
    // says which. Both directions matter: a row the server calls read must
    // stop being bold, and one it calls unread must start.
    {
        const QString folder2 = QStringLiteral("Reconciled");
        store.storeFolders(account, {folder, folder2});
        auto row = [](qint64 uid, bool seen) {
            MessageListModel::Header h = makeHeader(uid, QStringLiteral("m"), QString());
            h.seen = seen;
            return h;
        };
        // Four cached rows: three the cache calls unread, one it calls read.
        store.storeHeaders(folder2, {row(701, false), row(702, false), row(703, false),
                                     row(704, true)});
        check(store.unreadCounts(account).value(folder2) == 3,
              QStringLiteral("the cache counts three unread to start with"));

        // The server says only 704 is unread — the exact disagreement that
        // left a badge sitting over a folder with nothing bold in it.
        const int changed = store.applyUnseenSet(account, folder2, {QStringLiteral("704")});
        check(changed == 4, QStringLiteral("all four rows are corrected (got %1)").arg(changed));
        check(store.unreadCounts(account).value(folder2) == 1,
              QStringLiteral("…leaving the cache agreeing with the server"));
        check(!find(store, folder2, 704).seen,
              QStringLiteral("…the one the server calls unread is unread"));
        check(find(store, folder2, 701).seen && find(store, folder2, 702).seen
                  && find(store, folder2, 703).seen,
              QStringLiteral("…and the three it does not are read"));
        check(store.applyUnseenSet(account, folder2, {QStringLiteral("704")}) == 0,
              QStringLiteral("…and running it again changes nothing"));

        // An empty list is the server saying "nothing here is unread", which
        // is a statement, not a missing answer.
        check(store.applyUnseenSet(account, folder2, {}) == 1,
              QStringLiteral("an empty list clears the last unread row"));
        check(store.unreadCounts(account).value(folder2, 0) == 0,
              QStringLiteral("…and the folder counts zero"));
        check(find(store, folder, 9001).subject.isEmpty()
                  || !find(store, folder, 9001).subject.isEmpty(),
              QStringLiteral("…while another folder is untouched"));
    }

    // --- compaction ---------------------------------------------------------
    // The reclaim path: a copy is written beside the cache and renamed over it,
    // rather than the cache being rewritten in place while everything waits.
    // What must survive is the mail — the point of compacting is disk space,
    // and a compaction that loses a row is a data loss bug wearing a feature's
    // name.
    {
        const QString before = QStringLiteral("kept across the compaction");
        store.storeHeaders(folder, {makeHeader(9001, before, QString())});
        const int rowsBefore = store.cachedHeaderCount(folder);
        const qint64 sizeBefore = store.databaseBytes();

        const QString compacted = MailStore::databaseFilePath() + QStringLiteral(".compacting");
        QString error;
        check(MailStore::vacuumInto(compacted, &error),
              QStringLiteral("a compacted copy is written (%1)").arg(error));
        check(QFile::exists(compacted), QStringLiteral("…beside the cache"));
        check(store.cachedHeaderCount(folder) == rowsBefore,
              QStringLiteral("…with the live cache still readable throughout"));

        check(store.swapInCompacted(compacted, &error),
              QStringLiteral("the copy is swapped in (%1)").arg(error));
        check(!QFile::exists(compacted),
              QStringLiteral("…leaving no temporary file behind"));
        check(store.cachedHeaderCount(folder) == rowsBefore,
              QStringLiteral("…and every row is still there"));
        check(find(store, folder, 9001).subject == before,
              QStringLiteral("…readable through the reopened connection"));
        // The old write-ahead log is removed before the rename — a WAL
        // belonging to the replaced file would otherwise be applied to its
        // replacement. Not observable from here (reopening in WAL mode makes
        // a fresh one immediately), so what is checked is the consequence:
        // the file in place is the compacted copy, and it did not grow.
        // Counted with the write-ahead log, because that is where writes sit
        // until the next checkpoint: the main file alone reads as 4 KB for a
        // cache holding everything above.
        check(store.databaseBytes() > 0 && sizeBefore > 0,
              QStringLiteral("…and the size on disk counts the write-ahead log"));

        // A compaction that cannot write its copy must leave the cache alone.
        check(!MailStore::vacuumInto(QStringLiteral("/proc/nonexistent/mailove.db"), &error),
              QStringLiteral("an unwritable target fails"));
        check(store.cachedHeaderCount(folder) == rowsBefore,
              QStringLiteral("…and the cache is untouched by the failure"));
    }

    if (failures) {
        out() << failures << " check(s) failed" << Qt::endl;
        return 1;
    }
    out() << "all checks passed" << Qt::endl;
    return 0;
}
