// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "mailstore.h"

#include "attachmentstore.h"
#include "spamheuristics.h"

#include <QDateTime>
#include <QHash>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSqlError>
#include <QSqlQuery>
#include <QStandardPaths>
#include <QThread>

/// The store runs on the GUI thread: any call here directly delays input
/// handling and rendering. The UI budget is 20 ms — make violations loud.
namespace
{
struct SlowGuard {
    explicit SlowGuard(const char *operation)
        : op(operation)
    {
        timer.start();
    }
    ~SlowGuard()
    {
        const qint64 ms = timer.elapsed();
        if (ms > 20)
            qWarning() << "mailstore: SLOW" << op << ms << "ms on the GUI thread";
    }
    QElapsedTimer timer;
    const char *op;
};

/// One-time migrations record themselves in meta_flags so they cost a single
/// indexed lookup on every later start instead of a full-table pass. Both
/// helpers assume meta_flags exists (open() creates it first thing).
bool migrationDone(const QSqlDatabase &db, const QString &flag)
{
    QSqlQuery q(db);
    q.prepare(QStringLiteral("SELECT 1 FROM meta_flags WHERE flag = ?"));
    q.addBindValue(flag);
    return q.exec() && q.next();
}

void markMigrationDone(const QSqlDatabase &db, const QString &flag)
{
    QSqlQuery q(db);
    q.prepare(QStringLiteral("INSERT OR IGNORE INTO meta_flags (flag) VALUES (?)"));
    q.addBindValue(flag);
    q.exec();
}
}

bool MailStore::open()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    // Cached mail is private data — owner-only on the whole directory so the
    // -wal/-shm side files are covered too.
    QFile::setPermissions(dir, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);

    m_db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), QStringLiteral("mailstore"));
    m_db.setDatabaseName(dir + QStringLiteral("/mailove.db"));
    if (!m_db.open()) {
        qWarning() << "mailstore: cannot open database:" << m_db.lastError().text();
        return false;
    }
    QFile::setPermissions(dir + QStringLiteral("/mailove.db"),
                          QFile::ReadOwner | QFile::WriteOwner);

    SlowGuard guard("open");
    QSqlQuery q(m_db);
    q.exec(QStringLiteral("PRAGMA journal_mode=WAL"));
    // The purge and vacuum workers write on their own connections. Without a
    // busy timeout this connection would fail its writes outright the moment
    // one of them held the lock, instead of waiting the few ms it takes.
    q.exec(QStringLiteral("PRAGMA busy_timeout=15000"));

    // Gates every one-time migration below, so create it before the first one.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS meta_flags (flag TEXT PRIMARY KEY)"));
    // Resumable progress for migrations too long to finish in one run.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS meta_values ("
                          " key TEXT PRIMARY KEY, value TEXT)"));
    if (!q.exec(QStringLiteral(
            "CREATE TABLE IF NOT EXISTS messages ("
            " folder TEXT NOT NULL, uid INTEGER NOT NULL,"
            " subject TEXT, sender TEXT, date INTEGER, seen INTEGER DEFAULT 0,"
            " PRIMARY KEY(folder, uid))"))) {
        qWarning() << "mailstore: schema failed:" << q.lastError().text();
        return false;
    }
    q.exec(QStringLiteral(
        "CREATE TABLE IF NOT EXISTS bodies ("
        " folder TEXT NOT NULL, uid INTEGER NOT NULL, raw BLOB,"
        " PRIMARY KEY(folder, uid))"));

    // Sweep ghost rows cached by earlier versions: entries without a uid or
    // with no content at all ("(no subject), 1970") can never be opened.
    // Neither predicate is indexable, so this is a full pass over messages and
    // bodies — once, not on every start, since no current code writes them.
    if (!migrationDone(m_db, QStringLiteral("ghost_sweep1"))) {
        q.exec(QStringLiteral("DELETE FROM messages WHERE uid <= 0"
                              " OR (IFNULL(subject,'') = '' AND IFNULL(sender,'') = ''"
                              "     AND IFNULL(date,0) <= 0)"));
        q.exec(QStringLiteral("DELETE FROM bodies WHERE uid <= 0"));
        markMigrationDone(m_db, QStringLiteral("ghost_sweep1"));
    }

    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS folders ("
                          " mailbox TEXT PRIMARY KEY, sortkey INTEGER)"));

    // Per-account folder lists (the legacy global "folders" table is adopted
    // into this one on first run, see adoptLegacyCache()).
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS account_folders ("
                          " account TEXT NOT NULL, mailbox TEXT NOT NULL,"
                          " sortkey INTEGER, uidvalidity INTEGER DEFAULT 0,"
                          " PRIMARY KEY(account, mailbox))"));

    // Attachment payloads live in files keyed by content hash (see
    // attachmentstore.h); these two tables are the index over that store.
    // `refs` is what makes eviction possible at all — the old
    // (folder, uid) -> BLOB layout had nowhere to record that the same
    // payload was reachable from several messages.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS attachments ("
                          " hash TEXT PRIMARY KEY, size INTEGER NOT NULL,"
                          " stored INTEGER NOT NULL, codec INTEGER NOT NULL DEFAULT 0,"
                          " refs INTEGER NOT NULL DEFAULT 0, last_used INTEGER DEFAULT 0)"));
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS message_parts ("
                          " folder TEXT NOT NULL, uid INTEGER NOT NULL, part_id TEXT NOT NULL,"
                          " hash TEXT NOT NULL, filename TEXT, mime TEXT, encoding TEXT,"
                          " PRIMARY KEY(folder, uid, part_id))"));
    // Dropping a folder has to find its parts by (folder, uid); releasing a
    // payload has to count the remaining referrers by hash.
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_message_parts_hash"
                          " ON message_parts(hash)"));

    // The first attachment migration mis-reported the codec of deduplicated
    // payloads and skipped those messages, having already moved its cursor
    // past them. Rewind once so they get another pass; messages already
    // migrated simply parse, find nothing large inline, and cost one read.
    if (!migrationDone(m_db, QStringLiteral("attach_migrate_reset1"))) {
        q.exec(QStringLiteral(
            "DELETE FROM meta_values WHERE key = 'attach_migrate_cursor'"));
        q.exec(QStringLiteral("DELETE FROM meta_flags WHERE flag = 'attach_migrate1'"));
        markMigrationDone(m_db, QStringLiteral("attach_migrate_reset1"));
    }

    // Bodies deliberately not cached because they exceed the size limit.
    // Without this the backfill would ask for them again on every single pass:
    // uidsWithoutBody() cannot tell "never fetched" from "refused to store".
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS body_skipped ("
                          " folder TEXT NOT NULL, uid INTEGER NOT NULL,"
                          " size INTEGER DEFAULT 0,"
                          " PRIMARY KEY(folder, uid))"));

    // Senders the user chose to always load remote content for.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS remote_senders ("
                          " sender TEXT PRIMARY KEY)"));

    // How much mail each sending organization has a history of here — the
    // spam scorer's familiarity signal (SpamHeuristics::Context::seenFromOrg).
    //
    // An aggregate rather than a query over messages, because the question
    // "how many messages are from this domain" has no index that can answer it:
    // messages.sender holds a full mailbox value, so any direct answer is a
    // full scan of the largest table in the cache, on the GUI thread, per
    // sender. Counting forward as mail is stored costs one indexed upsert per
    // new message instead.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS sender_domains ("
                          " org TEXT PRIMARY KEY, seen INTEGER NOT NULL DEFAULT 0,"
                          " first_seen INTEGER NOT NULL DEFAULT 0,"
                          " last_seen INTEGER NOT NULL DEFAULT 0)"));

    // Addresses mail was sent to, for compose autocompletion.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS recipients ("
                          " account TEXT NOT NULL, address TEXT NOT NULL,"
                          " name TEXT DEFAULT '', last_used INTEGER DEFAULT 0,"
                          " use_count INTEGER DEFAULT 0,"
                          " PRIMARY KEY(account, address))"));

    // Which Sent messages each of those addresses came from. This is what
    // makes a recipient removable: deleting one message the address appears in
    // must not forget the address, deleting the last one must. use_count alone
    // could never answer that — it counts sightings, not messages, so nothing
    // could tell a second sighting of one message from a second message.
    // A recipient with no rows here (typed into compose, allowlisted out of
    // spam) is not message-derived and is never pruned.
    q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS recipient_refs ("
                          " account TEXT NOT NULL, folder TEXT NOT NULL,"
                          " uid INTEGER NOT NULL, address TEXT NOT NULL,"
                          " PRIMARY KEY(folder, uid, address))"));
    // The primary key answers "which addresses does this message hold"; this
    // index answers the opposite question, "is any message left holding this
    // address", which is the one the prune asks per removed address.
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_recipient_refs_addr"
                          " ON recipient_refs(account, address)"));

    // Schema upgrades for pre-existing databases; fail silently if present.
    q.exec(QStringLiteral("ALTER TABLE folders ADD COLUMN uidvalidity INTEGER DEFAULT 0"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN suspicious INTEGER DEFAULT 0"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN auth TEXT DEFAULT ''"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN attach INTEGER DEFAULT 0"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN color INTEGER DEFAULT 0"));
    // Message-ID is the only stable identity a message has: IMAP UIDs are
    // per-folder and do not survive a move or a UIDVALIDITY reset. NULL means
    // "not known yet" and is what backfillMessageIds() looks for; '' means
    // "looked, and the message has no Message-ID".
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN msgid TEXT"));
    // Our own DKIM/ARC verdict, kept so a message is verified once rather than
    // on every open. That is not just a speed matter: re-checking costs a DNS
    // query per open, and for a message whose attachments were lifted out of
    // the body there is no longer a byte-exact copy to re-check against — the
    // verdict recorded while we still had one is the only honest answer.
    // Empty status = never verified, which is what makes this self-filling.
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN dkim TEXT DEFAULT ''"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN dkim_detail TEXT DEFAULT ''"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN dkim_trusted INTEGER DEFAULT 0"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN arc TEXT DEFAULT ''"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN arc_sealer TEXT DEFAULT ''"));
    // The To line, for the Sent and Drafts folders where every message is from
    // the user and the From column says the same thing on every row. Only
    // written for those folders — see MailClient::listsRecipients().
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN recipients TEXT DEFAULT ''"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN arc_detail TEXT DEFAULT ''"));
    // OpenPGP shape of the message (doc/openpgp.md §8): 0 none, 1 encrypted,
    // 2 signed, 3 both. Set from the raw head at header-store time and refined
    // once the body arrives, exactly like attach.
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN crypto INTEGER DEFAULT 0"));
    // Local spam verdict (see spamheuristics.h). The score is stored rather
    // than the verdict so that moving a threshold re-judges old mail instead of
    // freezing yesterday's opinion into the cache. spam_state says how much was
    // known when it was computed — 0 never scored, 1 headers only, 2 with the
    // body, 3 exempt under Rule 0 — which is what lets the score be refined
    // when the body lands rather than treated as final.
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN spam_score INTEGER DEFAULT 0"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN spam_state INTEGER DEFAULT 0"));
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN spam_detail TEXT DEFAULT ''"));
    // The allowlist asks "have I ever written to this address", across every
    // account and ignoring any +tag. Neither half of the (account, address)
    // primary key can answer that, hence a normalized column of its own.
    // The backend's own name for a message (see Header::remoteId). Nullable
    // and deliberately never backfilled: for the IMAP rows already on disk the
    // uid *is* the remote id, so a sweep over `messages` would rewrite every
    // row in a multi-gigabyte cache to say what the primary key already says.
    // The read path substitutes the uid when this is NULL instead.
    q.exec(QStringLiteral("ALTER TABLE messages ADD COLUMN remote_id TEXT"));
    // Opaque per-folder sync position, whatever the backend needs to resume a
    // delta sync: IMAP has uidvalidity (its own column, kept as-is so existing
    // caches keep working), JMAP stores its Email/changes state string here.
    // The store never interprets it.
    q.exec(QStringLiteral("ALTER TABLE account_folders ADD COLUMN sync_state TEXT DEFAULT ''"));
    q.exec(QStringLiteral("ALTER TABLE recipients ADD COLUMN addr_norm TEXT DEFAULT ''"));
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_recipients_norm"
                          " ON recipients(addr_norm)"));
    if (!migrationDone(m_db, QStringLiteral("recipients_norm"))) {
        // Small table (one row per person ever mailed), so a full rewrite here
        // is nothing like a sweep over messages. The CASE only splits on '+'
        // once the local part is known to contain one, so a '+' in a domain
        // cannot truncate the address.
        q.exec(QStringLiteral(
            "UPDATE recipients SET addr_norm = CASE"
            " WHEN instr(substr(address, 1, instr(address, '@') - 1), '+') > 0"
            "  THEN substr(address, 1, instr(address, '+') - 1)"
            "       || substr(address, instr(address, '@'))"
            " ELSE address END"
            " WHERE addr_norm = '' OR addr_norm IS NULL"));
        markMigrationDone(m_db, QStringLiteral("recipients_norm"));
    }
    // Carrying the sort keys, for the same reason idx_messages_color does:
    // "every failing message in this folder, newest first" is then a seek plus
    // a LIMIT rather than a full folder read and sort. The lookup on open goes
    // through the (folder, uid) primary key and needs neither of these.
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_messages_dkim"
                          " ON messages(folder, dkim, date DESC, uid DESC)"));
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_messages_arc"
                          " ON messages(folder, arc, date DESC, uid DESC)"));
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_messages_msgid"
                          " ON messages(msgid)"));
    // (folder, color) alone could find the rows but not order them, so the
    // colour filter still sorted the whole folder. Carrying the sort keys in
    // the index makes it a seek plus a LIMIT.
    if (!migrationDone(m_db, QStringLiteral("color_index2"))) {
        q.exec(QStringLiteral("DROP INDEX IF EXISTS idx_messages_color"));
        markMigrationDone(m_db, QStringLiteral("color_index2"));
    }
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_messages_color"
                          " ON messages(folder, color, date DESC, uid DESC)"));
    // Every list query is "newest first within a folder". Without this the
    // only usable index is the (folder, uid) primary key, which yields uid
    // order — so SQLite read the whole folder into a temp B-tree and sorted it
    // before applying LIMIT. On a 200k-message folder that is a full sort to
    // show 1000 rows, on the GUI thread, on every open, scroll and search.
    q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_messages_date"
                          " ON messages(folder, date DESC, uid DESC)"));

    // remove_diacritics 2 folds accents in both the index and the query, so
    // "ave" finds "ávé" — the default (1) leaves several Latin ranges alone.
    m_ftsAvailable = q.exec(QStringLiteral(
        "CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5("
        " subject, sender, body, folder UNINDEXED, uid UNINDEXED,"
        " tokenize = \"unicode61 remove_diacritics 2\")"));
    if (!m_ftsAvailable)
        qWarning() << "mailstore: FTS5 unavailable:" << q.lastError().text();

    // An index built before that option folds nothing, and there is no way to
    // change a tokenizer in place — it has to be rebuilt. Only noted here;
    // doing it costs a pass over the whole index and belongs on a worker.
    if (m_ftsAvailable) {
        QSqlQuery schema(m_db);
        if (schema.exec(QStringLiteral(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'fts'"))
            && schema.next()) {
            m_ftsRebuildNeeded =
                !schema.value(0).toString().contains(QLatin1String("remove_diacritics 2"));
        }
    }

    // One-time rebuild keying every fts row by its messages.rowid. folder/uid
    // are UNINDEXED in fts5, so per-message maintenance filtered on them was
    // a full scan of the whole index — O(index) CPU on the GUI thread for
    // EVERY header stored and body cached. rowid lookups are O(1).
    if (m_ftsAvailable
        && (!q.exec(QStringLiteral("SELECT 1 FROM meta_flags WHERE flag = 'fts_rowid'"))
            || !q.next())) {
        q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS meta_flags (flag TEXT PRIMARY KEY)"));
        m_db.transaction();
        QSqlQuery mig(m_db);
        mig.exec(QStringLiteral(
            "CREATE VIRTUAL TABLE fts_new USING fts5("
            " subject, sender, body, folder UNINDEXED, uid UNINDEXED)"));
        mig.exec(QStringLiteral(
            "INSERT INTO fts_new (rowid, subject, sender, body, folder, uid)"
            " SELECT m.rowid, f.subject, f.sender, f.body, f.folder, f.uid"
            " FROM fts f JOIN messages m ON m.folder = f.folder AND m.uid = f.uid"));
        mig.exec(QStringLiteral("DROP TABLE fts"));
        mig.exec(QStringLiteral("ALTER TABLE fts_new RENAME TO fts"));
        q.exec(QStringLiteral("INSERT OR IGNORE INTO meta_flags (flag) VALUES ('fts_rowid')"));
        m_db.commit();
    }

    // Self-healing index rebuild: (re)creates the header rows for every
    // message missing from fts in one statement, and queues every cached
    // body for background text re-indexing (fts_pending). Runs once; if any
    // step fails (e.g. the DB is locked by another instance) nothing is
    // committed and it retries on the next start.
    if (m_ftsAvailable
        && (!q.exec(QStringLiteral("SELECT 1 FROM meta_flags WHERE flag = 'fts_rebuild1'"))
            || !q.next())) {
        q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS meta_flags (flag TEXT PRIMARY KEY)"));
        m_db.transaction();
        QSqlQuery mig(m_db);
        bool ok = mig.exec(QStringLiteral(
            "INSERT INTO fts (rowid, subject, sender, body, folder, uid)"
            " SELECT m.rowid, IFNULL(m.subject, ''), IFNULL(m.sender, ''), '', m.folder, m.uid"
            " FROM messages m"
            " WHERE NOT EXISTS (SELECT 1 FROM fts WHERE rowid = m.rowid)"));
        ok = mig.exec(QStringLiteral(
                 "CREATE TABLE IF NOT EXISTS fts_pending ("
                 " folder TEXT NOT NULL, uid INTEGER NOT NULL,"
                 " PRIMARY KEY(folder, uid))"))
            && ok;
        ok = mig.exec(QStringLiteral(
                 "INSERT OR IGNORE INTO fts_pending (folder, uid)"
                 " SELECT folder, uid FROM bodies"))
            && ok;
        if (ok) {
            q.exec(QStringLiteral(
                "INSERT OR IGNORE INTO meta_flags (flag) VALUES ('fts_rebuild1')"));
            m_db.commit();
        } else {
            qWarning() << "mailstore: fts rebuild failed, retrying next start:"
                       << mig.lastError().text();
            m_db.rollback();
        }
    }

    // One-time backfill: rows cached before the attach column existed get
    // their flag recomputed from the raw bodies we already have on disk.
    if (!q.exec(QStringLiteral("SELECT 1 FROM meta_flags WHERE flag = 'attach_backfill'"))
        || !q.next()) {
        q.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS meta_flags (flag TEXT PRIMARY KEY)"));
        QSqlQuery bodies(m_db);
        QSqlQuery upd(m_db);
        upd.prepare(QStringLiteral(
            "UPDATE messages SET attach = 1 WHERE folder = ? AND uid = ?"));
        m_db.transaction();
        if (bodies.exec(QStringLiteral("SELECT folder, uid, raw FROM bodies"))) {
            while (bodies.next()) {
                const QByteArray raw = bodies.value(2).toByteArray();
                const int headEnd = raw.indexOf("\r\n\r\n") >= 0
                    ? raw.indexOf("\r\n\r\n") : raw.indexOf("\n\n");
                if (headIndicatesAttachment(headEnd > 0 ? raw.left(headEnd) : raw)) {
                    upd.addBindValue(bodies.value(0));
                    upd.addBindValue(bodies.value(1));
                    upd.exec();
                }
            }
        }
        q.exec(QStringLiteral("INSERT OR IGNORE INTO meta_flags (flag) VALUES ('attach_backfill')"));
        m_db.commit();
    }
    return true;
}

void MailStore::setAccountKey(const QString &key)
{
    m_accountKey = key;
}

QString MailStore::scoped(const QString &folder) const
{
    return scopedIn(m_accountKey, folder);
}

QString MailStore::scopedIn(const QString &account, const QString &folder)
{
    if (account.isEmpty())
        return folder;
    return account + QChar(0x1f) + folder;
}

void MailStore::adoptLegacyCache(const QString &account)
{
    if (!m_db.isOpen() || account.isEmpty())
        return;
    // Strictly a first-run upgrade step. The instr() predicates below cannot
    // use an index, so re-running it on an already-scoped cache scanned every
    // messages/bodies/fts row for nothing — the single largest cost in
    // startup. Once claimed, no unscoped row can appear again.
    if (migrationDone(m_db, QStringLiteral("legacy_adopt1")))
        return;
    SlowGuard guard("adoptLegacyCache");
    m_db.transaction();
    QSqlQuery q(m_db);

    // Global folder list → this account's per-account list.
    q.prepare(QStringLiteral(
        "INSERT OR IGNORE INTO account_folders (account, mailbox, sortkey, uidvalidity)"
        " SELECT ?, mailbox, sortkey, uidvalidity FROM folders"));
    q.addBindValue(account);
    q.exec();
    q.exec(QStringLiteral("DELETE FROM folders"));

    // Unscoped message/body/index rows get this account's folder-key prefix.
    // instr() guards make this idempotent — prefixed rows are left alone.
    const QString prefix = account + QChar(0x1f);
    for (const char *table : {"messages", "bodies", "fts"}) {
        if (!m_ftsAvailable && qstrcmp(table, "fts") == 0)
            continue;
        QSqlQuery upd(m_db);
        upd.prepare(QStringLiteral(
                        "UPDATE %1 SET folder = ? || folder WHERE instr(folder, char(31)) = 0")
                        .arg(QLatin1String(table)));
        upd.addBindValue(prefix);
        upd.exec();
    }
    if (m_db.commit())
        markMigrationDone(m_db, QStringLiteral("legacy_adopt1"));
}

QStringList MailStore::cachedFolders(const QString &account)
{
    QStringList out;
    if (!m_db.isOpen())
        return out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT mailbox FROM account_folders WHERE account = ? ORDER BY sortkey"));
    q.addBindValue(account);
    if (q.exec()) {
        while (q.next())
            out.append(q.value(0).toString());
    }
    return out;
}

void MailStore::storeFolders(const QString &account, const QStringList &folders)
{
    if (!m_db.isOpen())
        return;
    m_db.transaction();
    QSqlQuery q(m_db);
    // Preserve each folder's cached UIDVALIDITY across the rewrite.
    QHash<QString, qint64> validity;
    q.prepare(QStringLiteral(
        "SELECT mailbox, uidvalidity FROM account_folders WHERE account = ?"));
    q.addBindValue(account);
    if (q.exec()) {
        while (q.next())
            validity.insert(q.value(0).toString(), q.value(1).toLongLong());
    }
    q.prepare(QStringLiteral("DELETE FROM account_folders WHERE account = ?"));
    q.addBindValue(account);
    q.exec();
    q.prepare(QStringLiteral("INSERT INTO account_folders"
                             " (account, mailbox, sortkey, uidvalidity) VALUES (?, ?, ?, ?)"));
    for (int i = 0; i < folders.size(); ++i) {
        q.addBindValue(account);
        q.addBindValue(folders.at(i));
        q.addBindValue(i);
        q.addBindValue(validity.value(folders.at(i), 0));
        q.exec();
    }
    m_db.commit();
}

namespace
{
std::function<bool(const QString &)> g_isJunkFolder;
}

void MailStore::setJunkFolderTest(std::function<bool(const QString &)> isJunk)
{
    g_isJunkFolder = std::move(isJunk);
}

/// Applies the junk-folder verdict to rows just read from the cache.
///
/// Everything in a junk folder is spam by definition, and most of what is in
/// one predates any scoring — filed by the server or by hand, with no stored
/// verdict at all. Done on the way out of the database rather than written
/// into it, so that moving a message out of junk stops it being marked
/// immediately instead of waiting for a write to catch up.
///
/// A verdict the user has settled (state 3, "not spam") is left alone, as is a
/// row that some rule already marked on its own evidence.
void applyJunkVerdict(QList<MessageListModel::Header> &rows, const QString &scopedFolder)
{
    if (rows.isEmpty() || !g_isJunkFolder)
        return;
    // The whole key, account part included: the cache holds every account's
    // rows, and whether a "Junk" folder means anything depends on whose it is
    // — an imported archive's does not. The predicate does the splitting.
    if (!g_isJunkFolder(scopedFolder))
        return;
    for (MessageListModel::Header &h : rows) {
        if (h.spamState == 3 || h.spamScore >= SpamHeuristics::SpamThreshold)
            continue;
        SpamHeuristics::Score s;
        s.verdict = SpamHeuristics::Verdict::Spam;
        s.total = SpamHeuristics::JunkFolderWeight;
        s.hits.append({QStringLiteral("junk-folder"), SpamHeuristics::JunkFolderWeight,
                       QStringLiteral("This message is in your Junk folder — you or your "
                                      "mail server put it there")});
        h.spamScore = s.total;
        h.spamState = 1;
        h.spamDetail = s.explanation();
    }
}

static QList<MessageListModel::Header> readHeaderRows(QSqlQuery &q)
{
    QList<MessageListModel::Header> out;
    if (!q.exec())
        return out;
    while (q.next()) {
        MessageListModel::Header h;
        h.uid = q.value(0).toLongLong();
        h.subject = q.value(1).toString();
        h.from = q.value(2).toString();
        h.date = QDateTime::fromSecsSinceEpoch(q.value(3).toLongLong());
        h.seen = q.value(4).toBool();
        h.suspicious = q.value(5).toBool();
        h.authInfo = q.value(6).toString();
        h.attachKind = q.value(7).toInt();
        h.colorLabel = q.value(8).toInt();
        h.crypto = q.value(9).toInt();
        h.spamScore = q.value(10).toInt();
        h.spamState = q.value(11).toInt();
        h.spamDetail = q.value(12).toString();
        h.remoteId = q.value(13).toString();
        h.to = q.value(14).toString();
        out.append(h);
    }
    return out;
}

QList<MessageListModel::Header> MailStore::cachedHeaders(const QString &folder, int limit)
{
    if (!m_db.isOpen())
        return {};
    SlowGuard guard("cachedHeaders");
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT uid, subject, sender, date, seen, suspicious, auth, attach,"
                             " color, crypto, spam_score, spam_state, spam_detail,"
                             " IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '')"
                             " FROM messages WHERE folder = ?"
                             " ORDER BY date DESC, uid DESC LIMIT ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(limit);
    QList<MessageListModel::Header> rows = readHeaderRows(q);
    applyJunkVerdict(rows, scoped(folder));
    return rows;
}

QList<MessageListModel::Header> MailStore::cachedHeadersBefore(const QString &folder,
                                                               qint64 dateSecs, qint64 uid,
                                                               int limit)
{
    if (!m_db.isOpen())
        return {};
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT uid, subject, sender, date, seen, suspicious, auth, attach,"
                             " color, crypto, spam_score, spam_state, spam_detail,"
                             " IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '')"
                             " FROM messages WHERE folder = ?"
                             " AND (date < ? OR (date = ? AND uid < ?))"
                             " ORDER BY date DESC, uid DESC LIMIT ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(dateSecs);
    q.addBindValue(dateSecs);
    q.addBindValue(uid);
    q.addBindValue(limit);
    QList<MessageListModel::Header> rows = readHeaderRows(q);
    applyJunkVerdict(rows, scoped(folder));
    return rows;
}

/// The sort key expressions behind MessageListModel::lessThan(), by column.
/// lower() is ASCII-only where the model case-folds in full, so around a page
/// boundary the two can disagree on a name starting with an accented capital.
/// The model re-sorts whatever arrives, so that only ever moves the boundary
/// of a page by a row or two — it cannot misorder one; at worst a row near the
/// boundary is fetched twice and deduped by uid.
static QString sortKeySql(int column)
{
    switch (MessageListModel::SortColumn(column)) {
    case MessageListModel::SortColumn::From:
        // Whichever name the column is showing — see primeKeys(). The two must
        // agree or a page boundary would sort by one field and the page's
        // contents by the other.
        return QStringLiteral("CASE WHEN IFNULL(recipients, '') = ''"
                              " THEN IFNULL(lower(sender), '') ELSE lower(recipients) END");
    case MessageListModel::SortColumn::Subject:
        return QStringLiteral("IFNULL(lower(subject), '')");
    case MessageListModel::SortColumn::Attachment:
        return QStringLiteral("(IFNULL(attach, 0) IN (1, 2))");
    default:
        return QStringLiteral("date");
    }
}

/// The anchor row's value of that key, as a bind value.
static QVariant sortKeyValue(int column, const MessageListModel::Header &h)
{
    switch (MessageListModel::SortColumn(column)) {
    case MessageListModel::SortColumn::From:
        return (h.to.isEmpty() ? h.from : h.to).toLower();
    case MessageListModel::SortColumn::Subject:
        return h.subject.toLower();
    case MessageListModel::SortColumn::Attachment:
        return int(MessageListModel::kindHasAttachment(h.attachKind));
    default:
        return h.date.isValid() ? h.date.toSecsSinceEpoch() : 0;
    }
}

QList<MessageListModel::Header> MailStore::sortedHeaders(const QString &folder, int column,
                                                         bool descending, int limit,
                                                         const MessageListModel::Header *after)
{
    SlowGuard guard("sortedHeaders");
    return sortedHeadersOn(m_db, scoped(folder), column, descending, limit, after);
}

QList<MessageListModel::Header> MailStore::sortedHeadersOn(QSqlDatabase &db,
                                                           const QString &scopedFolder,
                                                           int column, bool descending, int limit,
                                                           const MessageListModel::Header *after)
{
    if (!db.isOpen() || scopedFolder.isEmpty())
        return {};

    const bool byAttachment =
        MessageListModel::SortColumn(column) == MessageListModel::SortColumn::Attachment;
    const QString key = sortKeySql(column);
    const QLatin1String dir(descending ? " DESC" : " ASC");
    const QLatin1String rev(descending ? " ASC" : " DESC");
    // Ties break on uid exactly as lessThan() does, which makes the ordering
    // total: every row has one place, so "the next page" is well-defined.
    // Inside an attachment group the model orders chronologically *against*
    // the group direction, hence `rev` on the date there.
    QString order = QStringLiteral(" ORDER BY ") + key + dir;
    if (byAttachment)
        order += QStringLiteral(", date") + rev;
    order += QStringLiteral(", uid") + dir;

    // Keyset predicate: strictly after \a after in that total order.
    const QLatin1String cmp(descending ? "<" : ">");
    const QLatin1String cmpRev(descending ? ">" : "<");
    QString where;
    if (after) {
        if (byAttachment)
            where = QStringLiteral(" AND (%1 %2 ? OR (%1 = ? AND (date %3 ?"
                                   " OR (date = ? AND uid %2 ?))))")
                        .arg(key, cmp, cmpRev);
        else
            where = QStringLiteral(" AND (%1 %2 ? OR (%1 = ? AND uid %2 ?))").arg(key, cmp);
    }

    QSqlQuery q(db);
    q.prepare(QStringLiteral("SELECT uid, subject, sender, date, seen, suspicious, auth, attach,"
                             " color, crypto, spam_score, spam_state, spam_detail,"
                             " IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '')"
                             " FROM messages WHERE folder = ?")
              + where + order + QStringLiteral(" LIMIT ?"));
    q.addBindValue(scopedFolder);
    if (after) {
        const QVariant anchor = sortKeyValue(column, *after);
        q.addBindValue(anchor);
        q.addBindValue(anchor);
        if (byAttachment) {
            const qint64 date = after->date.isValid() ? after->date.toSecsSinceEpoch() : 0;
            q.addBindValue(date);
            q.addBindValue(date);
        }
        q.addBindValue(after->uid);
    }
    q.addBindValue(limit);
    QList<MessageListModel::Header> rows = readHeaderRows(q);
    applyJunkVerdict(rows, scopedFolder);
    return rows;
}

QList<MessageListModel::Header> MailStore::headersByColor(const QString &folder, int color,
                                                          int limit)
{
    if (!m_db.isOpen())
        return {};
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT uid, subject, sender, date, seen, suspicious, auth, attach,"
                             " color, crypto, spam_score, spam_state, spam_detail,"
                             " IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '')"
                             " FROM messages WHERE folder = ? AND color = ?"
                             " ORDER BY date DESC, uid DESC LIMIT ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(color);
    q.addBindValue(limit);
    QList<MessageListModel::Header> rows = readHeaderRows(q);
    applyJunkVerdict(rows, scoped(folder));
    return rows;
}

int MailStore::cachedHeaderCount(const QString &folder)
{
    return cachedHeaderCountIn(m_accountKey, folder);
}

int MailStore::cachedHeaderCountIn(const QString &account, const QString &folder)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT COUNT(*) FROM messages WHERE folder = ?"));
    q.addBindValue(scopedIn(account, folder));
    return (q.exec() && q.next()) ? q.value(0).toInt() : 0;
}

qint64 MailStore::maxCachedUid(const QString &folder)
{
    return maxCachedUidIn(m_accountKey, folder);
}

qint64 MailStore::maxCachedUidIn(const QString &account, const QString &folder)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT MAX(uid) FROM messages WHERE folder = ?"));
    q.addBindValue(scopedIn(account, folder));
    return (q.exec() && q.next()) ? q.value(0).toLongLong() : 0;
}

void MailStore::storeHeaders(const QString &folder,
                             const QList<MessageListModel::Header> &headers)
{
    storeHeadersIn(m_accountKey, folder, headers);
}

void MailStore::storeHeadersIn(const QString &account, const QString &folder,
                               const QList<MessageListModel::Header> &headers)
{
    if (!m_db.isOpen())
        return;
    SlowGuard guard("storeHeaders");
    storeHeadersOn(m_db, scopedIn(account, folder), headers, m_ftsAvailable);
}

void MailStore::storeHeadersOn(QSqlDatabase &db, const QString &scopedFolder,
                               const QList<MessageListModel::Header> &headers,
                               bool ftsAvailable)
{
    if (!db.isOpen() || headers.isEmpty())
        return;
    db.transaction();
    const QString key = scopedFolder;
    QSqlQuery q(db);
    // Header refreshes only know "has attachment or not" (attach 0/1); a
    // refined kind learned from the full body (2 = calendar invite, 3 = the
    // body has no attachment despite the head) survives.
    q.prepare(QStringLiteral(
        "INSERT INTO messages"
        " (folder, uid, subject, sender, date, seen, suspicious, auth, attach, msgid,"
        " crypto, spam_score, spam_state, spam_detail, remote_id, recipients)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(folder, uid) DO UPDATE SET"
        " subject = excluded.subject, sender = excluded.sender, date = excluded.date,"
        // Never overwrite a known Message-ID with an unknown one: a header
        // refresh that could not read it must not erase what a body gave us.
        " msgid = COALESCE(excluded.msgid, messages.msgid),"
        // A locally-read message stays read even if the server still reports
        // \Unseen — e.g. it was read offline and the STORE never went out.
        " seen = MAX(messages.seen, excluded.seen),"
        " suspicious = excluded.suspicious, auth = excluded.auth,"
        " attach = CASE WHEN messages.attach > 1 AND excluded.attach = 1"
        " THEN messages.attach ELSE excluded.attach END,"
        // Same rule for crypto: a header refresh can only see the outer type,
        // so it must not undo "signed *and* encrypted" learned from the body.
        " crypto = CASE WHEN messages.crypto > excluded.crypto AND excluded.crypto > 0"
        " THEN messages.crypto ELSE excluded.crypto END,"
        // A header refresh only ever knows what the headers say, so it must not
        // undo a richer verdict: a score computed with the body (state 2), or a
        // sender the user has since cleared by hand (state 3), both outrank it.
        " spam_score = CASE WHEN messages.spam_state > excluded.spam_state"
        " THEN messages.spam_score ELSE excluded.spam_score END,"
        " spam_detail = CASE WHEN messages.spam_state > excluded.spam_state"
        " THEN messages.spam_detail ELSE excluded.spam_detail END,"
        " spam_state = MAX(messages.spam_state, excluded.spam_state),"
        // Same COALESCE rule as msgid: a producer that does not know the
        // backend id (the Thunderbird importer, an older cached row being
        // refreshed) must not erase one that is already recorded.
        " remote_id = COALESCE(excluded.remote_id, messages.remote_id),"
        // Same rule again: a producer that does not fill it (any folder that is
        // not Sent or Drafts) must not blank what is already recorded.
        // IFNULL, not a bare comparison: a producer that leaves the field
        // default-constructed binds SQL NULL, and NULL = '' is NULL, so the
        // CASE fell through and erased the stored value.
        " recipients = CASE WHEN IFNULL(excluded.recipients, '') = ''"
        " THEN messages.recipients ELSE excluded.recipients END"));
    QSqlQuery ins(db);
    if (ftsAvailable) {
        // Keyed by messages.rowid — an O(1) lookup. Never filter fts by its
        // UNINDEXED folder/uid columns here: that is a full-index scan.
        ins.prepare(QStringLiteral(
            "INSERT INTO fts (rowid, subject, sender, body, folder, uid)"
            " SELECT m.rowid, ?, ?, '', ?, ? FROM messages m"
            " WHERE m.folder = ? AND m.uid = ?"
            " AND NOT EXISTS (SELECT 1 FROM fts WHERE rowid = m.rowid)"));
    }
    // Familiarity counts messages, not sightings: storeHeaders runs again over
    // mail already cached on every refresh and rescore, so a blind increment
    // would let one much-refreshed folder invent a history the user never had.
    // The primary-key probe below is what makes it idempotent.
    QSqlQuery seenBefore(db);
    seenBefore.prepare(QStringLiteral(
        "SELECT 1 FROM messages WHERE folder = ? AND uid = ?"));
    QSqlQuery bumpOrg(db);
    bumpOrg.prepare(QStringLiteral(
        "INSERT INTO sender_domains (org, seen, first_seen, last_seen)"
        " VALUES (?, 1, ?, ?)"
        " ON CONFLICT(org) DO UPDATE SET"
        "  seen = seen + 1,"
        "  first_seen = MIN(first_seen, excluded.first_seen),"
        "  last_seen = MAX(last_seen, excluded.last_seen)"));

    for (const auto &h : headers) {
        seenBefore.addBindValue(key);
        seenBefore.addBindValue(h.uid);
        const bool isNew = !(seenBefore.exec() && seenBefore.next());
        seenBefore.finish();
        if (isNew) {
            const QString org =
                SpamHeuristics::organizationalDomainOf(SpamHeuristics::addressOf(h.from));
            const qint64 when = h.date.isValid() ? h.date.toSecsSinceEpoch() : 0;
            if (!org.isEmpty() && when > 0) {
                bumpOrg.addBindValue(org);
                bumpOrg.addBindValue(when);
                bumpOrg.addBindValue(when);
                bumpOrg.exec();
                bumpOrg.finish();
            }
        }

        q.addBindValue(key);
        q.addBindValue(h.uid);
        q.addBindValue(h.subject);
        q.addBindValue(h.from);
        q.addBindValue(h.date.toSecsSinceEpoch());
        q.addBindValue(h.seen ? 1 : 0);
        q.addBindValue(h.suspicious ? 1 : 0);
        q.addBindValue(h.authInfo);
        q.addBindValue(h.attachKind);
        q.addBindValue(h.msgid.isEmpty() ? QVariant(QMetaType(QMetaType::QString)) : h.msgid);
        q.addBindValue(h.crypto);
        q.addBindValue(h.spamScore);
        q.addBindValue(h.spamState);
        q.addBindValue(h.spamDetail);
        q.addBindValue(h.remoteId.isEmpty() ? QVariant(QMetaType(QMetaType::QString))
                                            : h.remoteId);
        q.addBindValue(h.to);
        q.exec();
        if (ftsAvailable) {
            ins.addBindValue(h.subject);
            ins.addBindValue(h.from);
            ins.addBindValue(key);
            ins.addBindValue(h.uid);
            ins.addBindValue(key);
            ins.addBindValue(h.uid);
            ins.exec();
        }
    }
    db.commit();
}

void MailStore::setSpamVerdict(const QString &folder, qint64 uid, int score, int state,
                               const QString &detail)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET spam_score = ?, spam_state = ?,"
                             " spam_detail = ? WHERE folder = ? AND uid = ?"));
    q.addBindValue(score);
    q.addBindValue(state);
    q.addBindValue(detail);
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

QList<MailStore::RawRow> MailStore::rawsMissingRecipientsOn(QSqlDatabase &db,
                                                            const QString &scopedFolder,
                                                            int limit)
{
    QList<RawRow> out;
    if (!db.isOpen())
        return out;
    QSqlQuery q(db);
    q.prepare(QStringLiteral(
        "SELECT m.uid, b.raw FROM messages m JOIN bodies b"
        " ON b.folder = m.folder AND b.uid = m.uid"
        " WHERE m.folder = ? AND IFNULL(m.recipients, '') = ''"
        " AND b.raw IS NOT NULL AND length(b.raw) > 0"
        " ORDER BY m.date DESC LIMIT ?"));
    q.addBindValue(scopedFolder);
    q.addBindValue(limit);
    if (!q.exec())
        return out;
    while (q.next())
        out.append({q.value(0).toLongLong(), q.value(1).toByteArray()});
    return out;
}

QStringList MailStore::allCachedFolderKeysOn(QSqlDatabase &db)
{
    QStringList out;
    if (!db.isOpen())
        return out;
    QSqlQuery q(db);
    if (!q.exec(QStringLiteral("SELECT DISTINCT folder FROM messages")))
        return out;
    while (q.next())
        out.append(q.value(0).toString());
    return out;
}

int MailStore::missingRecipientCountOn(QSqlDatabase &db, const QString &scopedFolder)
{
    if (!db.isOpen())
        return 0;
    QSqlQuery q(db);
    q.prepare(QStringLiteral(
        "SELECT COUNT(*) FROM messages m JOIN bodies b"
        " ON b.folder = m.folder AND b.uid = m.uid"
        " WHERE m.folder = ? AND IFNULL(m.recipients, '') = ''"
        " AND b.raw IS NOT NULL AND length(b.raw) > 0"));
    q.addBindValue(scopedFolder);
    return (q.exec() && q.next()) ? q.value(0).toInt() : 0;
}

void MailStore::setRecipientsBatchOn(QSqlDatabase &db, const QString &scopedFolder,
                                    const QHash<qint64, QString> &byUid)
{
    if (!db.isOpen() || byUid.isEmpty())
        return;
    db.transaction();
    QSqlQuery q(db);
    q.prepare(QStringLiteral("UPDATE messages SET recipients = ?"
                             " WHERE folder = ? AND uid = ?"));
    const QString key = scopedFolder;
    for (auto it = byUid.cbegin(); it != byUid.cend(); ++it) {
        // A message genuinely addressed to nobody (a Bcc-only send) would be
        // re-read on every pass otherwise, so it is marked done with a space
        // rather than left empty. The list trims it back to nothing.
        q.addBindValue(it.value().isEmpty() ? QStringLiteral(" ") : it.value());
        q.addBindValue(key);
        q.addBindValue(it.key());
        q.exec();
    }
    db.commit();
}

int MailStore::spamStateOf(const QString &folder, qint64 uid)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT spam_state FROM messages WHERE folder = ? AND uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    if (!q.exec() || !q.next())
        return 0;
    return q.value(0).toInt();
}

void MailStore::setAttachKind(const QString &folder, qint64 uid, int kind)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET attach = ? WHERE folder = ? AND uid = ?"));
    q.addBindValue(kind);
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

void MailStore::setCrypto(const QString &folder, qint64 uid, int kind)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET crypto = ? WHERE folder = ? AND uid = ?"));
    q.addBindValue(kind);
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

void MailStore::setColorLabel(const QString &folder, qint64 uid, int color)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET color = ? WHERE folder = ? AND uid = ?"));
    q.addBindValue(color);
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

MailStore::AuthVerdict MailStore::authVerdict(const QString &folder, qint64 uid)
{
    AuthVerdict v;
    if (!m_db.isOpen())
        return v;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT dkim, dkim_detail, dkim_trusted, arc, arc_sealer, arc_detail"
        " FROM messages WHERE folder = ? AND uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    if (q.exec() && q.next()) {
        v.dkimStatus = q.value(0).toString();
        v.dkimDetail = q.value(1).toString();
        v.dkimTrusted = q.value(2).toBool();
        v.arcStatus = q.value(3).toString();
        v.arcSealer = q.value(4).toString();
        v.arcDetail = q.value(5).toString();
    }
    return v;
}

void MailStore::storeAuthVerdict(const QString &folder, qint64 uid, const AuthVerdict &v)
{
    if (!m_db.isOpen() || v.isEmpty())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "UPDATE messages SET dkim = ?, dkim_detail = ?, dkim_trusted = ?,"
        " arc = ?, arc_sealer = ?, arc_detail = ? WHERE folder = ? AND uid = ?"));
    q.addBindValue(v.dkimStatus);
    q.addBindValue(v.dkimDetail);
    q.addBindValue(v.dkimTrusted ? 1 : 0);
    q.addBindValue(v.arcStatus);
    q.addBindValue(v.arcSealer);
    q.addBindValue(v.arcDetail);
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

QList<MailStore::AgedMessage> MailStore::messagesOlderThan(const QString &folder,
                                                           qint64 cutoffSecs)
{
    QList<AgedMessage> out;
    if (!m_db.isOpen() || folder.isEmpty())
        return out;
    QSqlQuery q(m_db);
    // date <= 0 is a message whose Date header was missing or unparseable —
    // the rows that show as 1970. Treated as old: a message that cannot say
    // when it was sent should not be able to sit in spam forever by saying
    // nothing.
    //
    // The remote id falls back to the uid in decimal, exactly as remoteIdFor()
    // does: that is what an IMAP backend expects, and what rows cached before
    // the remote_id column existed hold implicitly.
    q.prepare(QStringLiteral("SELECT uid, IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '') FROM messages"
                             " WHERE folder = ? AND (date < ? OR date <= 0)"));
    q.addBindValue(scoped(folder));
    q.addBindValue(cutoffSecs);
    if (!q.exec())
        return out;
    while (q.next())
        out.append({q.value(0).toLongLong(), q.value(1).toString()});
    return out;
}

void MailStore::setUnseen(const QString &folder, qint64 uid)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET seen = 0 WHERE folder = ? AND uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

QList<MailStore::AgedMessage> MailStore::unseenMessages(const QString &folder)
{
    QList<AgedMessage> out;
    if (!m_db.isOpen())
        return out;
    QSqlQuery q(m_db);
    // Same remote-id fallback as remoteIdFor(): rows cached before the
    // remote_id column existed carry the uid in decimal implicitly.
    q.prepare(QStringLiteral("SELECT uid, IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '') FROM messages"
                             " WHERE folder = ? AND seen = 0"));
    q.addBindValue(scoped(folder));
    if (!q.exec())
        return out;
    while (q.next())
        out.append({q.value(0).toLongLong(), q.value(1).toString()});
    return out;
}

void MailStore::setFolderSeen(const QString &folder)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET seen = 1"
                             " WHERE folder = ? AND seen = 0"));
    q.addBindValue(scoped(folder));
    q.exec();
}

void MailStore::setSeen(const QString &folder, qint64 uid)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("UPDATE messages SET seen = 1 WHERE folder = ? AND uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.exec();
}

QList<qint64> MailStore::uidsWithoutBody(const QString &folder, int limit)
{
    QList<qint64> out;
    if (!m_db.isOpen())
        return out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT m.uid FROM messages m"
        " LEFT JOIN bodies b ON b.folder = m.folder AND b.uid = m.uid"
        " LEFT JOIN body_skipped s ON s.folder = m.folder AND s.uid = m.uid"
        " WHERE m.folder = ? AND b.uid IS NULL AND s.uid IS NULL"
        " ORDER BY m.date DESC, m.uid DESC LIMIT ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(limit);
    if (q.exec()) {
        while (q.next())
            out.append(q.value(0).toLongLong());
    }
    return out;
}

int MailStore::missingBodyCount(const QString &folder)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT COUNT(*) FROM messages m"
        " LEFT JOIN bodies b ON b.folder = m.folder AND b.uid = m.uid"
        " LEFT JOIN body_skipped s ON s.folder = m.folder AND s.uid = m.uid"
        " WHERE m.folder = ? AND b.uid IS NULL AND s.uid IS NULL"));
    q.addBindValue(scoped(folder));
    return (q.exec() && q.next()) ? q.value(0).toInt() : 0;
}

void MailStore::skipBody(const QString &folder, qint64 uid, qint64 size)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO body_skipped (folder, uid, size) VALUES (?, ?, ?)"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    q.addBindValue(size);
    q.exec();
}

int MailStore::unskipBodiesUpTo(qint64 maxSize)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    // maxSize <= 0 means "no limit" — everything previously refused is fair
    // game again, so the backfill picks it up on its next pass.
    if (maxSize <= 0) {
        q.exec(QStringLiteral("DELETE FROM body_skipped"));
    } else {
        q.prepare(QStringLiteral("DELETE FROM body_skipped WHERE size <= ?"));
        q.addBindValue(maxSize);
        q.exec();
    }
    return q.numRowsAffected();
}

QString MailStore::remoteIdFor(const QString &folder, qint64 uid)
{
    if (!m_db.isOpen())
        return {};
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT IFNULL(remote_id, CAST(uid AS TEXT)), IFNULL(recipients, '') FROM messages"
                             " WHERE folder = ? AND uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    if (q.exec() && q.next())
        return q.value(0).toString();
    return {};
}

QByteArray MailStore::cachedBody(const QString &folder, qint64 uid)
{
    if (!m_db.isOpen())
        return {};
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT raw FROM bodies WHERE folder = ? AND uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    if (q.exec() && q.next())
        return q.value(0).toByteArray();
    return {};
}

void MailStore::storeParts(const QString &folder, qint64 uid, const QList<PartRef> &parts)
{
    storePartsOn(m_db, scoped(folder), uid, parts);
}

void MailStore::storePartsOn(QSqlDatabase &db, const QString &key, qint64 uid,
                             const QList<PartRef> &parts)
{
    if (!db.isOpen() || parts.isEmpty())
        return;
    QSqlQuery att(db);
    // The payload row may already exist from another message referencing the
    // same bytes; only the reference count moves in that case.
    att.prepare(QStringLiteral(
        "INSERT INTO attachments (hash, size, stored, codec, refs, last_used)"
        " VALUES (?, ?, ?, ?, 1, ?)"
        " ON CONFLICT(hash) DO UPDATE SET refs = refs + 1, last_used = excluded.last_used"));
    QSqlQuery part(db);
    part.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO message_parts"
        " (folder, uid, part_id, hash, filename, mime, encoding) VALUES (?, ?, ?, ?, ?, ?, ?)"));
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (const PartRef &p : parts) {
        att.addBindValue(p.hash);
        att.addBindValue(p.size);
        att.addBindValue(p.stored);
        att.addBindValue(p.codec);
        att.addBindValue(now);
        att.exec();
        part.addBindValue(key);
        part.addBindValue(uid);
        part.addBindValue(p.partId);
        part.addBindValue(p.hash);
        part.addBindValue(p.filename);
        part.addBindValue(p.mime);
        part.addBindValue(QString()); // encoding: payloads are stored decoded
        part.exec();
    }
}

QList<MailStore::PartRef> MailStore::partsFor(const QString &folder, qint64 uid)
{
    QList<PartRef> out;
    if (!m_db.isOpen())
        return out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT p.part_id, p.hash, p.filename, p.mime, a.size, a.stored, a.codec"
        " FROM message_parts p LEFT JOIN attachments a ON a.hash = p.hash"
        " WHERE p.folder = ? AND p.uid = ?"));
    q.addBindValue(scoped(folder));
    q.addBindValue(uid);
    if (!q.exec())
        return out;
    while (q.next()) {
        PartRef p;
        p.partId = q.value(0).toString();
        p.hash = q.value(1).toString();
        p.filename = q.value(2).toString();
        p.mime = q.value(3).toString();
        p.size = q.value(4).toLongLong();
        p.stored = q.value(5).toLongLong();
        p.codec = q.value(6).toInt();
        out.append(p);
    }
    return out;
}

qint64 MailStore::releaseParts(const QString &scopedFolder, const QList<qint64> &uids)
{
    return releasePartsOn(m_db, scopedFolder, uids);
}

qint64 MailStore::releasePartsOn(QSqlDatabase &db, const QString &scopedFolder,
                                 const QList<qint64> &uids)
{
    if (!db.isOpen() || uids.isEmpty())
        return 0;
    QStringList uidList;
    uidList.reserve(uids.size());
    for (qint64 u : uids)
        uidList << QString::number(u);
    const QString uidIn = uidList.join(QLatin1Char(','));

    // Which payloads do these messages reference, and how many times?
    QHash<QString, int> releasing;
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral("SELECT hash FROM message_parts"
                                 " WHERE folder = ? AND uid IN (%1)")
                      .arg(uidIn));
        q.addBindValue(scopedFolder);
        if (q.exec()) {
            while (q.next())
                releasing[q.value(0).toString()] += 1;
        }
    }
    if (releasing.isEmpty())
        return 0;

    QSqlQuery del(db);
    del.prepare(QStringLiteral("DELETE FROM message_parts WHERE folder = ? AND uid IN (%1)")
                    .arg(uidIn));
    del.addBindValue(scopedFolder);
    del.exec();

    qint64 freed = 0;
    QSqlQuery dec(db);
    dec.prepare(QStringLiteral("UPDATE attachments SET refs = refs - ? WHERE hash = ?"));
    QSqlQuery look(db);
    look.prepare(QStringLiteral("SELECT refs, stored FROM attachments WHERE hash = ?"));
    QSqlQuery drop(db);
    drop.prepare(QStringLiteral("DELETE FROM attachments WHERE hash = ?"));
    for (auto it = releasing.cbegin(); it != releasing.cend(); ++it) {
        dec.addBindValue(it.value());
        dec.addBindValue(it.key());
        dec.exec();
        look.addBindValue(it.key());
        if (!look.exec() || !look.next())
            continue;
        if (look.value(0).toLongLong() > 0)
            continue; // still referenced by another message
        freed += look.value(1).toLongLong();
        drop.addBindValue(it.key());
        drop.exec();
        AttachmentStore::remove(it.key());
    }
    return freed;
}

qint64 MailStore::attachmentBytes()
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral("SELECT IFNULL(SUM(stored), 0) FROM attachments")) || !q.next())
        return 0;
    return q.value(0).toLongLong();
}

bool MailStore::attachmentMigrationPending()
{
    return m_db.isOpen() && !migrationDone(m_db, QStringLiteral("attach_migrate1"));
}

int MailStore::migrateAttachmentsChunk(
    QSqlDatabase &db, qint64 &cursor, int limit, qint64 &bytesSaved,
    const std::function<QByteArray(const QByteArray &, QList<PartRef> *)> &splitFn)
{
    if (!db.isOpen() || limit <= 0)
        return 0;
    // Keyset pagination by rowid: OFFSET would re-walk the whole table on
    // every chunk, and rows are being rewritten underneath us as we go.
    struct Row {
        qint64 rowid;
        QString folder;
        qint64 uid;
        QByteArray raw;
    };
    QList<Row> rows;
    {
        QSqlQuery q(db);
        q.prepare(QStringLiteral(
            "SELECT rowid, folder, uid, raw FROM bodies WHERE rowid > ?"
            " ORDER BY rowid LIMIT ?"));
        q.addBindValue(cursor);
        q.addBindValue(limit);
        if (!q.exec())
            return 0;
        while (q.next())
            rows.append({q.value(0).toLongLong(), q.value(1).toString(),
                         q.value(2).toLongLong(), q.value(3).toByteArray()});
    }
    if (rows.isEmpty())
        return 0;

    db.transaction();
    QSqlQuery upd(db);
    upd.prepare(QStringLiteral("UPDATE bodies SET raw = ? WHERE rowid = ?"));
    for (const Row &row : rows) {
        cursor = row.rowid;
        QList<PartRef> parts;
        const QByteArray stub = splitFn(row.raw, &parts);
        if (parts.isEmpty())
            continue; // nothing big enough to lift out
        bytesSaved += row.raw.size() - stub.size();
        upd.addBindValue(stub);
        upd.addBindValue(row.rowid);
        upd.exec();
        storePartsOn(db, row.folder, row.uid, parts);
    }
    QSqlQuery cur(db);
    cur.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO meta_values (key, value) VALUES ('attach_migrate_cursor', ?)"));
    cur.addBindValue(QString::number(cursor));
    cur.exec();
    if (!db.commit())
        db.rollback();
    return rows.size();
}

void MailStore::finishAttachmentMigration(QSqlDatabase &db)
{
    markMigrationDone(db, QStringLiteral("attach_migrate1"));
}

int MailStore::sweepOrphanAttachments()
{
    if (!m_db.isOpen())
        return 0;
    const QStringList onDisk = AttachmentStore::allHashes();
    if (onDisk.isEmpty())
        return 0;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT 1 FROM attachments WHERE hash = ?"));
    int removed = 0;
    for (const QString &hash : onDisk) {
        q.addBindValue(hash);
        if (q.exec() && q.next())
            continue; // known payload
        if (AttachmentStore::remove(hash))
            ++removed;
    }
    return removed;
}

QSqlDatabase MailStore::openWorkerConnection(const QString &name)
{
    QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), name);
    db.setDatabaseName(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                       + QStringLiteral("/mailove.db"));
    if (!db.open()) {
        qWarning() << "mailstore: worker connection failed:" << db.lastError().text();
        return {};
    }
    QSqlQuery pragma(db);
    // Several connections write now; each must wait rather than fail.
    pragma.exec(QStringLiteral("PRAGMA busy_timeout=15000"));
    return db;
}

void MailStore::writeBodiesOn(QSqlDatabase &db, const QList<BodyWrite> &batch)
{
    if (!db.isOpen() || batch.isEmpty())
        return;
    db.transaction();
    QSqlQuery body(db);
    body.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO bodies (folder, uid, raw) VALUES (?, ?, ?)"));
    QSqlQuery del(db);
    del.prepare(QStringLiteral(
        "DELETE FROM fts WHERE rowid ="
        " (SELECT rowid FROM messages WHERE folder = ? AND uid = ?)"));
    QSqlQuery ins(db);
    ins.prepare(QStringLiteral(
        "INSERT INTO fts (rowid, subject, sender, body, folder, uid)"
        " SELECT rowid, subject, sender, ?, folder, uid FROM messages"
        " WHERE folder = ? AND uid = ?"));
    QSqlQuery done(db);
    done.prepare(QStringLiteral("DELETE FROM fts_pending WHERE folder = ? AND uid = ?"));
    for (const BodyWrite &w : batch) {
        body.addBindValue(w.scopedFolder);
        body.addBindValue(w.uid);
        body.addBindValue(w.raw);
        body.exec();
        del.addBindValue(w.scopedFolder);
        del.addBindValue(w.uid);
        del.exec();
        ins.addBindValue(w.indexText);
        ins.addBindValue(w.scopedFolder);
        ins.addBindValue(w.uid);
        ins.exec();
        done.addBindValue(w.scopedFolder);
        done.addBindValue(w.uid);
        done.exec();
        // Part rows share the stub's transaction: a payload file with no row
        // is recoverable (the orphan sweep deletes it), a row with no file is
        // not — the message would read back with an empty attachment.
        storePartsOn(db, w.scopedFolder, w.uid, w.parts);
    }
    if (!db.commit())
        db.rollback();
}

void MailStore::removeBodyOnly(const QString &folder, qint64 uid)
{
    if (!m_db.isOpen())
        return;
    const QString key = scoped(folder);
    m_db.transaction();
    releasePartsOn(m_db, key, {uid});
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("DELETE FROM bodies WHERE folder = ? AND uid = ?"));
    q.addBindValue(key);
    q.addBindValue(uid);
    q.exec();
    m_db.commit();
}

void MailStore::storeBody(const QString &folder, qint64 uid, const QByteArray &raw,
                          const QString &indexText)
{
    if (!m_db.isOpen() || raw.isEmpty())
        return;
    SlowGuard guard("storeBody");
    m_db.transaction();
    const QString key = scoped(folder);
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO bodies (folder, uid, raw) VALUES (?, ?, ?)"));
    q.addBindValue(key);
    q.addBindValue(uid);
    q.addBindValue(raw);
    q.exec();

    if (m_ftsAvailable) {
        // Re-index this message with the body text included (rowid-keyed —
        // filtering fts on folder/uid would scan the whole index).
        QSqlQuery del(m_db);
        del.prepare(QStringLiteral(
            "DELETE FROM fts WHERE rowid ="
            " (SELECT rowid FROM messages WHERE folder = ? AND uid = ?)"));
        del.addBindValue(key);
        del.addBindValue(uid);
        del.exec();
        QSqlQuery ins(m_db);
        ins.prepare(QStringLiteral(
            "INSERT INTO fts (rowid, subject, sender, body, folder, uid)"
            " SELECT rowid, subject, sender, ?, folder, uid FROM messages"
            " WHERE folder = ? AND uid = ?"));
        ins.addBindValue(indexText);
        ins.addBindValue(key);
        ins.addBindValue(uid);
        ins.exec();
        // Freshly indexed — no background re-index needed anymore.
        QSqlQuery done(m_db);
        done.prepare(QStringLiteral("DELETE FROM fts_pending WHERE folder = ? AND uid = ?"));
        done.addBindValue(key);
        done.addBindValue(uid);
        done.exec();
    }
    m_db.commit();
}

QList<MailStore::PendingBody> MailStore::pendingBodyIndex(int limit)
{
    QList<PendingBody> out;
    if (!m_db.isOpen() || !m_ftsAvailable)
        return out;
    QSqlQuery q(m_db);
    // CROSS JOIN, not JOIN: it is the one way to pin the join order. A plain
    // JOIN lets SQLite drive from `bodies` and probe fts_pending per row, and
    // it does — which with an empty queue means scanning every row of a
    // quarter-million-row table to return nothing, on the GUI thread, on every
    // tick of a 300 ms timer. Driving from fts_pending costs exactly as many
    // primary-key lookups as there are queued rows (none, when there are none).
    q.prepare(QStringLiteral(
        "SELECT b.folder, b.uid, b.raw FROM fts_pending p"
        " CROSS JOIN bodies b ON b.folder = p.folder AND b.uid = p.uid LIMIT ?"));
    q.addBindValue(limit);
    if (q.exec()) {
        while (q.next()) {
            PendingBody p;
            p.scopedFolder = q.value(0).toString();
            p.uid = q.value(1).toLongLong();
            p.raw = q.value(2).toByteArray();
            out.append(p);
        }
    }
    // Only rows without a cached body can be left once the join comes back
    // empty — they can never be indexed, so drop them and finish the rebuild.
    if (out.isEmpty())
        q.exec(QStringLiteral("DELETE FROM fts_pending"));
    return out;
}

void MailStore::finishBodyIndex(const QString &scopedFolder, qint64 uid,
                                const QString &indexText)
{
    if (!m_db.isOpen())
        return;
    SlowGuard guard("finishBodyIndex");
    m_db.transaction();
    if (m_ftsAvailable) {
        QSqlQuery del(m_db);
        del.prepare(QStringLiteral(
            "DELETE FROM fts WHERE rowid ="
            " (SELECT rowid FROM messages WHERE folder = ? AND uid = ?)"));
        del.addBindValue(scopedFolder);
        del.addBindValue(uid);
        del.exec();
        QSqlQuery ins(m_db);
        ins.prepare(QStringLiteral(
            "INSERT INTO fts (rowid, subject, sender, body, folder, uid)"
            " SELECT rowid, IFNULL(subject, ''), IFNULL(sender, ''), ?, folder, uid"
            " FROM messages WHERE folder = ? AND uid = ?"));
        ins.addBindValue(indexText);
        ins.addBindValue(scopedFolder);
        ins.addBindValue(uid);
        ins.exec();
    }
    QSqlQuery done(m_db);
    done.prepare(QStringLiteral("DELETE FROM fts_pending WHERE folder = ? AND uid = ?"));
    done.addBindValue(scopedFolder);
    done.addBindValue(uid);
    done.exec();
    m_db.commit();
}

void MailStore::finishBodyIndexBatch(
    const QList<std::tuple<QString, qint64, QString>> &entries)
{
    if (!m_db.isOpen() || entries.isEmpty())
        return;
    SlowGuard guard("finishBodyIndexBatch");
    // One transaction for the whole batch. Per-message commits meant one fsync
    // per cached body — 122k of them on a full index rebuild.
    m_db.transaction();
    QSqlQuery del(m_db);
    del.prepare(QStringLiteral(
        "DELETE FROM fts WHERE rowid ="
        " (SELECT rowid FROM messages WHERE folder = ? AND uid = ?)"));
    QSqlQuery ins(m_db);
    ins.prepare(QStringLiteral(
        "INSERT INTO fts (rowid, subject, sender, body, folder, uid)"
        " SELECT rowid, IFNULL(subject, ''), IFNULL(sender, ''), ?, folder, uid"
        " FROM messages WHERE folder = ? AND uid = ?"));
    QSqlQuery done(m_db);
    done.prepare(QStringLiteral("DELETE FROM fts_pending WHERE folder = ? AND uid = ?"));
    for (const auto &entry : entries) {
        const QString &folder = std::get<0>(entry);
        const qint64 uid = std::get<1>(entry);
        if (m_ftsAvailable) {
            del.addBindValue(folder);
            del.addBindValue(uid);
            del.exec();
            ins.addBindValue(std::get<2>(entry));
            ins.addBindValue(folder);
            ins.addBindValue(uid);
            ins.exec();
        }
        done.addBindValue(folder);
        done.addBindValue(uid);
        done.exec();
    }
    m_db.commit();
}

void MailStore::removeMessages(const QString &folder, const QList<qint64> &uids)
{
    if (!m_db.isOpen() || uids.isEmpty())
        return;
    SlowGuard guard("removeMessages");
    m_db.transaction();
    // Give back the attachment references first: once the part rows are gone
    // the payloads on disk would have no way of ever being freed.
    releaseParts(scoped(folder), uids);
    // Same shape of bookkeeping for the compose autocompletion: an address is
    // only forgotten once no Sent message holds it any more. A no-op for every
    // folder but Sent, which is the only one with refs.
    dropSentRecipients(folder, uids);
    // fts first (rowid-keyed via messages, which must still exist), then the
    // regular tables.
    if (m_ftsAvailable) {
        QSqlQuery q(m_db);
        q.prepare(QStringLiteral(
            "DELETE FROM fts WHERE rowid ="
            " (SELECT rowid FROM messages WHERE folder = ? AND uid = ?)"));
        for (qint64 uid : uids) {
            q.addBindValue(scoped(folder));
            q.addBindValue(uid);
            q.exec();
        }
    }
    for (const char *table : {"messages", "bodies"}) {
        QSqlQuery q(m_db);
        q.prepare(QStringLiteral("DELETE FROM %1 WHERE folder = ? AND uid = ?")
                      .arg(QLatin1String(table)));
        for (qint64 uid : uids) {
            q.addBindValue(scoped(folder));
            q.addBindValue(uid);
            q.exec();
        }
    }
    m_db.commit();
}

qint64 MailStore::uidValidity(const QString &folder)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT uidvalidity FROM account_folders WHERE account = ? AND mailbox = ?"));
    q.addBindValue(m_accountKey);
    q.addBindValue(folder);
    return (q.exec() && q.next()) ? q.value(0).toLongLong() : 0;
}

void MailStore::setUidValidity(const QString &folder, qint64 validity)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "UPDATE account_folders SET uidvalidity = ? WHERE account = ? AND mailbox = ?"));
    q.addBindValue(validity);
    q.addBindValue(m_accountKey);
    q.addBindValue(folder);
    q.exec();
}

QString MailStore::syncState(const QString &folder)
{
    return syncStateIn(m_accountKey, folder);
}

QString MailStore::syncStateIn(const QString &account, const QString &folder)
{
    if (!m_db.isOpen())
        return {};
    QSqlQuery q(m_db);
    // The UIDVALIDITY fallback: rows written before sync_state existed hold
    // their resume point in the older column, and an IMAP backend's token is
    // that number spelled as text — so the two are the same value and reading
    // one for the other is exact, not an approximation. NULLIF keeps a folder
    // that never recorded either (uidvalidity 0) reading as "no position".
    q.prepare(QStringLiteral(
        "SELECT IFNULL(NULLIF(sync_state, ''), NULLIF(CAST(uidvalidity AS TEXT), '0'))"
        " FROM account_folders WHERE account = ? AND mailbox = ?"));
    q.addBindValue(account);
    q.addBindValue(folder);
    return (q.exec() && q.next()) ? q.value(0).toString() : QString();
}

void MailStore::setSyncState(const QString &folder, const QString &state)
{
    setSyncStateIn(m_accountKey, folder, state);
}

void MailStore::setSyncStateIn(const QString &account, const QString &folder,
                               const QString &state)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "UPDATE account_folders SET sync_state = ? WHERE account = ? AND mailbox = ?"));
    q.addBindValue(state);
    q.addBindValue(account);
    q.addBindValue(folder);
    q.exec();
}

void MailStore::clearFolder(const QString &folder)
{
    if (!m_db.isOpen())
        return;
    SlowGuard guard("clearFolder");
    m_db.transaction();
    QSqlQuery q(m_db);
    // Attachment payloads are refcounted, so the folder's references have to
    // be given back before its part rows go — otherwise the files leak.
    {
        QList<qint64> uids;
        QSqlQuery pick(m_db);
        pick.prepare(QStringLiteral("SELECT uid FROM message_parts WHERE folder = ?"));
        pick.addBindValue(scoped(folder));
        if (pick.exec()) {
            while (pick.next())
                uids.append(pick.value(0).toLongLong());
        }
        releaseParts(scoped(folder), uids);
    }
    // The refs, but not the recipients: this is the cache being thrown away
    // and re-synced, not mail being deleted. Nobody stopped being someone the
    // user wrote to because the server reset its UIDVALIDITY.
    forgetRecipientRefs(folder);
    // fts first: its rows are found via messages rowids, so the messages
    // rows must still be there.
    if (m_ftsAvailable) {
        q.prepare(QStringLiteral(
            "DELETE FROM fts WHERE rowid IN"
            " (SELECT rowid FROM messages WHERE folder = ?)"));
        q.addBindValue(scoped(folder));
        q.exec();
    }
    for (const char *table : {"messages", "bodies"}) {
        q.prepare(QStringLiteral("DELETE FROM %1 WHERE folder = ?").arg(QLatin1String(table)));
        q.addBindValue(scoped(folder));
        q.exec();
    }
    m_db.commit();
}

void MailStore::renameFolderOn(QSqlDatabase &db, const QString &account,
                               const QString &oldFolder, const QString &newFolder,
                               QChar separator)
{
    if (!db.isOpen() || oldFolder.isEmpty() || newFolder.isEmpty()
        || oldFolder == newFolder || separator.isNull())
        return;

    const auto key = [&account](const QString &folder) {
        return account.isEmpty() ? folder : account + QChar(0x1f) + folder;
    };
    const QString oldKey = key(oldFolder);
    const QString newKey = key(newFolder);

    // The subtree is every key starting with "<oldKey><separator>". Written as
    // a half-open range rather than a LIKE so SQLite can seek the (folder, uid)
    // primary key instead of scanning tables that hold gigabytes of bodies.
    const auto range = [separator](const QString &prefix) {
        const QString lo = prefix + separator;
        QString hi = lo;
        hi[hi.size() - 1] = QChar(ushort(separator.unicode() + 1));
        return std::pair<QString, QString>{lo, hi};
    };
    const auto [lo, hi] = range(oldKey);
    const auto [boxLo, boxHi] = range(oldFolder);

    db.transaction();
    QSqlQuery q(db);
    // fts rows are keyed by messages.rowid, which an UPDATE of a non-rowid
    // column preserves — and its own folder column is UNINDEXED and never
    // filtered on (search() joins on rowid), so the index needs no touching.
    for (const char *table : {"messages", "bodies", "body_skipped", "message_parts"}) {
        const QString name = QLatin1String(table);
        // OR REPLACE: a folder of the same name may have been cached at the
        // destination before; the moved rows are the current truth.
        q.prepare(QStringLiteral("UPDATE OR REPLACE %1 SET folder = ? WHERE folder = ?").arg(name));
        q.addBindValue(newKey);
        q.addBindValue(oldKey);
        q.exec();

        q.prepare(QStringLiteral("UPDATE OR REPLACE %1 SET folder = ? || substr(folder, ?)"
                                 " WHERE folder >= ? AND folder < ?").arg(name));
        q.addBindValue(newKey);
        q.addBindValue(oldKey.size() + 1);
        q.addBindValue(lo);
        q.addBindValue(hi);
        q.exec();
    }

    // The per-account folder list stores bare mailbox paths, not scoped keys.
    q.prepare(QStringLiteral("UPDATE OR REPLACE account_folders SET mailbox = ?"
                             " WHERE account = ? AND mailbox = ?"));
    q.addBindValue(newFolder);
    q.addBindValue(account);
    q.addBindValue(oldFolder);
    q.exec();
    q.prepare(QStringLiteral("UPDATE OR REPLACE account_folders"
                             " SET mailbox = ? || substr(mailbox, ?)"
                             " WHERE account = ? AND mailbox >= ? AND mailbox < ?"));
    q.addBindValue(newFolder);
    q.addBindValue(oldFolder.size() + 1);
    q.addBindValue(account);
    q.addBindValue(boxLo);
    q.addBindValue(boxHi);
    q.exec();
    db.commit();
}

QHash<QString, int> MailStore::unreadCountsOn(QSqlDatabase &db, const QString &account)
{
    QHash<QString, int> out;
    if (!db.isOpen() || account.isEmpty())
        return out;

    QSqlQuery q(db);
    // A partial index over unread rows only. The full (folder, seen) index
    // would be one entry per cached message — hundreds of thousands of them,
    // for a question about the few that are unread. This one holds only the
    // unread rows, so it stays small and the count below is an index-only
    // range scan.
    //
    // Building it is still one pass over `messages`, which is why this runs on
    // a worker connection and is done once, recorded in meta_flags. Without it
    // the planner picked idx_messages_color and had to visit every row of the
    // account in the table to read `seen`.
    if (!migrationDone(db, QStringLiteral("unseen_index1"))) {
        if (q.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS idx_messages_unseen"
                                  " ON messages(folder) WHERE seen = 0")))
            markMigrationDone(db, QStringLiteral("unseen_index1"));
    }

    // Half-open range over "account\x1f<folder>", the same trick renameFolderOn
    // uses — a LIKE could not seek the index.
    const QString lo = account + QChar(0x1f);
    QString hi = lo;
    hi[hi.size() - 1] = QChar(0x20);

    q.prepare(QStringLiteral("SELECT folder, count(*) FROM messages"
                             " WHERE folder >= ? AND folder < ? AND seen = 0"
                             " GROUP BY folder"));
    q.addBindValue(lo);
    q.addBindValue(hi);
    if (!q.exec())
        return out;
    while (q.next()) {
        const QString key = q.value(0).toString();
        const int count = q.value(1).toInt();
        if (count > 0)
            out.insert(key.mid(lo.size()), count); // strip the account scope
    }
    return out;
}

int MailStore::purgeChunkOn(QSqlDatabase &db, const QString &key, int limit)
{
    if (!db.isOpen() || key.isEmpty() || limit <= 0)
        return 0;

    // Take one chunk of rowids up front: fts is keyed by messages.rowid, so
    // every delete below is driven by the same fixed set and the three tables
    // cannot drift apart if a later statement fails.
    QList<qint64> rowids;
    QList<qint64> uids;
    {
        QSqlQuery pick(db);
        pick.prepare(QStringLiteral(
            "SELECT rowid, uid FROM messages WHERE folder = ? LIMIT ?"));
        pick.addBindValue(key);
        pick.addBindValue(limit);
        if (pick.exec()) {
            while (pick.next()) {
                rowids.append(pick.value(0).toLongLong());
                uids.append(pick.value(1).toLongLong());
            }
        }
    }

    if (rowids.isEmpty()) {
        // Headers are gone; sweep any bodies left behind (a body can outlive
        // its header if a previous purge was interrupted between the two).
        QSqlQuery rest(db);
        rest.prepare(QStringLiteral(
            "DELETE FROM bodies WHERE rowid IN"
            " (SELECT rowid FROM bodies WHERE folder = ? LIMIT ?)"));
        rest.addBindValue(key);
        rest.addBindValue(limit);
        return (rest.exec() ? rest.numRowsAffected() : 0);
    }

    QStringList rowList;
    rowList.reserve(rowids.size());
    for (qint64 r : std::as_const(rowids))
        rowList << QString::number(r);
    QStringList uidList;
    uidList.reserve(uids.size());
    for (qint64 u : std::as_const(uids))
        uidList << QString::number(u);
    // Numeric ids straight from SQL — no user input, so inlining them (rather
    // than binding N placeholders) is safe and keeps this to three statements.
    const QString rowIn = rowList.join(QLatin1Char(','));
    const QString uidIn = uidList.join(QLatin1Char(','));

    db.transaction();
    // Hand back this chunk's attachment references before its rows go, or the
    // payload files would be orphaned with no row left to free them.
    releasePartsOn(db, key, uids);
    QSqlQuery q(db);
    // fts may be absent on a build without FTS5; the DELETE then simply fails.
    q.exec(QStringLiteral("DELETE FROM fts WHERE rowid IN (%1)").arg(rowIn));
    q.prepare(QStringLiteral("DELETE FROM fts_pending WHERE folder = ? AND uid IN (%1)")
                  .arg(uidIn));
    q.addBindValue(key);
    q.exec();
    // The refs go with the rows they point at, but no recipient is pruned
    // here: this is cache eviction, not deletion. Nobody threw the mail away,
    // mailove just stopped keeping a copy of it, and forgetting who it was
    // addressed to is not part of that bargain.
    q.prepare(QStringLiteral("DELETE FROM recipient_refs WHERE folder = ? AND uid IN (%1)")
                  .arg(uidIn));
    q.addBindValue(key);
    q.exec();
    q.prepare(QStringLiteral("DELETE FROM bodies WHERE folder = ? AND uid IN (%1)").arg(uidIn));
    q.addBindValue(key);
    q.exec();
    q.exec(QStringLiteral("DELETE FROM messages WHERE rowid IN (%1)").arg(rowIn));
    const int removed = q.numRowsAffected();
    if (!db.commit()) {
        db.rollback();
        return 0;
    }
    return removed > 0 ? removed : rowids.size();
}

void MailStore::purgeFolder(const QString &scopedFolder, const QAtomicInt &cancel,
                            const std::function<void(int)> &progress)
{
    const QString name = QStringLiteral("mailstore-purge");
    int total = 0;
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), name);
        db.setDatabaseName(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                           + QStringLiteral("/mailove.db"));
        if (db.open()) {
            QSqlQuery pragma(db);
            // The GUI thread is the other writer. Chunks are small enough that
            // it never waits long, but it must be willing to wait at all.
            pragma.exec(QStringLiteral("PRAGMA busy_timeout=15000"));
            // 100 rows keeps a single write-lock hold to a few ms, so a folder
            // switch on the GUI thread is never stuck behind this.
            while (!cancel.loadRelaxed()) {
                const int removed = purgeChunkOn(db, scopedFolder, 100);
                if (removed <= 0)
                    break;
                total += removed;
                if (progress)
                    progress(total);
                // Yield the write lock between chunks — without this the purge
                // would hold it back-to-back and starve the GUI thread.
                QThread::msleep(20);
            }
            db.close();
        }
    }
    QSqlDatabase::removeDatabase(name);
}

qint64 MailStore::databaseBytes() const
{
    return m_db.isOpen() ? QFileInfo(m_db.databaseName()).size() : 0;
}

qint64 MailStore::reclaimableBytes()
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery q(m_db);
    if (!q.exec(QStringLiteral("SELECT * FROM pragma_freelist_count(), pragma_page_size()"))
        || !q.next())
        return 0;
    return q.value(0).toLongLong() * q.value(1).toLongLong();
}

bool MailStore::vacuum(QString *error)
{
    // Its own connection, so this can run on a worker thread while the GUI
    // thread's "mailstore" connection stays put. The connection name is unique
    // per call — a stale one left by a previous failed run would be reused
    // with the wrong thread affinity.
    const QString name = QStringLiteral("mailstore-vacuum");
    bool ok = false;
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), name);
        db.setDatabaseName(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                           + QStringLiteral("/mailove.db"));
        if (!db.open()) {
            if (error)
                *error = db.lastError().text();
        } else {
            QSqlQuery q(db);
            // No busy_timeout would make this fail instantly whenever the GUI
            // thread happens to hold a write lock.
            q.exec(QStringLiteral("PRAGMA busy_timeout=30000"));
            ok = q.exec(QStringLiteral("VACUUM"));
            if (!ok && error)
                *error = q.lastError().text();
            db.close();
        }
    }
    QSqlDatabase::removeDatabase(name);
    return ok;
}

QString MailStore::messageIdFromHead(const QByteArray &head)
{
    static const QRegularExpression re(
        QStringLiteral("^Message-ID\\s*:(.*?)(?=\\r?\\n[^ \\t]|\\z)"),
        QRegularExpression::MultilineOption | QRegularExpression::DotMatchesEverythingOption
            | QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(QString::fromLatin1(head));
    if (!m.hasMatch())
        return {};
    QString v = m.captured(1);
    v.remove(QLatin1Char('\r'));
    v.remove(QLatin1Char('\n'));
    const int lt = v.indexOf(QLatin1Char('<'));
    const int gt = v.lastIndexOf(QLatin1Char('>'));
    if (lt >= 0 && gt > lt)
        v = v.mid(lt + 1, gt - lt - 1);
    return v.trimmed();
}

int MailStore::backfillMessageIds(int limit)
{
    if (!m_db.isOpen())
        return 0;
    QSqlQuery sel(m_db);
    // Reads only the head of each body: pulling whole payloads here would drag
    // gigabytes through for a value that always lives in the first few KB.
    // Rows with no cached body are not joined and stay NULL, which is honest —
    // we genuinely do not know their Message-ID yet.
    sel.prepare(QStringLiteral(
        "SELECT m.folder, m.uid, substr(b.raw, 1, 16384) FROM messages m"
        " JOIN bodies b ON b.folder = m.folder AND b.uid = m.uid"
        " WHERE m.msgid IS NULL LIMIT ?"));
    sel.addBindValue(limit);
    if (!sel.exec())
        return 0;

    struct Row {
        QString folder;
        qint64 uid;
        QString msgid;
    };
    QList<Row> rows;
    while (sel.next()) {
        rows.append({sel.value(0).toString(), sel.value(1).toLongLong(),
                     messageIdFromHead(sel.value(2).toByteArray())});
    }
    if (rows.isEmpty())
        return 0;

    QSqlQuery upd(m_db);
    upd.prepare(QStringLiteral("UPDATE messages SET msgid = ? WHERE folder = ? AND uid = ?"));
    m_db.transaction();
    for (const Row &r : rows) {
        // '' rather than NULL when the message carries no Message-ID, so the
        // next pass does not pick the same rows up again forever.
        upd.addBindValue(r.msgid);
        upd.addBindValue(r.folder);
        upd.addBindValue(r.uid);
        upd.exec();
    }
    m_db.commit();
    return rows.size();
}

QList<QPair<QString, qint64>> MailStore::locateByMessageId(const QString &msgid)
{
    QList<QPair<QString, qint64>> out;
    if (!m_db.isOpen() || msgid.isEmpty())
        return out;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT folder, uid FROM messages WHERE msgid = ?"));
    q.addBindValue(msgid);
    if (!q.exec())
        return out;
    while (q.next())
        out.append({q.value(0).toString(), q.value(1).toLongLong()});
    return out;
}

bool MailStore::headIndicatesAttachment(const QByteArray &head)
{
    static const QRegularExpression ctRe(
        QStringLiteral("(?:^|\\n)content-type:((?:[^\\n]|\\n[ \\t])*)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch m = ctRe.match(QString::fromLatin1(head));
    return m.hasMatch()
        && m.captured(1).contains(QLatin1String("multipart/mixed"), Qt::CaseInsensitive);
}

bool MailStore::remoteContentAllowedFor(const QString &sender)
{
    if (!m_db.isOpen() || sender.isEmpty())
        return false;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT 1 FROM remote_senders WHERE sender = ?"));
    q.addBindValue(sender);
    return q.exec() && q.next();
}

void MailStore::setRemoteContentAllowedFor(const QString &sender, bool allowed)
{
    if (!m_db.isOpen() || sender.isEmpty())
        return;
    QSqlQuery q(m_db);
    if (allowed)
        q.prepare(QStringLiteral("INSERT OR IGNORE INTO remote_senders (sender) VALUES (?)"));
    else
        q.prepare(QStringLiteral("DELETE FROM remote_senders WHERE sender = ?"));
    q.addBindValue(sender);
    q.exec();
}

void MailStore::addRecipient(const QString &address, const QString &name)
{
    if (!m_db.isOpen() || m_accountKey.isEmpty() || !address.contains(QLatin1Char('@')))
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "INSERT INTO recipients (account, address, addr_norm, name, last_used, use_count)"
        " VALUES (?, ?, ?, ?, ?, 1)"
        " ON CONFLICT(account, address) DO UPDATE SET"
        "  use_count = use_count + 1, last_used = excluded.last_used,"
        "  addr_norm = excluded.addr_norm,"
        "  name = CASE WHEN excluded.name != '' THEN excluded.name ELSE name END"));
    q.addBindValue(m_accountKey);
    q.addBindValue(address.trimmed().toLower());
    q.addBindValue(SpamHeuristics::normalizeAddress(address));
    q.addBindValue(name.trimmed());
    q.addBindValue(QDateTime::currentSecsSinceEpoch());
    q.exec();
}

void MailStore::addSentRecipient(const QString &folder, qint64 uid, const QString &address,
                                 const QString &name)
{
    if (!m_db.isOpen() || m_accountKey.isEmpty() || uid < 0
        || !address.contains(QLatin1Char('@')))
        return;
    QSqlQuery ref(m_db);
    ref.prepare(QStringLiteral(
        "INSERT OR IGNORE INTO recipient_refs (account, folder, uid, address)"
        " VALUES (?, ?, ?, ?)"));
    ref.addBindValue(m_accountKey);
    ref.addBindValue(scoped(folder));
    ref.addBindValue(uid);
    ref.addBindValue(address.trimmed().toLower());
    if (!ref.exec() || ref.numRowsAffected() <= 0)
        return; // this message was already counted — opening it again is not
                // a second use, and treating it as one is what made use_count
                // drift away from anything a delete could undo.
    addRecipient(address, name);
}

void MailStore::dropSentRecipients(const QString &folder, const QList<qint64> &uids)
{
    if (!m_db.isOpen() || uids.isEmpty())
        return;
    QStringList uidList;
    uidList.reserve(uids.size());
    for (qint64 u : uids)
        uidList << QString::number(u);
    dropRecipientRefs(QStringLiteral("folder = ? AND uid IN (%1)").arg(uidList.join(
                          QLatin1Char(','))),
                      scoped(folder));
}

void MailStore::forgetRecipientRefs(const QString &folder)
{
    if (!m_db.isOpen())
        return;
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("DELETE FROM recipient_refs WHERE folder = ?"));
    q.addBindValue(scoped(folder));
    q.exec();
}

void MailStore::dropRecipientRefs(const QString &where, const QString &scopedFolder)
{
    // Which addresses are at stake has to be read before the refs go — the
    // whole question afterwards is whether any *other* message still holds
    // them, and the answer changes as soon as these rows are deleted.
    QStringList addresses;
    {
        QSqlQuery pick(m_db);
        pick.prepare(QStringLiteral("SELECT DISTINCT address FROM recipient_refs WHERE ")
                     + where);
        pick.addBindValue(scopedFolder);
        if (pick.exec()) {
            while (pick.next())
                addresses.append(pick.value(0).toString());
        }
    }
    if (addresses.isEmpty())
        return;

    QSqlQuery del(m_db);
    del.prepare(QStringLiteral("DELETE FROM recipient_refs WHERE ") + where);
    del.addBindValue(scopedFolder);
    del.exec();

    // Only addresses that just lost a ref are considered, so an address that
    // never had one (typed into compose, allowlisted out of spam) cannot be
    // reached by this at all.
    QSqlQuery prune(m_db);
    prune.prepare(QStringLiteral(
        "DELETE FROM recipients WHERE account = ? AND address = ?"
        " AND NOT EXISTS (SELECT 1 FROM recipient_refs"
        "                 WHERE account = ? AND address = ?)"));
    for (const QString &address : std::as_const(addresses)) {
        prune.addBindValue(m_accountKey);
        prune.addBindValue(address);
        prune.addBindValue(m_accountKey);
        prune.addBindValue(address);
        prune.exec();
    }
}

void MailStore::addSentRecipientsOn(QSqlDatabase &db, const QString &account,
                                    const QString &scopedFolder,
                                    const QList<SentRecipient> &batch)
{
    if (!db.isOpen() || batch.isEmpty())
        return;
    db.transaction();
    QSqlQuery ref(db);
    ref.prepare(QStringLiteral(
        "INSERT OR IGNORE INTO recipient_refs (account, folder, uid, address)"
        " VALUES (?, ?, ?, ?)"));
    QSqlQuery rcpt(db);
    rcpt.prepare(QStringLiteral(
        "INSERT INTO recipients (account, address, addr_norm, name, last_used, use_count)"
        " VALUES (?, ?, ?, ?, ?, 1)"
        " ON CONFLICT(account, address) DO UPDATE SET"
        "  use_count = use_count + 1, last_used = excluded.last_used,"
        "  addr_norm = excluded.addr_norm,"
        "  name = CASE WHEN excluded.name != '' THEN excluded.name ELSE name END"));
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (const SentRecipient &r : batch) {
        const QString address = r.address.trimmed().toLower();
        if (!address.contains(QLatin1Char('@')))
            continue;
        ref.addBindValue(account);
        ref.addBindValue(scopedFolder);
        ref.addBindValue(r.uid);
        ref.addBindValue(address);
        if (!ref.exec() || ref.numRowsAffected() <= 0)
            continue;
        rcpt.addBindValue(account);
        rcpt.addBindValue(address);
        rcpt.addBindValue(SpamHeuristics::normalizeAddress(address));
        rcpt.addBindValue(r.name.trimmed());
        rcpt.addBindValue(now);
        rcpt.exec();
    }
    db.commit();
}

bool MailStore::isKnownCorrespondent(const QString &address)
{
    if (!m_db.isOpen())
        return false;
    const QString needle = SpamHeuristics::normalizeAddress(address);
    if (needle.isEmpty() || !needle.contains(QLatin1Char('@')))
        return false;
    // Deliberately not filtered by account: a person you wrote to from one
    // address is the same person when they write to another of yours, and
    // scoping the allowlist per account would mark their reply as spam in every
    // mailbox but the one you happened to use.
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral("SELECT 1 FROM recipients WHERE addr_norm = ? LIMIT 1"));
    q.addBindValue(needle);
    return q.exec() && q.next();
}

QSet<QString> MailStore::knownCorrespondents(const QSet<QString> &addresses)
{
    QSet<QString> out;
    if (!m_db.isOpen() || addresses.isEmpty())
        return out;
    // One statement for a whole FETCH batch. Scoring runs over every header the
    // sync delivers, and a query per message would put a few thousand round
    // trips on the path that also has to keep the list responsive.
    QStringList needles;
    needles.reserve(addresses.size());
    for (const QString &a : addresses) {
        const QString n = SpamHeuristics::normalizeAddress(a);
        if (!n.isEmpty() && n.contains(QLatin1Char('@')))
            needles.append(n);
    }
    if (needles.isEmpty())
        return out;
    // Chunked: SQLite's default parameter limit is 999, and a large folder can
    // easily deliver more distinct senders than that in one batch.
    constexpr int chunk = 500;
    for (qsizetype start = 0; start < needles.size(); start += chunk) {
        const QStringList slice = needles.mid(start, chunk);
        const QString placeholders =
            QStringList(slice.size(), QStringLiteral("?")).join(QLatin1Char(','));
        QSqlQuery q(m_db);
        q.prepare(QStringLiteral("SELECT DISTINCT addr_norm FROM recipients"
                                 " WHERE addr_norm IN (%1)")
                      .arg(placeholders));
        for (const QString &n : slice)
            q.addBindValue(n);
        if (!q.exec())
            continue;
        while (q.next())
            out.insert(q.value(0).toString());
    }
    return out;
}

QSet<QString> MailStore::knownMessageIds(const QSet<QString> &msgids)
{
    QSet<QString> out;
    if (!m_db.isOpen() || msgids.isEmpty())
        return out;
    QStringList needles;
    needles.reserve(msgids.size());
    for (const QString &raw : msgids) {
        QString id = raw.trimmed();
        if (id.startsWith(QLatin1Char('<')) && id.endsWith(QLatin1Char('>')))
            id = id.mid(1, id.size() - 2);
        if (!id.isEmpty())
            needles.append(id);
    }
    if (needles.isEmpty())
        return out;
    // Chunked exactly as knownCorrespondents() is, and for the same reason: a
    // References header can name a dozen ancestors, so one batch of headers can
    // ask about far more ids than SQLite will bind at once.
    constexpr int chunk = 500;
    for (qsizetype start = 0; start < needles.size(); start += chunk) {
        const QStringList slice = needles.mid(start, chunk);
        const QString placeholders =
            QStringList(slice.size(), QStringLiteral("?")).join(QLatin1Char(','));
        QSqlQuery q(m_db);
        q.prepare(QStringLiteral("SELECT DISTINCT msgid FROM messages WHERE msgid IN (%1)")
                      .arg(placeholders));
        for (const QString &n : slice)
            q.addBindValue(n);
        if (!q.exec())
            continue;
        while (q.next())
            out.insert(q.value(0).toString());
    }
    return out;
}

QHash<QString, MailStore::DomainHistory>
MailStore::senderDomainHistory(const QSet<QString> &orgs)
{
    QHash<QString, DomainHistory> out;
    if (!m_db.isOpen() || orgs.isEmpty())
        return out;
    const QStringList list(orgs.cbegin(), orgs.cend());
    // Same chunking as knownCorrespondents, for the same reason: one statement
    // per FETCH batch rather than one per message, and never more bound
    // parameters than SQLite's default limit allows.
    constexpr int chunk = 500;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (qsizetype start = 0; start < list.size(); start += chunk) {
        const QStringList slice = list.mid(start, chunk);
        const QString placeholders =
            QStringList(slice.size(), QStringLiteral("?")).join(QLatin1Char(','));
        QSqlQuery q(m_db);
        q.prepare(QStringLiteral("SELECT org, seen, first_seen FROM sender_domains"
                                 " WHERE org IN (%1)")
                      .arg(placeholders));
        for (const QString &o : slice)
            q.addBindValue(o);
        if (!q.exec())
            continue;
        while (q.next()) {
            DomainHistory h;
            h.seen = q.value(1).toInt();
            const qint64 first = q.value(2).toLongLong();
            // Age is measured to now rather than to last_seen: what the scorer
            // is asking is "has this domain been around a while", and a domain
            // that wrote fifty times last Tuesday should not read as old.
            h.days = first > 0 && now > first ? static_cast<int>((now - first) / 86400) : 0;
            out.insert(q.value(0).toString(), h);
        }
    }
    return out;
}

QStringList MailStore::recipientCompletions(const QString &prefix, int limit)
{
    QStringList out;
    const QString needle = prefix.trimmed().toLower();
    if (!m_db.isOpen() || m_accountKey.isEmpty() || needle.isEmpty())
        return out;
    QString esc = needle;
    esc.replace(QLatin1Char('\\'), QLatin1String("\\\\"))
        .replace(QLatin1Char('%'), QLatin1String("\\%"))
        .replace(QLatin1Char('_'), QLatin1String("\\_"));
    QSqlQuery q(m_db);
    q.prepare(QStringLiteral(
        "SELECT address FROM recipients WHERE account = ?"
        " AND (address LIKE ? ESCAPE '\\' OR lower(name) LIKE ? ESCAPE '\\')"
        " ORDER BY use_count DESC, last_used DESC LIMIT ?"));
    q.addBindValue(m_accountKey);
    const QString pattern = QLatin1Char('%') + esc + QLatin1Char('%');
    q.addBindValue(pattern);
    q.addBindValue(pattern);
    q.addBindValue(limit);
    if (q.exec()) {
        while (q.next())
            out.append(q.value(0).toString());
    }
    return out;
}

QList<MessageListModel::Header> MailStore::search(const QString &folder,
                                                  const QString &keyword, bool byRecipient)
{
    QList<MessageListModel::Header> out;
    if (!m_db.isOpen())
        return out;
    SlowGuard guard("search");
    searchOn(m_db, scoped(folder), keyword, m_ftsAvailable,
             [&out](const QList<MessageListModel::Header> &batch) {
                 out += batch;
                 return true;
             },
             false, byRecipient);
    return out;
}

void MailStore::searchOn(QSqlDatabase &db, const QString &scopedFolder, const QString &keyword,
                         bool ftsAvailable, const SearchSink &deliver, bool headersOnly,
                         bool byRecipient)
{
    if (!db.isOpen() || keyword.trimmed().isEmpty())
        return;
    QSet<qint64> seen;
    bool cancelled = false;

    // Handed over in batches rather than at the end: the two passes below walk
    // an index that may hold a hundred thousand rows for the folder, and the
    // reader wants the first names on screen while that is still going. The
    // sink returns false to abandon a search whose answer nobody is waiting for
    // any more — a newer query, or a folder switch.
    constexpr int kBatch = 10;
    const auto readRows = [&](QSqlQuery &q) {
        QList<MessageListModel::Header> batch;
        while (q.next()) {
            MessageListModel::Header h;
            h.uid = q.value(0).toLongLong();
            if (seen.contains(h.uid))
                continue;
            seen.insert(h.uid);
            h.subject = q.value(1).toString();
            h.from = q.value(2).toString();
            h.date = QDateTime::fromSecsSinceEpoch(q.value(3).toLongLong());
            h.seen = q.value(4).toBool();
            h.suspicious = q.value(5).toBool();
            h.authInfo = q.value(6).toString();
            h.attachKind = q.value(7).toInt();
            h.colorLabel = q.value(8).toInt();
            h.spamScore = q.value(9).toInt();
            h.spamState = q.value(10).toInt();
            h.spamDetail = q.value(11).toString();
            h.to = q.value(12).toString();
            batch.append(h);
            if (batch.size() < kBatch)
                continue;
            if (!deliver(batch)) {
                cancelled = true;
                return;
            }
            batch.clear();
        }
        if (!batch.isEmpty() && !deliver(batch))
            cancelled = true;
    };

    if (ftsAvailable) {
        QSqlQuery q(db);
        // MATCH must be a one-shot subquery, not a JOIN: with the join, the
        // planner put messages on the outside and re-ran the whole FTS query
        // for every row of the folder — tens of seconds where this form is
        // milliseconds (EXPLAIN: LIST SUBQUERY vs SCAN f per row).
        q.prepare(QStringLiteral(
            "SELECT m.uid, m.subject, m.sender, m.date, m.seen, m.suspicious, m.auth, m.attach,"
            " m.color, m.spam_score, m.spam_state, m.spam_detail, IFNULL(m.recipients, '')"
            " FROM messages m"
            " WHERE m.rowid IN (SELECT rowid FROM fts WHERE fts MATCH ?)"
            " AND m.folder = ? ORDER BY m.date DESC LIMIT 200"));
        // Quote as a literal phrase so FTS5 operators in user input can't
        // break it; the trailing * makes it a prefix query, so partial words
        // match too ("hung" finds "hungarian").
        QString phrase = keyword;
        phrase.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        // {subject sender} is fts5's column filter — body stays out of the
        // match when only headers are wanted.
        // The index has no recipients column — adding one means rebuilding it,
        // and the substring pass below already answers a name in To. So a
        // recipient search narrows FTS to the subject and lets LIKE do the rest.
        const QString columns = byRecipient ? QStringLiteral("{subject}")
                                            : QStringLiteral("{subject sender}");
        q.addBindValue(headersOnly ? QStringLiteral("%1 : \"%2\"*").arg(columns, phrase)
                                   : QStringLiteral("\"%1\"*").arg(phrase));
        q.addBindValue(scopedFolder);
        if (q.exec())
            readRows(q);
        else
            qWarning() << "mailstore: fts search failed:" << q.lastError().text();
    }
    if (cancelled)
        return;

    // Substring pass over subject/sender — catches word-internal fragments
    // the token-based FTS index cannot ("gari" inside "hungarian").
    QSqlQuery like(db);
    like.prepare(QStringLiteral(
        "SELECT uid, subject, sender, date, seen, suspicious, auth, attach, color,"
        " spam_score, spam_state, spam_detail, IFNULL(recipients, '') FROM messages"
        " WHERE folder = ? AND (subject LIKE ? ESCAPE '\\' OR %1 LIKE ? ESCAPE '\\')"
        " ORDER BY date DESC LIMIT 200")
                     // Whichever column the list is showing. In Sent every row
                     // has the same sender, so matching it finds the whole
                     // folder or nothing — the recipient is the name a person
                     // is actually looking for there.
                     .arg(byRecipient ? QStringLiteral("recipients")
                                      : QStringLiteral("sender")));
    QString escaped = keyword;
    escaped.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    escaped.replace(QLatin1Char('%'), QStringLiteral("\\%"));
    escaped.replace(QLatin1Char('_'), QStringLiteral("\\_"));
    const QString pattern = QLatin1Char('%') + escaped + QLatin1Char('%');
    like.addBindValue(scopedFolder);
    like.addBindValue(pattern);
    like.addBindValue(pattern);
    if (like.exec())
        readRows(like);
}

// --- Diacritics-folding index rebuild --------------------------------------
//
// The tokenizer of an fts5 table is fixed at creation, so teaching the index to
// ignore accents means building a second one and swapping it in. It is done in
// slices on a worker, with the cursor persisted, because the index is as large
// as the mail that produced it: a single statement would hold the write lock
// for minutes and quitting halfway would throw the work away.

bool MailStore::beginFtsRebuild(QSqlDatabase &db)
{
    QSqlQuery q(db);
    if (!q.exec(QStringLiteral(
            "CREATE VIRTUAL TABLE IF NOT EXISTS fts_dia USING fts5("
            " subject, sender, body, folder UNINDEXED, uid UNINDEXED,"
            " tokenize = \"unicode61 remove_diacritics 2\")"))) {
        qWarning() << "mailstore: cannot create the folded index:" << q.lastError().text();
        return false;
    }
    return true;
}

qint64 MailStore::ftsRebuildCursor(QSqlDatabase &db)
{
    QSqlQuery q(db);
    q.prepare(QStringLiteral("SELECT value FROM meta_values WHERE key = 'fts_dia_cursor'"));
    return (q.exec() && q.next()) ? q.value(0).toLongLong() : 0;
}

int MailStore::copyFtsChunk(QSqlDatabase &db, qint64 *cursor, int limit)
{
    // Copied out of the old index rather than re-derived from the messages and
    // bodies: the body column holds text that cost a MIME parse to produce, and
    // re-extracting it for every cached message would turn minutes into days.
    QSqlQuery read(db);
    read.prepare(QStringLiteral(
        "SELECT rowid, subject, sender, body, folder, uid FROM fts"
        " WHERE rowid > ? ORDER BY rowid LIMIT ?"));
    read.addBindValue(*cursor);
    read.addBindValue(limit);
    if (!read.exec()) {
        qWarning() << "mailstore: index rebuild read failed:" << read.lastError().text();
        return -1;
    }

    db.transaction();
    QSqlQuery write(db);
    write.prepare(QStringLiteral(
        "INSERT INTO fts_dia (rowid, subject, sender, body, folder, uid)"
        " VALUES (?, ?, ?, ?, ?, ?)"));
    int copied = 0;
    qint64 last = *cursor;
    while (read.next()) {
        last = read.value(0).toLongLong();
        write.addBindValue(last);
        write.addBindValue(read.value(1));
        write.addBindValue(read.value(2));
        write.addBindValue(read.value(3));
        write.addBindValue(read.value(4));
        write.addBindValue(read.value(5));
        if (!write.exec()) {
            qWarning() << "mailstore: index rebuild write failed:" << write.lastError().text();
            db.rollback();
            return -1;
        }
        ++copied;
    }
    QSqlQuery mark(db);
    mark.prepare(QStringLiteral(
        "INSERT OR REPLACE INTO meta_values (key, value) VALUES ('fts_dia_cursor', ?)"));
    mark.addBindValue(QString::number(last));
    mark.exec();
    db.commit();
    *cursor = last;
    return copied;
}

bool MailStore::finishFtsRebuild(QSqlDatabase &db)
{
    // One transaction for the swap itself: at no point may a reader find the
    // search index missing.
    db.transaction();
    QSqlQuery q(db);
    const bool ok = q.exec(QStringLiteral("DROP TABLE fts"))
        && q.exec(QStringLiteral("ALTER TABLE fts_dia RENAME TO fts"))
        && q.exec(QStringLiteral("DELETE FROM meta_values WHERE key = 'fts_dia_cursor'"));
    if (!ok) {
        qWarning() << "mailstore: index swap failed, keeping the old index:"
                   << q.lastError().text();
        db.rollback();
        return false;
    }
    db.commit();
    return true;
}

qint64 MailStore::indexedMessageCount(QSqlDatabase &db)
{
    QSqlQuery q(db);
    // messages, not fts: counting an fts5 table means walking its own storage,
    // and this is only the denominator of a percentage.
    return (q.exec(QStringLiteral("SELECT count(*) FROM messages")) && q.next())
        ? q.value(0).toLongLong()
        : 0;
}

void MailStore::queueForReindex(QSqlDatabase &db, const QList<BodyWrite> &batch)
{
    if (!db.isOpen() || batch.isEmpty())
        return;
    QSqlQuery q(db);
    q.prepare(QStringLiteral(
        "INSERT OR IGNORE INTO fts_pending (folder, uid) VALUES (?, ?)"));
    for (const BodyWrite &w : batch) {
        q.addBindValue(w.scopedFolder);
        q.addBindValue(w.uid);
        q.exec();
    }
}
