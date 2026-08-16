// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "jmapbackend.h"

#include "jmaprequest.h"
#include "jmapsession.h"

#include "advancedconfig.h"

#include <KMime/Message>

#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QTimer>

namespace
{
/// How many blob downloads to keep in the air. HTTP does not serialize, but a
/// server states maxConcurrentRequests for a reason and the whole point of the
/// backfill is that nobody is waiting on it.
int kMaxConcurrentBodies() { return AdvancedConfig::i("jmap/maxConcurrentBodies"); }
/// A single message body. Larger than any mail worth rendering, and small
/// enough that a server answering with something else does not exhaust memory.
qint64 kMaxBodyBytes() { return AdvancedConfig::i("jmap/maxBodyBytes"); }
int kBodyTimeoutMs() { return AdvancedConfig::i("jmap/bodyTimeoutMs"); }
/// An upload answers with a four-field JSON object (RFC 8620 §6.1). The cap is
/// so a server answering with something else — an HTML error page from a proxy
/// in front of it — cannot be read into memory unbounded.
qint64 kMaxUploadReplyBytes() { return AdvancedConfig::i("jmap/maxUploadReplyBytes"); }
/// How many changes to ask for in one `Email/changes`. A cap the client sets
/// rather than the server, so a folder that has been away for months arrives in
/// pages that can be merged as they come instead of one reply holding
/// everything. `hasMoreChanges` is what says another call is due.
int kMaxChangesPerCall() { return AdvancedConfig::i("jmap/maxChangesPerCall"); }

/// How often the server should send a keepalive comment down the EventSource.
/// Not for us — the stream would work without it — but for everything between
/// us and the server: a NAT or proxy that sees nothing for minutes closes the
/// connection, and a client that has stopped receiving push has no way to
/// notice that from silence alone.
int kPushPingSeconds() { return AdvancedConfig::i("jmap/pushPingSeconds"); }
/// One StateChange is a small JSON object. The cap is a guard against a server
/// (or something in front of it) streaming bytes that are not events at all,
/// which would otherwise grow this buffer without bound.
int kMaxPushBufferBytes() { return AdvancedConfig::i("jmap/maxPushBufferBytes"); }
int kPushBaseRetryMs() { return AdvancedConfig::i("jmap/pushBaseRetryMs"); }
int kPushMaxBackoffShift() { return AdvancedConfig::i("jmap/pushMaxBackoffShift"); } ///< 2s → ~4min before the cap applies
int kPushMaxRetryMs() { return AdvancedConfig::i("jmap/pushMaxRetryMs"); }

QString jmapString(const QJsonObject &object, const char *key)
{
    return object.value(QLatin1String(key)).toString();
}
} // namespace

QChar JmapBackend::pathSeparator()
{
    return QLatin1Char('/');
}

JmapBackend::JmapBackend(QObject *parent)
    : MailBackend(parent)
{
    m_session = new JmapSession(this);

    connect(m_session, &JmapSession::ready, this, [this] {
        if (m_connected)
            return;
        m_connected = true;
        Q_EMIT connectedChanged(true);
    });
    connect(m_session, &JmapSession::failed, this,
            [this](Error error, const QString &message) {
                const bool wasConnected = m_connected;
                m_connected = false;
                Q_EMIT errorOccurred(error, message);
                if (wasConnected) {
                    Q_EMIT connectionLost();
                    Q_EMIT connectedChanged(false);
                }
            });
}

JmapBackend::~JmapBackend() = default;

void JmapBackend::connectAccount(const Credentials &credentials)
{
    m_session->discover(credentials);
}

void JmapBackend::disconnectAccount()
{
    stopPush();
    m_session->cancel();
    m_session->clear();
    m_bodyQueue.clear();
    m_bodyBatchDone.clear();
    m_bodyBatchOutstanding.clear();
    m_bodiesInFlight = 0;
    m_mailboxes.clear();
    m_pathById.clear();
    m_idByPath.clear();
    m_blobIds.clear();
    m_openFolder.clear();
    m_emailState.clear();
    m_mailboxState.clear();
    // Identities belong to the account this session authenticated as, so they
    // must not survive it: reconnecting as somebody else and submitting under
    // the previous account's identity is the one failure here that would reach
    // a recipient.
    m_identityByEmail.clear();
    m_defaultIdentityId.clear();
    m_identitiesFetched = false;
    if (m_connected) {
        m_connected = false;
        Q_EMIT connectedChanged(false);
    }
}

JmapRequest *JmapBackend::newRequest()
{
    if (!m_session->isValid())
        return nullptr;
    return new JmapRequest(m_session, this);
}

void JmapBackend::report(const OpCallback &done, Error error, const QString &message)
{
    if (done)
        done(error, message);
    if (error != Error::None)
        Q_EMIT errorOccurred(error, message);
}

QString JmapBackend::mailboxId(const QString &path) const
{
    return m_idByPath.value(path);
}

// --- Translations ----------------------------------------------------------

QByteArray JmapBackend::headerBlockFromJmap(const QJsonArray &headers)
{
    QByteArray block;
    for (const QJsonValue &value : headers) {
        const QJsonObject header = value.toObject();
        const QString name = header.value(QLatin1String("name")).toString();
        if (name.isEmpty())
            continue;
        // The value arrives exactly as it sat on the wire, leading space and
        // folding included, so nothing is added between the colon and it.
        block += name.toUtf8();
        block += ':';
        block += header.value(QLatin1String("value")).toString().toUtf8();
        block += "\r\n";
    }
    return block;
}

QStringList JmapBackend::flagsFromKeywords(const QJsonObject &keywords)
{
    QStringList flags;
    if (keywords.value(QLatin1String("$seen")).toBool())
        flags.append(QStringLiteral("seen"));
    if (keywords.value(QLatin1String("$draft")).toBool())
        flags.append(QStringLiteral("draft"));
    if (keywords.value(QLatin1String("$flagged")).toBool())
        flags.append(QStringLiteral("flagged"));
    // No "deleted": JMAP has no such keyword. A message is deleted by being
    // removed from every mailbox, which is a move, not a flag.
    return flags;
}

MailBackend::FolderRole JmapBackend::roleFromJmap(const QString &role)
{
    if (role == QLatin1String("inbox"))
        return FolderRole::Inbox;
    if (role == QLatin1String("sent"))
        return FolderRole::Sent;
    if (role == QLatin1String("drafts"))
        return FolderRole::Drafts;
    if (role == QLatin1String("trash"))
        return FolderRole::Trash;
    if (role == QLatin1String("junk"))
        return FolderRole::Junk;
    if (role == QLatin1String("archive"))
        return FolderRole::Archive;
    if (role == QLatin1String("all"))
        return FolderRole::All;
    return FolderRole::None;
}

qint64 JmapBackend::hashedLocalKey(const QString &remoteId)
{
    const QByteArray digest =
        QCryptographicHash::hash(remoteId.toUtf8(), QCryptographicHash::Sha256);
    quint64 key = 0;
    for (int i = 0; i < 8; ++i)
        key = (key << 8) | static_cast<quint8>(digest.at(i));
    // Positive: the value travels through qint64 columns and comparisons that
    // have no reason to meet a negative id.
    return static_cast<qint64>(key & 0x7fffffffffffffffULL);
}

// --- Folders ---------------------------------------------------------------

void JmapBackend::rebuildPaths(const QList<Mailbox> &mailboxes)
{
    m_mailboxes.clear();
    m_pathById.clear();
    m_idByPath.clear();
    for (const Mailbox &mailbox : mailboxes)
        m_mailboxes.insert(mailbox.id, mailbox);

    // Walk up parentId for each mailbox. The guard is not paranoia: parentId
    // comes off the wire and a cycle would otherwise hang the GUI thread.
    for (const Mailbox &mailbox : mailboxes) {
        QStringList parts;
        QString current = mailbox.id;
        int depth = 0;
        while (!current.isEmpty() && depth++ < 64) {
            const auto it = m_mailboxes.constFind(current);
            if (it == m_mailboxes.constEnd())
                break;
            parts.prepend(it->name);
            current = it->parentId;
        }
        const QString path = parts.join(pathSeparator());
        m_pathById.insert(mailbox.id, path);
        m_idByPath.insert(path, mailbox.id);
    }
}

JmapBackend::Mailbox JmapBackend::mailboxFromJson(const QJsonObject &object)
{
    Mailbox mailbox;
    mailbox.id = jmapString(object, "id");
    mailbox.name = jmapString(object, "name");
    mailbox.parentId = jmapString(object, "parentId");
    mailbox.role = jmapString(object, "role");
    mailbox.total = object.value(QLatin1String("totalEmails")).toInt();
    mailbox.unread = object.value(QLatin1String("unreadEmails")).toInt();
    return mailbox;
}

void JmapBackend::emitFolderList()
{
    QList<FolderInfo> folders;
    folders.reserve(m_mailboxes.size());
    for (auto it = m_mailboxes.constBegin(); it != m_mailboxes.constEnd(); ++it) {
        FolderInfo info;
        info.path = m_pathById.value(it->id);
        info.separator = pathSeparator();
        // JMAP has no \Noselect: every mailbox holds mail, and a container is
        // simply one that happens to be empty.
        info.selectable = true;
        info.role = roleFromJmap(it->role);
        folders.append(info);
    }
    Q_EMIT foldersListed(folders, pathSeparator());
}

void JmapBackend::listFolders()
{
    // A tree already learned is topped up rather than fetched again. The saving
    // is not the mailbox list itself — that is small — but the per-mailbox
    // properties: an account with hundreds of folders sends all of them on
    // every refresh, where a delta sends the handful that moved.
    if (m_mailboxState.isEmpty() || m_mailboxes.isEmpty())
        listAllMailboxes();
    else
        listChangedMailboxes();
}

void JmapBackend::listAllMailboxes()
{
    JmapRequest *request = newRequest();
    if (!request) {
        Q_EMIT errorOccurred(Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    request->addCall(QStringLiteral("Mailbox/get"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("ids"), QJsonValue::Null}});
    request->send([this, request](Error error, const QList<JmapRequest::Response> &responses,
                                  const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            Q_EMIT errorOccurred(error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            Q_EMIT errorOccurred(JmapRequest::errorForType(failed.errorType()),
                                 tr("The server refused to list mailboxes (%1).")
                                     .arg(failed.errorType()));
            return;
        }
        if (responses.isEmpty())
            return;

        QList<Mailbox> mailboxes;
        const QJsonArray list =
            responses.first().arguments.value(QLatin1String("list")).toArray();
        for (const QJsonValue &value : list) {
            const Mailbox mailbox = mailboxFromJson(value.toObject());
            if (!mailbox.id.isEmpty())
                mailboxes.append(mailbox);
        }
        rebuildPaths(mailboxes);
        // Where the next delta starts. Recorded only on a listing that
        // succeeded, so a refused one leaves the previous position usable.
        m_mailboxState = responses.first().arguments.value(QLatin1String("state")).toString();
        emitFolderList();
    });
}

void JmapBackend::listChangedMailboxes()
{
    JmapRequest *request = newRequest();
    if (!request) {
        Q_EMIT errorOccurred(Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    const QString changesId = request->addCall(
        QStringLiteral("Mailbox/changes"),
        QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                    {QStringLiteral("sinceState"), m_mailboxState},
                    {QStringLiteral("maxChanges"), kMaxChangesPerCall()}});
    // Created and updated are fetched together — the tree is merged from both
    // the same way, an id we have being an update and one we do not being new.
    for (const char *path : {"/created", "/updated"}) {
        request->addCall(
            QStringLiteral("Mailbox/get"),
            QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                        {QStringLiteral("#ids"),
                         JmapRequest::resultReference(changesId,
                                                      QStringLiteral("Mailbox/changes"),
                                                      QString::fromLatin1(path))}});
    }

    request->send([this, request](Error error, const QList<JmapRequest::Response> &responses,
                                  const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            Q_EMIT errorOccurred(error, message);
            return;
        }

        // The server's change log no longer reaches our position. Unlike the
        // message case this costs nothing to recover from — the tree is small
        // and re-listing it is what the first connection does anyway — so it
        // is not folderInvalidated() material.
        for (const JmapRequest::Response &response : responses) {
            if (response.isError()
                && response.errorType() == QLatin1String("cannotCalculateChanges")) {
                m_mailboxState.clear();
                listAllMailboxes();
                return;
            }
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            Q_EMIT errorOccurred(JmapRequest::errorForType(failed.errorType()),
                                 tr("The server refused to report mailbox changes (%1).")
                                     .arg(failed.errorType()));
            return;
        }

        QString newState;
        bool hasMore = false;
        for (const JmapRequest::Response &response : responses) {
            if (response.method == QLatin1String("Mailbox/changes")) {
                newState = response.arguments.value(QLatin1String("newState")).toString();
                hasMore = response.arguments.value(QLatin1String("hasMoreChanges")).toBool();
                const QJsonArray destroyed =
                    response.arguments.value(QLatin1String("destroyed")).toArray();
                for (const QJsonValue &value : destroyed)
                    m_mailboxes.remove(value.toString());
                continue;
            }
            if (response.method != QLatin1String("Mailbox/get"))
                continue;
            const QJsonArray list = response.arguments.value(QLatin1String("list")).toArray();
            for (const QJsonValue &value : list) {
                const Mailbox mailbox = mailboxFromJson(value.toObject());
                if (!mailbox.id.isEmpty())
                    m_mailboxes.insert(mailbox.id, mailbox);
            }
        }

        if (!newState.isEmpty())
            m_mailboxState = newState;
        // Another page before anyone is told: a half-merged tree would list
        // folders whose parents had not arrived yet, and the paths built from
        // it would be wrong rather than merely incomplete.
        if (hasMore && !newState.isEmpty()) {
            listChangedMailboxes();
            return;
        }
        rebuildPathsFromCache();
        emitFolderList();
    });
}

void JmapBackend::openFolder(const QString &folder, const QString &syncToken)
{
    const QString id = mailboxId(folder);
    if (id.isEmpty()) {
        Q_EMIT errorOccurred(Error::NotFound, tr("No such mailbox: %1").arg(folder));
        return;
    }
    m_openFolder = folder;
    // Where a later Email/changes resumes from. Deliberately no comparison
    // with the state the server is about to report: a JMAP state string
    // changes every time anything in the account is modified, so a difference
    // is the ordinary case — it means "there is news", not "your cache is
    // void". Only the server saying cannotCalculateChanges means the latter,
    // and fetchHeadersSince() is where that is heard.
    if (!syncToken.isEmpty())
        m_emailState.insert(folder, syncToken);

    JmapRequest *request = newRequest();
    if (!request) {
        Q_EMIT errorOccurred(Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }
    // Email/get with no ids is how the account's Email state string is had
    // without fetching anything; it is what fetchHeadersSince()'s
    // Email/changes resumes from, and openFolder() is where the caller
    // expects to be told it.
    request->addCall(QStringLiteral("Email/query"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("filter"),
                                  QJsonObject{{QStringLiteral("inMailbox"), id}}},
                                 {QStringLiteral("limit"), 0},
                                 {QStringLiteral("calculateTotal"), true}});
    request->addCall(QStringLiteral("Email/get"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("ids"), QJsonArray{}}});

    request->send([this, request, folder](Error error,
                                          const QList<JmapRequest::Response> &responses,
                                          const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            Q_EMIT errorOccurred(error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            Q_EMIT errorOccurred(JmapRequest::errorForType(failed.errorType()),
                                 tr("The server refused to open %1 (%2).")
                                     .arg(folder, failed.errorType()));
            return;
        }

        qint64 total = 0;
        QString state;
        for (const JmapRequest::Response &response : responses) {
            if (response.method == QLatin1String("Email/query"))
                total = response.arguments.value(QLatin1String("total")).toInt();
            else if (response.method == QLatin1String("Email/get"))
                state = response.arguments.value(QLatin1String("state")).toString();
        }
        Q_EMIT folderOpened(folder, total, state);
    });
}

// --- Headers ---------------------------------------------------------------

void JmapBackend::emitHeaders(const QString &folder, const QJsonArray &list)
{
    QList<HeaderInfo> headers;
    headers.reserve(list.size());

    for (const QJsonValue &value : list) {
        const QJsonObject object = value.toObject();
        const QString id = jmapString(object, "id");
        if (id.isEmpty())
            continue;

        HeaderInfo info;
        info.remoteId = id;
        info.uid = hashedLocalKey(id);
        info.size = object.value(QLatin1String("size")).toInt();
        info.flags = flagsFromKeywords(object.value(QLatin1String("keywords")).toObject());

        const QByteArray head =
            headerBlockFromJmap(object.value(QLatin1String("headers")).toArray());
        auto message = std::make_shared<KMime::Message>();
        message->setHead(head);
        message->parse();
        // Parsed exactly once, here — the contract HeaderInfo::message states,
        // and what keeps the DKIM and spam paths reading real octets.
        info.message = message;

        const QString blobId = jmapString(object, "blobId");
        if (!blobId.isEmpty())
            m_blobIds.insert(id, blobId);

        headers.append(info);
    }

    if (!headers.isEmpty())
        Q_EMIT headersFetched(folder, headers);
}

void JmapBackend::queryAndGet(const QString &folder, const QJsonObject &filter, int position,
                              int limit, const OpCallback &done)
{
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    QJsonObject sort;
    sort.insert(QStringLiteral("property"), QStringLiteral("receivedAt"));
    sort.insert(QStringLiteral("isAscending"), false);

    QJsonObject queryArgs{{QStringLiteral("accountId"), m_session->mailAccountId()},
                          {QStringLiteral("filter"), filter},
                          {QStringLiteral("sort"), QJsonArray{sort}},
                          {QStringLiteral("position"), position},
                          {QStringLiteral("calculateTotal"), true}};
    if (limit > 0)
        queryArgs.insert(QStringLiteral("limit"), limit);

    const QString queryId = request->addCall(QStringLiteral("Email/query"), queryArgs);
    request->addCall(
        QStringLiteral("Email/get"),
        QJsonObject{
            {QStringLiteral("accountId"), m_session->mailAccountId()},
            {QStringLiteral("#ids"), JmapRequest::resultReference(
                                         queryId, QStringLiteral("Email/query"),
                                         QStringLiteral("/ids"))},
            // `headers` is what makes the header block a reconstruction rather
            // than a summary; the rest is what MessageListModel shows.
            {QStringLiteral("properties"),
             QJsonArray{QStringLiteral("id"), QStringLiteral("blobId"),
                        QStringLiteral("size"), QStringLiteral("keywords"),
                        QStringLiteral("headers")}}});

    request->send([this, request, folder, done](Error error,
                                                const QList<JmapRequest::Response> &responses,
                                                const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused the header request (%1).")
                       .arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            if (response.method == QLatin1String("Email/get"))
                emitHeaders(folder, response.arguments.value(QLatin1String("list")).toArray());
        }
        if (done)
            done(Error::None, QString());
    });
}

void JmapBackend::fetchHeaderWindow(const QString &folder, int fromNewest, int count,
                                    bool background, const OpCallback &done)
{
    Q_UNUSED(background) // HTTP does not serialize: nothing queues behind anything.

    const QString id = mailboxId(folder);
    if (id.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(folder));
        return;
    }
    queryAndGet(folder, QJsonObject{{QStringLiteral("inMailbox"), id}}, fromNewest, count,
                done);
}

void JmapBackend::fetchHeadersSince(const QString &folder, const QString &sinceRemoteId,
                                    const OpCallback &done)
{
    // sinceRemoteId is IMAP's way of asking this question — everything above a
    // uid — and JMAP has a better one: the server's own change log, which also
    // knows what was deleted and what moved away, neither of which an
    // open-ended id range can express.
    Q_UNUSED(sinceRemoteId)

    const QString id = mailboxId(folder);
    if (id.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(folder));
        return;
    }
    const QString since = m_emailState.value(folder);
    if (since.isEmpty()) {
        // No position to resume from — a folder never synced on this machine.
        // The newest page is the honest answer, and the caller merges it the
        // same way it merges a delta.
        queryAndGet(folder, QJsonObject{{QStringLiteral("inMailbox"), id}}, 0, 0, done);
        return;
    }

    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    const QString changesId = request->addCall(
        QStringLiteral("Email/changes"),
        QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                    {QStringLiteral("sinceState"), since},
                    {QStringLiteral("maxChanges"), kMaxChangesPerCall()}});

    // Both lists are read in the same request through back-references, so a
    // delta costs one round trip however much changed. They need separate
    // calls because a back-reference names one path, and separate call ids
    // because both answer as "Email/get" and the two mean different things:
    // an updated message that is no longer in this mailbox has left it.
    const QJsonArray properties{QStringLiteral("id"),   QStringLiteral("blobId"),
                                QStringLiteral("size"), QStringLiteral("keywords"),
                                QStringLiteral("mailboxIds"), QStringLiteral("headers")};
    const QString createdId = request->addCall(
        QStringLiteral("Email/get"),
        QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                    {QStringLiteral("#ids"),
                     JmapRequest::resultReference(changesId, QStringLiteral("Email/changes"),
                                                  QStringLiteral("/created"))},
                    {QStringLiteral("properties"), properties}});
    const QString updatedId = request->addCall(
        QStringLiteral("Email/get"),
        QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                    {QStringLiteral("#ids"),
                     JmapRequest::resultReference(changesId, QStringLiteral("Email/changes"),
                                                  QStringLiteral("/updated"))},
                    {QStringLiteral("properties"), properties}});

    request->send([this, request, folder, id, createdId, updatedId, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }

        // cannotCalculateChanges before anything else: the server's change log
        // no longer reaches back to the caller's position, so the delta is not
        // merely empty, it is unanswerable, and everything cached for this
        // folder has to be re-read rather than merged into.
        for (const JmapRequest::Response &response : responses) {
            if (response.isError()
                && response.errorType() == QLatin1String("cannotCalculateChanges")) {
                qWarning() << "mailove: JMAP server cannot compute changes for" << folder
                           << "- the cached messages are void";
                m_emailState.remove(folder);
                Q_EMIT folderInvalidated(folder);
                // Give the caller a folder to show rather than an empty one:
                // its cache has just been thrown away, and the newest page is
                // what a first sync would have fetched anyway.
                queryAndGet(folder, QJsonObject{{QStringLiteral("inMailbox"), id}}, 0, 0,
                            done);
                return;
            }
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused to report changes (%1).").arg(failed.errorType()));
            return;
        }

        QString newState;
        bool hasMore = false;
        QStringList vanished;
        for (const JmapRequest::Response &response : responses) {
            if (response.method == QLatin1String("Email/changes")) {
                newState = response.arguments.value(QLatin1String("newState")).toString();
                hasMore = response.arguments.value(QLatin1String("hasMoreChanges")).toBool();
                const QJsonArray destroyed =
                    response.arguments.value(QLatin1String("destroyed")).toArray();
                for (const QJsonValue &value : destroyed)
                    vanished.append(value.toString());
                continue;
            }
            if (response.method != QLatin1String("Email/get"))
                continue;

            // Email/changes is account-wide — JMAP has one change log, not one
            // per mailbox — so everything it names has to be sorted into this
            // folder or out of it.
            QJsonArray mine;
            const QJsonArray list = response.arguments.value(QLatin1String("list")).toArray();
            for (const QJsonValue &value : list) {
                const QJsonObject object = value.toObject();
                if (object.value(QLatin1String("mailboxIds")).toObject().contains(id)) {
                    mine.append(object);
                } else if (response.callId == updatedId) {
                    // It was in this folder when the caller last looked and is
                    // not now: from this folder's point of view it is gone,
                    // which is what a move to another mailbox looks like here.
                    // Only for updated ids — a *created* message elsewhere was
                    // never this folder's business.
                    vanished.append(object.value(QLatin1String("id")).toString());
                }
            }
            Q_UNUSED(createdId)
            if (!mine.isEmpty())
                emitHeaders(folder, mine);
        }

        vanished.removeAll(QString());
        if (!vanished.isEmpty())
            Q_EMIT messagesVanished(folder, vanished);

        if (!newState.isEmpty())
            m_emailState.insert(folder, newState);
        // maxChanges caps one call, not the catch-up: a folder that has been
        // away a long time takes several, each resuming from the state the
        // last one reached. Re-entered from the callback, so this is not
        // recursion on the stack.
        if (hasMore && !newState.isEmpty()) {
            fetchHeadersSince(folder, QString(), done);
            return;
        }
        if (done)
            done(Error::None, QString());
    });
}

void JmapBackend::fetchHeadersById(const QString &folder, const QStringList &remoteIds,
                                   const OpCallback &done)
{
    if (remoteIds.isEmpty()) {
        report(done, Error::None, QString());
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    QJsonArray ids;
    for (const QString &id : remoteIds)
        ids.append(id);

    request->addCall(QStringLiteral("Email/get"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("ids"), ids},
                                 {QStringLiteral("properties"),
                                  QJsonArray{QStringLiteral("id"), QStringLiteral("blobId"),
                                             QStringLiteral("size"),
                                             QStringLiteral("keywords"),
                                             QStringLiteral("headers")}}});

    request->send([this, request, folder, done](Error error,
                                                const QList<JmapRequest::Response> &responses,
                                                const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused the header request (%1).")
                       .arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses)
            emitHeaders(folder, response.arguments.value(QLatin1String("list")).toArray());
        if (done)
            done(Error::None, QString());
    });
}

// --- Bodies ----------------------------------------------------------------

int JmapBackend::freeBodySlots() const
{
    return qMax(0, kMaxConcurrentBodies() - m_bodiesInFlight);
}

void JmapBackend::fetchBodies(const QString &folder, const QStringList &remoteIds,
                              const OpCallback &done)
{
    if (remoteIds.isEmpty()) {
        report(done, Error::None, QString());
        return;
    }
    if (!m_session->isValid()) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    // Ids whose blob is already known go straight to the download queue; the
    // rest need one Email/get first. Header fetches populate m_blobIds, so in
    // practice the second path is only taken for cache-warm rows.
    QStringList unknown;
    QList<PendingBody> ready;
    for (const QString &id : remoteIds) {
        const QString blobId = m_blobIds.value(id);
        if (blobId.isEmpty())
            unknown.append(id);
        else
            ready.append({folder, id, blobId, 0});
    }

    const auto enqueue = [this, folder, done](const QList<PendingBody> &bodies) {
        if (bodies.isEmpty()) {
            report(done, Error::None, QString());
            return;
        }
        m_bodyBatchDone.insert(folder, done);
        m_bodyBatchOutstanding[folder] += bodies.size();
        m_bodyQueue.append(bodies);
        while (freeBodySlots() > 0 && !m_bodyQueue.isEmpty())
            downloadNextBody();
    };

    if (unknown.isEmpty()) {
        enqueue(ready);
        return;
    }

    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }
    QJsonArray ids;
    for (const QString &id : unknown)
        ids.append(id);
    request->addCall(QStringLiteral("Email/get"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("ids"), ids},
                                 {QStringLiteral("properties"),
                                  QJsonArray{QStringLiteral("id"), QStringLiteral("blobId"),
                                             QStringLiteral("size")}}});
    request->send([this, request, folder, ready, enqueue, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        QList<PendingBody> bodies = ready;
        for (const JmapRequest::Response &response : responses) {
            if (response.isError())
                continue;
            const QJsonArray list = response.arguments.value(QLatin1String("list")).toArray();
            for (const QJsonValue &value : list) {
                const QJsonObject object = value.toObject();
                const QString id = jmapString(object, "id");
                const QString blobId = jmapString(object, "blobId");
                if (id.isEmpty() || blobId.isEmpty())
                    continue;
                m_blobIds.insert(id, blobId);
                bodies.append({folder, id, blobId,
                               static_cast<qint64>(object.value(QLatin1String("size")).toInt())});
            }
            // Ids the server does not have are reported once so the caller
            // stops asking on every backfill pass.
            const QJsonArray notFound =
                response.arguments.value(QLatin1String("notFound")).toArray();
            for (const QJsonValue &value : notFound)
                Q_EMIT bodyUnavailable(folder, value.toString(), 0);
        }
        enqueue(bodies);
    });
}

void JmapBackend::downloadNextBody()
{
    if (m_bodyQueue.isEmpty() || !m_session->isValid())
        return;

    const PendingBody body = m_bodyQueue.takeFirst();
    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QNetworkRequest request(m_session->downloadUrl(m_session->mailAccountId(), body.blobId,
                                                   QStringLiteral("message/rfc822"),
                                                   QStringLiteral("message.eml")));
    m_session->authorize(request);
    request.setTransferTimeout(kBodyTimeoutMs());

    ++m_bodiesInFlight;
    QNetworkReply *reply = m_net->get(request);
    m_session->guardRedirects(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, body] {
        reply->deleteLater();
        --m_bodiesInFlight;

        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status == 200) {
            const QByteArray raw = reply->read(kMaxBodyBytes() + 1);
            if (raw.size() > kMaxBodyBytes()) {
                Q_EMIT bodyUnavailable(body.folder, body.remoteId, raw.size());
            } else {
                auto message = std::make_shared<KMime::Message>();
                // CRLFtoLF, always: the blob arrives off the wire with CRLF
                // line endings, and setContent() takes LF. Handing it CRLF
                // parses the head fine — KMime folds those itself — but the
                // boundary lines of a multipart never match, so the message
                // comes out with no children at all and the viewer says it has
                // no displayable text part. IMAP never hit this because KIMAP
                // hands back a message that is already parsed.
                message->setContent(KMime::CRLFtoLF(raw));
                message->parse();
                Q_EMIT bodyFetched(body.folder, body.remoteId, message);
            }
        } else if (status == 404) {
            Q_EMIT bodyUnavailable(body.folder, body.remoteId, body.size);
        } else if (status == 429 || status == 503) {
            Q_EMIT throttled();
            Q_EMIT bodyUnavailable(body.folder, body.remoteId, body.size);
        } else {
            Q_EMIT errorOccurred(Error::Connection, reply->errorString());
            Q_EMIT bodyUnavailable(body.folder, body.remoteId, body.size);
        }

        // The batch is done when its last body is, however each one ended:
        // the caller is pacing itself by this and must not be left waiting on
        // a message the server will never hand over.
        if (--m_bodyBatchOutstanding[body.folder] <= 0) {
            m_bodyBatchOutstanding.remove(body.folder);
            const OpCallback done = m_bodyBatchDone.take(body.folder);
            if (done)
                done(Error::None, QString());
        }
        while (freeBodySlots() > 0 && !m_bodyQueue.isEmpty())
            downloadNextBody();
    });
}

// --- Counts and search -----------------------------------------------------

void JmapBackend::folderUnreadCounts(
    const QStringList &folders,
    const std::function<void(Error, const QHash<QString, int> &counts,
                             const QString &message)> &done)
{
    JmapRequest *request = newRequest();
    if (!request) {
        if (done)
            done(Error::Auth, {}, tr("Not connected to a JMAP server."));
        return;
    }

    // One Mailbox/get answers for every folder at once — where IMAP needs a
    // STATUS per mailbox, this is a single call whatever the list looks like.
    request->addCall(QStringLiteral("Mailbox/get"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("ids"), QJsonValue::Null}});
    request->send([this, request, folders, done](Error error,
                                                 const QList<JmapRequest::Response> &responses,
                                                 const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            if (done)
                done(error, {}, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            if (done)
                done(JmapRequest::errorForType(failed.errorType()), {},
                     tr("The server refused to report unread counts (%1).")
                         .arg(failed.errorType()));
            return;
        }

        QList<Mailbox> mailboxes;
        for (const JmapRequest::Response &response : responses) {
            const QJsonArray list = response.arguments.value(QLatin1String("list")).toArray();
            for (const QJsonValue &value : list) {
                const Mailbox mailbox = mailboxFromJson(value.toObject());
                if (!mailbox.id.isEmpty())
                    mailboxes.append(mailbox);
            }
        }
        rebuildPaths(mailboxes);
        // This is a full Mailbox/get like listAllMailboxes(), so it seeds the
        // delta position too — a poll leaves the tree no less current than a
        // listing would.
        if (!responses.isEmpty()) {
            m_mailboxState =
                responses.first().arguments.value(QLatin1String("state")).toString();
        }

        QHash<QString, int> counts;
        for (const Mailbox &mailbox : std::as_const(mailboxes)) {
            const QString path = m_pathById.value(mailbox.id);
            if (mailbox.unread > 0 && (folders.isEmpty() || folders.contains(path)))
                counts.insert(path, static_cast<int>(mailbox.unread));
        }
        if (done)
            done(Error::None, counts, QString());
    });
}

void JmapBackend::search(const QString &folder, const QString &query, bool headersOnly,
                         bool byRecipient, const OpCallback &done)
{
    const QString id = mailboxId(folder);
    if (id.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(folder));
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    QJsonObject filter{{QStringLiteral("inMailbox"), id}};
    if (headersOnly) {
        // "sender and subject" as MailBackend defines it: either matching is a
        // hit, which is an OR of two conditions rather than one text search.
        filter.insert(QStringLiteral("operator"), QStringLiteral("AND"));
        filter.insert(
            QStringLiteral("conditions"),
            QJsonArray{
                QJsonObject{{QStringLiteral("inMailbox"), id}},
                QJsonObject{{QStringLiteral("operator"), QStringLiteral("OR")},
                            {QStringLiteral("conditions"),
                             QJsonArray{
                                 QJsonObject{{byRecipient ? QStringLiteral("to")
                                                          : QStringLiteral("from"),
                                              query}},
                                 QJsonObject{{QStringLiteral("subject"), query}}}}}});
        filter.remove(QStringLiteral("inMailbox"));
    } else {
        filter.insert(QStringLiteral("text"), query);
    }

    request->addCall(QStringLiteral("Email/query"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("filter"), filter}});
    request->send([this, request, folder, done](Error error,
                                                const QList<JmapRequest::Response> &responses,
                                                const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused the search (%1).").arg(failed.errorType()));
            return;
        }
        QStringList ids;
        for (const JmapRequest::Response &response : responses) {
            const QJsonArray list = response.arguments.value(QLatin1String("ids")).toArray();
            for (const QJsonValue &value : list)
                ids.append(value.toString());
        }
        Q_EMIT searchResults(folder, ids);
        if (done)
            done(Error::None, QString());
    });
}

// --- Writing ---------------------------------------------------------------

QString JmapBackend::keywordForFlag(const QString &flag)
{
    if (flag == QLatin1String("seen"))
        return QStringLiteral("$seen");
    if (flag == QLatin1String("draft"))
        return QStringLiteral("$draft");
    if (flag == QLatin1String("flagged"))
        return QStringLiteral("$flagged");
    // "deleted" lands here, and answering empty is the point. IMAP deletes by
    // flagging and expunging; JMAP by removing a message from every mailbox,
    // which is deleteMessages(). Inventing a `$deleted` nobody honours would
    // report success for a message still sitting in the folder.
    return QString();
}

QJsonObject JmapBackend::keywordPatch(const QStringList &addFlags,
                                      const QStringList &removeFlags)
{
    QJsonObject patch;
    for (const QString &flag : addFlags) {
        const QString keyword = keywordForFlag(flag);
        if (!keyword.isEmpty())
            patch.insert(QStringLiteral("keywords/") + keyword, true);
    }
    // Removals are written second, so a flag named in both directions ends up
    // removed — the order the IMAP backend's two STOREs produce.
    for (const QString &flag : removeFlags) {
        const QString keyword = keywordForFlag(flag);
        if (!keyword.isEmpty())
            patch.insert(QStringLiteral("keywords/") + keyword, QJsonValue::Null);
    }
    return patch;
}

QJsonObject JmapBackend::firstRejection(const QJsonObject &arguments, const char *rejectedKey)
{
    const QJsonObject rejected = arguments.value(QLatin1String(rejectedKey)).toObject();
    if (rejected.isEmpty())
        return {};
    return rejected.constBegin().value().toObject();
}

MailBackend::Error JmapBackend::setError(const QJsonObject &arguments,
                                         const char *rejectedKey, QString *message)
{
    const QJsonObject rejected = arguments.value(QLatin1String(rejectedKey)).toObject();
    if (rejected.isEmpty())
        return Error::None;
    // Every rejected object carries its own reason, but the caller has one
    // yes-or-no to give: the first stands for the batch, and the count says
    // whether it was the whole of it.
    const QJsonObject first = rejected.constBegin().value().toObject();
    const QString type = first.value(QLatin1String("type")).toString();
    if (message) {
        const QString description = first.value(QLatin1String("description")).toString();
        *message = description.isEmpty() ? type : description;
        if (rejected.size() > 1)
            *message = tr("%1 (and %n more)", nullptr, rejected.size() - 1).arg(*message);
    }
    return JmapRequest::errorForType(type);
}

void JmapBackend::updateEmails(const QStringList &remoteIds, const QJsonObject &patch,
                               const QString &what, const OpCallback &done)
{
    if (remoteIds.isEmpty() || patch.isEmpty()) {
        report(done, Error::None, QString());
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    // maxObjectsInSet is a ceiling the server refuses the whole call for
    // exceeding, so the list is cut to it rather than discovering the limit by
    // being rejected. Zero means the server stated none. Marking a large
    // folder read is the case that reaches it.
    const qint64 stated = m_session->limits().maxObjectsInSet;
    const int chunk = stated > 0 ? static_cast<int>(qMin<qint64>(stated, remoteIds.size()))
                                 : remoteIds.size();

    QJsonObject update;
    for (int i = 0; i < chunk; ++i)
        update.insert(remoteIds.at(i), patch);
    request->addCall(QStringLiteral("Email/set"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("update"), update}});

    const QStringList rest = remoteIds.mid(chunk);
    request->send([this, request, rest, patch, what, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused to %1 (%2).").arg(what, failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            QString detail;
            const Error rejected = setError(response.arguments, "notUpdated", &detail);
            if (rejected != Error::None) {
                report(done, rejected, tr("The server refused to %1: %2").arg(what, detail));
                return;
            }
        }
        // The next chunk only starts once this one is known to have worked, so
        // a partial failure stops rather than compounding. Re-entered from the
        // callback, not from the stack this call sits on.
        if (!rest.isEmpty()) {
            updateEmails(rest, patch, what, done);
            return;
        }
        report(done, Error::None, QString());
    });
}

void JmapBackend::setFlags(const QString &folder, const QStringList &remoteIds,
                           const QStringList &addFlags, const QStringList &removeFlags,
                           const OpCallback &done)
{
    // The folder is not named in the call: JMAP flags belong to the message,
    // not to a copy of it in a mailbox, so there is no selection to make.
    Q_UNUSED(folder)
    updateEmails(remoteIds, keywordPatch(addFlags, removeFlags), tr("change flags"), done);
}

void JmapBackend::moveMessages(const QString &folder, const QStringList &remoteIds,
                               const QString &targetFolder, const OpCallback &done)
{
    const QString fromId = mailboxId(folder);
    const QString toId = mailboxId(targetFolder);
    if (fromId.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(folder));
        return;
    }
    if (toId.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(targetFolder));
        return;
    }
    if (fromId == toId) {
        report(done, Error::None, QString());
        return;
    }
    // A patch of the two ends rather than a replacement of mailboxIds: a
    // message may be in several mailboxes at once (JMAP's answer to Gmail's
    // labels), and moving it out of this folder must not evict it from the
    // others the user filed it in.
    const QJsonObject patch{
        {QStringLiteral("mailboxIds/") + fromId, QJsonValue::Null},
        {QStringLiteral("mailboxIds/") + toId, true}};
    updateEmails(remoteIds, patch, tr("move messages"), done);
}

void JmapBackend::deleteMessages(const QString &folder, const QStringList &remoteIds,
                                 const OpCallback &done)
{
    Q_UNUSED(folder) // As for setFlags: destroy names the message, not a copy.
    if (remoteIds.isEmpty()) {
        report(done, Error::None, QString());
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    const qint64 stated = m_session->limits().maxObjectsInSet;
    const int chunk = stated > 0 ? static_cast<int>(qMin<qint64>(stated, remoteIds.size()))
                                 : remoteIds.size();
    QJsonArray destroy;
    for (int i = 0; i < chunk; ++i)
        destroy.append(remoteIds.at(i));
    request->addCall(QStringLiteral("Email/set"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("destroy"), destroy}});

    const QStringList rest = remoteIds.mid(chunk);
    request->send([this, request, folder, rest, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused to delete messages (%1).").arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            QString detail;
            const Error rejected = setError(response.arguments, "notDestroyed", &detail);
            if (rejected != Error::None) {
                report(done, rejected,
                       tr("The server refused to delete messages: %1").arg(detail));
                return;
            }
        }
        if (!rest.isEmpty()) {
            deleteMessages(folder, rest, done);
            return;
        }
        report(done, Error::None, QString());
    });
}

// --- Mailboxes -------------------------------------------------------------

QString JmapBackend::mailboxIdForRole(const QString &role) const
{
    for (auto it = m_mailboxes.constBegin(); it != m_mailboxes.constEnd(); ++it) {
        if (it->role == role)
            return it->id;
    }
    return QString();
}

void JmapBackend::rebuildPathsFromCache()
{
    rebuildPaths(m_mailboxes.values());
}

bool JmapBackend::splitPath(const QString &path, QString *parentId, QString *name) const
{
    // The last separator wins, which is the one place this backend's invented
    // path language can be wrong: a JMAP mailbox may legally be *named* "a/b",
    // and a path cannot then say whether that is one mailbox or a child of "a".
    // Ambiguity is unavoidable while the interface speaks paths, and reading it
    // as a hierarchy is the reading that matches every other server.
    const int cut = path.lastIndexOf(pathSeparator());
    if (cut < 0) {
        if (parentId)
            parentId->clear();
        if (name)
            *name = path;
        return true;
    }
    const QString id = mailboxId(path.left(cut));
    if (id.isEmpty())
        return false;
    if (parentId)
        *parentId = id;
    if (name)
        *name = path.mid(cut + 1);
    return true;
}

void JmapBackend::createFolder(const QString &path, const OpCallback &done)
{
    QString parentId;
    QString name;
    if (!splitPath(path, &parentId, &name) || name.isEmpty()) {
        report(done, Error::NotFound, tr("No parent mailbox for %1.").arg(path));
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    QJsonObject mailbox{{QStringLiteral("name"), name}};
    mailbox.insert(QStringLiteral("parentId"),
                   parentId.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(parentId));
    request->addCall(
        QStringLiteral("Mailbox/set"),
        QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                    {QStringLiteral("create"),
                     QJsonObject{{QStringLiteral("mailbox"), mailbox}}}});

    request->send([this, request, name, parentId, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused to create the mailbox (%1).")
                       .arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            QString detail;
            const Error rejected = setError(response.arguments, "notCreated", &detail);
            if (rejected != Error::None) {
                report(done, rejected,
                       tr("The server refused to create the mailbox: %1").arg(detail));
                return;
            }
            // Record the new mailbox at once. The caller re-lists after this,
            // but an operation issued in between would otherwise be told the
            // path it just created does not exist.
            const QString id = response.arguments.value(QLatin1String("created"))
                                   .toObject()
                                   .value(QLatin1String("mailbox"))
                                   .toObject()
                                   .value(QLatin1String("id"))
                                   .toString();
            if (!id.isEmpty()) {
                Mailbox created;
                created.id = id;
                created.name = name;
                created.parentId = parentId;
                m_mailboxes.insert(id, created);
                rebuildPathsFromCache();
            }
        }
        report(done, Error::None, QString());
    });
}

void JmapBackend::renameFolder(const QString &from, const QString &to,
                               const OpCallback &done)
{
    const QString id = mailboxId(from);
    if (id.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(from));
        return;
    }
    QString parentId;
    QString name;
    if (!splitPath(to, &parentId, &name) || name.isEmpty()) {
        report(done, Error::NotFound, tr("No parent mailbox for %1.").arg(to));
        return;
    }
    if (parentId == id) {
        report(done, Error::Protocol, tr("A mailbox cannot be moved inside itself."));
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    // One patch says both things a rename can mean — a new name, a new parent,
    // or both — and the subtree follows without being named, parentId being
    // what the children point at.
    QJsonObject patch{{QStringLiteral("name"), name}};
    patch.insert(QStringLiteral("parentId"),
                 parentId.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(parentId));
    request->addCall(QStringLiteral("Mailbox/set"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("update"), QJsonObject{{id, patch}}}});

    request->send([this, request, id, name, parentId, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused to rename the mailbox (%1).")
                       .arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            QString detail;
            const Error rejected = setError(response.arguments, "notUpdated", &detail);
            if (rejected != Error::None) {
                report(done, rejected,
                       tr("The server refused to rename the mailbox: %1").arg(detail));
                return;
            }
        }
        const auto it = m_mailboxes.find(id);
        if (it != m_mailboxes.end()) {
            it->name = name;
            it->parentId = parentId;
            rebuildPathsFromCache();
        }
        report(done, Error::None, QString());
    });
}

void JmapBackend::deleteFolder(const QString &path, const OpCallback &done)
{
    const QString id = mailboxId(path);
    if (id.isEmpty()) {
        report(done, Error::NotFound, tr("No such mailbox: %1").arg(path));
        return;
    }
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }

    // onDestroyRemoveEmails matches what IMAP's DELETE does: the mailbox goes
    // and the mail in it goes with it. Left at its default the server refuses
    // to destroy a mailbox that still holds anything, which would make
    // deleting a folder work only when it was already empty.
    request->addCall(
        QStringLiteral("Mailbox/set"),
        QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                    {QStringLiteral("destroy"), QJsonArray{id}},
                    {QStringLiteral("onDestroyRemoveEmails"), true}});

    request->send([this, request, id, done](Error error,
                                            const QList<JmapRequest::Response> &responses,
                                            const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The server refused to delete the mailbox (%1).")
                       .arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            QString detail;
            const Error rejected = setError(response.arguments, "notDestroyed", &detail);
            if (rejected != Error::None) {
                report(done, rejected,
                       tr("The server refused to delete the mailbox: %1").arg(detail));
                return;
            }
        }
        m_mailboxes.remove(id);
        rebuildPathsFromCache();
        report(done, Error::None, QString());
    });
}

// --- Filing and sending ----------------------------------------------------

void JmapBackend::uploadBlob(const QByteArray &raw, const QByteArray &contentType,
                             const std::function<void(Error, const QString &blobId,
                                                      const QString &message)> &done)
{
    if (!m_session->isValid()) {
        if (done)
            done(Error::Auth, QString(), tr("Not connected to a JMAP server."));
        return;
    }
    // Checked here rather than left to a 413: the server states the limit in
    // its session object precisely so a client need not find it by failing.
    const qint64 maxSize = m_session->limits().maxSizeUpload;
    if (maxSize > 0 && raw.size() > maxSize) {
        if (done)
            done(Error::Protocol, QString(),
                 tr("The message is %1 bytes, and this server accepts at most %2.")
                     .arg(raw.size())
                     .arg(maxSize));
        return;
    }

    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QNetworkRequest request(m_session->uploadUrl(m_session->mailAccountId()));
    m_session->authorize(request);
    request.setHeader(QNetworkRequest::ContentTypeHeader, contentType);
    request.setTransferTimeout(kBodyTimeoutMs());

    QNetworkReply *reply = m_net->post(request, raw);
    m_session->guardRedirects(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, done] {
        reply->deleteLater();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->read(kMaxUploadReplyBytes());

        if (status == 200 || status == 201) {
            const QString blobId = QJsonDocument::fromJson(body)
                                       .object()
                                       .value(QLatin1String("blobId"))
                                       .toString();
            if (blobId.isEmpty()) {
                if (done)
                    done(Error::Protocol, QString(),
                         tr("The server accepted the upload without naming a blob."));
                return;
            }
            if (done)
                done(Error::None, blobId, QString());
            return;
        }
        if (status == 401) {
            if (done)
                done(Error::Auth, QString(),
                     tr("The server rejected the credentials for the upload."));
            return;
        }
        if (status == 429 || status == 503) {
            Q_EMIT throttled();
            if (done)
                done(Error::Throttled, QString(),
                     tr("The server is refusing uploads for now."));
            return;
        }
        if (done)
            done(status > 0 ? Error::Protocol : Error::Connection, QString(),
                 status > 0 ? tr("The server refused the upload (HTTP %1).").arg(status)
                            : reply->errorString());
    });
}

void JmapBackend::storeMessage(const QString &folder, const QByteArray &raw,
                               const QStringList &flags,
                               const std::function<void(Error, const QString &remoteId,
                                                        const QString &message)> &done)
{
    const QString id = mailboxId(folder);
    if (id.isEmpty()) {
        if (done)
            done(Error::NotFound, QString(), tr("No such mailbox: %1").arg(folder));
        return;
    }

    // Two legs, because a JMAP batch is JSON and a message is octets: the bytes
    // go up as a blob, and Email/import is what turns a blob into a message in
    // a mailbox — the nearest thing the protocol has to IMAP's APPEND.
    uploadBlob(raw, QByteArrayLiteral("message/rfc822"),
               [this, id, flags, done](Error error, const QString &blobId,
                                       const QString &message) {
        if (error != Error::None) {
            if (done)
                done(error, QString(), message);
            return;
        }
        JmapRequest *request = newRequest();
        if (!request) {
            if (done)
                done(Error::Auth, QString(), tr("Not connected to a JMAP server."));
            return;
        }

        QJsonObject keywords;
        for (const QString &flag : flags) {
            const QString keyword = keywordForFlag(flag);
            if (!keyword.isEmpty())
                keywords.insert(keyword, true);
        }
        const QJsonObject email{
            {QStringLiteral("blobId"), blobId},
            {QStringLiteral("mailboxIds"), QJsonObject{{id, true}}},
            {QStringLiteral("keywords"), keywords},
            {QStringLiteral("receivedAt"),
             QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}};
        request->addCall(
            QStringLiteral("Email/import"),
            QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                        {QStringLiteral("emails"),
                         QJsonObject{{QStringLiteral("filed"), email}}}});

        request->send([request, done](Error error,
                                      const QList<JmapRequest::Response> &responses,
                                      const QString &message) {
            request->deleteLater();
            if (error != Error::None) {
                if (done)
                    done(error, QString(), message);
                return;
            }
            const JmapRequest::Response failed = JmapRequest::firstError(responses);
            if (!failed.method.isEmpty()) {
                if (done)
                    done(JmapRequest::errorForType(failed.errorType()), QString(),
                         tr("The server refused to file the message (%1).")
                             .arg(failed.errorType()));
                return;
            }
            for (const JmapRequest::Response &response : responses) {
                QString detail;
                const Error rejected = setError(response.arguments, "notCreated", &detail);
                if (rejected != Error::None) {
                    // `alreadyExists` is not a failure to file — it means the
                    // server already holds this exact message and is naming the
                    // copy. The caller wanted it filed, and it is, so answering
                    // with the existing id is both true and what saves a
                    // duplicate draft on every retry of an unchanged message.
                    const QJsonObject rejection =
                        firstRejection(response.arguments, "notCreated");
                    const QString existing =
                        rejection.value(QLatin1String("existingId")).toString();
                    if (rejection.value(QLatin1String("type")).toString()
                            == QLatin1String("alreadyExists")
                        && !existing.isEmpty()) {
                        if (done)
                            done(Error::None, existing, QString());
                        return;
                    }
                    if (done)
                        done(rejected, QString(),
                             tr("The server refused to file the message: %1").arg(detail));
                    return;
                }
                // Unlike IMAP without UIDPLUS, JMAP always names what it filed,
                // so the caller never has to re-list to find its own message.
                const QString filedId = response.arguments.value(QLatin1String("created"))
                                            .toObject()
                                            .value(QLatin1String("filed"))
                                            .toObject()
                                            .value(QLatin1String("id"))
                                            .toString();
                if (!filedId.isEmpty()) {
                    if (done)
                        done(Error::None, filedId, QString());
                    return;
                }
            }
            if (done)
                done(Error::None, QString(), QString());
        });
    });
}

void JmapBackend::withIdentity(const QString &from,
                               const std::function<void(Error, const QString &identityId,
                                                        const QString &message)> &done)
{
    const auto answer = [this, from, done] {
        // The stated address first, the account's default second. A server may
        // spell an identity's address differently from the one composed with
        // (an alias domain, a different case), and refusing to send over that
        // would be stricter than the server itself is.
        const QString id = m_identityByEmail.value(from.toLower(), m_defaultIdentityId);
        if (id.isEmpty()) {
            done(Error::Protocol, QString(),
                 tr("The server offers no identity to send from %1 as.").arg(from));
            return;
        }
        done(Error::None, id, QString());
    };
    if (m_identitiesFetched) {
        answer();
        return;
    }

    JmapRequest *request = newRequest();
    if (!request) {
        done(Error::Auth, QString(), tr("Not connected to a JMAP server."));
        return;
    }
    request->useCapability(JmapSession::submissionCapability());
    request->addCall(
        QStringLiteral("Identity/get"),
        QJsonObject{{QStringLiteral("accountId"), m_session->submissionAccountId()},
                    {QStringLiteral("ids"), QJsonValue::Null}});

    request->send([this, request, answer, done](Error error,
                                                const QList<JmapRequest::Response> &responses,
                                                const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            done(error, QString(), message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            done(JmapRequest::errorForType(failed.errorType()), QString(),
                 tr("The server refused to list identities (%1).").arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            const QJsonArray list = response.arguments.value(QLatin1String("list")).toArray();
            for (const QJsonValue &value : list) {
                const QJsonObject object = value.toObject();
                const QString id = jmapString(object, "id");
                const QString email = jmapString(object, "email");
                if (id.isEmpty())
                    continue;
                if (!email.isEmpty())
                    m_identityByEmail.insert(email.toLower(), id);
                if (m_defaultIdentityId.isEmpty())
                    m_defaultIdentityId = id;
            }
        }
        // Set even when the list came back empty: the answer "this account has
        // no identities" is worth remembering, and asking again per send would
        // cost a round trip to be told the same thing.
        m_identitiesFetched = true;
        answer();
    });
}

void JmapBackend::sendMessage(const QByteArray &raw, const QString &from,
                              const QStringList &recipients, const OpCallback &done)
{
    if (recipients.isEmpty()) {
        report(done, Error::Protocol, tr("No recipient given."));
        return;
    }
    if (!m_session->isValid()) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }
    if (!m_session->hasCapability(JmapSession::submissionCapability())) {
        report(done, Error::Protocol,
               tr("This server does not offer JMAP submission, so mail cannot be "
                  "sent from this account."));
        return;
    }

    withIdentity(from, [this, raw, from, recipients, done](Error error,
                                                           const QString &identityId,
                                                           const QString &message) {
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        uploadBlob(raw, QByteArrayLiteral("message/rfc822"),
                   [this, from, recipients, identityId, done](
                       Error error, const QString &blobId, const QString &message) {
            if (error != Error::None) {
                report(done, error, message);
                return;
            }
            submitBlob(blobId, identityId, from, recipients, done);
        });
    });
}

void JmapBackend::submitBlob(const QString &blobId, const QString &identityId,
                             const QString &from, const QStringList &recipients,
                             const OpCallback &done)
{
    // JMAP will not submit an Email that does not exist, so the message is
    // imported first and the submission names it by creation id — one request,
    // and onSuccessUpdateEmail files the sent copy server-side, which is what
    // sentCopyIsAutomatic() promises the caller.
    const QString draftsId = mailboxIdForRole(QStringLiteral("drafts"));
    const QString sentId = mailboxIdForRole(QStringLiteral("sent"));
    const QString holdId = !draftsId.isEmpty() ? draftsId : sentId;
    if (holdId.isEmpty()) {
        report(done, Error::NotFound,
               tr("The server named neither a Drafts nor a Sent mailbox, so there is "
                  "nowhere to put the message while it is sent."));
        return;
    }

    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }
    request->useCapability(JmapSession::submissionCapability());

    const QJsonObject email{
        {QStringLiteral("blobId"), blobId},
        {QStringLiteral("mailboxIds"), QJsonObject{{holdId, true}}},
        {QStringLiteral("keywords"),
         QJsonObject{{QStringLiteral("$draft"), true}, {QStringLiteral("$seen"), true}}},
        {QStringLiteral("receivedAt"),
         QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}};
    request->addCall(QStringLiteral("Email/import"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("emails"),
                                  QJsonObject{{QStringLiteral("draft"), email}}}});

    request->addCall(
        QStringLiteral("EmailSubmission/set"),
        QJsonObject{{QStringLiteral("accountId"), m_session->submissionAccountId()},
                    {QStringLiteral("create"),
                     QJsonObject{{QStringLiteral("send"),
                                  submissionCreate(QStringLiteral("#draft"), identityId, from,
                                                   recipients)}}},
                    {QStringLiteral("onSuccessUpdateEmail"),
                     QJsonObject{{QStringLiteral("#send"), sentCopyPatch(holdId, sentId)}}}});

    request->send([this, request, identityId, from, recipients, done](
                      Error error, const QList<JmapRequest::Response> &responses,
                      const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }

        // The import and the submission answer separately, and the interesting
        // case is the one where the first worked and the second did not: the
        // message is then sitting in Drafts having never been sent.
        QString importedId;
        Error failure = Error::None;
        QString detail;
        for (const JmapRequest::Response &response : responses) {
            if (response.isError()) {
                if (failure == Error::None) {
                    failure = JmapRequest::errorForType(response.errorType());
                    detail = tr("the server refused the request (%1)")
                                 .arg(response.errorType());
                }
                continue;
            }
            if (response.method == QLatin1String("Email/import")) {
                importedId = response.arguments.value(QLatin1String("created"))
                                 .toObject()
                                 .value(QLatin1String("draft"))
                                 .toObject()
                                 .value(QLatin1String("id"))
                                 .toString();
                // The server already holds this exact message, so there was
                // nothing to import — and the submission in this request failed
                // with it, its `#draft` reference having nothing to resolve to.
                // Nothing is wrong except that the message needs naming by id,
                // so the send is retried that way rather than reported as a
                // failure the user can do nothing about.
                const QJsonObject rejection =
                    firstRejection(response.arguments, "notCreated");
                const QString existing =
                    rejection.value(QLatin1String("existingId")).toString();
                if (rejection.value(QLatin1String("type")).toString()
                        == QLatin1String("alreadyExists")
                    && !existing.isEmpty()) {
                    submitExistingEmail(existing, identityId, from, recipients, done);
                    return;
                }
            }
            // Both calls create, so both report their refusals the same way —
            // an import the server would not accept and a submission it would
            // not make are alike "notCreated".
            QString rejectedDetail;
            const Error rejected =
                setError(response.arguments, "notCreated", &rejectedDetail);
            if (rejected != Error::None && failure == Error::None) {
                failure = rejected;
                detail = rejectedDetail;
            }
        }

        if (failure == Error::None) {
            report(done, Error::None, QString());
            return;
        }
        // Clear up after a submission that failed with the draft already
        // imported — otherwise every refused send leaves a copy in Drafts that
        // the user never asked to save.
        if (!importedId.isEmpty())
            destroyEmailQuietly(importedId);
        report(done, failure, tr("The message was not sent: %1").arg(detail));
    });
}

QJsonObject JmapBackend::submissionCreate(const QString &emailId, const QString &identityId,
                                          const QString &from,
                                          const QStringList &recipients) const
{
    // The envelope, not the headers: Bcc recipients are here and nowhere else,
    // which is the whole reason MailBackend takes a flat recipient list.
    QJsonArray rcptTo;
    for (const QString &recipient : recipients)
        rcptTo.append(QJsonObject{{QStringLiteral("email"), recipient}});

    return QJsonObject{
        {QStringLiteral("emailId"), emailId},
        {QStringLiteral("identityId"), identityId},
        {QStringLiteral("envelope"),
         QJsonObject{{QStringLiteral("mailFrom"), QJsonObject{{QStringLiteral("email"), from}}},
                     {QStringLiteral("rcptTo"), rcptTo}}}};
}

QJsonObject JmapBackend::sentCopyPatch(const QString &holdId, const QString &sentId)
{
    QJsonObject patch{{QStringLiteral("keywords/$draft"), QJsonValue::Null},
                      {QStringLiteral("keywords/$seen"), true}};
    if (!sentId.isEmpty() && sentId != holdId) {
        patch.insert(QStringLiteral("mailboxIds/") + holdId, QJsonValue::Null);
        patch.insert(QStringLiteral("mailboxIds/") + sentId, true);
    }
    return patch;
}

void JmapBackend::submitExistingEmail(const QString &emailId, const QString &identityId,
                                      const QString &from, const QStringList &recipients,
                                      const OpCallback &done)
{
    JmapRequest *request = newRequest();
    if (!request) {
        report(done, Error::Auth, tr("Not connected to a JMAP server."));
        return;
    }
    request->useCapability(JmapSession::submissionCapability());

    // The message is wherever the server already had it, which need not be
    // Drafts — so the sent copy is filed by moving it out of the mailbox the
    // Sent role names nothing about. Only the Sent half of the patch applies.
    const QString sentId = mailboxIdForRole(QStringLiteral("sent"));
    QJsonObject onSuccess{{QStringLiteral("keywords/$draft"), QJsonValue::Null},
                          {QStringLiteral("keywords/$seen"), true}};
    if (!sentId.isEmpty())
        onSuccess.insert(QStringLiteral("mailboxIds/") + sentId, true);

    request->addCall(
        QStringLiteral("EmailSubmission/set"),
        QJsonObject{{QStringLiteral("accountId"), m_session->submissionAccountId()},
                    {QStringLiteral("create"),
                     QJsonObject{{QStringLiteral("send"),
                                  submissionCreate(emailId, identityId, from, recipients)}}},
                    {QStringLiteral("onSuccessUpdateEmail"),
                     QJsonObject{{QStringLiteral("#send"), onSuccess}}}});

    request->send([this, request, done](Error error,
                                        const QList<JmapRequest::Response> &responses,
                                        const QString &message) {
        request->deleteLater();
        if (error != Error::None) {
            report(done, error, message);
            return;
        }
        const JmapRequest::Response failed = JmapRequest::firstError(responses);
        if (!failed.method.isEmpty()) {
            report(done, JmapRequest::errorForType(failed.errorType()),
                   tr("The message was not sent: the server refused the request (%1).")
                       .arg(failed.errorType()));
            return;
        }
        for (const JmapRequest::Response &response : responses) {
            QString detail;
            const Error rejected = setError(response.arguments, "notCreated", &detail);
            if (rejected != Error::None) {
                // Nothing to tidy here: this path imported nothing, the message
                // having been the server's before the send was attempted.
                report(done, rejected, tr("The message was not sent: %1").arg(detail));
                return;
            }
        }
        report(done, Error::None, QString());
    });
}

void JmapBackend::destroyEmailQuietly(const QString &remoteId)
{
    JmapRequest *request = newRequest();
    if (!request)
        return;
    request->addCall(QStringLiteral("Email/set"),
                     QJsonObject{{QStringLiteral("accountId"), m_session->mailAccountId()},
                                 {QStringLiteral("destroy"), QJsonArray{remoteId}}});
    request->send([request](Error, const QList<JmapRequest::Response> &, const QString &) {
        request->deleteLater();
    });
}

// --- Push ------------------------------------------------------------------

void JmapBackend::startPush(const QString &folder)
{
    m_pushWanted = true;
    // Re-aiming, not reconnecting. A JMAP EventSource covers the whole account,
    // so a folder change costs nothing here — where IMAP has to leave IDLE,
    // SELECT the new mailbox and idle again on every click.
    m_pushFolder = folder;
    if (m_pushReply)
        return;
    openPushStream();
}

void JmapBackend::stopPush()
{
    m_pushWanted = false;
    if (m_pushRetryTimer)
        m_pushRetryTimer->stop();
    m_pushRetries = 0;
    m_pushBuffer.clear();
    // Dropped rather than resumed: the caller asked to stop, and replaying
    // events from before it did would be answering a question nobody asked.
    m_pushLastEventId.clear();
    if (m_pushReply) {
        QNetworkReply *reply = m_pushReply;
        m_pushReply = nullptr;
        reply->disconnect(this);
        reply->abort();
        reply->deleteLater();
    }
    if (m_pushActive) {
        m_pushActive = false;
        // No signal: pushActive() is polled by the caller's fallback timer,
        // which is exactly what should take over now.
    }
}

void JmapBackend::openPushStream()
{
    if (!m_pushWanted || m_pushReply || !m_session->isValid())
        return;

    const QUrl url = m_session->eventSourceUrl(
        {QStringLiteral("Email"), QStringLiteral("Mailbox")}, kPushPingSeconds());
    if (!url.isValid() || url.isEmpty())
        return; // the server offers no EventSource; the caller keeps polling

    if (!m_net)
        m_net = new QNetworkAccessManager(this);

    QNetworkRequest request(url);
    m_session->authorize(request);
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("text/event-stream"));
    if (!m_pushLastEventId.isEmpty())
        request.setRawHeader(QByteArrayLiteral("Last-Event-ID"), m_pushLastEventId.toUtf8());
    // Deliberately no transfer timeout. Every other request here sets one; this
    // is the one whose whole purpose is to stay open and say nothing for
    // minutes at a time, and a timeout would tear it down on schedule.
    m_pushBuffer.clear();

    m_pushReply = m_net->get(request);
    m_session->guardRedirects(m_pushReply);
    // The stream is established when the server answers 200, not when it first
    // has something to say — which may be minutes away, or a whole ping
    // interval. Waiting for data would leave pushActive() false (and the
    // caller's fallback poll running) across an entirely healthy quiet period.
    connect(m_pushReply, &QNetworkReply::metaDataChanged, this, [this] {
        if (!m_pushReply || m_pushActive)
            return;
        if (m_pushReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200)
            return;
        m_pushActive = true;
        m_pushRetries = 0;
    });
    connect(m_pushReply, &QNetworkReply::readyRead, this, &JmapBackend::readPushStream);
    connect(m_pushReply, &QNetworkReply::finished, this, [this] {
        QNetworkReply *reply = m_pushReply;
        if (!reply)
            return; // stopPush() got there first
        m_pushReply = nullptr;
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        reply->deleteLater();
        m_pushActive = false;

        // A stream that ends is normal — servers close them, and `closeafter`
        // asks them to — so the ordinary answer is to open another.
        if (status == 401) {
            m_session->refresh();
            schedulePushRetry();
            return;
        }
        // But a server can also say, immediately and definitively, that it does
        // not do this: the Cyrus in the test container answers 204 in under a
        // millisecond because its httpd was built without push. Reconnecting
        // for ever against that is pure waste, and it is indistinguishable from
        // a dropped stream unless the status is read. Anything in the 2xx-that
        // -is-not-200 or 4xx-that-is-not-transient range is taken as "this
        // server has no EventSource"; push simply stays off and the caller's
        // poll timer remains the only refresh, which is a supported state.
        const bool transient = status == 0        // socket-level, may recover
            || status == 408 || status == 429     // timeout, rate limit
            || status >= 500;                     // server-side, may recover
        if (status == 200 || transient) {
            schedulePushRetry();
            return;
        }
        qWarning() << "mailove: JMAP server does not offer an EventSource (HTTP" << status
                   << ") - falling back to polling";
        m_pushWanted = false;
    });
}

void JmapBackend::readPushStream()
{
    if (!m_pushReply)
        return;
    const int status = m_pushReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status != 0 && status != 200) {
        m_pushReply->readAll(); // let finished() deal with it
        return;
    }
    if (!m_pushActive) {
        m_pushActive = true;
        m_pushRetries = 0; // a stream that opened resets the backoff
    }

    m_pushBuffer += m_pushReply->readAll();
    if (m_pushBuffer.size() > kMaxPushBufferBytes()) {
        // A server streaming something that is not events, or one event larger
        // than any StateChange could be. Drop it rather than grow without
        // bound; the next event boundary resynchronises.
        m_pushBuffer.clear();
        return;
    }
    const QList<QByteArray> blocks = takeSseBlocks(m_pushBuffer);
    for (const QByteArray &block : blocks)
        handlePushEvent(block);
}

QList<QByteArray> JmapBackend::takeSseBlocks(QByteArray &buffer)
{
    // Hold back a trailing CR: it may be the first half of a CRLF whose LF is
    // still on the wire, and normalising it now would invent a line ending.
    int usable = buffer.size();
    if (usable > 0 && buffer.at(usable - 1) == '\r')
        --usable;

    // SSE accepts CRLF, LF or a bare CR; normalising means the split below only
    // ever looks for a blank LF line.
    QByteArray head = buffer.left(usable);
    head.replace("\r\n", "\n").replace('\r', '\n');
    const QByteArray tail = buffer.mid(usable);

    QList<QByteArray> blocks;
    int cut;
    while ((cut = head.indexOf("\n\n")) >= 0) {
        blocks.append(head.left(cut));
        head.remove(0, cut + 2);
    }
    buffer = head + tail;
    return blocks;
}

JmapBackend::PushEvent JmapBackend::parseSseBlock(const QByteArray &block)
{
    PushEvent event;
    bool haveData = false;
    for (const QByteArray &line : block.split('\n')) {
        if (line.isEmpty() || line.startsWith(':'))
            continue; // a comment, which is how servers keep the socket warm

        const int colon = line.indexOf(':');
        const QByteArray field = colon < 0 ? line : line.left(colon);
        QByteArray value = colon < 0 ? QByteArray() : line.mid(colon + 1);
        // Exactly one leading space is syntax, not content — a second belongs
        // to the value.
        if (value.startsWith(' '))
            value.remove(0, 1);

        if (field == "data") {
            if (haveData)
                event.data += '\n'; // several data lines are one payload
            event.data += value;
            haveData = true;
        } else if (field == "event") {
            event.name = QString::fromUtf8(value);
        } else if (field == "id") {
            event.id = QString::fromUtf8(value);
        }
    }
    return event;
}

bool JmapBackend::stateChangeTouchesMail(const QByteArray &data, const QString &accountId)
{
    // A StateChange (RFC 8620 §7.1) names the account and the types whose state
    // moved. What actually changed is then fetched the ordinary way, which is
    // what keeps IDLE and EventSource interchangeable to the caller.
    const QJsonObject changed = QJsonDocument::fromJson(data)
                                    .object()
                                    .value(QLatin1String("changed"))
                                    .toObject()
                                    .value(accountId)
                                    .toObject();
    // Email covers new mail and flags; Mailbox covers counts and the tree.
    // The calendar and contact types share the channel and are not ours.
    return changed.contains(QLatin1String("Email"))
        || changed.contains(QLatin1String("Mailbox"));
}

void JmapBackend::handlePushEvent(const QByteArray &block)
{
    const PushEvent event = parseSseBlock(block);
    if (!event.id.isEmpty())
        m_pushLastEventId = event.id;
    if (event.data.isEmpty() || event.name == QLatin1String("ping"))
        return;
    if (!stateChangeTouchesMail(event.data, m_session->mailAccountId()))
        return;

    // Both, and in this order. The open folder is what somebody is looking at,
    // so it is refreshed first; the account-wide news is what the stream can
    // say and IDLE cannot, and is what keeps the other folders' unread counts
    // honest without opening them.
    if (!m_pushFolder.isEmpty())
        Q_EMIT folderChanged(m_pushFolder);
    Q_EMIT accountChanged();
}

void JmapBackend::schedulePushRetry()
{
    if (!m_pushWanted)
        return;
    if (!m_pushRetryTimer) {
        m_pushRetryTimer = new QTimer(this);
        m_pushRetryTimer->setSingleShot(true);
        connect(m_pushRetryTimer, &QTimer::timeout, this, &JmapBackend::openPushStream);
    }
    // Exponential with jitter: a server coming back up is met by clients
    // spread over the interval rather than all of them on the same second.
    const int step = qMin(m_pushRetries++, kPushMaxBackoffShift());
    const int base = kPushBaseRetryMs() << step;
    const int delay = base + QRandomGenerator::global()->bounded(base / 2 + 1);
    m_pushRetryTimer->start(qMin(delay, kPushMaxRetryMs()));
}
