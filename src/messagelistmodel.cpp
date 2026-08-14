// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "messagelistmodel.h"

#include "spamheuristics.h"

#include <QDebug>
#include <QElapsedTimer>
#include <QLoggingCategory>

#include <algorithm>

namespace
{
/// Same contract as MailStore's SlowGuard: anything above one frame spent in
/// here is spent with the window frozen, so say so instead of letting it hide.
constexpr qint64 kSlowMs = 20;

/// The paging trend, for chasing "scrolling gets slower the longer I hold the
/// key": every append logs its size and cost when mailove.trace is on, so a cost
/// that grows with the model shows up as a rising series, not a one-off spike.
const QLoggingCategory &logModel()
{
    static const QLoggingCategory cat("mailove.trace");
    return cat;
}
}

int MessageListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_rows.size();
}

QVariant MessageListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_rows.size())
        return {};
    const Header &h = m_all.at(m_rows.at(index.row()));
    switch (role) {
    case SubjectRole:
        return h.subject.isEmpty() ? QStringLiteral("(no subject)") : h.subject;
    case FromRole:
        return h.from;
    case ToRole:
        return h.to;
    case DateRole: {
        const QDateTime local = h.date.toLocalTime();
        if (local.date() == QDate::currentDate())
            return local.toString(QStringLiteral("hh:mm"));
        return local.toString(m_dateFormat + QStringLiteral(" hh:mm"));
    }
    case UidRole:
        return h.uid;
    case SeenRole:
        return h.seen;
    case SuspiciousRole:
        return h.suspicious;
    case AuthInfoRole:
        return h.authInfo;
    case AttachmentRole:
        return kindHasAttachment(h.attachKind);
    case CalendarRole:
        return h.attachKind == CalendarAttachment;
    case ColorLabelRole:
        return h.colorLabel;
    case CryptoRole:
        return h.crypto;
    case SpamRole:
        // Only the confident tail is shown. "Unsure" deliberately renders as
        // nothing at all: a maybe-mark on an ordinary message is a false
        // positive the reader still has to spend attention dismissing.
        return h.spamState != 3 && h.spamScore >= SpamHeuristics::SpamThreshold;
    case SpamDetailRole:
        return h.spamDetail;
    }
    return {};
}

QHash<int, QByteArray> MessageListModel::roleNames() const
{
    return {
        {SubjectRole, "subject"},
        {FromRole, "from"},
        {ToRole, "to"},
        {DateRole, "date"},
        {UidRole, "uid"},
        {SeenRole, "seen"},
        {SuspiciousRole, "suspicious"},
        {AuthInfoRole, "authInfo"},
        {AttachmentRole, "hasAttachment"},
        {CalendarRole, "calendarAttachment"},
        {ColorLabelRole, "colorLabel"},
        {CryptoRole, "crypto"},
        {SpamRole, "spam"},
        {SpamDetailRole, "spamDetail"},
    };
}

void MessageListModel::primeKeys(Header &h)
{
    h.dateSecs = h.date.isValid() ? h.date.toSecsSinceEpoch() : 0;
    // The name the row actually shows: To where there is one (Sent, Drafts),
    // From everywhere else. Sorting the column by a field it is not displaying
    // would look like the sort was simply broken. `to` is only ever filled for
    // the folders that display it, so this needs no knowledge of which folder
    // is open — see MailClient::listsRecipients().
    h.fromKey = (h.to.isEmpty() ? h.from : h.to).toCaseFolded();
    h.subjectKey = h.subject.toCaseFolded();
}

void MessageListModel::setDateFormat(const QString &format)
{
    if (m_dateFormat == format)
        return;
    m_dateFormat = format;
    if (!m_rows.isEmpty())
        Q_EMIT dataChanged(index(0), index(m_rows.size() - 1), {DateRole});
}

void MessageListModel::setHeaders(QList<Header> headers)
{
    m_all = std::move(headers);
    for (Header &h : m_all)
        primeKeys(h);
    reindex();
    rebuildVisible();
}

int MessageListModel::appendHeaders(const QList<Header> &headers)
{
    if (headers.isEmpty())
        return 0;
    QElapsedTimer timer;
    timer.start();
    int added = 0;
    // Sorted inserts instead of a model reset, so the ListView keeps its
    // scroll position when older messages arrive.
    const auto cmp = [this](int a, int b) { return lessThan(m_all.at(a), m_all.at(b)); };
    QList<int> fresh; // m_all indexes of the genuinely new, visible rows
    fresh.reserve(headers.size());
    for (const Header &h : headers) {
        const auto known = m_byUid.constFind(h.uid);
        if (known != m_byUid.constEnd()) {
            // Already listed (usually from the disk cache): refresh the row so
            // server-derived fields (seen, attachment, auth verdict) update.
            Header &existing = m_all[known.value()];
            Header merged = h;
            // A head-only refresh only knows generic/none — keep the
            // refined kind (calendar invite) learned from the body.
            if (existing.attachKind > GenericAttachment && h.attachKind == GenericAttachment)
                merged.attachKind = existing.attachKind;
            // A locally-read message stays read: the server refresh
            // may predate our \Seen write-back landing there.
            if (existing.seen)
                merged.seen = true;
            // The color mark is local-only — the server never knows it.
            if (existing.colorLabel != 0)
                merged.colorLabel = existing.colorLabel;
            // Same as attachKind: a head-only refresh sees the outer content
            // type and nothing else, so it must not undo what the body taught
            // us (inline PGP, or a signature inside an encrypted message).
            if (existing.crypto > merged.crypto && merged.crypto > 0)
                merged.crypto = existing.crypto;
            primeKeys(merged);
            existing = merged;
            const int row = visibleRowOf(known.value());
            if (row >= 0) {
                const QModelIndex idx = index(row);
                Q_EMIT dataChanged(idx, idx);
            }
            continue;
        }
        ++added;
        const int at = m_all.size();
        m_all.append(h);
        primeKeys(m_all[at]);
        m_byUid.insert(h.uid, at);
        if ((hasFilter() || m_colorFilter != 0) && !matchesFilter(m_all.at(at)))
            continue;
        fresh.append(at);
    }

    // The new rows go in as contiguous runs, not one at a time. A page of
    // older mail is 500 rows that all belong together at the end of the list,
    // and inserting them singly cost 500 beginInsertRows/endInsertRows rounds
    // — each one a full round of view invalidation — plus 500 mid-list
    // insertions into m_rows, which on a 40k-row folder is tens of millions of
    // element moves. That is what made scrolling through an imported folder
    // crawl. In the paging case this loop runs exactly once.
    std::sort(fresh.begin(), fresh.end(), cmp);
    for (int i = 0; i < fresh.size();) {
        const int row = int(std::upper_bound(m_rows.begin(), m_rows.end(), fresh.at(i), cmp)
                            - m_rows.begin());
        // Everything that still sorts before the row now at `row` belongs in
        // the same run, in order: fresh is sorted, so they simply follow on.
        int run = 1;
        while (i + run < fresh.size()
               && (row == m_rows.size()
                   || cmp(fresh.at(i + run), m_rows.at(row))))
            ++run;
        beginInsertRows({}, row, row + run - 1);
        m_rows.insert(row, run, 0);
        for (int k = 0; k < run; ++k)
            m_rows[row + k] = fresh.at(i + k);
        endInsertRows();
        i += run;
    }
    const qint64 totalMs = timer.elapsed();
    qCDebug(logModel(), "append %lld rows (%d new) -> %lld total, %lld ms",
            qint64(headers.size()), added, qint64(m_all.size()), totalMs);
    if (totalMs > kSlowMs) {
        qWarning() << "messagelist: SLOW append" << headers.size() << "rows (" << added
                   << "new ) at" << m_all.size() << "total," << totalMs << "ms";
    }
    return added;
}

void MessageListModel::clear()
{
    beginResetModel();
    m_rows.clear();
    m_all.clear();
    m_byUid.clear();
    m_filter = QRegularExpression();
    endResetModel();
}

void MessageListModel::applyFilter(const QRegularExpression &pattern)
{
    // rebuildVisible() is a full model reset, which throws away every delegate
    // the view holds — far too violent to run for a filter that did not
    // change. The search path clears the filter before every query (including
    // the debounced one behind each keystroke), so without this guard that was
    // a reset per keystroke on a list the view is actively scrolling.
    if (m_filter == pattern)
        return;
    m_filter = pattern;
    rebuildVisible();
}

void MessageListModel::sortBy(int column, bool descending)
{
    if (m_sortColumn == SortColumn(column) && m_sortDescending == descending)
        return;
    m_sortColumn = SortColumn(column);
    m_sortDescending = descending;
    resortVisible();
}

bool MessageListModel::lessThan(const Header &a, const Header &b) const
{
    int c;
    switch (m_sortColumn) {
    case SortColumn::From:
        c = QString::compare(a.fromKey, b.fromKey);
        break;
    case SortColumn::Subject:
        c = QString::compare(a.subjectKey, b.subjectKey);
        break;
    case SortColumn::Attachment:
        // Ties fall back to date so the groups stay chronological.
        c = int(kindHasAttachment(a.attachKind)) - int(kindHasAttachment(b.attachKind));
        if (c == 0)
            c = a.dateSecs < b.dateSecs ? 1 : (b.dateSecs < a.dateSecs ? -1 : 0);
        break;
    default:
        c = a.dateSecs < b.dateSecs ? -1 : (b.dateSecs < a.dateSecs ? 1 : 0);
        break;
    }
    if (c != 0)
        return m_sortDescending ? c > 0 : c < 0;
    // Ties break on uid, which makes this a total order: no two rows compare
    // equal. That keeps rows with the same timestamp (or the same sender, when
    // sorting by sender) from shuffling on every re-sort, and it is what lets
    // visibleRowOf() find a row by binary search instead of scanning.
    if (a.uid == b.uid)
        return false;
    return m_sortDescending ? a.uid > b.uid : a.uid < b.uid;
}

int MessageListModel::visibleRowOf(int allIndex) const
{
    // m_rows is always held in sort order, so a row can be found by its sort
    // key rather than walked to. This was m_rows.indexOf(), a linear scan —
    // and every background update that touches one row (a cached body
    // revealing an attachment, a colour mark, a flag) went through it, so with
    // 40k rows paged in each of those cost a 40k-element walk. That is what
    // made a long paging session feel heavier the longer it went on.
    if (allIndex < 0 || allIndex >= m_all.size())
        return -1;
    const auto cmp = [this](int a, int b) { return lessThan(m_all.at(a), m_all.at(b)); };
    auto it = std::lower_bound(m_rows.begin(), m_rows.end(), allIndex, cmp);
    // lessThan is a total order, so the match is at that position if anywhere;
    // the loop is belt and braces for equal keys that should not exist.
    for (; it != m_rows.end() && !cmp(allIndex, *it); ++it) {
        if (*it == allIndex)
            return int(it - m_rows.begin());
    }
    return -1;
}

bool MessageListModel::matchesFilter(const Header &h) const
{
    if (m_colorFilter != 0 && h.colorLabel != m_colorFilter)
        return false;
    if (!hasFilter())
        return true;
    return m_filter.match(h.subject).hasMatch() || m_filter.match(h.from).hasMatch();
}

void MessageListModel::setColorFilter(int color)
{
    if (m_colorFilter == color)
        return;
    m_colorFilter = color;
    rebuildVisible();
}

void MessageListModel::reindex()
{
    m_byUid.clear();
    m_byUid.reserve(m_all.size());
    for (int i = 0; i < m_all.size(); ++i)
        m_byUid.insert(m_all.at(i).uid, i);
}

void MessageListModel::rebuildVisible()
{
    QElapsedTimer timer;
    timer.start();
    beginResetModel();
    m_rows.clear();
    m_rows.reserve(m_all.size());
    const bool filtered = hasFilter() || m_colorFilter != 0;
    for (int i = 0; i < m_all.size(); ++i) {
        if (!filtered || matchesFilter(m_all.at(i)))
            m_rows.append(i);
    }
    std::stable_sort(m_rows.begin(), m_rows.end(),
                     [this](int a, int b) { return lessThan(m_all.at(a), m_all.at(b)); });
    const qint64 sortMs = timer.elapsed();
    endResetModel();
    const qint64 totalMs = timer.elapsed();
    if (totalMs > kSlowMs) {
        qWarning() << "messagelist: SLOW rebuild" << m_all.size() << "rows," << m_rows.size()
                   << "visible; sort" << sortMs << "ms, reset" << (totalMs - sortMs) << "ms";
    }
}

void MessageListModel::resortVisible()
{
    if (m_rows.size() < 2)
        return;
    QElapsedTimer timer;
    timer.start();
    Q_EMIT layoutAboutToBeChanged({}, VerticalSortHint);

    const QList<int> before = m_rows;
    std::stable_sort(m_rows.begin(), m_rows.end(),
                     [this](int a, int b) { return lessThan(m_all.at(a), m_all.at(b)); });
    const qint64 sortMs = timer.elapsed();

    // Carry the view's persistent indices (selection, current row) over to
    // wherever their message ended up, so re-sorting does not reset them.
    QHash<int, int> rowOf;
    rowOf.reserve(m_rows.size());
    for (int row = 0; row < m_rows.size(); ++row)
        rowOf.insert(m_rows.at(row), row);
    const QModelIndexList from = persistentIndexList();
    QModelIndexList to;
    to.reserve(from.size());
    for (const QModelIndex &idx : from) {
        const int oldRow = idx.row();
        to.append(oldRow >= 0 && oldRow < before.size()
                      ? index(rowOf.value(before.at(oldRow), -1), idx.column())
                      : QModelIndex());
    }
    changePersistentIndexList(from, to);

    Q_EMIT layoutChanged({}, VerticalSortHint);
    const qint64 totalMs = timer.elapsed();
    if (totalMs > kSlowMs) {
        qWarning() << "messagelist: SLOW sort column" << int(m_sortColumn) << "over"
                   << m_rows.size() << "rows; sort" << sortMs << "ms, apply"
                   << (totalMs - sortMs) << "ms";
    }
}

qint64 MessageListModel::uidAt(int row) const
{
    return (row >= 0 && row < m_rows.size()) ? m_all.at(m_rows.at(row)).uid : -1;
}

QString MessageListModel::remoteIdAt(int row) const
{
    if (row < 0 || row >= m_rows.size())
        return {};
    const Header &header = m_all.at(m_rows.at(row));
    return header.remoteId.isEmpty() ? QString::number(header.uid) : header.remoteId;
}

int MessageListModel::rowForUid(qint64 uid) const
{
    if (uid < 0)
        return -1;
    const auto it = m_byUid.constFind(uid);
    return it == m_byUid.constEnd() ? -1 : visibleRowOf(it.value());
}

bool MessageListModel::seenAt(int row) const
{
    return row >= 0 && row < m_rows.size() && m_all.at(m_rows.at(row)).seen;
}

void MessageListModel::removeByUids(const QList<qint64> &uids)
{
    const QSet<qint64> gone(uids.begin(), uids.end());
    for (int i = m_rows.size() - 1; i >= 0; --i) {
        if (gone.contains(m_all.at(m_rows.at(i)).uid)) {
            beginRemoveRows({}, i, i);
            m_rows.removeAt(i);
            endRemoveRows();
        }
    }
    // Splicing m_all renumbers everything after the first hole, so the
    // surviving m_rows indices and the uid map are both rebuilt from scratch.
    const QList<qint64> visible = [this] {
        QList<qint64> out;
        out.reserve(m_rows.size());
        for (int idx : m_rows)
            out.append(m_all.at(idx).uid);
        return out;
    }();
    m_all.removeIf([&gone](const Header &h) { return gone.contains(h.uid); });
    reindex();
    m_rows.clear();
    m_rows.reserve(visible.size());
    for (qint64 uid : visible)
        m_rows.append(m_byUid.value(uid));
}

void MessageListModel::setCrypto(qint64 uid, int kind)
{
    const auto it = m_byUid.constFind(uid);
    if (it == m_byUid.constEnd() || m_all.at(it.value()).crypto == kind)
        return;
    m_all[it.value()].crypto = kind;
    const int row = visibleRowOf(it.value());
    if (row >= 0) {
        const QModelIndex idx = index(row);
        Q_EMIT dataChanged(idx, idx, {CryptoRole});
    }
}

void MessageListModel::setAttachKind(qint64 uid, int kind)
{
    const auto it = m_byUid.constFind(uid);
    if (it == m_byUid.constEnd() || m_all.at(it.value()).attachKind == kind)
        return;
    m_all[it.value()].attachKind = kind;
    const int row = visibleRowOf(it.value());
    if (row >= 0) {
        const QModelIndex idx = index(row);
        Q_EMIT dataChanged(idx, idx, {AttachmentRole, CalendarRole});
    }
}

QString MessageListModel::fromAt(int row) const
{
    return (row >= 0 && row < m_rows.size()) ? m_all.at(m_rows.at(row)).from : QString();
}

void MessageListModel::clearSpam(qint64 uid)
{
    const auto it = m_byUid.constFind(uid);
    if (it == m_byUid.constEnd())
        return;
    const int allIndex = it.value();
    Header &h = m_all[allIndex];
    h.spamScore = 0;
    h.spamState = 3;
    h.spamDetail.clear();
    const int row = visibleRowOf(allIndex);
    if (row >= 0) {
        const QModelIndex idx = index(row, 0);
        Q_EMIT dataChanged(idx, idx, {SpamRole, SpamDetailRole});
    }
}

void MessageListModel::setSpamVerdict(qint64 uid, int score, int state, const QString &detail)
{
    const auto it = m_byUid.constFind(uid);
    if (it == m_byUid.constEnd())
        return;
    Header &h = m_all[it.value()];
    // State 3 is the user's own answer — "not spam", or the known-correspondent
    // exemption. A body-stage re-score knows strictly less than that.
    if (h.spamState == 3)
        return;
    h.spamScore = score;
    h.spamState = state;
    h.spamDetail = detail;
    const int row = visibleRowOf(it.value());
    if (row >= 0) {
        const QModelIndex idx = index(row, 0);
        Q_EMIT dataChanged(idx, idx, {SpamRole, SpamDetailRole});
    }
}

int MessageListModel::spamStateOf(qint64 uid) const
{
    const auto it = m_byUid.constFind(uid);
    return it == m_byUid.constEnd() ? 0 : m_all.at(it.value()).spamState;
}

int MessageListModel::colorLabelAt(int row) const
{
    return (row >= 0 && row < m_rows.size()) ? m_all.at(m_rows.at(row)).colorLabel : 0;
}

void MessageListModel::setColorLabel(qint64 uid, int color)
{
    const auto it = m_byUid.constFind(uid);
    if (it == m_byUid.constEnd())
        return;
    const int allIndex = it.value();
    m_all[allIndex].colorLabel = color;

    const int row = visibleRowOf(allIndex);
    // The change can move the row into or out of an active color filter —
    // insert/remove it instead of only repainting in place.
    const bool matches = matchesFilter(m_all.at(allIndex));
    if (row >= 0 && !matches) {
        beginRemoveRows({}, row, row);
        m_rows.removeAt(row);
        endRemoveRows();
    } else if (row < 0 && matches) {
        const auto cmp = [this](int a, int b) { return lessThan(m_all.at(a), m_all.at(b)); };
        const int at = int(std::upper_bound(m_rows.begin(), m_rows.end(), allIndex, cmp)
                           - m_rows.begin());
        beginInsertRows({}, at, at);
        m_rows.insert(at, allIndex);
        endInsertRows();
    } else if (row >= 0) {
        const QModelIndex idx = index(row);
        Q_EMIT dataChanged(idx, idx, {ColorLabelRole});
    }
}

void MessageListModel::markUnseen(int row)
{
    if (row < 0 || row >= m_rows.size())
        return;
    m_all[m_rows.at(row)].seen = false;
    const QModelIndex idx = index(row);
    Q_EMIT dataChanged(idx, idx, {SeenRole});
}

void MessageListModel::markSeen(int row)
{
    if (row < 0 || row >= m_rows.size())
        return;
    m_all[m_rows.at(row)].seen = true;
    const QModelIndex idx = index(row);
    Q_EMIT dataChanged(idx, idx, {SeenRole});
}

void MessageListModel::markAllSeen()
{
    if (m_all.isEmpty())
        return;
    for (Header &h : m_all)
        h.seen = true;
    if (m_rows.isEmpty())
        return;
    // One span rather than a signal per row: nothing here reorders or filters
    // on \Seen, so every visible row simply repaints.
    Q_EMIT dataChanged(index(0), index(m_rows.size() - 1), {SeenRole});
}

QList<qint64> MessageListModel::allUids() const
{
    QList<qint64> uids;
    uids.reserve(m_all.size());
    for (const Header &h : m_all)
        uids.append(h.uid);
    return uids;
}
