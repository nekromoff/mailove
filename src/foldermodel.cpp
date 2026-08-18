// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "foldermodel.h"

#include <QSettings>

static QString collapsedSettingsKey(const QString &accountKey)
{
    // '/' would create nested QSettings groups — flatten it away.
    QString safe = accountKey;
    safe.replace(QLatin1Char('/'), QLatin1Char('_'));
    return QStringLiteral("ui/collapsedFolders/") + safe;
}

int FolderModel::rowForMailBox(const QString &mailBox) const
{
    if (mailBox.isEmpty())
        return -1;
    for (int row = 0; row < m_visible.size(); ++row) {
        if (m_all.at(m_visible.at(row)).mailBox == mailBox)
            return row;
    }
    return -1;
}

QString FolderModel::mailBoxAt(int row) const
{
    if (row < 0 || row >= m_visible.size())
        return {};
    return m_all.at(m_visible.at(row)).mailBox;
}

bool FolderModel::selectableAt(int row) const
{
    if (row < 0 || row >= m_visible.size())
        return false;
    return m_all.at(m_visible.at(row)).selectable;
}

int FolderModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_visible.size();
}

QVariant FolderModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_visible.size())
        return {};
    const int allIndex = m_visible.at(index.row());
    const Folder &f = m_all.at(allIndex);
    switch (role) {
    case NameRole:
        return f.displayName;
    case MailBoxRole:
        return f.mailBox;
    case LevelRole:
        return f.level;
    case SelectableRole:
        return f.selectable;
    case HasChildrenRole:
        return hasChildren(allIndex);
    case ExpandedRole:
        return !m_collapsed.contains(f.mailBox);
    case UnreadRole:
        return m_unread.value(f.mailBox, 0);
    case HiddenUnreadRole:
        return m_hiddenUnread.value(allIndex, 0);
    }
    return {};
}

QHash<int, QByteArray> FolderModel::roleNames() const
{
    return {
        {NameRole, "name"},
        {MailBoxRole, "mailBox"},
        {LevelRole, "level"},
        {SelectableRole, "selectable"},
        {HasChildrenRole, "hasChildren"},
        {ExpandedRole, "expanded"},
        {UnreadRole, "unread"},
        {HiddenUnreadRole, "hiddenUnread"},
    };
}

void FolderModel::setUnreadCounts(QHash<QString, int> counts)
{
    if (counts == m_unread)
        return; // recounts land often and usually say the same thing
    m_unread = std::move(counts);
    recomputeHiddenUnread();
    if (m_visible.isEmpty())
        return;
    Q_EMIT dataChanged(index(0), index(m_visible.size() - 1),
                       {UnreadRole, HiddenUnreadRole});
}

QStringList FolderModel::allMailBoxes() const
{
    QStringList out;
    out.reserve(m_all.size());
    for (const Folder &f : m_all)
        out.append(f.mailBox);
    return out;
}

QStringList FolderModel::selectableMailBoxes() const
{
    QStringList out;
    out.reserve(m_all.size());
    for (const Folder &f : m_all) {
        if (f.selectable)
            out.append(f.mailBox);
    }
    return out;
}

QSet<QString> FolderModel::savedCollapsed(const QString &accountKey)
{
    if (accountKey.isEmpty())
        return {};
    QSettings s(QStringLiteral("mailove"), QStringLiteral("mailove"));
    const QStringList saved = s.value(collapsedSettingsKey(accountKey)).toStringList();
    return QSet<QString>(saved.begin(), saved.end());
}

void FolderModel::toggleSavedCollapsed(const QString &accountKey, const QString &mailBox)
{
    if (accountKey.isEmpty() || mailBox.isEmpty())
        return;
    QSettings s(QStringLiteral("mailove"), QStringLiteral("mailove"));
    const QString key = collapsedSettingsKey(accountKey);
    QStringList saved = s.value(key).toStringList();
    if (saved.removeAll(mailBox) == 0)
        saved.append(mailBox);
    s.setValue(key, saved);
}

void FolderModel::setAccountKey(const QString &key)
{
    if (key == m_accountKey)
        return;
    m_accountKey = key;
    m_collapsed = savedCollapsed(key);
    beginResetModel();
    rebuildVisible();
    endResetModel();
}

void FolderModel::saveCollapsed() const
{
    if (m_accountKey.isEmpty())
        return;
    QSettings s(QStringLiteral("mailove"), QStringLiteral("mailove"));
    s.setValue(collapsedSettingsKey(m_accountKey), QStringList(m_collapsed.values()));
}

void FolderModel::setFolders(QList<Folder> folders)
{
    // The same tree is handed here several times per account switch: once from
    // the cache, once from what the server lists, and again from any pass that
    // re-derives it. Each one used to be a full reset, and a reset empties the
    // view before refilling it — so the sidebar blinked to nothing and back
    // three times on one click, taking the selection and the auto-open
    // debounce with it every time (see folderList.onCountChanged in Main.qml,
    // which cannot tell a repopulation from a real change).
    //
    // Comparing costs one pass over a list of tens of entries. The reset it
    // avoids costs a rebuild of every delegate.
    if (folders == m_all)
        return;
    beginResetModel();
    m_all = std::move(folders);
    rebuildVisible();
    endResetModel();
}

bool FolderModel::hasChildren(int allIndex) const
{
    return allIndex + 1 < m_all.size()
        && m_all.at(allIndex + 1).level > m_all.at(allIndex).level;
}

void FolderModel::toggleExpanded(int row)
{
    if (row < 0 || row >= m_visible.size())
        return;
    const int allIndex = m_visible.at(row);
    if (!hasChildren(allIndex))
        return;
    const QString &mailBox = m_all.at(allIndex).mailBox;
    if (m_collapsed.contains(mailBox))
        m_collapsed.remove(mailBox);
    else
        m_collapsed.insert(mailBox);
    saveCollapsed();
    beginResetModel();
    rebuildVisible();
    endResetModel();
}

void FolderModel::expandRow(int row)
{
    if (row < 0 || row >= m_visible.size())
        return;
    const int allIndex = m_visible.at(row);
    if (!hasChildren(allIndex) || !m_collapsed.contains(m_all.at(allIndex).mailBox))
        return;
    toggleExpanded(row);
}

void FolderModel::rebuildVisible()
{
    m_visible.clear();
    int skipDeeperThan = -1; // hide rows below a collapsed ancestor
    for (int i = 0; i < m_all.size(); ++i) {
        const Folder &f = m_all.at(i);
        if (skipDeeperThan >= 0 && f.level > skipDeeperThan)
            continue;
        skipDeeperThan = -1;
        m_visible.append(i);
        if (m_collapsed.contains(f.mailBox))
            skipDeeperThan = f.level;
    }
    recomputeHiddenUnread();
}

void FolderModel::recomputeHiddenUnread()
{
    m_hiddenUnread.assign(m_all.size(), 0);
    const QSet<int> visible(m_visible.cbegin(), m_visible.cend());
    for (int i = 0; i < m_all.size(); ++i) {
        if (visible.contains(i))
            continue; // it is on screen and speaks for itself
        const int unread = m_unread.value(m_all.at(i).mailBox, 0);
        if (unread == 0)
            continue;
        // Credit every ancestor, not just the nearest: with two levels folded
        // the number has to reach the one row that is actually drawn.
        for (int j = i - 1, level = m_all.at(i).level; j >= 0 && level > 0; --j) {
            if (m_all.at(j).level < level) {
                level = m_all.at(j).level;
                m_hiddenUnread[j] += unread;
            }
        }
    }
}
