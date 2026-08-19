// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QFileSystemWatcher>
#include <QQmlPropertyMap>
#include <QVariant>

/**
 * The window's persisted UI state — the [ui] group of mailove.conf.
 *
 * This is deliberately not QML's Settings type. Settings holds every property
 * in its category in memory from startup and rewrites *all* of them on any one
 * change, so anything that touched the file meanwhile — a second Mailove, an
 * editor — was silently reverted to the values this run happened to start with.
 * That is how hand-picked label colors kept coming back empty.
 *
 * Here every write is one key, read-modify-written against the file as it
 * stands, and the file is watched so a change made elsewhere arrives as a
 * property update instead of being overwritten. A key this build does not know
 * is never touched: what another version wrote survives an older one running.
 */
class UiSettings : public QQmlPropertyMap
{
    Q_OBJECT

public:
    explicit UiSettings(QObject *parent = nullptr);

    /// The one instance, registered with QML as UiSettings.
    static UiSettings &instance();

protected:
    /// Called for every assignment made from QML; persists it before it lands.
    QVariant updateValue(const QString &key, const QVariant &input) override;

private:
    /// Re-reads the file into the map, emitting valueChanged for what moved.
    void reload();

    QFileSystemWatcher m_watcher;
    /// Set while reload() writes into the map, so watching our own write does
    /// not read the file back a second time for nothing.
    bool m_reloading = false;
};
