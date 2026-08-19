// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "uisettings.h"

#include <QFileInfo>
#include <QLoggingCategory>
#include <QSettings>

namespace
{
Q_LOGGING_CATEGORY(logUi, "mailove.uisettings")

/// The group these keys live in, and the only one this class touches.
QString uiKey(QLatin1StringView key)
{
    return QStringLiteral("ui/") + key;
}

struct Knob
{
    QLatin1StringView key;
    QVariant def;
};

/// Every key the window persists, with the value it has before anyone picks
/// one. The type of the default is also the type the stored string is read
/// back as — an INI file has only strings to offer.
const QList<Knob> &knobs()
{
    static const QList<Knob> list = {
        {QLatin1StringView("columnOrder"), QStringLiteral("[]")},
        {QLatin1StringView("sortColumn"), 0},
        {QLatin1StringView("sortDescending"), true},
        {QLatin1StringView("collapsedAccounts"), QStringLiteral("[]")},
        {QLatin1StringView("rowDensity"), 1},
        {QLatin1StringView("bgColor"), QString()},
        {QLatin1StringView("messageLayout"), 0},
        {QLatin1StringView("splitBelowHeight"), 0.0},
        {QLatin1StringView("splitBesideWidth"), 0.0},
        {QLatin1StringView("folderPaneWidth"), 220.0},
        {QLatin1StringView("composeInWindow"), false},
        {QLatin1StringView("composeQuoteSplitReply"), 0.0},
        {QLatin1StringView("composeQuoteSplitForward"), 0.0},
        {QLatin1StringView("shortcutDelete"), QStringLiteral("Del")},
        {QLatin1StringView("shortcutToggleRead"), QStringLiteral("M")},
        {QLatin1StringView("shortcutJunk"), QStringLiteral("J")},
        {QLatin1StringView("shortcutCompose"), QStringLiteral("C")},
        {QLatin1StringView("shortcutReply"), QStringLiteral("R")},
        {QLatin1StringView("shortcutForward"), QStringLiteral("F")},
        {QLatin1StringView("shortcutSelect"), QStringLiteral("Ins")},
        {QLatin1StringView("shortcutAttach"), QStringLiteral("Ctrl+Shift+A")},
        {QLatin1StringView("shortcutSend"), QStringLiteral("Ctrl+Return")},
        {QLatin1StringView("shortcutUndoSend"), QStringLiteral("Ctrl+Z")},
        {QLatin1StringView("shortcutFind"), QStringLiteral("Ctrl+F")},
        {QLatin1StringView("shortcutSource"), QStringLiteral("Ctrl+U")},
        {QLatin1StringView("shortcutLog"), QStringLiteral("Ctrl+Shift+L")},
        {QLatin1StringView("scaleKey0"), QStringLiteral("0")},
        {QLatin1StringView("scaleKey1"), QString()},
        {QLatin1StringView("scaleKey2"), QString()},
        {QLatin1StringView("scaleKey3"), QString()},
        {QLatin1StringView("scaleKey4"), QString()},
        {QLatin1StringView("scaleKey5"), QString()},
        {QLatin1StringView("scaleColor1"), QString()},
        {QLatin1StringView("scaleColor2"), QString()},
        {QLatin1StringView("scaleColor3"), QString()},
        {QLatin1StringView("scaleColor4"), QString()},
        {QLatin1StringView("scaleColor5"), QString()},
    };
    return list;
}

QSettings settings()
{
    return QSettings(QStringLiteral("mailove"), QStringLiteral("mailove"));
}

/// The stored value for \a knob, as the type the default says it is. A
/// QSettings built here and thrown away reads the file as it stands rather
/// than a copy taken at startup — that is the whole point of this class.
QVariant stored(const Knob &knob, QSettings &s)
{
    QVariant v = s.value(uiKey(knob.key));
    if (!v.isValid())
        return knob.def;
    // INI hands everything back as a string; the default names the real type.
    if (!v.convert(knob.def.metaType()))
        return knob.def;
    return v;
}
} // namespace

UiSettings &UiSettings::instance()
{
    static UiSettings self;
    return self;
}

UiSettings::UiSettings(QObject *parent)
    : QQmlPropertyMap(this, parent)
{
    QSettings s = settings();
    for (const Knob &knob : knobs())
        insert(knob.key, stored(knob, s));

    // The file, not the directory: QSettings replaces it through a temporary,
    // so the watch has to be re-armed after every change (see reload()).
    m_watcher.addPath(QFileInfo(s.fileName()).absoluteFilePath());
    connect(&m_watcher, &QFileSystemWatcher::fileChanged, this, &UiSettings::reload);
}

QVariant UiSettings::updateValue(const QString &key, const QVariant &input)
{
    // Straight through for anything not ours: the map is only asked about keys
    // it was given, so this is a guard against a typo becoming a stored key.
    if (!contains(key)) {
        qCWarning(logUi, "ui: refusing to store unknown setting %s", qUtf8Printable(key));
        return input;
    }
    if (!m_reloading) {
        QSettings s = settings();
        s.setValue(QStringLiteral("ui/") + key, input);
        // On disk now, one key deep, leaving every other key in the file — the
        // ones this build has never heard of included — exactly as it found it.
        s.sync();
    }
    return input;
}

void UiSettings::reload()
{
    // A replaced file drops the watch with it; the path has to be taken up
    // again or this is the last change ever noticed.
    QSettings s = settings();
    const QString path = QFileInfo(s.fileName()).absoluteFilePath();
    if (!m_watcher.files().contains(path))
        m_watcher.addPath(path);

    m_reloading = true;
    int moved = 0;
    for (const Knob &knob : knobs()) {
        const QVariant now = stored(knob, s);
        if (value(knob.key) == now)
            continue;
        // insert() does not route through updateValue(), so this updates the
        // window without writing what was just read straight back out.
        insert(knob.key, now);
        ++moved;
    }
    m_reloading = false;
    if (moved > 0)
        qCDebug(logUi, "ui: %d setting(s) changed on disk, picked up", moved);
}
