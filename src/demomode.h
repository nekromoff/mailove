// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QObject>
#include <QString>

/**
 * Demo mode: real mail on screen, fake words in its place — for screenshots
 * that show a working client without showing anyone's mail.
 *
 * Purely a display filter. Nothing that is stored, synced, sent, searched or
 * acted on ever passes through here: the store, the models' keys, reply and
 * forward data and every action keep the real values, and turning the mode
 * off shows the real mail again at once. What it covers is what gets painted
 * — account and folder names, the list's subjects, correspondents and dates,
 * the open message's headers and its body — each at the one place it is
 * turned into text on screen.
 *
 * Replacement is per word, so a name reads the same in the list, in the
 * header and in the body, and a line keeps roughly its shape: every word
 * becomes an English word of about its length, in the same capitalisation;
 * digits become other digits; an address becomes word.word@word.com. Dates
 * move by one fixed offset, so the order and the spacing between messages
 * survive. The mapping is keyed by a random salt drawn at launch (or by
 * demo/seed, for screenshots that must come out the same every run), so a
 * fake word cannot be looked up to recover the one it stands for.
 */
class DemoMode : public QObject
{
    Q_OBJECT
    /// Whether demo mode is on. Bindings that call text() reference this, so
    /// they re-run when it is switched in Settings.
    Q_PROPERTY(bool on READ on NOTIFY changed)

public:
    static DemoMode &instance();

    static bool enabled();
    bool on() const { return enabled(); }

    /// \a s with every word, number and address replaced. Unchanged when demo
    /// mode is off.
    Q_INVOKABLE static QString text(const QString &s);
    /// \a html with the text between its tags replaced as text() does, and
    /// the markup itself — tags, attributes, entities, <style> and <script>
    /// bodies, comments — left byte for byte. Unchanged when demo mode is off.
    static QByteArray html(const QByteArray &html);
    /// html() for QML, which holds markup as a string — a rich-text field's
    /// contents, such as a signature.
    Q_INVOKABLE static QString markup(const QString &html);
    /// A key fingerprint or key id with every hex digit replaced, spacing and
    /// case kept — a real one could be looked up on a keyserver, which names
    /// its owner. The same key always gets the same fake. Unchanged when off.
    Q_INVOKABLE static QString fingerprint(const QString &fp);
    /// \a s — the client's own sentence about someone, such as a signature
    /// verdict — with only the addresses and key ids in it replaced, so the
    /// explanation still reads. Unchanged when off.
    Q_INVOKABLE static QString identifiers(const QString &s);
    /// \a when moved by the session's fixed offset. Unchanged when off.
    static QDateTime date(const QDateTime &when);
    /// The offset date() applies, in seconds; 0 when demo mode is off.
    static qint64 dateShiftSecs();

    /// The same, unconditionally — for tests, which have no config to turn
    /// the mode on with. \a salt picks the mapping.
    static QString scrambleText(const QString &s, quint64 salt);
    static QString scrambleHtml(const QString &html, quint64 salt);
    static QString scrambleFingerprint(const QString &fp, quint64 salt);
    static QString scrambleIdentifiers(const QString &s, quint64 salt);

Q_SIGNALS:
    /// Demo mode was switched, or its seed changed: what is on screen is stale.
    void changed();

private:
    explicit DemoMode(QObject *parent = nullptr);
    static quint64 salt();

    bool m_lastOn = false;
    int m_lastSeed = 0;
};
