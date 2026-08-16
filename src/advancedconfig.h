// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QHash>
#include <QList>
#include <QObject>
#include <QReadWriteLock>
#include <QString>
#include <QVariant>
#include <QVariantList>

#include <functional>

/**
 * The tunables that have no widget of their own: fetch pacing, connection
 * counts, protocol timeouts, spam weights, cache thresholds.
 *
 * One table (kSchema in the .cpp) is the only place a default, a range or a
 * description is written down. Everything else — the accessors call sites use,
 * the clamping, the seeded template, the reference list in Settings — is
 * derived from it, so the three cannot drift apart.
 *
 * Storage is a plain INI file the user owns, `advanced.conf` next to
 * mailove.conf, *not* a QSettings value: QSettings escapes multi-line strings
 * into one unreadable quoted line (see how a signature is stored), which would
 * take the comments with it. Nothing here ever rewrites that file except an
 * explicit save from the Settings page, so comments, blank lines and ordering
 * survive exactly as typed.
 *
 * No secret is ever kept here. A Secret knob's line holds "@wallet" and
 * nothing else: a value typed on one is moved into the system wallet — on
 * save, and on startup for a file edited by hand — and the line rewritten
 * before anything is written to disk. Nothing in this class can hand a secret
 * back out; the reader looks it up in the wallet under walletKeyFor().
 *
 * Reads are lazy and cached; an absent key, an unparsable one and an
 * out-of-range one all end at the schema default, so a broken file degrades to
 * stock behaviour rather than to a broken client.
 */
class AdvancedConfig : public QObject
{
    Q_OBJECT
    /// The file being edited, shown in the UI so it can be found by hand.
    Q_PROPERTY(QString filePath READ filePath CONSTANT)
    /// The file's text, verbatim. Empty when it does not exist yet.
    Q_PROPERTY(QString text READ text NOTIFY textChanged)

public:
    /// Secret is a String whose value never lives in this file. The file only
    /// ever holds the placeholder below; the value itself goes to the system
    /// wallet, which is the one place this client keeps anything secret.
    enum class Type { Int, Double, Bool, String, Secret };
    /// Whether a change reaches the running client or waits for a restart.
    /// Live for anything read at the point of use, Restart for what is read
    /// once while something is being built (a timer's interval, a connection).
    enum class Reload { Live, Restart };

    /// One tunable. `key` is "group/name", which is also the INI [group] and
    /// key= it is read from.
    struct Knob {
        const char *key;
        Type type;
        QVariant def;
        QVariant min; ///< Int/Double only; invalid = unbounded
        QVariant max;
        Reload reload;
        const char *doc; ///< one line, shown in the reference list
    };

    /// A complaint about the text being edited. `line` is 1-based; 0 means the
    /// problem is not tied to one line.
    struct Issue {
        int line = 0;
        QString text;
    };

    static AdvancedConfig &instance();

    // --- reading, for call sites ---------------------------------------
    // The key must exist in the schema; a typo is a programming error and
    // trips an assertion in a debug build rather than silently reading 0.
    static int i(const char *key);
    static double d(const char *key);
    static bool b(const char *key);
    static QString s(const char *key);

    static QString filePath();
    QString text() const;

    // --- secrets ---------------------------------------------------------
    /// What a Secret key is allowed to hold in the file: a pointer at the
    /// wallet, never a secret. Anything else typed on such a line is moved to
    /// the wallet and the line rewritten to this, on save and on sweep alike.
    static QString walletPlaceholder();
    /// The wallet key a Secret knob is stored under — "advanced/" plus the
    /// schema key, so the reader (MailClient) and this writer cannot drift.
    static QString walletKeyFor(const QString &key);
    /// Where a secret goes. Called with the wallet key and the value as typed;
    /// an empty value means "forget it". A function rather than a QtKeychain
    /// call here because this file links into a dozen test binaries that have
    /// no wallet — main() installs the real one.
    using SecretSink = std::function<void(const QString &walletKey, const QString &value)>;
    static void setSecretSink(SecretSink sink);
    /// Moves any secret already sitting in the file into the wallet and
    /// rewrites the file with placeholders. Called once at startup, after the
    /// sink is installed, so a hand-edited file does not keep a secret on disk
    /// until the next save. The only rewrite this class does on its own.
    void sweepSecrets();

    // --- editor support -------------------------------------------------
    /// Syntax and schema problems in \a candidate, worst first. Fatal syntax
    /// errors and unknown keys both land here; the UI blocks Apply on the
    /// former and only warns about the latter, so a typo does not eat the line.
    Q_INVOKABLE QVariantList problems(const QString &candidate) const;
    /// Keys in \a candidate whose new value only takes effect on restart.
    Q_INVOKABLE QStringList restartKeys(const QString &candidate) const;
    /// Writes \a candidate verbatim and re-reads it. False (with \a error set
    /// through the returned string) when the file cannot be written; a text
    /// with syntax errors is refused outright.
    Q_INVOKABLE QString save(const QString &candidate);
    /// \a text with \a key added at its default value, placed under the
    /// [group] it belongs to if that section is already there and appended as
    /// a new one if it is not. Unchanged when the key is already set — the
    /// point is to reach a line to edit, not to add a second one.
    Q_INVOKABLE QString withKey(const QString &text, const QString &key) const;
    /// Every knob as {key, group, type, def, range, doc, restart, set}, in
    /// schema order. `set` is true when the current file overrides it — which
    /// is what the reference list highlights.
    Q_INVOKABLE QVariantList reference() const;
    /// The whole schema as commented-out INI, for a first-run file or the
    /// "Insert all defaults" button. Every key is present and inert, which is
    /// how the format documents itself.
    Q_INVOKABLE QString defaultTemplate() const;

Q_SIGNALS:
    void textChanged();
    /// A save landed: call sites reading Live keys will see the new values.
    void reloaded();

private:
    explicit AdvancedConfig(QObject *parent = nullptr);

    struct Parsed {
        QHash<QString, QString> raw; ///< "group/key" -> value as typed
        QList<Issue> errors;
        QList<Issue> warnings;
    };
    /// Line-based INI: [group], key = value, # and ; comments. Hand-written
    /// rather than QSettings so a syntax error can name the line it is on —
    /// QSettings reports FormatError with no location — and so a value with a
    /// comma stays one string instead of becoming a QStringList.
    static Parsed parse(const QString &text);
    /// Typed, clamped values for \a raw, appending what had to be corrected.
    static QHash<QString, QVariant> resolve(const QHash<QString, QString> &raw,
                                            const QHash<QString, int> *lines,
                                            QList<Issue> *warnings);
    static const Knob *knob(const QString &key);
    /// \a text with every Secret line's value replaced by the placeholder,
    /// collecting what was found in \a relayed (wallet key -> value as typed).
    /// Formatting is otherwise untouched: only the text right of the '=' on
    /// those lines changes.
    static QString scrubSecrets(const QString &text, QHash<QString, QString> *relayed);
    /// Position of \a key in the schema, or -1. Call sites pass string
    /// literals, so the answer is memoised per pointer: a read on a hot path
    /// (the message list asks for the spam threshold once per row, per role)
    /// must not walk the schema or build a QString to do it.
    static int indexOf(const char *key);
    void load();
    void apply(const QHash<QString, QVariant> &overrides);
    QVariant value(const char *key) const;

    QString m_text;
    QHash<QString, QVariant> m_values; ///< only what the file overrides
    /// Every knob's value in force, in schema order — defaults with the
    /// overrides applied, so a read is one indexed lookup.
    QList<QVariant> m_effective;
    /// m_effective is read from worker threads (the store, the attachment
    /// writer, the spam scorer) and rewritten by a save on the GUI thread.
    mutable QReadWriteLock m_lock;
};
