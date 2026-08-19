// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QObject>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;

/// The decisions the update check makes about a response, separated from the
/// network plumbing that delivers one. Everything here is a pure function of
/// its arguments, which is what lets updatechecktest.cpp cover the cases that
/// actually carry risk — a tag that is not a version, a Location aimed
/// somewhere else, "3.10" against "3.9" — without a server or a socket.
namespace UpdateCheckLogic {

/// The version in a release tag, or empty if the tag is not one.
///
/// Strict on purpose. This string came off the network and is about to be put
/// in the window's own title row, beside the real version — the one place in
/// the app where the user is entitled to assume they are reading Mailove and
/// not a stranger. A tag reading "SECURITY: act now" must never reach a label,
/// and neither must one long enough to push the status breadcrumb off screen.
/// Digits and dots, four components at most, a leading "v" tolerated in case a
/// later tag grows one.
QString versionFromTag(const QString &tag);

/// The tag a redirect points at: the last path segment of \a location. Empty
/// unless \a location is an https URL on \a expectedHost — a 302 that leaves
/// the host we asked is not an answer to the question we asked, and its last
/// path segment is not something to read a version out of.
QString tagFromLocation(const QString &location, const QString &expectedHost);

/// Component-wise and numeric, because a string compare gets "3.10" against
/// "3.9" backwards. A missing component counts as zero, so "3.1" beats "3.0.9"
/// and ties with "3.1.0".
bool isNewer(const QString &candidate, const QString &running);

} // namespace UpdateCheckLogic

/**
 * Whether a newer Mailove has been released.
 *
 * One HEAD request to the project's "latest release" URL. GitHub answers that
 * with a 302 whose Location carries the tag, so the version arrives in a
 * header and no body is ever fetched, stored or parsed. The request carries
 * nothing but the User-Agent the client already sends: no identifier, no
 * account, no install id, no counter.
 *
 * Everything here is asynchronous. The GUI thread never waits on the network:
 * the reply lands on a signal, the three properties change, and the bindings
 * in the title row repaint themselves. A check that fails — offline, timed
 * out, rate-limited, no release at all — changes nothing and says nothing.
 * The user did not ask for this, so it must never cost them attention when it
 * does not work.
 */
class UpdateCheck : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available NOTIFY changed)
    Q_PROPERTY(QString latestVersion READ latestVersion NOTIFY changed)
    Q_PROPERTY(QString releaseUrl READ releaseUrl NOTIFY changed)

public:
    /// The one instance, registered with QML as Updates.
    static UpdateCheck &instance();

    /// The version a fetched release is measured against. MAILOVE_VERSION
    /// unless --force-version= said otherwise, which exists so the marker can
    /// be seen and the comparison exercised without cutting a release: run
    /// with --force-version=2.9 against a repo whose latest tag is 3.0 and the
    /// marker appears. Only the comparison moves — the window still shows the
    /// real version, so a forced run can never be mistaken for a real one.
    static QString runningVersion();
    static void setRunningVersion(const QString &version);

    /// True only once a strictly newer, fully validated version came back.
    bool available() const { return !m_latest.isEmpty(); }
    QString latestVersion() const { return m_latest; }
    /// Built here from the validated version and the configured template —
    /// never from the response. A hostile or tampered Location must not be
    /// able to choose the address the user's browser is sent to.
    QString releaseUrl() const;

    /// Arms the first check, 30 seconds out. Called once, after the UI is up:
    /// startup is when the client has an account to connect and a folder list
    /// to fetch, and this is the least urgent thing in the process.
    void start();

    /// A check the user implied by opening Settings. Skips the daily gate,
    /// because the point is that the answer is fresh while they are looking at
    /// it, but keeps a short floor so opening the sheet repeatedly does not
    /// turn into a request each time.
    Q_INVOKABLE void checkNow();

public Q_SLOTS:
    /// An automatic check: honors the daily interval. Wired to connectivity
    /// changes, so a machine that was offline at the 30-second mark still gets
    /// an answer once it has a network.
    void maybeCheck();

Q_SIGNALS:
    /// All three properties move together — there is only ever one answer.
    void changed();

private:
    explicit UpdateCheck(QObject *parent = nullptr);

    void check(bool userAsked);
    void finished(QNetworkReply *reply);

    QNetworkAccessManager *m_net = nullptr; ///< created on first use
    QString m_latest;                       ///< empty unless newer than ours
    bool m_inFlight = false;
};

