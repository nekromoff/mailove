// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QAtomicInt>
#include <QMutex>
#include <QWaitCondition>
#include <QDateTime>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

#include <functional>
#include <memory>

#include "accountstore.h"
#include "dkimverifier.h"
#include "foldermodel.h"
#include "mailbackend.h"
#include "maintenancescheduler.h"
#include "mailstore.h"
#include "syncengine.h"
#include "messagecontext.h"
#include "messagepresenter.h"
#include "messageverifier.h"
#include "messagelistmodel.h"
#include "pgpengine.h"
#include "spamheuristics.h"

class QThread;

class QThread;

namespace KMime
{
class Content;
class Message;
}
class OAuthHelper;
class PgpEngine;
class ViewerSchemeHandler;

/**
 * Central mail controller exposed to QML as the "Mail" singleton.
 *
 * Everything above the wire: the folder and message models, the reading pane,
 * compose, the offline cache, spam scoring and sender authentication. What
 * happens *on* the wire belongs to MailBackend (ImapBackend or JmapBackend),
 * and this class names no protocol — which mailbox is the trash, when to
 * backfill, what a header means are the same questions whichever one answered.
 *
 * All work is asynchronous on the event loop; the only threads are the DKIM
 * verifier, the search indexer and the unread recount, none of which touch the
 * network. How many connections a protocol needs, and which one a request goes
 * out on, is the backend's business alone.
 */
class MailClient : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool hasAccount READ hasAccount NOTIFY accountChanged)
    /// True while the active account is a local archive (imported mail, no
    /// server configured): nothing ever connects, the cache is the account.
    Q_PROPERTY(bool accountIsLocal READ accountIsLocal NOTIFY accountChanged)
    Q_PROPERTY(bool connected READ connected NOTIFY connectedChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(int spamRetentionDays READ spamRetentionDays WRITE setSpamRetentionDays
                   NOTIFY spamRetentionDaysChanged)
    /// Deleting spam removes it outright instead of filing it in the trash —
    /// both when the user deletes it and when the retention sweep does.
    /// On by default: spam in the trash is still spam to clear out. Persisted.
    Q_PROPERTY(bool spamSkipTrash READ spamSkipTrash WRITE setSpamSkipTrash
                   NOTIFY spamSkipTrashChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY statusTextChanged)
    /// True while a cache vacuum is running — the UI disables the button and
    /// shows a spinner, since the database is locked for writes meanwhile.
    Q_PROPERTY(bool reclaiming READ reclaiming NOTIFY reclaimingChanged)
    /// True while the search index is being rebuilt to fold diacritics. The
    /// window refuses to close during it: the swap at the end is what makes
    /// the work count, and abandoning it means starting the pass again.
    Q_PROPERTY(bool indexRebuilding READ indexRebuilding NOTIFY indexRebuildChanged)
    /// True from the moment a search starts until the last result is in. The
    /// list shows it directly — an empty list during a slow search is
    /// indistinguishable from "nothing found" unless the view says otherwise.
    Q_PROPERTY(bool searching READ searching NOTIFY searchingChanged)
    /// Hits delivered so far by the search in flight.
    Q_PROPERTY(int searchFound READ searchFound NOTIFY searchingChanged)
    /// How far that has got, 0-100, for the message shown on a close attempt.
    Q_PROPERTY(int indexRebuildPercent READ indexRebuildPercent NOTIFY indexRebuildChanged)
    /// A one-time cache migration is running. Generic on purpose: these three
    /// drive one modal, so the next migration needs a worker and nothing else.
    Q_PROPERTY(bool migrationRunning READ migrationRunning NOTIFY migrationChanged)
    Q_PROPERTY(QString migrationLabel READ migrationLabel NOTIFY migrationChanged)
    /// 0-100, or -1 when the total is not known yet — an indeterminate bar.
    Q_PROPERTY(int migrationPercent READ migrationPercent NOTIFY migrationChanged)
    /// ABOUT.md compiled into the binary (Settings → About). CONSTANT — baked
    /// in at build time, never changes at runtime.
    Q_PROPERTY(QString aboutText READ aboutText CONSTANT)
    Q_PROPERTY(FolderModel *folderModel READ folderModel CONSTANT)
    Q_PROPERTY(MessageListModel *messageModel READ messageModel CONSTANT)
    /// The reading pane's message context — the state MessageViewer binds to.
    /// Detached message windows get their own context via messageWindowReady.
    Q_PROPERTY(MessageContext *readingContext READ readingContext CONSTANT)
    /// Attachments of the last fetched message: [{name, sizeText}, …]
    Q_PROPERTY(QVariantList attachments READ attachments NOTIFY attachmentsChanged)
    /// Per-message opt-in for remote images/CSS/fonts; resets on every message.
    Q_PROPERTY(bool remoteContentAllowed READ remoteContentAllowed
                   WRITE setRemoteContentAllowed NOTIFY remoteContentAllowedChanged)
    /// Instant plain-text stand-in shown while the HTML view renders.
    Q_PROPERTY(QString textPreview READ textPreview NOTIFY textPreviewChanged)
    /// True while the shown message comes from a junk/spam folder: the viewer
    /// then defaults to plain text and renders HTML only on explicit request.
    Q_PROPERTY(bool junkTextOnly READ junkTextOnly NOTIFY junkTextOnlyChanged)

    // Account fields for prefilling the settings sheet
    Q_PROPERTY(QString accountHost READ accountHost NOTIFY accountChanged)
    Q_PROPERTY(int accountPort READ accountPort NOTIFY accountChanged)
    Q_PROPERTY(QString accountUser READ accountUser NOTIFY accountChanged)
    Q_PROPERTY(QString accountEmail READ accountEmail NOTIFY accountChanged)
    /// The address mail actually goes out as — accountEmail when the account
    /// sets one, the derived fallback when it does not. The settings editor
    /// wants accountEmail (the stored field, blank until saved); anything
    /// *showing* the identity in use wants this.
    Q_PROPERTY(QString accountSendAddress READ ownAddress NOTIFY accountChanged)
    Q_PROPERTY(QString accountDisplayName READ accountDisplayName NOTIFY accountChanged)
    Q_PROPERTY(QString accountOrganization READ accountOrganization NOTIFY accountChanged)
    Q_PROPERTY(int accountSecurity READ accountSecurity NOTIFY accountChanged)
    Q_PROPERTY(QString smtpHost READ smtpHost NOTIFY accountChanged)
    Q_PROPERTY(int smtpPort READ smtpPort NOTIFY accountChanged)
    Q_PROPERTY(int smtpSecurity READ smtpSecurity NOTIFY accountChanged)

    /// The active account's OpenPGP settings, for the compose window: which
    /// key it signs with (empty = none configured) and how it starts out.
    Q_PROPERTY(QString accountPgpKeyFp READ accountPgpKey NOTIFY accountChanged)
    Q_PROPERTY(bool accountPgpSignByDefault READ accountPgpSignByDefault
                   NOTIFY accountChanged)
    Q_PROPERTY(bool accountPgpEncryptByDefault READ accountPgpEncryptByDefault
                   NOTIFY accountChanged)
    /// Whether to ask a recipient's own domain for their key while composing
    /// (WKD). Never a keyserver — that would tell a third party who is about
    /// to be written to (doc/openpgp.md §7).
    Q_PROPERTY(bool accountPgpAutoWkd READ accountPgpAutoWkd NOTIFY accountChanged)

    // All configured accounts (display names) and which one is active
    Q_PROPERTY(QStringList accountNames READ accountNames NOTIFY accountsChanged)
    Q_PROPERTY(int currentAccount READ currentAccount NOTIFY accountsChanged)
    /// Bumped whenever a cached folder tree changes (collapse toggle) — QML
    /// bindings reference it so cachedFolderList() gets re-evaluated.
    Q_PROPERTY(int cachedFolderRevision READ cachedFolderRevision NOTIFY cachedFoldersChanged)

    /// Poll interval for the open folder in minutes, used only while IMAP
    /// IDLE push is not active. 0 disables polling. Persisted.
    Q_PROPERTY(int refreshMinutes READ refreshMinutes WRITE setRefreshMinutes
                   NOTIFY refreshMinutesChanged)
    /// Largest message body to keep in the offline cache, in MB (0 = no
    /// limit). Bigger ones are still opened on demand, just never stored.
    Q_PROPERTY(int maxBodyMB READ maxBodyMB WRITE setMaxBodyMB NOTIFY maxBodyMBChanged)
    /// Master switch for sender authentication: our own DKIM and ARC
    /// verification, and the SPF/DKIM/DMARC verdict our receiving server
    /// stamped into Authentication-Results. On by default. When off, nothing
    /// is checked and nothing is shown — no DNS query is emitted, and no
    /// verdict is stored on a message header. Persisted.
    Q_PROPERTY(bool authVerification READ authVerification WRITE setAuthVerification
                   NOTIFY authVerificationChanged)
    /// Writes a running trace of folder/account/sync activity to the console.
    /// Off by default; takes effect immediately. Persisted.
    Q_PROPERTY(bool debugLogging READ debugLogging WRITE setDebugLogging
                   NOTIFY debugLoggingChanged)
    /// The folder actually open right now. The sidebar follows this rather
    /// than deciding for itself which row is open.
    Q_PROPERTY(QString selectedFolder READ selectedFolder NOTIFY selectedFolderChanged)

    /// Qt date pattern (e.g. "dd/MM/yyyy") used for message dates in the list
    /// and the viewer; today's messages show only the time. Persisted.
    Q_PROPERTY(QString dateFormat READ dateFormat WRITE setDateFormat
                   NOTIFY dateFormatChanged)

public:
    // Keep in sync with the combo box in AccountSheet.qml
    enum Security { SslTls = 0, StartTls = 1, None = 2 };
    Q_ENUM(Security)

    explicit MailClient(QObject *parent = nullptr);
    /// Stops and joins the cache workers — both hold a raw `this` and a SQLite
    /// connection, neither of which may outlive the client.
    ~MailClient() override;

    /// The scheme handler that serves message bodies to the viewer.
    void setViewerHandler(ViewerSchemeHandler *handler);
    /// Hands the client the OpenPGP backend (main.cpp owns it). Without it —
    /// or with one that reports unavailable — encrypted mail is shown as
    /// encrypted and undecryptable, and nothing else changes.
    void setPgpEngine(PgpEngine *engine);

    bool hasAccount() const;
    bool accountIsLocal() const { return m_acct.local; }
    bool connected() const { return m_backend->isConnected(); }
    bool busy() const { return m_busy; }
    QString statusText() const { return m_statusText; }
    QString aboutText() const;
    FolderModel *folderModel() { return &m_folderModel; }
    MessageListModel *messageModel() { return &m_messageModel; }
    MessageContext *readingContext() { return m_reading; }

    QString accountHost() const { return m_acct.host; }
    int accountPort() const { return m_acct.port; }
    QString accountUser() const { return m_acct.user; }
    QString accountEmail() const { return m_acct.email; }
    QString accountDisplayName() const { return m_acct.displayName; }
    QString accountOrganization() const { return m_acct.organization; }
    int accountSecurity() const { return m_acct.security; }

    QString smtpHost() const { return m_acct.smtpHost; }
    int smtpPort() const { return m_acct.smtpPort; }
    int smtpSecurity() const { return m_acct.smtpSecurity; }

    QStringList accountNames() const;
    int currentAccount() const { return m_accounts.currentIndex(); }
    int cachedFolderRevision() const { return m_cachedFolderRevision; }
    int refreshMinutes() const { return m_refreshMinutes; }
    int spamRetentionDays() const { return m_spamRetentionDays; }
    void setSpamRetentionDays(int days);
    bool spamSkipTrash() const { return m_spamSkipTrash; }
    void setSpamSkipTrash(bool skip);
    /// True when deleting from the folder now open destroys the messages
    /// rather than filing them — already in the trash, or spam with
    /// spamSkipTrash() on. The confirmation prompt is worded from this.
    Q_INVOKABLE bool deleteIsPermanent() const;
    int maxBodyMB() const { return m_maxBodyMB; }
    void setMaxBodyMB(int mb);
    bool authVerification() const { return m_authVerification; }
    void setAuthVerification(bool on);
    QString selectedFolder() const { return m_selectedFolder; }
    bool debugLogging() const { return m_debugLogging; }
    void setDebugLogging(bool on);
    /// Installs the logging filter rules for quiet (default) or verbose mode.
    /// Static and called first thing in main(): parts of the app log during
    /// construction, before the settings-driven setDebugLogging() runs.
    static void applyLogFilterRules(bool on);
    void setRefreshMinutes(int minutes);
    QString dateFormat() const { return m_dateFormat; }
    void setDateFormat(const QString &format);
    /// Cached folder tree of account \a index for the sidebar, as a list of
    /// {name, mailBox, level} maps — available even while the account is not
    /// the connected one.
    Q_INVOKABLE QVariantList cachedFolderList(int index);
    /// Collapses/expands a folder in the cached tree of account \a index
    /// (persisted; the sidebar re-reads cachedFolderList on cachedFoldersChanged).
    Q_INVOKABLE void toggleCachedCollapsed(int index, const QString &mailBox);
    /// Opens a folder that may belong to another account: switches the
    /// connection there first when needed, then opens the folder.
    Q_INVOKABLE void openFolderInAccount(int index, const QString &mailBox);
    /// Config fields of account \a index as {host, port, security, user,
    /// smtpHost, smtpPort, smtpSecurity, authType, clientId, clientSecret};
    /// empty map for an unknown index.
    /// The account's own OpenPGP fingerprint, or empty when it has none.
    QString accountPgpKey() const;
    bool accountPgpSignByDefault() const;
    bool accountPgpEncryptByDefault() const;
    bool accountPgpAutoWkd() const;
    Q_INVOKABLE QVariantMap accountDetails(int index) const;
    /// Creates (index -1 or out of range) or updates an account from the same
    /// map shape accountDetails() returns (plus "password"/"savePassword"),
    /// then makes it the active one. An empty password keeps the stored one.
    Q_INVOKABLE void saveAccountDetails(int index, const QVariantMap &details);
    /// Writes just the keys \a details carries into an existing account, and
    /// touches nothing else: no wallet write, and above all no reconnect.
    ///
    /// This is what the settings page autosaves through. Everything that only
    /// changes how mail is written or displayed — the display name, the
    /// organization, the signature, the HTML preference, the OpenPGP settings
    /// — can be stored while a session is up, whereas saveAccountDetails()
    /// tears the session down and dials again, which is right for a changed
    /// server and quite wrong for every keystroke in the signature box.
    ///
    /// Server and identity keys ("host", "port", "security", "user", "email",
    /// "smtpHost", "smtpPort", "smtpSecurity", "authType", "local",
    /// "cacheKey") are refused here: they decide the account key that names
    /// the cache and the wallet entry, so they go through the explicit save.
    Q_INVOKABLE void saveAccountPrefs(int index, const QVariantMap &details);
    Q_INVOKABLE void removeAccount(int index);
    /// Imports a Thunderbird mail directory (mbox files, ".sbd" hierarchy)
    /// into a new local-archive account: browsable from the cache like any
    /// other account, but never connected or synced — unless server details
    /// are filled in later, which turns it into a normal account. Runs on a
    /// worker thread; importFinished() reports the outcome.
    Q_INVOKABLE void importThunderbird(const QUrl &dir);
    /// Reorders the account list (drag-and-drop in the account pane). Purely
    /// presentational — nothing is keyed on an account's position.
    Q_INVOKABLE void moveAccount(int from, int to);
    /// Disconnects, loads account \a index and reconnects.
    Q_INVOKABLE void switchAccount(int index);
    /// Builds a MIME message and sends it via SMTP. attachments are local file URLs.
    /// \a sign and \a encrypt are the compose window's toggles; both need the
    /// account to have an OpenPGP key configured, and encryption additionally
    /// needs a key for every recipient. A missing key is refused outright
    /// rather than silently downgraded to plaintext.
    /// \a appendQuote is a deferred reply/forward quote (too big or too
    /// remote-image-laden for the editor — see quotedBody) appended to the
    /// outgoing HTML here; \a appendStrip runs the remote-content strip on it
    /// first, deferred from the open for the same reason.
    Q_INVOKABLE void sendMail(const QString &to, const QString &cc, const QString &bcc,
                              const QString &subject, const QString &html,
                              const QList<QUrl> &attachments, bool sign = false,
                              bool encrypt = false,
                              const QString &appendQuote = QString(),
                              bool appendStrip = false);
    /// APPENDs the same message to the Drafts folder instead of sending it.
    /// Unlike sendMail this accepts an unfinished message — no recipient, or
    /// an address still being typed — because that is the state a draft is
    /// saved from. Emits draftSaved() or sendFailed().
    /// \a replacesUid is the draft being re-saved (-1 for a new one); it is
    /// removed only after the server has accepted the replacement.
    /// \a encrypt encrypts the draft to the sender's own key before it is
    /// appended — a draft of an encrypted message must never sit in the clear
    /// in a server-side folder.
    Q_INVOKABLE void saveDraft(const QString &to, const QString &cc, const QString &bcc,
                               const QString &subject, const QString &html,
                               const QList<QUrl> &attachments, qint64 replacesUid = -1,
                               bool sign = false, bool encrypt = false,
                               const QString &appendQuote = QString(),
                               bool appendStrip = false);
    /// Whether a Drafts folder is known, so the UI can hide the action when
    /// there is nowhere to put one.
    Q_PROPERTY(bool hasDraftsFolder READ hasDraftsFolder NOTIFY draftsFolderChanged)
    bool hasDraftsFolder() const { return !m_draftsFolder.isEmpty(); }
    /// Compose prefill for replying to the currently shown message:
    /// {to, cc, subject, body} — body is HTML with the original quoted.
    /// cc is filled only for \a replyAll. Empty map when nothing is shown.
    Q_INVOKABLE QVariantMap replyData(bool replyAll);
    /// Compose prefill for forwarding the currently shown message:
    /// {to, cc, subject, body} — to/cc empty, subject "Fwd:"-prefixed, body
    /// HTML with the original quoted. Empty map when nothing is shown.
    /// The original's attachments are NOT carried over (compose attaches
    /// local files only).
    Q_INVOKABLE QVariantMap forwardData();
    /// Compose prefill for forwarding the shown message as a message/rfc822
    /// attachment (.eml) — the original bytes, untouched: the full-fidelity
    /// forward. {to, cc, subject, body, attachments}.
    Q_INVOKABLE QVariantMap forwardAsAttachmentData();
    /// Frees a composer quote-preview slot handed out in reply/forwardData
    /// (quotePreviewSlot) once the composer is done with it.
    Q_INVOKABLE void releaseQuotePreview(quint64 slot);
    /// "Copy as Markdown": converts the clipboard's HTML flavour (which a
    /// WebEngine Copy action puts there beside the plain text) to Markdown
    /// and makes that the clipboard text. Polls briefly — the renderer fills
    /// the clipboard asynchronously.
    Q_INVOKABLE void clipboardSelectionToMarkdown(int attempt = 0);
    /// Compose prefill for editing the currently shown message as a draft:
    /// {to, cc, bcc, subject, body, uid} — the message verbatim, not quoted.
    /// uid is the draft's own uid so the old copy can be removed on send.
    /// Empty map when nothing is shown.
    Q_INVOKABLE QVariantMap draftData();
    /// True while the open folder holds the user's own outgoing mail: Sent,
    /// Drafts, Templates, Outbox. Every message in one is from the user, so the
    /// From column repeats the same name on every row and says nothing; the
    /// list shows To instead, and search looks there too.
    Q_PROPERTY(bool viewingOutgoing READ viewingOutgoing NOTIFY selectedFolderChanged)
    bool viewingOutgoing() const { return listsRecipients(m_selectedFolder); }
    /// True while the open folder is the junk one — see viewingJunkFolder().
    Q_PROPERTY(bool viewingJunk READ viewingJunkFolder NOTIFY selectedFolderChanged)
    /// True while the open folder is this account's Drafts folder — clicking a
    /// message there reopens it in the composer instead of the reader.
    Q_PROPERTY(bool viewingDrafts READ viewingDrafts NOTIFY selectedFolderChanged)
    bool viewingDrafts() const
    {
        return !m_draftsFolder.isEmpty() && m_selectedFolder == m_draftsFolder;
    }
    /// Deletes a draft by uid — the superseded copy, once its replacement has
    /// been sent or re-saved.
    Q_INVOKABLE void discardDraft(qint64 uid);
    /// Copy the given text to the system clipboard (used to grab the full
    /// status breadcrumb trail on right-click).
    Q_INVOKABLE void copyToClipboard(const QString &text) const;
    /// Initial body for a brand-new message: a blank line for the cursor
    /// followed by the account's signature (empty when no signature is set).
    Q_INVOKABLE QString newMessageBody() const;
    /// Reads a local HTML file (signature import). Returns its content, or
    /// an empty string on failure (an error notification is emitted then).
    Q_INVOKABLE QString loadHtmlFile(const QUrl &fileUrl);
    /// Known recipient addresses (previously sent to) matching \a prefix,
    /// best-ranked first — compose field autocompletion.
    Q_INVOKABLE QStringList recipientSuggestions(const QString &prefix);
    /// The Image.source that shows \a from's picture, or an empty string when
    /// sender pictures are off (advanced.conf, avatars/enabled) or the header
    /// carries no address. \a from may be a full "Name <addr>" header.
    ///
    /// What goes into the URL — and out to gravatar.com — is the SHA-256 of
    /// the lowercased address, never the address, because that is what
    /// Gravatar keys pictures by. Off by default: the request itself tells
    /// gravatar.com this reader saw that address.
    Q_INVOKABLE QString avatarSource(const QString &from) const;
    /// Pixel size avatarSource() asks for, for the QML that lays it out.
    Q_INVOKABLE int avatarSize() const;
    /// The authentication methods spam/trust* currently believes, lowercased
    /// ("spf", "dkim", ...). The viewer's badge filters against this so a
    /// method distrusted in advanced.conf is not displayed either — showing
    /// spf=pass while the score ignores SPF would be the badge arguing with
    /// the tooltip.
    Q_INVOKABLE QStringList trustedAuthMethods() const;
    Q_INVOKABLE void connectAccount();
    Q_INVOKABLE void openFolder(const QString &mailBox);
    Q_INVOKABLE void fetchMessage(int row);
    /// Opens the message at \a row in its own top-level window: fetches it
    /// (cache or server) and emits messageWindowReady() with a fresh
    /// MessageContext once it is presentable.
    Q_INVOKABLE void openMessageInWindow(int row);
    /// Quietly fetch a message's body into the cache (hover / read-ahead).
    /// No viewer or status changes; skipped when cached or offline.
    Q_INVOKABLE void prefetchMessage(int row);
    /// Fetches the next (older) window of headers; no-op if everything is loaded.
    Q_INVOKABLE void loadMoreMessages();
    /// Pages in every remaining cached header of the open folder at once, so
    /// the End key can reach the oldest message instead of the oldest one
    /// scrolled to so far. Returns true if anything was added.
    Q_INVOKABLE bool loadAllCachedMessages();
    /// Tells the client which sort the list is showing, so the head of the
    /// folder under that sort can be pulled in from the cache.
    ///
    /// The model can only order what has been loaded, and what has been loaded
    /// is the newest page of the folder. Sorting by date ascending therefore
    /// showed the oldest message of the last page or so rather than the oldest
    /// there is — and by sender or subject, the first name of that page rather
    /// than of the folder. Call this whenever the sort changes.
    Q_INVOKABLE void seedSortOrder(int column, bool descending);

    /// True when the currently open folder is the trash folder.
    Q_INVOKABLE bool isTrashFolder() const;
    /// Deletes the given model rows: moves them to Trash, or — when the open
    /// folder IS the trash — flags \Deleted and expunges (permanent).
    /// The QML side is responsible for confirming the permanent case.
    Q_INVOKABLE void deleteMessages(const QVariantList &rows);

    /// Moves the given model rows to the account's junk/spam folder.
    /// No-op when the open folder already is the junk folder.
    Q_INVOKABLE void markAsJunk(const QVariantList &rows);

    /// Clears the local spam mark on the given rows and adds their senders to
    /// the allowlist, so nothing from them is ever marked again. The counterpart
    /// to markAsJunk(), and the only way a false positive gets corrected — which
    /// is why it settles the verdict permanently (state 3) rather than leaving
    /// the message to be re-scored to the same wrong answer on the next sync.
    Q_INVOKABLE void markAsNotSpam(const QVariantList &rows);

    /// Moves the given model rows into \a targetFolder — the sidebar's
    /// drag-and-drop target. No-op when it is the folder they are already in.
    Q_INVOKABLE void moveMessagesTo(const QVariantList &rows, const QString &targetFolder);

    /// True when \a mailBox may be dropped onto \a newParent ("" = top level):
    /// a real, different, non-protected folder that is not inside \a mailBox
    /// itself, and whose resulting path is still free. The sidebar asks this
    /// per hovered row, so it only outlines targets a drop would work on.
    Q_INVOKABLE bool canMoveFolder(const QString &mailBox, const QString &newParent) const;
    /// Reparents \a mailBox (with its whole subtree) under \a newParent via
    /// IMAP RENAME; "" moves it to the top level. The cached mail moves with
    /// it — see MailStore::renameFolderOn.
    Q_INVOKABLE void moveFolder(const QString &mailBox, const QString &newParent);

    /// True for the folders that must not be moved or deleted: INBOX and the
    /// account's special-use mailboxes (sent, drafts, trash, junk).
    Q_INVOKABLE bool folderProtected(const QString &mailBox) const;

    /// Empty when \a mailBox can be renamed; otherwise one sentence saying why
    /// not, for the context menu to show in place of the Rename entry. The
    /// reasons are protocol ones, not policy: INBOX keeps its name by RFC 3501,
    /// and a RFC 6154 special-use mailbox is recreated under the old name.
    Q_INVOKABLE QString folderRenameBlockedReason(const QString &mailBox) const;
    /// The name the sidebar shows for \a mailBox — what the rename dialog
    /// prefills. Defined with the path helpers further down.
    Q_INVOKABLE QString folderDisplayLeaf(const QString &mailBox) const;
    /// Renames \a mailBox in place — \a newName replaces its last path step
    /// only; reparenting is what dragging a folder does. No-op when the name is
    /// unchanged, taken, or contains the hierarchy delimiter.
    Q_INVOKABLE void renameFolder(const QString &mailBox, const QString &newName);
    /// True when deleting \a mailBox removes it from the server for good —
    /// it already lives in the trash (or the account has no trash folder).
    /// The confirmation dialog is worded from this.
    Q_INVOKABLE bool folderDeleteIsPermanent(const QString &mailBox) const;
    /// Deletes \a mailBox: moves it into the trash, or — when it is already
    /// there — removes it and its subfolders from the server. The QML side is
    /// responsible for confirming either case.
    Q_INVOKABLE void deleteFolder(const QString &mailBox);

    /// Local-only color-scale mark (1..5) for the given model rows; a row
    /// already carrying that color is cleared instead (toggle). 0 clears —
    /// a scale slot left without a color acts as the "clear mark" shortcut.
    Q_INVOKABLE void markMessageColor(const QVariantList &rows, int color);

    /// Quick filter: show only messages marked with this color (0 = off).
    /// Queries the disk cache so marks outside the loaded page appear too.
    Q_INVOKABLE void filterByColor(int color);

    /// Server-side IMAP SEARCH in the selected folder.
    /// field: 0 = from + subject only, 1 = everything (body, cc, all headers).
    /// A query wrapped in slashes (/pattern/) instead regex-filters the loaded list.
    Q_INVOKABLE void searchMessages(const QString &query, int field);
    /// Leaves search mode and reloads the folder.
    Q_INVOKABLE void clearSearch();

    // --- Viewer debug helpers (operate on the last fetched message) ---
    /// Rendered HTML view; falls back to the text part when there is no HTML.
    Q_INVOKABLE QString htmlViewUrl();
    /// Plain-text part of the message ("discard HTML").
    Q_INVOKABLE QString textViewUrl();
    /// The complete raw RFC-822 message (headers + MIME structure + parts),
    /// escaped, monospace — our "view message source".
    Q_INVOKABLE QString sourceViewUrl();

    // The message-state properties delegate to the reading pane's context —
    // kept on Mail so existing callers keep working; per-window state lives
    // on each window's own MessageContext.
    QVariantList attachments() const { return m_reading->attachments(); }
    bool remoteContentAllowed() const { return m_reading->remoteContentAllowed(); }
    void setRemoteContentAllowed(bool allow);
    QString textPreview() const { return m_textPreview; }
    bool junkTextOnly() const { return m_reading->junkTextOnly(); }
    /// Writes attachment \a index of the current message to \a fileUrl.
    Q_INVOKABLE void saveAttachment(int index, const QUrl &fileUrl);
    /// True when the attachment could execute code if opened (.sh, .desktop,
    /// AppImage, .exe, …) — the UI shows a confirmation first.
    Q_INVOKABLE bool attachmentRisky(int index) const;
    /// Opens attachment \a index with the system handler (via a temp copy).
    Q_INVOKABLE void openAttachment(int index);
    /// Saves attachment \a index into ~/Downloads under its own filename,
    /// deduplicating ("name (1).pdf") instead of overwriting.
    Q_INVOKABLE void saveAttachmentToDownloads(int index);
    /// Opens a link from a message in the system browser / mail handler.
    Q_INVOKABLE void openExternalUrl(const QUrl &url);

    // --- Cache maintenance (Settings → Storage) ---
    /// Human-readable cache size, e.g. "13.4 GB (6.2 GB reclaimable)".
    Q_INVOKABLE QString cacheSizeText();
    /// Rebuilds the cache file on a worker thread to hand free pages back to
    /// the filesystem. Deleting messages only marks pages reusable — the file
    /// itself never shrinks without this. Sync is paused for the duration.
    Q_INVOKABLE void reclaimDiskSpace();
    /// Whether a rebuild would actually hand anything back. False right after
    /// one has run, so the UI can stop offering a multi-minute no-op.
    Q_INVOKABLE bool reclaimWorthwhile();
    bool reclaiming() const;
    bool indexRebuilding() const;
    bool searching() const { return m_searching; }
    int searchFound() const { return m_searchFound; }
    int indexRebuildPercent() const;
    bool migrationRunning() const;
    QString migrationLabel() const;
    int migrationPercent() const;
    /// Asks to quit as soon as the rebuild finishes; the window is closed for
    /// the user rather than leaving them to try again.
    Q_INVOKABLE void quitWhenIndexRebuildDone() { m_quitAfterIndex = true; }

Q_SIGNALS:
    void reclaimingChanged();
    void indexRebuildChanged();
    void migrationChanged();
    void searchingChanged();
    /// The rebuild finished and a close was pending — QML closes the window,
    /// so it still saves its geometry on the way out.
    void closeRequested();
    void accountChanged();
    void connectedChanged();
    void spamRetentionDaysChanged();
    void spamSkipTrashChanged();
    void busyChanged();
    void statusTextChanged();
    /// Fired when a full message body has been fetched and parsed.
    /// bodyUrl is a mailove:// URL the viewer should load.
    void messageLoaded(const QString &subject, const QString &from,
                       const QString &to, const QString &cc,
                       const QString &date, const QString &bodyUrl,
                       const QString &authInfo);
    void errorOccurred(const QString &message);
    /// A double-clicked message is ready to show in its own window. The
    /// context is parented to this client; the window calls release() on it
    /// when it closes.
    void messageWindowReady(MessageContext *context);
    void mailSent();
    void draftSaved();
    void draftsFolderChanged();
    /// Sending failed — carries the full (unshortened) server error. The
    /// compose window stays open and shows this in a dismissible dialog; it is
    /// deliberately NOT routed through the status log.
    void sendFailed(const QString &error);
    /// Folder contents were refreshed from the server (initial or re-open).
    void folderRefreshed();
    void attachmentsChanged();
    void remoteContentAllowedChanged();
    void textPreviewChanged();
    void junkTextOnlyChanged();
    void accountsChanged();
    void cachedFoldersChanged();
    /// Thunderbird import finished; \a message is user-presentable either way.
    void importFinished(bool ok, const QString &message);
    void refreshMinutesChanged();
    void maxBodyMBChanged();
    void authVerificationChanged();
    void debugLoggingChanged();
    void selectedFolderChanged();
    void dateFormatChanged();

private:
    friend class MessageContext; // thin QML front for the *For methods below

    /// Storage identity of the active account — see AccountConfig::accountKey().
    QString accountKey() const { return m_acct.accountKey(); }
    /// Fills the folder model from the disk cache (instant sidebar).
    void loadCachedFolderModel();
    /// Records a body-derived attachment kind (e.g. calendar invite) in the
    /// cache and the visible list.
    void refineAttachKind(const QString &folder, qint64 uid, KMime::Message *msg);
    /// Starts the automatic read mark for the message just opened at \a row:
    /// after view/markReadSeconds it is marked read, unless another message is
    /// opened (or the folder changes) first. Does nothing when that is 0.
    void markMessageRead(int row);
    /// Marks the message at \a row read everywhere: visible list, disk cache,
    /// and (when online) the server via STORE \Seen — so the state survives
    /// restarts. What the delay above ends in.
    void applyReadMark(int row);

public:
    /// Clears \Seen on the given model rows, in the model, the cache and (when
    /// online) on the server. Deliberately does not touch the viewer: a message
    /// marked unread while open stays open and stays unread, and the ordinary
    /// rule takes over again — it is marked read the next time it is opened.
    Q_INVOKABLE void markMessagesUnread(const QVariantList &rows);
    /// Sets \Seen on the given model rows — the counterpart to the above, and
    /// the explicit command that still works when view/markReadSeconds is 0.
    /// Same three places: model, cache, server when online.
    Q_INVOKABLE void markMessagesRead(const QVariantList &rows);
    /// Marks every message of \a mailBox read — in the cache, in the list when
    /// that folder is the open one, and (when online) on the server. Acts on
    /// the whole folder, not on the page of headers the list happens to hold.
    Q_INVOKABLE void markFolderRead(const QString &mailBox);
    /// True when \a mailBox has cached unread mail, so the menu can grey out
    /// "Mark all read" instead of offering a command with nothing to do.
    Q_INVOKABLE bool folderHasUnread(const QString &mailBox);

private:
    /// STOREs \Seen on \a ids of \a mailBox, best effort — what a folder's
    /// "mark all read" comes down to on the wire.
    void sendSeenStore(const QString &mailBox, const QStringList &ids);
    /// Sends the \Seen stores that markFolderRead() could not send offline.
    void flushPendingSeen();

    /// Sets the folder on screen and keeps every collaborator that cares in
    /// step. The single assignment point: SyncEngine reads it on every fetch
    /// reply, and a stale copy there files a folder's mail under another's.
    void setSelectedFolder(const QString &folder);
    /// Same, for "search results are showing in place of the folder".
    void setSearchActive(bool active);
    void loadAccount();
    void loadAccountFields();
    /// Switches to account \a index. \a targetFolder is the folder to land
    /// on — its cached contents are shown immediately, and it is what the
    /// connection opens once the folder list arrives. Empty means INBOX.
    void switchAccountInternal(int index, const QString &sessionPassword,
                               const QString &targetFolder = {});
    void setBusy(bool busy);
    void setStatus(const QString &text);
    /// Composed background-sync status for the open folder: the header-sync
    /// progress ("N of M synced") and the body-caching progress ("caching K
    /// bodies") shown together, so the two phases don't overwrite each other's
    /// numbers. Empty when nothing is syncing. \a folder must be the open one.
    QString openFolderSyncStatus(const QString &folder);
    /// Grow the background-sync backoff after server pushback (a throttling
    /// NO/BAD, or a dropped connection) and re-arm the backfill after that
    /// pause. Doubling, capped at 60 s.
    void backoffBackfill();
    /// Clear the throttle backoff/attempt state — called when a fetch succeeds
    /// and on (re)connect or folder change, so a healthy server resumes at
    /// full pace.
    void resetBackfillBackoff();
    void listFolders();
    /// Turns a folder listing into the sidebar tree, the cached folder list and
    /// the choice of which folder to open. Everything the listing means to the
    /// application; the protocol only supplies the mailboxes and their roles.
    void applyFolderListing(const QList<MailBackend::FolderInfo> &folders, QChar separator);
    /// Records a folder's size and sync token once the backend has opened it,
    /// and hands the result to whichever of the two openers asked for it.
    void applyFolderOpened(const QString &folder, qint64 messageCount,
                           const QString &syncToken);
    /// Stores \a folder's new sync position, and reads nothing into it. What a
    /// changed token means is the protocol's business — for IMAP a regenerated
    /// mailbox, for JMAP simply that something happened — so a backend that
    /// finds the cache void says so with folderInvalidated() instead.
    void applySyncToken(const QString &folder, const QString &syncToken);
    /// Throws away everything cached for \a folder, and re-reads it when it is
    /// the one on screen. The backend's word that the cache cannot be merged
    /// into any more.
    void applyFolderInvalidated(const QString &folder);
    /// Drops messages the backend reports gone from \a folder — deleted or
    /// moved away by another client. Only a protocol with a change log can say
    /// this, so silence is never a promise that nothing vanished.
    void applyMessagesVanished(const QString &folder, const QStringList &remoteIds);
    /// Checks every other configured account for new mail on the refresh
    /// timer: connect, STATUS its folders, disconnect. Accounts that are not
    /// the open one hold no session at all, so this is the only way their
    /// unread counts ever move. Sequential, one account at a time.
    void pollOtherAccounts();
    /// One account's check; \a done is called however it ends, so the queue
    /// keeps moving even when an account is unreachable.
    void pollAccount(const QVariantMap &account, const std::function<void()> &done);
    /// Second half of one account's check: the mail behind the counts. Syncs
    /// whatever is newer than the cache into every folder of a background
    /// account, on the short-lived \a backend the poll already holds and under
    /// the cache key \a key.
    ///
    /// The inbox goes first and the rest follow, one at a time on the one
    /// connection — that ordering is the point, since the inbox is where mail
    /// the user has not seen actually lands and it must not queue behind a
    /// dozen archive folders. Sequential also bounds the cost: a round that
    /// outlasts the refresh interval simply makes the next tick skip
    /// (m_accountPollBusy) rather than piling logins on the server.
    void syncBackgroundFolders(MailBackend *backend, const QString &key, const QString &host,
                               const QStringList &folders, const std::function<void()> &done);
    /// Permanently removes messages older than spamRetentionDays() from the
    /// account's spam folder. Runs once per connection, on the background sync
    /// session so it never disturbs the folder being read.
    void sweepOldSpam();
    /// Asks for the sidebar's unread pills to be recomputed. Debounced and
    /// coalesced: marking a run of messages read fires this once per burst, and
    /// a request arriving while the worker runs re-runs it once afterwards
    /// rather than queueing one pass per call.
    void scheduleUnreadRecount();
    /// Debounced request for this account's unread counts from the server.
    /// Raised by MailBackend::accountChanged(), so in practice JMAP only.
    void scheduleAccountCountRefresh();
    /// Asks the live backend what every cached folder's unread count is now.
    /// Unlike startUnreadRecount(), which counts the local cache, this learns
    /// about mail in folders that have never been opened.
    void refreshAccountUnreadCounts();
    /// The server's hierarchy delimiter, as reported by LIST. Falls back to
    /// guessing from the known paths before the first listing has arrived.
    QChar folderSeparator() const;
    /// Last path component of a mailbox ("INBOX/a/b" -> "b").
    QString folderLeaf(const QString &mailBox) const;
    /// Everything above the last component ("INBOX/a/b" -> "INBOX/a"; empty
    /// for a top-level folder).
    QString folderParent(const QString &mailBox) const;
    /// The ancestor \a mailBox visibly hangs under in the sidebar — the deepest
    /// prefix that is itself a known mailbox, empty for a top-level row. Not the
    /// same as folderParent() for an imported archive, whose paths carry a
    /// server-directory root that is not a mailbox of its own.
    QString folderDisplayParent(const QString &mailBox) const;
    // folderDisplayLeaf() belongs with these, but is declared public above so
    // the rename dialog can prefill with it.
    /// \a leaf placed under \a parent ("" = top level), with " (2)", " (3)" …
    /// appended until the path is one no mailbox already uses.
    QString freeChildPath(const QString &parent, const QString &leaf) const;
    /// \a mailBox plus every folder below it, deepest first — the order a
    /// server will accept DELETEs in.
    QStringList folderSubtree(const QString &mailBox) const;
    /// RENAMEs \a from to \a to, then re-keys the cache, follows the open
    /// folder to its new path and re-lists the tree. \a doneStatus is the
    /// breadcrumb shown on success.
    void renameFolderOnServer(const QString &from, const QString &to,
                              const QString &doneStatus);
    /// Moves the cached mail of a renamed subtree onto its new paths, on a
    /// worker thread (it rewrites body blobs). \a done, if given, runs on the
    /// GUI thread once the re-key has finished.
    void renameCachedFolder(const QString &from, const QString &to,
                            std::function<void()> done = {});
    /// Folder-model rows built from bare mailbox paths, inferring levels and
    /// display names the way the cached-folder loader does.
    static QList<FolderModel::Folder> foldersFromPaths(const QStringList &paths);
    /// Drops the cached mail of folders deleted from the server, on the same
    /// worker (chunked, so the GUI thread never waits for a write lock).
    void purgeCachedFolders(const QStringList &folders);
    /// True for a mailbox that duplicates every other one (Gmail's All Mail).
    static bool isAllMailName(const QString &mailBox);

    /// Cached missingBodyCount() for one folder — see the .cpp for why.
    int missingBodiesIn(const QString &folder);
    void noteBodyStored(const QString &folder);
    void invalidateMissingBodies();


    /// Remembers the oldest (date, uid) shown from the disk cache, so
    /// loadMoreMessages() can page the next cached chunk in from there.
    void updatePageAnchor(const QList<MessageListModel::Header> &page);
    /// Fetches the open folder's first page under the list's sort (which
    /// replaces the list). A no-op for the newest-first default, which is what
    /// the page window already holds.
    void requestSortSeed();
    /// Fetches the page after m_sortAnchor — the sorted browse's "scrolled
    /// near the end, load more".
    void requestSortPage(bool append);
    /// Puts a fetched sorted page into the model and moves the keyset anchor
    /// past it; an empty page marks the cache exhausted under this sort.
    void applySortPage(bool append, const QList<MessageListModel::Header> &rows);
    /// Date pages by either direction are one indexed lookup, the same cost as
    /// the default path's — those run right here on the GUI thread. The other
    /// columns sort the whole folder per page and go through the worker.
    bool sortPagesInline() const;
    /// Fetches the given uids as search results; when \a localMergeKeyword is
    /// set, local partial-match hits are merged into the result list.
    void fetchHeadersByUids(const QList<qint64> &uids, const QString &localMergeKeyword = {},
                            bool headersOnly = true);
    /// Local index search, off the GUI thread and streamed: rows appear as the
    /// worker finds them instead of after the last one. \a append keeps what is
    /// already listed (server hits being topped up with local partial matches);
    /// otherwise the first batch replaces the list.
    /// \a headersOnly limits matching to sender and subject.
    void localKeywordFilter(const QString &keyword, const QString &reason, bool append = false,
                            bool headersOnly = true);
    /// Copies the search index into one that folds diacritics, in slices on a
    /// worker, resuming where a previous run stopped.
    void startIndexRebuild();
    /// Removes rows the finished search did not confirm.
    void pruneSearchResults();
    /// Stops caring about the search in flight, if any. The worker notices on
    /// its next batch and gives up.
    void abandonLocalSearch() { m_searchSeq.fetchAndAddOrdered(1); }
    void appendToSentFolder(const QByteArray &rawMessage);
    /// Builds the MIME message shared by sendMail() and saveDraft().
    /// \a strict rejects malformed or missing recipients (sending); otherwise
    /// unparseable addresses are kept verbatim so a half-typed draft survives.
    /// Returns null and emits sendFailed() on a fatal problem.
    std::shared_ptr<KMime::Message> composeMessage(
        const QString &to, const QString &cc, const QString &bcc, const QString &subject,
        const QString &html, const QList<QUrl> &attachments, bool strict,
        QStringList *toList = nullptr, QStringList *ccList = nullptr,
        QStringList *bccList = nullptr);
    // --- Per-context message presentation (reading pane + detached windows) ---
    /// Corrects a listed row's OpenPGP mark from the full body — see the
    /// definition. Runs wherever refineAttachKind does.
    void refineCrypto(const QString &folder, qint64 uid, KMime::Message *msg);
    /// Offers a public key attached to the message — see the definition.
    void findAttachedKey(MessageContext *ctx, KMime::Content *root);
    /// Fills \a ctx's body, preview, inline parts and attachments from \a root.
    /// Runs a second time, over the decrypted tree, for an encrypted message.
    void applyBodyParts(MessageContext *ctx, KMime::Message *root, bool junk);
    /// Starts detached verification of \a root's RFC 3156 signature, if it has
    /// one, and records the job against \a ctx. Returns true if a job started.
    bool startPgpVerification(MessageContext *ctx, KMime::Message *root);
    /// Wraps \a msg per RFC 3156 and hands the finished wire bytes to
    /// \a done. Runs \a done immediately with the plain message when neither
    /// flag is set. On failure \a done is never called and sendFailed() has
    /// been emitted — a message that could not be encrypted is not a message
    /// to send in the clear.
    void applyOutgoingCrypto(const std::shared_ptr<KMime::Message> &msg,
                             const QStringList &recipients, bool sign, bool encrypt,
                             std::function<void(const QByteArray &)> done);

    /// Presents \a message in the reading pane's context.
    void presentMessage(const std::shared_ptr<KMime::Message> &message);
    /// A standalone copy of the reading context for a detached window. Shares
    /// the parsed KMime message; gets its own scheme-handler slot so the
    /// window keeps rendering after the reading pane moves on.
    MessageContext *detachReading();
    // Context-parameterised backends of the public message API; MessageContext
    // delegates here (friend both ways keeps the logic in one place).
    QVariantMap replyDataFor(MessageContext *ctx, bool replyAll);
    QVariantMap forwardDataFor(MessageContext *ctx);
    QVariantMap forwardAsAttachmentDataFor(MessageContext *ctx);
    /// The message quoted for reply/forward, full HTML fidelity: returned
    /// whole when the editor can lay it out in one pass, else empty with
    /// \a appendQuote filled for send-time appending (see quotedBody's comment).
    QString quotedBody(MessageContext *ctx, bool forward, QString *appendQuote,
                       bool *appendStrip, QStringList *chunks) const;
    QString htmlViewUrlFor(MessageContext *ctx);
    QString textViewUrlFor(MessageContext *ctx);
    QString sourceViewUrlFor(MessageContext *ctx);
    bool attachmentRiskyFor(const MessageContext *ctx, int index) const;
    void openAttachmentFor(MessageContext *ctx, int index);
    void saveAttachmentToDownloadsFor(MessageContext *ctx, int index);
    void saveAttachmentFor(MessageContext *ctx, int index, const QUrl &fileUrl);
    /// Persists the per-sender remote-content choice (MessageContext toggle).
    void rememberRemoteContent(const QString &senderAddress, bool allow);
    /// Records the To/Cc addresses of a message from the Sent folder in the
    /// recipient-autocompletion store.
    void harvestRecipients(const KMime::Message *msg, const QString &folder, qint64 uid);
    /// Fills in the spam fields of \a h from its raw \a head. \a knownSenders
    /// and \a orgHistory are the pre-resolved allowlist and sender-domain
    /// history for the whole batch (see appendScoredHeaders).
    void scoreHeader(MessageListModel::Header &h, const QString &folder,
                     const QByteArray &head,
                     const QSet<QString> &knownSenders,
                     const QHash<QString, MailStore::DomainHistory> &orgHistory,
                     const QSet<QString> &knownMsgIds,
                     const MailStore::SentTldProfile &tldProfile);
    /// Scores a message again now that its body is in hand, and stores the
    /// result as verdict state 2.
    ///
    /// The list-time score sees only headers, so every attachment, link and
    /// body rule is silent there. This is the second look — the same scorer,
    /// the same context, with the parts of the message that had not arrived
    /// yet. Never called for a message the user has settled (state 3).
    void rescoreWithBody(const QString &folder, qint64 uid, KMime::Message *msg);
    /// The scoring context for one message, built from the store and the
    /// account. Shared by the header pass and the body pass so the two cannot
    /// disagree about who the sender is.
    SpamHeuristics::Context spamContextFor(const QString &folder, const QString &fromValue,
                                           const QByteArray &head,
                                           const QSet<QString> &knownSenders,
                                           const QHash<QString, MailStore::DomainHistory> &orgHistory,
                                           const QSet<QString> &knownMsgIds,
                                           const MailStore::SentTldProfile &tldProfile) const;
    /// Every address this account receives at, normalized. Read by the
    /// "addressed to nobody you are" rule, which stays silent when it is empty.
    QStringList ownAddresses() const;
    /// The Message-IDs a header block claims as ancestors: In-Reply-To plus
    /// every id in References.
    static QSet<QString> referencedMessageIds(const QByteArray &head);
    /// Turns one header delivery into scored list rows and appends them to
    /// \a out. Single place where a backend's header batch becomes rows, so
    /// the allowlist lookup stays batched and no fetch path can quietly skip
    /// scoring.
    void appendScoredHeaders(QList<MessageListModel::Header> &out,
                             const QString &folder,
                             const QList<MailBackend::HeaderInfo> &infos,
                             const QStringList &authDomains);
    /// True for the folders spam scoring applies to.
    ///
    /// Two of them. The Inbox, because that is where spam arrives and where a
    /// verdict changes what the user does about it. And the Junk folder,
    /// because everything in it is spam by definition and must show the marker
    /// — including the mail that arrived before any of these rules existed,
    /// which carries no stored verdict and would otherwise sit there unmarked.
    ///
    /// Nowhere else. Sent and Drafts hold the user's own mail and marking that
    /// "!" is absurd, Trash is on its way out, and mail filed into a folder by
    /// a rule was sorted deliberately. Scoring those also charged every sync
    /// for a verdict nothing would show.
    bool scoresSpamIn(const QString &folder) const;
    /// True for a folder whose mail the user sent: Sent, Drafts, Templates,
    /// Outbox. Named the same generous way isJunkFolder() is, because the
    /// server's own attributes only cover the two it knows about.
    bool listsRecipients(const QString &folder) const;
    /// The name half of listsRecipients(), with no account state behind it.
    ///
    /// Static because the recipient migration walks the folders of *every*
    /// account in the cache, not just the open one — and for an account that
    /// is not open there is no configured Sent folder to consult, only a name.
    static bool folderNameIsOutgoing(const QString &folder);
    /// True when \a accountKey names an imported archive rather than a server
    /// account. Spam scoring is skipped for those entirely — see scoresSpamIn().
    bool isLocalAccountKey(const QString &accountKey) const;
    /// True when \a folder is the junk folder, for the decisive rule of the
    /// same name. Takes a scoped or plain folder key, unlike isJunkFolder().
    bool isJunkFolderKey(const QString &folder) const;
    /// The account's own sending address, bare — no display name. This is the
    /// SMTP envelope sender, and the address excluded from reply-all lists.
    QString ownAddress() const;
    /// The account signature as an HTML fragment ready to splice into a
    /// compose body; empty when no signature is set.
    QString signatureBlock() const;
    QString trashFolderName() const;
    QString junkFolderName() const;
    /// Junk/spam folders get hostile-content handling in the viewer.
    bool isJunkFolder(const QString &mailBox) const;
    /// Whether the folder on screen is the junk one — isJunkFolderKey(), the
    /// same answer the sidebar's junk icon and the viewer's hostile-content
    /// defaults use, decided once as the folder loads (setSelectedFolder())
    /// and again if the server names its junk folder later.
    ///
    /// The context menu offers "Not spam" for everything in this folder, mark
    /// or no mark: a message put there by a server-side rule carries no local
    /// score to flip.
    bool viewingJunkFolder() const { return m_selectedIsJunk; }
    /// authserv-ids whose Authentication-Results we are willing to believe for
    /// the account's IMAP host — empty when authVerification is off, which is
    /// what makes the whole SPF/DKIM/DMARC display collapse to nothing.
    QStringList trustedAuthDomains() const;
    /// Hands \a ctx's message to the DKIM worker thread. Called only when a
    /// message is actually opened — never during sync or prefetch, so the
    /// mailbox does not turn into a stream of DNS queries to the resolver.
    void startDkimVerification(MessageContext *ctx);
    /// Fetches \a folder/\a uid's body from the server for a re-check of a
    /// signature that failed against the cached copy, and hands the result to
    /// \a done. Returns false when there is nothing to ask — offline, or the
    /// message is not cached — in which case \a done is never called.
    /// \a isRetry marks the second attempt, which is what stops a backend that
    /// declined the first one (bulk transfers all busy) from being asked
    /// forever.
    bool refetchBodyForVerification(const QString &folder, qint64 uid, bool isRetry,
                                    MessageVerifier::BodyReady done);
    void purgeDeleted(const QList<qint64> &uids);
    QString oauthWalletKey() const;
    /// Obtains a fresh access token (refresh grant or browser sign-in), then
    /// re-enters connectAccount().
    void acquireTokenAndConnect();
    /// The account's server settings and secrets, as the backend wants them.
    MailBackend::Credentials backendCredentials() const;
    /// The network half of fetchMessage(): asks the backend for one body and
    /// presents it. \a isRetry marks the second attempt, which is what stops a
    /// backend that declined the first one (bulk transfers all busy) from
    /// being asked forever.
    void requestMessageBody(int row, const QString &remoteId, bool isRetry);
    /// Reacts to the backend losing a connection that had been up: remembers
    /// the open folder and dials again shortly.
    void handleConnectionLost();
    /// Merges any new server messages into the open folder without clearing it.
    void refreshCurrentFolder();
    /// Arms the idle-time fetch of the next older header window.
    void scheduleBackfill(int delayMs = 4000);
    void processPrefetchQueue();
    /// Parses and caches one prefetched body (raw + search text + refined
    /// attachment kind; recipient harvesting for the Sent folder).
    void storeFetchedBody(const QString &folder, qint64 uid,
                          const std::shared_ptr<KMime::Message> &message);
    void teardownSession();

    /// The active account's stored configuration. Refilled wholesale by every
    /// account load or switch, so no field can outlive the account it names.
    AccountConfig m_acct;
    /// Where accounts and their secrets live on disk. Owns the current-account
    /// index too, since that is the one thing about "which account" that is
    /// itself persisted.
    AccountStore m_accounts;
    OAuthHelper *m_oauth = nullptr;
    bool m_connectWhenReady = false; ///< connect was requested before the secret arrived
    int m_cachedFolderRevision = 0; ///< see cachedFolderRevision property

    /// Keeps the cache and the visible list in step with the server.
    SyncEngine *m_sync = nullptr;
    ViewerSchemeHandler *m_viewerHandler = nullptr;
    /// Renders a message into a MessageContext: bodies, inline parts,
    /// attachments and the three view URLs.
    MessagePresenter *m_presenter = nullptr;
    /// The protocol side of the account: owns the connections and every
    /// operation run over them. Never null, and never named more precisely
    /// than this — nothing here knows which protocol answered.
    MailBackend *m_backend = nullptr;
    /// Replaces m_backend with one that speaks \a protocol, rewiring its
    /// signals. A no-op when the current one already does.
    void setBackendProtocol(MailBackend::Protocol protocol);
    /// Wires one backend's signals to this client. Called for every backend
    /// that becomes m_backend, so the set is stated once.
    void connectBackend(MailBackend *backend);
    QString m_selectedFolder;
    QString m_pendingFolder; ///< folder to reopen after (re)connect
    QString m_sentFolder;    ///< where sent mail gets APPENDed
    QString m_draftsFolder;  ///< where "Save as draft" APPENDs
    /// Trash and Junk as the *server* named them (FolderInfo::role). Empty
    /// when it named neither, which is when trashFolderName()/isJunkFolder()
    /// fall back to guessing from folder names. All of these are refilled from
    /// scratch by every folder listing, so none can outlive its account.
    QString m_trashFolder;
    QString m_junkFolder;
    /// Whether m_selectedFolder is the junk one, decided when it is set rather
    /// than on every ask — see viewingJunkFolder().
    bool m_selectedIsJunk = false;
    /// The open message's delayed read mark: the uid waiting for the timer,
    /// and the timer itself (created on first use). Restarted by every open,
    /// stopped by a folder change — see markMessageRead().
    qint64 m_pendingReadUid = -1;
    QTimer *m_markReadTimer = nullptr;
    /// Gmail's \All archive: excluded from the folder list and the backfill
    /// because it re-stores every message already held under INBOX and labels.
    QString m_allMailFolder;
    QChar m_folderSeparator; ///< hierarchy delimiter reported by LIST
    int m_maxBodyMB = 5; ///< bodies above this are not cached (0 = no limit)

    /// The sort the list is showing, as last reported by seedSortOrder(). Kept
    /// so a folder change can re-seed under it, and so a seed that arrives
    /// after the user has clicked another column can be recognised as stale.
    int m_sortColumn = 0;
    bool m_sortDescending = true;
    /// Keyset anchor of the sorted browse: the last row of the last page shown,
    /// which the next page continues after. Invalid until the first page lands.
    MessageListModel::Header m_sortAnchor;
    bool m_sortAnchorValid = false;
    /// The cache ran dry under this sort — stop asking until it changes.
    bool m_sortExhausted = false;
    /// A sorted page is on its way. The prefetch zone asks on every scroll
    /// tick it spends inside the zone; only the first ask may reach the worker
    /// — by sender that query costs half a second per pass, and re-running it
    /// for the same anchor returns rows the model would just throw away.
    bool m_sortPageInFlight = false;
    bool m_authVerification = true; ///< DKIM/ARC/SPF/DMARC checking and display
    bool m_debugLogging = false;

    /// Every cache worker thread and the rules between them.
    MaintenanceScheduler *m_jobs = nullptr;
    /// Builds it and wires what it reports back. Called first thing in the
    /// constructor: nothing may queue a body write before it exists.
    void setUpMaintenance();

    QThread *m_importThread = nullptr;  ///< Thunderbird mbox import worker
    QAtomicInt m_importStop;            ///< asks the importer to stop mid-file
    QTimer m_accountCountDebounce;
    /// Unread counts per account key, so the pane can show them for accounts
    /// that are only cached — one worker pass fills them all.
    QHash<QString, QHash<QString, int>> m_unreadByAccount;
    /// "Mark all read" asked while offline: folder -> the remote ids to STORE
    /// \Seen on once the connection is up. Right-clicking a folder of another
    /// account opens that account first, so the command routinely lands before
    /// its connection does — without this the next header sync would read the
    /// server's untouched flags back and undo it. Dropped on an account
    /// switch: the ids name messages of the account it was asked on.
    QHash<QString, QStringList> m_pendingSeen;
    bool m_searching = false;   ///< a search is in flight (server or local)
    int m_searchFound = 0;      ///< hits delivered by it so far
    bool m_quitAfterIndex = false; ///< close was attempted mid-rebuild
    QTimer m_pollTimer;      ///< IDLE-less fallback refresh of the open folder
    int m_refreshMinutes = 5;
    int m_spamRetentionDays = 30; ///< 0 = keep spam forever
    bool m_spamSkipTrash = true;  ///< delete spam outright, not into the trash
    bool m_spamSwept = false;     ///< the sweep has run for this connection
    bool m_accountPollBusy = false; ///< a background account round is in flight
    QString m_dateFormat;    ///< Qt date pattern for list/viewer dates
    bool m_searchActive = false; ///< showing search results, not the folder
    /// Bumped for every local search started or abandoned. The worker carries
    /// the value it was started with and stops as soon as it no longer
    /// matches, so a user who keeps typing is never waiting on the query for
    /// the word they have already changed.
    QAtomicInteger<quint64> m_searchSeq;
    /// Uids the current search has delivered (GUI thread only). When the
    /// search completes, rows outside this set are pruned — the list morphs
    /// from the old query's results into the new one's instead of being
    /// cleared up front, which flashed blank on every keystroke.
    QSet<qint64> m_searchSeen;
    /// Ids the backend's last server search returned, held between the
    /// searchResults signal and the request's completion callback.
    QStringList m_pendingSearchIds;

    MessageContext *m_reading = nullptr; ///< the reading pane's message state

    /// OpenPGP backend, set by main.cpp. Null, or unavailable, on a machine
    /// without gnupg — every path through here checks before using it. Held
    /// here only so presentMessage() can start a decryption; the jobs and
    /// verdicts belong to m_verifier.
    QPointer<PgpEngine> m_pgp;
    /// DKIM/ARC and OpenPGP verdicts, and the cache-healing rule they share.
    MessageVerifier *m_verifier = nullptr;

    /// Fills in Message-IDs for rows cached before the column existed. Small
    /// chunks on a slow timer: the work is one-time and must never be felt.
    QTimer m_msgidBackfillTimer;

    /// True while presenting a message rebuilt from the cache rather than one
    /// straight off the wire. Purely diagnostic: the cached form is a stub with
    /// attachment payloads stripped and re-inserted on read, so it cannot be
    /// assumed byte-identical to what arrived. Logged next to the DKIM verdict
    /// so the two paths can be told apart — see doc/roadmap.md.
    bool m_presentingFromCache = false;
    bool m_detachPending = false; ///< a double-click is waiting for its fetch
    qint64 m_detachUid = -1;      ///< the message that double-click asked for
    QString m_textPreview;
    bool m_busy = false;
    QString m_statusText;        ///< breadcrumb shown in the UI (newest first)
    QStringList m_statusTrail;   ///< recent raw messages, newest first (max 3)

    FolderModel m_folderModel;
    MessageListModel m_messageModel;
    MailStore m_store;
};
