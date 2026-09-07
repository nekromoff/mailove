// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <QAbstractListModel>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QRegularExpression>
#include <QSet>

/// Message headers of the currently selected folder, newest first.
class MessageListModel : public QAbstractListModel
{
    Q_OBJECT
    /// The most marker glyphs any loaded row shows at once — what the marker
    /// column has to be wide enough for, and nothing more. A folder whose mail
    /// carries no attachments, no signatures and no forwards reports 0, and the
    /// column takes no width at all.
    Q_PROPERTY(int markerCount READ markerCount NOTIFY markerCountChanged)

public:
    enum Roles {
        SubjectRole = Qt::UserRole + 1,
        FromRole,
        /// The To line, for the folders where From is always the user.
        ToRole,
        DateRole,
        UidRole,
        SeenRole,
        SuspiciousRole,
        AuthInfoRole,
        AttachmentRole,
        CalendarRole,
        ColorLabelRole,
        /// PgpMime::StoredKind — 0 none, 1 encrypted, 2 signed, 3 both. Comes
        /// from the messages.crypto column, so the list costs no extra query.
        CryptoRole,
        /// True when the local spam score reached SpamHeuristics::spamThreshold().
        /// Shares the "!" marker with SuspiciousRole: to a reader both mean
        /// "this message is not what it appears to be", and two different
        /// warning glyphs in one row would be two things to learn instead of one.
        SpamRole,
        /// Multi-line "Why?" text — one line per rule that fired.
        SpamDetailRole,
        /// How many ordinary attachments the message really has — 0 until its
        /// body has been seen, so a row that only shows the head-derived
        /// paperclip has a count of 0 rather than a wrong number. Invitations
        /// are counted separately, by CalendarCountRole.
        AttachCountRole,
        /// The .ics invitations, counted from the same body pass.
        CalendarCountRole,
        /// The user forwarded this message: the $Forwarded keyword, which is
        /// what every other client writes for the same fact (IMAP RFC 5788,
        /// JMAP $forwarded). Set by our own forward, read back from the
        /// server for forwards made anywhere else.
        ForwardedRole
    };

    /// Attachment kinds carried in Header::attachKind. The values are ordered:
    /// anything above GenericAttachment was learned from the body and outranks
    /// the head-only guess, both in the model's merge and in the cache's
    /// `attach` column, so a header refresh cannot undo it.
    enum AttachKind {
        NoAttachment = 0,
        GenericAttachment = 1,   ///< head-only guess: top-level multipart/mixed
        CalendarAttachment = 2,  ///< body: every attachment is an .ics invite
        /// Body: no attachment parts at all. Distinct from NoAttachment so a
        /// multipart/mixed head that wraps nothing but the message text — what
        /// Mailove itself used to send — stops showing a paperclip.
        ConfirmedNoAttachment = 3,
        /// Body: an .ics invite AND at least one ordinary attachment — an
        /// invitation that arrives with the agenda attached, which is common
        /// enough that collapsing it to one or the other lost real information.
        /// Both glyphs show for it.
        CalendarAndOther = 4,
    };

    /// What a Header::spamState value means. Ordered by how much the verdict
    /// behind it is worth, and every path that writes one respects the order:
    /// the cache upsert keeps MAX() of the old and the new, a body re-score
    /// gives up against anything from SpamExempt upwards, and the 2.9
    /// re-derivation sweep leaves those states alone. A verdict may be
    /// refined, never demoted.
    enum SpamState {
        SpamNotScored = 0,
        SpamFromHeaders = 1,
        SpamWithBody = 2,
        /// Rule 0 (a known correspondent), or a folder that is not scored at
        /// all. Reached by the filter deciding not to judge, which is a weaker
        /// thing than the user deciding for it.
        SpamExempt = 3,
        /// The user answered for this message: "Not spam", or a drag out of
        /// the junk folder. Nothing the scorer computes may overwrite it, and
        /// it is what MailStore::userClearedMessageIds() looks for so that the
        /// answer survives the move that expressed it.
        SpamUserCleared = 4,
    };

    int markerCount() const { return m_markerCount; }

    /// Whether \a kind (an AttachKind) means "this message has attachments of
    /// any sort" — what the attachment sort orders by.
    static constexpr bool kindHasAttachment(int kind)
    {
        return kind == GenericAttachment || kind == CalendarAttachment
            || kind == CalendarAndOther;
    }

    /// Whether \a kind means "show the paperclip": an ordinary attachment, as
    /// opposed to an invitation, which has a glyph of its own.
    static constexpr bool kindHasFile(int kind)
    {
        return kind == GenericAttachment || kind == CalendarAndOther;
    }

    /// Whether \a kind means "show the calendar glyph".
    static constexpr bool kindHasCalendar(int kind)
    {
        return kind == CalendarAttachment || kind == CalendarAndOther;
    }

    struct Header {
        qint64 uid = -1;
        QString subject;
        QString from;
        /// To recipients, already joined for display. Only filled for mail in
        /// the user's own outgoing folders — everywhere else the From line is
        /// what the list shows and this would be dead weight in the cache.
        QString to;
        QDateTime date;
        bool seen = false;
        /// $Forwarded — see ForwardedRole.
        bool forwarded = false;
        bool suspicious = false; ///< SPF/DKIM/DMARC failure reported by our server
        QString authInfo;        ///< raw Authentication-Results header
        int attachKind = NoAttachment; ///< AttachKind
        /// Ordinary attachment parts counted from the body, invitations not
        /// included; 0 when unknown. See AttachCountRole.
        int attachCount = 0;
        /// The .ics invitations among them, counted the same way.
        int calendarCount = 0;
        int colorLabel = 0;      ///< local color-scale mark (0 = none, 1..5)
        int crypto = 0;          ///< PgpMime::StoredKind, see CryptoRole
        /// Local spam heuristics (spamheuristics.h). The score is kept rather
        /// than a boolean so a threshold change re-judges cached mail.
        int spamScore = 0;
        /// A SpamState: how much was known when the score was computed, and
        /// hence what may overwrite it.
        int spamState = SpamNotScored;
        QString spamDetail;      ///< one line per rule that fired
        /// RFC 5322 Message-ID with the angle brackets stripped. Stable across
        /// folders and UIDVALIDITY resets, unlike uid.
        QString msgid;
        /// The backend's own id for this message, as the protocol states it.
        /// IMAP writes the uid in decimal here, JMAP its opaque Email id — so
        /// the cache can key a message the way its server names it without the
        /// rest of the code caring which protocol produced it. `uid` stays the
        /// local primary key either way (a JMAP row gets a synthetic one).
        /// Empty means "not recorded", which for an IMAP row reads back as the
        /// uid: rows cached before this column existed are not rewritten.
        QString remoteId;

        // Sort keys, derived from the fields above by primeKeys() when the
        // header enters the model. Producers do not fill them. They exist so a
        // comparison costs an integer compare or a plain QString compare,
        // instead of a QDateTime compare (timezone-aware, local-spec) or a
        // case-insensitive compare that re-folds both strings every time — on
        // a list of 100k rows that is the difference between a sort the user
        // does not notice and one that freezes the GUI thread.
        qint64 dateSecs = 0;  ///< date.toSecsSinceEpoch(), 0 when invalid
        QString fromKey;      ///< case-folded from
        QString subjectKey;   ///< case-folded subject
    };

    using QAbstractListModel::QAbstractListModel;

    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    enum class SortColumn { Date = 0, From = 1, Subject = 2, Attachment = 3 };

    /// Date pattern (Qt format string) used for non-today rows; today's rows
    /// always show only the time.
    void setDateFormat(const QString &format);

    void setHeaders(QList<Header> headers);
    /// Returns the number of rows actually inserted (uid duplicates skipped).
    int appendHeaders(const QList<Header> &headers);
    /// Every loaded row, visible or filtered out — the measure of how far the
    /// user has paged, where rowCount() only counts what a filter lets show.
    int totalCount() const { return int(m_all.size()); }
    void clear();
    Q_INVOKABLE qint64 uidAt(int row) const;
    /// The backend's own id for the message at \a row — what MailBackend
    /// operations name a message by. Falls back to the uid in decimal, which
    /// is exactly what an IMAP backend expects and what rows cached before the
    /// remote_id column existed hold implicitly. Empty when there is no such
    /// row.
    QString remoteIdAt(int row) const;
    /// Visible row showing \a uid, or -1 when it is not in the model. Lets the
    /// view re-find the message the user picked after a reset renumbers rows.
    Q_INVOKABLE int rowForUid(qint64 uid) const;
    /// Invokable because the message context menu flips between "Mark read"
    /// and "Mark unread" on it, and the menu sits outside the delegate that
    /// has the roles.
    Q_INVOKABLE bool seenAt(int row) const;
    /// The same verdict SpamRole shows — confident spam only, an unsure score
    /// is not a mark. The context menu flips between "Mark as spam" and "Not
    /// spam" on it.
    Q_INVOKABLE bool spamAt(int row) const;
    /// Whether the row already carries $Forwarded, so a second forward of the
    /// same message records nothing.
    bool forwardedAt(int row) const;
    void markSeen(int row);
    void markUnseen(int row);
    /// Marks every listed message read at once — the model side of a folder's
    /// "mark all read". Rows hidden by an active filter are marked too: the
    /// command is about the folder, not about what is on screen.
    void markAllSeen();
    /// Sets or clears $Forwarded on the row showing \a uid (no-op when it is
    /// not loaded). Takes a uid rather than a row because the caller is the
    /// send path, which knows the message and not where it currently sits.
    void setForwarded(qint64 uid, bool on);
    /// Refines a message's attachment kind in place (body-derived knowledge).
    void setAttachKind(qint64 uid, int kind);
    /// The exact counts, learned from the same body pass: ordinary
    /// attachments and invitations, kept apart because each has its own glyph.
    void setAttachCounts(qint64 uid, int files, int calendars);
    /// PgpMime::StoredKind for a listed row, refined from the full body.
    void setCrypto(qint64 uid, int kind);
    /// Raw From header of a visible row, display name included.
    QString fromAt(int row) const;
    /// The row's Message-ID as the header sync recorded it (angle brackets
    /// stripped); empty when the message carries none.
    QString msgidAt(int row) const;
    /// Drops a row's spam mark and settles the verdict (state 3) so a later
    /// re-score cannot bring it back.
    void clearSpam(qint64 uid);
    /// Replaces a row's spam verdict with one scored from the full message.
    /// Refuses to touch a row the user has settled (state 3): a re-score must
    /// never undo "not spam".
    void setSpamVerdict(qint64 uid, int score, int state, const QString &detail);
    /// The stored verdict state of a row, or 0 when it is not listed.
    int spamStateOf(qint64 uid) const;
    /// Unmarks every loaded row from \a address and records the user's answer
    /// on them. The in-memory half of MailStore::clearSpamVerdictsFrom().
    int clearSpamFrom(const QString &address);
    int colorLabelAt(int row) const;
    void setColorLabel(qint64 uid, int color);
    /// Drops the given uids from the model (visible and hidden lists).
    void removeByUids(const QList<qint64> &uids);
    /// Every uid held, visible or filtered out — the reconcile pass after a
    /// search uses this to find rows the new query no longer justifies.
    QList<qint64> allUids() const;

    /// Show only rows whose subject or sender matches; empty pattern clears.
    void applyFilter(const QRegularExpression &pattern);
    bool hasFilter() const { return m_filter.isValid() && !m_filter.pattern().isEmpty(); }

    Q_INVOKABLE void sortBy(int column, bool descending);
    /// Quick filter: show only rows carrying this color mark (0 = off).
    Q_INVOKABLE void setColorFilter(int color);

Q_SIGNALS:
    void markerCountChanged();

private:
    /// How many marker glyphs one row shows: the forwarded arrow, the
    /// lock, the invitation and the paperclip, counted as drawn.
    static int markerGlyphsOf(const Header &h);
    /// Recomputes markerCount from every loaded row and reports a change.
    /// Cheap enough to run on a wholesale change; the incremental setters
    /// below only ever raise it, so a row losing a glyph leaves the column a
    /// little wider than it strictly needs until the folder is reloaded.
    void refreshMarkerCount();
    /// Raises markerCount if \a h now needs more glyphs than any row so far.
    void noteMarkers(const Header &h);
    /// Fills the derived sort keys of a header entering the model.
    static void primeKeys(Header &h);
    /// Recomputes m_rows (sort + filter) inside a model reset.
    void rebuildVisible();
    /// Re-sorts m_rows in place and reports it as a layout change, so the view
    /// keeps its scroll position and its selection.
    void resortVisible();
    /// Rebuilds the uid → m_all index map after m_all is replaced or spliced.
    void reindex();
    /// Visible row showing the m_all entry \a allIndex, or -1 when filtered out.
    /// Row of an m_all entry in the visible list, or -1 when filtered out.
    /// Binary search over the sorted rows — see the definition.
    int visibleRowOf(int allIndex) const;
    bool lessThan(const Header &a, const Header &b) const;
    bool matchesFilter(const Header &h) const;

    QString m_dateFormat = QStringLiteral("yyyy-MM-dd");
    /// Everything fetched for the folder, in arrival order. Rows are only ever
    /// appended here, so the indices held in m_rows and m_byUid stay valid;
    /// removeByUids() is the one exception and rebuilds both.
    QList<Header> m_all;
    /// Visible rows: indices into m_all, in sort order, filter applied. The
    /// visible list is a permutation and not a second copy of the headers —
    /// copying them meant every insert detached the shared list (a deep copy
    /// of the whole folder) and left two copies of state to keep in step.
    QList<int> m_rows;
    QHash<qint64, int> m_byUid; ///< uid → index into m_all
    QRegularExpression m_filter;
    int m_colorFilter = 0;
    /// See markerCount().
    int m_markerCount = 0;
    SortColumn m_sortColumn = SortColumn::Date;
    bool m_sortDescending = true;
};
