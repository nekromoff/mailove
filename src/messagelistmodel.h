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
        /// True when the local spam score reached SpamHeuristics::SpamThreshold.
        /// Shares the "!" marker with SuspiciousRole: to a reader both mean
        /// "this message is not what it appears to be", and two different
        /// warning glyphs in one row would be two things to learn instead of one.
        SpamRole,
        /// Multi-line "Why?" text — one line per rule that fired.
        SpamDetailRole
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
    };

    /// Whether \a kind (an AttachKind) means "show the paperclip".
    static constexpr bool kindHasAttachment(int kind)
    {
        return kind == GenericAttachment || kind == CalendarAttachment;
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
        bool suspicious = false; ///< SPF/DKIM/DMARC failure reported by our server
        QString authInfo;        ///< raw Authentication-Results header
        int attachKind = NoAttachment; ///< AttachKind
        int colorLabel = 0;      ///< local color-scale mark (0 = none, 1..5)
        int crypto = 0;          ///< PgpMime::StoredKind, see CryptoRole
        /// Local spam heuristics (spamheuristics.h). The score is kept rather
        /// than a boolean so a threshold change re-judges cached mail.
        int spamScore = 0;
        /// 0 never scored, 1 scored from headers, 2 scored with the body,
        /// 3 exempt under Rule 0 (a known correspondent).
        int spamState = 0;
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
    bool seenAt(int row) const;
    void markSeen(int row);
    void markUnseen(int row);
    /// Marks every listed message read at once — the model side of a folder's
    /// "mark all read". Rows hidden by an active filter are marked too: the
    /// command is about the folder, not about what is on screen.
    void markAllSeen();
    /// Refines a message's attachment kind in place (body-derived knowledge).
    void setAttachKind(qint64 uid, int kind);
    /// PgpMime::StoredKind for a listed row, refined from the full body.
    void setCrypto(qint64 uid, int kind);
    /// Raw From header of a visible row, display name included.
    QString fromAt(int row) const;
    /// Drops a row's spam mark and settles the verdict (state 3) so a later
    /// re-score cannot bring it back.
    void clearSpam(qint64 uid);
    /// Replaces a row's spam verdict with one scored from the full message.
    /// Refuses to touch a row the user has settled (state 3): a re-score must
    /// never undo "not spam".
    void setSpamVerdict(qint64 uid, int score, int state, const QString &detail);
    /// The stored verdict state of a row, or 0 when it is not listed.
    int spamStateOf(qint64 uid) const;
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

private:
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
    SortColumn m_sortColumn = SortColumn::Date;
    bool m_sortDescending = true;
};
