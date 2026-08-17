// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "advancedconfig.h"

#include <QDir>
#include <QElapsedTimer>
#include <QLoggingCategory>
#include <QReadLocker>
#include <QFileInfo>
#include <QSaveFile>
#include <QSettings>
#include <QWriteLocker>
#include <QStringList>

namespace
{
/// Same category as the rest of the client's tracing, so
/// QT_LOGGING_RULES='mailove.trace.debug=true' (or the Settings toggle) turns
/// these on with everything else. Its own object because advancedconfig.cpp
/// links into the test binaries, which have no logTrace to extern.
Q_LOGGING_CATEGORY(logAdvanced, "mailove.trace")

using Type = AdvancedConfig::Type;
using Reload = AdvancedConfig::Reload;

/// The only value a Secret key may hold in the file. Everything else on such
/// a line is a secret in the clear, and is moved to the wallet rather than
/// written back.
constexpr auto kWalletPlaceholder = QLatin1String("@wallet");
/// Where scrubbed secrets go; installed by main(). Written once at startup
/// and read on the GUI thread only, which is where every save happens.
AdvancedConfig::SecretSink gSecretSink;

/// Bumped whenever a key is added, removed or its default changes, so a
/// template seeded by an older build can be spotted and offered a refresh.
constexpr int kSchemaVersion = 2;

/// One [group] in the file, with the heading the Settings page shows above it.
///
/// Same reason the per-key \a doc exists: a section named "psl" or "dkim" says
/// nothing to anyone who does not already know what it is, and a reader who
/// has to guess which group a knob lives in reads them all. Every group in
/// kSchema must appear here — groupTitleOf() falls back to the bare name, which
/// is the old behaviour and easy to miss, so the assertion in reference()
/// catches a group added without a heading.
struct GroupDoc {
    const char *name;
    const char *title;
    const char *doc;
};

/// Alphabetical, like kSchema itself: the file, this list and the reference
/// beside the editor are all read in the same order, so a key seen in one is
/// found in the others without scanning.
const GroupDoc kGroups[] = {
    {"attachments", "Attachments",
     "Where attachments are kept and how hard they are squeezed: the size at which "
     "a file moves out of the database into its own file, and what compression pays."},
    {"avatars", "Sender pictures",
     "Whether gravatar.com is asked what a sender looks like. Off by default, "
     "because asking tells gravatar.com that you have this message."},
    {"compose", "Composing",
     "Limits on what a message being written may carry — pasted images, and the "
     "remote pictures fetched once you allow them."},
    {"db", "Database",
     "How the local cache database behaves when something else is writing to it."},
    {"dkim", "DKIM / DNS",
     "How long the DNS records used to verify a DKIM signature are remembered, "
     "including the lookups that found nothing."},
    {"imap", "IMAP",
     "How this client talks to an IMAP server: how often an idle connection is "
     "kept alive, and how many connections may fetch bodies at once."},
    {"jmap", "JMAP",
     "Timeouts, size limits and push-stream behaviour for JMAP accounts. "
     "Nothing here is read for an IMAP account."},
    {"oauth", "OAuth 2 sign-in",
     "Endpoints and client credentials for signing in to Google and Microsoft. "
     "Your own app registration goes here; secrets move to the system wallet."},
    {"psl", "Public suffix list",
     "The list that tells where one organization's domain ends — what makes "
     "example.co.uk one name and not two. Turning it off keeps the built-in copy."},
    {"spam", "Spam scoring",
     "The numbers the spam scorer works to: what score marks a message, and how "
     "much history a sender needs before it is treated as familiar."},
    {"spamrules", "Spam rules",
     "What each rule is worth when it fires — positive accuses, negative excuses, "
     "0 turns the rule off. A change applies to mail scored from now on; messages "
     "already in the mailbox keep the verdict and the explanation they were given."},
    {"sync", "Sync pacing",
     "How fast mail is fetched and how the client backs off when a server says "
     "no. Raise the pauses for a provider that rate-limits."},
    {"view", "Reading",
     "What happens while a message is open: when it counts as read, and how much "
     "of a very large body is rendered."},
};

constexpr int kGroupCount = int(std::size(kGroups));

/// The one place a default, a range and a description are written down.
///
/// Ranges are clamps, not validation: a value outside them is corrected and
/// reported, never refused, because the alternative is a config file that
/// stops the client from starting. Reload::Restart marks the keys read once
/// while something is being built — a timer's interval, a connection — where
/// saving cannot reach the object that already exists.
const AdvancedConfig::Knob kSchema[] = {
    // --- attachments ---------------------------------------------------------
    {"attachments/externalizeThresholdBytes", Type::Int, 32768, 0, 1073741824, Reload::Live,
     "Attachments at least this big are stored outside the database."},
    {"attachments/zstdLevel", Type::Int, 3, 1, 19, Reload::Live,
     "zstd compression level for stored attachments."},
    {"attachments/compressionSampleBytes", Type::Int, 65536, 1024, 16777216, Reload::Live,
     "Sample compressed first to decide whether compressing the whole file pays."},
    {"attachments/worthwhileRatio", Type::Double, 0.90, 0.10, 1.0, Reload::Live,
     "Compress only when the sample shrinks below this fraction of its size."},
    {"attachments/maxPayloadBytes", Type::Int, 1073741824, 1048576, 2000000000, Reload::Live,
     "Largest attachment payload decompressed into memory."},

    // --- avatars -------------------------------------------------------------
    // Off by default and deliberately so: asking gravatar.com for a picture
    // tells gravatar.com that this address was seen by this reader, which is
    // not a request anyone should make on the reader's behalf without being
    // asked. Nothing is fetched, cached or shown until this is turned on.
    {"avatars/enabled", Type::Bool, false, {}, {}, Reload::Restart,
     "Show sender pictures from gravatar.com. Off means no request is ever made."},
    {"avatars/cacheDays", Type::Int, 365, 1, 3650, Reload::Live,
     "How long a fetched picture is reused before it is asked for again."},
    {"avatars/missCacheDays", Type::Int, 30, 1, 3650, Reload::Live,
     "How long 'this address has no picture' is remembered."},
    {"avatars/sizePixels", Type::Int, 40, 8, 512, Reload::Live,
     "Size a picture is shown at. Fetched at twice this, so it stays sharp on "
     "HiDPI screens."},

    // --- compose -------------------------------------------------------------
    {"compose/maxPastedImageBytes", Type::Int, 20971520, 65536, 268435456, Reload::Live,
     "Largest image accepted from a paste or drop."},
    {"compose/pastedImageDisplayWidth", Type::Int, 640, 64, 4096, Reload::Live,
     "Width a pasted image is displayed at; the sent file keeps its own size."},
    {"compose/remoteImagePrefetch", Type::Int, 40, 0, 1000, Reload::Live,
     "Remote images fetched per message once remote content is allowed."},
    {"compose/maxRemoteImageBytes", Type::Int, 10485760, 65536, 268435456, Reload::Live,
     "Largest single remote image accepted."},

    // --- db ------------------------------------------------------------------
    {"db/busyTimeoutMs", Type::Int, 15000, 1000, 300000, Reload::Restart,
     "How long a query waits for another writer before failing."},
    {"db/rebuildBusyTimeoutMs", Type::Int, 30000, 1000, 600000, Reload::Restart,
     "The same, on the index-rebuild connection, which waits behind the GUI."},

    // --- dkim ----------------------------------------------------------------
    {"dkim/dnsCacheMinTtl", Type::Int, 1800, 0, 86400, Reload::Live,
     "Shortest time a DKIM key record is cached, whatever its TTL says."},
    {"dkim/dnsCacheMaxTtl", Type::Int, 86400, 60, 604800, Reload::Live,
     "Longest time a DKIM key record is cached."},
    {"dkim/dnsNegativeTtl", Type::Int, 600, 0, 86400, Reload::Live,
     "How long a failed DKIM key lookup is remembered."},

    // --- imap ----------------------------------------------------------------
    {"imap/keepAliveSeconds", Type::Int, 180, 30, 3600, Reload::Restart,
     "How often an idle connection sends CAPABILITY so the server keeps it."},
    {"imap/bodyPoolSize", Type::Int, 2, 0, 8, Reload::Restart,
     "Extra connections for body fetches. Gmail caps ~15; some servers throttle at 3."},

    // --- jmap ----------------------------------------------------------------
    {"jmap/maxConcurrentBodies", Type::Int, 4, 1, 16, Reload::Live,
     "Blob downloads in flight. Capped by the server's maxConcurrentRequests."},
    {"jmap/maxBodyBytes", Type::Int, 134217728, 1048576, 2000000000, Reload::Live,
     "Largest single message body accepted from a blob download."},
    {"jmap/bodyTimeoutMs", Type::Int, 120000, 1000, 3600000, Reload::Live,
     "Timeout for one blob download."},
    {"jmap/requestTimeoutMs", Type::Int, 60000, 1000, 3600000, Reload::Live,
     "Timeout for one JMAP method call."},
    {"jmap/discoveryTimeoutMs", Type::Int, 30000, 1000, 600000, Reload::Live,
     "Timeout for session discovery, which blocks the account coming up."},
    {"jmap/maxSessionBytes", Type::Int, 1048576, 4096, 67108864, Reload::Live,
     "Largest session object accepted; a bigger reply is a login page, not JMAP."},
    {"jmap/maxUploadReplyBytes", Type::Int, 65536, 1024, 16777216, Reload::Live,
     "Largest reply accepted from a blob upload."},
    {"jmap/maxChangesPerCall", Type::Int, 500, 10, 4096, Reload::Live,
     "Changes asked for per Email/changes call."},
    {"jmap/pushPingSeconds", Type::Int, 300, 30, 3600, Reload::Restart,
     "Keepalive the server sends down the push stream, so proxies keep it open."},
    {"jmap/maxPushBufferBytes", Type::Int, 262144, 4096, 16777216, Reload::Restart,
     "Cap on the push stream's read buffer."},
    {"jmap/pushBaseRetryMs", Type::Int, 2000, 100, 600000, Reload::Live,
     "First wait before reconnecting a dropped push stream."},
    {"jmap/pushMaxBackoffShift", Type::Int, 7, 0, 16, Reload::Live,
     "Doublings of the push retry wait before the cap applies."},
    {"jmap/pushMaxRetryMs", Type::Int, 300000, 1000, 3600000, Reload::Live,
     "Ceiling for the push reconnect wait."},

    // --- oauth ---------------------------------------------------------------
    {"oauth/googleClientId", Type::String, QString(), {}, {}, Reload::Live,
     "Your own Google client ID. Empty uses the one shipped with Mailove."},
    {"oauth/googleClientSecret", Type::Secret, QString(), {}, {}, Reload::Live,
     "Client secret for the ID above. Type it here once: on save it moves to "
     "the system wallet and this line keeps only @wallet."},
    {"oauth/googleAuthUrl", Type::String,
     QStringLiteral("https://accounts.google.com/o/oauth2/v2/auth"), {}, {}, Reload::Live,
     "Google authorization endpoint."},
    {"oauth/googleTokenUrl", Type::String,
     QStringLiteral("https://oauth2.googleapis.com/token"), {}, {}, Reload::Live,
     "Google token endpoint."},
    {"oauth/googleScope", Type::String, QStringLiteral("https://mail.google.com/"), {}, {},
     Reload::Live, "Scopes requested from Google, space separated."},
    {"oauth/microsoftClientId", Type::String, QString(), {}, {}, Reload::Live,
     "Your own Microsoft application (client) ID. Empty uses the shipped one."},
    {"oauth/microsoftClientSecret", Type::Secret, QString(), {}, {}, Reload::Live,
     "Client secret for the ID above. Type it here once: on save it moves to "
     "the system wallet and this line keeps only @wallet."},
    {"oauth/microsoftAuthUrl", Type::String,
     QStringLiteral("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"), {}, {},
     Reload::Live, "Microsoft authorization endpoint. Replace 'common' for a single tenant."},
    {"oauth/microsoftTokenUrl", Type::String,
     QStringLiteral("https://login.microsoftonline.com/common/oauth2/v2.0/token"), {}, {},
     Reload::Live, "Microsoft token endpoint. Replace 'common' for a single tenant."},
    {"oauth/microsoftScope", Type::String,
     QStringLiteral("https://outlook.office365.com/IMAP.AccessAsUser.All "
                    "https://outlook.office365.com/SMTP.Send offline_access"),
     {}, {}, Reload::Live, "Scopes requested from Microsoft, space separated."},
    {"oauth/authTimeoutMinutes", Type::Int, 5, 1, 60, Reload::Live,
     "How long the loopback listener waits for the browser before giving up."},
    {"oauth/tokenExpirySkewSeconds", Type::Int, 60, 0, 600, Reload::Live,
     "Refresh this long before the token actually expires."},
    {"oauth/defaultExpiresIn", Type::Int, 3600, 60, 86400, Reload::Live,
     "Assumed token lifetime when the server does not state one."},

    // --- psl -----------------------------------------------------------------
    {"psl/enabled", Type::Bool, true, {}, {}, Reload::Restart,
     "Fetch the public suffix list. 0 keeps the built-in copy and makes no request."},
    {"psl/listUrl", Type::String,
     QStringLiteral("https://publicsuffix.org/list/public_suffix_list.dat"), {}, {},
     Reload::Restart, "Where the public suffix list is fetched from."},
    {"psl/refreshHours", Type::Int, 168, 1, 8760, Reload::Restart,
     "How old the list may get before it is refetched."},
    {"psl/checkHours", Type::Int, 6, 1, 720, Reload::Restart,
     "How often staleness is checked."},
    {"psl/startupDelaySeconds", Type::Int, 10, 0, 3600, Reload::Restart,
     "Delay before the first check, so it never competes with startup."},

    // --- spam ----------------------------------------------------------------
    // The floor is 1, not 0: the verdict is "total >= threshold" and a message
    // no rule fired on totals exactly 0, so a threshold of 0 would not mean
    // "very strict" — it would mark every message in the mailbox.
    {"spam/threshold", Type::Int, 50, 1, 1000, Reload::Live,
     "Score at which a message is marked spam. Lower catches more and errs more."},
    {"spam/familiarCount", Type::Int, 20, 1, 10000, Reload::Live,
     "Messages from a domain before it counts as familiar and is trusted more."},
    {"spam/familiarDays", Type::Int, 60, 1, 3650, Reload::Live,
     "How far back the familiarity count looks."},
    {"spam/tldSharePercent", Type::Int, 10, 1, 100, Reload::Live,
     "Share of your sent mail a top-level domain needs before mail from it "
     "stops looking unusual. Higher trusts fewer countries."},
    {"spam/tldMinSample", Type::Int, 50, 1, 100000, Reload::Live,
     "Sent addresses needed before the top-level domain rule says anything."},
    {"spam/linkGroupCap", Type::Int, 40, 1, 10000, Reload::Live,
     "Links examined per message by the link rules."},
    // One switch per authentication method the trusted Authentication-Results
    // header can carry. The account's own "verify authentication" checkbox is
    // the master: off, no header is read and none of these matter. These are
    // the finer grain — a server whose SPF answers are wrong (a forwarding
    // setup, say) can be disbelieved method by method without giving up DKIM.
    // Distrusted is invisible too: the message viewer's badge drops a method
    // whose key is 0, so nothing is shown that is not also scored.
    {"spam/trustArc", Type::Bool, true, {}, {}, Reload::Live,
     "Honour arc=pass as proof a relay (mailing list, forwarder) broke SPF/DKIM "
     "legitimately. 0 scores such failures like any other."},
    {"spam/trustCompauth", Type::Bool, true, {}, {}, Reload::Live,
     "Count Microsoft's compauth verdict with the others. Only ever present on "
     "Microsoft 365 accounts; 0 ignores it for a tenant whose verdicts are noisy."},
    {"spam/trustDkim", Type::Bool, true, {}, {}, Reload::Live,
     "Count the server's DKIM verdicts. 0 ignores them both ways."},
    {"spam/trustDmarc", Type::Bool, true, {}, {}, Reload::Live,
     "Count the server's DMARC verdicts. 0 ignores them both ways."},
    {"spam/trustSpf", Type::Bool, true, {}, {}, Reload::Live,
     "Count the server's SPF verdicts. 0 ignores them both ways — useful when "
     "forwarding makes SPF fail on legitimate mail."},

    // --- spamrules --------------------------------------------------------------
    // Every rule the scorer can fire, and what it is worth. Ids are the ones
    // printed in the "Why?" tooltip, so a rule that misfires on your mail can be
    // found by reading the message it misfired on and turned down or off here.
    //
    // Nothing is rescored: a verdict is stored with the explanation it was given,
    // and a weight changed today would otherwise silently contradict a tooltip
    // written last week. New mail is scored with the new numbers.
    {"spamrules/attachment-double-extension", Type::Int, 50, -999, 999, Reload::Live,
     "An attachment named to look like a document but is a program (invoice.pdf.exe)."},
    {"spamrules/attachment-executable", Type::Int, 45, -999, 999, Reload::Live,
     "An attached program or disk image rather than a document."},
    {"spamrules/attachment-macro", Type::Int, 15, -999, 999, Reload::Live,
     "An attached Office file of a kind that can carry macros."},
    {"spamrules/auth-fail", Type::Int, 35, -999, 999, Reload::Live,
     "Your receiving server reported an SPF, DKIM or DMARC failure."},
    {"spamrules/auth-pass", Type::Int, -8, -999, 999, Reload::Live,
     "Authentication passed, but for a domain with no history here — worth little on its "
     "own, since a spammer can publish SPF in an afternoon."},
    {"spamrules/auth-pass-familiar", Type::Int, -25, -999, 999, Reload::Live,
     "Authentication passed for a domain you have heard from for a long time."},
    {"spamrules/auth-softfail", Type::Int, 20, -999, 999, Reload::Live,
     "The receiving server reported a soft failure (spf=softfail): the sending "
     "domain hedges rather than denies. Never revokes the known-correspondent "
     "exemption."},
    {"spamrules/brand-impersonation", Type::Int, 30, -999, 999, Reload::Live,
     "Calls itself a well-known brand from a domain that brand does not send from."},
    {"spamrules/charset-mismatch", Type::Int, 8, -999, 999, Reload::Live,
     "The subject was needlessly encoded, which hides it from simple filters."},
    {"spamrules/date-skew", Type::Int, 15, -999, 999, Reload::Live,
     "The Date header is hours away from when the message actually arrived."},
    {"spamrules/display-name-address", Type::Int, 30, -999, 999, Reload::Live,
     "The sender's name shows one address while the message comes from another."},
    {"spamrules/display-name-confusable", Type::Int, 30, -999, 999, Reload::Live,
     "The sender's name mixes alphabets inside one word, imitating a name you know."},
    {"spamrules/encrypted-archive", Type::Int, 50, -999, 999, Reload::Live,
     "An attached archive needs a password, so no virus scanner can look inside it."},
    {"spamrules/familiar-domain", Type::Int, -15, -999, 999, Reload::Live,
     "You have had mail from this domain for a long time."},
    {"spamrules/familiar-domain-spoofed", Type::Int, 25, -999, 999, Reload::Live,
     "Claims a domain you really do hear from, while failing authentication."},
    {"spamrules/freemail-brand-name", Type::Int, 25, -999, 999, Reload::Live,
     "Presents as a company but writes from a personal Gmail-style mailbox."},
    {"spamrules/freemail-reply-to", Type::Int, 20, -999, 999, Reload::Live,
     "Presents as a company but replies would go to a personal mailbox."},
    {"spamrules/from-domain-confusable", Type::Int, 30, -999, 999, Reload::Live,
     "The sender's domain mixes alphabets inside one name — a lookalike domain."},
    {"spamrules/from-ip-literal", Type::Int, 25, -999, 999, Reload::Live,
     "The sender's address is a bare IP address instead of a domain name."},
    {"spamrules/hacked-php-url", Type::Int, 15, -999, 999, Reload::Live,
     "A link calls a PHP script with several long random codes — the shape of mail sent "
     "through a hacked website. Capped with the other link rules."},
    {"spamrules/hacked-wordpress-link", Type::Int, 15, -999, 999, Reload::Live,
     "A link leads into a WordPress code directory (wp-includes, script files under "
     "wp-content) — a hacked site's landing page. Media links are not matched."},
    {"spamrules/html-attachment", Type::Int, 30, -999, 999, Reload::Live,
     "A web page sent as a file, which is how a fake sign-in form dodges link checks."},
    {"spamrules/html-password-form", Type::Int, 40, -999, 999, Reload::Live,
     "The message body contains a password box. A real sign-in page never is one."},
    {"spamrules/image-only", Type::Int, 12, -999, 999, Reload::Live,
     "Nearly the whole message is one image, with no text a filter could read."},
    {"spamrules/junk-folder", Type::Int, 999, -999, 999, Reload::Live,
     "The message is already in a junk folder. Far above the threshold on purpose: it is "
     "a decision you or your server made, not a guess. 0 makes junk folders score like "
     "any other."},
    {"spamrules/known-contact-spoofed", Type::Int, 60, -999, 999, Reload::Live,
     "Claims to be somebody you have written to, while failing authentication. Decisive "
     "on its own — forging an address you correspond with is targeted."},
    {"spamrules/link-text-mismatch", Type::Int, 25, -999, 999, Reload::Live,
     "A link's visible text names one domain while it goes to another. Not read in list "
     "mail, whose click trackers do this legitimately."},
    {"spamrules/msgid-local", Type::Int, 15, -999, 999, Reload::Live,
     "The Message-ID was issued by 'localhost' rather than a real domain."},
    {"spamrules/msgid-malformed", Type::Int, 15, -999, 999, Reload::Live,
     "The Message-ID has no domain part, which no normal mail software produces."},
    {"spamrules/no-date", Type::Int, 15, -999, 999, Reload::Live,
     "No Date header, which every mail client writes."},
    {"spamrules/no-message-id", Type::Int, 18, -999, 999, Reload::Live,
     "No Message-ID, which normal mail software always writes."},
    {"spamrules/no-received", Type::Int, 20, -999, 999, Reload::Live,
     "No Received headers: the message went through no server we can see."},
    {"spamrules/not-addressed-to-you", Type::Int, 8, -999, 999, Reload::Live,
     "None of your addresses appear in To or Cc. Low, because ordinary bcc looks the "
     "same."},
    {"spamrules/pgp-encrypted", Type::Int, -40, -999, 999, Reload::Live,
     "The message is OpenPGP encrypted. Spam is not."},
    {"spamrules/pgp-signed", Type::Int, -50, -999, 999, Reload::Live,
     "The message is OpenPGP signed. Spam is not."},
    {"spamrules/php-cms-origin", Type::Int, 25, -999, 999, Reload::Live,
     "Sent by a script inside a CMS content directory (WordPress uploads, a Joomla "
     "component), where mail-sending code does not belong."},
    {"spamrules/php-eval-source", Type::Int, 40, -999, 999, Reload::Live,
     "Sent by PHP code that exists only in memory (eval), the signature of malware on a "
     "hacked website."},
    {"spamrules/php-script-origin", Type::Int, 10, -999, 999, Reload::Live,
     "Sent by a PHP script on a web server. Low: every small shop's order mail is one."},
    {"spamrules/reply-to-mismatch", Type::Int, 8, -999, 999, Reload::Live,
     "Replies would leave the sender's own domain."},
    {"spamrules/single-hop-unknown", Type::Int, 12, -999, 999, Reload::Live,
     "Delivered in one hop from a machine with no host name, not through a mail server."},
    {"spamrules/subject-bidi-override", Type::Int, 30, -999, 999, Reload::Live,
     "The subject carries a text-direction override, so it reads differently than it is."},
    {"spamrules/subject-confusable", Type::Int, 25, -999, 999, Reload::Live,
     "The subject mixes alphabets inside a word, a common way to imitate a brand."},
    {"spamrules/subject-shouting", Type::Int, 6, -999, 999, Reload::Live,
     "The subject is almost entirely capitals."},
    {"spamrules/text-html-divergence", Type::Int, 10, -999, 999, Reload::Live,
     "The plain-text copy is nearly empty while the formatted one is not."},
    {"spamrules/thread-reply", Type::Int, -30, -999, 999, Reload::Live,
     "A reply inside a conversation already in your mailbox — which a stranger cannot "
     "fake, since it needs a Message-ID you received."},
    {"spamrules/undisclosed-recipients", Type::Int, 6, -999, 999, Reload::Live,
     "The message names no recipient at all."},
    {"spamrules/unfamiliar-tld", Type::Int, 15, -999, 999, Reload::Live,
     "The sender is in a top-level domain your own mail never goes to. Deliberately too "
     "low to mark anything by itself."},
    {"spamrules/upstream-ham", Type::Int, -15, -999, 999, Reload::Live,
     "Your mail server's own filter scored this well below its threshold."},
    {"spamrules/upstream-near-threshold", Type::Int, 12, -999, 999, Reload::Live,
     "Your mail server's own filter came close to its threshold without calling it."},
    {"spamrules/upstream-spam", Type::Int, 40, -999, 999, Reload::Live,
     "Your mail server's own filter marked this as spam."},
    {"spamrules/upstream-spam-high", Type::Int, 50, -999, 999, Reload::Live,
     "Your mail server's own filter scored this at twice its own threshold."},
    {"spamrules/url-brand-subdomain", Type::Int, 25, -999, 999, Reload::Live,
     "A link spells a brand's name in the part of its address anyone can choose."},
    {"spamrules/url-credential-trick", Type::Int, 30, -999, 999, Reload::Live,
     "A link written so it appears to go somewhere other than where it goes."},
    {"spamrules/url-ip-host", Type::Int, 20, -999, 999, Reload::Live,
     "A link points at a bare IP address rather than a named site."},
    {"spamrules/url-punycode-brand", Type::Int, 25, -999, 999, Reload::Live,
     "A link's name is built from two alphabets to look like one you trust."},
    {"spamrules/url-shortener", Type::Int, 8, -999, 999, Reload::Live,
     "A link hides behind a URL shortener. Only read outside list mail, and can never "
     "mark alone."},
    {"spamrules/vulnerable-mailer", Type::Int, 12, -999, 999, Reload::Live,
     "Sent with a PHPMailer version unmaintained and exploitable for years — a relic "
     "server or a spam kit's fake header."},
    {"spamrules/zero-width-obfuscation", Type::Int, 25, -999, 999, Reload::Live,
     "Invisible characters hidden inside a word, which is only ever done to disguise it."},

    // --- sync ----------------------------------------------------------------
    {"sync/headerWindow", Type::Int, 200, 10, 1000, Reload::Live,
     "Headers fetched per request in the folder on screen."},
    {"sync/backfillFolderWindow", Type::Int, 250, 10, 1000, Reload::Live,
     "Headers per request for folders nobody is looking at."},
    {"sync/headerPauseMs", Type::Int, 400, 0, 60000, Reload::Live,
     "Pause between header windows. Raise it for a server that rate-limits."},
    {"sync/bodyPauseMs", Type::Int, 600, 0, 60000, Reload::Live,
     "Pause between body-fetch batches."},
    {"sync/backfillIdleMs", Type::Int, 4000, 100, 600000, Reload::Restart,
     "How long the backfill waits after going idle before resuming."},
    {"sync/backoffBaseMs", Type::Int, 1000, 100, 60000, Reload::Live,
     "First wait after the server throttles; doubles per attempt."},
    {"sync/backoffCapMs", Type::Int, 64000, 1000, 600000, Reload::Live,
     "Ceiling for one backoff wait."},
    {"sync/backoffJitterMs", Type::Int, 1000, 0, 60000, Reload::Live,
     "Random spread added to each backoff wait."},
    {"sync/backoffMaxAttempts", Type::Int, 8, 1, 100, Reload::Live,
     "Throttled attempts before the backfill pauses until the next connect."},

    // --- view ----------------------------------------------------------------
    {"view/markReadSeconds", Type::Double, 0.1, 0.0, 86400.0, Reload::Live,
     "Seconds an open message stays unread before it is marked read; decimals "
     "fine. 0 leaves it unread until marked read by hand."},
    {"view/maxHtmlPreviewChars", Type::Int, 500000, 1000, 10000000, Reload::Live,
     "HTML taken for the text preview before it is truncated."},
    {"view/maxTextBodyBytes", Type::Int, 1048576, 4096, 67108864, Reload::Live,
     "Largest plain-text body rendered whole."},
};

constexpr int kSchemaCount = int(std::size(kSchema));

/// "sync/headerWindow" -> "sync". The INI section a key belongs to.
QString groupOf(const QString &key)
{
    const qsizetype slash = key.indexOf(u'/');
    return slash < 0 ? QString() : key.left(slash);
}

/// The heading for a group, or nullptr when the schema has no entry for it.
const GroupDoc *groupDoc(const QString &group)
{
    for (int n = 0; n < kGroupCount; ++n) {
        if (group == QLatin1String(kGroups[n].name))
            return &kGroups[n];
    }
    return nullptr;
}

QString nameOf(const QString &key)
{
    const qsizetype slash = key.indexOf(u'/');
    return slash < 0 ? key : key.mid(slash + 1);
}

/// \a text with the blank lines at its top and bottom removed, ending in
/// exactly one newline. Only the ends: blank lines *between* sections are the
/// user's layout — they are what makes the file readable — and nothing here
/// reflows them.
QString trimBlankEnds(const QString &text)
{
    QStringList lines = text.split(u'\n');
    while (!lines.isEmpty() && lines.first().trimmed().isEmpty())
        lines.removeFirst();
    while (!lines.isEmpty() && lines.last().trimmed().isEmpty())
        lines.removeLast();
    return lines.isEmpty() ? QString() : lines.join(u'\n') + u'\n';
}

/// \a text as "# " comment lines of at most 78 columns. Only used for the
/// group explainers, which are the only multi-sentence strings written into
/// the file; a per-key doc is one line by construction.
QStringList wrapComment(const QString &text)
{
    QStringList out;
    QString line;
    const QStringList words = text.split(u' ', Qt::SkipEmptyParts);
    for (const QString &word : words) {
        if (!line.isEmpty() && line.size() + word.size() + 1 > 76) {
            out.append(QStringLiteral("# %1\n").arg(line));
            line.clear();
        }
        line += line.isEmpty() ? word : u' ' + word;
    }
    if (!line.isEmpty())
        out.append(QStringLiteral("# %1\n").arg(line));
    return out;
}

QString asText(const QVariant &v, Type type)
{
    if (type == Type::Bool)
        return v.toBool() ? QStringLiteral("1") : QStringLiteral("0");
    if (type == Type::Double)
        return QString::number(v.toDouble(), 'g', 6);
    // A secret has no text form here by construction: the template, the
    // reference and withKey() all show the placeholder, never a value.
    if (type == Type::Secret)
        return kWalletPlaceholder;
    return v.toString();
}
} // namespace

AdvancedConfig::AdvancedConfig(QObject *parent)
    : QObject(parent)
{
    load();
}

AdvancedConfig &AdvancedConfig::instance()
{
    static AdvancedConfig config;
    return config;
}

int AdvancedConfig::intOr(const QString &key, int fallback)
{
    // Indexed rather than scanned: i() memoises per string literal, which a
    // built key cannot do, and this is called once per spam rule that fires —
    // per message, on the path that also has to keep the list scrolling.
    static const QHash<QString, int> index = [] {
        QHash<QString, int> out;
        out.reserve(kSchemaCount);
        for (int n = 0; n < kSchemaCount; ++n) {
            if (kSchema[n].type == Type::Int)
                out.insert(QString::fromLatin1(kSchema[n].key), n);
        }
        return out;
    }();
    // Deliberately not asserting on an unknown key the way i() does: the whole
    // point is a caller whose keys are built at runtime, where "no such knob"
    // is an ordinary answer and means "use what the code says".
    const auto it = index.constFind(key);
    if (it == index.cend())
        return fallback;
    const AdvancedConfig &self = instance();
    const QReadLocker locked(&self.m_lock);
    return self.m_effective.at(*it).toInt();
}

QString AdvancedConfig::filePath()
{
    // Derived from where QSettings actually put mailove.conf rather than
    // rebuilt from QStandardPaths, so the two files always sit together even
    // if Qt's idea of the config location changes under us.
    const QSettings probe(QStringLiteral("mailove"), QStringLiteral("mailove"));
    return QFileInfo(probe.fileName()).dir().filePath(QStringLiteral("advanced.conf"));
}

QString AdvancedConfig::walletPlaceholder()
{
    return kWalletPlaceholder;
}

QString AdvancedConfig::walletKeyFor(const QString &key)
{
    return QStringLiteral("advanced/") + key;
}

void AdvancedConfig::setSecretSink(SecretSink sink)
{
    gSecretSink = std::move(sink);
}

QString AdvancedConfig::scrubSecrets(const QString &text, QHash<QString, QString> *relayed)
{
    QStringList lines = text.split(u'\n');
    QString group;
    bool changed = false;
    for (QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith(u'#') || trimmed.startsWith(u';'))
            continue;
        if (trimmed.startsWith(u'[') && trimmed.endsWith(u']')) {
            group = trimmed.mid(1, trimmed.size() - 2).trimmed();
            continue;
        }
        const qsizetype eq = line.indexOf(u'=');
        if (eq < 0 || group.isEmpty())
            continue;
        const QString name = line.left(eq).trimmed();
        const Knob *k = knob(group + u'/' + name);
        if (!k || k->type != Type::Secret)
            continue;
        QString value = line.mid(eq + 1).trimmed();
        if (value.size() >= 2 && value.startsWith(u'"') && value.endsWith(u'"'))
            value = value.mid(1, value.size() - 2);
        if (value == kWalletPlaceholder)
            continue; // already a pointer at the wallet
        // An emptied line is a deletion, not a secret: it has to reach the
        // wallet too, or clearing it here would leave the value stored there.
        // The line itself stays empty — writing the placeholder over it would
        // claim a secret that is no longer anywhere.
        if (relayed)
            relayed->insert(walletKeyFor(group + u'/' + name), value);
        if (value.isEmpty())
            continue;
        // Only the value changes; the indentation and spacing the user typed
        // on the left of the '=' are theirs.
        line = line.left(eq + 1) + u' ' + kWalletPlaceholder;
        changed = true;
    }
    return changed ? lines.join(u'\n') : text;
}

void AdvancedConfig::sweepSecrets()
{
    // From the file, not from what was loaded earlier: the point of the sweep
    // is a file edited outside the client, so what is in memory may predate
    // the secret being typed into it.
    load();
    QHash<QString, QString> relayed;
    const QString scrubbed = scrubSecrets(m_text, &relayed);
    if (relayed.isEmpty())
        return;
    if (!gSecretSink) {
        qCWarning(logAdvanced, "advanced: %d secret(s) in the file and no wallet to move them to",
                  int(relayed.size()));
        return;
    }
    for (auto it = relayed.cbegin(); it != relayed.cend(); ++it)
        gSecretSink(it.key(), it.value());
    if (scrubbed == m_text)
        return;
    const QString path = filePath();
    QSaveFile file(path);
    bool written = file.open(QIODevice::WriteOnly | QIODevice::Text);
    if (written) {
        file.write(scrubbed.toUtf8());
        written = file.commit();
    }
    if (!written) {
        qCWarning(logAdvanced, "advanced: cannot rewrite %s without its secrets: %s",
                  qUtf8Printable(path), qUtf8Printable(file.errorString()));
        return;
    }
    qCDebug(logAdvanced, "advanced: moved %d secret(s) out of the file into the wallet",
            int(relayed.size()));
    m_text = scrubbed;
    Q_EMIT textChanged();
}

const AdvancedConfig::Knob *AdvancedConfig::knob(const QString &key)
{
    for (int i = 0; i < kSchemaCount; ++i) {
        if (QLatin1String(kSchema[i].key) == key)
            return &kSchema[i];
    }
    return nullptr;
}

void AdvancedConfig::load()
{
    QElapsedTimer elapsed;
    elapsed.start();
    m_text.clear();
    QFile file(filePath());
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        m_text = QString::fromUtf8(file.readAll());
    const Parsed parsed = parse(m_text);
    apply(resolve(parsed.raw, nullptr, nullptr));
    qCDebug(logAdvanced, "advanced: load %lld ms (%lld bytes, %d set)", elapsed.elapsed(),
            qint64(m_text.size()), int(m_values.size()));
}

void AdvancedConfig::apply(const QHash<QString, QVariant> &overrides)
{
    QList<QVariant> effective;
    effective.reserve(kSchemaCount);
    for (int n = 0; n < kSchemaCount; ++n) {
        effective.append(
            overrides.value(QString::fromLatin1(kSchema[n].key), kSchema[n].def));
    }
    const QWriteLocker locked(&m_lock);
    m_values = overrides;
    m_effective = std::move(effective);
}

int AdvancedConfig::indexOf(const char *key)
{
    // Keyed by the pointer, not the text: every call site is a string literal
    // with a stable address, so the schema is walked once per call site for
    // the life of the process. Per thread, because the map is written on
    // first use and reads come from several.
    static thread_local QHash<const char *, int> cache;
    const auto it = cache.constFind(key);
    if (it != cache.cend())
        return *it;
    int found = -1;
    for (int n = 0; n < kSchemaCount; ++n) {
        if (qstrcmp(kSchema[n].key, key) == 0) {
            found = n;
            break;
        }
    }
    cache.insert(key, found);
    return found;
}

AdvancedConfig::Parsed AdvancedConfig::parse(const QString &text)
{
    Parsed out;
    QString group;
    QHash<QString, int> seen; ///< key -> line, for the duplicate warning
    const QStringList lines = text.split(u'\n');
    for (int n = 0; n < lines.size(); ++n) {
        const QString line = lines.at(n).trimmed();
        const int lineNo = n + 1;
        // Whole-line comments only: a '#' inside a value is part of the value,
        // which is what keeps a URL fragment from being eaten.
        if (line.isEmpty() || line.startsWith(u'#') || line.startsWith(u';'))
            continue;
        if (line.startsWith(u'[')) {
            if (!line.endsWith(u']')) {
                out.errors.append({lineNo, QStringLiteral("unterminated [group] header")});
                continue;
            }
            group = line.mid(1, line.size() - 2).trimmed();
            if (group.isEmpty())
                out.errors.append({lineNo, QStringLiteral("empty [group] name")});
            continue;
        }
        const qsizetype eq = line.indexOf(u'=');
        if (eq < 0) {
            out.errors.append(
                {lineNo, QStringLiteral("not a 'key = value' line, a [group] or a # comment")});
            continue;
        }
        const QString name = line.left(eq).trimmed();
        if (name.isEmpty()) {
            out.errors.append({lineNo, QStringLiteral("no key before '='")});
            continue;
        }
        if (group.isEmpty()) {
            out.errors.append({lineNo, QStringLiteral("'%1' sits outside any [group]").arg(name)});
            continue;
        }
        QString value = line.mid(eq + 1).trimmed();
        // Quotes are optional and only ever a way to keep leading or trailing
        // spaces; strip one matching pair and nothing else.
        if (value.size() >= 2 && value.startsWith(u'"') && value.endsWith(u'"'))
            value = value.mid(1, value.size() - 2);
        const QString key = group + u'/' + name;
        if (!knob(key)) {
            out.warnings.append({lineNo,
                                 QStringLiteral("unknown key '%1' — ignored, the rest of the "
                                                "file still applies")
                                     .arg(key)});
            continue;
        }
        const auto dup = seen.constFind(key);
        if (dup != seen.cend()) {
            out.warnings.append({lineNo, QStringLiteral("'%1' was already set on line %2; this "
                                                        "one wins")
                                             .arg(key)
                                             .arg(*dup)});
        }
        seen.insert(key, lineNo);
        if (knob(key)->type == Type::Secret && !value.isEmpty()
            && value != kWalletPlaceholder) {
            out.warnings.append(
                {lineNo, QStringLiteral("'%1' is a secret: it is moved to the system wallet on "
                                        "save and this line keeps only %2")
                             .arg(key, kWalletPlaceholder)});
        }
        out.raw.insert(key, value);
    }
    return out;
}

QHash<QString, QVariant> AdvancedConfig::resolve(const QHash<QString, QString> &raw,
                                                 const QHash<QString, int> *lines,
                                                 QList<Issue> *warnings)
{
    QHash<QString, QVariant> out;
    const auto warn = [&](const QString &key, const QString &text) {
        if (!warnings)
            return;
        warnings->append({lines ? lines->value(key, 0) : 0, text});
    };
    for (auto it = raw.cbegin(); it != raw.cend(); ++it) {
        const Knob *k = knob(it.key());
        if (!k)
            continue; // parse() already warned
        const QString &text = it.value();
        QVariant value;
        switch (k->type) {
        case Type::Int: {
            bool ok = false;
            const qlonglong n = text.toLongLong(&ok);
            if (!ok) {
                warn(it.key(), QStringLiteral("'%1' is not a whole number; using the default %2")
                                   .arg(text, asText(k->def, k->type)));
                continue;
            }
            value = int(qBound(qlonglong(k->min.toInt()), n, qlonglong(k->max.toInt())));
            if (value.toInt() != n) {
                warn(it.key(), QStringLiteral("%1 is outside %2–%3; using %4")
                                   .arg(n)
                                   .arg(k->min.toInt())
                                   .arg(k->max.toInt())
                                   .arg(value.toInt()));
            }
            break;
        }
        case Type::Double: {
            bool ok = false;
            const double n = text.toDouble(&ok);
            if (!ok) {
                warn(it.key(), QStringLiteral("'%1' is not a number; using the default %2")
                                   .arg(text, asText(k->def, k->type)));
                continue;
            }
            value = qBound(k->min.toDouble(), n, k->max.toDouble());
            if (!qFuzzyCompare(value.toDouble(), n)) {
                warn(it.key(), QStringLiteral("%1 is outside %2–%3; using %4")
                                   .arg(n)
                                   .arg(k->min.toDouble())
                                   .arg(k->max.toDouble())
                                   .arg(value.toDouble()));
            }
            break;
        }
        case Type::Bool: {
            const QString v = text.toLower();
            if (v == QLatin1String("1") || v == QLatin1String("true")
                || v == QLatin1String("yes") || v == QLatin1String("on")) {
                value = true;
            } else if (v == QLatin1String("0") || v == QLatin1String("false")
                       || v == QLatin1String("no") || v == QLatin1String("off")) {
                value = false;
            } else {
                warn(it.key(), QStringLiteral("'%1' is not 1/0; using the default %2")
                                   .arg(text, asText(k->def, k->type)));
                continue;
            }
            break;
        }
        case Type::String:
            value = text;
            break;
        case Type::Secret:
            // A secret never becomes a value in memory either: whatever the
            // file says, what is in force is "look in the wallet". A file
            // hand-edited to hold one is scrubbed by sweepSecrets(), and until
            // it is, nothing here can hand the plaintext back out.
            value = text.isEmpty() ? QString() : QString(kWalletPlaceholder);
            break;
        }
        out.insert(it.key(), value);
    }
    return out;
}

QVariant AdvancedConfig::value(const char *key) const
{
    const int index = indexOf(key);
    Q_ASSERT_X(index >= 0, "AdvancedConfig", key); // not in kSchema: a typo in the caller
    if (index < 0)
        return {};
    const QReadLocker locked(&m_lock);
    return m_effective.at(index);
}

int AdvancedConfig::i(const char *key)
{
    return instance().value(key).toInt();
}

double AdvancedConfig::d(const char *key)
{
    return instance().value(key).toDouble();
}

bool AdvancedConfig::b(const char *key)
{
    return instance().value(key).toBool();
}

QString AdvancedConfig::s(const char *key)
{
    // A Secret is never readable from here — the value is in the wallet and
    // this would only ever hand back the placeholder. Reading one is a bug in
    // the caller, which wants walletKeyFor() and an async wallet lookup.
    const int index = indexOf(key);
    Q_ASSERT_X(index < 0 || kSchema[index].type != Type::Secret, "AdvancedConfig::s", key);
    return instance().value(key).toString();
}

QString AdvancedConfig::text() const
{
    return m_text;
}

QVariantList AdvancedConfig::problems(const QString &candidate) const
{
    QElapsedTimer elapsed;
    elapsed.start();
    Parsed parsed = parse(candidate);
    // Line numbers for the clamp warnings, which resolve() cannot know itself.
    QHash<QString, int> lines;
    {
        QString group;
        const QStringList raw = candidate.split(u'\n');
        for (int n = 0; n < raw.size(); ++n) {
            const QString line = raw.at(n).trimmed();
            if (line.isEmpty() || line.startsWith(u'#') || line.startsWith(u';'))
                continue;
            if (line.startsWith(u'[') && line.endsWith(u']')) {
                group = line.mid(1, line.size() - 2).trimmed();
                continue;
            }
            const qsizetype eq = line.indexOf(u'=');
            if (eq > 0 && !group.isEmpty())
                lines.insert(group + u'/' + line.left(eq).trimmed(), n + 1);
        }
    }
    QList<Issue> clamped;
    resolve(parsed.raw, &lines, &clamped);
    parsed.warnings += clamped;

    const auto sortByLine = [](const Issue &a, const Issue &b) { return a.line < b.line; };
    std::sort(parsed.errors.begin(), parsed.errors.end(), sortByLine);
    std::sort(parsed.warnings.begin(), parsed.warnings.end(), sortByLine);

    QVariantList out;
    for (const Issue &e : std::as_const(parsed.errors)) {
        out.append(QVariantMap{{QStringLiteral("line"), e.line},
                               {QStringLiteral("fatal"), true},
                               {QStringLiteral("text"), e.text}});
    }
    for (const Issue &w : std::as_const(parsed.warnings)) {
        out.append(QVariantMap{{QStringLiteral("line"), w.line},
                               {QStringLiteral("fatal"), false},
                               {QStringLiteral("text"), w.text}});
    }
    qCDebug(logAdvanced, "advanced: problems() %lld ms (%d issues)", elapsed.elapsed(),
            int(out.size()));
    return out;
}

QStringList AdvancedConfig::restartKeys(const QString &candidate) const
{
    QElapsedTimer elapsed;
    elapsed.start();
    const Parsed parsed = parse(candidate);
    const QHash<QString, QVariant> next = resolve(parsed.raw, nullptr, nullptr);
    const QReadLocker locked(&m_lock);
    QStringList out;
    for (int n = 0; n < kSchemaCount; ++n) {
        const Knob &k = kSchema[n];
        if (k.reload != Reload::Restart)
            continue;
        const QString key = QString::fromLatin1(k.key);
        const QVariant before = m_values.value(key, k.def);
        const QVariant after = next.value(key, k.def);
        if (before != after)
            out.append(key);
    }
    qCDebug(logAdvanced, "advanced: restartKeys() %lld ms", elapsed.elapsed());
    return out;
}

QString AdvancedConfig::save(const QString &candidate)
{
    const Parsed parsed = parse(candidate);
    if (!parsed.errors.isEmpty()) {
        const Issue &first = parsed.errors.first();
        return QStringLiteral("line %1: %2").arg(first.line).arg(first.text);
    }
    // Secrets are taken out before anything is written, so the plaintext the
    // user typed never reaches the disk at all — not even for the moment
    // between writing it and rewriting it.
    QHash<QString, QString> relayed;
    // Trimmed at the ends only — see trimBlankEnds(). A file that grew a
    // trailing blank line on every visit is the reason, and an empty one is
    // then simply the case where nothing is left.
    const QString text = trimBlankEnds(scrubSecrets(candidate, &relayed));
    if (!relayed.isEmpty() && !gSecretSink) {
        // Refused rather than silently dropped: saving the file with the
        // secret blanked would look like it had been stored somewhere.
        return QStringLiteral("no system wallet available to store the secret in; "
                              "nothing was saved");
    }
    const QString path = filePath();

    // Nothing left: the file goes rather than being left behind as a blank
    // one. A text cleared by selecting all and deleting often keeps a newline
    // or three, and a file kept for those would say "there are settings here"
    // to anyone who looks. No file is also exactly the state a fresh install
    // is in, so "cleared it" and "never touched it" end up the same.
    if (text.isEmpty()) {
        if (QFile::exists(path) && !QFile::remove(path))
            return QStringLiteral("cannot remove %1").arg(path);
        // The wallet entries go with it. Nothing can reach them once the keys
        // that named them are gone — the client id beside a secret went with
        // the same delete — so leaving them would only be a secret nobody can
        // use and nobody knows is there.
        if (gSecretSink) {
            for (int n = 0; n < kSchemaCount; ++n) {
                if (kSchema[n].type == Type::Secret)
                    gSecretSink(walletKeyFor(QString::fromLatin1(kSchema[n].key)), QString());
            }
        }
        m_text.clear();
        apply({});
        qCDebug(logAdvanced, "advanced: save() emptied — %s removed", qUtf8Printable(path));
        Q_EMIT textChanged();
        Q_EMIT reloaded();
        return {};
    }

    QDir().mkpath(QFileInfo(path).path());
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return QStringLiteral("cannot write %1: %2").arg(path, file.errorString());
    // Verbatim, comments and all: this file is the user's, and nothing here
    // ever regenerates it from the parsed values. The one edit is the secrets
    // above, which are replaced by their placeholder.
    file.write(text.toUtf8());
    if (!file.commit())
        return QStringLiteral("cannot write %1: %2").arg(path, file.errorString());

    for (auto it = relayed.cbegin(); it != relayed.cend(); ++it)
        gSecretSink(it.key(), it.value());

    m_text = text;
    apply(resolve(parse(text).raw, nullptr, nullptr));
    qCDebug(logAdvanced, "advanced: save() %lld bytes (%d secret(s) to the wallet)",
            qint64(text.size()), int(relayed.size()));
    Q_EMIT textChanged();
    Q_EMIT reloaded();
    return {};
}

QString AdvancedConfig::withKey(const QString &text, const QString &key) const
{
    const Knob *k = knob(key);
    if (!k)
        return text;
    const QString group = groupOf(key);
    const QString line = QStringLiteral("%1 = %2").arg(nameOf(key), asText(k->def, k->type));

    QStringList lines = text.split(u'\n');
    QString current;
    int lastOfGroup = -1; ///< last line that still belongs to [group]
    for (int n = 0; n < lines.size(); ++n) {
        const QString trimmed = lines.at(n).trimmed();
        if (trimmed.startsWith(u'[') && trimmed.endsWith(u']')) {
            current = trimmed.mid(1, trimmed.size() - 2).trimmed();
            if (current == group)
                lastOfGroup = n;
            continue;
        }
        if (current != group)
            continue;
        lastOfGroup = n;
        // Already there: leave the file alone rather than setting it twice.
        const qsizetype eq = trimmed.indexOf(u'=');
        if (eq > 0 && trimmed.left(eq).trimmed() == nameOf(key)
            && !trimmed.startsWith(u'#') && !trimmed.startsWith(u';')) {
            return text;
        }
    }

    if (lastOfGroup < 0) {
        // No such section yet: start one at the end, with a blank line before
        // it unless the file is empty or already ends in one.
        QString out = text;
        if (!out.isEmpty() && !out.endsWith(u'\n'))
            out += u'\n';
        if (!out.isEmpty() && !out.endsWith(QLatin1String("\n\n")))
            out += u'\n';
        return out + QStringLiteral("[%1]\n").arg(group) + line + u'\n';
    }

    // Into the existing section, after its last line — skipping back over the
    // blank lines that separate it from whatever follows.
    int at = lastOfGroup;
    while (at > 0 && lines.at(at).trimmed().isEmpty())
        --at;
    lines.insert(at + 1, line);
    return lines.join(u'\n');
}

QVariantList AdvancedConfig::reference() const
{
    QElapsedTimer elapsed;
    elapsed.start();
    const QReadLocker locked(&m_lock);
    QVariantList out;
    for (int n = 0; n < kSchemaCount; ++n) {
        const Knob &k = kSchema[n];
        const QString key = QString::fromLatin1(k.key);
        QString range;
        if (k.min.isValid() && k.max.isValid()) {
            range = k.type == Type::Double
                ? QStringLiteral("%1–%2").arg(k.min.toDouble()).arg(k.max.toDouble())
                : QStringLiteral("%1–%2").arg(k.min.toInt()).arg(k.max.toInt());
        } else if (k.type == Type::Bool) {
            range = QStringLiteral("1 or 0");
        } else if (k.type == Type::Secret) {
            range = QStringLiteral("kept in the system wallet");
        }
        const QString group = groupOf(key);
        const GroupDoc *gd = groupDoc(group);
        Q_ASSERT_X(gd, "AdvancedConfig::reference", "schema group with no heading in kGroups");
        out.append(QVariantMap{
            {QStringLiteral("key"), key},
            {QStringLiteral("group"), group},
            {QStringLiteral("groupTitle"),
             gd ? QString::fromUtf8(gd->title) : group},
            {QStringLiteral("groupDoc"), gd ? QString::fromUtf8(gd->doc) : QString()},
            {QStringLiteral("name"), nameOf(key)},
            {QStringLiteral("def"), asText(k.def, k.type)},
            {QStringLiteral("range"), range},
            {QStringLiteral("doc"), QString::fromUtf8(k.doc)},
            {QStringLiteral("restart"), k.reload == Reload::Restart},
            {QStringLiteral("set"), m_values.contains(key)},
        });
    }
    qCDebug(logAdvanced, "advanced: reference() %lld ms (%d rows)", elapsed.elapsed(),
            int(out.size()));
    return out;
}

QString AdvancedConfig::defaultTemplate() const
{
    QElapsedTimer elapsed;
    elapsed.start();
    QString out;
    out += QStringLiteral("# Mailove advanced settings (schema %1)\n").arg(kSchemaVersion);
    out += QStringLiteral("#\n");
    out += QStringLiteral("# Every key below is commented out and shows its default. Uncomment\n"
                          "# a line to change it. Values outside the stated range are corrected\n"
                          "# on save, and an unknown key is ignored with a warning — neither\n"
                          "# stops the rest of the file from applying.\n");
    out += QStringLiteral("#\n");
    out += QStringLiteral("# Comments run to the end of a line only when the line starts with\n"
                          "# '#' or ';', so a '#' inside a URL stays part of the value.\n");
    out += QStringLiteral("#\n");
    out += QStringLiteral("# No secret is ever stored in this file. A key marked as kept in the\n"
                          "# system wallet takes its value once — type it, save, and the line is\n"
                          "# rewritten to '%1' with the value in the wallet. Clear the line to\n"
                          "# forget it.\n")
               .arg(kWalletPlaceholder);

    QString group;
    for (int n = 0; n < kSchemaCount; ++n) {
        const Knob &k = kSchema[n];
        const QString key = QString::fromLatin1(k.key);
        if (groupOf(key) != group) {
            group = groupOf(key);
            // The section's own explainer, in the file as well as in the UI: a
            // reader who opens advanced.conf in an editor is exactly the reader
            // who cannot see the Settings page while reading it.
            if (const GroupDoc *gd = groupDoc(group)) {
                out += QStringLiteral("\n# --- %1 ---\n").arg(QString::fromUtf8(gd->title));
                for (const QString &line : wrapComment(QString::fromUtf8(gd->doc)))
                    out += line;
            }
            out += QStringLiteral("\n[%1]\n").arg(group);
        }
        out += QStringLiteral("# %1\n").arg(QString::fromUtf8(k.doc));
        QStringList notes;
        if (k.min.isValid() && k.max.isValid()) {
            notes << (k.type == Type::Double
                          ? QStringLiteral("range %1–%2").arg(k.min.toDouble()).arg(k.max.toDouble())
                          : QStringLiteral("range %1–%2").arg(k.min.toInt()).arg(k.max.toInt()));
        }
        if (k.type == Type::Secret)
            notes << QStringLiteral("moved to the system wallet on save");
        if (k.reload == Reload::Restart)
            notes << QStringLiteral("takes effect on restart");
        if (!notes.isEmpty())
            out += QStringLiteral("# (%1)\n").arg(notes.join(QStringLiteral(", ")));
        out += QStringLiteral("# %1 = %2\n").arg(nameOf(key), asText(k.def, k.type));
    }
    qCDebug(logAdvanced, "advanced: defaultTemplate() %lld ms", elapsed.elapsed());
    return out;
}
