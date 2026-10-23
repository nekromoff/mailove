// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "demomode.h"

#include "advancedconfig.h"

#include <QList>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>

#include <cctype>

namespace
{
/// What every word is replaced with. One flat list, bucketed by length at
/// first use, so adding a word cannot put it in the wrong bucket. Plain,
/// harmless nouns and adjectives: a screenshot full of them reads as mail
/// about gardens and lighthouses, which is the point.
const char *const kWords[] = {
    "a", "an", "as", "at", "be", "by", "do", "go", "if", "in", "is", "it", "me", "my",
    "no", "of", "on", "or", "so", "to", "up", "us", "we",
    "act", "air", "arm", "art", "bag", "bed", "box", "car", "cat", "cup", "day", "dog",
    "ear", "egg", "end", "eye", "fan", "fig", "fox", "hat", "ice", "ink", "jam", "jar",
    "key", "kit", "lab", "map", "mix", "net", "oak", "oil", "owl", "pan", "pen", "pie",
    "pot", "ray", "row", "sea", "sky", "sun", "tea", "toy", "van", "web", "zoo",
    "area", "bake", "band", "bark", "bell", "bird", "blue", "boat", "book", "cake",
    "calm", "card", "cave", "city", "coat", "cool", "corn", "dawn", "deer", "desk",
    "door", "dove", "drum", "dust", "east", "echo", "farm", "fern", "fish", "flag",
    "foam", "fork", "frog", "gate", "gift", "glow", "gold", "hall", "harp", "hill",
    "home", "idea", "iron", "jazz", "kite", "lake", "lamp", "leaf", "lily", "lion",
    "mint", "moon", "nest", "note", "oven", "park", "pear", "pine", "plan", "pond",
    "rain", "reef", "ring", "road", "rock", "rose", "sail", "salt", "sand", "ship",
    "silk", "snow", "soup", "star", "stem", "team", "tide", "tree", "wave", "wind",
    "wolf", "wood", "yard",
    "amber", "apple", "beach", "berry", "bloom", "brave", "bread", "brick", "brook",
    "cabin", "candy", "cedar", "chair", "chalk", "cloud", "coral", "crane", "creek",
    "daisy", "dance", "delta", "dream", "eagle", "earth", "fable", "field", "flame",
    "flute", "frost", "globe", "grain", "grape", "green", "heart", "honey", "horse",
    "house", "ivory", "jewel", "juice", "lemon", "light", "lunar", "maple", "marsh",
    "metal", "music", "noble", "ocean", "olive", "otter", "paint", "pearl", "piano",
    "plaza", "quiet", "radio", "raven", "river", "robin", "salad", "shell", "smile",
    "solar", "spice", "stone", "storm", "sugar", "table", "tiger", "toast", "tower",
    "train", "tulip", "vivid", "whale", "wheat", "world",
    "anchor", "autumn", "basket", "bridge", "button", "candle", "canyon", "carpet",
    "castle", "cherry", "circle", "copper", "cotton", "desert", "dinner", "falcon",
    "forest", "garden", "ginger", "glider", "harbor", "island", "jungle", "kitten",
    "ladder", "lagoon", "laptop", "lizard", "marble", "meadow", "mirror", "number",
    "orange", "orchid", "parrot", "pebble", "pencil", "pepper", "planet", "pocket",
    "puzzle", "rabbit", "ribbon", "rocket", "saddle", "silver", "spring", "stream",
    "summer", "sunset", "tomato", "travel", "tunnel", "turtle", "valley", "velvet",
    "violet", "walnut", "window", "winter", "yellow",
    "academy", "balcony", "blanket", "bicycle", "cabinet", "captain", "century",
    "chapter", "chimney", "compass", "concert", "crystal", "curtain", "diamond",
    "dolphin", "evening", "feather", "fortune", "gallery", "harvest", "horizon",
    "journey", "kitchen", "lantern", "library", "machine", "meeting", "morning",
    "mustard", "network", "orchard", "painter", "pelican", "penguin", "picture",
    "pumpkin", "rainbow", "seagull", "shelter", "sparrow", "station", "success",
    "sunrise", "theater", "thunder", "trumpet", "uniform", "venture", "village",
    "weather", "whistle",
    "airplane", "aquarium", "backpack", "birthday", "calendar", "campfire", "cardinal",
    "champion", "chestnut", "notebook", "daylight", "elephant", "festival", "fireside",
    "flamingo", "footpath", "frontier", "gardener", "hedgehog", "highland", "keyboard",
    "lavender", "lemonade", "magnolia", "marigold", "mountain", "mushroom", "necklace",
    "overture", "painting", "pavilion", "platform", "portrait", "question", "raindrop",
    "sapphire", "seashore", "snowfall", "squirrel", "stardust", "sunlight", "treasure",
    "umbrella", "vineyard", "waterway", "woodland",
    "adventure", "afternoon", "butterfly", "carnation", "celebrate", "chocolate",
    "community", "crocodile", "dandelion", "direction", "discovery", "education",
    "evergreen", "excellent", "fireplace", "framework", "furniture", "geography",
    "grassland", "happiness", "horseshoe", "important", "invention", "landscape",
    "lightning", "limestone", "marmalade", "moonlight", "newspaper", "orchestra",
    "pineapple", "sandstone", "signature", "snowflake", "spaceship", "starlight",
    "sunflower", "telescope", "tradition", "waterfall", "wonderful",
    "lighthouse", "strawberry", "blackberry", "waterproof", "playground", "background",
    "basketball", "friendship", "generation", "instrument", "motorcycle", "photograph",
    "restaurant", "scientific", "technology", "television", "typewriter", "understand",
    "vegetables", "watermelon", "wilderness", "woodpecker",
};

/// kWords by length: buckets()[n] holds the words of n letters.
const QList<QStringList> &buckets()
{
    static const QList<QStringList> byLength = [] {
        QList<QStringList> out;
        for (const char *w : kWords) {
            const QString word = QString::fromLatin1(w);
            while (out.size() <= word.size())
                out.append(QStringList());
            out[word.size()].append(word);
        }
        return out;
    }();
    return byLength;
}

/// Kept as typed: they say what kind of text this is (a reply, a link)
/// without saying anything about whose it is, and a subject that has lost
/// its "Re:" no longer looks like mail.
const QSet<QString> &passthrough()
{
    static const QSet<QString> words = {
        QStringLiteral("re"),    QStringLiteral("fw"),  QStringLiteral("fwd"),
        QStringLiteral("http"),  QStringLiteral("https"), QStringLiteral("www"),
        QStringLiteral("mailto"),
        // The standard folders: every client has them, and a sidebar where
        // even "Inbox" is a made-up word looks broken rather than private.
        QStringLiteral("inbox"), QStringLiteral("sent"), QStringLiteral("drafts"),
        QStringLiteral("trash"), QStringLiteral("junk"), QStringLiteral("spam"),
        QStringLiteral("archive"), QStringLiteral("outbox"),
    };
    return words;
}

/// Stable across runs and platforms, unlike qHash, so a demo/seed screenshot
/// comes out the same every time.
quint64 mix(quint64 x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

quint64 hashOf(QStringView s, quint64 salt)
{
    quint64 h = 0xcbf29ce484222325ULL ^ salt;
    for (QChar c : s) {
        h ^= c.unicode();
        h *= 0x100000001b3ULL;
    }
    return mix(h);
}

bool isWordChar(QChar c)
{
    return c.isLetter() || c.isMark();
}

/// \a fake in the capitalisation \a real was typed in: ALL CAPS, Capitalised
/// or lower case. Anything mixed reads as Capitalised.
QString cased(const QString &real, QString fake)
{
    int letters = 0;
    int upper = 0;
    for (QChar c : real) {
        if (c.isLetter()) {
            ++letters;
            if (c.isUpper())
                ++upper;
        }
    }
    if (letters > 1 && upper == letters)
        return fake.toUpper();
    if (!real.isEmpty() && real.at(0).isUpper())
        fake[0] = fake.at(0).toUpper();
    return fake;
}

QString fakeWord(const QString &real, quint64 salt)
{
    const QString lower = real.toLower();
    if (passthrough().contains(lower))
        return real;
    const QList<QStringList> &byLength = buckets();
    const int longest = int(byLength.size()) - 1;
    quint64 h = hashOf(lower, salt);
    // Lengths wobble by one either way past three letters, so a fake line
    // does not spell out the exact length of every real word in it.
    int target = int(real.size());
    if (target >= 4)
        target += int((h >> 40) % 3) - 1;
    QString out;
    while (target > 0) {
        int len = qMin(target, longest);
        while (len > 1 && byLength.at(len).isEmpty())
            --len;
        const QStringList &bucket = byLength.at(len);
        out += bucket.at(int(h % quint64(bucket.size())));
        target -= len;
        h = mix(h);
        // A long word is a compound of short ones; a sliver left at the end
        // would only add a stray "a".
        if (target < 3)
            break;
    }
    return cased(real, out);
}

QString fakeDigits(const QString &real, quint64 salt)
{
    quint64 h = hashOf(real, salt ^ 0xd1b54a32d192ed03ULL);
    QString out;
    out.reserve(real.size());
    for (int n = 0; n < real.size(); ++n) {
        int digit = int(h % 10);
        // "07" for "42" looks like a different kind of number; keep it a
        // number of the same size.
        if (n == 0 && real.size() > 1 && digit == 0)
            digit = 1 + int((h >> 8) % 9);
        out += QChar(u'0' + digit);
        h = mix(h);
    }
    return out;
}

/// Words and digit runs replaced, everything between them (spaces,
/// punctuation, symbols) kept so the line keeps its shape.
QString scrambleWords(const QString &s, quint64 salt)
{
    QString out;
    out.reserve(s.size() + 8);
    qsizetype i = 0;
    while (i < s.size()) {
        const QChar c = s.at(i);
        if (isWordChar(c)) {
            qsizetype j = i;
            while (j < s.size() && isWordChar(s.at(j)))
                ++j;
            out += fakeWord(s.mid(i, j - i), salt);
            i = j;
        } else if (c.isDigit()) {
            qsizetype j = i;
            while (j < s.size() && s.at(j).isDigit())
                ++j;
            out += fakeDigits(s.mid(i, j - i), salt);
            i = j;
        } else {
            out += c;
            ++i;
        }
    }
    return out;
}

QString fakeAddress(const QString &local, const QString &domain, quint64 salt)
{
    QString out = scrambleWords(local, salt).toLower() + QLatin1Char('@');
    const QStringList labels = domain.split(QLatin1Char('.'));
    for (int n = 0; n + 1 < labels.size(); ++n)
        out += scrambleWords(labels.at(n), salt).toLower() + QLatin1Char('.');
    static const char *const kTlds[] = {"com", "org", "net"};
    out += QLatin1String(kTlds[hashOf(domain.toLower(), salt) % 3]);
    return out;
}

/// Whether \a html at \a i opens a tag named \a name (case-insensitive).
bool opensTag(const QString &html, qsizetype i, QLatin1String name)
{
    if (html.at(i) != u'<')
        return false;
    const qsizetype end = i + 1 + name.size();
    if (end > html.size()
        || QStringView(html).mid(i + 1, name.size()).compare(name, Qt::CaseInsensitive) != 0)
        return false;
    return end == html.size() || !html.at(end).isLetterOrNumber();
}
} // namespace

DemoMode &DemoMode::instance()
{
    static DemoMode demo;
    return demo;
}

DemoMode::DemoMode(QObject *parent)
    : QObject(parent)
    , m_lastOn(enabled())
    , m_lastSeed(AdvancedConfig::i("demo/seed"))
{
    connect(&AdvancedConfig::instance(), &AdvancedConfig::reloaded, this, [this] {
        const bool on = enabled();
        const int seed = AdvancedConfig::i("demo/seed");
        if (on == m_lastOn && (seed == m_lastSeed || !on)) {
            m_lastSeed = seed;
            return;
        }
        m_lastOn = on;
        m_lastSeed = seed;
        Q_EMIT changed();
    });
}

bool DemoMode::enabled()
{
    return AdvancedConfig::b("demo/enabled");
}

quint64 DemoMode::salt()
{
    // Drawn once per launch: a fake word seen in one run's screenshot says
    // nothing about the real one, because the next run maps it elsewhere.
    static const quint64 launch = QRandomGenerator::system()->generate64();
    const int seed = AdvancedConfig::i("demo/seed");
    return seed ? mix(quint64(seed)) : launch;
}

QString DemoMode::text(const QString &s)
{
    return enabled() ? scrambleText(s, salt()) : s;
}

QByteArray DemoMode::html(const QByteArray &html)
{
    if (!enabled())
        return html;
    return scrambleHtml(QString::fromUtf8(html), salt()).toUtf8();
}

QString DemoMode::markup(const QString &html)
{
    return enabled() ? scrambleHtml(html, salt()) : html;
}

QString DemoMode::fingerprint(const QString &fp)
{
    return enabled() ? scrambleFingerprint(fp, salt()) : fp;
}

QString DemoMode::identifiers(const QString &s)
{
    return enabled() ? scrambleIdentifiers(s, salt()) : s;
}

qint64 DemoMode::dateShiftSecs()
{
    if (!enabled())
        return 0;
    // Into the past, by two months to three years and an odd number of
    // minutes, so neither the day nor the time of day is the real one.
    const quint64 h = mix(salt() ^ 0x5851f42d4c957f2dULL);
    const qint64 days = 60 + qint64(h % 1000);
    const qint64 minutes = qint64((h >> 32) % 1440);
    return -(days * 86400 + minutes * 60);
}

QDateTime DemoMode::date(const QDateTime &when)
{
    const qint64 shift = dateShiftSecs();
    return shift && when.isValid() ? when.addSecs(shift) : when;
}

QString DemoMode::scrambleText(const QString &s, quint64 salt)
{
    static const QRegularExpression addressRe(
        QStringLiteral("([A-Za-z0-9._%+\\-]+)@([A-Za-z0-9\\-]+(?:\\.[A-Za-z0-9\\-]+)+)"));
    QString out;
    out.reserve(s.size() + 8);
    qsizetype last = 0;
    auto it = addressRe.globalMatch(s);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out += scrambleWords(s.mid(last, m.capturedStart() - last), salt);
        out += fakeAddress(m.captured(1), m.captured(2), salt);
        last = m.capturedEnd();
    }
    out += scrambleWords(s.mid(last), salt);
    return out;
}

QString DemoMode::scrambleFingerprint(const QString &fp, quint64 salt)
{
    // Keyed by the digits alone, so "ABCD 1234" and "abcd1234" — the same key
    // grouped or not — come out as the same fake. Hashed from the start
    // rather than per digit: a short key id must not be the tail of the fake
    // full fingerprint it belongs to, or one would give the other away.
    QString digits;
    bool lower = false;
    for (QChar c : fp) {
        if (c.unicode() < 128 && isxdigit(c.unicode())) {
            digits += c.toUpper();
            lower = lower || c.isLower();
        }
    }
    quint64 h = hashOf(digits, salt ^ 0x2545f4914f6cdd1dULL);
    // Case follows the whole input, not each position: a digit has none, and
    // the fake letter standing in for it must match its neighbours.
    const char *const hex = lower ? "0123456789abcdef" : "0123456789ABCDEF";
    QString out;
    out.reserve(fp.size());
    for (QChar c : fp) {
        if (c.unicode() < 128 && isxdigit(c.unicode())) {
            out += QLatin1Char(hex[h & 15]);
            h = mix(h);
        } else {
            out += c;
        }
    }
    return out;
}

QString DemoMode::scrambleIdentifiers(const QString &s, quint64 salt)
{
    // An address, a fingerprint grouped in fours, or a bare hex run of key-id
    // length. The run must hold a digit: "acceded" is a word, not a key id.
    static const QRegularExpression re(QStringLiteral(
        "([A-Za-z0-9._%+\\-]+)@([A-Za-z0-9\\-]+(?:\\.[A-Za-z0-9\\-]+)+)"
        "|\\b[0-9A-Fa-f]{4}(?: [0-9A-Fa-f]{4}){3,}\\b"
        "|\\b(?=[0-9A-Fa-f]*[0-9])[0-9A-Fa-f]{8,}\\b"));
    QString out;
    qsizetype last = 0;
    auto it = re.globalMatch(s);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out += QStringView(s).mid(last, m.capturedStart() - last);
        out += m.capturedLength(1) > 0 ? fakeAddress(m.captured(1), m.captured(2), salt)
                                       : scrambleFingerprint(m.captured(), salt);
        last = m.capturedEnd();
    }
    out += QStringView(s).mid(last);
    return out;
}

QString DemoMode::scrambleHtml(const QString &html, quint64 salt)
{
    QString out;
    out.reserve(html.size() + 64);
    QString text;
    auto flush = [&] {
        if (!text.isEmpty()) {
            out += scrambleText(text, salt);
            text.clear();
        }
    };
    static const QRegularExpression entityRe(QStringLiteral("&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);"));
    qsizetype i = 0;
    while (i < html.size()) {
        const QChar c = html.at(i);
        if (c == u'<') {
            flush();
            qsizetype end;
            if (QStringView(html).mid(i).startsWith(QLatin1String("<!--"))) {
                end = html.indexOf(QLatin1String("-->"), i + 4);
                end = end < 0 ? html.size() : end + 3;
            } else {
                // A '>' inside a quoted attribute value does not close the tag.
                QChar quote;
                end = i + 1;
                while (end < html.size()) {
                    const QChar t = html.at(end);
                    if (!quote.isNull()) {
                        if (t == quote)
                            quote = QChar();
                    } else if (t == u'"' || t == u'\'') {
                        quote = t;
                    } else if (t == u'>') {
                        break;
                    }
                    ++end;
                }
                end = qMin(end + 1, html.size());
            }
            // Style and script bodies are code, not text: copied untouched
            // up to their closing tag.
            for (QLatin1String raw : {QLatin1String("style"), QLatin1String("script")}) {
                if (opensTag(html, i, raw)) {
                    const qsizetype close =
                        html.indexOf(QLatin1String("</") + raw, end, Qt::CaseInsensitive);
                    end = close < 0 ? html.size() : close;
                    break;
                }
            }
            out += QStringView(html).mid(i, end - i);
            i = end;
        } else if (c == u'&') {
            const QRegularExpressionMatch m =
                entityRe.match(html, i, QRegularExpression::NormalMatch,
                                   QRegularExpression::AnchorAtOffsetMatchOption);
            if (m.hasMatch()) {
                flush();
                out += m.captured();
                i = m.capturedEnd();
            } else {
                text += c;
                ++i;
            }
        } else {
            text += c;
            ++i;
        }
    }
    flush();
    return out;
}
