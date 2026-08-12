// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "securewipe.h"

#include <QLoggingCategory>

#include <openssl/crypto.h>

#ifdef Q_OS_LINUX
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

namespace
{
Q_LOGGING_CATEGORY(logWipe, "mailove.wipe")

/// How many contexts are currently holding decrypted plaintext. Not atomic:
/// every caller is on the GUI thread, which is where messages are opened and
/// closed.
int g_plaintextHolders = 0;
/// What RLIMIT_CORE was before we set it to zero, so it can be put back.
#ifdef Q_OS_LINUX
rlimit g_savedCoreLimit{};
bool g_coreLimitSaved = false;
#endif
}

namespace SecureWipe
{

void wipe(QByteArray &b)
{
    if (b.isEmpty())
        return;
    // See the header: overwriting a shared buffer wipes a private copy Qt
    // makes on the spot and leaves the shared bytes alone. Better to do
    // nothing than to do something that reads as protection and is not.
    if (!b.isDetached()) {
        qCDebug(logWipe, "not wiping a shared buffer of %lld bytes", qint64(b.size()));
        b.clear();
        return;
    }
    // OPENSSL_cleanse, not memset: this is a dead store to memory about to be
    // freed, and a compiler is entitled to delete that. cleanse is defined not
    // to be optimised away, and libcrypto is already linked for DKIM.
    OPENSSL_cleanse(b.data(), size_t(b.size()));
    b.clear();
}

void wipe(QString &s)
{
    if (s.isEmpty())
        return;
    if (!s.isDetached()) {
        qCDebug(logWipe, "not wiping a shared string of %lld chars", qint64(s.size()));
        s.clear();
        return;
    }
    OPENSSL_cleanse(s.data(), size_t(s.size()) * sizeof(QChar));
    s.clear();
}

void holdPlaintext()
{
    if (++g_plaintextHolders != 1)
        return;
#ifdef Q_OS_LINUX
    // Two separate doors to the same room. PR_SET_DUMPABLE stops the kernel
    // writing a dump for this process (and, usefully, also stops another
    // process ptrace-ing it); RLIMIT_CORE stops it independently, and is what
    // a core pattern piped to a helper obeys.
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (getrlimit(RLIMIT_CORE, &g_savedCoreLimit) == 0) {
        g_coreLimitSaved = true;
        rlimit off = g_savedCoreLimit;
        off.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &off);
    }
    qCDebug(logWipe, "decrypted mail in memory: core dumps suppressed");
#endif
}

void releasePlaintext()
{
    if (g_plaintextHolders <= 0 || --g_plaintextHolders != 0)
        return;
#ifdef Q_OS_LINUX
    // Back to normal, so an ordinary crash is still debuggable. The window in
    // which dumps are off is exactly the window in which a decrypted message
    // is open.
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    if (g_coreLimitSaved) {
        setrlimit(RLIMIT_CORE, &g_savedCoreLimit);
        g_coreLimitSaved = false;
    }
    qCDebug(logWipe, "no decrypted mail in memory: core dumps restored");
#endif
}

}
