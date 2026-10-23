// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

// Silences the XOAUTH2 SASL plugin's chatter.
//
// libkdexoauth2 (libkgapi's Cyrus SASL plugin, which KIMAP signs in to Gmail
// and Outlook through) prints "[SASL-XOAUTH2] - Requesting token!" and two
// siblings to stderr on every login, unconditionally — several lines per
// connection, per poll, forever. It writes with a bare fprintf, not Qt
// logging, so no filter rule reaches it.
//
// It is built with _FORTIFY_SOURCE, so that fprintf is glibc's __fprintf_chk.
// Defining the symbol here, and exporting it from the executable (see
// CMakeLists.txt), makes the plugin bind to this one when it is dlopen'd: the
// executable comes first in the lookup scope. Exactly the plugin's progress
// lines are dropped; its "FAILED!" lines and everything every other library
// writes go through unchanged to glibc's own implementation.
//
// Deliberately not done by pointing fd 2 at a pipe and filtering it: a
// process that is aborting writes its last words to stderr and dies before a
// reader thread could pass them on, and those are the lines that matter most.

// Included before the test: __GLIBC__ comes from the C library's own headers.
#include <cstdarg>
#include <cstdio>
#include <cstring>

#if defined(__GLIBC__) && defined(__linux__)

extern "C" int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap);

extern "C" __attribute__((visibility("default"))) int
__fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
    static const char kPrefix[] = "[SASL-XOAUTH2] - ";
    if (stream == stderr && format && std::strncmp(format, kPrefix, sizeof kPrefix - 1) == 0
        && !std::strstr(format, "FAILED"))
        return 0;
    va_list ap;
    va_start(ap, format);
    const int written = __vfprintf_chk(stream, flag, format, ap);
    va_end(ap);
    return written;
}

#endif
