# Mailove

The fast KDE-only email client.

<img width="300" height="300" alt="org mailove Mailove" src="https://github.com/user-attachments/assets/67841075-7f20-4e41-a6ca-7814b1988757" />


(c) 2026 Daniel Duris, dusoft@staznosti.sk

## What it does

Security-minded KDE-only IMAP and JMAP mail client, blazing fast.

### General
- **IMAP, JMAP, Gmail/365 OAuth** — multiple accounts supported. IMAP against any server (SSL/TLS, STARTTLS, plain), password or OAuth 2 for Gmail and Microsoft 365; JMAP (RFC 8620/8621) discovers its own endpoints from the address and authenticates with an API token or a password.
- **Push, or polling where there is none** — IMAP IDLE and JMAP EventSource both land as "something changed there"; what changed is then fetched the ordinary way. A timed refresh covers servers offering neither.
- **Every account stays current, not just the open one** — the same refresh syncs the accounts you are not looking at: inbox first, then their other folders.
- **Local cache with full-text search** — headers, read bodies and folders in SQLite: folders open instantly, offline included. FTS5 (accent-folding) + a case-insensitive regex.
- **Spam handling** — around 50 heuristic rules, not just the `X-Spam-*` headers: impersonation, homograph and zero-width tricks, phishing links, password forms in the body, dangerous attachments etc. A red **!** marks Spam - mouseover lists every rule that fired - everything explained. Older spam is cleared out automatically.

### UI
- **Fast by design** — a 20 ms limit on the GUI thread, one frame: anything slower runs on a worker. Nothing ever snaps or stalls mid-scroll.
- **UX to taste** — Look and feel sets the layout (message preview below or beside the list), row density, background colour and tab or window to compose email; Message sorting by any column; Shortcuts rebinds every action; Color labels for messages; Change the date format, refresh interval, spam retention, cache limits and debug logging
- **Compose & send** — SMTP with rich text, pasted images, attachments, signature and resumable drafts.
- **Attachments** — click to open, right-click to save. Stored zstd-compressed and deduplicated outside the database.
- **OpenPGP** — read and send signed and encrypted mail through GnuPG. Key manager, WKD discovery. Decrypted plaintext is never indexed, never cached, and is wiped from memory when the message closes.
- **Keyboard-first** — arrows, Page Up/Down, Home/End, Enter to open, Ctrl+W to close a tab, and the keyboard follows the folder you open.
- **Tabs** — Compose, Settings and opened messages are tabs. Ctrl+W closes; Compose can be set to open in a window if preferred.
- **Folders moving** — drag a folder onto another to reparent it, or onto the account name to move it to the top level. Rename from the context menu; where the protocol forbids it, the menu says so instead.
- **Unread counts** — a pill on every folder, blue on the inbox. A collapsed folder shows what is unread in the subfolders folded beneath it.

### Security & safety
- **Secure credential storage** — passwords and OAuth tokens in KWallet via Qt6Keychain, never a config file.
- **Sandboxed message viewing** — HTML renders with JavaScript, plugins and local-file access off, off-the-record, and every remote request blocked until the per-message opt-in. Links open in the system browser.
- **Sender authentication verdicts** — DKIM verified, ARC chains validated, server SPF/DKIM/DMARC alongside, shown per message in the viewer and fed into the spam score. A signature that covers only a stated length of the body (`l=`) reads as *partial*. ARC is what keeps mailing lists — which break SPF and DKIM by design — from being marked.

### Imports (MBOX)
- **Imported mail** — point it at a folder of mbox files and it imports as an offline account (Thunderbird, Evolution, KMail etc.). Subfolders become folder hierarchy, and Thunderbird's .sbd naming is understood. Add servers later to promote it to a live account.

## Screenshots
<img width="1920" height="1034" alt="1" src="https://github.com/user-attachments/assets/37cb8a95-5e58-4fdf-bbe4-1db994fc3848" />
<img width="1132" height="818" alt="compose" src="https://github.com/user-attachments/assets/128b1bf7-6eab-4ecd-9b98-afd7d1ec78ab" />
<img width="1920" height="1038" alt="02-settings-accounts" src="https://github.com/user-attachments/assets/108c1e8c-dc90-406f-8719-4fb24efef692" />
<img width="1920" height="1038" alt="03-settings-general" src="https://github.com/user-attachments/assets/594e49de-5bf6-43cb-8868-2c11bc185974" />
<img width="1920" height="1038" alt="04-settings-look" src="https://github.com/user-attachments/assets/cfa9486b-bdb6-41e1-8db1-28fcaffc104e" />
<img width="1920" height="1038" alt="05-settings-shortcuts" src="https://github.com/user-attachments/assets/a01aa48d-3a70-40ea-ac71-47e5afd9e115" />
<img width="1920" height="1038" alt="06-settings-about" src="https://github.com/user-attachments/assets/14543538-9c8d-4f1b-8b94-5bb9c9296783" />
<img width="571" height="112" alt="Screenshot_20260813_115049" src="https://github.com/user-attachments/assets/ac41c815-df3d-4e70-a791-5d152238cc6a" />
<img width="802" height="112" alt="Screenshot_20260813_115137" src="https://github.com/user-attachments/assets/1c07d657-731d-476c-aa20-6de2f05eb0b9" />
<img width="802" height="136" alt="Screenshot_20260813_115219" src="https://github.com/user-attachments/assets/7f8dbf7e-ae4a-4b5a-9348-8459de23ef19" />

## Installation

Packaged as DEB package and AppImage. Go to https://github.com/nekromoff/mailove/releases (open assets) to download.

## Technology

| Layer | Choice |
|---|---|
| Language / toolkit | C++20, Qt 6.11 (QML/Quick) |
| UI framework | KDE Kirigami 6 + Kirigami Addons |
| IMAP | KPim6 KIMAP (async KJobs, no Akonadi) |
| MIME parsing/building | KPim6 KMime |
| SMTP | KPim6 KSMTP |
| HTML viewer | QtWebEngine (Quick), custom `mailove:` URL scheme + request interceptor |
| Storage | SQLite via Qt SQL (WAL), FTS5 for full-text indexing |
| Attachment store | content-addressed files, zstd-compressed and deduplicated |
| DKIM / ARC | verified in-process against OpenSSL (libcrypto), worker thread |
| OpenPGP | GpgME / QGpgME → GnuPG (optional, `MAILOVE_OPENPGP`) |
| Secrets | Qt6Keychain → KWallet / libsecret |
| Rich-text editing | QTextDocument/QTextCursor exposed to QML (`DocumentHandler`) |
| Build | CMake + Ninja |

Computer-assisted development was used in the process.

## Building

```bash
sudo apt install cmake ninja-build extra-cmake-modules qt6-webengine-dev \
  kf6-kmime-dev kpim6-kimap-dev kpim6-ksmtp-dev qtkeychain-qt6-dev \
  qt6-base-dev qt6-declarative-dev kf6-kirigami-dev \
  libgpgmepp-dev libqgpgmeqt6-dev libzstd-dev

cmake -B build -G Ninja
cmake --build build
./build/mailove
```

OpenPGP is on by default and degrades gracefully: without GpgME the build drops
it, and without gnupg at runtime the Encryption settings say so and no gpg
process is ever spawned. `cmake -B build -DMAILOVE_OPENPGP=OFF` leaves it out
outright.

`build/tests/viewertest` is a headless end-to-end test of the sandboxed viewer pipeline (scheme registration, handler, render).

Packages are built from the same tree and land in the project root, named with
the version from `project()`:

```bash
cmake --build build --target package-deb   # mailove_<version>_<arch>.deb
cmake --build build --target packages      # the .deb and the AppImage
```

## Data locations

- Message cache: `~/.local/share/mailove/mailove/mailove.db`
- Settings: `~/.config/mailove/mailove.conf` (no secrets)
- Passwords and OAuth refresh tokens: KWallet, service `mailove`

## Known issues

- **KMime nested-boundary artifact** ([KDE bug 523826](https://bugs.kde.org/show_bug.cgi?id=523826)) — on messages whose inner MIME part closes tight against the parent boundary, a shape Gmail produces on replies with attachments, KMime inserts a blank line the original did not have. The body no longer hashes to what the sender signed, so DKIM and OpenPGP report such a message as *modified after signing* when nothing modified it. Upstream defect, not worked around here: the byte the parser discarded cannot be recovered downstream.

## Status

Working and in daily use. Multiple accounts, OAuth for Gmail and Microsoft 365, imported offline archives, and caches into the tens of gigabytes.
