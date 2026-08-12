// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * Checks the translations JmapBackend does between JMAP and MailBackend
 * (doc/JMAP_ROADMAP.md phase 1): the RFC 5322 header block rebuilt from
 * `Email/get`'s `headers`, the flag vocabulary, mailbox roles, and the
 * synthetic local key for an opaque JMAP id.
 *
 * The first of those carries the load. `HeaderInfo::message` is a *parsed*
 * header and the spam and DKIM paths read its raw octets, so a reconstruction
 * that is merely close would show up later as messages that verified fine over
 * IMAP failing over JMAP — the kind of bug that looks like a crypto problem for
 * a week. The claim is therefore pinned to a recording of both halves:
 * `cyrus-jmap-headers.json` is what the server said the headers were, and
 * `cyrus-jmap-message.eml` is the same message's blob. Rebuilding the first
 * must reproduce the second byte for byte.
 */

#include "../src/jmapbackend.h"

#include <KMime/Message>

#include <QCoreApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QTimer>

static int failures = 0;

/// Plain stdout rather than qInfo: a diagnostic tool has to print its findings
/// whatever the ambient QT_LOGGING_RULES say, and the default rules drop
/// qInfo() on the floor.
static QTextStream &out()
{
    static QTextStream s(stdout);
    return s;
}

static void check(bool ok, const QString &what)
{
    out() << (ok ? QStringLiteral("  ok   ") : QStringLiteral("  FAIL ")) << what << Qt::endl;
    if (!ok)
        ++failures;
}

/// Something the server in front of us cannot do, as distinct from something
/// this client got wrong. Counted separately so a container built without a
/// feature does not read as a defect in mailove — and so it does not read as a
/// pass either.
static int skipped = 0;
static void skip(const QString &what, const QString &why)
{
    out() << QStringLiteral("  skip ") << what << QStringLiteral(" — ") << why << Qt::endl;
    ++skipped;
}

static QByteArray readFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        check(false, QStringLiteral("cannot read %1: %2").arg(path, file.errorString()));
        return {};
    }
    return file.readAll();
}

/// Drives the real backend against a real server: connect, list, open, page,
/// fetch a body. The whole Phase 1 read path, in the order MailClient walks it.
/// Meant for the test container — see doc/JMAP_ROADMAP.md.
static int runLive(const QString &host, const QString &token)
{
    MailBackend::Credentials credentials;
    credentials.host = host;
    credentials.accessToken = token;

    JmapBackend backend;
    QEventLoop loop;
    int result = 1;
    QString folder;

    QObject::connect(&backend, &MailBackend::errorOccurred, &loop,
                     [&](MailBackend::Error error, const QString &message) {
                         out() << "error (" << static_cast<int>(error) << "): " << message
                               << Qt::endl;
                         loop.quit();
                     });

    QObject::connect(&backend, &MailBackend::bodyFetched, &loop,
                     [&](const QString &, const QString &remoteId,
                         const std::shared_ptr<KMime::Message> &message) {
                         out() << "body " << remoteId << "  "
                               << message->encodedContent().size() << " bytes, subject="
                               << message->subject()->asUnicodeString() << Qt::endl;
                         result = 0;
                         loop.quit();
                     });

    QObject::connect(&backend, &MailBackend::headersFetched, &loop,
                     [&](const QString &which, const QList<MailBackend::HeaderInfo> &headers) {
                         out() << "headers in " << which << ": " << headers.size() << Qt::endl;
                         QStringList firstBody;
                         for (const MailBackend::HeaderInfo &header : headers) {
                             out() << "  uid=" << header.uid << " remoteId=" << header.remoteId
                                   << " size=" << header.size << " flags=["
                                   << header.flags.join(QLatin1Char(',')) << "]" << Qt::endl
                                   << "    subject: "
                                   << (header.message && header.message->subject(KMime::DontCreate)
                                           ? header.message->subject()->asUnicodeString()
                                           : QStringLiteral("(none)"))
                                   << Qt::endl
                                   << "    from:    "
                                   << (header.message && header.message->from(KMime::DontCreate)
                                           ? header.message->from()->asUnicodeString()
                                           : QStringLiteral("(none)"))
                                   << Qt::endl
                                   << "    head is " << (header.message
                                                             ? header.message->head().size()
                                                             : 0)
                                   << " raw bytes" << Qt::endl;
                             if (firstBody.isEmpty())
                                 firstBody.append(header.remoteId);
                         }
                         if (firstBody.isEmpty()) {
                             out() << "no messages to fetch a body for" << Qt::endl;
                             result = 0;
                             loop.quit();
                             return;
                         }
                         out() << "fetching body of " << firstBody.first() << Qt::endl;
                         backend.fetchBodies(folder, firstBody, {});
                     });

    QObject::connect(&backend, &MailBackend::folderOpened, &loop,
                     [&](const QString &which, qint64 count, const QString &syncToken) {
                         out() << "opened " << which << ": " << count
                               << " message(s), syncToken=\"" << syncToken << "\"" << Qt::endl;
                         backend.fetchHeaderWindow(which, 0, 10, false, {});
                     });

    QObject::connect(&backend, &MailBackend::foldersListed, &loop,
                     [&](const QList<MailBackend::FolderInfo> &folders, QChar separator) {
                         out() << folders.size() << " folder(s), separator '" << separator
                               << "'" << Qt::endl;
                         for (const MailBackend::FolderInfo &info : folders) {
                             out() << "  " << info.path << "  role="
                                   << static_cast<int>(info.role) << Qt::endl;
                             if (info.role == MailBackend::FolderRole::Inbox)
                                 folder = info.path;
                         }
                         if (folder.isEmpty() && !folders.isEmpty())
                             folder = folders.first().path;
                         if (folder.isEmpty()) {
                             out() << "no folder to open" << Qt::endl;
                             loop.quit();
                             return;
                         }
                         backend.openFolder(folder, QString());
                     });

    QObject::connect(&backend, &MailBackend::connectedChanged, &loop, [&](bool connected) {
        out() << "connected: " << (connected ? "yes" : "no") << Qt::endl;
        if (connected)
            backend.listFolders();
    });

    backend.connectAccount(credentials);
    loop.exec();
    return result;
}

/**
 * Drives the whole write path against a real server, in the order a user would:
 * create a mailbox, rename it, file a message in it, flag the message, move it,
 * delete it, and delete the mailbox.
 *
 * Sequential on purpose, and not just for readability — each step names
 * something the one before it produced, and there is nothing offline that can
 * check the *shape* of an `Email/set` against a server's opinion of it. The
 * first failure stops the run rather than pressing on: a half-applied sequence
 * leaves a mailbox on the server that the next run then trips over, and the
 * error that matters is the first one anyway.
 *
 * Sending is left out unless \a sendTo is given, because it is the one step
 * that cannot be undone — a submission goes to a real recipient.
 */
static int runLiveWrite(const QString &host, const QString &token, const QString &sendFrom,
                        const QString &sendTo)
{
    MailBackend::Credentials credentials;
    credentials.host = host;
    credentials.accessToken = token;

    JmapBackend backend;
    QEventLoop loop;
    int result = 1;

    const QString stamp = QString::number(QDateTime::currentSecsSinceEpoch());
    const QString created = QStringLiteral("mailove-test-") + stamp;
    const QString renamed = created + QStringLiteral("-renamed");
    QString inbox;
    QString filedId;
    // Hoisted so the duplicate-filing step can present the *identical* bytes;
    // that is the whole trigger for the server's `alreadyExists`.
    const QByteArray filedRaw =
        "From: tester <tester@example.invalid>\r\n"
        "To: tester <tester@example.invalid>\r\n"
        "Subject: mailove write-path test\r\n"
        "Date: Wed, 05 Aug 2026 10:00:00 +0000\r\n"
        "Message-ID: <mailove-write-" + stamp.toUtf8()
        + "@example.invalid>\r\n"
          "MIME-Version: 1.0\r\n"
          "Content-Type: text/plain; charset=utf-8\r\n"
          "\r\n"
          "Filed by jmapbackendtest --live-write.\r\n";

    // Errors reach the callbacks too, but errorOccurred() is what the
    // application listens to and a step that reports success while raising one
    // is itself a bug worth seeing.
    QObject::connect(&backend, &MailBackend::errorOccurred, &loop,
                     [&](MailBackend::Error error, const QString &message) {
                         out() << "    (errorOccurred " << static_cast<int>(error) << ": "
                               << message << ")" << Qt::endl;
                     });

    using Done = std::function<void(bool, const QString &)>;
    struct Step {
        QString name;
        std::function<void(Done)> run;
    };
    // The callback every operation takes, turned into the yes-or-no the runner
    // wants: MailBackend reports Error::None for success and words for the rest.
    const auto asDone = [](const Done &done) {
        return [done](MailBackend::Error error, const QString &message) {
            done(error == MailBackend::Error::None, message);
        };
    };

    QList<Step> steps;
    steps.append({QStringLiteral("create a mailbox"), [&](Done done) {
                      backend.createFolder(created, asDone(done));
                  }});
    steps.append({QStringLiteral("rename it"), [&](Done done) {
                      backend.renameFolder(created, renamed, asDone(done));
                  }});
    steps.append({QStringLiteral("file a message in it"), [&](Done done) {
                      backend.storeMessage(renamed, filedRaw, {QStringLiteral("draft")},
                                           [&, done](MailBackend::Error error,
                                                     const QString &remoteId,
                                                     const QString &message) {
                                               filedId = remoteId;
                                               if (error == MailBackend::Error::None
                                                   && remoteId.isEmpty()) {
                                                   done(false,
                                                        QStringLiteral("filed without an id"));
                                                   return;
                                               }
                                               done(error == MailBackend::Error::None, message);
                                           });
                  }});
    steps.append({QStringLiteral("filing the same bytes again names the same copy"),
                  [&](Done done) {
                      // The server answers `alreadyExists` rather than filing a
                      // second copy, and names the one it kept. The caller asked
                      // for the message to be filed and it is, so that is a
                      // success carrying the existing id — not a failure, and
                      // certainly not a duplicate draft.
                      backend.storeMessage(renamed, filedRaw, {QStringLiteral("draft")},
                                           [&, done](MailBackend::Error error,
                                                     const QString &remoteId,
                                                     const QString &message) {
                          if (error != MailBackend::Error::None) {
                              done(false, message);
                              return;
                          }
                          done(remoteId == filedId,
                               QStringLiteral("got id \"%1\", expected the first copy's "
                                              "\"%2\"")
                                   .arg(remoteId, filedId));
                      });
                  }});
    steps.append({QStringLiteral("mark it read and flagged"), [&](Done done) {
                      backend.setFlags(renamed, {filedId},
                                       {QStringLiteral("seen"), QStringLiteral("flagged")},
                                       {QStringLiteral("draft")}, asDone(done));
                  }});
    steps.append({QStringLiteral("read the flags back"), [&](Done done) {
                      // The one step that checks rather than acts: a /set the
                      // server quietly declined answers success, so the flags
                      // have to be seen to have changed.
                      auto *connection = new QMetaObject::Connection;
                      *connection = QObject::connect(
                          &backend, &MailBackend::headersFetched, &loop,
                          [&, done, connection](const QString &,
                                                const QList<MailBackend::HeaderInfo> &headers) {
                              QObject::disconnect(*connection);
                              delete connection;
                              if (headers.isEmpty()) {
                                  done(false, QStringLiteral("the message came back as nothing"));
                                  return;
                              }
                              const QStringList flags = headers.first().flags;
                              out() << "      flags now [" << flags.join(QLatin1Char(','))
                                    << "]" << Qt::endl;
                              if (!flags.contains(QStringLiteral("seen"))
                                  || !flags.contains(QStringLiteral("flagged"))) {
                                  done(false, QStringLiteral("the added flags are not set"));
                                  return;
                              }
                              if (flags.contains(QStringLiteral("draft"))) {
                                  done(false, QStringLiteral("the removed flag is still set"));
                                  return;
                              }
                              done(true, QString());
                          });
                      backend.fetchHeadersById(renamed, {filedId}, {});
                  }});
    steps.append({QStringLiteral("move it to the inbox"), [&](Done done) {
                      backend.moveMessages(renamed, {filedId}, inbox, asDone(done));
                  }});
    steps.append({QStringLiteral("delete it"), [&](Done done) {
                      backend.deleteMessages(inbox, {filedId}, asDone(done));
                  }});
    if (!sendTo.isEmpty()) {
        // Shared between the two send steps: sending the identical bytes twice
        // is what drives the server to answer `alreadyExists` to the import the
        // submission is built on.
        auto sentRaw = std::make_shared<QByteArray>(
            "From: " + sendFrom.toUtf8() + "\r\nTo: " + sendTo.toUtf8()
            + "\r\nSubject: mailove JMAP submission test\r\n"
              "Date: Wed, 05 Aug 2026 10:00:00 +0000\r\n"
              "Message-ID: <mailove-send-"
            + stamp.toUtf8()
            + "@example.invalid>\r\n"
              "MIME-Version: 1.0\r\n"
              "Content-Type: text/plain; charset=utf-8\r\n"
              "\r\nSent by jmapbackendtest --live-write.\r\n");
        steps.append({QStringLiteral("send a message"), [&, sentRaw](Done done) {
                          backend.sendMessage(*sentRaw, sendFrom, {sendTo}, asDone(done));
                      }});
        steps.append({QStringLiteral("sending the same bytes again still sends"),
                      [&, sentRaw](Done done) {
                          // The first send left this exact message in Sent, so
                          // the import behind the submission is refused with
                          // `alreadyExists`. Nothing is actually wrong — the
                          // message simply has to be named by id instead of by
                          // the creation id of an import that did not happen —
                          // and the send must go through rather than fail with
                          // something the user can do nothing about.
                          backend.sendMessage(*sentRaw, sendFrom, {sendTo}, asDone(done));
                      }});
    }
    steps.append({QStringLiteral("delete the mailbox"), [&](Done done) {
                      backend.deleteFolder(renamed, asDone(done));
                  }});

    int index = 0;
    std::function<void()> next;
    next = [&] {
        if (index >= steps.size()) {
            result = failures ? 1 : 0;
            loop.quit();
            return;
        }
        const Step step = steps.at(index++);
        step.run([&, name = step.name](bool ok, const QString &error) {
            check(ok, ok ? name : name + QStringLiteral(" — ") + error);
            if (!ok) {
                out() << "stopping: the mailbox " << renamed
                      << " may need deleting by hand" << Qt::endl;
                loop.quit();
                return;
            }
            next();
        });
    };

    QObject::connect(&backend, &MailBackend::foldersListed, &loop,
                     [&](const QList<MailBackend::FolderInfo> &folders, QChar) {
                         for (const MailBackend::FolderInfo &info : folders) {
                             if (info.role == MailBackend::FolderRole::Inbox)
                                 inbox = info.path;
                         }
                         if (inbox.isEmpty() && !folders.isEmpty())
                             inbox = folders.first().path;
                         out() << folders.size() << " folder(s); inbox is " << inbox << Qt::endl;
                         next();
                     });

    QObject::connect(&backend, &MailBackend::connectedChanged, &loop, [&](bool connected) {
        if (connected)
            backend.listFolders();
    });

    backend.connectAccount(credentials);
    loop.exec();
    return result;
}

/**
 * Drives Phase 3 against a real server: `Email/changes` delta sync, then
 * EventSource push.
 *
 * Both are things no fixture can establish, for the same reason: they are
 * claims about what the *server* does between two points in time. The delta
 * half files a message, asks what changed, and expects to be told about that
 * message and no other; then deletes it and expects to be told it is gone —
 * which is the half IMAP cannot do at all, and the reason `messagesVanished`
 * exists. The push half opens the stream, makes a change, and waits to be told
 * about it without having asked.
 */
static int runLiveSync(const QString &host, const QString &token)
{
    MailBackend::Credentials credentials;
    credentials.host = host;
    credentials.accessToken = token;

    JmapBackend backend;
    QEventLoop loop;
    int result = 1;

    QString inbox;
    QString openToken;   ///< what folderOpened() last reported
    QString filedId;
    QStringList sawHeaders;
    QStringList sawVanished;
    int folderChangedCount = 0;
    bool pushAvailable = false;
    QStringList folderPaths;
    const QString stamp = QString::number(QDateTime::currentSecsSinceEpoch());

    QObject::connect(&backend, &MailBackend::errorOccurred, &loop,
                     [&](MailBackend::Error error, const QString &message) {
                         out() << "    (errorOccurred " << static_cast<int>(error) << ": "
                               << message << ")" << Qt::endl;
                     });
    QObject::connect(&backend, &MailBackend::headersFetched, &loop,
                     [&](const QString &, const QList<MailBackend::HeaderInfo> &headers) {
                         for (const MailBackend::HeaderInfo &header : headers)
                             sawHeaders.append(header.remoteId);
                     });
    QObject::connect(&backend, &MailBackend::messagesVanished, &loop,
                     [&](const QString &, const QStringList &ids) { sawVanished += ids; });
    QObject::connect(&backend, &MailBackend::folderInvalidated, &loop,
                     [&](const QString &folder) {
                         check(false, QStringLiteral("folderInvalidated fired for ") + folder
                                          + QStringLiteral(" — a delta should never "
                                                           "discard a healthy cache"));
                     });
    QObject::connect(&backend, &MailBackend::folderChanged, &loop,
                     [&](const QString &folder) {
                         ++folderChangedCount;
                         out() << "      folderChanged(" << folder << ")" << Qt::endl;
                     });

    using Done = std::function<void(bool, const QString &)>;
    struct Step {
        QString name;
        std::function<void(Done)> run;
    };
    // listFolders() answers with a signal too, and the tree is what this step
    // is judged on, so the paths are handed to the continuation.
    const auto listAndWait = [&loop](JmapBackend &which,
                                     const std::function<void(const QStringList &)> &then) {
        auto *connection = new QMetaObject::Connection;
        *connection = QObject::connect(
            &which, &MailBackend::foldersListed, &loop,
            [then, connection](const QList<MailBackend::FolderInfo> &folders, QChar) {
                QObject::disconnect(*connection);
                delete connection;
                QStringList paths;
                for (const MailBackend::FolderInfo &info : folders)
                    paths.append(info.path);
                then(paths);
            });
        which.listFolders();
    };

    // openFolder() answers with a signal rather than a callback, so a step that
    // opens waits for folderOpened() and takes the token off it.
    const auto openWith = [&](const QString &syncToken, Done done) {
        auto *connection = new QMetaObject::Connection;
        *connection = QObject::connect(&backend, &MailBackend::folderOpened, &loop,
                                       [&, done, connection](const QString &, qint64,
                                                             const QString &reported) {
                                           QObject::disconnect(*connection);
                                           delete connection;
                                           openToken = reported;
                                           done(!reported.isEmpty(),
                                                QStringLiteral("the server reported no state"));
                                       });
        backend.openFolder(inbox, syncToken);
    };

    QList<Step> steps;
    steps.append({QStringLiteral("open the inbox with no stored position"),
                  [&](Done done) { openWith(QString(), done); }});
    steps.append({QStringLiteral("re-open handing the position back"), [&](Done done) {
                      // What a second session does: the token it stored last
                      // time is where Email/changes resumes from.
                      openWith(openToken, done);
                  }});
    steps.append({QStringLiteral("file a message while the position is held"), [&](Done done) {
                      const QByteArray raw =
                          "From: delta <delta@example.invalid>\r\n"
                          "To: cassandane <cassandane@example.invalid>\r\n"
                          "Subject: delta sync probe\r\n"
                          "Date: Wed, 05 Aug 2026 11:00:00 +0000\r\n"
                          "Message-ID: <delta-probe@example.invalid>\r\n"
                          "\r\nProbe.\r\n";
                      backend.storeMessage(inbox, raw, {},
                                           [&, done](MailBackend::Error error,
                                                     const QString &remoteId,
                                                     const QString &message) {
                                               filedId = remoteId;
                                               done(error == MailBackend::Error::None
                                                        && !remoteId.isEmpty(),
                                                    message);
                                           });
                  }});
    steps.append({QStringLiteral("Email/changes reports it as new"), [&](Done done) {
                      sawHeaders.clear();
                      backend.fetchHeadersSince(inbox, QString(),
                                                [&, done](MailBackend::Error error,
                                                          const QString &message) {
                          if (error != MailBackend::Error::None) {
                              done(false, message);
                              return;
                          }
                          out() << "      delta returned " << sawHeaders.size()
                                << " header(s)" << Qt::endl;
                          if (!sawHeaders.contains(filedId)) {
                              done(false, QStringLiteral("the filed message was not in the "
                                                         "delta"));
                              return;
                          }
                          // The point of a delta: what changed, not the folder.
                          // A whole-page fetch would also "contain" it, and
                          // would mean Email/changes was never used.
                          done(sawHeaders.size() == 1,
                               QStringLiteral("the delta returned %1 headers, not just the "
                                              "one that changed")
                                   .arg(sawHeaders.size()));
                      });
                  }});
    steps.append({QStringLiteral("delete it"), [&](Done done) {
                      backend.deleteMessages(inbox, {filedId},
                                             [done](MailBackend::Error error,
                                                    const QString &message) {
                                                 done(error == MailBackend::Error::None,
                                                      message);
                                             });
                  }});
    steps.append({QStringLiteral("Email/changes reports it as gone"), [&](Done done) {
                      sawVanished.clear();
                      backend.fetchHeadersSince(inbox, QString(),
                                                [&, done](MailBackend::Error error,
                                                          const QString &message) {
                          if (error != MailBackend::Error::None) {
                              done(false, message);
                              return;
                          }
                          done(sawVanished.contains(filedId),
                               QStringLiteral("the deleted message was not reported as "
                                              "vanished (got %1)")
                                   .arg(sawVanished.join(QLatin1Char(','))));
                      });
                  }});
    // --- Mailbox/changes ---------------------------------------------------
    // The delta only runs on a backend that has already listed once, so the
    // decisive test needs a *second* client to make the change: anything this
    // one did itself it would also have recorded locally, and a stale full
    // listing would pass.
    const QString deltaFolder = QStringLiteral("mailove-delta-") + stamp;
    steps.append({QStringLiteral("list the mailbox tree once"), [&](Done done) {
                      listAndWait(backend, [&, done](const QStringList &paths) {
                          folderPaths = paths;
                          done(!paths.isEmpty(), QStringLiteral("no folders came back"));
                      });
                  }});
    steps.append({QStringLiteral("another client creates a mailbox"), [&](Done done) {
                      auto *other = new JmapBackend(&loop);
                      QObject::connect(other, &MailBackend::connectedChanged, &loop,
                                       [other, deltaFolder, done](bool up) {
                          if (!up)
                              return;
                          other->createFolder(deltaFolder,
                                              [other, done](MailBackend::Error error,
                                                            const QString &message) {
                              other->disconnectAccount();
                              other->deleteLater();
                              done(error == MailBackend::Error::None, message);
                          });
                      });
                      other->connectAccount(credentials);
                  }});
    steps.append({QStringLiteral("Mailbox/changes picks it up"), [&](Done done) {
                      listAndWait(backend, [&, done](const QStringList &paths) {
                          out() << "      tree went from " << folderPaths.size() << " to "
                                << paths.size() << " folder(s)" << Qt::endl;
                          if (!paths.contains(deltaFolder)) {
                              done(false, QStringLiteral("the new mailbox is missing — the "
                                                         "delta did not merge it"));
                              return;
                          }
                          // The whole tree, not just the change: a delta is an
                          // optimisation of how the listing was learned, never
                          // a different answer.
                          done(paths.size() == folderPaths.size() + 1,
                               QStringLiteral("the listing has %1 folders, expected %2")
                                   .arg(paths.size())
                                   .arg(folderPaths.size() + 1));
                      });
                  }});
    steps.append({QStringLiteral("and the delta-learned mailbox is usable"), [&](Done done) {
                      // Proof the merge produced a real id and not just a path:
                      // deleting it needs the id the delta carried.
                      backend.deleteFolder(deltaFolder, [done](MailBackend::Error error,
                                                               const QString &message) {
                          done(error == MailBackend::Error::None, message);
                      });
                  }});

    steps.append({QStringLiteral("the EventSource stream opens"), [&](Done done) {
                      backend.startPush(inbox);
                      // A server may simply not offer one — the Cyrus in the
                      // test container answers 204 because its httpd was built
                      // without push — and the backend's contract is that this
                      // costs the caller a poll timer, not a feature. So a
                      // stream that never opens is recorded as the server's
                      // limitation and the push steps stand down.
                      // pushActive() turns true when the server answers 200,
                      // which is a round trip away, not a signal.
                      auto *timer = new QTimer(&loop);
                      auto *waited = new int(0);
                      timer->setInterval(200);
                      QObject::connect(timer, &QTimer::timeout, &loop,
                                       [&backend, &pushAvailable, timer, waited, done] {
                                           const bool up = backend.pushActive();
                                           if (!up && (*waited += 200) < 15000)
                                               return;
                                           timer->stop();
                                           timer->deleteLater();
                                           delete waited;
                                           pushAvailable = up;
                                           if (!up) {
                                               skip(QStringLiteral("EventSource push"),
                                                    QStringLiteral("this server does not "
                                                                   "offer a stream"));
                                           }
                                           done(true, QString());
                                       });
                      timer->start();
                  }});
    steps.append({QStringLiteral("a change is pushed without being asked for"), [&](Done done) {
                      if (!pushAvailable) {
                          done(true, QString());
                          return;
                      }
                      folderChangedCount = 0;
                      // Something the server will certainly report: a new
                      // message in the account the stream covers.
                      const QByteArray raw =
                          "From: push <push@example.invalid>\r\n"
                          "To: cassandane <cassandane@example.invalid>\r\n"
                          "Subject: push probe\r\n"
                          "Date: Wed, 05 Aug 2026 11:05:00 +0000\r\n"
                          "Message-ID: <push-probe@example.invalid>\r\n"
                          "\r\nProbe.\r\n";
                      backend.storeMessage(inbox, raw, {},
                                           [&, done](MailBackend::Error error,
                                                     const QString &remoteId,
                                                     const QString &message) {
                          if (error != MailBackend::Error::None) {
                              done(false, message);
                              return;
                          }
                          filedId = remoteId;
                          auto *timer = new QTimer(&loop);
                          auto *waited = new int(0);
                          timer->setInterval(200);
                          QObject::connect(timer, &QTimer::timeout, &loop,
                                           [&folderChangedCount, timer, waited, done] {
                                               if (folderChangedCount > 0) {
                                                   timer->stop();
                                                   timer->deleteLater();
                                                   delete waited;
                                                   done(true, QString());
                                                   return;
                                               }
                                               if ((*waited += 200) >= 20000) {
                                                   timer->stop();
                                                   timer->deleteLater();
                                                   delete waited;
                                                   done(false,
                                                        QStringLiteral("no folderChanged in "
                                                                       "20s"));
                                               }
                                           });
                          timer->start();
                      });
                  }});
    steps.append({QStringLiteral("tidy the probe away"), [&](Done done) {
                      backend.stopPush();
                      check(!backend.pushActive(),
                            QStringLiteral("stopPush() leaves push inactive"));
                      if (!pushAvailable) {
                          done(true, QString());
                          return;
                      }
                      backend.deleteMessages(inbox, {filedId},
                                             [done](MailBackend::Error error,
                                                    const QString &message) {
                                                 done(error == MailBackend::Error::None,
                                                      message);
                                             });
                  }});

    int index = 0;
    std::function<void()> next;
    next = [&] {
        if (index >= steps.size()) {
            result = failures ? 1 : 0;
            loop.quit();
            return;
        }
        const Step step = steps.at(index++);
        step.run([&, name = step.name](bool ok, const QString &error) {
            check(ok, ok ? name : name + QStringLiteral(" — ") + error);
            if (!ok) {
                loop.quit();
                return;
            }
            next();
        });
    };

    // One-shot, and that matters: the steps below list again, and a standing
    // connection here would advance the runner a second time — the steps would
    // then interleave, each judging what the one after it had done.
    auto *bootstrap = new QMetaObject::Connection;
    *bootstrap = QObject::connect(
        &backend, &MailBackend::foldersListed, &loop,
        [&, bootstrap](const QList<MailBackend::FolderInfo> &folders, QChar) {
            QObject::disconnect(*bootstrap);
            delete bootstrap;
            for (const MailBackend::FolderInfo &info : folders) {
                if (info.role == MailBackend::FolderRole::Inbox)
                    inbox = info.path;
            }
            if (inbox.isEmpty() && !folders.isEmpty())
                inbox = folders.first().path;
            next();
        });
    QObject::connect(&backend, &MailBackend::connectedChanged, &loop, [&](bool connected) {
        if (connected)
            backend.listFolders();
    });

    backend.connectAccount(credentials);
    loop.exec();
    return result;
}

/**
 * The push path end to end, against `tests/data/jmap-push-stub.py`.
 *
 * Separate from --live-sync because the one server that can exercise this is
 * not the one that can exercise everything else: the Cyrus container answers
 * 204 to /jmap/eventsource, its httpd having been built without push. The stub
 * serves a session object and a stream and nothing more, which is all the push
 * path touches — and it sends the events split across reads, so what is being
 * checked is the plumbing the offline framing tests cannot reach.
 */
static int runLivePush(const QString &host)
{
    MailBackend::Credentials credentials;
    credentials.host = host;
    credentials.accessToken = QStringLiteral("stub-token");

    JmapBackend backend;
    QEventLoop loop;
    QStringList changed;

    QObject::connect(&backend, &MailBackend::errorOccurred, &loop,
                     [&](MailBackend::Error error, const QString &message) {
                         out() << "    (errorOccurred " << static_cast<int>(error) << ": "
                               << message << ")" << Qt::endl;
                     });
    QObject::connect(&backend, &MailBackend::folderChanged, &loop,
                     [&](const QString &folder) { changed.append(folder); });
    QObject::connect(&backend, &MailBackend::connectedChanged, &loop, [&](bool connected) {
        if (connected)
            backend.startPush(QStringLiteral("INBOX"));
    });

    // The stub sends its decisive event about a second in, having first sent a
    // comment, a ping and another account's change — none of which may fire.
    QTimer::singleShot(6000, &loop, [&loop] { loop.quit(); });
    backend.connectAccount(credentials);
    loop.exec();

    check(backend.pushActive(),
          QStringLiteral("the stream is established once the server answers 200"));
    check(changed.size() == 1,
          QStringLiteral("exactly one folderChanged — the comment, the ping and the "
                         "other account's change all stayed quiet (got %1)")
              .arg(changed.size()));
    check(changed.value(0) == QStringLiteral("INBOX"),
          QStringLiteral("it names the folder push was started on"));

    backend.stopPush();
    check(!backend.pushActive(), QStringLiteral("stopPush() closes the stream"));

    if (failures) {
        out() << failures << " check(s) failed" << Qt::endl;
        return 1;
    }
    out() << "all checks passed" << Qt::endl;
    return 0;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const QStringList args = app.arguments();
    if (args.size() > 2 && args.at(1) == QLatin1String("--live")) {
        const QString scheme = args.value(3);
        return runLive(args.at(2),
                       scheme == QLatin1String("--bearer") ? args.value(4) : QString());
    }
    if (args.size() > 2 && args.at(1) == QLatin1String("--live-push"))
        return runLivePush(args.at(2));
    if (args.size() > 2 && args.at(1) == QLatin1String("--live-sync")) {
        const QString scheme = args.value(3);
        return runLiveSync(args.at(2),
                           scheme == QLatin1String("--bearer") ? args.value(4) : QString());
    }
    if (args.size() > 2 && args.at(1) == QLatin1String("--live-write")) {
        const QString scheme = args.value(3);
        const int send = args.indexOf(QLatin1String("--send"));
        return runLiveWrite(args.at(2),
                            scheme == QLatin1String("--bearer") ? args.value(4) : QString(),
                            send > 0 ? args.value(send + 1) : QString(),
                            send > 0 ? args.value(send + 2) : QString());
    }

    out() << "the header block rebuilt from Email/get" << Qt::endl;
    {
        const QByteArray recorded =
            readFile(QStringLiteral(JMAP_TEST_DATA_DIR "/cyrus-jmap-headers.json"));
        const QByteArray blob =
            readFile(QStringLiteral(JMAP_TEST_DATA_DIR "/cyrus-jmap-message.eml"));

        const QJsonObject root = QJsonDocument::fromJson(recorded).object();
        const QJsonObject email = root.value(QLatin1String("methodResponses"))
                                      .toArray()
                                      .at(1)
                                      .toArray()
                                      .at(1)
                                      .toObject()
                                      .value(QLatin1String("list"))
                                      .toArray()
                                      .at(0)
                                      .toObject();
        const QJsonArray headers = email.value(QLatin1String("headers")).toArray();
        check(headers.size() > 5,
              QStringLiteral("the recording carries the message's header fields"));

        // The blob's header block is everything up to the blank line, the
        // separating CRLF included.
        const int separator = blob.indexOf("\r\n\r\n");
        check(separator > 0, QStringLiteral("the recorded blob has a header/body boundary"));
        const QByteArray original = blob.left(separator + 2);
        const QByteArray rebuilt = JmapBackend::headerBlockFromJmap(headers);

        check(rebuilt == original,
              QStringLiteral("the rebuilt header block is byte-identical to the blob's"));
        if (rebuilt != original) {
            out() << "         rebuilt  " << rebuilt.size() << " bytes" << Qt::endl
                  << "         original " << original.size() << " bytes" << Qt::endl;
            for (int i = 0; i < qMin(rebuilt.size(), original.size()); ++i) {
                if (rebuilt.at(i) != original.at(i)) {
                    out() << "         first difference at byte " << i << Qt::endl
                          << "         rebuilt:  " << rebuilt.mid(qMax(0, i - 40), 80) << Qt::endl
                          << "         original: " << original.mid(qMax(0, i - 40), 80)
                          << Qt::endl;
                    break;
                }
            }
        }

        // The properties that make the reconstruction faithful rather than a
        // summary, each of which a naive rebuild would drop.
        check(original.contains("\r\n\t"),
              QStringLiteral("the recorded message has a folded header, so folding is tested"));
        check(rebuilt.contains("\r\n\t"),
              QStringLiteral("folding inside a field is preserved"));
        check(rebuilt.contains("Received:"),
              QStringLiteral("server-added trace fields are kept, as DKIM needs"));
        check(rebuilt.indexOf("Return-Path:") < rebuilt.indexOf("From:"),
              QStringLiteral("fields stay in their original order"));
        check(rebuilt.contains("Subject: First test message\r\n"),
              QStringLiteral("the single space after a colon is neither doubled nor dropped"));
    }

    out() << "an empty and a malformed header list" << Qt::endl;
    {
        check(JmapBackend::headerBlockFromJmap({}).isEmpty(),
              QStringLiteral("no headers rebuild to nothing"));
        const QJsonArray nameless{QJsonObject{{QStringLiteral("value"), QStringLiteral(" x")}}};
        check(JmapBackend::headerBlockFromJmap(nameless).isEmpty(),
              QStringLiteral("a field with no name is skipped rather than written as ': x'"));
        const QJsonArray valueless{QJsonObject{{QStringLiteral("name"), QStringLiteral("X-Empty")}}};
        check(JmapBackend::headerBlockFromJmap(valueless) == QByteArray("X-Empty:\r\n"),
              QStringLiteral("a field with an empty value is still a field"));
    }

    out() << "keywords to flags" << Qt::endl;
    {
        check(JmapBackend::flagsFromKeywords({}).isEmpty(),
              QStringLiteral("no keywords means no flags — an unread message"));

        const QJsonObject seen{{QStringLiteral("$seen"), true}};
        check(JmapBackend::flagsFromKeywords(seen) == QStringList{QStringLiteral("seen")},
              QStringLiteral("$seen becomes seen"));

        const QJsonObject several{{QStringLiteral("$seen"), true},
                                  {QStringLiteral("$flagged"), true},
                                  {QStringLiteral("$draft"), true}};
        const QStringList flags = JmapBackend::flagsFromKeywords(several);
        check(flags.contains(QStringLiteral("seen")) && flags.contains(QStringLiteral("flagged"))
                  && flags.contains(QStringLiteral("draft")),
              QStringLiteral("all three of the shared flags are translated"));
        check(!flags.contains(QStringLiteral("deleted")),
              QStringLiteral("nothing maps to deleted: JMAP has no such keyword"));

        const QJsonObject custom{{QStringLiteral("$seen"), true},
                                 {QStringLiteral("holiday-photos"), true}};
        check(JmapBackend::flagsFromKeywords(custom).size() == 1,
              QStringLiteral("a user's own keyword is not mistaken for a flag"));

        const QJsonObject explicitlyFalse{{QStringLiteral("$seen"), false}};
        check(JmapBackend::flagsFromKeywords(explicitlyFalse).isEmpty(),
              QStringLiteral("a keyword present but false is not set"));
    }

    out() << "flags to keywords — the write direction" << Qt::endl;
    {
        check(JmapBackend::keywordForFlag(QStringLiteral("seen"))
                  == QStringLiteral("$seen"),
              QStringLiteral("seen becomes $seen"));
        check(JmapBackend::keywordForFlag(QStringLiteral("flagged"))
                  == QStringLiteral("$flagged"),
              QStringLiteral("flagged becomes $flagged"));
        check(JmapBackend::keywordForFlag(QStringLiteral("draft"))
                  == QStringLiteral("$draft"),
              QStringLiteral("draft becomes $draft"));
        check(JmapBackend::keywordForFlag(QStringLiteral("deleted")).isEmpty(),
              QStringLiteral("deleted has no keyword — deleting is Email/set destroy"));
        check(JmapBackend::keywordForFlag(QStringLiteral("$seen")).isEmpty(),
              QStringLiteral("the JMAP spelling is not itself a MailBackend flag"));

        // The round trip both directions have to agree on, since one writes
        // what the other reads back.
        const QJsonObject keywords{{QStringLiteral("$seen"), true},
                                   {QStringLiteral("$flagged"), true}};
        for (const QString &flag : JmapBackend::flagsFromKeywords(keywords)) {
            check(keywords.contains(JmapBackend::keywordForFlag(flag)),
                  QStringLiteral("%1 round-trips through both translations").arg(flag));
        }
    }

    out() << "the Email/set patch a flag change becomes" << Qt::endl;
    {
        const QJsonObject add =
            JmapBackend::keywordPatch({QStringLiteral("seen")}, {});
        check(add.value(QLatin1String("keywords/$seen")) == QJsonValue(true),
              QStringLiteral("adding a flag is a JSON-pointer key set to true"));
        check(add.size() == 1, QStringLiteral("and touches nothing else"));

        const QJsonObject remove =
            JmapBackend::keywordPatch({}, {QStringLiteral("seen")});
        check(remove.value(QLatin1String("keywords/$seen")).isNull(),
              QStringLiteral("removing a flag is null, not false — JMAP keywords are "
                             "present or absent"));

        const QJsonObject both = JmapBackend::keywordPatch(
            {QStringLiteral("seen")}, {QStringLiteral("flagged")});
        check(both.size() == 2 && both.value(QLatin1String("keywords/$seen")) == QJsonValue(true)
                  && both.value(QLatin1String("keywords/$flagged")).isNull(),
              QStringLiteral("one patch does both directions, where IMAP needs two STOREs"));

        check(JmapBackend::keywordPatch({QStringLiteral("deleted")}, {}).isEmpty(),
              QStringLiteral("a flag with no keyword produces no patch entry"));

        const QJsonObject contradictory = JmapBackend::keywordPatch(
            {QStringLiteral("seen")}, {QStringLiteral("seen")});
        check(contradictory.size() == 1
                  && contradictory.value(QLatin1String("keywords/$seen")).isNull(),
              QStringLiteral("asked to both add and remove, removal wins — as the IMAP "
                             "backend's add-then-remove ordering does"));
    }

    out() << "reading a /set response's rejections" << Qt::endl;
    {
        QString message;
        const QJsonObject clean{{QStringLiteral("updated"),
                                 QJsonObject{{QStringLiteral("M1"), QJsonValue::Null}}}};
        check(JmapBackend::setError(clean, "notUpdated", &message) == MailBackend::Error::None,
              QStringLiteral("a response that rejected nothing is not an error"));

        // The case that matters: no `error` response anywhere, so firstError()
        // is happy, and yet nothing was done.
        const QJsonObject refused{
            {QStringLiteral("updated"), QJsonObject{}},
            {QStringLiteral("notUpdated"),
             QJsonObject{{QStringLiteral("M1"),
                          QJsonObject{{QStringLiteral("type"), QStringLiteral("notFound")},
                                      {QStringLiteral("description"),
                                       QStringLiteral("no such message")}}}}}};
        check(JmapBackend::setError(refused, "notUpdated", &message)
                  == MailBackend::Error::NotFound,
              QStringLiteral("a rejection is an error even though the call succeeded"));
        check(message.contains(QStringLiteral("no such message")),
              QStringLiteral("the server's own description is what the user sees"));

        const QJsonObject typeOnly{
            {QStringLiteral("notDestroyed"),
             QJsonObject{{QStringLiteral("M1"),
                          QJsonObject{{QStringLiteral("type"), QStringLiteral("forbidden")}}}}}};
        check(JmapBackend::setError(typeOnly, "notDestroyed", &message)
                  == MailBackend::Error::Auth,
              QStringLiteral("forbidden reads as an auth problem, not a protocol one"));
        check(message == QStringLiteral("forbidden"),
              QStringLiteral("with no description, the type itself is the message"));

        const QJsonObject many{
            {QStringLiteral("notUpdated"),
             QJsonObject{{QStringLiteral("M1"),
                          QJsonObject{{QStringLiteral("type"), QStringLiteral("overQuota")}}},
                         {QStringLiteral("M2"),
                          QJsonObject{{QStringLiteral("type"), QStringLiteral("overQuota")}}}}}};
        JmapBackend::setError(many, "notUpdated", &message);
        check(message.contains(QStringLiteral("1 more")),
              QStringLiteral("several rejections say so rather than reporting one"));

        check(JmapBackend::setError(refused, "notCreated", &message)
                  == MailBackend::Error::None,
              QStringLiteral("only the rejection map asked about is read"));
    }

    out() << "framing the push stream into events" << Qt::endl;
    {
        QByteArray buffer("event: state\ndata: one\n\nevent: state\ndata: two\n\n");
        QList<QByteArray> blocks = JmapBackend::takeSseBlocks(buffer);
        check(blocks.size() == 2, QStringLiteral("two complete events come out as two"));
        check(buffer.isEmpty(), QStringLiteral("and nothing is left behind"));

        buffer = QByteArray("data: whole\n\ndata: parti");
        blocks = JmapBackend::takeSseBlocks(buffer);
        check(blocks.size() == 1 && blocks.first() == QByteArray("data: whole"),
              QStringLiteral("a complete event is taken"));
        check(buffer == QByteArray("data: parti"),
              QStringLiteral("the partial one waits for the rest of its bytes"));
        buffer += QByteArray("al\n\n");
        blocks = JmapBackend::takeSseBlocks(buffer);
        check(blocks.size() == 1 && blocks.first() == QByteArray("data: partial"),
              QStringLiteral("and is delivered once completed across two reads"));

        // The bug this function exists to prevent. A read can end between the
        // CR and the LF of one line ending; normalising the CR immediately
        // makes it a line break, and the next read's LF then completes a blank
        // line that was never sent.
        buffer = QByteArray("data: a\r");
        blocks = JmapBackend::takeSseBlocks(buffer);
        check(blocks.isEmpty(),
              QStringLiteral("a read ending on a bare CR dispatches nothing yet"));
        buffer += QByteArray("\ndata: b\r\n\r\n");
        blocks = JmapBackend::takeSseBlocks(buffer);
        check(blocks.size() == 1,
              QStringLiteral("a CRLF split across two reads is one line ending, not two"));
        check(blocks.value(0) == QByteArray("data: a\ndata: b"),
              QStringLiteral("and both lines land in the same event"));

        buffer = QByteArray("data: x\r\rdata: y\n\n");
        blocks = JmapBackend::takeSseBlocks(buffer);
        check(blocks.size() == 2,
              QStringLiteral("a bare double CR is a blank line, as SSE says it is"));

        buffer = QByteArray("data: no terminator yet");
        check(JmapBackend::takeSseBlocks(buffer).isEmpty() && !buffer.isEmpty(),
              QStringLiteral("an unterminated event is not guessed at"));
        buffer.clear();
        check(JmapBackend::takeSseBlocks(buffer).isEmpty(),
              QStringLiteral("an empty buffer yields nothing"));
    }

    out() << "the push channel's event blocks" << Qt::endl;
    {
        const auto parse = [](const char *text) {
            return JmapBackend::parseSseBlock(QByteArray(text));
        };

        const JmapBackend::PushEvent plain =
            parse("event: state\ndata: {\"x\":1}\nid: 42");
        check(plain.name == QStringLiteral("state"), QStringLiteral("the event name is read"));
        check(plain.data == QByteArray("{\"x\":1}"),
              QStringLiteral("one leading space after the colon is syntax, not content"));
        check(plain.id == QStringLiteral("42"),
              QStringLiteral("the id is read — it is what resumes a dropped stream"));

        check(parse("data:{\"x\":1}").data == QByteArray("{\"x\":1}"),
              QStringLiteral("the space is optional"));
        check(parse("data:  {\"x\":1}").data == QByteArray(" {\"x\":1}"),
              QStringLiteral("a second space belongs to the value"));

        check(parse("data: one\ndata: two").data == QByteArray("one\ntwo"),
              QStringLiteral("several data lines are one payload joined by newlines"));
        check(parse("data: one\ndata:\ndata: three").data == QByteArray("one\n\nthree"),
              QStringLiteral("an empty data line contributes an empty line, not nothing"));

        check(parse(": keepalive").data.isEmpty(),
              QStringLiteral("a comment line carries nothing — servers send them to hold "
                             "the socket open"));
        check(parse(": keepalive\ndata: real").data == QByteArray("real"),
              QStringLiteral("a comment beside real fields is skipped, not fatal"));
        check(parse("event\ndata: x").name.isEmpty(),
              QStringLiteral("a field with no colon has an empty value"));
        check(parse("unknown: x\ndata: y").data == QByteArray("y"),
              QStringLiteral("fields we do not model are ignored"));
        check(parse("").data.isEmpty() && parse("").name.isEmpty(),
              QStringLiteral("an empty block parses to an empty event"));
    }

    out() << "which state changes are this account's mail" << Qt::endl;
    {
        const auto touches = [](const char *json, const char *account) {
            return JmapBackend::stateChangeTouchesMail(QByteArray(json),
                                                       QString::fromLatin1(account));
        };

        check(touches(R"({"@type":"StateChange","changed":{"a":{"Email":"s1"}}})", "a"),
              QStringLiteral("an Email state change is news"));
        check(touches(R"({"@type":"StateChange","changed":{"a":{"Mailbox":"s1"}}})", "a"),
              QStringLiteral("a Mailbox state change is news — counts and the tree"));
        check(touches(R"({"changed":{"a":{"Email":"s1","Mailbox":"s2"}}})", "a"),
              QStringLiteral("both at once is still one piece of news"));

        check(!touches(R"({"changed":{"b":{"Email":"s1"}}})", "a"),
              QStringLiteral("another account on the same session is not ours"));
        check(!touches(R"({"changed":{"a":{"CalendarEvent":"s1"}}})", "a"),
              QStringLiteral("calendars share the channel and are not ours to react to"));
        check(!touches(R"({"changed":{}})", "a"),
              QStringLiteral("a StateChange naming nothing changes nothing"));
        check(!touches("not json at all", "a"),
              QStringLiteral("a payload that is not JSON is ignored rather than crashing"));
        check(!touches("", "a"), QStringLiteral("an empty payload is ignored"));
    }

    out() << "an alreadyExists rejection names the copy the server kept" << Qt::endl;
    {
        // The case that turns a refusal into an answer: filing or sending a
        // message the server already holds byte for byte.
        const QJsonObject args{
            {QStringLiteral("notCreated"),
             QJsonObject{{QStringLiteral("draft"),
                          QJsonObject{{QStringLiteral("type"),
                                       QStringLiteral("alreadyExists")},
                                      {QStringLiteral("existingId"),
                                       QStringLiteral("M1234")}}}}}};
        const QJsonObject rejection = JmapBackend::firstRejection(args, "notCreated");
        check(rejection.value(QLatin1String("type")).toString()
                  == QStringLiteral("alreadyExists"),
              QStringLiteral("the rejection type is readable"));
        check(rejection.value(QLatin1String("existingId")).toString()
                  == QStringLiteral("M1234"),
              QStringLiteral("and so is the id of the copy already filed"));
        check(JmapBackend::firstRejection(args, "notUpdated").isEmpty(),
              QStringLiteral("only the map asked about is read"));
        check(JmapBackend::firstRejection({}, "notCreated").isEmpty(),
              QStringLiteral("a response that rejected nothing yields nothing"));
    }

    out() << "the patch that files a sent copy" << Qt::endl;
    {
        const QJsonObject moved = JmapBackend::sentCopyPatch(QStringLiteral("drafts-id"),
                                                             QStringLiteral("sent-id"));
        check(moved.value(QLatin1String("keywords/$draft")).isNull(),
              QStringLiteral("a sent message is no longer a draft"));
        check(moved.value(QLatin1String("keywords/$seen")) == QJsonValue(true),
              QStringLiteral("and is read, having been written here"));
        check(moved.value(QLatin1String("mailboxIds/drafts-id")).isNull()
                  && moved.value(QLatin1String("mailboxIds/sent-id")) == QJsonValue(true),
              QStringLiteral("it moves out of Drafts and into Sent"));

        // No Sent mailbox, or one that is already where the message sits:
        // clearing the only mailbox an Email is in would destroy it, JMAP
        // having no other notion of where a message lives.
        const QJsonObject same = JmapBackend::sentCopyPatch(QStringLiteral("sent-id"),
                                                            QStringLiteral("sent-id"));
        check(same.size() == 2,
              QStringLiteral("held in the same mailbox it is filed in, nothing moves"));
        const QJsonObject none =
            JmapBackend::sentCopyPatch(QStringLiteral("drafts-id"), QString());
        check(none.size() == 2 && !none.contains(QLatin1String("mailboxIds/drafts-id")),
              QStringLiteral("with no Sent mailbox it stays put rather than being "
                             "evicted from the only one it has"));
    }

    out() << "mailbox roles" << Qt::endl;
    {
        check(JmapBackend::roleFromJmap(QStringLiteral("inbox"))
                  == MailBackend::FolderRole::Inbox,
              QStringLiteral("inbox"));
        check(JmapBackend::roleFromJmap(QStringLiteral("trash"))
                  == MailBackend::FolderRole::Trash,
              QStringLiteral("trash — the role that stops trashFolderName() guessing"));
        check(JmapBackend::roleFromJmap(QStringLiteral("junk"))
                  == MailBackend::FolderRole::Junk,
              QStringLiteral("junk"));
        check(JmapBackend::roleFromJmap(QStringLiteral("sent"))
                  == MailBackend::FolderRole::Sent,
              QStringLiteral("sent"));
        check(JmapBackend::roleFromJmap(QStringLiteral("drafts"))
                  == MailBackend::FolderRole::Drafts,
              QStringLiteral("drafts"));
        check(JmapBackend::roleFromJmap(QStringLiteral("archive"))
                  == MailBackend::FolderRole::Archive,
              QStringLiteral("archive"));
        check(JmapBackend::roleFromJmap(QString()) == MailBackend::FolderRole::None,
              QStringLiteral("a mailbox with no role has none"));
        check(JmapBackend::roleFromJmap(QStringLiteral("important"))
                  == MailBackend::FolderRole::None,
              QStringLiteral("a role we do not model is None, not a guess"));
        check(JmapBackend::roleFromJmap(QStringLiteral("Inbox"))
                  == MailBackend::FolderRole::None,
              QStringLiteral("roles are lower-case per RFC 8621 and not case-folded here"));
    }

    out() << "local keys for opaque ids" << Qt::endl;
    {
        const qint64 first = JmapBackend::hashedLocalKey(QStringLiteral("M9b47a140143f9a9d7d8e121e"));
        check(first > 0, QStringLiteral("a key is positive"));
        check(first == JmapBackend::hashedLocalKey(QStringLiteral("M9b47a140143f9a9d7d8e121e")),
              QStringLiteral("the same id always gives the same key"));
        check(first != JmapBackend::hashedLocalKey(QStringLiteral("M1c2578e9c323740b000b1603")),
              QStringLiteral("different ids give different keys"));
        check(JmapBackend::hashedLocalKey(QStringLiteral("M9b47a140143f9a9d7d8e121E")) != first,
              QStringLiteral("ids differing only in case are different keys"));
        check(JmapBackend::hashedLocalKey(QString()) > 0,
              QStringLiteral("even an empty id yields a usable key rather than 0"));

        // The recorded ids, so the values are pinned to something real: a
        // change in how keys are derived would orphan every cached row.
        check(JmapBackend::hashedLocalKey(QStringLiteral("M9b47a140143f9a9d7d8e121e"))
                  == Q_INT64_C(1115986195932954017),
              QStringLiteral("the key derivation has not changed under the cache"));
    }

    out() << "the path separator" << Qt::endl;
    {
        check(JmapBackend::pathSeparator() == QLatin1Char('/'),
              QStringLiteral("paths are built with a separator of this backend's choosing"));
    }

    if (failures) {
        out() << failures << " check(s) failed" << Qt::endl;
        return 1;
    }
    out() << "all checks passed" << Qt::endl;
    return 0;
}
