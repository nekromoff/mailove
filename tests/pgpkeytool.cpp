// SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
// SPDX-License-Identifier: LGPL-3.0-or-later

/// Diagnostic, not a pass/fail test: drives PgpEngine against a real keyring
/// and prints what it sees. There is nothing to assert against — the answer
/// depends on the keys the machine holds — so this exists to check that the
/// engine talks to gpg correctly at all, without launching the GUI.
///
/// Point GNUPGHOME at a throwaway directory before running it against
/// anything but your own keyring.
///
///   ./pgpkeytool                          list every key
///   ./pgpkeytool --for me@example.com     secret keys usable as that identity
///   ./pgpkeytool --export FPR out.asc     write a public key
///   ./pgpkeytool --import file.asc        import a key block
///   ./pgpkeytool --delete FPR             delete a public key (own keys refused)
///   ./pgpkeytool --trust FPR LEVEL        set owner trust (0,2,3,4,5; 0 = remove)
///   ./pgpkeytool --wkd you@example.com    Web Key Directory lookup (network)
///   ./pgpkeytool --keyserver you@ex.com   keys.openpgp.org lookup (network)
///   ./pgpkeytool --decrypt msg.eml        classify and decrypt a message file
///   ./pgpkeytool --verify msg.eml         check a multipart/signed message
///   ./pgpkeytool --roundtrip FPR          sign+encrypt a message, then read it back
///   ./pgpkeytool --readback FPR           sign+encrypt, then decrypt AND verify it

#include "pgpengine.h"
#include "pgpmime.h"

#include <KMime/Message>

#include <QCoreApplication>
#include <QFile>
#include <QTextStream>
#include <QTimer>

#include <cstdio>
#include <memory>

namespace
{
QTextStream out(stdout);

void printKey(const PgpKey &k)
{
    out << (k.secret ? QStringLiteral("sec ") : QStringLiteral("pub "))
        << k.fingerprint << '\n'
        << "    " << k.uid << '\n'
        << "    " << k.algorithm << ", created "
        << (k.created.isValid() ? k.created.date().toString(Qt::ISODate)
                                : QStringLiteral("?"))
        << ", "
        << (k.expires.isValid() ? QStringLiteral("expires ")
                                      + k.expires.date().toString(Qt::ISODate)
                                : QStringLiteral("never expires"))
        << (k.isBad() ? QStringLiteral(" [UNUSABLE]") : QString()) << '\n'
        << "    validity " << k.validity << ", sign " << (k.canSign ? "yes" : "no")
        << ", encrypt " << (k.canEncrypt ? "yes" : "no") << '\n'
        << "    addresses: " << k.addresses.join(QStringLiteral(", ")) << '\n';
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments();

    PgpEngine engine;
    out << "backend: " << (engine.available() ? QStringLiteral("available")
                                              : engine.unavailableReason())
        << '\n';
    out.flush();
    if (!engine.available())
        return 1;

    QObject::connect(&engine, &PgpEngine::errorOccurred, [](const QString &t) {
        out << "error: " << t << '\n';
        out.flush();
    });
    QObject::connect(&engine, &PgpEngine::statusMessage, [](const QString &t) {
        out << t << '\n';
        out.flush();
    });
    QObject::connect(&engine, &PgpEngine::importFinished,
                     [](int imported, int unchanged, const QString &error) {
                         out << "import: " << imported << " new, " << unchanged
                             << " unchanged"
                             << (error.isEmpty() ? QString()
                                                 : QStringLiteral(", error: ") + error)
                             << '\n';
                         out.flush();
                     });
    QObject::connect(&engine, &PgpEngine::secretKeyImported, [](const QString &fp) {
        out << "private key imported: " << fp << '\n';
        out.flush();
    });
    QObject::connect(&engine, &PgpEngine::exportFinished,
                     [](const QString &file, const QString &error) {
                         out << "export: " << file
                             << (error.isEmpty() ? QStringLiteral(" ok")
                                                 : QStringLiteral(" failed: ") + error)
                             << '\n';
                         out.flush();
                     });
    QObject::connect(&engine, &PgpEngine::lookupFinished,
                     [](const QString &address, bool found, const QString &source) {
                         out << "lookup " << address << " via " << source << ": "
                             << (found ? "key found" : "nothing published") << '\n';
                         out.flush();
                     });

    // The engine lists the keyring on construction; everything here waits for
    // that first snapshot rather than racing it.
    QObject::connect(&engine, &PgpEngine::keysChanged, [&] {
        static bool done = false;
        if (done)
            return;
        done = true;

        const int forIdx = args.indexOf(QStringLiteral("--for"));
        const int expIdx = args.indexOf(QStringLiteral("--export"));
        const int impIdx = args.indexOf(QStringLiteral("--import"));
        const int wkdIdx = args.indexOf(QStringLiteral("--wkd"));
        const int ksIdx = args.indexOf(QStringLiteral("--keyserver"));

        if (forIdx > 0 && forIdx + 1 < args.size()) {
            const QVariantList keys = engine.secretKeysFor(args.at(forIdx + 1));
            out << keys.size() << " secret key(s) for " << args.at(forIdx + 1) << '\n';
            for (const QVariant &v : keys) {
                const QVariantMap m = v.toMap();
                out << "  " << m.value(QStringLiteral("fingerprint")).toString() << "  "
                    << m.value(QStringLiteral("uid")).toString() << '\n';
            }
            QTimer::singleShot(0, qApp, &QCoreApplication::quit);
            return;
        }
        if (expIdx > 0 && expIdx + 2 < args.size()) {
            engine.exportPublicKey(args.at(expIdx + 1),
                                   QUrl::fromLocalFile(args.at(expIdx + 2)));
            QObject::connect(&engine, &PgpEngine::exportFinished, qApp,
                             &QCoreApplication::quit);
            return;
        }
        if (impIdx > 0 && impIdx + 1 < args.size()) {
            engine.importKeyFile(QUrl::fromLocalFile(args.at(impIdx + 1)));
            QObject::connect(&engine, &PgpEngine::importFinished, qApp,
                             &QCoreApplication::quit);
            return;
        }
        const int verIdx = args.indexOf(QStringLiteral("--verify"));
        if (verIdx > 0 && verIdx + 1 < args.size()) {
            QFile f(args.at(verIdx + 1));
            if (!f.open(QIODevice::ReadOnly)) {
                out << "cannot open " << args.at(verIdx + 1) << '\n';
                QCoreApplication::exit(2);
                return;
            }
            static QByteArray raw = f.readAll();
            static auto msg = std::make_shared<KMime::Message>();
            msg->setContent(KMime::CRLFtoLF(raw));
            msg->parse();
            const PgpMime::Structure s = PgpMime::classify(msg.get());
            if (s.kind != PgpMime::Kind::Signed) {
                out << "not a multipart/signed message\n";
                out.flush();
                QCoreApplication::exit(1);
                return;
            }
            QObject::connect(&engine, &PgpEngine::verifyFinished,
                             [](quint64, const PgpSignatureInfo &sig) {
                                 static const char *names[] = {
                                     "None",       "Valid",   "NotVerified", "UnknownKey",
                                     "Expired",    "Revoked", "Error"};
                                 out << "signature: " << names[int(sig.status)] << '\n'
                                     << "  signer: "
                                     << (sig.signerEmail.isEmpty() ? QStringLiteral("(unknown)")
                                                                   : sig.signerEmail)
                                     << "  fpr: " << sig.fingerprint << '\n'
                                     << "  detail: " << sig.detail << '\n';
                                 out.flush();
                                 QCoreApplication::exit(sig.status == PgpSignatureInfo::Valid
                                                            ? 0
                                                            : 1);
                             });
            // The production path: octets sliced out of the message's own
            // bytes, not rebuilt from the parsed tree.
            bool exact = false;
            const QByteArray octets = PgpMime::signedOctets(raw, s, &exact);
            out << "signed octets: " << (exact ? "sliced from the raw message"
                                               : "rebuilt from the parsed tree")
                << '\n';
            if (engine.verifyDetached(octets, PgpMime::signature(s)) == 0) {
                out << "could not start verification\n";
                QCoreApplication::exit(1);
            }
            return;
        }

        // The §6 send path end to end, without SMTP: build a message, sign it,
        // encrypt the result, then put the bytes back through the *reading*
        // path. If the octets survive, a real recipient's client will verify
        // what we sent — which is the one thing unit vectors cannot prove.
        const int rtIdx = args.indexOf(QStringLiteral("--roundtrip"));
        if (rtIdx > 0 && rtIdx + 1 < args.size()) {
            static const QString fpr = args.at(rtIdx + 1);
            static const QByteArray assembled =
                "From: test@example.com\r\n"
                "To: test@example.com\r\n"
                "Subject: round trip\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: text/plain; charset=\"utf-8\"\r\n"
                "\r\n"
                "The body that gets signed and encrypted.\r\n";
            static const PgpMime::OutgoingParts parts = PgpMime::splitForCrypto(assembled);
            static quint64 signJob = 0;
            static quint64 encJob = 0;

            QObject::connect(&engine, &PgpEngine::signFinished,
                             [&engine](quint64 id, const QByteArray &sig,
                                       const QString &micalg, const QString &error) {
                                 if (id != signJob)
                                     return;
                                 if (!error.isEmpty()) {
                                     out << "sign failed: " << error << '\n';
                                     out.flush();
                                     QCoreApplication::exit(1);
                                     return;
                                 }
                                 out << "signed, micalg=" << micalg << '\n';
                                 static QByteArray signedMsg =
                                     PgpMime::buildSigned(parts, sig, micalg);
                                 // Read it back the way a recipient would.
                                 KMime::Message check;
                                 check.setContent(KMime::CRLFtoLF(signedMsg));
                                 check.parse();
                                 const PgpMime::Structure s = PgpMime::classify(&check);
                                 bool exact = false;
                                 const QByteArray octets =
                                     PgpMime::signedOctets(signedMsg, s, &exact);
                                 out << "  reparsed as "
                                     << (s.kind == PgpMime::Kind::Signed ? "Signed" : "NOT SIGNED")
                                     << ", octets " << (exact ? "exact" : "rebuilt")
                                     << ", identical to what was signed: "
                                     << (octets == parts.contentPart ? "yes" : "NO") << '\n';
                                 // Kept so the signature can be checked with a
                                 // separate --verify run, which is the only
                                 // proof that a recipient's client would accept
                                 // what we built.
                                 if (qEnvironmentVariableIsSet("MAILOVE_ROUNDTRIP_OUT")) {
                                     QFile f(qEnvironmentVariable("MAILOVE_ROUNDTRIP_OUT"));
                                     if (f.open(QIODevice::WriteOnly))
                                         f.write(signedMsg);
                                 }
                                 out.flush();
                                 // Now encrypt the signed message, as "both" does.
                                 const PgpMime::OutgoingParts sp =
                                     PgpMime::splitForCrypto(signedMsg);
                                 encJob = engine.encryptTo(sp.contentPart, {fpr});
                                 static PgpMime::OutgoingParts spKeep = sp;
                                 QObject::connect(
                                     &engine, &PgpEngine::encryptFinished,
                                     [](quint64 id, const QByteArray &cipher,
                                        const QString &error) {
                                         if (id != encJob)
                                             return;
                                         if (!error.isEmpty()) {
                                             out << "encrypt failed: " << error << '\n';
                                             out.flush();
                                             QCoreApplication::exit(1);
                                             return;
                                         }
                                         const QByteArray enc =
                                             PgpMime::buildEncrypted(spKeep, cipher);
                                         KMime::Message m;
                                         m.setContent(KMime::CRLFtoLF(enc));
                                         m.parse();
                                         const PgpMime::Structure es = PgpMime::classify(&m);
                                         out << "encrypted, reparsed as "
                                             << (es.kind == PgpMime::Kind::Encrypted
                                                     ? "Encrypted"
                                                     : "NOT ENCRYPTED")
                                             << ", subject visible: "
                                             << (enc.contains("Subject: round trip") ? "yes"
                                                                                     : "no")
                                             << '\n';
                                         out.flush();
                                         QCoreApplication::quit();
                                     });
                             });
            signJob = engine.signDetached(parts.contentPart, fpr);
            if (signJob == 0) {
                out << "could not start signing\n";
                QCoreApplication::exit(1);
            }
            return;
        }

        // The full receiving path for a signed-and-encrypted message: build
        // one, then decrypt it and check the signature the way presentMessage()
        // does — against the plaintext octets, not a re-serialisation of them.
        // Thunderbird reports such messages as "Good Digital Signature"; so
        // must we.
        const int rbIdx = args.indexOf(QStringLiteral("--readback"));
        if (rbIdx > 0 && rbIdx + 1 < args.size()) {
            static const QString fpr2 = args.at(rbIdx + 1);
            static const QByteArray src =
                "From: test@example.com\r\n"
                "To: test@example.com\r\n"
                "Subject: signed then encrypted\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: text/plain; charset=\"utf-8\"\r\n"
                "\r\n"
                "Signed, then encrypted.\r\n";
            static const PgpMime::OutgoingParts p0 = PgpMime::splitForCrypto(src);
            static quint64 sJob = 0, eJob = 0, dJob = 0;
            static QByteArray signedMsg, encMsg;

            QObject::connect(&engine, &PgpEngine::signFinished,
                             [&engine](quint64 id, const QByteArray &sig,
                                       const QString &micalg, const QString &err) {
                                 if (id != sJob)
                                     return;
                                 if (!err.isEmpty()) {
                                     out << "sign failed: " << err << '\n';
                                     QCoreApplication::exit(1);
                                     return;
                                 }
                                 signedMsg = PgpMime::buildSigned(p0, sig, micalg);
                                 const PgpMime::OutgoingParts sp =
                                     PgpMime::splitForCrypto(signedMsg);
                                 eJob = engine.encryptTo(sp.contentPart, {fpr2});
                             });
            QObject::connect(&engine, &PgpEngine::encryptFinished,
                             [&engine](quint64 id, const QByteArray &cipher,
                                       const QString &err) {
                                 if (id != eJob)
                                     return;
                                 if (!err.isEmpty()) {
                                     out << "encrypt failed: " << err << '\n';
                                     QCoreApplication::exit(1);
                                     return;
                                 }
                                 encMsg = PgpMime::buildEncrypted(
                                     PgpMime::splitForCrypto(signedMsg), cipher);
                                 out << "built signed-then-encrypted message, "
                                     << encMsg.size() << " bytes\n";
                                 // Now read it back.
                                 KMime::Message m;
                                 m.setContent(KMime::CRLFtoLF(encMsg));
                                 m.parse();
                                 dJob = engine.decrypt(
                                     PgpMime::ciphertext(PgpMime::classify(&m)));
                             });
            QObject::connect(&engine, &PgpEngine::decryptFinished,
                             [&engine](quint64 id, const QByteArray &plain,
                                       const QString &err, bool) {
                                 if (id != dJob)
                                     return;
                                 if (!err.isEmpty()) {
                                     out << "decrypt failed: " << err << '\n';
                                     QCoreApplication::exit(1);
                                     return;
                                 }
                                 out << "decrypted ok\n";
                                 // Exactly what startPgpVerification does: parse
                                 // the plaintext, then slice the signed octets
                                 // out of the plaintext bytes themselves.
                                 static KMime::Message inner;
                                 inner.setContent(KMime::CRLFtoLF(plain));
                                 inner.parse();
                                 const PgpMime::Structure is = PgpMime::classify(&inner);
                                 bool exact = false;
                                 const QByteArray octets =
                                     PgpMime::signedOctets(plain, is, &exact);
                                 out << "  inner is "
                                     << (is.kind == PgpMime::Kind::Signed ? "Signed"
                                                                          : "NOT SIGNED")
                                     << ", octets " << (exact ? "exact" : "rebuilt") << '\n';
                                 out.flush();
                                 engine.verifyDetached(octets, PgpMime::signature(is));
                             });
            QObject::connect(&engine, &PgpEngine::verifyFinished,
                             [](quint64, const PgpSignatureInfo &sig) {
                                 static const char *names[] = {"None", "Valid", "NotVerified",
                                                               "UnknownKey", "Expired",
                                                               "Revoked", "Error"};
                                 out << "  signature: " << names[int(sig.status)] << " ("
                                     << sig.signerEmail << ")\n";
                                 out.flush();
                                 QCoreApplication::exit(sig.status == PgpSignatureInfo::Valid
                                                            ? 0 : 1);
                             });
            sJob = engine.signDetached(p0.contentPart, fpr2);
            return;
        }

        const int decIdx = args.indexOf(QStringLiteral("--decrypt"));
        if (decIdx > 0 && decIdx + 1 < args.size()) {
            QFile f(args.at(decIdx + 1));
            if (!f.open(QIODevice::ReadOnly)) {
                out << "cannot open " << args.at(decIdx + 1) << '\n';
                QCoreApplication::exit(2);
                return;
            }
            // Exactly the sequence MailClient::presentMessage follows: parse,
            // classify, hand the ciphertext to the engine, parse what comes
            // back as the inner MIME tree.
            static auto msg = std::make_shared<KMime::Message>();
            msg->setContent(KMime::CRLFtoLF(f.readAll()));
            msg->parse();
            const PgpMime::Structure s = PgpMime::classify(msg.get());
            const char *kind = s.kind == PgpMime::Kind::Encrypted ? "Encrypted"
                : s.kind == PgpMime::Kind::Signed                 ? "Signed"
                : s.kind == PgpMime::Kind::InlineEncrypted        ? "InlineEncrypted"
                : s.kind == PgpMime::Kind::Partial                ? "Partial"
                                                                  : "None";
            out << "classified as " << kind << '\n';
            if (!s.isEncrypted()) {
                out << "nothing to decrypt\n";
                out.flush();
                QTimer::singleShot(0, qApp, &QCoreApplication::quit);
                return;
            }
            QObject::connect(&engine, &PgpEngine::decryptFinished,
                             [](quint64, const QByteArray &plain, const QString &error,
                                bool noSecretKey) {
                                 if (!error.isEmpty()) {
                                     out << "decrypt failed: " << error
                                         << (noSecretKey ? " (no secret key)" : "") << '\n';
                                     out.flush();
                                     QCoreApplication::exit(1);
                                     return;
                                 }
                                 KMime::Message inner;
                                 inner.setContent(KMime::CRLFtoLF(plain));
                                 inner.parse();
                                 const auto *ct = std::as_const(inner).contentType();
                                 out << "decrypted " << plain.size() << " bytes, inner type "
                                     << (ct ? QString::fromLatin1(ct->mimeType())
                                            : QStringLiteral("(none)"))
                                     << '\n';
                                 KMime::Content *text = inner.mainBodyPart("text/plain");
                                 if (text)
                                     out << "--- text/plain ---\n" << text->decodedText() << '\n';
                                 const auto atts = inner.attachments();
                                 out << atts.size() << " attachment(s) in the decrypted tree\n";
                                 out.flush();
                                 QCoreApplication::quit();
                             });
            if (engine.decrypt(PgpMime::ciphertext(s)) == 0) {
                out << "could not start decryption\n";
                QCoreApplication::exit(1);
            }
            return;
        }

        const int trustIdx = args.indexOf(QStringLiteral("--trust"));
        if (trustIdx > 0 && trustIdx + 2 < args.size()) {
            const QString fp = args.at(trustIdx + 1);
            const int level = args.at(trustIdx + 2).toInt();
            for (const PgpKey &k : engine.keys()) {
                if (k.fingerprint == fp)
                    out << "before: ownerTrust=" << k.ownerTrust
                        << " computed validity=" << k.validity << '\n';
            }
            QObject::connect(&engine, &PgpEngine::keysChanged, [&engine, fp] {
                for (const PgpKey &k : engine.keys()) {
                    if (k.fingerprint == fp)
                        out << "after:  ownerTrust=" << k.ownerTrust
                            << " computed validity=" << k.validity << '\n';
                }
                out.flush();
                QCoreApplication::quit();
            });
            QObject::connect(&engine, &PgpEngine::errorOccurred, qApp,
                             &QCoreApplication::quit);
            engine.setOwnerTrust(fp, level);
            return;
        }

        const int delIdx = args.indexOf(QStringLiteral("--delete"));
        if (delIdx > 0 && delIdx + 1 < args.size()) {
            // Refusal comes back as errorOccurred and success as keysChanged,
            // so end on either rather than waiting for one that will not come.
            // Connected first: a refusal is emitted synchronously from the call
            // below, and would be missed by a connection made after it.
            QObject::connect(&engine, &PgpEngine::errorOccurred, qApp,
                             &QCoreApplication::quit);
            QObject::connect(&engine, &PgpEngine::keysChanged, qApp,
                             &QCoreApplication::quit);
            engine.deletePublicKey(args.at(delIdx + 1));
            return;
        }
        if ((wkdIdx > 0 && wkdIdx + 1 < args.size())
            || (ksIdx > 0 && ksIdx + 1 < args.size())) {
            // A lookup that finds something goes on to import it, so waiting on
            // lookupFinished alone would exit before the interesting half. Only
            // a lookup that found nothing ends there.
            QObject::connect(&engine, &PgpEngine::lookupFinished,
                             [](const QString &, bool found, const QString &) {
                                 if (!found)
                                     QTimer::singleShot(0, qApp,
                                                        &QCoreApplication::quit);
                             });
            QObject::connect(&engine, &PgpEngine::importFinished, qApp,
                             &QCoreApplication::quit);
            if (wkdIdx > 0)
                engine.lookupWkd(args.at(wkdIdx + 1));
            else
                engine.lookupKeyserver(args.at(ksIdx + 1));
            return;
        }

        out << engine.keys().size() << " key(s) in the keyring\n\n";
        for (const PgpKey &k : engine.keys())
            printKey(k);
        out.flush();
        QTimer::singleShot(0, qApp, &QCoreApplication::quit);
    });

    // Nothing should take this long; without it a wedged dirmngr would leave
    // the tool running forever with nothing on screen.
    QTimer::singleShot(30000, qApp, [] {
        out << "timed out\n";
        out.flush();
        QCoreApplication::exit(2);
    });

    return app.exec();
}
