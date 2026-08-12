#!/usr/bin/env python3
# SPDX-FileCopyrightText: (c) 2026 Daniel Duris, dusoft@staznosti.sk
# SPDX-License-Identifier: LGPL-3.0-or-later
"""
Puts the cyrus-jmap-tester container behind a plain username/password, so a
JMAP account can be added in the GUI and driven by hand.

Two things stop the account sheet talking to that container directly, and this
fixes both:

  * The sheet sends Basic auth for a password JMAP account, and the container's
    Cyrus rejects it — saslauthd is not running, so the JWT is the only way in.
  * `http_jwt_max_age: 1800s` expires a token after thirty minutes, which is
    shorter than any session worth testing.

So this forwards everything to Cyrus with a **freshly minted JWT on every
request**, discarding whatever credential the client sent. That is only
acceptable because it is a throwaway test server on loopback: it authenticates
nobody and will hand the mailbox to anything that connects.

    python3 tests/data/jmap-dev-proxy.py            # 18082 -> 127.0.0.1:18080
    python3 tests/data/jmap-dev-proxy.py 18082 127.0.0.1:18080 cassandane

Then add a JMAP account whose server is http://127.0.0.1:18082 — any username
and password will do, since neither is checked.
"""

import base64
import hashlib
import hmac
import http.client
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18082
UPSTREAM = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1:18080"
USER = sys.argv[3] if len(sys.argv) > 3 else "cassandane"
# entrypoint.sh writes the key as `echo $JWT_SECRET | base64`, so the HMAC key
# carries the newline echo added. Signing with the bare secret fails.
SECRET = (sys.argv[4] if len(sys.argv) > 4 else "mailove-test-secret").encode() + b"\n"

# Streamed rather than buffered: an EventSource reply never ends, so anything
# that waits for a complete body would hang push instead of proxying it.
STREAMING_TYPES = ("text/event-stream",)


def mint_token():
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    # `iat` is mandatory — http_jwt_max_age makes a token without one
    # authenticate as nobody, and the log says only "Authentication failed".
    payload = b64(json.dumps({"sub": USER, "iat": int(time.time())},
                             separators=(",", ":")).encode())
    signed = header + b"." + payload
    return (signed + b"." + b64(hmac.new(SECRET, signed, hashlib.sha256).digest())).decode()


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("proxy: " + (fmt % args) + "\n")

    def do_GET(self):
        self.forward("GET")

    def do_POST(self):
        self.forward("POST")

    def do_PUT(self):
        self.forward("PUT")

    def forward(self, method):
        body = None
        length = self.headers.get("Content-Length")
        if length:
            body = self.rfile.read(int(length))

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("authorization", "host", "connection",
                                        "accept-encoding")}
        headers["Authorization"] = "Bearer " + mint_token()
        headers["Host"] = UPSTREAM
        # Cyrus answers br-compressed when asked; nothing here needs to read the
        # body, but a client that did not ask for br must not receive it.
        headers["Accept-Encoding"] = "identity"

        upstream = http.client.HTTPConnection(UPSTREAM, timeout=300)
        try:
            upstream.request(method, self.path, body=body, headers=headers)
            reply = upstream.getresponse()
        except Exception as exc:                                  # noqa: BLE001
            self.log_message("upstream failed: %s", exc)
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # A redirect to the upstream's own address would send the client
        # straight past this proxy, and its next request would be unauthorised.
        location = reply.getheader("Location")
        content_type = reply.getheader("Content-Type", "")
        streaming = any(t in content_type for t in STREAMING_TYPES)

        self.send_response(reply.status)
        for key, value in reply.getheaders():
            low = key.lower()
            if low in ("transfer-encoding", "connection", "content-length",
                       "upgrade", "alt-svc", "location"):
                continue
            self.send_header(key, value)
        if location:
            self.send_header("Location", location.replace(UPSTREAM, "127.0.0.1:%d" % PORT))
        if streaming:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.pump_chunked(reply)
            return

        payload = reply.read()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def pump_chunked(self, reply):
        """Relay an endless reply as it arrives, so push stays push."""
        try:
            while True:
                chunk = reply.read(1)
                if not chunk:
                    break
                chunk += reply.read(len(reply.fp.peek() or b"")) if hasattr(reply, "fp") else b""
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Proxy)
    server.daemon_threads = True
    sys.stderr.write("proxy: 127.0.0.1:%d -> %s as %s\n" % (PORT, UPSTREAM, USER))
    server.serve_forever()
