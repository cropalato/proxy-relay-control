#!/usr/bin/env python3
"""A stand-in for the corporate proxy, used by the end-to-end suite.

It does what the real thing does and nothing more: demand Basic credentials,
record which account opened each tunnel, and relay. Squid would work too, but
its auth helpers differ across images, and the assertion that matters here is
"which account did the relay present", which this makes trivial to read back.
"""
import base64
import http.server
import json
import os
import select
import socket
import socketserver
import threading
import urllib.parse

ACCOUNTS = json.loads(os.environ.get("ACCOUNTS", '{"svc-team-a":"pw-a","svc-team-b":"pw-b"}'))
LOG_LOCK = threading.Lock()
LOG = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _account(self):
        header = self.headers.get("Proxy-Authorization", "")
        if not header.startswith("Basic "):
            return None
        try:
            raw = base64.b64decode(header[6:]).decode()
        except Exception:
            return None
        user, _, password = raw.partition(":")
        if ACCOUNTS.get(user) == password:
            return user
        return None

    def _record(self, account, target):
        with LOG_LOCK:
            LOG.append({"account": account, "target": target})

    def _deny(self):
        body = b"proxy authentication required\n"
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="corp"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):
        account = self._account()
        self._record(account, self.path)
        if account is None:
            self._deny()
            return

        host, _, port = self.path.rpartition(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            self.send_error(502)
            return

        self.send_response(200, "Connection established")
        self.end_headers()
        self.wfile.flush()
        self._pump(upstream)

    def _pump(self, upstream):
        client = self.connection
        sockets = [client, upstream]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 60)
                if errored or not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is client else client).sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()

    def _forward(self):
        account = self._account()
        self._record(account, self.path)
        if account is None:
            self._deny()
            return

        parsed = urllib.parse.urlsplit(self.path)
        if not parsed.hostname:
            self.send_error(400)
            return
        port = parsed.port or 80
        try:
            upstream = socket.create_connection((parsed.hostname, port), timeout=10)
        except OSError:
            self.send_error(502)
            return

        target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        request = [f"{self.command} {target} HTTP/1.1"]
        for key, value in self.headers.items():
            if key.lower().startswith("proxy-"):
                continue
            request.append(f"{key}: {value}")
        request.append("Connection: close")
        upstream.sendall(("\r\n".join(request) + "\r\n\r\n").encode())

        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            upstream.sendall(self.rfile.read(length))

        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            self.connection.sendall(chunk)
        upstream.close()
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _forward


class AuditHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        with LOG_LOCK:
            body = json.dumps(LOG).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    audit = Threaded(("0.0.0.0", 3129), AuditHandler)
    threading.Thread(target=audit.serve_forever, daemon=True).start()
    Threaded(("0.0.0.0", 3128), Handler).serve_forever()
