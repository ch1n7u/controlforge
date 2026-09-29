#!/usr/bin/env python3
"""CONTROLFORGE lab target: lab-webapp (deliberately vulnerable, stdlib only).

Deliberate weaknesses (all fake/simulated, nothing real):
  * /admin            - admin panel, no authentication
  * /.git/HEAD        - exposed git metadata
  * /.env             - exposed config with obviously fake EXAMPLE values
  * /server-status    - exposed "server status" endpoint (200)
  * /phpinfo.php      - exposed "phpinfo" endpoint (200)
  * /login            - sets a session cookie with NO Secure, NO HttpOnly,
                        NO SameSite
  * every response    - Access-Control-Allow-Origin: *
  * /error            - returns a full Python traceback (500)
  * Server: header    - leaks the Python version (BaseHTTP/x Python/3.12.x)
  * /health           - 200, only route with no deliberate weakness
"""
import json
import secrets
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST = "0.0.0.0"
PORT = 8000

# Obviously fake placeholder values - never real credentials.
FAKE_ENV = """# lab-webapp example configuration
# LAB EXAMPLE VALUES ONLY - NOT REAL SECRETS
APP_ENV=production
APP_DEBUG=true
DB_HOST=db
DB_USER=app
DB_PASSWORD=EXAMPLE-NOT-A-REAL-SECRET
DB_NAME=appdb
REDIS_URL=redis://cache:6379/0
JWT_SECRET=EXAMPLE-NOT-A-REAL-SECRET
AWS_ACCESS_KEY_ID=EXAMPLE-NOT-A-REAL-KEY
AWS_SECRET_ACCESS_KEY=EXAMPLE-NOT-A-REAL-SECRET
STRIPE_SECRET_KEY=EXAMPLE-NOT-A-REAL-KEY
"""

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>lab-webapp</title></head><body>
<h1>CONTROLFORGE lab-webapp</h1>
<p>Deliberately vulnerable application target.</p>
<ul>
  <li><a href="/admin">/admin</a></li>
  <li><a href="/login">/login</a></li>
  <li><a href="/server-status">/server-status</a></li>
  <li><a href="/phpinfo.php">/phpinfo.php</a></li>
</ul>
</body></html>
"""

ADMIN_HTML = """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head><body>
<h1>Administration Panel</h1>
<p>Welcome, administrator. No credentials were required to view this page.</p>
<table border="1">
  <tr><th>User</th><th>Role</th></tr>
  <tr><td>admin</td><td>superuser</td></tr>
  <tr><td>operator</td><td>user</td></tr>
</table>
</body></html>
"""

SERVER_STATUS = """Apache Server Status for lab-webapp (simulated)
Server Version: Apache/2.4.58 (lab simulation)
Current Time: lab clock
Restart Time: lab boot
Total accesses: 1337 - Total Traffic: 4.2 MB
CPU Usage: u0.1 s0.2
0 requests currently being processed, 5 idle workers
"""

PHPINFO_HTML = """<!DOCTYPE html>
<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 8.2.0 (lab simulation)</h1>
<table>
<tr><td>System</td><td>Linux lab-webapp (simulated)</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI (simulated)</td></tr>
<tr><td>display_errors</td><td>On</td></tr>
</table>
</body></html>
"""

LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Login</title></head><body>
<h1>Sign in</h1>
<form method="post" action="/login">
  <label>Username <input name="username" type="text"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Log in</button>
</form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    # NOTE: server_version / sys_version intentionally left at the stdlib
    # defaults so the banner leaks the Python version, e.g.
    #   Server: BaseHTTP/0.6 Python/3.12.14
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type="text/html; charset=utf-8",
              extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Deliberate weakness: wildcard CORS on every response.
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- routes -----------------------------------------------------------

    def _route_get(self, path):
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML)
        elif path == "/health":
            self._send(200, "ok\n", "text/plain; charset=utf-8")
        elif path == "/admin":
            # Deliberate weakness: admin panel without authentication.
            self._send(200, ADMIN_HTML)
        elif path == "/.git/HEAD":
            # Deliberate weakness: exposed git metadata.
            self._send(200, "ref: refs/heads/main\n", "text/plain; charset=utf-8")
        elif path == "/.env":
            # Deliberate weakness: exposed config (fake EXAMPLE values only).
            self._send(200, FAKE_ENV, "text/plain; charset=utf-8")
        elif path == "/server-status":
            # Deliberate weakness: exposed status endpoint.
            self._send(200, SERVER_STATUS, "text/plain; charset=utf-8")
        elif path == "/phpinfo.php":
            # Deliberate weakness: exposed "phpinfo" endpoint.
            self._send(200, PHPINFO_HTML)
        elif path == "/login":
            # Deliberate weakness: the login page already hands out a session
            # cookie, with no Secure, no HttpOnly and no SameSite attribute.
            token = "lab-toy-session-" + secrets.token_hex(16)
            self._send(200, LOGIN_HTML, "text/html; charset=utf-8",
                       {"Set-Cookie": f"session={token}; Path=/"})
        elif path == "/error":
            # Deliberate weakness: unhandled exception -> full traceback
            # returned to the client.
            raise RuntimeError(
                "lab-webapp: deliberate unhandled exception (simulated "
                "backend crash)")
        elif path == "/logout":
            self._send(200, "logged out\n", "text/plain; charset=utf-8",
                       {"Set-Cookie": "session=; Path=/; Max-Age=0"})
        else:
            self._send(404, "not found\n", "text/plain; charset=utf-8")

    def _route_post(self, path):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # drain body; credentials are ignored
        if path == "/login":
            # Deliberate weakness: session cookie with no Secure, no
            # HttpOnly and no SameSite attribute.
            token = "lab-toy-session-" + secrets.token_hex(16)
            self._send(
                200,
                json.dumps({"status": "ok",
                            "message": "logged in (any credentials accepted)"}),
                "application/json",
                {"Set-Cookie": f"session={token}; Path=/"})
        else:
            self._send(404, "not found\n", "text/plain; charset=utf-8")

    def _dispatch(self):
        path = urlsplit(self.path).path
        try:
            if self.command == "POST":
                self._route_post(path)
            else:
                self._route_get(path)
        except Exception:
            # Deliberate weakness: leak the full Python traceback.
            tb = traceback.format_exc()
            self._send(500, tb, "text/plain; charset=utf-8")

    def do_GET(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def log_message(self, fmt, *args):  # keep lab noise on stderr
        super().log_message(fmt, *args)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"lab-webapp listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
