#!/usr/bin/env python3
"""CONTROLFORGE lab target: lab-api (deliberately vulnerable, stdlib only).

Deliberate weaknesses:
  * GET /api/v1/users         - full user list with no authentication
  * GET /api/v1/admin/config  - admin config with no authentication
  * GET /api/v1/error         - returns a full Python traceback (500)
  * no security headers on any response
  * Access-Control-Allow-Origin: * on every response
  * /health returns 200 (the only non-vulnerable route)

All values are unmistakably fake EXAMPLE placeholders.
"""
import json
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST = "0.0.0.0"
PORT = 8000

# Obviously fake placeholder values - never real credentials.
FAKE_USERS = {
    "users": [
        {"id": 1, "username": "admin", "email": "admin@example.invalid",
         "role": "admin", "password": "EXAMPLE-NOT-A-REAL-SECRET",
         "api_key": "EXAMPLE-NOT-A-REAL-KEY"},
        {"id": 2, "username": "operator", "email": "operator@example.invalid",
         "role": "user", "password": "EXAMPLE-NOT-A-REAL-SECRET",
         "api_key": "EXAMPLE-NOT-A-REAL-KEY"},
        {"id": 3, "username": "auditor", "email": "auditor@example.invalid",
         "role": "readonly", "password": "EXAMPLE-NOT-A-REAL-SECRET",
         "api_key": "EXAMPLE-NOT-A-REAL-KEY"},
    ]
}

FAKE_ADMIN_CONFIG = {
    "debug": True,
    "environment": "production (simulated)",
    "db": {
        "host": "db",
        "name": "appdb",
        "user": "app",
        "password": "EXAMPLE-NOT-A-REAL-SECRET",
    },
    "jwt_secret": "EXAMPLE-NOT-A-REAL-SECRET",
    "s3_access_key_id": "EXAMPLE-NOT-A-REAL-KEY",
    "s3_secret_access_key": "EXAMPLE-NOT-A-REAL-SECRET",
    "feature_flags": {"maintenance_mode": False, "beta_features": True},
}

INDEX = {
    "service": "lab-api",
    "note": "CONTROLFORGE deliberately vulnerable API target",
    "endpoints": [
        "GET /health",
        "GET /api/v1/users",
        "GET /api/v1/admin/config",
        "GET /api/v1/error",
    ],
}


class Handler(BaseHTTPRequestHandler):
    # NOTE: server_version / sys_version intentionally left at the stdlib
    # defaults so the banner leaks the Python version.
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, content_type="application/json",
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

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, indent=2))

    def _dispatch(self):
        path = urlsplit(self.path).path
        try:
            if path in ("/", "/api", "/api/v1"):
                self._json(200, INDEX)
            elif path == "/health":
                self._json(200, {"status": "ok"})
            elif path == "/api/v1/users":
                # Deliberate weakness: no authentication, full user records.
                self._json(200, FAKE_USERS)
            elif path == "/api/v1/admin/config":
                # Deliberate weakness: no authentication, admin config.
                self._json(200, FAKE_ADMIN_CONFIG)
            elif path == "/api/v1/error":
                # Deliberate weakness: unhandled exception -> full traceback.
                raise RuntimeError(
                    "lab-api: deliberate unhandled exception (simulated "
                    "backend crash)")
            else:
                self._json(404, {"error": "not found", "path": path})
        except Exception:
            tb = traceback.format_exc()
            self._send(500, tb, "text/plain; charset=utf-8")

    def do_GET(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._dispatch()

    def log_message(self, fmt, *args):  # keep lab noise on stderr
        super().log_message(fmt, *args)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"lab-api listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
