# CONTROLFORGE lab

The safe, allowlisted set of deliberately-vulnerable targets that CONTROLFORGE
validates its security-control engines against. Every target fails specific
controls in a way the engines (nmap, testssl.sh, the Python HTTP-header probe,
the HTTP path-exposure probe, nuclei) can actually observe.

**Every port is bound to `127.0.0.1` only** - nothing in this lab is reachable
from outside this host.

## Start / stop

```sh
# Core lab (5 services), blocks until everything is healthy:
docker compose -f /home/chintu/controlforge/lab/docker-compose.yml up -d --wait

# Optional extra target (OWASP Juice Shop):
docker compose -f /home/chintu/controlforge/lab/docker-compose.yml --profile juice up -d --wait juice-shop

# Stop:
docker compose -f /home/chintu/controlforge/lab/docker-compose.yml --profile juice down
```

Compose project and bridge network are both named `controlforge-lab`.
All images build from the locally-pulled bases `alpine:3.20`, `nginx:alpine`
and `python:3.12-alpine`; no `pip install` anywhere. The one build-time network
dependency is `apk add openssh` in `targets/ssh/` (openssh is not in the base
image).

## Targets

| Target | Host port | Control(s) it deliberately violates | Engine that observes it |
|---|---|---|---|
| **lab-headers** (nginx) | `127.0.0.1:8081` | No `Strict-Transport-Security`, no `X-Content-Type-Options`, no `X-Frame-Options`, no `Content-Security-Policy`; version-leaking `Server: nginx/1.31.6` banner (`server_tokens on`); `autoindex on` directory listing at `/files/`; plain HTTP with no HTTPS redirect | Python http-headers probe (missing-header assertions + banner), HTTP path-exposure probe (`/files/`), nuclei (nginx version / directory-listing templates), nmap (`-sV` banner) |
| **lab-weaktls** (nginx + TLS) | `127.0.0.1:8443` | Self-signed cert generated at image build time (RSA-**1024**, 2-day validity, no SAN); `ssl_protocols TLSv1 TLSv1.1 TLSv1.2` (TLS 1.0/1.1 handshakes verified working); deliberately weak cipher list — the **NULL** entries negotiate (no encryption), while `3DES`/`RC4` entries are accepted in config but not offered by OpenSSL 3 (see notes); no HSTS | testssl.sh (protocol versions, cipher suites, certificate), nmap (`ssl-enum-ciphers`, least strength **F**; `ssl-cert`), Python http-headers probe (missing HSTS) |
| **lab-webapp** (stdlib Python) | `127.0.0.1:8082` | `/admin` admin panel with **no authentication**; `/.git/HEAD` returns `ref: refs/heads/main`; `/.env` exposes config with obviously fake `EXAMPLE-NOT-A-REAL-SECRET` values; `/server-status` and `/phpinfo.php` return 200; `/login` sets a session cookie with **no Secure, no HttpOnly, no SameSite**; `Access-Control-Allow-Origin: *`; `/error` returns a full Python traceback; `Server:` header leaks the Python version (`BaseHTTP/0.6 Python/3.12.14`) | HTTP path-exposure probe (`/.git/HEAD`, `/.env`, `/server-status`, `/phpinfo.php`, `/admin`), Python http-headers probe (cookie flags, CORS, banner), nuclei (exposed git/env/phpinfo templates) |
| **lab-api** (stdlib Python) | `127.0.0.1:8083` | `GET /api/v1/users` returns user records (fake EXAMPLE secrets) with **no authentication**; `GET /api/v1/admin/config` returns admin config with no authentication; `/api/v1/error` returns a full Python traceback; `Access-Control-Allow-Origin: *`; no security headers; Python-version banner | HTTP path-exposure probe (unauthenticated API endpoints), Python http-headers probe (CORS + missing headers), nuclei, nmap (`-sV`) |
| **lab-ssh** (alpine + openssh) | `127.0.0.1:2222` | `PermitRootLogin yes` + `PasswordAuthentication yes` with the lab toy credential `root:toor` (`PermitEmptyPasswords no`); root is offered password auth | nmap (`--script ssh-auth-methods` reports `password` for root), CONTROLFORGE SSH credential checks |
| **juice-shop** (profile `juice`) | `127.0.0.1:8084` | OWASP Juice Shop's built-in vulnerability set (SQLi, XSS, broken auth, ...) | nuclei (large template set), path-exposure probe, http-headers probe |

`/health` on `lab-webapp` and `lab-api` returns 200 and is the *only*
non-vulnerable route; it exists for the compose healthchecks.

## Verification quick reference

```sh
curl -sSI http://127.0.0.1:8081/                 # missing security headers + banner
curl -sS  http://127.0.0.1:8081/files/           # autoindex listing
curl -skI https://127.0.0.1:8443/                # no HSTS, version banner
openssl s_client -connect 127.0.0.1:8443 -tls1_1 </dev/null 2>&1 | grep Protocol
nmap -p 8443 --script ssl-enum-ciphers 127.0.0.1
curl -sS  http://127.0.0.1:8082/.git/HEAD        # 200, git ref
curl -sS  http://127.0.0.1:8082/.env             # 200, fake EXAMPLE values
curl -si -X POST http://127.0.0.1:8082/login    # cookie without Secure/HttpOnly/SameSite
curl -sS  http://127.0.0.1:8083/api/v1/users     # unauth fake user list
nmap -p 2222 --script ssh-auth-methods 127.0.0.1 # password auth offered
ss -tlnp | grep -E ':(8081|8082|8083|8084|8443|2222)\b'
```

## Notes / known limitations

- **All fake secrets are unmistakably fake** (`EXAMPLE-NOT-A-REAL-SECRET`,
  `EXAMPLE-NOT-A-REAL-KEY`). The ssh credential `toor` is a deliberate lab toy.
- **weaktls cipher reality (verified)**: the `ssl_ciphers` list in
  `targets/weaktls/nginx.conf` includes `DES-CBC3-SHA` and `RC4-*` entries;
  OpenSSL 3.x in Alpine no longer provides those algorithms for this build, so
  nginx silently drops them - `nmap ssl-enum-ciphers` confirms the server
  actually offers `AES128/256-CBC-SHA` plus `NULL-SHA`/`NULL-MD5` (least
  strength: F, and `NULL-SHA` completes a real handshake). TLS 1.0, 1.1 and
  1.2 all negotiate.
- **weaktls certificate** is regenerated on every image build by
  `targets/weaktls/gen_cert.py` - a pure-stdlib X.509 generator (no
  `openssl` CLI exists in `nginx:alpine`), producing RSA-1024, 2-day
  validity, self-signed, no SAN.
- The `juice-shop` image is distroless: no shell and `node` is not on `PATH`,
  so its healthcheck calls `/nodejs/bin/node` by absolute path.
- Nothing outside the five ports above is published, and every published port
  is bound to `127.0.0.1`.
