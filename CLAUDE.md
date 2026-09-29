# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CONTROLFORGE is a local-first security **control validation** platform: a control is defined once, expressed as executable validation tests, run against authorized targets, and the raw tool output is turned into typed **facts** that declarative **assertions** evaluate into a tri-state result — PASS, FAIL, INCONCLUSIVE, NOT APPLICABLE — backed by evidence and, on failure, a finding with a remediation/retest workflow.

The tri-state evaluation is the point. "We could not determine whether the control holds" is a different answer from "the control holds." Never collapse INCONCLUSIVE into a pass or a fail — in the backend, the UI, or a report.

## Commands

```bash
./test.sh           # backend pytest + frontend typecheck/build; runs as the invoking user
./start.sh          # start PostgreSQL, API, worker, firewall refresh, nginx (re-execs sudo)
./stop.sh ./restart.sh ./status.sh
./install.sh        # re-render deploy/ templates to systemd/nginx/sudoers (idempotent, never starts)
sudo ./provision.sh # bare host -> working install; --help lists every option
./scripts/lab_up.sh ./scripts/lab_down.sh   # docker lab of deliberately vulnerable targets
```

Backend (from `backend/`, using its venv):

```bash
.venv/bin/python -m pytest -q                              # full suite (needs Postgres running)
.venv/bin/python -m pytest tests/test_scope_policy.py -q   # one file
.venv/bin/python -m pytest tests/test_scope_policy.py::test_port_matching_is_inclusive -q
.venv/bin/alembic upgrade head                             # migrations; URL from CONTROLFORGE_DB_URL
.venv/bin/python -m app.seed                               # admin account + control/test catalog
```

Frontend (from `frontend/`):

```bash
npm run dev     # Vite dev server, /api proxied to 127.0.0.1:8000 (start the API first)
npm run build   # tsc -b && vite build -> dist/  (this is also the typecheck)
npm run lint    # oxlint
```

Test/environment notes:

- `backend/tests/conftest.py` redirects everything to a `<db>_test` database, a temp evidence dir and a temp audit file, and TRUNCATEs tables between tests. Never run two pytest runs concurrently against the same test DB; set `CONTROLFORGE_TEST_DB` to a different name to isolate a run.
- Live tests (`test_engine_live.py`, `test_worker_live.py`) skip themselves when the lab is not up; bring the lab up first for real end-to-end coverage.
- Settings load from `CONTROLFORGE_*` env vars or `/etc/controlforge/controlforge.env`; `app.config.get_settings()` is an lru_cache'd singleton (tests clear the cache). A missing `CONTROLFORGE_SECRET_KEY` raises on import.

## Architecture

### Request/execution flow

1. The API (FastAPI, **sync** SQLAlchemy + psycopg3) enqueues a `ValidationRun` row — the queue **is** Postgres; there is no Redis. `app/queue/jobs.py` does claim (`FOR UPDATE SKIP LOCKED`), lease, heartbeat, defer, cancel and reap. Per-target concurrency uses Postgres advisory locks held on dedicated connections (`app/db.py`) so a dying worker releases them immediately.
2. `app/runner/worker.py` orchestrates one run, and the order is deliberate: **authorize → execute → store evidence → evaluate**.
   - Authorization is re-read from the database immediately before the tool starts (`app/scope/load.py` + `authorize()`), not trusted from enqueue time. A narrowed scope stops the run.
   - The engine runs via `app/engines/runtime.py`; long-running work never holds a DB transaction (sessions are opened for the load, log flushes and the persist).
   - Evidence is written and hashed *before* the assertion is evaluated, so every verdict traces to recorded bytes.
   - `app/core/assertions.py` evaluates the assertion against the stored fact rows; `app/core/findings.py` turns the outcome into finding state (one finding per `(test, target, assertion)` fingerprint: FAIL opens/reopens, PASS resolves, INCONCLUSIVE leaves it untouched).
3. `app/runner/exec.py` runs external tools: argv lists only (a shell string is a bug), own session so timeouts kill the whole process group, capped output that keeps draining, rebuilt minimal environment (no inherited secrets).

### Engine catalogue — the contract

`app/engines/catalogue.py` declares every engine: id, pydantic params model, the exact `fact_types` it may emit, target types, default timeout, mutating flag. It is the contract for three consumers: the API (refuses a test whose assertion references a fact type its engine cannot emit), the runner (validates stored parameters), and the UI (schema-driven forms). `runtime.run_engine` additionally refuses an engine that emits an undeclared fact type — a mismatch would otherwise make an assertion silently meaningless.

Engine modules (`app/engines/<id>.py`) expose `run(target, params, ctx) -> EngineResult`. They receive a **pinned IP address** in `TargetView`, never a hostname to resolve; the hostname is only for `Host:`/SNI. To add an engine: add an `EngineSpec` to the catalogue, add the module, add `fact_types`-aware tests.

### Scope and safety model (load-bearing — understand before changing)

- `app/scope/policy.py` — what a human may authorize: entries are CIDR/host with explicit ports; wildcards refused; broad ranges need `allow_broad`; anything touching public space needs an `authorization_ref`; loopback needs `is_lab`; hard-denied ranges (metadata IP, multicast, etc.) cannot be authorized at all.
- `app/scope/authorize.py` — the pure exec-time decision: resolve the hostname once (no cache), pin the addresses, require every resolved address to be covered, refuse loopback reached through a *name* (rebinding defence), never hand a hostname to an engine.
- The kernel is the real boundary: an nftables table (`deploy/nftables/controlforge.nft`) matches the worker's uid and default-denies egress except loopback plus the active scopes' `(address, port)` pairs. `scripts/sync_firewall.py` re-derives it every 15 s via the `controlforge-fw-sync` timer. Do not add code paths that let the worker reach the network outside this.
- Narrowing a scope cancels queued and running runs relying on it at commit time (`jobs.cancel_active_for_target`).
- `app/core/evidence.py` — content-addressed store (filename is its SHA-256), append-only, digest re-verified on read; there is no delete API.

### API and auth

- Routers in `app/api/`: auth, registry (controls/targets/scopes), testing (tests + immutable versions), runs, findings, evidence, dashboard, audit, system.
- Session cookie auth only. Cookie is `HttpOnly`; CSRF token returned by `/api/auth/me` and required as `X-CSRF-Token` on mutations (`app/api/deps.py`: `require_user`, `require_writer`, `require_admin`). The API listens on loopback only; nginx is the single front door.
- Every security-relevant action is recorded in the append-only audit log (`app/core/audit.py`: table + JSONL mirror).
- Test versions are immutable; a run references the exact version it executed.

### Frontend

React 19 + TypeScript SPA (Vite, Tailwind v4, React Router 7, TanStack Query 5; hand-rolled SVG charts, no chart dependency). All requests use relative `/api/...` paths; the CSRF token lives in memory only. Forms for assertions and engine params are schema-driven from the API (`src/components/SchemaForm.tsx`, `AssertionEditor.tsx`). Tri-state tones live in `src/lib/tones.ts`. The nginx CSP is strict: no CDN scripts/fonts, no inline handlers. See `frontend/README.md`.

### Deploy

`deploy/` holds **templates**, not live files: systemd units, nginx site, sudoers drop-in carry `@PLACEHOLDER@` tokens rendered by `./install.sh` from `<conf-dir>/install.conf`. `provision.sh` is the only script that knows distro differences. Secrets live in `/etc/controlforge/controlforge.env` (root:`controlforge`, 0640) and are never printed or committed.

## Conventions

- Tri-state is never a boolean. INCONCLUSIVE gets its own run status and its own UI tone.
- No free-form command strings anywhere in the execution path: typed parameters validated against the catalogue, argv lists to `Popen`.
- Read-only engines only; mutating engines are a declared-but-disabled concept.
- Facts, not text: assertions select typed facts by type/subject/key, never parse tool output.
- Evidence is append-only and hashed at capture; never write file contents to logs or the database (a digest and size suffice, and cannot leak secrets).
- Enum values persist as VARCHAR; the vocabulary lives in `app/models/enums.py`.
- `README.md` is the product-level source of truth (safety model, known limitations, next priorities) — keep it accurate when behaviour changes.
