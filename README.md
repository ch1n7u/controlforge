# CONTROLFORGE

CONTROLFORGE is a continuous security control validation and effectiveness
testing platform, running entirely on this machine — no cloud service in the
loop. It is not a scanner with a web front end.

You define a security control once and express it as one or more executable
validation tests. Those tests run against authorized targets on demand, or as a
retest of an earlier finding. The raw output of the tool underneath is turned
into typed **facts**, and declarative **assertions** evaluate those facts into a
tri-state result — **PASS**, **FAIL**, **INCONCLUSIVE**, **NOT APPLICABLE** —
each backed by evidence. A failed assertion opens a **finding** with a
remediation and retest workflow.

The tri-state evaluation is the point. "We could not determine whether the
control holds" is a different answer from "the control holds", and a platform
that cannot say the first one is a scanner.

**Version 0.1.0** — local-first MVP, single node.

---

## What is where

| | |
|---|---|
| Project root | `/home/chintu/controlforge` |
| Backend | `backend/` — FastAPI, SQLAlchemy 2.0 (sync) + psycopg3, Alembic |
| Frontend | `frontend/` — Vite + React + TypeScript + Tailwind v4 (see `frontend/README.md`) |
| Built UI | `frontend/dist/` — served directly by nginx |
| Lab targets | `lab/` — deliberately vulnerable containers |
| Deployment files | `deploy/` — nginx site, systemd units, sudoers drop-in, nftables ruleset |
| Operations scripts | `scripts/` — DB bootstrap, seed, firewall sync, lab up/down |
| Database | PostgreSQL 18 on `127.0.0.1:5432`, database `controlforge` |
| Evidence store | `/var/lib/controlforge/evidence` (append-only, content-addressed) |
| Application logs | `/var/log/controlforge/` and `journalctl -u controlforge-*` |
| Secrets | `/etc/controlforge/controlforge.env`, mode `0640 root:controlforge` |

## URLs and ports

| URL | What |
|---|---|
| `http://127.0.0.1/` | **The web UI** (nginx) |
| `http://172.28.150.51/` | The same UI on the LAN |
| `http://127.0.0.1:8000/api/health` | API liveness (API itself is loopback-only) |
| `http://127.0.0.1:8000/api/docs` | Interactive API reference (loopback-only) |
| `http://127.0.0.1:5432` | PostgreSQL (loopback-only) |

The API is deliberately **not** exposed on the LAN. nginx publishes the UI and
reverse-proxies `/api` to `127.0.0.1:8000`, so there is one front door.

Lab targets (only present when the lab is up, all loopback-only):

| Port | Target | Purpose |
|---|---|---|
| `8081` | nginx with weak headers | missing HSTS/CSP/X-Content-Type-Options |
| `8443` | nginx with weak TLS | old protocol versions, weak ciphers |
| `8082` | small API | exposed paths such as `/.env`, `/server-status` |
| `8083` | small web app | security-header and cookie-flag failures |
| `2222` | SSH | weak configuration |
| `8084` | OWASP Juice Shop | a realistic vulnerable application |

## The web UI

Everything is drivable from the interface, and each action sits on the page it
belongs to:

- **Overview** — assertion outcomes, control coverage and the findings waiting
  for triage.
- **Runs** — start one from a test or a target and watch its log stream live;
  the facts and assertion results it produced stay on the run's page.
- **Findings** — triage (status, severity, assignment, notes) and retest a
  remediated finding to close it out.
- **Evidence** — the captured artifacts, with the recorded SHA-256 checked when
  a file is downloaded.
- **Configuration** — controls with their framework references, frameworks,
  tests and their versions, targets, and the scopes that authorize runs. All of
  it is editable in place; nothing here needs the API by hand.
- **Administration** — the audit log, user accounts, and run safety (kill
  switch, safe mode, the global concurrency cap).

The interface is a client of the same API documented at `/api/docs`, not a
second implementation.

## Start, stop, restart, test

```bash
./start.sh      # bring everything up (idempotent; safe to re-run)
./stop.sh       # stop the API and worker
./restart.sh    # stop.sh followed by start.sh
./status.sh     # what is running right now; exit 0 when every check passes
./test.sh       # backend pytest + frontend typecheck and production build
```

`./start.sh` starts PostgreSQL, the API, the worker, refreshes the firewall and
checks that nginx answers on both `127.0.0.1:80` and the LAN address. It refuses
to report success if port 8000 answers but the systemd unit is not the thing
answering it.

`./stop.sh` stops the API and the worker. PostgreSQL and nginx are left alone,
and the worker's egress firewall stays loaded on purpose: stopping the
application is not a reason to open the worker's network access back up.

```bash
./install.sh    # re-install units, nginx site, directories, sudoers drop-in
```

`./install.sh` is idempotent and never starts anything.

## Deploying on another host

```bash
sudo ./provision.sh
```

`./provision.sh` takes a bare machine to a working install. It is the only
script that needs to know how a distribution differs from the next one, so it is
the one to run on a fresh host; `./install.sh` assumes the work below is already
done and stops with a pointer if it is not.

What it does, in order: installs the distribution's packages · initialises and
starts a PostgreSQL cluster · creates the system account and group · builds the
virtualenv and the frontend · installs the validation engines · renders the units
and the nginx site · creates the database and generates the secrets · applies the
migrations and seeds the account and the control catalog.

It asks for the handful of decisions that actually vary between installs —
administrator username, LAN exposure, whether to seed the control catalog — and
takes everything else as a flag or an environment variable:

```bash
sudo ./provision.sh --no-lan --admin-user secops -y
sudo SERVICE_USER=svc CONF_DIR=/opt/controlforge/conf ./provision.sh
sudo ./provision.sh --help          # every option, with defaults
```

Everything is recorded in `<conf-dir>/install.conf` and re-applied by re-running
the script, so changing an install-time choice later is an edit plus a re-run
rather than a reinstall. Existing secrets are never overwritten: re-provisioning
a live host leaves the running deployment's credentials alone.

It is idempotent and safe to re-run. Every step checks for what it is about to
create.

**Supported distributions.** Debian, Ubuntu and Kali · RHEL, Fedora, Rocky,
AlmaLinux and Oracle Linux · Arch and Manjaro · openSUSE and SLES. Package names
are mapped per family explicitly rather than guessed, and the PostgreSQL
initialisation follows each family's own convention (Debian's
`pg_createcluster`, RHEL's `postgresql-setup --initdb`, Arch's `initdb`,
openSUSE's initialise-on-first-start).

**systemd is required.** The units are systemd units and there is no OpenRC or
SysV path; `provision.sh` says so plainly instead of installing something that
cannot start. Minimal container images (Alpine, WSL1) are the usual cause.

Node 20.19+ or 22.12+ is needed to build the frontend. Without it the API and
the database still come up and `provision.sh` says the UI will 404 rather than
failing the whole provisioning. `nuclei` is not packaged by any of these
distributions, so it is reported as missing rather than installed, and the
nuclei-based tests report INCONCLUSIVE until it is present.

### Lab lifecycle

```bash
./scripts/lab_up.sh     # docker compose up for lab/, wait for healthchecks
./scripts/lab_down.sh   # docker compose down
```

## Services

| Unit | User | What it does |
|---|---|---|
| `controlforge-api.service` | `controlforge` | FastAPI on `127.0.0.1:8000` |
| `controlforge-worker.service` | `controlforge` | claims runs from the queue and executes engines |
| `controlforge-fw-sync.service` + `.timer` | root (oneshot) | re-derives the worker egress allow-list every 15 s |
| `nginx.service` | root | static UI + `/api` reverse proxy |
| `postgresql.service` | `postgres` | the database, loopback-only |

All are enabled at boot, as is nginx — a reboot brings the platform back without
anyone logging in.

## Validation engines

Six engines ship in 0.1.0:

| Engine | What it observes |
|---|---|
| `nmap` | TCP connect scan over the authorized ports, with optional service and version detection |
| `tls_config` | protocol versions, ciphers, certificate posture and protocol-level vulnerabilities, via testssl.sh |
| `http_headers` | the response line, every response header and every cookie flag |
| `http_exposure` | a curated list of well-known sensitive paths, reported only when the body matches that path's signature |
| `nuclei` | template matches, restricted to non-intrusive HTTP template classes |
| `local_baseline` | this host's sysctls, file modes and sshd settings (target type `local`; touches no network) |

## How the safety model works

This is the part that makes the tool safe to point at real infrastructure, and
it is worth understanding before adding targets.

1. **Nothing runs outside a scope.** A `Scope` carries CIDR/host entries with
   port ranges, an expiry and an approving user. A target with no scope covering
   it cannot be validated at all — the run is refused before any process starts.
   Broad ranges require an explicit `allow_broad` flag plus a written
   authorization reference; the link-local metadata address is always refused;
   loopback requires a scope marked as a lab.
2. **Addresses are resolved once and pinned.** The API resolves the target's
   hostname, stores the resolved IPs on the run, and refuses the run if *any*
   answer falls outside the scope. Engines are handed IP addresses only, never
   hostnames, with the `Host` header and TLS SNI supplied explicitly. A hostname
   cannot re-resolve to something else inside the tool.
3. **The kernel enforces the boundary, not the code.** An nftables table
   (`inet controlforge`) matches the worker's uid and default-denies egress
   except loopback and the currently-authorized `(ip, port)` pairs. The
   `fw-sync` timer re-derives it from the active scopes every 15 seconds, so a
   narrowed authorization reaches the kernel within one interval and a ruleset
   wiped by hand heals without intervention. Operators who need it applied
   immediately can run `sudo systemctl start controlforge-fw-sync.service`.
4. **Narrowing an authorization stops work in flight.** Deactivating a scope,
   removing an entry, or unlinking a target cancels the queued and running runs
   that were relying on it, at the moment the change is committed.
5. **Engines take typed parameters, never a command line.** There is no
   free-form argument or shell string anywhere in the execution path. `safe_mode`
   selects a non-intrusive argument template per engine.
6. **Runaway work is bounded.** Per-target concurrency uses Postgres advisory
   locks, there is a global concurrency cap and a kill switch, and every run has
   a wall-clock timeout enforced by a poll loop that also honours cancellation,
   escalating to `SIGTERM` and then killing the process group.
7. **Evidence is append-only and verifiable.** Every artifact is hashed with
   SHA-256 at capture, along with the tool version, the exact arguments, the
   scope snapshot and a database timestamp. There is no delete API.

Every engine shipped in 0.1.0 is read-only: no run changes state on a target.

## Accounts and secrets

One administrator account is created when the platform is first set up, with a
generated password stored as `CONTROLFORGE_ADMIN_INITIAL_PASSWORD` in
`/etc/controlforge/controlforge.env`, and it is required to change that password at first
sign-in.

Every other account is made by an administrator on the **Users** screen: an
account is created with a role and an initial password (which it must change at
first sign-in), and it can be renamed, re-roled, deactivated or reactivated, or
given a new password — setting one revokes every session that account has open.
Accounts are deactivated rather than deleted, so the audit trail keeps naming a
real person, and an administrator cannot demote or deactivate themselves, so
the platform can never be left without one. There is no self-service signup.

Three roles, enforced per route rather than merely recorded:

- **viewer** — read-only.
- **analyst** — the validation work: create and edit targets, controls,
  frameworks and tests, start and cancel runs, triage findings, and retest.
- **admin** — everything an analyst may do, plus accounts, scopes and settings,
  and the deletes reserved to an administrator: targets, controls and
  frameworks.

Passwords are 12 characters or more and must mix upper case, lower case and a
digit.

Secrets live in `/etc/controlforge/controlforge.env` (`0640
root:controlforge`): the database URL, the session signing key, the evidence
directory and the initial admin password. That file is never printed by any
script and must never be committed. `CONTROLFORGE_ADMIN_INITIAL_PASSWORD` can be
deleted from it once the administrator has signed in.

To read the file you must either be root or a member of the `controlforge`
group; membership takes effect on next login.

## Tests

```bash
./test.sh
```

runs the backend suite (unit, policy and integration tests, including deliberate
scope-bypass attempts) against a database named `<your db>_test`, with evidence
and audit output redirected to a temporary directory, so a test run can never
touch production data or the real append-only audit trail. The frontend step is
`tsc -b && vite build`.

To isolate a test run from another one working in the same tree, set
`CONTROLFORGE_TEST_DB` to a different database name.

The tests that exercise real engines against real services skip themselves when
the lab is not running, so `./test.sh` passes either way — with the lab up you
get end-to-end coverage against live targets, and with it down you get the
unit and policy suites.

## Repository layout

```
controlforge/
├── provision.sh            prepares a bare host, then installs CONTROLFORGE on it
├── start.sh stop.sh restart.sh status.sh test.sh install.sh
├── backend/
│   ├── alembic/            migrations
│   ├── app/
│   │   ├── api/            routers: auth, registry, testing, runs, findings,
│   │   │                   evidence, dashboard, audit, system
│   │   ├── core/           security, sessions, audit writer, evidence store
│   │   ├── engines/        pluggable validation engines
│   │   ├── models/         SQLAlchemy models and enums
│   │   ├── queue/          claim / lease / heartbeat / reaper
│   │   ├── runner/         executor, fact emission, assertion evaluation
│   │   ├── schemas/        pydantic request and response models
│   │   └── seed/           frameworks, controls, tests, targets, scopes
│   └── tests/
├── frontend/               Vite + React + TypeScript SPA
├── lab/                    docker-compose.yml + deliberately vulnerable targets
├── deploy/                 nginx, systemd units, sudoers drop-in, nftables ruleset
└── scripts/                lib.sh (shared config and host detection),
                            bootstrap_db.sh, sync_firewall.py, lab_up.sh,
                            lab_down.sh, engine_harness.py
```

`deploy/` holds templates, not files: the systemd units and the nginx site carry
`@REPO_DIR@`-style placeholders and are rendered for this host by `./install.sh`.
Every path, account name and port in a rendered file comes from
`<conf-dir>/install.conf`, so an install can be moved or renamed by editing that
file and re-running `./install.sh`.

Re-seeding the framework/control/test catalogue and the lab targets is
`python -m app.seed` from `backend/` (see `backend/app/seed/lab.py` for what it
creates).

## Design notes worth knowing

- **No Redis.** PostgreSQL is both the queue and the store. Workers claim jobs
  with `SELECT … FOR UPDATE SKIP LOCKED` in a short transaction, heartbeat while
  running, and a reaper requeues expired leases with an attempt cap, moving
  exhausted runs to a dead-letter state.
- **No AI in the critical path.** Nothing about defining, running or evaluating a
  control depends on a language model. An optional reporting plugin is possible
  later; it will never sit in the execution path.
- **Facts, not text.** Engines emit typed observables, and assertions evaluate
  those observables. This is what makes results comparable over time and across
  tools instead of being bespoke parsing of whatever a tool printed.
- **Test versions are immutable.** A run references the exact version of a test
  it executed, so changing a check never rewrites history or silently re-labels
  an old finding.

## Known limitations

- **Read-only validation.** Every engine shipped is non-mutating. Engines that
  change state exist as a concept but are disabled; there is no rollback
  machinery in this release.
- **Unprivileged worker.** The worker runs without `CAP_NET_RAW`, so scans are
  TCP connect scans. No SYN scanning, no masscan, no packet crafting.
- **Session authentication only.** There are no API tokens yet, so automation
  must drive the API with a session cookie.
- **Account management is deliberately small.** Administrators create, edit and
  deactivate accounts, but never delete them (the audit trail has to keep
  pointing at a real person), and there is no self-service signup or
  email-based password reset.
- **Single node.** No high availability, no clustering, no distributed workers.
- **Tool data is local.** Nuclei needs its local templates, and testssl.sh its
  local data bundle; neither auto-updates, which is deliberate for reproducibility
  but means the tool data is only as fresh as the last manual update.
- **Firewall convergence is periodic.** Changes reach the kernel within 15
  seconds (or immediately with the manual command above), not instantly.
- **A busy target defers rather than queues.** When another run already holds
  the target's slot, the run is released back to the queue without consuming an
  attempt, so a target that is permanently busy defers indefinitely instead of
  dead-lettering. That is the safe direction - nothing is lost - but it is not a
  bound.
- **Tool identity is recorded, tool data is not.** A run records the version of
  the binary it ran, so a result can be attributed to an nmap or testssl build.
  It does not yet record which nuclei template set was in use, so two runs weeks
  apart are comparable as to engine but not as to template content.
- **The bootstrap password is only as good as the operator.** An account that
  still uses it is flagged in the interface until it is changed.
- One pre-existing host issue is unrelated to this project:
  `/etc/sudoers.d/chintu` is mode `0644` where sudo wants `0440`. It is reported
  as a warning by `visudo -c`. Fixing it is a one-line `chmod`, but it is the
  machine's own file rather than CONTROLFORGE's, so it was left alone.

## Next priorities

1. API tokens for automation, so scheduled revalidation does not depend on a
   browser session.
2. File checksums in the local-baseline engine. Modes, sysctls and sshd settings
   are covered; file contents are not hashed yet, so a rewritten file that
   keeps its mode is not detectable.
3. More engines underneath the same model: OWASP ZAP, Trivy, Semgrep.
4. Scheduled and continuous revalidation with drift detection.
5. SLA and due-date tracking on findings, building on the remediation workflow.
6. Compliance report export (PDF/CSV) from the posture data.
7. An optional AI reporting plugin — explicitly outside the critical path.
