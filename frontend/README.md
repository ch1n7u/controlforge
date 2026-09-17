# Valtros web UI

The single-page application for Valtros. One origin, one front door: nginx
serves the built files from `dist/` and reverse-proxies `/api` to the API on
`127.0.0.1:8000`. Nothing in here talks to the API on any other host or port.

## Stack

| | |
|---|---|
| Build | Vite 8 |
| UI | React 19 + TypeScript 6 |
| Styling | Tailwind v4 (via `@tailwindcss/vite`) |
| Routing | React Router 7 |
| Server state | TanStack Query 5 |
| Charts | none — hand-rolled SVG in `src/components/charts.tsx` |
| Lint | oxlint |

There is no charting dependency on purpose. The four visuals the dashboard
needs (`Donut`, `BarList`, `RatioBar`, `TrendChart`) are a few dozen lines of
SVG each, which keeps the build small and means the posture colours come from
the same `src/lib/tones.ts` table the rest of the interface uses, rather than
from a library's palette.

## How it talks to the API

Every request goes to a **relative** `/api/...` path. That is what lets the same
build work unchanged at `http://127.0.0.1/` and at the LAN address: the browser
resolves `/api` against whatever origin served the page, so there is no host to
configure and no CORS.

Authentication is a session cookie the API sets `HttpOnly`, so the SPA cannot
and does not read it. `src/lib/api.ts` therefore holds the CSRF token **in
memory only** — never in `localStorage` or a readable cookie — obtained from
`/api/auth/me` after login and sent as `X-CSRF-Token` on every mutating request.
A `403` on a mutation triggers one refresh-and-retry, which covers the case
where the token rotated in another tab.

## Build and run

```bash
npm ci            # from the lockfile; use `npm install` only if the lockfile changed
npm run build     # tsc -b && vite build  ->  dist/
npm run dev       # dev server, /api proxied to 127.0.0.1:8000
npm run lint      # oxlint
```

`npm run build` type-checks first, so a type error fails the build rather than
shipping. `./provision.sh` and `./test.sh` both run this same command; there is
no separate deployment build.

For development, `vite.config.ts` proxies `/api` to the API on `127.0.0.1:8000`
with SSE buffering disabled, so the live run log streams in dev exactly as it
does behind nginx. Start the API with `./start.sh` first.

`npm run dev` needs Node 20.19+ or 22.12+; the production build is served by
nginx as static files and has no runtime Node requirement.

## Layout

```
src/
├── main.tsx App.tsx        entry point and the route table
├── auth/                   session provider; the CSRF token lives here
├── components/             Layout, tables, dialog, editors, hand-rolled charts
├── hooks/                  useRunLog (SSE), useDebounced
├── lib/                    api client, types, formatting, schema and tone tables
└── pages/                  one component per route
```

Routes, all under the authenticated layout except `/login`:

| Path | Page |
|---|---|
| `/overview` | posture dashboard: assertion outcomes, control coverage, findings awaiting triage (landing route) |
| `/controls`, `/controls/:id` | controls and their validation tests |
| `/targets`, `/targets/:id` | targets, resolved addresses, scope linkage |
| `/scopes`, `/scopes/:id` | authorization scopes, entries, expiry, governance warnings |
| `/tests`, `/tests/new`, `/tests/:id` | validation tests, versions, assertions |
| `/runs`, `/runs/:id` | executions, live log, facts and assertion results |
| `/findings`, `/findings/:id` | findings, remediation and retest |
| `/evidence`, `/evidence/:id` | artifacts, hashes and verification |
| `/audit` | append-only audit trail, filterable by actor, action and entity |
| `/settings` | run limits, run safety, result freshness and install health; every edit is recorded in the audit log |

## Conventions

- **Tri-state is never a boolean.** PASS, FAIL, INCONCLUSIVE and NOT APPLICABLE
  each have their own tone in `src/lib/tones.ts`; INCONCLUSIVE must never be
  rendered as a failure or as a pass, because "we could not determine whether
  the control holds" is the answer the platform exists to give.
- **Facts, not tool output.** Interfaces render fields from typed facts. Raw
  stdout belongs in the run log and nowhere else.
- **Schema-driven forms.** Assertion and engine parameters are rendered from the
  API's schema by `SchemaForm.tsx` / `AssertionEditor.tsx`, so adding an engine
  does not mean hand-writing a form.
- **No placeholder content.** Empty states and errors say what happened and what
  to do next; they never stand in for a feature that does not exist.

## Security notes

The nginx site sets a strict CSP (`script-src 'self'`, `connect-src 'self'`,
`object-src 'none'`, `frame-ancestors 'none'`), so this code must not introduce
remote fonts, CDN scripts, inline event handlers or a websocket to another
origin. `style-src` allows `'unsafe-inline'` only because React's `style`
attribute needs it.
