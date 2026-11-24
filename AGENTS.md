# AGENTS.md

Guidance for anyone — human or AI — changing this repository. Read it before editing code.
The goal is to keep changes small, tested and consistent with the architecture that already
exists.

## What this is

DMARCView is a self-hosted DMARC aggregate (RUA) and TLS-RPT reporting dashboard for
Stalwart (or any JMAP server). It polls a mailbox, parses report attachments, stores them in
SQLite, and serves a React dashboard plus live DNS/transport health checks.

**Stack:** Python 3.11+ / FastAPI / SQLModel / SQLite / Alembic · React 19 / Vite / TypeScript /
Recharts · Docker (multi-arch).

The initial implementation was generated with AI assistance and reviewed by the maintainer.
Treat it as reviewed code, not as infallible: verify protocol details against the RFCs and
Stalwart's behaviour before trusting them.

## Quick commands

```bash
# Backend (from backend/)
../.venv/bin/pytest -q                  # test suite
../.venv/bin/ruff check app tests       # lint
../.venv/bin/python -m app.cli stats    # row counts
../.venv/bin/python -m app.cli import ../samples/*.eml
../.venv/bin/python -m app.cli backup --keep 14
../.venv/bin/python -m app.cli migrate

# Frontend (from frontend/)
npm ci
npm run dev        # Vite on :5173, proxies /api to :8000
npm run build      # tsc -b + vite build; this is the type check

# Local demo data (never used in production)
DATABASE_URL=sqlite:///$PWD/data/demo.db .venv/bin/python scripts/demo_seed.py
DATABASE_URL=sqlite:///$PWD/data/demo.db JMAP_ENABLED=false ADMIN_PASSWORD=demo \
  .venv/bin/uvicorn app.main:app --app-dir backend --port 8000

# Containers
docker compose up -d --build
docker build -t dmarcview .
```

## Repository map

| Path | Contents |
| --- | --- |
| `backend/app/ingest/` | MIME unwrap → DMARC XML / TLS-RPT JSON parsers → persistence; JMAP client |
| `backend/app/alerts/` | Rule specs and evaluators, notification channels, evaluation/dedupe service |
| `backend/app/health/` | DNS/HTTP clients, checks, DKIM selector discovery, TLS probes, engine, persistence |
| `backend/app/analytics.py` | Read-side aggregation for the dashboard, reports and TLS pages |
| `backend/app/routers/` | `auth`, `api` (dashboard/reports/tls), `ingest`, `health`, `alerts` |
| `backend/app/jobs.py` | In-process scheduler (health checks, probes, PTR enrichment, alert evaluation) |
| `backend/app/models.py` | SQLModel schema — the source of truth for Alembic |
| `backend/migrations/` | Alembic revisions (`0001` baseline, `0002` health/probes/jobs, `0003` alerts, `0004` ASN) |
| `frontend/src/` | `pages/`, `components/`, `state.tsx`, `api.ts`, `types.ts`, `styles.css` |
| `samples/` | Hand-written CRLF `.eml` fixtures used by the test suite |
| `docs/` | Roadmap and screenshots |

## Invariants and traps

**Datetimes are timezone-aware UTC.** SQLModel 0.0.50's `UTCDateTime` rejects naive values.
Use `models.utcnow()`; when reading from SQLite assume UTC.

**Use SQLModel's `select`, not SQLAlchemy's.** `session.exec(select(Model))` returns model
instances, but a single-column select returns scalars — `row[0]` on a scalar silently takes the
first character (this shipped once as a PTR bug). Multi-column selects return `Row`s.

**Schema changes require an Alembic revision** in `backend/migrations/versions/`.
`db.init_db()` upgrades on start; an existing v1 database without `alembic_version` is stamped
at `0001` first. Do not reintroduce `SQLModel.metadata.create_all()` in application code.

**Ingestion is idempotent at three levels:** processed message key, attachment SHA-256, and
`(org_name, report_id, domain_id)`. Keep raw XML/JSON bytes; the report browser serves them.
Malformed attachments must never abort the rest of a batch.

**JMAP queries use RFC 8621 filters.** The date filter is `after`, not `receivedAfter`.
Servers that reject it are handled by a newest-first scan fallback in `JMAPClient`.

**DKIM selectors cannot be enumerated.** Stalwart rotates date-based selectors
(`v1-ed25519-20260101`). Selectors discovered from report `auth_results` are always checked;
date variants around today cover the gap after a rotation; manual selectors are an extra.
Never hardcode a selector list as the only source.

**Health checks degrade to `unknown`, never `fail`,** when DNS or HTTP is unavailable.
Checks receive injected `dns`/`http` clients; tests must use fakes, never the network.
`MTA-STS`'s `id` is an opaque change marker, not a hash.

**TLS probes verify certificates via certifi** (interpreter CA stores are often stale). They
never authenticate, never send mail, and only connect to MX hosts plus configured targets.

**Sender identities group by envelope/header domain plus external DKIM domain, not by IP.**
The same IP can send for several recipient domains (and one ESP rotates many IPs), so
grouping on IP alone merges unrelated senders — there is a regression test for this. ASN/PTR
is display context, not part of the identity key.

**Alerts dedupe on `(rule, domain, dedupe_key)` while an incident is open.** A new episode is
suppressed until the rule's cooldown passes; when the condition clears the open event is
resolved and a resolution notice is sent. Do not create a second open event for the same key.

**Alert channel credentials live only in the environment** (`SMTP_*`, `TELEGRAM_*`,
`SIGNAL_*`, `WEBHOOK_*`). Never persist secrets in `alert_rules` or log them. Channel
delivery must never block ingestion; failures are recorded on the event.

**A new alert kind needs three things:** a `RuleSpec` in `alerts/specs.py` (fields + defaults,
which seed `alert_rules`), an evaluator in `alerts/rules.py`, and a test. Thresholds are
clamped by `RuleSpec.clean()`; the API rejects unknown condition keys.

**Tests are isolated from the developer's `.env`.** `APP_ENV=test` disables dotenv loading.
GeoIP is stubbed in `tests/conftest.py`, so the suite passes without the gitignored `.mmdb`.

**The Docker build needs BuildKit** because the frontend stage uses `$BUILDPLATFORM` for fast
multi-arch builds. The image copies `LICENSE` and `THIRD_PARTY_NOTICES.md`; keep them there.

**Fixtures are CRLF by design.** `.gitattributes` marks `*.eml` as `-text`; don't normalize them.

## Conventions

- **Backend:** Python 3.11+ syntax, line length 110, ruff rules `E4/E7/E9/F/B/SIM`.
  New endpoints go under `/api` and depend on `current_user`. Keep response shapes stable;
  the frontend mirrors them by hand in `frontend/src/types.ts`.
- **Frontend:** no UI framework or CSS-in-JS. Extend the design tokens in
  `frontend/src/styles.css`; use the primitives in `components/ui.tsx`. Keep API calls in
  `api.ts`. Every page must work at 430 px wide and with reduced motion.
- **Errors:** user-facing messages explain the fix, not the exception. Log technical detail
  server-side, never secrets.
- **Dependencies:** keep the footprint small. Do not add Redis/Celery, a UI kit, or a second
  web framework. SQLite is the default; PostgreSQL is an optional target.

## Definition of done

1. `cd backend && ../.venv/bin/pytest -q` passes.
2. `../.venv/bin/ruff check app tests` is clean.
3. `cd frontend && npm run build` succeeds.
4. Schema changes ship with a migration (and upgrade of an existing database was tested).
5. README / `.env.example` updated when configuration changes.
6. No secrets, tokens, real report data or `.env` files are committed.

## Releases and images

- Bump `backend/app/version.py`, `backend/pyproject.toml`, `frontend/package.json` and the
  default image tag in `docker-compose.yml` together.
- Tag releases as `vX.Y.Z`; `.github/workflows/publish-image.yml` publishes
  `ghcr.io/<owner>/dmarcview` for `linux/amd64` and `linux/arm64`. `latest` only tracks
  stable tags; `edge` tracks the default branch.
- The workflow runs the tests and a frontend build before publishing, and attaches SBOM +
  provenance attestations.
- After a successful tag publish it creates the GitHub Release automatically: generated
  notes plus the image reference and digest. Re-running the workflow leaves an existing
  release untouched, so hand-edited notes are safe.

## Roadmap

`docs/ROADMAP.md` is a plan, not an automatic backlog. Do not implement roadmap items unless
the user asks for them. The analytics foundation (identities + period changes) is delivered;
the analytics phase is complete; the next planned slice is read-only share links, then
export and retention.

## Security expectations

Single-admin session auth with PBKDF2, origin checks, CSP and a login throttle. Never weaken
these to make a feature easier. Do not log credentials, bearer tokens or report contents.
Outbound connections are limited to the configured JMAP server, DNS resolvers, certificate
probes and the explicit GeoIP download.
