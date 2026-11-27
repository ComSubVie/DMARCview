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
../.venv/bin/python -m app.cli restore ../data/backups/dmarc-YYYYMMDD-HHMMSS.db --yes
../.venv/bin/python -m app.cli geo-enrich
../.venv/bin/python -m app.cli prune --dry-run
../.venv/bin/python -m app.cli mailbox-debug --days 90 --json
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
| `backend/app/simulation.py` | Read-only policy projection over stored reports |
| `backend/app/timeline.py` | Private annotations plus derived domain timeline events |
| `backend/app/routers/` | `auth`, `api` (dashboard/reports/tls), `simulation`, `timeline`, `expectations`, `fleet_views`, `audit`, `ingest`, `health`, `alerts`, `share`, `export` |
| `backend/app/jobs.py` | In-process scheduler (health checks, probes, PTR enrichment, alert evaluation) |
| `backend/app/share.py` | Share-token signing, public payload shaping, storage helpers |
| `backend/app/retention.py` | Raw archiving and opt-in report pruning |
| `backend/app/models.py` | SQLModel schema — the source of truth for Alembic |
| `backend/migrations/` | Alembic revisions (`0001` baseline, `0002` health/probes/jobs, `0003` alerts, `0004` ASN, `0005` share links + mute, `0006` DMARCbis fields, `0007` annotations, `0008` source expectations, `0009` alert overrides/retry, `0010` domain tags, `0011` saved fleet views, `0012` report errors, `0013` audit log, `0014` IP FCrDNS, `0015` global alerts/domain HELO) |
| `frontend/src/` | `pages/`, `components/`, `state.tsx`, `api.ts`, `types.ts`, `styles.css` |
| `samples/` | Hand-written CRLF `.eml` fixtures used by the test suite |
| `scripts/` | GeoIP/demo helpers and the DeepSeek release-note generator |
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
Servers that reject it are handled by a newest-first scan fallback in `JMAPClient`. Normal
sync uses a cursor with one day of overlap; `sync --days/--all` exists for mailbox backfills.
`mailbox-debug` is the read-only way to inspect why a message/payload was skipped.

**DKIM selectors cannot be enumerated.** Stalwart rotates date-based selectors
(`v1-ed25519-20260101`). Selectors discovered from report `auth_results` are always checked;
date variants around today cover the gap after a rotation; manual selectors are an extra.
Never hardcode a selector list as the only source.

**Health checks degrade to `unknown`, never `fail`,** when DNS or HTTP is unavailable.
Checks receive injected `dns`/`http` clients; tests must use fakes, never the network.
`MTA-STS`'s `id` is an opaque change marker, not a hash.

**TLS probes verify certificates via certifi** (interpreter CA stores are often stale). They
never authenticate, never send mail, and only connect to MX hosts plus configured targets.

**Policy simulation is read-only.** `app/simulation.py` projects a proposed policy from stored
reports; it must never write DNS, reports or policy state. Foreign header-from rows are excluded
from impact, and the comparison baseline is the latest report (not live DNS).

**Timeline annotations are private.** `domain_annotations` is admin-only and must never appear
in share payloads. Derived timeline events are computed from snapshots/alerts/identities; they
are not a second source of truth.

**Restore takes a safety snapshot and requires --yes.** `restore_database` verifies the
snapshot and replaces the live SQLite file; stop the web process first. Archives are separate.

**The weekly digest is opt-in and uses its own recipients.** `DIGEST_ENABLED` gates the job;
`DIGEST_TO` falls back to `ALERT_TO`. It must not send through the alert dedupe path.

**Known-sender expectations suppress noise, not evidence.** `source_expectations` only skips
new-source *findings*; it never hides reports, sources or history.

**Audit events are append-only while retained and must not contain secrets.** `app/audit.py`
records admin actions; never include passwords, tokens, raw report contents or alert-channel
credentials in `detail`. Optional `AUDIT_RETENTION_DAYS` prunes old rows; it is not a backdoor
for normal editing.

**Per-domain alert overrides are layered over global rules.** Preserve dedupe/resolution
semantics; disabling an override must resolve open events, not leave them stale.

**External rua=/ruf= destinations require _report._dmarc authorization.** The DMARC check
queries `_report._dmarc.<destination>` for destinations outside the policy domain and reports
an unauthorized warning; keep this read-only and subject to the same fake-DNS tests.

**DMARCbis policy discovery is additive.** `check_dmarc` keeps the author-domain behaviour;
only when `_dmarc.<domain>` has no valid record does `health/dmarcbis.py` walk parents (max
eight queries), select the org/PSD record via `psd=`, apply `sp=`/`np=`/`t=`, and report an
inherited warning. Do not replace the author path with the tree walk.

**Sender identities group by envelope/header domain plus external DKIM domain, not by IP.**
The same IP can send for several recipient domains (and one ESP rotates many IPs), so
grouping on IP alone merges unrelated senders — there is a regression test for this. ASN/PTR
is display context, not part of the identity key.

**Share tokens are stored only as SHA-256 hashes.** Never log or persist the raw token. The
public payload may include sources only when the link allows it, and must always strip
envelope from/to, identities and other header-from domains. Public responses set
`no-referrer`, `noindex` and `no-store`.

**Off-box backups bundle the database and archive.** Scheduled/manual backups upload a `.tar.gz` containing the SQLite snapshot and `data/archive/`; never include `.env`, tokens or credentials. Restore accepts `.db` or `.tar.gz` and takes a safety snapshot first.

**Retention archives raw payloads before deleting anything.** `app/retention.py` writes
`data/archive/YYYY/MM/` first, then removes reports and child rows; `--yes` is required for a
real run, and the scheduler only enables it when `RETENTION_DAYS > 0`. Processed-message
dedupe keys are intentionally retained.

**Scheduled checks honour `domain_settings.dns_checks_enabled` and `checks_muted_until`;
manual runs deliberately ignore the mute.**

**Alert rules are domain-scoped by default; `sync_failure` and `job_failure` are global.** Global events have
`domain_id = NULL` and cannot be overridden per domain. Do not assume every `AlertEvent` has a
domain.

**Alerts dedupe on `(rule, domain, dedupe_key)` while an incident is open.** A new episode is
suppressed until the rule's cooldown passes; when the condition clears the open event is
resolved and a resolution notice is sent. Do not create a second open event for the same key.

**Email transport is selected explicitly or automatically.** `EMAIL_TRANSPORT=auto` prefers
fully configured SMTP, falls back to JMAP on SMTP failure, and uses JMAP when SMTP is absent.
`EMAIL_TRANSPORT=jmap` forces JMAP. JMAP submission reuses `JMAP_URL`/`JMAP_TOKEN` (or basic
auth) and `JMAP_FROM`; it goes through `EmailSubmission/set`, not a second SMTP client.

**Alert channel credentials live only in the environment** (`SMTP_*`, `JMAP_*`, `TELEGRAM_*`,
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
- Release images get their version from the tag via the `APP_VERSION` Docker build argument;
  the workflow writes the tag version into `backend/app/version.py` before building, so a
  forgotten manual version bump cannot block a release.
- The release job generates notes with `scripts/generate_release_notes.py`. It uses
  `DEEPSEEK_API_KEY` when configured and falls back to GitHub generated notes. Never commit
  the token or print it; it is an Actions secret.
- The workflow runs the tests and a frontend build before publishing, and attaches SBOM +
  provenance attestations.
- After a successful tag publish it creates the GitHub Release automatically: AI-generated or
  fallback notes plus the Full Changelog link, image reference and digest. Re-running the
  workflow leaves an existing release untouched, so hand-edited notes are safe.
- Web Markdown (release notes included) must not use manual line wraps: one line per paragraph
  and per bullet, blank lines only between blocks.

## Roadmap

`docs/ROADMAP.md` is a plan, not an automatic backlog. Do not implement roadmap items unless
the user asks for them. Export, fleet comparison, retention, DMARCbis and decision support are
delivered, including v1.20 transport health visibility, TLS no-policy labelling, host backfill and DKIM evidence drill-downs. No mandatory roadmap work remains. MFA stays
parked; RUF and platform work remain optional/trigger-based.

## Security expectations

Single-admin session auth with PBKDF2, origin checks, CSP and a login throttle. Never weaken
these to make a feature easier. Do not log credentials, bearer tokens or report contents.
Outbound connections are limited to the configured JMAP server, DNS resolvers, certificate
probes, the explicit GeoIP download and the configured WebDAV/S3 backup targets. The public share endpoint is unauthenticated but
must stay read-only, token-scoped, rate-limited and covered by the stripping rules above.
