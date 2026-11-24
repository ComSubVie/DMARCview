# Roadmap

_Rev 11 · 24 November 2026 · retention delivered (v1.7)_

v1 answered **"what happened?"**; v1.1 added **"is my configuration correct?"**; v1.2 added
**"tell me when it changes"**; v1.4 completed **why it changed**; v1.5 added signed read-only
sharing; v1.6 added export and a sortable fleet; v1.7 adds opt-in retention with raw
archiving. RUF and platform work remain trigger-based.

## Delivered so far

| Area | What shipped |
| --- | --- |
| **Migrations** | Alembic `0001` baseline, `0002` health/probes/jobs/settings, `0003` alerts, `0004` ASN metadata. Existing databases upgrade in place on start; `python -m app.cli migrate`. |
| **Scheduler** | In-process runner with overlap guards, jitter, initial delay and `job_runs`. Jobs: health checks, transport probes, PTR enrichment, alert evaluation. No Redis/Celery. |
| **Domain settings** | Per-domain DKIM selectors, extra probe targets, expected report interval, check toggle. |
| **Domain health** | DMARC (incl. drift vs reports), SPF (10-lookup/2-void), DKIM, MX, MTA-STS, TLS-RPT, DNSSEC, BIMI; snapshot history and Health page. |
| **Transport probes** | MX :25 STARTTLS plus submission/IMAP/HTTPS targets; chain/hostname/expiry, TLS version/cipher, DANE/TLSA. No auth, no mail sent. |
| **Alerting** | Nine rules over reports, snapshots and probes; hourly + manual; dedupe/cooldown/resolution; SMTP, Telegram, Signal (signal-cli) and signed webhook; editable thresholds, history and test buttons. |
| **PTR enrichment** | Reverse DNS for sending IPs, shown under each source. |
| **Storage & backups** | Consistent SQLite snapshots with rotation, storage/growth panel, jobs panel. Retention stays **off by default**. |
| **Dashboard polish** | Report-gap banner when a domain misses its expected interval; copy buttons for DMARC/TLS policy strings and report IDs. |
| **Analytics foundation** | Sender identities grouped by envelope/header domain + external DKIM domain, with ASN/PTR context; DB-IP ASN Lite fetched by default and backfilled into `ip_meta`; "what changed" chips and new-identity list; full identity drawer. |
| **Anomaly score** | Robust z-score (MAD, standard-deviation fallback when MAD is 0) of the latest reporting day against the trailing 28-day baseline; shown on the volume card when \|z\| ≥ 2 and used by the `volume_spike` alert rule (`min_z`). |
| **URL filters** | Domain and period persist in `?domain=&days=`, so dashboard views are bookmarkable and survive reloads. |
| **Coverage** | Reporter coverage (silent reporters vs the previous period), other header-from domains checked against the effective `sp=` policy, and the `pct=` ramp timeline. |
| **Share links** | HMAC-signed, expiring, revocable read-only links; only token hashes stored; public dashboard/TLS view with sources optional and envelope identities stripped; usage tracking and revoke. |
| **Quick wins** | Print stylesheet, editable domain display name/notes, report search persisted in the URL, and per-domain mute for scheduled health checks/probes (now actually honoured by the scheduler). |
| **Export** | Reports CSV/JSON, sources CSV and TLS CSV with current filters; capped `raw.zip` (500 reports / 200 MB) and export actions in the UI. |
| **Fleet comparison** | Sortable domain table with volume, alignment, failing sources, last report, TLS success, policy, health and a 14-day sparkline; click-through to the domain. |
| **Retention** | Opt-in `RETENTION_DAYS`; raw XML/JSON archived to `data/archive/YYYY/MM/` before deleting reports and child rows; dry-run CLI and daily scheduler job. |
| **Tests** | 90 backend tests: parsers, ingestion, API, auth, mocked JMAP, health checks/probes, migration path, alerts, report-gap, identities, period changes, anomaly scoring, coverage, share links, domain profile, check mute, GeoIP backfill, export, fleet and retention. |

Known limits: DNSSEC relies on the resolver's AD flag (no chain validation); BIMI checks
presence only; probes need outbound port 25; alert rules are global (no per-domain overrides
or mute yet) and failed deliveries are recorded but not retried.

## Decisions locked in

| # | Decision | Consequence |
| --- | --- | --- |
| 1 | **SMTP + Telegram + Signal + webhook** alerts | Delivered. Signal runs through a `signal-cli` sidecar. |
| 2 | App **may probe MX on 25** and other mail ports | Delivered: STARTTLS, certificates, DANE. |
| 3 | **No off-box backup target yet**; retention is opt-in | Keep-forever default; when enabled, raw payloads are archived locally before pruning. Off-box backup is still open. |
| 4 | **Single admin**; read-only **share links without authentication** | Delivered: signed, revocable tokens at `/s/<token>`, default 7 days, 90-day cap. No OIDC/SSO. |
| 5 | **Analytics before sharing** (Rev 5, 24 Nov 2026) | No technical dependency; for a single-admin deployment, explaining changes is worth more than distributing them. Share links can move forward at any time if external access becomes necessary. |

## Remaining sequence

| Phase | Theme | Effort | Status |
| --- | --- | --- | --- |
| **4** | Forensic (RUF) reports | 3–4 d | optional / next |
| **5** | Platform: Postgres, IMAP, tokens, metrics | 8–10 d | trigger-based |
| **6b** | DMARCbis readiness | 2–4 d | when the RFC is final |

≈ **13–18 focused engineer-days** remaining, tests included. RUF and platform work are both
optional and can be reordered freely.

---

## Phase 6a — Analytics depth (complete)

### Delivered

- **Sender identities.** Sources are grouped by envelope/header domain + external DKIM domain.
  Rotating addresses of one ESP collapse into one row; the same IP serving two recipient
  domains no longer merges them (regression test). ASN/PTR appears as network context.
- **ASN enrichment.** `scripts/fetch_geoip.py` downloads DB-IP ASN Lite (CC BY 4.0) by default,
  `ip_meta.asn`/`asn_org` store the result, and the PTR job backfills existing IPs. Identity
  grouping still works without the ASN file.
- **What changed.** Current vs previous period chips for messages, aligned points, sources and
  identities, plus the new-identity list, on the dashboard summary. The full identity table is
  available in a drawer.

- **Anomaly scoring.** The latest reporting day is compared with the trailing 28-day baseline
  using a robust z-score; when MAD is zero (runs of identical quiet days) it falls back to the
  standard deviation. The volume card shows the score when |z| ≥ 2, and `volume_spike` accepts
  a `min_z` threshold alongside the multiplier.

- **Coverage.** Reporter coverage marks reporters that were active in the previous period but
  are silent now; other header-from domains are checked against the effective `sp` (falling
  back to `p`) and flagged as covered/uncovered; the `pct=` timeline shows the ramp from the
  first to the latest value.
- **URL filters.** Domain and period are in the URL, so a dashboard view can be bookmarked or
  shared.

Phase 6a is complete; the next slice is distribution.

---

## Phase 3 — Export, fleet, retention

### 3.1 Read-only share links (delivered)

- Token: `base64url(payload) + "." + base64url(HMAC-SHA256)` with `{v, id, domain, days,
  include_sources, exp}`, served at `/s/<token>` (path, so it never leaks through `Referer`).
- Storage: `share_links` keeps only the token hash, scope, expiry, revoke, last use and uses.
- Public API: dashboard/TLS summaries only — no raw reports, search, ingest or alert config.
  Sources are opt-in; envelope from/to, identities and other header-from domains are always
  stripped.
- Hardening: `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, `no-store`,
  per-token rate limit, 7-day default / 90-day cap.
- UI: topbar Share drawer with scope/expiry/include-sources, copy-once URL, active links and
  revoke; `/s/<token>` renders a read-only shell with a shared-view badge.

### 3.2 Export (delivered)

`reports.csv|json`, `sources.csv` and `tls.csv` with the current filters, plus a capped
`raw.zip` (500 reports / 200 MB). CSV, raw-ZIP and TLS export actions are in the UI.

### 3.3 Fleet comparison (delivered)

Sortable domain table with messages, alignment, failing sources, last report, TLS success,
policy, health and a 14-day sparkline; clicking a row drills into the domain.

### 3.4 Retention (delivered)

Opt-in `RETENTION_DAYS`: a daily job (or `app.cli prune`) archives raw XML/JSON to
`data/archive/YYYY/MM/`, then deletes reports and child rows older than the cutoff. `prune
--dry-run` reports counts and bytes; actual deletion requires `--yes`. Processed-message
dedupe keys are retained, and archives must be included in any off-box backup.

---

## Phase 4 — Forensic / RUF reports (3–4 days)

Optional; most receivers disable RUF.

Parse ARF (`multipart/report; report-type=feedback-report`): `Feedback-Type`,
`Authentication-Results`, `Original-Mail-From`, `Source-IP`, `Reported-Domain`. Headers and
failed auth results only — never bodies; redact subject/recipient by default; per-domain
opt-in, daily row cap, shorter retention. Link forensic failures to the source IP row.

---

## Phase 5 — Platform (8–10 days)

| Item | Effort | Trigger |
| --- | --- | --- |
| PostgreSQL | 2–3 d | >10 M source records, multiple instances, external BI; audit `func.date()`, `ILIKE`, JSON operators; SQLite+Postgres CI matrix |
| IMAP transport | 3 d | `imaplib` behind the `JMAPClient` interface: `UIDVALIDITY`, `IDLE` fallback, `BODY.PEEK[]`, handled flag |
| API tokens, metrics, webhook | 2–3 d | read-only bearer tokens (`dvc_…`, hashed, per-domain), Prometheus `/api/metrics`, optional new-report webhook |

SSO stays parked unless the single-admin decision changes.

---

## Phase 6b — DMARCbis readiness (2–4 days)

After the RFC is final:

- testing flag (`t=`), non-existent-subdomain policy (`np=`), tightened syntax;
- `pct=` handling and external reporting addresses;
- a readiness panel comparing live DNS with the stored reports;
- recommendations only — never automatic DNS changes.

---

## Quick wins

All planned quick wins are shipped: report-gap banner, copy-to-clipboard, URL-backed
domain/period/report-search filters, print stylesheet, editable domain profiles, and
per-domain scheduled-check mute.

---

## Deliberately not planned

- **OIDC / multi-user** — single admin; share links cover read-only needs.
- **BIMI VMC verification** — CA chain, trademark checks, often paid; presence only.
- **Automatic DNS changes** — recommend, never write.
- **Storing message bodies** — privacy and disk cost.
- **Multi-tenant SaaS** — one deployment, one admin.
- **Simultaneous IMAP + JMAP for one account** — one transport per deployment.

---

## Still open

1. **Off-box backup:** when a target appears, sync the SQLite snapshot and `data/archive/`.
2. **Alert follow-ups:** per-domain overrides and delivery retry after real-world use.
3. **Share-link rate limit:** currently per-process memory; revisit if multiple workers/replicas are added.
4. **RUF/PII policy:** decide whether forensic reports are worth the extra handling before Phase 4.
