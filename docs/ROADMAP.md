# Roadmap

_Rev 6 · 24 November 2026 · analytics foundation delivered_

v1 answered **"what happened?"**; v1.1 added **"is my configuration correct?"**; v1.2 adds
**"tell me when it changes"**. The analytics foundation now goes deeper on **why it changed**:
sender identities and period-over-period deltas. Coverage and anomaly scoring remain before
distribution (share links/export).

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
| **Tests** | 75 backend tests: parsers, ingestion, API, auth, mocked JMAP, health checks/probes, migration path, alerts, report-gap, identities, period changes. |

Known limits: DNSSEC relies on the resolver's AD flag (no chain validation); BIMI checks
presence only; probes need outbound port 25; alert rules are global (no per-domain overrides
or mute yet) and failed deliveries are recorded but not retried.

## Decisions locked in

| # | Decision | Consequence |
| --- | --- | --- |
| 1 | **SMTP + Telegram + Signal + webhook** alerts | Delivered. Signal runs through a `signal-cli` sidecar. |
| 2 | App **may probe MX on 25** and other mail ports | Delivered: STARTTLS, certificates, DANE. |
| 3 | **No off-box backup target yet**, retention undecided | Keep-forever default, local snapshots, growth panel; retention opt-in. |
| 4 | **Single admin**; read-only **share links without authentication** later | No OIDC/SSO. Share links use signed, revocable tokens when built. |
| 5 | **Analytics before sharing** (Rev 5, 24 Nov 2026) | No technical dependency; for a single-admin deployment, explaining changes is worth more than distributing them. Share links can move forward at any time if external access becomes necessary. |

## Remaining sequence

| Phase | Theme | Effort | Status |
| --- | --- | --- | --- |
| **6a.3** | Analytics remainder: coverage + anomaly scoring | 1–2 d | **next** |
| **3.1** | Read-only share links | 2–3 d | planned |
| **3.2–3.3** | Export + fleet comparison table | 3–4 d | planned |
| **4** | Forensic (RUF) reports | 3–4 d | optional |
| **5** | Platform: Postgres, IMAP, tokens, metrics | 8–10 d | trigger-based |
| **6b** | DMARCbis readiness | 2–4 d | when the RFC is final |

≈ **19–27 focused engineer-days** remaining, tests included. Everything after 6a.3 is
independent and can be reordered without rework.

---

## Phase 6a — Analytics depth (foundation delivered)

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

### Remaining (1–2 days)

- **Coverage:** reporter coverage per domain, subdomain coverage vs `sp=`, `pct` ramp timeline.
- **Anomaly scoring:** robust z-score/MAD against a trailing 28-day baseline, feeding the
  existing `volume_spike` rule instead of duplicating alerting. Deltas are currently exact
  period-over-period numbers, not anomaly scores.

---

## Phase 3 — Share links, export, fleet (6–8 days)

Can move ahead of 6a if external sharing becomes urgent; it shares no code with analytics.

### 3.1 Read-only share links (2–3 d)

- Token: `base64url(payload) + "." + base64url(HMAC-SHA256)`, payload
  `{v, id, domain, days, include_sources, exp}`; link at `/s/<token>` (path, so it never
  leaks through `Referer`).
- Storage: `share_links(id, token_hash, domain, days, include_sources, created_at,
  expires_at, revoked_at, last_used_at, uses)`; only the hash is stored.
- API: `/api/public/<token>/…` serves dashboard and TLS summaries only — no raw reports, no
  search, no ingest, no alert config; envelope from/to stripped even when sources are shown.
- Hardening: `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, `no-store`, no cookies,
  per-token rate limit, 7-day default / 90-day cap.
- UI: Share button with scope/expiry/include-sources, active links with revoke, read-only
  shared shell with a "shared view" badge.

### 3.2 Export (2 d)

Streamed `reports.csv|json`, `sources.csv`, `tls.csv` with current filters; capped
`raw.zip` (500 reports / 200 MB); "Export current view" buttons.

### 3.3 Fleet comparison (1–2 d)

Sortable domain table: messages, aligned %, failing sources, last report, TLS success,
policy, health, sparkline, click-through.

### 3.4 Retention (0.5 d)

Opt-in only: `RETENTION_DAYS`, archive raw payloads to `data/archive/YYYY/MM/` before
pruning, `cli prune --dry-run`. The storage panel already shows growth.

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

Done: report-gap banner, copy-to-clipboard for policies and report IDs.

Remaining (<1 day each):

- Print stylesheet for the dashboard.
- Editable domain display names and notes (`domains.notes` already exists).
- Filters (domain, period, search) persisted in the URL.
- Per-domain mute for scheduled checks.

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

1. **Off-box backup:** when a target appears, the local snapshot format is what it syncs.
2. **Retention:** revisit once the storage panel shows real growth.
3. **Alert follow-ups:** per-domain overrides and delivery retry after real-world use.
4. **Share-link defaults:** expiry and whether "include sources" is allowed.
