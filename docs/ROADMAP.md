# Roadmap

_Rev 4 · 24 November 2026 · after shipping alerting_

v1 answered **"what happened?"**; v1.1 added **"is my configuration correct?"**; v1.2 adds
**"tell me when it changes"**. Next comes read-only sharing and export, then retention.

## Delivered so far

| Area | What shipped |
| --- | --- |
| **Migrations** | Alembic baseline (`0001`) plus `0002` for the new tables. v1 databases are stamped automatically and upgraded in place on start. `python -m app.cli migrate`. |
| **Scheduler** | In-process job runner with overlap guards, jitter, initial delay and `job_runs` history. Jobs: health checks, transport probes, PTR enrichment, alert evaluation. No Redis/Celery. |
| **Domain settings** | Per-domain DKIM selectors, extra probe targets, expected report interval, check toggle — with a settings form on the Health page. |
| **Domain health** | Live checks for DMARC (incl. drift vs. reports), SPF (recursive, 10-lookup/2-void limits), DKIM (selectors, key size), MX, MTA-STS (policy fetch, mode/mx/max_age), TLS-RPT, DNSSEC (AD), BIMI. Snapshot history, dashboard card, full Health page. |
| **Transport probes** | MX :25 (STARTTLS) plus configurable submission/IMAP/HTTPS targets. Chain and hostname verification, expiry days, TLS version/cipher, DANE/TLSA matching. No auth, no mail sent. |
| **PTR enrichment** | Reverse DNS for sending IPs, shown under the source in the Sending sources table. |
| **Storage & backups** | `python -m app.cli backup` (consistent SQLite snapshot, integrity-checked, rotated), storage/growth panel, jobs panel. Retention stays **off by default**. |
| **Alerting** | Nine rules over reports, health snapshots and probes; hourly + manual evaluation; dedupe/cooldown/resolution; SMTP, Telegram, Signal (signal-cli) and signed webhook channels; editable thresholds; incident history. |
| **Tests** | 72 backend tests, including every health check against fixtures, probe parsing, a local TLS server, migration upgrade path, the health API, and alert evaluation/dedupe/resolution with mocked delivery. |

Known limits: DNSSEC relies on the resolver's AD flag (no explicit chain validation);
BIMI verifies presence only; probes require outbound port 25; alert rules are global (no
per-domain overrides or mute yet) and failed deliveries are recorded but not retried.

## Decisions locked in (24 Nov 2026)

| # | Decision | Consequence |
| --- | --- | --- |
| 1 | **SMTP** alerts, **Telegram** and **Signal** as extra channels | Delivered: SMTP, Telegram, Signal (via a `signal-cli` sidecar) and a signed webhook. |
| 2 | App **may probe MX on 25** (and other mail ports) | Delivered: live STARTTLS, certificate and DANE checks. |
| 3 | **No off-box backup target yet**, retention undecided | Keep-forever default, local rolling snapshots, growth panel; retention stays opt-in. |
| 4 | **Single admin**; read-only **share links without authentication** | OIDC/SSO stays dropped. Share links (Phase 3) use signed, revocable tokens. |

## Remaining sequence

| Phase | Theme | Effort | Status |
| --- | --- | --- | --- |
| **3** | Share links, export, fleet comparison table | 6–8 d | next |
| **4** | Forensic (RUF) reports | 3–4 d | planned |
| **5** | Platform: Postgres, IMAP, API tokens, metrics | 8–10 d | trigger-based |
| **6** | Analytics depth: identities, anomalies, DMARCbis | 6–10 d | planned |

≈ **23–32 focused engineer-days** remaining, tests included. Alerting was the only piece that
turns the product from pull to push; everything now is depth and sharing.

---

## Delivered: alerting (v1.2)

Nine rules, evaluated hourly and from the Alerts page, over reports, health snapshots and
probes. Incidents are deduplicated while open, repeat episodes respect a cooldown, and a
resolution notice is sent when the condition clears. Thresholds, enablement and cooldown are
editable per rule.

Schema: `alert_rules` (kind, condition JSON, enabled, cooldown) and `alert_events`
(rule, domain, dedupe_key, severity, payload, triggered_at, resolved_at, delivered_at,
delivery_error). Channel credentials stay in the environment, never in SQLite.

| Rule | Default | Uses |
| --- | --- | --- |
| `compliance_drop` | aligned < 95 %, ≥ 10 messages, 24 h | reports |
| `new_source` | unseen IP, ≥ 5 messages, 24 h | reports |
| `dkim_break` | previously passing source now fails, 14 d lookback | reports |
| `tls_failure` | TLS success < 95 %, ≥ 5 sessions | TLS-RPT |
| `report_gap` | no report within expected interval + grace | reports + settings |
| `volume_spike` | ≥ 3× trailing 28-day median, ≥ 20 messages | reports |
| `policy_drift` | DNS p ≠ latest reported p | health snapshots |
| `cert_expiry` | ≤ 21 d (warning), < 7 d (critical) | probes |
| `starttls_broken` | probe fails without a certificate error | probes |

Channels: SMTP, Telegram, Signal (signal-cli REST), webhook (HMAC-signed). "Run now" and a
per-channel "Send test" live on the Alerts page; with no channel configured incidents are
still recorded and the page names the missing variables.

Deliberately left for later: per-domain overrides, "mute for N days", a header bell for
unresolved incidents, and delivery retry with backoff (failures are recorded on the event
and shown in the UI).

---

## Phase 3 — Share links, export, fleet (6–8 days)

### 3.1 Unauthenticated read-only share links (2–3 d)
Replaces viewer accounts, so the constraints matter more than the UI.

- **Token:** `base64url(payload) + "." + base64url(HMAC-SHA256)`, payload
  `{v, id, domain, days, include_sources, exp}`; link at `/s/<token>` (path, so it never
  leaks through Referer).
- **Server model:** `share_links(id, token_hash, domain, days, include_sources, created_at,
  expires_at, revoked_at, last_used_at, uses)`. Only the hash is stored; links are revocable
  and their last use is visible.
- **API:** `/api/public/<token>/…` serves the dashboard and TLS summaries only. No raw
  reports, no report search, no ingest, no alert config; envelope from/to stripped even when
  sources are included.
- **Hardening:** `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, `no-store`, no
  cookies, per-token rate limit, expiry capped at 90 days (default 7).
- **UI:** Share button → scope, expiry, include-sources; active links with revoke. Public
  view is the same dashboard in a read-only shell with a "shared view" badge.

### 3.2 Export (2 d)
- `GET /api/export/reports.csv|json`, `/sources.csv`, `/tls.csv` with the UI's filters,
  streamed.
- `GET /api/export/raw.zip?domain=&from=&to=` — streamed ZIP of original XML/JSON, capped
  (500 reports / 200 MB).
- "Export current view" buttons in the report and TLS tables.

### 3.3 Fleet comparison table (1–2 d)
The fleet view currently shows KPIs, policy per domain and health. Add a sortable domain
table: messages, aligned %, failing sources, last report, TLS success, policy, health,
sparkline, click-through.

### 3.4 Retention (0.5 d)
Still opt-in. When a decision is made: `RETENTION_DAYS`, archive raw payloads to
`data/archive/YYYY/MM/` before pruning, `cli prune --dry-run`. The storage panel already
provides the growth numbers.

---

## Phase 4 — Forensic / RUF reports (3–4 days)

Low priority: most receivers disable RUF.

- Parse ARF (`multipart/report; report-type=feedback-report`): `Feedback-Type`,
  `Authentication-Results`, `Original-Mail-From`, `Source-IP`, `Reported-Domain`.
- **Headers and failed auth results only**, never bodies; subject/recipient redacted by
  default. Per-domain opt-in, daily row cap, shorter retention.
- Link forensic failures to the source IP row ("3 forensic reports").

---

## Phase 5 — Platform (8–10 days)

### 5.1 PostgreSQL (2–3 d)
Trigger: >10 M source records, multiple instances, external BI. Audit `func.date()`,
`ILIKE`, JSON operators and boolean comparisons in [analytics.py](../backend/app/analytics.py);
add a SQLite + Postgres CI matrix.

### 5.2 IMAP transport (3 d)
`imaplib` behind the same interface as [JMAPClient](../backend/app/ingest/jmap.py):
`UIDVALIDITY` persistence, `IDLE` with polling fallback, `BODY.PEEK[]`, handled flag/move,
`MAIL_SOURCE=imap`.

### 5.3 API tokens, metrics, ingestion webhook (2–3 d)
Read-only bearer tokens (`dvc_…`, hashed, per-domain scope), Prometheus `/api/metrics`
(ingest lag, report counts, failed probes, cert expiry), optional webhook on new reports.

### 5.4 SSO — parked
Single admin by decision. If that changes: Authlib/OIDC or `AUTH_MODE=header` behind a reverse
proxy; neither is scheduled.

---

## Phase 6 — Analytics depth (6–10 days)

- **Sender identity grouping** by envelope domain / DKIM domain, not just IP, so "the CRM" is
  one row instead of 40 rotating addresses.
- **Reporter coverage & gaps** per domain, catching silent `rua` problems individually.
- **Subdomain coverage** vs `sp=`, flagging subdomains with no policy.
- **`pct` ramp tracking** as a timeline (25 → 50 → 100).
- **Anomaly detection** (z-score vs trailing 28-day baseline) feeding `volume_spike` and a
  "what changed" diff against the previous period.
- **DMARCbis readiness** once the RFC is final: testing flag, non-existent-subdomain policy,
  tightened syntax.

---

## Quick wins (each < 1 day)

- CSV export of the current table (before Phase 3).
- "Report gap" banner on the dashboard when a domain has had no report for 48 h.
- Print stylesheet for the dashboard.
- Editable domain display names and notes (`domains.notes` already exists).
- Filters (domain, period, search) persisted in the URL.
- Copy-to-clipboard for policy strings and report IDs.
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

1. **Off-box backup:** when a target appears, the local snapshot format is what it should
   sync; name the target before Phase 3 closes.
2. **Retention:** revisit once the storage panel shows real growth; the mechanism is not
   built, only the numbers are.
3. **Alert follow-ups:** whether per-domain overrides and delivery retry are worth the
   complexity after real-world use.
