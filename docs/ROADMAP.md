# Roadmap

_Rev 3 · 24 November 2026 · after shipping Phase 0 and domain/transport health_

v1 answered **"what happened?"**; this iteration adds **"is my configuration correct?"**.
Next comes **"tell me when it changes"** (alerting), then read-only sharing and export.

## Delivered in this iteration

| Area | What shipped |
| --- | --- |
| **Migrations** | Alembic baseline (`0001`) plus `0002` for the new tables. v1 databases are stamped automatically and upgraded in place on start. `python -m app.cli migrate`. |
| **Scheduler** | In-process job runner with overlap guards, jitter, initial delay and `job_runs` history. Jobs: health checks, transport probes, PTR enrichment. No Redis/Celery. |
| **Domain settings** | Per-domain DKIM selectors, extra probe targets, expected report interval, check toggle — with a settings form on the Health page. |
| **Domain health** | Live checks for DMARC (incl. drift vs. reports), SPF (recursive, 10-lookup/2-void limits), DKIM (selectors, key size), MX, MTA-STS (policy fetch, mode/mx/max_age), TLS-RPT, DNSSEC (AD), BIMI. Snapshot history, dashboard card, full Health page. |
| **Transport probes** | MX :25 (STARTTLS) plus configurable submission/IMAP/HTTPS targets. Chain and hostname verification, expiry days, TLS version/cipher, DANE/TLSA matching. No auth, no mail sent. |
| **PTR enrichment** | Reverse DNS for sending IPs, shown under the source in the Sending sources table. |
| **Storage & backups** | `python -m app.cli backup` (consistent SQLite snapshot, integrity-checked, rotated), storage/growth panel, jobs panel. Retention stays **off by default**. |
| **Tests** | 64 backend tests, including every health check against fixtures, probe parsing, a local TLS server, migration upgrade path and the health API. |

Known limits: DNSSEC relies on the resolver's AD flag (no explicit chain validation);
BIMI verifies presence only; probes require outbound port 25; alerting is not built yet.

## Decisions locked in (24 Nov 2026)

| # | Decision | Consequence |
| --- | --- | --- |
| 1 | **SMTP** alerts, **Telegram** and **Signal** as extra channels | Phase 1 ships SMTP + Telegram; Signal behind the same interface once a `signal-cli` sidecar exists. |
| 2 | App **may probe MX on 25** (and other mail ports) | Delivered: live STARTTLS, certificate and DANE checks. |
| 3 | **No off-box backup target yet**, retention undecided | Keep-forever default, local rolling snapshots, growth panel; retention stays opt-in. |
| 4 | **Single admin**; read-only **share links without authentication** | OIDC/SSO stays dropped. Share links (Phase 3) use signed, revocable tokens. |

## Remaining sequence

| Phase | Theme | Effort | Status |
| --- | --- | --- | --- |
| **1** | Alerting: rules engine + SMTP/Telegram (Signal later) | 6–8 d | next |
| **3** | Share links, export, fleet comparison table | 6–8 d | planned |
| **4** | Forensic (RUF) reports | 3–4 d | planned |
| **5** | Platform: Postgres, IMAP, API tokens, metrics | 8–10 d | trigger-based |
| **6** | Analytics depth: identities, anomalies, DMARCbis | 6–10 d | planned |

≈ **29–40 focused engineer-days** remaining, tests included. Phase 1 is the only piece that
turns the product from pull to push; everything after it is optional depth.

---

## Phase 1 — Alerting (6–8 days)

### Rules engine

```text
alert_rules(id, name, kind, domain_id?, condition JSON, severity, enabled, cooldown_minutes)
alert_channels(id, kind, config JSON, enabled)
alert_events(id, rule_id, domain_id, dedupe_key, severity, payload JSON,
             triggered_at, resolved_at, delivered_at, error)
```

- Evaluate hourly **and** after a sync; the first run warms a baseline instead of firing on
  30 days of history.
- Cooldown/dedupe on `(rule, domain, dedupe_key)`: one message per incident plus a resolution
  notice. Delivery failures are recorded, retried with backoff, never block ingestion.
- Per-domain overrides, "mute for N days", and a "send test" button per channel.

| Rule | Default condition | Uses |
| --- | --- | --- |
| `compliance_drop` | aligned < 95 % over 24 h and ≥ 10 messages | reports |
| `new_source` | unseen IP/domain sends ≥ 5 messages | reports |
| `dkim_break` | a previously aligned source starts failing DKIM | reports |
| `tls_failure` | any failed sessions, or success < 95 % over 24 h | TLS-RPT |
| `report_gap` | no reports for `expected_report_hours` (48 h) | reports + domain settings |
| `volume_spike` | daily messages > 3× the trailing 28-day median | reports |
| `policy_drift` | live DNS policy ≠ latest reported policy, or record changed | **health snapshots** |
| `cert_expiry` | any probe target < 21 days (warn) / < 7 days (fail) | **probes** |
| `starttls_broken` | a previously passing probe now fails | **probes** |

The last three plug straight into data this iteration already stores.

### Channels

A `Channel` protocol (`send(alert) -> DeliveryResult`), one module per transport.

| Channel | Config | Notes |
| --- | --- | --- |
| **SMTP** | `SMTP_HOST`, `SMTP_PORT` (587/465), `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_TO` | Default. stdlib `smtplib` + `EmailMessage`; works with Stalwart submission or any relay. |
| **Telegram** | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Bot API `sendMessage`; HTML, 4096-char split, honour 429 `retry_after`. |
| **Signal** | `SIGNAL_API_URL`, `SIGNAL_NUMBER`, `SIGNAL_RECIPIENTS` | Needs a self-hosted `signal-cli-rest-api` sidecar and a linked number. Documented, not bundled — adds ~1 day once the sidecar exists. |
| **Webhook** | `WEBHOOK_URL`, `WEBHOOK_SECRET` | HMAC-signed JSON; doubles as ntfy/Matrix hook. |

### UI & acceptance
Alerts page with rules, channel cards, test buttons, event history and delivery errors; a
header bell for unresolved alerts. A rule fires once, survives restart, respects cooldown,
resolves, and never double-sends. Tests freeze the clock and mock each channel.

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

1. **Signal:** is a `signal-cli` sidecar already running, or should Signal follow SMTP +
   Telegram?
2. **Off-box backup:** when a target appears, the local snapshot format is what it should
   sync; name the target before Phase 3 closes.
3. **Retention:** revisit once the storage panel shows real growth; the mechanism is not
   built, only the numbers are.
