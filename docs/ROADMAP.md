# Roadmap

_Rev 28 · 25 November 2026 · remote restore and retention (v1.18.1)_

DMARCView began as a self-hosted answer to **“what happened?”** and grew into a complete
reporting and operations dashboard: **“is my configuration correct?”**, **“tell me when it
changes”**, **“why did it change?”**, **“what should I do next?”**, and now **“can I prove what
changed and who changed it?”**.

**Current development release: v1.18.1.** The mandatory roadmap is complete. What remains is
optional, trigger-based or deliberately parked work.

## Delivered

| Area | What is available |
| --- | --- |
| **Ingestion** | JMAP polling with incremental cursor and full-mailbox backfill; DMARC RUA from zip/gzip/inline; TLS-RPT; idempotent message/attachment/report dedupe; raw report browser and downloads. |
| **Analytics** | Compliance, sources, sender identities, ASN/PTR context, period changes, volume anomaly, coverage, reporter quality, TLS delivery, policy advisor and a read-only policy simulator. |
| **Health** | Live DMARC (including RFC 9989 tree walk/PSD), SPF, DKIM rotation, MX with PTR checks, MTA-STS (including MX-consistency), TLS-RPT, DNSSEC, BIMI, CAA, HELO/EHLO DNS; transport STARTTLS/certificate/DANE probes; snapshot history and DNS diffs. |
| **Alerts** | Thirteen rules over reports, health snapshots, jobs and probes, including health regression, JMAP sync failure, scheduled-job failures and stale off-box backups; SMTP/JMAP email, Telegram/Signal/webhook; dedupe, cooldown, resolution; per-domain overrides; delivery retry; weekly digest. |
| **Distribution** | Signed read-only share links; CSV/JSON/raw export; sortable fleet comparison; domain tags/groups; saved fleet views. |
| **Operations** | Scheduler and job history; local SQLite backup plus WebDAV/S3 off-box bundles; verified restore; retention with raw archiving; known-sender expectations; append-only audit log; PTR/FCrDNS enrichment for sending IPs. |
| **Signal quality** | Every TLS-RPT policy domain attributed separately; RFC 9990 report warnings; DMARC/SPF/MTA-STS/TLS-RPT change history. |
| **DMARCbis** | Report fields `np`, `testing`, `discovery_method`; parent/PSD discovery; external `rua`/`ruf` authorization; readiness panel; effective-policy coverage. Existing author-domain logic is unchanged. |

## Recent releases

- **v1.18 — remote restore, retention and contextual health.** Fetch/verify/restore remote bundles, test backup targets, prune audit rows, and add BIMI/DANE/SPF-aware advice, a fleet Next action and check deep links.
- **v1.17 — backup verification and restore.** Remote checksum verification, stale-backup alerts, a Back up now action, backup audit events and archive extraction on restore.
- **v1.16 — off-box backups.** Scheduled or manual local snapshots bundled with the raw archive and uploaded to WebDAV and/or S3-compatible storage.
- **v1.15 — alert coverage and per-domain HELO.** Health-check regression, global JMAP-sync and health/probe-job alerts, domain-specific HELO/EHLO hostnames, and clearer HELO DNS-versus-outbound wording.
- **v1.14 — network checks.** Sending-IP PTR/FCrDNS, MX PTR confirmation, MTA-STS MX consistency, optional HELO/EHLO DNS readiness and CAA checks.
- **v1.13 — JMAP email transport.** Alerts and the weekly digest can send through SMTP or
  Stalwart JMAP `EmailSubmission`, using `ALERT_TO`/`DIGEST_TO` and `JMAP_FROM`.
- **v1.12 — operator visibility.** Editable per-domain alert overrides, dedicated DNS diff view,
  report-quality scores, delivery attempts/manual retry, digest controls and an audit log
  without MFA.
- **v1.11 — saved views and signal quality.** Named fleet filter/sort presets, TLS policy
  attribution per policy domain, RFC 9990 report warnings, DNS change history.
- **v1.10 — operational confidence.** Restore, weekly digest, reporter quality, known senders,
  alert overrides/retry and domain groups.
- **v1.9 — decision support.** Read-only policy simulator and private domain timeline.
- **v1.8 — DMARCbis.** RFC 9989 discovery, PSD, readiness panel and external reporting checks.
- **Earlier:** retention/export/fleet in v1.7; sharing and quick wins in v1.5; analytics in
  v1.4; sender identities in v1.3; alerting in v1.2; health/operations foundation in v1.1.

## Current status

- **Tests:** 145 backend tests, plus the frontend type/build check in CI.
- **Schema:** Alembic `0001` through `0015`; upgrades run automatically on start.
- **Runtime:** one container, one SQLite database, no Redis/Celery, no telemetry.

Known limits:

- DNSSEC relies on the resolver's AD flag; BIMI checks presence only; transport probes need
  outbound port 25.
- MFA is not implemented (parked); the audit log is.
- RUF is not ingested.
- Timeline/DNS-diff auto-history covers the last 20 health snapshots and 180 days.
- Share-link throttling is per-process memory; revisit with multiple workers/replicas.
- Alert-override thresholds and cooldowns are editable; the API remains the source of truth.
- FCrDNS is informational source context, not an alert rule.

## Optional backlog

| Priority | Item | Effort | When |
| --- | --- | --- | --- |
| **1** | **MFA** — TOTP, recovery codes and session invalidation. The audit log already exists. | 1–2 d | When the dashboard is exposed beyond a trusted network. |
| **2** | **RUF/ARF reports** — headers/auth metadata only, redaction, per-domain opt-in and short retention. | 3–4 d | Only with a real receiver sample and a settled PII policy. |
| **3** | **Platform** — PostgreSQL, IMAP transport, read-only API tokens and Prometheus `/api/metrics`. | 8–10 d | >10M source records, multiple instances, external BI or automation demand. |
| **4** | **Share-link throttling** — shared store or proxy-level limit. | 0.5–1 d | Multiple workers/replicas. |
| **5** | **Timeline polish** — configurable history depth; optional saved-view sharing/rename. | 0.5–1 d | Convenience, not a blocker. |

No mandatory item is open. Off-box backup is now delivered; the remaining work is optional.

## Deliberately not planned

- OIDC/multi-user RBAC — single admin, read-only share links cover distribution.
- BIMI VMC verification — CA/trademark checks, often paid; presence only.
- Automatic DNS changes — recommend, never write.
- Storing message bodies — privacy and disk cost.
- Multi-tenant SaaS.
- Simultaneous IMAP + JMAP for one account.

## Decisions

- **Single admin**, PBKDF2 session auth, origin checks, CSP and login throttling.
- **Read-only simulation and recommendations** — never write DNS.
- **Restore takes a safety snapshot**, verifies integrity and requires `--yes`.
- **Audit events are append-only** and never contain secrets or raw report contents.
- **RUF needs a PII decision** before implementation; no bodies by default.
- **Web Markdown has no manual line wraps** — one line per paragraph/bullet.

## Verification

```bash
cd backend && ../.venv/bin/pytest -q
../.venv/bin/ruff check app tests
cd ../frontend && npm run build
cd .. && docker build -t dmarcview .
```
