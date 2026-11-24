# DMARCView

Self-hosted DMARC and TLS-RPT reporting for Stalwart (or any JMAP server), with a
dashboard modelled on the polished SaaS tools — but running entirely on your own box.

![DMARCView dashboard](docs/screenshots/dashboard.png)

Report emails are fetched over JMAP, parsed offline, stored in SQLite and turned into
answers: *is my mail authenticating, who is sending as me, and is delivery encrypted?*

---

## What it does

- **Pulls reports automatically.** Polls a dedicated mailbox over JMAP with an
  incremental cursor — new mail is picked up every few minutes, and the first sync can
  look back 90 days.
- **Parses the real world.** DMARC aggregate XML from zip, gzip, `application/octet-stream`
  or inline bodies, with dmarc-1.0/2.0 or no namespace; TLS-RPT JSON with both RFC and
  draft key spellings. Every report is kept byte-for-byte for audit and re-parsing.
- **Answers the questions you actually have.**
  - Compliance over time, aligned vs. failing volume per day.
  - Sending sources grouped into *verified* / *not verified*, with the raw SPF and DKIM
    result *and* the aligned DMARC verdict shown separately.
  - Top countries, mailbox providers, plain-English summary, and a policy recommendation.
- **TLS delivery.** Session success rate per MX host, failure reasons
  (`certificate-expired`, `starttls-not-supported`, …) and the reporters behind them.
- **Checks your configuration, not just your reports.** Live DNS checks for DMARC, SPF (with the
  10-lookup limit), DKIM selectors, MX, MTA-STS (policy-id validation), TLS-RPT, DNSSEC and BIMI.
  Because outbound port 25 is allowed, it also probes MX, submission and IMAP endpoints:
  STARTTLS, TLS version, certificate chain, hostname, expiry and DANE/TLSA.
- **Runs itself.** An in-process scheduler re-checks every few hours, reverse-resolves sending
  IPs, and reports every run in the UI. No cron, Redis or Celery.
- **Multi-domain.** A fleet view plus a per-domain drill-down with a domain picker.
- **Report browser.** Search, filter, inspect every record, download the original XML/JSON.
- **Boring to operate.** One container, one SQLite file, no external services, no
  telemetry, no third-party IP lookups (GeoIP is local).

| Domain health | TLS delivery |
| --- | --- |
| ![Domain health](docs/screenshots/health.png) | ![TLS delivery](docs/screenshots/tls.png) |

---

## Quick start (Docker)

```bash
git clone <this-repo> dmarcview && cd dmarcview
cp .env.example .env
$EDITOR .env                      # set SECRET_KEY, ADMIN_PASSWORD, JMAP_*
python3 scripts/fetch_geoip.py geoip   # optional: country flags
docker compose up -d --build
```

Open <http://localhost:8000> and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`.

> **Cookie gotcha:** `.env.example` ships `COOKIE_SECURE=false` so plain-HTTP localhost
> works. If you put DMARCView behind HTTPS (you should), set it to `true` — otherwise
> the session cookie is dropped and you will bounce back to the login screen.

Check that ingestion works:

```bash
docker compose exec dmarcview python -m app.cli probe
docker compose exec dmarcview python -m app.cli sync
docker compose logs -f
```

Health checks start about 25 seconds after boot and then run every six hours; the first
report, the DNS snapshot and the transport probes appear on the Overview and Health pages
automatically. To force a run, use **Re-check now** on a domain, or the CLI
(`python -m app.cli` — see below) inside the container.

Write a local backup (consistent snapshot, safe while running):

```bash
docker compose exec dmarcview python -m app.cli backup --keep 14
```

Data lives in the `dmarcview-data` Docker volume:

```bash
docker run --rm -v dmarcview_dmarcview-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/dmarcview-backup.tgz -C /data .
```

## Published container images

`.github/workflows/publish-image.yml` builds a multi-architecture image (`linux/amd64`,
`linux/arm64`) and publishes it to the GitHub Container Registry as
`ghcr.io/<your-github-user>/dmarcview`.

| Tag | Source |
| --- | --- |
| `edge` | every push to the default branch |
| `1.2.3`, `1.2`, `1` | a `v1.2.3` tag |
| `latest` | the newest stable release tag |
| `sha-abc1234` | every build |

```bash
docker pull ghcr.io/<your-github-user>/dmarcview:latest
```

To run the published image instead of building locally:

```bash
export DMARCVIEW_IMAGE=ghcr.io/<your-github-user>/dmarcview:latest
docker compose pull
docker compose up -d --no-build
```

Every run first executes the backend test suite and a production frontend build; the image
is only published if those pass. Pull requests build `linux/amd64` only and never push.
Releases are published with SBOM and provenance attestations. GHCR packages start private — make the package public under
*GitHub → your profile → Packages* if you want unauthenticated pulls.

Publish a release with:

```bash
git tag v1.1.4 && git push origin v1.1.4
```

## Without Docker

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt

cd frontend && npm ci && npm run build && cd ..

export SECRET_KEY="$(openssl rand -base64 36)"
export ADMIN_PASSWORD="a-long-password"
export JMAP_ENABLED=true JMAP_URL=https://mail.example.com \
       JMAP_USERNAME=dmarc@example.com JMAP_PASSWORD=... JMAP_MAILBOX=DMARC

cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The built SPA is served by FastAPI from `frontend/dist`. For UI work run
`npm run dev` in `frontend/` — Vite proxies `/api` to `127.0.0.1:8000`.

---

## Stalwart setup

1. **Create a mailbox** for reports, e.g. `dmarc@yourdomain.tld`, and a folder named
   `DMARC` (or point `JMAP_MAILBOX` at any existing folder).
2. **Publish the reporting addresses** in DNS:

   ```dns
   _dmarc.yourdomain.tld.        TXT "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.tld"
   _smtp._tls.yourdomain.tld.    TXT "v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.tld"
   ```

   Receivers send aggregate reports once a day; most start arriving within 48 hours.
3. **Give DMARCView credentials** that can read that mailbox. Stalwart accepts basic
   auth with an account password, or a bearer token:

   ```env
   JMAP_ENABLED=true
   JMAP_URL=https://mail.yourdomain.tld
   JMAP_USERNAME=dmarc@yourdomain.tld
   JMAP_PASSWORD=…
   JMAP_MAILBOX=DMARC
   ```

4. **Verify** with `python -m app.cli probe`. It prints the account, every mailbox it can
   see, and whether `JMAP_MAILBOX` resolved. A failed lookup lists the available folders.

Reports can also arrive by forwarding to another mailbox; any JMAP account that can read
them works. IMAP is not implemented (the transport is a single interface, so adding one
is straightforward).

---

## Configuration

All settings are environment variables (`.env` is loaded automatically).

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | dev value | Signs the session cookie. **Set it.** |
| `ADMIN_USERNAME` | `admin` | Login name. |
| `ADMIN_PASSWORD` | — | Plain password (dev/simple). |
| `ADMIN_PASSWORD_HASH` | — | PBKDF2 hash; preferred over the plain password. |
| `COOKIE_SECURE` | `false` | `true` when served over HTTPS. |
| `SESSION_MAX_AGE` | `1209600` | Session lifetime in seconds. |
| `JMAP_ENABLED` | `false` | Turn scheduled polling on. |
| `JMAP_URL` | — | Server base URL, e.g. `https://mail.example.com`. |
| `JMAP_USERNAME` / `JMAP_PASSWORD` | — | Basic-auth credentials. |
| `JMAP_TOKEN` | — | Bearer token instead of basic auth. |
| `JMAP_MAILBOX` | `DMARC` | Folder name to poll. |
| `JMAP_POLL_SECONDS` | `300` | Poll interval (min 30). |
| `INGEST_INITIAL_DAYS` | `90` | How far back the first sync looks. |
| `DNS_NAMESERVERS` | system | Comma-separated resolvers for health checks. Use a validating resolver for DNSSEC. |
| `HEALTH_CHECKS_ENABLED` | `true` | Run the scheduled DNS/transport jobs at all. |
| `HEALTH_INTERVAL_MINUTES` | `360` | How often domain health checks run. |
| `PROBE_INTERVAL_MINUTES` | `360` | How often MX/submission/IMAP probes run. |
| `PROBE_TIMEOUT_SECONDS` | `8` | Per-target connect/handshake timeout. |
| `HTTP_TIMEOUT_SECONDS` | `6` | Timeout for MTA-STS and BIMI fetches. |
| `PTR_ENRICHMENT_ENABLED` | `true` | Reverse-resolve sending IPs in the background. |
| `JOBS_INITIAL_DELAY_SECONDS` | `25` | Delay before the first scheduled run after boot. |
| `BACKUP_KEEP` | `14` | Local snapshots retained by `app.cli backup`. |
| `MONTHLY_MESSAGE_ALERT` | `10000` | Progress-bar target on the dashboard. |
| `GEOIP_DB` | auto | Path to a `.mmdb`; otherwise `data/geoip/*.mmdb`. |
| `DATA_DIR` | `./data` | Database location outside Docker. |
| `DATABASE_URL` | `sqlite:///…/data/dmarc.db` | Full SQLAlchemy URL. |
| `FRONTEND_DIST` | `frontend/dist` | Built SPA location. |
| `ROOT_PATH` | — | Set when serving under a sub-path. |

Generate a password hash instead of storing a plaintext password:

```bash
python -m app.cli hash-password
# -> pbkdf2_sha256$310000$…
```

---

## GeoIP (optional)

Country flags and the *Top countries* card come from a local MaxMind-format database.
Nothing is sent to a third party.

```bash
python3 scripts/fetch_geoip.py geoip     # DB-IP Lite, refreshed monthly
```

The script tries the current month and falls back two months. It also picks a working TLS
trust store automatically (certifi, then the usual system bundles), because some python.org
builds ship a stale one. If a proxy intercepts TLS, pass `--ca-file /path/to/bundle.pem` (or
`--insecure` as a last resort). Restart the container after adding the file so the resolver
picks it up. Without a database the app runs normally; countries render as *Unknown*.

> IP Geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0). MaxMind GeoLite2 also works —
> point `GEOIP_DB` at the `.mmdb` file.

---

## CLI

```bash
python -m app.cli hash-password       # print a PBKDF2 hash
python -m app.cli init-db             # create/migrate the schema
python -m app.cli probe               # JMAP session + mailbox discovery
python -m app.cli sync                # one JMAP sync (cron-friendly)
python -m app.cli import samples/*.eml  # offline import of .eml / .zip
python -m app.cli migrate             # apply database migrations
python -m app.cli backup --keep 14    # consistent SQLite snapshot
python -m app.cli stats               # row counts
```

`import` is handy for backfilling an archive of saved report emails, or for checking a
parser fix before pointing the poller at the mailbox.

---

## How ingestion stays idempotent

Three layers prevent double counting:

1. **Mailbox message** — `ProcessedMessage.source_key` (`jmap:<email-id>` or
   `upload:<sha256>`) means a message is only parsed once.
2. **Attachment digest** — `raw_sha256` on each report. The same XML delivered twice (or
   as a different message) is ignored.
3. **Reporter report id** — `(org_name, report_id)` is unique, so re-sent reports cannot
   duplicate.

The poller keeps a cursor in `sync_state` (`jmap.last_received_at`) and overlaps by one
day for safety; the layers above absorb the overlap.

Malformed reports never abort a batch: the error is recorded on the message/run and the
next attachment is still processed.

---

## API

Everything below requires the session cookie (obtained via `POST /api/auth/login`).

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/dashboard?domain=&days=` | KPIs, daily series, sources, countries, policy, advice |
| `GET` | `/api/domains` | Domain list with 30-day stats |
| `GET` | `/api/reports` | Paged/filtered DMARC reports (`q`, `days`, `page`) |
| `GET` | `/api/reports/{id}` | Report detail with every record |
| `GET` | `/api/reports/{id}/raw` | Original XML download |
| `GET` | `/api/tls` | TLS-RPT KPIs, per-day sessions, failures, policies |
| `GET` | `/api/tls/reports/{id}` | TLS report detail |
| `POST` | `/api/ingest/run` | Trigger a sync (202, runs in background) |
| `POST` | `/api/ingest/upload` | Upload `.eml`/`.zip` files (multipart `files`) |
| `POST` | `/api/ingest/probe` | JMAP connectivity check |
| `GET` | `/api/ingest/status` | Poller state, counts, recent runs |
| `GET` | `/api/domain-health?domain=` | Latest DNS checks, probes and settings |
| `POST` | `/api/domain-health/run?domain=` | Run DNS checks and probes now |
| `GET` | `/api/domain-health/fleet` | Health summary per domain |
| `GET` | `/api/domain-health/history?domain=` | Snapshot history |
| `GET/PUT` | `/api/domains/{name}/settings` | DKIM selectors, probe targets, cadence |
| `GET` | `/api/storage` | Database, archive and backup sizes |
| `GET` | `/api/jobs` | Scheduled jobs and their last run |
| `GET` | `/api/health` | Unauthenticated liveness probe |

---

## Architecture

```
          ┌────────────┐   JMAP    ┌──────────────────────────────┐
 Stalwart │  DMARC box │◀──────────│ poller (asyncio, cursor)      │
          └────────────┘           │   ↓                          │
                                   │ MIME unwrap (zip/gz/inline)  │
                                   │   ↓            ↓             │
                                   │ DMARC XML   TLS-RPT JSON     │
                                   │   ↓            ↓             │
                                   │ SQLite (sqlmodel) + raw blobs│
                                   └──────────────┬───────────────┘
                                                  │ FastAPI
                                   ┌──────────────▼───────────────┐
                                   │ React + Vite + Recharts SPA  │
                                   └──────────────────────────────┘
```

- **Backend** `backend/app`: FastAPI, SQLModel/SQLite (WAL), Alembic migrations, httpx JMAP
  client, DNS checks on dnspython, certificate parsing with `cryptography`. Report parsers use
  only stdlib `email`/`xml`/`zipfile`/`gzip`.
- **Frontend** `frontend/src`: React 19, React Router, Recharts, hand-written CSS design
  system (no UI framework), self-hosted Inter + Space Grotesk.
- **Storage**: one SQLite file plus raw XML/JSON blobs. A few thousand reports per domain
  per year is comfortably within SQLite's range.

---

## Roadmap

v1.1 already adds live DNS and transport health checks. Next up: alerting over SMTP /
Telegram / Signal, then unauthenticated read-only share links and export. Sequencing, effort
estimates and the decisions behind them live in [docs/ROADMAP.md](docs/ROADMAP.md).

## Development

[AGENTS.md](AGENTS.md) is the contributor guide (human or AI): architecture map, commands,
invariants, the definition of done and the release process. `CLAUDE.md` imports it.

```bash
# backend tests (64 tests: parsers, ingestion, API, auth, mocked JMAP, health checks and probes)
cd backend && ../.venv/bin/pytest -q

# frontend type-check + production build
cd frontend && npm run build

# a realistic 30-day demo dataset (separate database, never used in production)
DATABASE_URL=sqlite:///$PWD/data/demo.db python scripts/demo_seed.py
```

The `samples/` directory holds hand-written report emails covering zip, gzip, inline-body,
namespace-less and TLS-RPT variants — useful when debugging a new reporter.

---

## Domain health & transport checks

The **Domain health** card is computed from live DNS, not from report contents:

| Check | Verified |
| --- | --- |
| DMARC | record present and valid, `p`/`sp`/`pct`, `rua`; flags drift against the policy receivers report |
| SPF | recursive includes, **≤10 DNS lookups**, ≤2 void lookups, terminal `all` |
| DKIM | a key for every configured **and report-discovered** selector, key type/size; date-based rotation selectors are expanded around today |
| MX | hosts resolve; null MX is understood |
| MTA-STS | `_mta-sts` TXT with an id, policy fetched over HTTPS, mode/mx/max_age |
| TLS-RPT | `_smtp._tls` TXT and `rua` |
| DNSSEC | DS present and validated (AD flag from the resolver) |
| BIMI | `default._bimi`, logo reachable — presence only, no VMC verification |

Selectors cannot be enumerated through DNS, and Stalwart rotates them on a date template
(`v1-ed25519-20260101`). DMARCView learns the real ones from the `auth_results/dkim/selector`
fields in your reports — including subdomain signing domains — and additionally probes date
variants around today, so a fresh rotation is covered before the next report arrives. Manual
selectors remain available for keys no report has seen yet.

**Transport probes** then connect to the MX hosts on port 25 (and any `host:port` targets you
add for submission/IMAP/HTTPS): EHLO, STARTTLS, certificate chain and hostname verification,
expiry, TLS version/cipher, and DANE/TLSA matching. No authentication is attempted and no
message is ever sent. If a network blocks outbound port 25 the probe is reported as a
failure with the connection error — DNS checks are unaffected.

Checks are cached in `domain_health_snapshots` (drift history) and `transport_probes`; the
scheduler runs them every six hours and `Re-check now` forces a run. Results degrade to
*unknown*, never *fail*, when DNS or the network is unavailable.

## Backups & retention

`python -m app.cli backup` writes a consistent snapshot with `sqlite3.Connection.backup()`
(safe while the app is serving), verifies it with `PRAGMA integrity_check`, and keeps the
last `BACKUP_KEEP` files in `data/backups/`. Retention of report data is **off by default**:
nothing is pruned until you set a policy, and the Ingestion page shows database size, raw
archive size and growth so the decision can be made with numbers.

## Security notes

- Single admin, PBKDF2-SHA256 password hashing (310k iterations), signed HttpOnly session
  cookie (`SameSite=Lax`), login lockout after 8 failures per IP.
- Cross-origin state-changing requests are rejected (Origin check); the SPA is served with
  CSP, `X-Frame-Options: DENY`, `nosniff` and a strict referrer policy.
- Report data stays local. The only outbound traffic is to your JMAP server (and the
  optional manual GeoIP download).
- Put it behind an HTTPS reverse proxy, set `COOKIE_SECURE=true`, and use a strong
  `SECRET_KEY` / password. The container runs as UID 1000 and needs write access only to
  `/data`.

---

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Login succeeds, then bounces back | `COOKIE_SECURE=true` over plain HTTP — set it to `false` or use HTTPS |
| `mailbox 'DMARC' not found` | `probe` lists the real folder names; adjust `JMAP_MAILBOX` |
| No reports appear | Check DNS `rua=` records, then `python -m app.cli sync` and look at Ingestion → recent runs |
| `unable to open database file` | The container user cannot write `/data`; fix volume ownership |
| Countries show *Unknown* | No `.mmdb` found — run `python3 scripts/fetch_geoip.py geoip` and `docker compose restart` |
| GeoIP download says `CERTIFICATE_VERIFY_FAILED` | The script now tries the system store; otherwise pass `--ca-file /etc/ssl/cert.pem` or run `./.venv/bin/python scripts/fetch_geoip.py` |
| A report is skipped | Its submitter/report-id or digest was already ingested; check `ProcessedMessage` / `Report.raw_sha256` |
| TLS page is empty | TLS-RPT reports only arrive if `_smtp._tls` publishes `rua=` |
| Health checks all show *Unknown* | DNS is blocked or the resolver is unreachable; set `DNS_NAMESERVERS` |
| Transport probes fail with timeouts | Outbound port 25 is blocked by the host or provider |
| MTA-STS not reachable | The policy must be served over HTTPS at `mta-sts.<domain>/.well-known/mta-sts.txt` |
| `no such table` after upgrading | Run `python -m app.cli migrate` (also runs on start) |
| `unsupportedFilter` on sync | Older builds sent `receivedAfter`; 1.1.1+ uses the RFC 8621 `after` filter and falls back to scanning if a server rejects it |

---

## Report formats supported

- DMARC aggregate (RUA) XML, compressed with zip/gzip or delivered inline; namespaces
  `dmarc-1.0`, `dmarc-2.0` or none; multiple XML files per zip.
- TLS-RPT JSON (RFC 8460), including draft-era keys
  (`total-success-session-count`, `receiving-mx`) and failure details nested either in
  `summary` or beside it.
- DMARC forensic (RUF) reports are intentionally out of scope.

Screenshots use a generated demo dataset (`scripts/demo_seed.py`); no real domain data is
included.

## Provenance

The initial implementation was generated with AI assistance and reviewed by the maintainer.
[AGENTS.md](AGENTS.md) records the conventions and the traps discovered during that work.

## License

MIT © 2026 Markus Schabel. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the bundled fonts (SIL OFL 1.1) and the
optional DB-IP data (CC BY 4.0).
