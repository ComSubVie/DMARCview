import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  Database,
  FileUp,
  Inbox,
  LockKeyhole,
  Plug,
  RefreshCw,
  Send,
  Server,
  UserRound,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api";
import { formatBytes } from "../components/health-ui";
import { Badge, EmptyState, Skeleton } from "../components/ui";
import { dateTime, formatNumber, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { IngestStatus, JobsResponse, ProbeResult, StorageInfo } from "../types";

function Tile({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="status-tile">
      <span className="k">
        {icon}
        {label}
      </span>
      <span className="v">{value}</span>
      {sub ? <span className="s">{sub}</span> : null}
    </div>
  );
}

export function IngestPage() {
  const { meta, refresh, toast } = useData();
  const [status, setStatus] = useState<IngestStatus | null>(null);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [uploadResult, setUploadResult] = useState<string | null>(null);
  const [storage, setStorage] = useState<StorageInfo | null>(null);
  const [jobs, setJobs] = useState<JobsResponse | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.title = "DMARCView — Ingestion";
  }, []);

  async function loadStatus() {
    try {
      setStatus(await api.ingestStatus());
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) {
        toast("Could not read ingestion status", "error");
      }
    }
  }

  async function loadAux() {
    try {
      const [storageInfo, jobInfo] = await Promise.all([api.storage(), api.jobs()]);
      setStorage(storageInfo);
      setJobs(jobInfo);
    } catch {
      /* the page still works without these panels */
    }
  }

  useEffect(() => {
    void loadStatus();
    void loadAux();
  }, []);

  useEffect(() => {
    if (!status?.state.running) return;
    const timer = window.setInterval(() => {
      void loadStatus();
    }, 2500);
    return () => window.clearInterval(timer);
  }, [status?.state.running]);

  async function handleSync() {
    setBusy("sync");
    try {
      await api.syncNow();
      toast("Sync started — reports will appear as they are parsed");
      window.setTimeout(() => {
        void loadStatus();
        void refresh();
      }, 2500);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Sync failed", "error");
    } finally {
      setBusy(null);
    }
  }

  async function handleProbe() {
    setBusy("probe");
    try {
      const result = await api.probe();
      setProbe(result);
      toast(result.ok ? "JMAP connection works" : "Connected, but the mailbox was not found", result.ok ? "ok" : "error");
    } catch (err) {
      setProbe({ ok: false, mailboxes: [], error: err instanceof Error ? err.message : "Probe failed" });
      toast("JMAP connection failed", "error");
    } finally {
      setBusy(null);
    }
  }

  async function handleUpload(files: FileList | null) {
    if (!files || files.length === 0) return;
    setBusy("upload");
    try {
      const result = await api.upload(files);
      const parts = [
        `${result.reports} DMARC`,
        `${result.tls_reports} TLS`,
        result.duplicates ? `${result.duplicates} duplicate` : null,
        result.ignored ? `${result.ignored} ignored` : null,
      ].filter(Boolean);
      setUploadResult(`Imported ${parts.join(" · ")}${result.errors.length ? ` — ${result.errors.length} warning(s)` : ""}`);
      toast(`Imported ${parts.join(" · ")}`, result.errors.length ? "error" : "ok");
      await loadStatus();
      await loadAux();
      await refresh();
    } catch (err) {
      toast(err instanceof Error ? err.message : "Upload failed", "error");
    } finally {
      setBusy(null);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  const running = status?.state.running;
  const lastRun = status?.runs[0];

  return (
    <div className="fade-in">
      <div className="section-head">
        <div>
          <h1>Ingestion</h1>
          <p>How reports get from your mailbox into this dashboard.</p>
        </div>
        <Badge tone={status?.configured ? "good" : "warn"}>
          {status?.configured ? "JMAP connected" : status?.enabled ? "Configured" : "Manual only"}
        </Badge>
      </div>

      <div className="grid ingest-grid">
        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Report mailbox</h2>
              <p className="card-sub">Polled over JMAP · Stalwart native</p>
            </div>
            {running ? <Badge tone="info">Syncing…</Badge> : <Badge tone="neutral">Idle</Badge>}
          </div>
          <div className="card-body">
            {!status ? (
              <Skeleton height={120} />
            ) : (
              <>
                <div className="status-grid">
                  <Tile
                    icon={<Plug size={11} />}
                    label="Endpoint"
                    value={status.url || "not configured"}
                  />
                  <Tile
                    icon={<UserRound size={11} />}
                    label="Account"
                    value={status.username || "—"}
                    sub="JMAP credentials"
                  />
                  <Tile
                    icon={<Inbox size={11} />}
                    label="Mailbox"
                    value={status.mailbox}
                    sub={`every ${Math.round(status.poll_seconds / 60)} min`}
                  />
                  <Tile
                    icon={<Clock size={11} />}
                    label="Last run"
                    value={lastRun ? relativeTime(lastRun.finished_at ?? lastRun.started_at) : "never"}
                    sub={lastRun ? `${lastRun.messages_ingested} messages ingested` : undefined}
                  />
                  <Tile
                    icon={<Database size={11} />}
                    label="DMARC reports"
                    value={formatNumber(status.counts.reports)}
                    sub="aggregate (RUA)"
                  />
                  <Tile
                    icon={<LockKeyhole size={11} />}
                    label="TLS reports"
                    value={formatNumber(status.counts.tls_reports)}
                    sub="TLS-RPT"
                  />
                </div>

                {!status.enabled ? (
                  <div className="callout" style={{ marginTop: 14 }}>
                    <AlertTriangle size={16} style={{ flex: "none", marginTop: 1 }} />
                    <span>
                      JMAP polling is off. Set <code>JMAP_ENABLED=true</code>, <code>JMAP_URL</code>,{" "}
                      <code>JMAP_USERNAME</code> and <code>JMAP_PASSWORD</code> (or <code>JMAP_TOKEN</code>) in
                      your environment, then restart. You can still upload <code>.eml</code> files below.
                    </span>
                  </div>
                ) : null}

                {status.state.last_error ? (
                  <div className="callout" style={{ marginTop: 14 }}>
                    <AlertTriangle size={16} style={{ flex: "none", marginTop: 1 }} />
                    <span>{status.state.last_error}</span>
                  </div>
                ) : null}

                <div className="actions-row">
                  <button className="btn primary" onClick={handleSync} disabled={!status.enabled || running || busy !== null} type="button">
                    {running ? <span className="spinner" /> : <RefreshCw size={14} />}
                    {running ? "Syncing…" : "Sync now"}
                  </button>
                  <button className="btn ghost" onClick={handleProbe} disabled={!status.url || busy !== null} type="button">
                    <Server size={14} />
                    Test connection
                  </button>
                  <button className="btn ghost" onClick={() => fileInput.current?.click()} disabled={busy !== null} type="button">
                    {busy === "upload" ? <span className="spinner dark" /> : <FileUp size={14} />}
                    Upload reports
                  </button>
                  <input
                    ref={fileInput}
                    type="file"
                    accept=".eml,.zip,.gz,.xml,.json"
                    multiple
                    hidden
                    onChange={(event) => void handleUpload(event.target.files)}
                  />
                </div>
                {uploadResult ? <p className="tiny muted" style={{ marginTop: 10 }}>{uploadResult}</p> : null}
              </>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Enrichment</h2>
              <p className="card-sub">Local, no third-party lookups</p>
            </div>
          </div>
          <div className="card-body">
            <div className="status-grid" style={{ gridTemplateColumns: "minmax(0,1fr)" }}>
              <Tile
                icon={<CheckCircle2 size={11} />}
                label="GeoIP database"
                value={status?.geoip ? "Available" : meta?.geoip ? "Available" : "Not installed"}
                sub={status?.geoip || meta?.geoip ? "DB-IP Lite / MaxMind country lookups" : "Drop a .mmdb into data/geoip/"}
              />
              <Tile
                icon={<Database size={11} />}
                label="Last report ingested"
                value={status?.counts.last_ingested_at ? relativeTime(status.counts.last_ingested_at) : "never"}
                sub={status?.counts.last_ingested_at ? dateTime(status.counts.last_ingested_at) : undefined}
              />
              <Tile
                icon={<Inbox size={11} />}
                label="Domains discovered"
                value={formatNumber(meta?.domain_count ?? 0)}
                sub="created automatically from reports"
              />
            </div>
            <div className="callout info" style={{ marginTop: 14 }}>
              <Send size={16} style={{ flex: "none", marginTop: 1 }} />
              <span>
                Point your DNS records at this mailbox: DMARC <code>rua=mailto:dmarc@…</code> and
                TLS-RPT <code>rua=mailto:tlsrpt@…</code>. Reports usually arrive once a day.
              </span>
            </div>
          </div>
        </section>
      </div>

      <div className="grid ingest-grid" style={{ marginTop: 16 }}>
        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Storage</h2>
              <p className="card-sub">One SQLite file plus the raw report archive</p>
            </div>
            <Badge tone="neutral">{storage ? formatBytes(storage.total_bytes) : "—"}</Badge>
          </div>
          <div className="card-body">
            {!storage ? (
              <Skeleton height={90} />
            ) : (
              <>
                <div className="status-grid">
                  <Tile
                    icon={<Database size={11} />}
                    label="Database"
                    value={formatBytes(storage.database_bytes + storage.wal_bytes)}
                    sub={`${formatNumber(storage.source_records)} source records`}
                  />
                  <Tile
                    icon={<FileUp size={11} />}
                    label="Raw reports"
                    value={formatBytes(storage.raw_bytes)}
                    sub={`${formatNumber(storage.reports)} DMARC · ${formatNumber(storage.tls_reports)} TLS`}
                  />
                  <Tile
                    icon={<Clock size={11} />}
                    label="Oldest report"
                    value={storage.oldest_report ? dateTime(storage.oldest_report).split(",")[0] : "—"}
                    sub={storage.retention_days > 0 ? `retention: ${storage.retention_days} days` : "retention: keep forever"}
                  />
                  <Tile
                    icon={<Database size={11} />}
                    label="Backups"
                    value={`${storage.backups.count}`}
                    sub={storage.backups.last_at ? `last ${relativeTime(storage.backups.last_at)}` : "run python -m app.cli backup"}
                  />
                </div>
                <p className="tiny muted" style={{ marginTop: 10, lineHeight: 1.6 }}>
                  Retention is opt-in. Until you set <code>RETENTION_DAYS</code>, nothing is pruned.
                  Backups are consistent SQLite snapshots written next to the database. Off-box
                  status: {storage.offsite.providers.length > 0
                    ? `${storage.offsite.providers.join(" + ")}${storage.offsite.last_at ? ` · last ${relativeTime(storage.offsite.last_at)}` : " · not uploaded yet"}`
                    : "not configured"}.
                  {storage.offsite.last_error ? ` Last error: ${storage.offsite.last_error}` : ""}
                </p>
              </>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Scheduled jobs</h2>
              <p className="card-sub">Health checks, probes and reverse DNS</p>
            </div>
            <Badge tone={jobs?.scheduled ? "good" : "warn"}>
              {jobs?.scheduled ? "running" : "disabled"}
            </Badge>
          </div>
          <div className="card-body" style={{ paddingTop: 4 }}>
            {!jobs ? (
              <Skeleton height={90} />
            ) : (
              <table className="data runs-table">
                <thead>
                  <tr>
                    <th>Job</th>
                    <th className="hide-sm">Every</th>
                    <th>Last run</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.items.map((job) => (
                    <tr key={job.name}>
                      <td>{job.label}</td>
                      <td className="hide-sm tiny muted">
                        {Math.round(job.interval_seconds / 3600)}h
                      </td>
                      <td className="tiny">
                        {job.last_run ? relativeTime(job.last_run.finished_at || job.last_run.started_at) : "never"}
                      </td>
                      <td>
                        <Badge
                          tone={
                            !job.last_run
                              ? "neutral"
                              : job.last_run.status === "ok"
                                ? "good"
                                : job.last_run.status === "running"
                                  ? "info"
                                  : "bad"
                          }
                        >
                          {job.last_run?.status ?? "—"}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="tiny muted" style={{ marginTop: 10, lineHeight: 1.6 }}>
              Checks run every few hours in the background. Use “Re-check now” on a domain for an
              immediate run.
            </p>
          </div>
        </section>
      </div>

      {probe ? (
        <section className="card" style={{ marginTop: 16 }}>
          <div className="card-head">
            <div>
              <h2 className="card-title">Connection probe</h2>
              <p className="card-sub">{probe.ok ? "Mailbox resolved successfully" : "Check the details below"}</p>
            </div>
            <Badge tone={probe.ok ? "good" : "bad"}>{probe.ok ? "OK" : "Failed"}</Badge>
          </div>
          <div className="card-body">
            {probe.error ? <div className="callout" style={{ marginBottom: 12 }}><AlertTriangle size={16} style={{ flex: "none" }} /><span>{probe.error}</span></div> : null}
            <div className="meta-grid">
              <div className="meta-cell">
                <div className="k">Account</div>
                <div className="v">{probe.account_name || probe.username || "—"}</div>
              </div>
              <div className="meta-cell">
                <div className="k">Report mailbox</div>
                <div className="v">{probe.report_mailbox || "not found"}</div>
              </div>
              <div className="meta-cell">
                <div className="k">Mailboxes</div>
                <div className="v">{probe.mailboxes.length}</div>
              </div>
              <div className="meta-cell">
                <div className="k">API</div>
                <div className="v" style={{ fontSize: 11, fontFamily: "var(--font-mono)" }}>{probe.api_url || "—"}</div>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      <section className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <h2 className="card-title">Recent ingestion runs</h2>
            <p className="card-sub">Newest first · failures are retried on the next poll</p>
          </div>
        </div>
        <div style={{ padding: "4px 8px 10px" }}>
          {!status ? (
            <div style={{ padding: 16 }}>
              <Skeleton height={100} />
            </div>
          ) : status.runs.length === 0 ? (
            <EmptyState icon={<Inbox size={20} />} title="No runs yet">
              Upload a report or wait for the first scheduled poll.
            </EmptyState>
          ) : (
            <table className="data runs-table">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th className="center hide-sm">Seen</th>
                  <th className="center">Ingested</th>
                  <th className="center hide-sm">DMARC</th>
                  <th className="center hide-sm">TLS</th>
                  <th className="hide-sm">Detail</th>
                </tr>
              </thead>
              <tbody>
                {status.runs.map((run) => (
                  <tr key={`${run.id}-${run.started_at}`}>
                    <td>{relativeTime(run.finished_at ?? run.started_at)}</td>
                    <td>
                      <Badge tone={run.source === "jmap" ? "info" : "neutral"}>{run.source}</Badge>
                    </td>
                    <td>
                      <Badge tone={run.status === "ok" ? "good" : run.status === "running" ? "info" : "bad"}>
                        {run.status}
                      </Badge>
                    </td>
                    <td className="center num hide-sm">{formatNumber(run.messages_seen)}</td>
                    <td className="center num">{formatNumber(run.messages_ingested)}</td>
                    <td className="center num hide-sm">{formatNumber(run.reports_created)}</td>
                    <td className="center num hide-sm">{formatNumber(run.tls_reports_created)}</td>
                    <td className="tiny muted hide-sm" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {run.error || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      <div className="callout strong" style={{ marginTop: 16 }}>
        <ArrowUpRight size={16} style={{ flex: "none", marginTop: 1 }} />
        <span>
          Prefer the command line? <code>python -m app.cli import reports/*.eml</code> imports a
          folder, and <code>python -m app.cli sync</code> runs one JMAP sync for cron jobs.
        </span>
      </div>
    </div>
  );
}
