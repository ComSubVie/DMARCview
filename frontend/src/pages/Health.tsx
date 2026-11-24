import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  RefreshCw,
  Server,
  Settings2,
  Wrench,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { CheckIcon, expiryTone, overallMeta, statusClass, statusMeta } from "../components/health-ui";
import { Badge, EmptyState, Skeleton } from "../components/ui";
import { dateTime, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { DomainHealth, FleetHealthItem, HealthCheckResult } from "../types";

function CheckCard({ result }: { result: HealthCheckResult }) {
  const meta = statusMeta[result.status];
  return (
    <article className={`card check-card ${statusClass(result.status)}`}>
      <div className="check-card-head">
        <span className={`health-icon ${statusClass(result.status)}`}>
          <CheckIcon checkKey={result.key} size={15} />
        </span>
        <h3>{result.label}</h3>
        <Badge tone={meta.tone}>{meta.label}</Badge>
      </div>
      <p className="check-summary">{result.summary}</p>
      {result.details.length > 0 ? (
        <ul className="check-details">
          {result.details.slice(0, 6).map((detail) => (
            <li key={detail}>{detail}</li>
          ))}
        </ul>
      ) : null}
      {result.remediation ? (
        <p className="check-fix">
          <Wrench size={12} />
          {result.remediation}
        </p>
      ) : null}
    </article>
  );
}

function SettingsCard({
  health,
  onSaved,
}: {
  health: DomainHealth;
  onSaved: (updated: DomainHealth["settings"]) => void;
}) {
  const { toast } = useData();
  const [selectors, setSelectors] = useState("");
  const [targets, setTargets] = useState("");
  const [hours, setHours] = useState(48);
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setSelectors(health.settings.dkim_selectors.join(", "));
    setTargets(health.settings.probe_targets.join("\n"));
    setHours(health.settings.expected_report_hours);
    setEnabled(health.settings.dns_checks_enabled);
  }, [health.settings]);

  async function save() {
    setSaving(true);
    try {
      const updated = await api.saveDomainSettings(health.domain, {
        dkim_selectors: selectors
          .split(/[,\s]+/)
          .map((value) => value.trim())
          .filter(Boolean),
        probe_targets: targets
          .split("\n")
          .map((value) => value.trim())
          .filter(Boolean),
        expected_report_hours: hours,
        dns_checks_enabled: enabled,
      });
      onSaved(updated);
      toast("Health settings saved");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save settings", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="card settings-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Check settings</h2>
          <p className="card-sub">Selectors and extra targets for this domain</p>
        </div>
        <Settings2 size={15} color="#98a2b3" />
      </div>
      <div className="card-body">
        {health.dkim_discovered.length > 0 ? (
          <div className="discovered-selectors">
            <span className="tiny muted">
              Discovered from report auth_results — checked automatically, including rotations:
            </span>
            <div className="chips" style={{ padding: 0 }}>
              {health.dkim_discovered.map((item) => (
                <span className="chip violet" key={`${item.domain}-${item.selector}`}>
                  {item.selector}
                  {item.domain !== health.domain ? (
                    <span style={{ opacity: 0.7 }}> @{item.domain}</span>
                  ) : null}
                </span>
              ))}
            </div>
          </div>
        ) : null}
        <div className="settings-grid">
          <div className="field">
            <label htmlFor="selectors">DKIM selectors</label>
            <input
              id="selectors"
              value={selectors}
              onChange={(event) => setSelectors(event.target.value)}
              placeholder="default, selector1, stalwart"
            />
            <span className="tiny muted">
              Selectors from reports are added automatically. Add extra names here for keys no
              report has seen yet.
            </span>
          </div>
          <div className="field">
            <label htmlFor="hours">Expected report interval (hours)</label>
            <input
              id="hours"
              type="number"
              min={6}
              max={336}
              value={hours}
              onChange={(event) => setHours(Number(event.target.value))}
            />
            <span className="tiny muted">Used for report-gap detection and alerting.</span>
          </div>
          <div className="field span-2">
            <label htmlFor="targets">Extra probe targets</label>
            <textarea
              id="targets"
              rows={3}
              value={targets}
              onChange={(event) => setTargets(event.target.value)}
              placeholder={"mail.example.com:465\nimap.example.com:993"}
            />
            <span className="tiny muted">
              One host:port per line. Ports 25/587 use STARTTLS, everything else is implicit TLS.
              MX hosts are always probed.
            </span>
          </div>
        </div>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          Run scheduled health checks for this domain
        </label>
        <div className="actions-row">
          <button className="btn primary" onClick={save} disabled={saving} type="button">
            {saving ? <span className="spinner" /> : null}
            Save settings
          </button>
        </div>
      </div>
    </section>
  );
}

export function HealthPage() {
  const { domain, setDomain, toast } = useData();
  const [health, setHealth] = useState<DomainHealth | null>(null);
  const [fleet, setFleet] = useState<FleetHealthItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    document.title = "DMARCView — Domain health";
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      if (domain === "all") {
        const result = await api.fleetHealth();
        setFleet(result.items);
        setHealth(null);
      } else {
        setHealth(await api.domainHealth(domain));
        setFleet([]);
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not load health data", "error");
    } finally {
      setLoading(false);
    }
  }, [domain, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function runChecks() {
    setRunning(true);
    try {
      const result = await api.runDomainHealth(domain);
      setHealth(result);
      toast("Health checks completed");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Health checks failed", "error");
    } finally {
      setRunning(false);
    }
  }

  if (domain === "all") {
    return (
      <div className="fade-in">
        <div className="section-head">
          <div>
            <h1>Domain health</h1>
            <p>Live DNS, MTA-STS and transport checks for every domain.</p>
          </div>
        </div>
        <section className="card">
          {loading ? (
            <div style={{ padding: 20, display: "grid", gap: 10 }}>
              <Skeleton height={44} />
              <Skeleton height={44} />
              <Skeleton height={44} />
            </div>
          ) : fleet.length === 0 ? (
            <EmptyState icon={<Server size={20} />} title="No domains yet">
              Import a DMARC report first; health checks run per domain.
            </EmptyState>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Status</th>
                  <th className="center">Core checks</th>
                  <th className="center hide-sm">Probes</th>
                  <th className="center hide-sm">Next expiry</th>
                  <th className="hide-sm">Checked</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {fleet.map((item) => (
                  <tr
                    key={item.domain}
                    className="report-row"
                    onClick={() => setDomain(item.domain)}
                  >
                    <td>
                      <span className="primary-cell">{item.domain}</span>
                    </td>
                    <td>
                      <Badge tone={overallMeta[item.overall].tone}>
                        {item.checked ? overallMeta[item.overall].label : "Not checked"}
                      </Badge>
                    </td>
                    <td className="center num">
                      {item.checked ? `${item.core_passed}/${item.core_total}` : "—"}
                    </td>
                    <td className="center num hide-sm">
                      {item.probes === 0 ? "—" : `${item.probes - item.failing_probes}/${item.probes}`}
                    </td>
                    <td className="center num hide-sm">
                      {item.next_expiry_days === null ? "—" : `${item.next_expiry_days}d`}
                    </td>
                    <td className="tiny muted hide-sm">
                      {item.checked ? relativeTime(item.checked_at) : "never"}
                    </td>
                    <td style={{ width: 28 }}>
                      <ArrowRight size={14} className="chev" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    );
  }

  if (loading && !health) {
    return (
      <div className="fade-in">
        <div className="section-head">
          <Skeleton width={300} height={28} />
        </div>
        <div className="check-grid">
          {[0, 1, 2, 3].map((index) => (
            <div className="card check-card" key={index} style={{ padding: 18 }}>
              <Skeleton width={140} height={15} />
              <div style={{ marginTop: 14 }}>
                <Skeleton height={11} />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!health) {
    return (
      <section className="card" style={{ marginTop: 26 }}>
        <EmptyState icon={<AlertTriangle size={20} />} title="Could not load health data">
          Try again in a moment.
        </EmptyState>
      </section>
    );
  }

  const meta = overallMeta[health.overall];
  const core = health.results.filter((result) => result.core);
  const optional = health.results.filter((result) => !result.core);

  return (
    <div className="fade-in">
      <div className="hero">
        <div>
          <span className="eyebrow">
            <span className="dot" />
            Domain health · live DNS
          </span>
          <h1>
            Health checks for <span className="target">{health.domain}</span>
          </h1>
        </div>
        <div className="hero-side">
          <span className="providers">
            <span className="dot" />
            {health.checked
              ? `Last checked ${relativeTime(health.checked_at)}`
              : "Never checked"}
          </span>
          <span className="stamp">
            {health.core_passed}/{health.core_total} core checks passing
            {health.stale ? " · stale" : ""}
          </span>
        </div>
      </div>

      <div className="health-hero card">
        <div className={`health-hero-score ${statusClass(health.overall)}`}>
          <span className="num">
            {Math.round(health.score * 100)}
            <small>%</small>
          </span>
          <span className="label">core score</span>
        </div>
        <div className="health-hero-main">
          <div className="health-hero-top">
            <Badge tone={meta.tone}>{meta.label}</Badge>
            <span className="tiny muted">
              checked {health.checked ? dateTime(health.checked_at) : "never"}
              {health.duration_ms ? ` · ${health.duration_ms} ms` : ""}
            </span>
          </div>
          <div className={`health-meter ${statusClass(health.overall)}`}>
            <span style={{ width: `${Math.max(3, health.score * 100)}%` }} />
          </div>
          <p className="tiny muted" style={{ marginTop: 8, lineHeight: 1.6 }}>
            Core checks cover DMARC, SPF, DKIM and MX. Optional checks add MTA-STS, TLS-RPT, DNSSEC
            and BIMI. Transport probes verify STARTTLS and certificate expiry on the actual hosts.
          </p>
        </div>
        <div className="health-hero-actions">
          <button className="btn primary" onClick={runChecks} disabled={running} type="button">
            {running ? <span className="spinner" /> : <RefreshCw size={14} />}
            {running ? "Checking…" : "Re-check now"}
          </button>
          <span className="tiny muted">
            <Clock size={11} style={{ verticalAlign: "-1px", marginRight: 4 }} />
            scheduled every 6h
          </span>
        </div>
      </div>

      <div className="check-grid">
        {core.map((result) => (
          <CheckCard key={result.key} result={result} />
        ))}
      </div>

      {optional.length > 0 ? (
        <>
          <h2 className="subsection-title">Optional checks</h2>
          <div className="check-grid">
            {optional.map((result) => (
              <CheckCard key={result.key} result={result} />
            ))}
          </div>
        </>
      ) : null}

      <div className="grid cols-8-4">
        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Transport & certificates</h2>
              <p className="card-sub">
                STARTTLS and certificate inspection · no mail is sent
              </p>
            </div>
            <span className="chip violet">{health.probes.length} targets</span>
          </div>
          <div className="card-body" style={{ paddingTop: 8 }}>
            {health.probes.length === 0 ? (
              <EmptyState icon={<Server size={20} />} title="No probe targets">
                MX hosts are probed automatically once DNS resolves. Add submission or IMAP targets
                in the settings below.
              </EmptyState>
            ) : (
              <table className="data probe-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th className="hide-sm">TLS</th>
                    <th className="center">Expires</th>
                    <th className="hide-sm">Chain</th>
                    <th className="hide-sm">DANE</th>
                  </tr>
                </thead>
                <tbody>
                  {health.probes.map((probe) => (
                    <tr key={`${probe.host}-${probe.port}`}>
                      <td>
                        <div className="primary-cell">
                          {probe.host}
                          <span className="probe-port">:{probe.port}</span>
                        </div>
                        <div className="tiny muted">
                          {probe.error || `${probe.tls_version ?? "TLS"} · ${probe.cipher ?? "—"}`}
                        </div>
                      </td>
                      <td>
                        <Badge
                          tone={
                            probe.status === "pass"
                              ? "good"
                              : probe.status === "warn"
                                ? "warn"
                                : probe.status === "fail"
                                  ? "bad"
                                  : "neutral"
                          }
                        >
                          {probe.status}
                        </Badge>
                      </td>
                      <td className="hide-sm tiny">{probe.tls_version ?? "—"}</td>
                      <td className="center">
                        <span className={`probe-days ${statusClass(expiryTone(probe.days_left))}`}>
                          {probe.days_left === null ? "—" : `${probe.days_left}d`}
                        </span>
                      </td>
                      <td className="center hide-sm">
                        {probe.chain_ok ? (
                          <CheckCircle2 size={14} color="#0b7a63" />
                        ) : (
                          <AlertTriangle size={14} color="#d92d20" />
                        )}
                      </td>
                      <td className="hide-sm tiny">
                        {probe.dane_status && probe.dane_status !== "none" ? probe.dane_status : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">History</h2>
              <p className="card-sub">Recent snapshots</p>
            </div>
          </div>
          <div className="card-body" style={{ paddingTop: 12 }}>
            {health.history.length === 0 ? (
              <p className="tiny muted">No history yet.</p>
            ) : (
              <div className="history-list">
                {[...health.history].reverse().slice(0, 8).map((entry) => (
                  <div className="history-row" key={entry.checked_at ?? Math.random()}>
                    <span className={`health-dot ${statusClass(entry.overall)}`} />
                    <span className="tiny">{dateTime(entry.checked_at)}</span>
                    <span className="tiny muted num" style={{ marginLeft: "auto" }}>
                      {entry.core_passed}/{entry.core_total}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      <SettingsCard
        health={health}
        onSaved={(settings) => setHealth({ ...health, settings })}
      />
    </div>
  );
}
