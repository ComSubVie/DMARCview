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
import { Link } from "react-router-dom";
import { api } from "../api";
import { CheckIcon, expiryTone, overallMeta, statusClass, statusMeta } from "../components/health-ui";
import { DnsDiffCard } from "../components/DnsDiffCard";
import { ExpectedSourcesCard } from "../components/ExpectedSourcesCard";
import { Badge, EmptyState, Skeleton } from "../components/ui";
import { dateTime, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { DomainHealth, FleetHealthItem, HealthCheckResult } from "../types";

type ExternalDestination = {
  kind: string;
  domain: string;
  external: boolean;
  authorized: boolean;
  query: string | null;
};

type DmarcbisEvidence = {
  record?: string;
  discovery_method?: string;
  policy_domain?: string;
  org_domain?: string;
  psd_domain?: string | null;
  effective_p?: string;
  np?: string;
  testing?: string;
  psd?: string;
  deprecated_tags?: string[];
  external_destinations?: ExternalDestination[];
};

function DmarcbisCard({ result, domain }: { result: HealthCheckResult; domain: string }) {
  const meta = statusMeta[result.status];
  const evidence = result.evidence as DmarcbisEvidence;
  const inherited = evidence.discovery_method === "treewalk";
  const hasRecord = typeof evidence.record === "string" && evidence.record.length > 0;
  const np = evidence.np ?? "";
  const testing = evidence.testing ?? "";
  const psd = evidence.psd ?? "";
  const validPolicy = (value: string) => ["none", "quarantine", "reject"].includes(value);
  const deprecated = evidence.deprecated_tags ?? [];
  const external = (evidence.external_destinations ?? []).filter((item) => item.external);
  const unauthorized = external.filter((item) => !item.authorized);
  const items = [
    {
      label: "Policy record",
      value: !hasRecord
        ? "No record"
        : inherited
          ? `Inherited from ${evidence.policy_domain ?? "parent"}`
          : "Published at this domain",
      tone: !hasRecord
        ? result.status === "unknown"
          ? ("neutral" as const)
          : ("bad" as const)
        : inherited
          ? ("info" as const)
          : ("good" as const),
      detail: !hasRecord
        ? result.status === "unknown"
          ? "DNS result unavailable; run the check again"
          : "No valid _dmarc record was found"
        : inherited
          ? `Org ${evidence.org_domain ?? "—"}${evidence.psd_domain ? ` · PSD ${evidence.psd_domain}` : ""}`
          : "Author-domain record wins",
    },
    {
      label: "np= non-existent subdomains",
      value: np ? `np=${np}` : "Not set",
      tone: np ? (validPolicy(np) ? ("good" as const) : ("warn" as const)) : ("neutral" as const),
      detail: np ? "Applies when the author domain is NXDOMAIN" : "Falls back to sp= then p=",
    },
    {
      label: "t= testing mode",
      value: testing === "y" ? "Testing" : "Off",
      tone: testing === "y" ? ("warn" as const) : ("good" as const),
      detail:
        testing === "y"
          ? `Applied policy reduced to ${evidence.effective_p ?? "one level below"}`
          : "Policy applied as published",
    },
    {
      label: "psd= boundary",
      value: psd ? `psd=${psd}` : "Not set",
      tone: psd
        ? psd === "y" || psd === "n"
          ? ("good" as const)
          : ("warn" as const)
        : ("neutral" as const),
      detail: psd ? "Explicit public-suffix boundary" : "Only needed on PSD records",
    },
    {
      label: "Deprecated tags",
      value: deprecated.length > 0 ? deprecated.join(", ") : "None",
      tone: deprecated.length > 0 ? ("warn" as const) : ("good" as const),
      detail:
        deprecated.length > 0
          ? "Removed in RFC 9989; receivers may ignore them"
          : "No pct=, rf= or ri=",
    },
    {
      label: "External reporting",
      value:
        unauthorized.length > 0
          ? `${unauthorized.length} unauthorized`
          : external.length > 0
            ? "Authorized"
            : "None",
      tone: unauthorized.length > 0 ? ("bad" as const) : ("good" as const),
      detail:
        unauthorized.length > 0
          ? unauthorized.map((item) => item.domain).join(", ")
          : external.length > 0
            ? "External rua=/ruf= verified"
            : "All report destinations are internal",
    },
  ];
  return (
    <section className="card dmarcbis-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">DMARCbis readiness</h2>
          <p className="card-sub">
            {domain} · RFC 9989 discovery, RFC 9990/9991 reporting
          </p>
        </div>
        <Badge tone={meta.tone}>{meta.label}</Badge>
      </div>
      <div className="card-body">
        <div className="dmarcbis-grid">
          {items.map((item) => (
            <div className="dmarcbis-item" key={item.label}>
              <div className="dmarcbis-item-head">
                <span className="dmarcbis-label">{item.label}</span>
                <Badge tone={item.tone}>{item.value}</Badge>
              </div>
              <p className="tiny muted">{item.detail}</p>
            </div>
          ))}
        </div>
        <p className="tiny muted dmarcbis-foot">
          The health check is read-only. See{" "}
          <a href="https://www.rfc-editor.org/rfc/rfc9989" target="_blank" rel="noreferrer">
            RFC 9989
          </a>{" "}
          for the policy tags and{" "}
          <a href="https://www.rfc-editor.org/rfc/rfc9990" target="_blank" rel="noreferrer">
            RFC 9990
          </a>{" "}
          for reporting.
        </p>
      </div>
    </section>
  );
}

type CheckLinkSpec = { to: string; label: string; external?: boolean };

const CHECK_LINKS: Record<string, CheckLinkSpec> = {
  dmarc: { to: "/", label: "Open dashboard" },
  spf: { to: "/", label: "View senders" },
  dkim: { to: "/", label: "View senders" },
  tls_rpt: { to: "/tls", label: "Open TLS reports" },
  mta_sts: {
    to: "https://www.rfc-editor.org/rfc/rfc8461",
    label: "MTA-STS docs",
    external: true,
  },
  dane: { to: "https://www.rfc-editor.org/rfc/rfc7672", label: "DANE docs", external: true },
  caa: { to: "https://www.rfc-editor.org/rfc/rfc8659", label: "CAA docs", external: true },
};

function CheckLink({ link }: { link: CheckLinkSpec }) {
  if (link.external) {
    return (
      <a className="check-link" href={link.to} target="_blank" rel="noreferrer">
        {link.label}
        <ArrowRight size={12} />
      </a>
    );
  }
  return (
    <Link className="check-link" to={link.to}>
      {link.label}
      <ArrowRight size={12} />
    </Link>
  );
}

function CheckCard({
  result,
  link,
}: {
  result: HealthCheckResult;
  link?: CheckLinkSpec;
}) {
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
      {link ? <CheckLink link={link} /> : null}
    </article>
  );
}

function DomainProfileCard({ domain }: { domain: string }) {
  const { toast, refresh } = useData();
  const [displayName, setDisplayName] = useState("");
  const [notes, setNotes] = useState("");
  const [tags, setTags] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .domainProfile(domain)
      .then((profile) => {
        if (cancelled) return;
        setDisplayName(profile.display_name ?? "");
        setNotes(profile.notes ?? "");
        setTags((profile.tags ?? []).join(", "));
      })
      .catch(() => {
        /* the profile is optional; the rest of the page still works */
      });
    return () => {
      cancelled = true;
    };
  }, [domain]);

  async function save() {
    setSaving(true);
    try {
      await api.updateDomainProfile(domain, {
        display_name: displayName.trim() || null,
        notes: notes.trim() || null,
        tags: tags
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
      });
      await refresh();
      toast("Domain profile saved");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save the domain profile", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="card settings-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Domain profile</h2>
          <p className="card-sub">Display name and private notes for this domain</p>
        </div>
      </div>
      <div className="card-body">
        <div className="settings-grid">
          <div className="field">
            <label htmlFor="domain-display-name">Display name</label>
            <input
              id="domain-display-name"
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              placeholder={domain}
            />
            <span className="tiny muted">Shown in the domain picker instead of the raw name.</span>
          </div>
          <div className="field span-2">
            <label htmlFor="domain-tags">Groups / tags</label>
            <input
              id="domain-tags"
              value={tags}
              onChange={(event) => setTags(event.target.value)}
              placeholder="production, client-a"
            />
            <span className="tiny muted">Comma-separated labels for grouping domains in the fleet.</span>
          </div>
          <div className="field span-2">
            <label htmlFor="domain-notes">Notes</label>
            <textarea
              id="domain-notes"
              rows={2}
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="Owner, registrar, migration notes…"
            />
            <span className="tiny muted">Stored locally; never included in share links.</span>
          </div>
        </div>
        <div className="actions-row">
          <button className="btn primary" onClick={save} disabled={saving} type="button">
            {saving ? <span className="spinner" /> : null}
            Save profile
          </button>
        </div>
      </div>
    </section>
  );
}

function toLocalInput(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
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
  const [helo, setHelo] = useState("");
  const [hours, setHours] = useState(48);
  const [enabled, setEnabled] = useState(true);
  const [mutedUntil, setMutedUntil] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setSelectors(health.settings.dkim_selectors.join(", "));
    setTargets(health.settings.probe_targets.join("\n"));
    setHelo(health.settings.helo_hostname ?? "");
    setHours(health.settings.expected_report_hours);
    setEnabled(health.settings.dns_checks_enabled);
    setMutedUntil(toLocalInput(health.settings.checks_muted_until));
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
        helo_hostname: helo.trim() || null,
        expected_report_hours: hours,
        dns_checks_enabled: enabled,
        checks_muted_until: mutedUntil ? new Date(mutedUntil).toISOString() : null,
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
          <div className="field">
            <label htmlFor="mute-until">Mute scheduled checks until</label>
            <input
              id="mute-until"
              type="datetime-local"
              value={mutedUntil}
              onChange={(event) => setMutedUntil(event.target.value)}
            />
            <span className="tiny muted">
              Health checks and transport probes skip this domain until then. Manual runs still
              work. Leave empty to unmute.
            </span>
          </div>
          <div className="field span-2">
            <label htmlFor="helo">Expected outbound HELO/EHLO hostname</label>
            <input
              id="helo"
              value={helo}
              onChange={(event) => setHelo(event.target.value)}
              placeholder="Inherit from HELO_HOSTNAME"
            />
            <span className="tiny muted">
              The EHLO name Stalwart actually sends. This only feeds the DNS readiness check; it
              does not configure Stalwart. Leave blank to inherit <code>HELO_HOSTNAME</code>, and
              override only if this domain uses a different outbound EHLO name.
            </span>
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
    const nextFleet = fleet.find((item) => item.next_action);
    return (
      <div className="fade-in">
        <div className="section-head">
          <div>
            <h1>Domain health</h1>
            <p>Live DNS, MTA-STS and transport checks for every domain.</p>
          </div>
        </div>
        {nextFleet?.next_action ? (
          <div className="callout health-next">
            <Wrench size={15} style={{ flex: "none", marginTop: 1 }} />
            <span>
              <strong>Next:</strong> {nextFleet.domain} — {nextFleet.next_action.label}:{" "}
              {nextFleet.next_action.remediation}
              <button className="btn ghost sm" type="button" onClick={() => setDomain(nextFleet.domain)}>
                Open domain
                <ArrowRight size={12} />
              </button>
            </span>
          </div>
        ) : null}
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
                      {item.transport_status === "fail" || item.transport_status === "warn" ? (
                        <div className={`tiny fleet-transport ${item.transport_status}`}>
                          Transport {item.probes - item.failing_probes}/{item.probes}{" "}
                          {item.transport_status === "fail" ? "failing" : "warning"}
                        </div>
                      ) : null}
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
  const dmarc = health.results.find((result) => result.key === "dmarc");
  const next = [...health.results]
    .filter((result) => result.status === "fail" || result.status === "warn")
    .sort(
      (a, b) =>
        (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1),
    )[0];
  const probeTotal = health.probes.length;
  const probePassed = health.probes.filter((probe) => probe.status === "pass").length;
  const probeFailed = health.probes.filter((probe) => probe.status === "fail").length;
  const probeWarn = health.probes.filter((probe) => probe.status === "warn").length;
  const probeTone = probeFailed > 0 ? "bad" : probeWarn > 0 ? "warn" : "ok";
  const probeAttention = health.probes
    .filter((probe) => probe.status === "fail" || probe.status === "warn")
    .sort((a, b) => (a.status === "fail" ? 0 : 1) - (b.status === "fail" ? 0 : 1));
  const nextProbe = probeAttention[0];
  const probeNames = probeAttention.map((probe) => `${probe.host}:${probe.port}`);
  const probeList =
    probeNames.slice(0, 3).join(", ") +
    (probeNames.length > 3 ? ` +${probeNames.length - 3} more` : "");

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
          <span className={`health-transport-line ${probeTone}`}>
            <span className={`health-dot ${probeTone}`} />
            {probeTotal > 0 ? `Transport ${probePassed}/${probeTotal} passing` : "No transport probes"}
          </span>
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
            Core checks cover DMARC, SPF, DKIM and MX. Optional checks add MTA-STS, TLS-RPT, DNSSEC,
            BIMI, CAA, DANE (when TLSA records exist) and HELO/EHLO DNS (when configured). The HELO check validates DNS only;
            it does not observe Stalwart’s outbound session. Transport probes verify STARTTLS and
            certificate expiry on the actual hosts.
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

      {next ? (
        <div className="callout health-next">
          <Wrench size={15} style={{ flex: "none", marginTop: 1 }} />
          <span>
            <strong>Next:</strong> {next.label} — {next.remediation || next.summary}
            {CHECK_LINKS[next.key] ? <CheckLink link={CHECK_LINKS[next.key]} /> : null}
          </span>
        </div>
      ) : null}

      {nextProbe ? (
        <div className={`callout health-next health-next-transport${nextProbe.status === "warn" ? " warn" : ""}`}>
          <Wrench size={15} style={{ flex: "none", marginTop: 1 }} />
          <span>
            <strong>
              Transport{probeAttention.length > 1 ? ` (${probeAttention.length} targets)` : ""}:
            </strong>{" "}
            {probeList} —{" "}
            {nextProbe.error ||
              (nextProbe.days_left !== null
                ? `certificate expires in ${nextProbe.days_left} days`
                : "STARTTLS or certificate check needs attention")}
            <a className="check-link" href="#transport">
              Open transport
              <ArrowRight size={12} />
            </a>
          </span>
        </div>
      ) : null}

      <div className="check-grid">
        {core.map((result) => (
          <CheckCard key={result.key} result={result} link={CHECK_LINKS[result.key]} />
        ))}
      </div>

      {dmarc ? <DmarcbisCard result={dmarc} domain={health.domain} /> : null}

      <DnsDiffCard domain={health.domain} />

      {optional.length > 0 ? (
        <>
          <h2 className="subsection-title">Optional checks</h2>
          <div className="check-grid">
            {optional.map((result) => (
              <CheckCard key={result.key} result={result} link={CHECK_LINKS[result.key]} />
            ))}
          </div>
        </>
      ) : null}

      <div className="grid cols-8-4">
        <section className="card" id="transport">
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

      <DomainProfileCard domain={health.domain} />
      <ExpectedSourcesCard domain={health.domain} />
      <SettingsCard
        health={health}
        onSaved={(settings) => setHealth({ ...health, settings })}
      />
    </div>
  );
}
