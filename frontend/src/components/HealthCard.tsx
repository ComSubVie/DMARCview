import { ArrowRight, ChevronDown, RefreshCw, ShieldQuestion } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { DomainHealth, FleetHealthItem, HealthCheckResult } from "../types";
import { relativeTime } from "../lib/format";
import { Badge, Skeleton } from "./ui";
import { CheckIcon, overallMeta, statusMeta, statusClass } from "./health-ui";

function CheckRow({ result }: { result: HealthCheckResult }) {
  const meta = statusMeta[result.status];
  return (
    <div className={`health-row ${statusClass(result.status)}`} title={result.details.join("\n")}>
      <span className={`health-icon ${statusClass(result.status)}`}>
        <CheckIcon checkKey={result.key} size={14} />
      </span>
      <span className="health-name">{result.label}</span>
      <span className="health-summary">{result.summary}</span>
      <span className={`health-dot ${statusClass(result.status)}`} aria-label={meta.label} />
    </div>
  );
}

export function HealthCard({
  health,
  fleet,
  allDomains,
  loading,
  running,
  onRun,
  onSelectDomain,
}: {
  health: DomainHealth | null;
  fleet: FleetHealthItem[] | null;
  allDomains: boolean;
  loading: boolean;
  running: boolean;
  onRun: () => void;
  onSelectDomain: (domain: string) => void;
}) {
  const [showOptional, setShowOptional] = useState(false);

  if (loading && !health && !fleet) {
    return (
      <section className="card">
        <div className="card-head">
          <Skeleton width={160} height={15} />
          <Skeleton width={60} height={26} />
        </div>
        <div style={{ padding: 20, display: "grid", gap: 10 }}>
          <Skeleton height={5} radius={99} />
          {[0, 1, 2, 3].map((index) => (
            <Skeleton key={index} height={34} radius={8} />
          ))}
        </div>
      </section>
    );
  }

  if (allDomains) {
    const items = fleet ?? [];
    const healthy = items.filter((item) => item.overall === "pass").length;
    return (
      <section className="card health-card">
        <div className="card-head">
          <div>
            <h2 className="card-title">Domain health</h2>
            <p className="card-sub">
              Live DNS · {healthy}/{items.length} domains healthy
            </p>
          </div>
          <Badge tone={healthy === items.length && items.length > 0 ? "good" : "warn"}>
            {healthy}/{items.length} healthy
          </Badge>
        </div>
        <div className="card-body" style={{ paddingTop: 10 }}>
          {items.length === 0 ? (
            <div className="empty" style={{ padding: "22px 10px" }}>
              <h3>No domains yet</h3>
              <p>Import a report to discover your first domain.</p>
            </div>
          ) : (
            <div className="fleet-health">
              {items.map((item) => (
                <button
                  key={item.domain}
                  className="fleet-health-row"
                  onClick={() => onSelectDomain(item.domain)}
                  type="button"
                >
                  <span className={`health-dot ${statusClass(item.overall)}`} />
                  <span className="fleet-name">{item.domain}</span>
                  <span className="fleet-score num">
                    {item.checked ? `${item.core_passed}/${item.core_total}` : "—"}
                  </span>
                  <span className="tiny muted">
                    {item.checked ? relativeTime(item.checked_at) : "not checked"}
                  </span>
                  <ArrowRight size={13} className="chev" />
                </button>
              ))}
            </div>
          )}
          <p className="tiny muted" style={{ marginTop: 12 }}>
            Select a domain to run and inspect its checks.
          </p>
        </div>
      </section>
    );
  }

  if (!health) {
    return (
      <section className="card health-card">
        <div className="card-head">
          <div>
            <h2 className="card-title">Domain health</h2>
            <p className="card-sub">Live DNS checks</p>
          </div>
        </div>
        <div className="empty" style={{ padding: "26px 20px" }}>
          <div className="empty-icon">
            <ShieldQuestion size={20} />
          </div>
          <h3>Not checked yet</h3>
          <p>Verify DMARC, SPF, DKIM, MX, MTA-STS and more against live DNS.</p>
          <button className="btn primary" onClick={onRun} disabled={running} type="button">
            {running ? <span className="spinner" /> : <RefreshCw size={14} />}
            Run checks
          </button>
        </div>
      </section>
    );
  }

  const core = health.results.filter((result) => result.core);
  const optional = health.results.filter((result) => !result.core);
  const meta = overallMeta[health.overall];
  const failing = health.results.filter((result) => result.status === "fail");
  const warnings = health.results.filter((result) => result.status === "warn");

  return (
    <section className="card health-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Domain health</h2>
          <p className="card-sub">
            Live DNS · checked {relativeTime(health.checked_at)}
            {health.stale ? " · stale" : ""}
          </p>
        </div>
        <div className="health-score">
          <span className="score-value num">
            {health.core_passed}/{health.core_total}
          </span>
          <span className="score-label">core checks passing</span>
        </div>
      </div>
      <div className="card-body" style={{ paddingTop: 10 }}>
        <div className="health-meter-row">
          <div className={`health-meter ${statusClass(health.overall)}`}>
            <span style={{ width: `${Math.max(3, health.score * 100)}%` }} />
          </div>
          <Badge tone={meta.tone}>{meta.label}</Badge>
        </div>

        <div className="health-rows">
          {core.map((result) => (
            <CheckRow key={result.key} result={result} />
          ))}
        </div>

        {optional.length > 0 ? (
          <>
            <button
              className="health-more"
              onClick={() => setShowOptional((value) => !value)}
              type="button"
              aria-expanded={showOptional}
            >
              <ChevronDown
                size={13}
                style={{ transform: showOptional ? "none" : "rotate(-90deg)", transition: "transform .2s" }}
              />
              {optional.filter((result) => result.status === "warn" || result.status === "fail").length === 0
                ? "Optional checks clean"
                : `${optional.filter((result) => result.status === "warn" || result.status === "fail").length} optional ${
                    optional.filter((result) => result.status === "warn" || result.status === "fail").length === 1
                      ? "warning"
                      : "warnings"
                  }`}
            </button>
            {showOptional ? (
              <div className="health-rows optional">
                {optional.map((result) => (
                  <CheckRow key={result.key} result={result} />
                ))}
              </div>
            ) : null}
          </>
        ) : null}

        {failing.length > 0 ? (
          <p className="health-note bad">
            <b>{failing[0].label}:</b> {failing[0].remediation || failing[0].summary}
          </p>
        ) : warnings.length > 0 ? (
          <p className="health-note warn">
            <b>{warnings[0].label}:</b> {warnings[0].summary}
          </p>
        ) : null}

        <div className="health-actions">
          <button className="btn ghost" onClick={onRun} disabled={running} type="button">
            {running ? <span className="spinner dark" /> : <RefreshCw size={13} />}
            {running ? "Checking…" : "Re-check"}
          </button>
          <Link className="link" to="/health">
            All checks
            <ArrowRight size={12} />
          </Link>
        </div>
      </div>
    </section>
  );
}
