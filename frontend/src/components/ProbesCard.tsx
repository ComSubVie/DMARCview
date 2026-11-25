import { ArrowRight, Lock, Server } from "lucide-react";
import { Link } from "react-router-dom";
import type { DomainHealth, FleetHealthItem, TransportProbeResult } from "../types";
import { relativeTime } from "../lib/format";
import { Skeleton } from "./ui";
import { expiryTone, statusClass } from "./health-ui";

function ProbeRow({ probe }: { probe: TransportProbeResult }) {
  const tone = expiryTone(probe.days_left);
  return (
    <div className="probe-row">
      <span className={`health-dot ${statusClass(probe.status === "pass" ? "pass" : probe.status)}`} />
      <div style={{ minWidth: 0 }}>
        <div className="probe-host">
          {probe.host}
          <span className="probe-port">:{probe.port}</span>
        </div>
        <div
          className="probe-meta"
          title={String(probe.details?.dane_detail ?? "") || undefined}
        >
          {probe.error ??
            `${probe.tls_version ?? "TLS"}${
              probe.dane_status === "match"
                ? " · DANE"
                : probe.dane_status === "unvalidated"
                  ? " · DANE unvalidated"
                  : ""
            }`}
        </div>
      </div>
      <span className={`probe-days ${statusClass(tone)}`}>
        {probe.days_left === null ? "—" : `${probe.days_left}d`}
      </span>
    </div>
  );
}

export function ProbesCard({
  health,
  fleet,
  allDomains,
  loading,
}: {
  health: DomainHealth | null;
  fleet: FleetHealthItem[] | null;
  allDomains: boolean;
  loading: boolean;
}) {
  if (loading && !health && !fleet) {
    return (
      <section className="card probes-card">
        <div className="card-head">
          <Skeleton width={150} height={15} />
        </div>
        <div style={{ padding: 20, display: "grid", gap: 10 }}>
          <Skeleton height={30} />
          <Skeleton height={30} />
        </div>
      </section>
    );
  }

  if (allDomains) {
    const items = fleet ?? [];
    const failing = items.reduce((sum, item) => sum + item.failing_probes, 0);
    const expiries = items
      .map((item) => item.next_expiry_days)
      .filter((value): value is number => value !== null && value !== undefined);
    const nextExpiry = expiries.length > 0 ? Math.min(...expiries) : null;
    return (
      <section className="card probes-card">
        <div className="card-head">
          <div>
            <h2 className="card-title">Transport & certificates</h2>
            <p className="card-sub">STARTTLS, TLS versions and expiry</p>
          </div>
          <Lock size={15} color="#98a2b3" />
        </div>
        <div className="card-body">
          <div className="probe-stats">
            <div>
              <span className="probe-stat-value num">{failing}</span>
              <span className="probe-stat-label">failing probes</span>
            </div>
            <div>
              <span className={`probe-stat-value num ${nextExpiry !== null && nextExpiry <= 21 ? "warn" : ""}`}>
                {nextExpiry === null ? "—" : `${nextExpiry}d`}
              </span>
              <span className="probe-stat-label">next expiry</span>
            </div>
          </div>
          <p className="tiny muted" style={{ marginTop: 10, lineHeight: 1.6 }}>
            Pick a domain to inspect its MX, submission and IMAP certificates.
          </p>
          <Link className="link" to="/health">
            Open health checks
            <ArrowRight size={12} />
          </Link>
        </div>
      </section>
    );
  }

  const probes = health?.probes ?? [];
  return (
    <section className="card probes-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Transport & certificates</h2>
          <p className="card-sub">
            {probes.length > 0
              ? `Live STARTTLS · checked ${relativeTime(health?.checked_at)}`
              : "Live STARTTLS and certificate checks"}
          </p>
        </div>
        <Server size={15} color="#98a2b3" />
      </div>
      <div className="card-body" style={{ paddingTop: 10 }}>
        {probes.length === 0 ? (
          <div className="empty" style={{ padding: "18px 8px" }}>
            <div className="empty-icon">
              <Lock size={18} />
            </div>
            <h3>No probes yet</h3>
            <p>
              MX hosts are probed automatically. Add extra host:port targets in the domain’s health
              settings.
            </p>
          </div>
        ) : (
          <div className="probe-list">
            {probes.slice(0, 5).map((probe) => (
              <ProbeRow key={`${probe.host}-${probe.port}`} probe={probe} />
            ))}
          </div>
        )}
        <Link className="link" to="/health" style={{ marginTop: 12 }}>
          Probe details
          <ArrowRight size={12} />
        </Link>
      </div>
    </section>
  );
}
