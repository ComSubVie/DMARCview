import { ArrowRight, Sparkles } from "lucide-react";
import { Link } from "react-router-dom";
import type { Advice, Policy, PolicyOverviewItem } from "../types";
import { Badge } from "./ui";

export function PolicyCard({
  policy,
  advice,
  overview = [],
  fleet = false,
}: {
  policy: Policy | null;
  advice: Advice;
  overview?: PolicyOverviewItem[];
  fleet?: boolean;
}) {
  if (fleet) {
    return (
      <section className="card policy-card">
        <div className="policy-head">
          <span className="eyebrow">
            <span className="dot" />
            Policy advisor
          </span>
          <Badge tone="info">{overview.length} domains</Badge>
        </div>
        <div className="card-body">
          <h3>Policy by domain</h3>
          <div className="policy-domains">
            {overview.length === 0 ? (
              <p className="tiny muted">No policies observed yet.</p>
            ) : (
              overview.map((item) => (
                <div className="policy-domain" key={item.domain}>
                  <span className="pd-name">{item.domain}</span>
                  <span className={`pd-p p-${item.p}`}>p={item.p}</span>
                  <span className="pd-pct">{item.aligned_pct === null ? "—" : `${item.aligned_pct.toFixed(0)}%`}</span>
                </div>
              ))
            )}
          </div>
          <p className="tiny" style={{ marginTop: 12, lineHeight: 1.6, color: "#5b5580" }}>
            Pick a domain in the toolbar to see its recommendation, sending sources and policy
            history.
          </p>
          <div style={{ marginTop: 14 }}>
            <Link className="btn green lg" to="/reports">
              Review reports
              <ArrowRight size={15} />
            </Link>
          </div>
        </div>
      </section>
    );
  }

  if (!policy || !policy.available) {
    return (
      <section className="card policy-card">
        <div className="policy-head">
          <span className="eyebrow">
            <span className="dot" />
            Policy advisor
          </span>
        </div>
        <div className="card-body">
          <h3>No policy observed</h3>
          <p className="tiny muted" style={{ marginTop: 8, lineHeight: 1.6 }}>
            {policy?.message ?? "Import DMARC reports to see the published policy and get a recommendation."}
          </p>
        </div>
      </section>
    );
  }

  const tone = advice.tone === "good" ? "good" : advice.tone === "warn" ? "warn" : "info";
  const statusLabel =
    policy.p === "reject" ? "Enforced" : policy.p === "quarantine" ? "Quarantine" : "Monitoring";

  return (
    <section className="card policy-card">
      <div className="policy-head">
        <span className="eyebrow">
          <span className="dot" />
          Policy advisor
        </span>
        <Badge tone={tone}>{statusLabel}</Badge>
      </div>
      <div className="card-body">
        <h3>{advice.label}</h3>

        <div className="policy-current">Current published policy</div>
        <div className="policy-code">{policy.label ?? `p=${policy.p ?? "none"}`}</div>

        <div className="policy-options">
          {advice.options.map((option) => (
            <div className={`policy-option ${option.state === "active" ? "on" : ""}`} key={option.value}>
              <span className="p-dot" />
              <span style={{ display: "grid", gap: 1 }}>
                <span className="p-name">{option.label}</span>
                <span className="p-detail">{option.detail}</span>
              </span>
            </div>
          ))}
        </div>

        <p className="tiny" style={{ marginTop: 14, lineHeight: 1.6, color: "#5b5580" }}>
          {advice.advice}
        </p>

        <div style={{ marginTop: 16, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <Link className="btn green lg" to="/reports">
            Review reports
            <ArrowRight size={15} />
          </Link>
          <Link className="link" to="/ingest">
            <Sparkles size={13} />
            See raw reports
          </Link>
        </div>
      </div>
    </section>
  );
}
