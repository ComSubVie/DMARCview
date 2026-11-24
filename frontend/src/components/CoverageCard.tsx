import { ArrowRight } from "lucide-react";
import type { CoverageDetail } from "../types";
import { relativeTime, shortDate } from "../lib/format";
import { Badge } from "./ui";

export function CoverageCard({
  coverage,
  allDomains,
}: {
  coverage: CoverageDetail;
  allDomains: boolean;
}) {
  const policy = coverage.subdomain_policy;
  return (
    <section className="card coverage-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Sending coverage</h2>
          <p className="card-sub">Reporter gaps, other header-from domains and the policy ramp</p>
        </div>
        <Badge tone="info">{coverage.reporters.length} reporter{coverage.reporters.length === 1 ? "" : "s"}</Badge>
      </div>
      <div className="coverage-grid">
        <div className="coverage-block">
          <h3>Reporters</h3>
          <div className="coverage-list">
            {coverage.reporters.length === 0 ? (
              <p className="tiny muted">No reports in this period.</p>
            ) : (
              coverage.reporters.map((reporter) => (
                <div className="coverage-row" key={`${reporter.org}-${reporter.status}`}>
                  <span className={`coverage-dot ${reporter.status}`} />
                  <span className="coverage-name">{reporter.org}</span>
                  <span className="tiny muted">{reporter.reports} reports</span>
                  <span className={`tiny ${reporter.status === "silent" ? "coverage-silent" : "muted"}`}>
                    {reporter.status === "silent"
                      ? "silent"
                      : reporter.last_report
                        ? relativeTime(reporter.last_report)
                        : "—"}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="coverage-block">
          <div className="coverage-block-head">
            <h3>Other header-from domains</h3>
            {!allDomains && policy ? <Badge tone={policy === "none" ? "warn" : "neutral"}>sp={policy}</Badge> : null}
          </div>
          {allDomains ? (
            <p className="tiny muted">Select a domain to compare observed header-from domains with its sp= policy.</p>
          ) : coverage.subdomains.length === 0 ? (
            <p className="tiny muted">No other header-from domains observed.</p>
          ) : (
            <div className="coverage-list">
              {coverage.subdomains.map((subdomain) => (
                <div className="coverage-row" key={subdomain.domain}>
                  <span className="coverage-name">{subdomain.domain}</span>
                  <span className="tiny muted">
                    {subdomain.messages} msgs · {subdomain.aligned_pct.toFixed(1)}%
                  </span>
                  <span className="tiny muted">{subdomain.sources} src</span>
                  <Badge tone={subdomain.status === "covered" ? "good" : "warn"}>{subdomain.status}</Badge>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="coverage-block">
          <h3>Policy ramp</h3>
          {allDomains ? (
            <p className="tiny muted">Select a domain to see its pct= ramp timeline.</p>
          ) : coverage.pct_start === null || coverage.pct_latest === null ? (
            <p className="tiny muted">No pct changes observed in this period.</p>
          ) : (
            <div className="pct-ramp">
              <div className="pct-ramp-value">
                {coverage.pct_start}%
                {coverage.pct_start !== coverage.pct_latest ? (
                  <>
                    <ArrowRight size={16} />
                    {coverage.pct_latest}%
                  </>
                ) : null}
              </div>
              <p className="tiny muted" style={{ margin: 0 }}>
                {coverage.pct_start === coverage.pct_latest
                  ? "stable"
                  : `over ${coverage.ramp_days ?? 0} days`}
                {coverage.pct_timeline.length > 0
                  ? ` · ${shortDate(coverage.pct_timeline[0].date)} – ${shortDate(
                      coverage.pct_timeline[coverage.pct_timeline.length - 1].date,
                    )}`
                  : ""}
              </p>
              {coverage.pct_start !== coverage.pct_latest ? (
                <div className="pct-steps">
                  {coverage.pct_timeline.slice(-6).map((point) => (
                    <span key={point.date}>{point.pct}%</span>
                  ))}
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
