import { Inbox, Mail, RadioTower, ShieldAlert, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { CountriesCard } from "../components/CountriesCard";
import { HealthCard } from "../components/HealthCard";
import { CoverageCard } from "../components/CoverageCard";
import { FleetTable } from "../components/FleetTable";
import { IdentitiesCard } from "../components/IdentitiesCard";
import { ProbesCard } from "../components/ProbesCard";
import { KpiCard } from "../components/KpiCard";
import { PolicyCard } from "../components/PolicyCard";
import { SourcesCard } from "../components/SourcesCard";
import { SummaryCard } from "../components/SummaryCard";
import { TlsTeaser } from "../components/TlsTeaser";
import { VolumeChart } from "../components/VolumeChart";
import { DashboardSkeleton, EmptyState } from "../components/ui";
import { formatNumber, rangeLabel, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { DomainHealth, FleetHealthItem } from "../types";

export function DashboardPage() {
  const { dashboard, domain, error, setDomain, toast } = useData();
  const [health, setHealth] = useState<DomainHealth | null>(null);
  const [fleet, setFleet] = useState<FleetHealthItem[] | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [runningChecks, setRunningChecks] = useState(false);

  useEffect(() => {
    document.title = "DMARCView — Overview";
  }, []);

  const loadHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      if (domain === "all") {
        const result = await api.fleetHealth();
        setFleet(result.items);
        setHealth(null);
      } else {
        setHealth(await api.domainHealth(domain));
        setFleet(null);
      }
    } catch {
      /* the card renders its own empty state */
    } finally {
      setHealthLoading(false);
    }
  }, [domain]);

  useEffect(() => {
    void loadHealth();
  }, [loadHealth, dashboard?.generated_at]);

  async function runChecks() {
    setRunningChecks(true);
    try {
      const result = await api.runDomainHealth(domain);
      setHealth(result);
      toast("Health checks completed");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Health checks failed", "error");
    } finally {
      setRunningChecks(false);
    }
  }

  if (error && !dashboard) {
    return (
      <section className="card" style={{ marginTop: 26 }}>
        <EmptyState icon={<ShieldAlert size={20} />} title="Could not load the dashboard">
          {error}
        </EmptyState>
      </section>
    );
  }

  if (!dashboard) return <DashboardSkeleton />;

  const kpis = dashboard.kpis;
  const activeDays = dashboard.daily.filter((day) => day.total > 0);
  const period =
    activeDays.length > 0
      ? rangeLabel(activeDays[0].date, activeDays[activeDays.length - 1].date)
      : rangeLabel(dashboard.range.start, dashboard.range.end);
  const target = domain === "all" ? "all domains" : dashboard.domain?.name ?? domain;
  const providers = Array.from(new Set(dashboard.submitters.map((item) => item.name)));
  const providerText =
    providers.length === 0
      ? "no reporters yet"
      : providers.slice(0, 3).join(", ") + (providers.length > 3 ? ` +${providers.length - 3}` : "");
  const alignedPct = kpis.messages > 0 ? (kpis.aligned / kpis.messages) * 100 : 0;
  const verifiedPct = kpis.sources > 0 ? (kpis.verified_sources / kpis.sources) * 100 : 0;
  const failedPct = kpis.messages > 0 ? (kpis.failed / kpis.messages) * 100 : 0;
  const coveragePct =
    dashboard.coverage.days > 0
      ? (dashboard.coverage.days_with_reports / dashboard.coverage.days) * 100
      : 0;
  const exportQuery = new URLSearchParams({ days: String(dashboard.range.days) });
  if (domain !== "all") exportQuery.set("domain", domain);
  const sourcesExport = `/api/export/sources.csv?${exportQuery.toString()}`;
  const volumePct =
    dashboard.volume.alert_threshold > 0
      ? Math.min(100, (dashboard.volume.month_messages / dashboard.volume.alert_threshold) * 100)
      : 0;

  return (
    <div className="fade-in">
      <div className="hero">
        <div>
          <span className="eyebrow">
            <span className="dot" />
            Reporting period · {period}
          </span>
          <h1>
            Email authentication for <span className="target">{target}</span>
          </h1>
        </div>
        <div className="hero-side">
          <span className="providers">
            <span className="dot" />
            Reported by {kpis.providers} mailbox {kpis.providers === 1 ? "provider" : "providers"} ·{" "}
            {providerText}
          </span>
          <span className="stamp">
            Last report ingested {relativeTime(dashboard.coverage.last_ingested_at)}
          </span>
        </div>
      </div>

      {dashboard.report_gaps.length > 0 ? (
        <section className="gap-banner" role="status">
          <span className="gap-icon">
            <Inbox size={16} />
          </span>
          <div>
            <strong>
              {dashboard.report_gaps.length === 1
                ? "DMARC reports stopped"
                : `DMARC reports stopped for ${dashboard.report_gaps.length} domains`}
            </strong>
            <p>
              {dashboard.report_gaps
                .slice(0, 3)
                .map(
                  (gap) =>
                    `${gap.domain}: ${gap.hours}h since the last report (expected every ${gap.expected_hours}h)`,
                )
                .join(" · ")}
              {dashboard.report_gaps.length > 3
                ? ` · +${dashboard.report_gaps.length - 3} more`
                : ""}
            </p>
          </div>
          <Link className="btn soft" to="/ingest">
            Check ingestion
          </Link>
        </section>
      ) : null}

      {kpis.messages === 0 ? (
        <section className="card" style={{ marginTop: 6 }}>
          <EmptyState
            icon={<Inbox size={21} />}
            title="No reports for this selection yet"
            action={
              <Link className="btn primary lg" to="/ingest" style={{ marginTop: 8 }}>
                Connect or import reports
              </Link>
            }
          >
            Point DMARCView at your report mailbox over JMAP, or upload a few <code>.eml</code> files
            to try it out. DMARC and TLS-RPT reports normally arrive once a day.
          </EmptyState>
        </section>
      ) : (
        <>
          <div className="kpis">
            <KpiCard
              icon={<Mail size={17} />}
              tone="blue"
              value={formatNumber(kpis.messages)}
              label="Total messages"
              pct={alignedPct}
            />
            <KpiCard
              icon={<ShieldCheck size={17} />}
              tone="green"
              value={kpis.aligned_pct.toFixed(1)}
              suffix="%"
              label="Aligned (DMARC pass)"
              pct={alignedPct}
            />
            <KpiCard
              icon={<RadioTower size={17} />}
              tone="blue"
              value={formatNumber(kpis.sources)}
              label="Active sending sources"
              pct={verifiedPct}
            />
            <KpiCard
              icon={<ShieldAlert size={17} />}
              tone="red"
              value={formatNumber(kpis.failed)}
              label="Messages that couldn’t be verified"
              pct={failedPct}
            />
          </div>

          <section className="card volume">
            <div className="volume-cols">
              <div className="volume-col">
                <div className="volume-head">
                  <span className="volume-label">Messages this month</span>
                  <span className="volume-value">
                    <strong>{formatNumber(dashboard.volume.month_messages)}</strong> of{" "}
                    {formatNumber(dashboard.volume.alert_threshold)}
                  </span>
                </div>
                <div className="track">
                  <span style={{ width: `${Math.max(2, volumePct)}%` }} />
                </div>
              </div>
              <div className="volume-col">
                <div className="volume-head">
                  <span className="volume-label">Report coverage</span>
                  <span className="volume-value">
                    <strong>{dashboard.coverage.days_with_reports}</strong> of{" "}
                    {dashboard.coverage.days} days · {dashboard.coverage.reports} reports
                  </span>
                </div>
                <div className="track green">
                  <span style={{ width: `${Math.max(2, coveragePct)}%` }} />
                </div>
              </div>
            </div>
          </section>

          <div className="grid cols-8-4">
            <HealthCard
              health={health}
              fleet={fleet}
              allDomains={domain === "all"}
              loading={healthLoading}
              running={runningChecks}
              onRun={runChecks}
              onSelectDomain={(name) => setDomain(name)}
            />
            <ProbesCard
              health={health}
              fleet={fleet}
              allDomains={domain === "all"}
              loading={healthLoading}
            />
          </div>

          {dashboard.fleet.length > 0 ? <FleetTable items={dashboard.fleet} /> : null}

          <div className="grid cols-8-4">
            <VolumeChart daily={dashboard.daily} days={dashboard.range.days} anomaly={dashboard.anomaly} />
            <SummaryCard
              sentences={kpis.sentences}
              failed={kpis.failed}
              policy={dashboard.policy}
              changes={dashboard.changes}
            />
          </div>

          <div className="grid cols-8-4 grid-bottom">
            <SourcesCard sources={dashboard.sources} exportHref={sourcesExport} />
            <div className="stack right">
              <CountriesCard countries={dashboard.countries} />
              <TlsTeaser tls={dashboard.tls} />
              <PolicyCard
                policy={dashboard.policy}
                advice={dashboard.advice}
                overview={dashboard.policy_overview}
                fleet={dashboard.domain === null}
              />
            </div>
          </div>

          <IdentitiesCard identities={dashboard.identities} />
          <CoverageCard coverage={dashboard.coverage_detail} allDomains={domain === "all"} />
        </>
      )}
    </div>
  );
}
