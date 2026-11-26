import { Inbox, Mail, RadioTower, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { CountriesCard } from "../components/CountriesCard";
import { KpiCard } from "../components/KpiCard";
import { PolicyCard } from "../components/PolicyCard";
import { SourcesCard } from "../components/SourcesCard";
import { SummaryCard } from "../components/SummaryCard";
import { TlsTeaser } from "../components/TlsTeaser";
import { VolumeChart } from "../components/VolumeChart";
import { Badge, DashboardSkeleton, EmptyState } from "../components/ui";
import { dateTime, formatNumber } from "../lib/format";
import type { PublicShareView } from "../types";

export function SharedView() {
  const { token } = useParams<{ token: string }>();
  const [view, setView] = useState<PublicShareView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.title = "DMARCView — Shared view";
    let cancelled = false;
    if (!token) {
      setError("Missing share token");
      return;
    }
    api
      .publicView(token)
      .then((result) => {
        if (!cancelled) setView(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError && err.status === 404
              ? "This share link is invalid, revoked or expired."
              : err instanceof Error
                ? err.message
                : "Could not load the shared view.",
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  if (error) {
    return (
      <div className="public-page">
        <PublicHeader expiresAt={null} />
        <main className="shell public-shell">
          <section className="card" style={{ marginTop: 30 }}>
            <EmptyState icon={<ShieldAlert size={20} />} title="Shared view unavailable">
              {error}
            </EmptyState>
          </section>
        </main>
      </div>
    );
  }

  if (!view) {
    return (
      <div className="public-page">
        <PublicHeader expiresAt={null} />
        <main className="shell public-shell">
          <DashboardSkeleton />
        </main>
      </div>
    );
  }

  const { dashboard, scope } = view;
  const kpis = dashboard.kpis;
  const alignedPct = kpis.messages > 0 ? (kpis.aligned / kpis.messages) * 100 : 0;
  const verifiedPct = kpis.sources > 0 ? (kpis.verified_sources / kpis.sources) * 100 : 0;
  const failedPct = kpis.messages > 0 ? (kpis.failed / kpis.messages) * 100 : 0;
  const target = dashboard.domain?.display_name || scope.domain || "all domains";

  return (
    <div className="public-page">
      <PublicHeader expiresAt={scope.expires_at} />
      <main className="shell public-shell">
        <div className="hero" style={{ marginTop: 18 }}>
          <div>
            <span className="eyebrow">
              <span className="dot" />
              Read-only · last {scope.days} days
            </span>
            <h1>
              Email authentication for <span className="target">{target}</span>
            </h1>
          </div>
          <div className="hero-side">
            <span className="providers">
              <span className="dot" />
              Reported by {kpis.providers} mailbox {kpis.providers === 1 ? "provider" : "providers"}
            </span>
          </div>
        </div>

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
          {dashboard.sources.length > 0 ? (
            <SourcesCard sources={dashboard.sources} interactive={false} />
          ) : (
            <section className="card">
              <div className="card-body">
                <EmptyState icon={<Inbox size={20} />} title="Sending sources are hidden">
                  This shared view only includes aggregate figures. Ask the owner for a link
                  with sources enabled if you need IP-level detail.
                </EmptyState>
              </div>
            </section>
          )}
          <div className="stack right">
            <CountriesCard countries={dashboard.countries} />
            <TlsTeaser tls={dashboard.tls} readonly />
            <PolicyCard
              policy={dashboard.policy}
              advice={dashboard.advice}
              overview={dashboard.policy_overview}
              fleet={dashboard.domain === null}
              readonly
            />
          </div>
        </div>

        <p className="tiny muted" style={{ marginTop: 22, textAlign: "center" }}>
          Read-only shared view · expires {dateTime(scope.expires_at)} · DMARCView
        </p>
      </main>
    </div>
  );
}

function PublicHeader({ expiresAt }: { expiresAt: string | null }) {
  return (
    <header className="public-topbar">
      <div className="public-brand">
        <span className="brand-mark">
          <ShieldCheck size={16} strokeWidth={2.2} />
        </span>
        <span className="brand-word">
          DMARC<span>View</span>
        </span>
      </div>
      <div className="public-meta">
        <Badge tone="info">Shared view</Badge>
        {expiresAt ? <span className="tiny muted">expires {dateTime(expiresAt)}</span> : null}
      </div>
    </header>
  );
}
