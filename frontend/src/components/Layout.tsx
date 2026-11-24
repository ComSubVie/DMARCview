import { CalendarRange, Globe2, LogOut, RefreshCw, Settings2, Share2, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useData } from "../state";
import { ShareDrawer } from "./ShareDrawer";
import { formatPct, relativeTime } from "../lib/format";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/health", label: "Health", end: false },
  { to: "/alerts", label: "Alerts", end: false },
  { to: "/reports", label: "Reports", end: false },
  { to: "/tls", label: "TLS", end: false },
  { to: "/ingest", label: "Ingestion", end: false },
  { to: "/audit", label: "Audit", end: false },
];

export function Layout({
  user,
  onSignOut,
  children,
}: {
  user: string;
  onSignOut: () => void;
  children: React.ReactNode;
}) {
  const {
    meta,
    domain,
    setDomain,
    days,
    setDays,
    dashboard,
    loading,
    refresh,
    toast,
    toastMessage,
  } = useData();
  const navigate = useNavigate();
  const location = useLocation();
  const [signingOut, setSigningOut] = useState(false);
  const [sharing, setSharing] = useState(false);

  const pct = dashboard?.kpis.aligned_pct;
  const tone = pct === undefined ? "" : pct >= 95 ? "good" : pct >= 80 ? "warn" : "bad";
  const initials = user.replace(/[^a-zA-Z0-9]/g, "").slice(0, 2).toUpperCase() || "DV";

  async function handleSignOut() {
    setSigningOut(true);
    try {
      await api.logout();
    } finally {
      setSigningOut(false);
      onSignOut();
      navigate("/");
    }
  }

  async function handleRefresh() {
    await refresh();
    toast("Dashboard refreshed");
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-inner">
          <NavLink to="/" className="brand" aria-label="DMARCView home">
            <span className="brand-mark">
              <ShieldCheck size={17} strokeWidth={2.2} />
            </span>
            <span className="brand-word">
              DMARC<span>View</span>
            </span>
          </NavLink>

          <nav className="nav" aria-label="Main">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => (isActive ? "active" : "")}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="topbar-right">
            <div className="compliance">
              <span className="eyebrow">Compliance</span>
              <strong style={tone === "bad" ? { color: "var(--red)" } : undefined}>
                {pct === undefined ? "—" : formatPct(pct)}
              </strong>
            </div>
            <button
              className="btn ghost icon"
              onClick={() => setSharing(true)}
              aria-label="Share dashboard"
              title="Share dashboard"
              type="button"
            >
              <Share2 size={15} />
            </button>
            <button className="btn ghost icon" onClick={handleRefresh} aria-label="Refresh data" type="button">
              <RefreshCw size={15} className={loading ? "spin" : undefined} />
            </button>
            <button className="btn ghost hide-sm" onClick={handleSignOut} disabled={signingOut} type="button">
              <LogOut size={14} />
              Sign out
            </button>
            <span className="avatar" title={user}>
              {initials}
            </span>
          </div>
        </div>
      </header>

      {location.pathname !== "/alerts" ? (
      <div className="toolbar">
        <label className="select strong">
          <Globe2 size={15} />
          <select
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            aria-label="Select domain"
          >
            <option value="all">All domains</option>
            {meta?.domains.map((item) => (
              <option key={item.name} value={item.name}>
                {item.display_name}
              </option>
            ))}
          </select>
        </label>

        <label className="select">
          <CalendarRange size={15} />
          <select
            value={days}
            onChange={(event) => setDays(Number(event.target.value))}
            aria-label="Select reporting period"
          >
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        </label>

        <button className="btn soft" onClick={() => navigate("/ingest")} type="button">
          <Settings2 size={14} />
          Settings
        </button>

        <div className="toolbar-right">
          <span className="tiny muted">
            Updated {relativeTime(dashboard?.generated_at)}
          </span>
        </div>
      </div>
      ) : null}

      {children}

      <footer className="app-footer">
        <span>DMARCView {meta?.version ?? "—"}</span>
        <span>Self-hosted · no telemetry</span>
      </footer>

      {sharing ? <ShareDrawer onClose={() => setSharing(false)} /> : null}

      {toastMessage ? (
        <div className={`toast ${toastMessage.tone === "error" ? "error" : ""}`} role="status">
          {toastMessage.text}
        </div>
      ) : null}
    </div>
  );
}
