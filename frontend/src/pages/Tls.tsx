import { ChevronRight, Download, Lock, Server, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, ApiError, rawTlsReportUrl } from "../api";
import { Drawer } from "../components/Drawer";
import { Badge, CopyButton, EmptyState, Skeleton } from "../components/ui";
import { formatNumber, formatPct, longDate, shortDate } from "../lib/format";
import { useData } from "../state";
import type { TlsDashboard, TlsReportDetail, TlsReportRow } from "../types";

function policyText(policy: {
  string: string[];
  type?: string | null;
  mode?: string | null;
  mx_hosts: string[];
}): string {
  return policy.string.length > 0
    ? policy.string.join("\n")
    : `${policy.type ?? "—"}\n${policy.mode ?? "—"}\n${policy.mx_hosts.join(", ")}`;
}

function TlsTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { dataKey?: string | number; value?: number }[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const success = Number(payload.find((item) => item.dataKey === "success")?.value ?? 0);
  const failure = Number(payload.find((item) => item.dataKey === "failure")?.value ?? 0);
  return (
    <div className="chart-tooltip">
      <div className="tt-date">{label}</div>
      <div className="tt-row">
        <span className="swatch" style={{ background: "#14b8a6" }} />
        Encrypted <b>{formatNumber(success)}</b>
      </div>
      <div className="tt-row">
        <span className="swatch" style={{ background: "#f43f5e" }} />
        Failed <b>{formatNumber(failure)}</b>
      </div>
    </div>
  );
}

function TlsDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const [report, setReport] = useState<TlsReportDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.tlsReport(id).then((data) => !cancelled && setReport(data)).catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [id]);

  return (
    <Drawer
      title={report ? `${report.org_name} · TLS-RPT` : "TLS report"}
      subtitle={report?.report_id}
      onClose={onClose}
    >
      {!report ? (
        <Skeleton height={240} />
      ) : (
        <>
          <div className="meta-grid">
            <div className="meta-cell">
              <div className="k">Report</div>
              <div className="v" style={{ fontFamily: "var(--font-mono)", fontSize: 11.5 }}>
                {report.report_id}
              </div>
            </div>
            <div className="meta-cell">
              <div className="k">Period</div>
              <div className="v">
                {longDate(report.date_begin)} – {longDate(report.date_end)}
              </div>
            </div>
            <div className="meta-cell">
              <div className="k">Sessions</div>
              <div className="v">
                {formatNumber(report.success)} ok · {formatNumber(report.failure)} failed
              </div>
            </div>
            <div className="meta-cell">
              <div className="k">Contact</div>
              <div className="v" style={{ fontSize: 11.5 }}>
                {report.contact_info || "—"}
              </div>
            </div>
          </div>

          <section className="card" style={{ padding: 16 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <div className="eyebrow">Published policy</div>
              <CopyButton value={policyText(report.policy)} label="Copy TLS policy" />
            </div>
            <pre
              style={{
                margin: "8px 0 0",
                fontFamily: "var(--font-mono)",
                fontSize: 12,
                lineHeight: 1.7,
                color: "#312e81",
                whiteSpace: "pre-wrap",
              }}
            >
              {report.policy.string.length > 0
                ? report.policy.string.join("\n")
                : `policy-type: ${report.policy.type}\nmode: ${report.policy.mode}\nmx: ${report.policy.mx_hosts.join(", ")}`}
            </pre>
          </section>

          <table className="data">
            <thead>
              <tr>
                <th>Receiving MX</th>
                <th className="center">OK</th>
                <th className="center">Failed</th>
              </tr>
            </thead>
            <tbody>
              {report.policies.map((policy) => (
                <tr key={`${policy.domain}-${policy.mx_hosts.join()}`}>
                  <td>
                    <div className="primary-cell">{policy.mx_hosts.join(", ") || "—"}</div>
                    <div className="tiny muted">{policy.domain}</div>
                  </td>
                  <td className="center num">{formatNumber(policy.success)}</td>
                  <td className="center num">{formatNumber(policy.failure)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {report.failure_details.length > 0 ? (
            <div className="failure-list">
              {report.failure_details.map((item, index) => (
                <div className="failure-item" key={`${item.result_type}-${index}`}>
                  <div className="f-top">
                    <span className="f-name">{item.result_type}</span>
                    <span className="f-count">{formatNumber(item.count)} failed</span>
                  </div>
                  <div className="f-meta">
                    <span>
                      {item.country.flag || "🌐"} {item.country.name || item.ip || "—"}
                    </span>
                    <span>{item.mx}</span>
                    {item.reason ? <span>{item.reason}</span> : null}
                  </div>
                  {item.info ? <div className="tiny muted">{item.info}</div> : null}
                </div>
              ))}
            </div>
          ) : null}

          <div>
            <a className="btn ghost" href={rawTlsReportUrl(report.id)} download>
              <Download size={14} />
              Original JSON
            </a>
          </div>
        </>
      )}
    </Drawer>
  );
}

function Row({ report, onOpen }: { report: TlsReportRow; onOpen: () => void }) {
  return (
    <tr className="report-row" onClick={onOpen}>
      <td>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <span className="provider-dot" style={{ background: report.org_color, width: 8, height: 8 }} />
          <div>
            <div className="primary-cell">{report.org_name}</div>
            <div className="tiny muted" style={{ fontFamily: "var(--font-mono)" }}>
              {shortDate(report.date_begin)}
            </div>
          </div>
        </div>
      </td>
      <td className="hide-sm">{report.domain}</td>
      <td className="center num">{formatNumber(report.sessions)}</td>
      <td>
        <span className="pct-pill">
          <span className="pct-bar">
            <span
              className={report.success_pct < 95 ? "low" : ""}
              style={{ width: `${Math.max(3, report.success_pct)}%` }}
            />
          </span>
          {formatPct(report.success_pct)}
        </span>
      </td>
      <td className="center num hide-sm">{formatNumber(report.failure)}</td>
      <td className="hide-sm">
        <Badge tone={report.source === "jmap" ? "info" : "neutral"}>{report.source}</Badge>
      </td>
      <td style={{ width: 28 }}>
        <ChevronRight size={15} className="chev" />
      </td>
    </tr>
  );
}

export function TlsPage() {
  const { domain, days } = useData();
  const [data, setData] = useState<TlsDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [showAllReports, setShowAllReports] = useState(false);

  useEffect(() => {
    document.title = "DMARCView — TLS delivery";
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .tls(domain, days)
      .then((result) => !cancelled && setData(result))
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Could not load TLS data");
      });
    return () => {
      cancelled = true;
    };
  }, [domain, days]);

  if (error) {
    return (
      <section className="card" style={{ marginTop: 26 }}>
        <EmptyState icon={<ShieldAlert size={20} />} title="Could not load TLS delivery data">
          {error}
        </EmptyState>
      </section>
    );
  }

  if (!data) {
    return (
      <div className="fade-in">
        <div className="section-head">
          <Skeleton width={320} height={28} />
        </div>
        <div className="kpis">
          {[0, 1, 2, 3].map((index) => (
            <div className="card kpi" key={index}>
              <Skeleton width={34} height={34} radius={10} />
              <div style={{ marginTop: 16 }}>
                <Skeleton width={90} height={30} />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const kpis = data.kpis;
  const chartData = data.daily.map((point) => ({ ...point, label: shortDate(point.date) }));
  const target = domain === "all" ? "all domains" : data.domain?.name ?? domain;
  const peak = Math.max(4, ...data.daily.map((point) => point.total));

  return (
    <div className="fade-in">
      <div className="hero">
        <div>
          <span className="eyebrow">
            <span className="dot" />
            Reporting period · {longDate(data.range.start)} – {longDate(data.range.end)}
          </span>
          <h1>
            Encrypted delivery for <span className="target">{target}</span>
          </h1>
        </div>
        <div className="hero-side">
          <span className="providers">
            <span className="dot" />
            {kpis.reports} TLS reports · {kpis.submitters}{" "}
            {kpis.submitters === 1 ? "reporter" : "reporters"}
          </span>
          <span className="stamp">MTA-STS and DANE session telemetry</span>
          <a
            className="btn ghost"
            href={`/api/export/tls.csv?${new URLSearchParams({
              ...(domain === "all" ? {} : { domain }),
              days: String(days),
            }).toString()}`}
            download
            style={{ marginTop: 8 }}
          >
            Export CSV
          </a>
        </div>
      </div>

      <div className="kpis">
        <article className="card kpi">
          <div className="kpi-icon tone-blue">
            <Lock size={17} />
          </div>
          <div className="kpi-value num">{formatNumber(kpis.sessions)}</div>
          <div className="kpi-label">Reported TLS sessions</div>
          <div className="kpi-bar">
            <i style={{ width: `${Math.max(4, kpis.success_pct)}%`, background: "linear-gradient(90deg,#6366f1,#a5b4fc)" }} />
            <i className="alt" style={{ flex: 1, background: "linear-gradient(90deg,#6366f1,#a5b4fc)" }} />
          </div>
        </article>
        <article className="card kpi">
          <div className="kpi-icon tone-green">
            <ShieldCheck size={17} />
          </div>
          <div className="kpi-value num">
            {kpis.success_pct.toFixed(1)}
            <small>%</small>
          </div>
          <div className="kpi-label">Sessions encrypted successfully</div>
          <div className="kpi-bar">
            <i style={{ width: `${Math.max(4, kpis.success_pct)}%`, background: "linear-gradient(90deg,#0f766e,#a7f3d0)" }} />
            <i className="alt" style={{ flex: 1, background: "linear-gradient(90deg,#0f766e,#a7f3d0)" }} />
          </div>
        </article>
        <article className="card kpi">
          <div className="kpi-icon tone-red">
            <ShieldAlert size={17} />
          </div>
          <div className="kpi-value num">{formatNumber(kpis.failure)}</div>
          <div className="kpi-label">Failed sessions</div>
          <div className="kpi-bar">
            <i
              style={{
                width: `${Math.max(4, 100 - kpis.success_pct)}%`,
                background: "linear-gradient(90deg,#ef4444,#fecaca)",
              }}
            />
            <i className="alt" style={{ flex: 1, background: "linear-gradient(90deg,#ef4444,#fecaca)" }} />
          </div>
        </article>
        <article className="card kpi">
          <div className="kpi-icon tone-amber">
            <Server size={17} />
          </div>
          <div className="kpi-value num">{kpis.mx_hosts}</div>
          <div className="kpi-label">Receiving MX hosts</div>
          <div className="kpi-bar">
            <i style={{ width: "60%", background: "linear-gradient(90deg,#f59e0b,#fde68a)" }} />
            <i className="alt" style={{ flex: 1, background: "linear-gradient(90deg,#f59e0b,#fde68a)" }} />
          </div>
        </article>
      </div>

      <div className="grid cols-8-4">
        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">TLS sessions per day</h2>
              <p className="card-sub">Successful and failed STARTTLS negotiations</p>
            </div>
            <div className="chart-legend">
              <span>
                <span className="swatch" style={{ background: "#14b8a6" }} />
                Encrypted
              </span>
              <span>
                <span className="swatch" style={{ background: "#f43f5e" }} />
                Failed
              </span>
            </div>
          </div>
          <div className="card-body" style={{ paddingTop: 10 }}>
            {kpis.sessions === 0 ? (
              <EmptyState icon={<Lock size={20} />} title="No TLS reports in this period">
                Receiving mail servers report TLS negotiation outcomes once a day when your DNS
                policy publishes a TLS-RPT address.
              </EmptyState>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData} margin={{ top: 12, right: 10, left: -14, bottom: 0 }} barCategoryGap="28%">
                  <CartesianGrid strokeDasharray="2 6" vertical={false} stroke="#edf0f7" />
                  <XAxis
                    dataKey="label"
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 11, fill: "#98a2b3" }}
                    minTickGap={34}
                    dy={6}
                  />
                  <YAxis
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 11, fill: "#98a2b3" }}
                    width={46}
                    allowDecimals={false}
                    domain={[0, Math.ceil(peak * 1.2)]}
                    tickCount={4}
                  />
                  <Tooltip content={<TlsTooltip />} cursor={{ fill: "rgba(99,102,241,.06)" }} />
                  <Bar dataKey="success" stackId="sessions" fill="#14b8a6" radius={[0, 0, 3, 3]} />
                  <Bar dataKey="failure" stackId="sessions" fill="#f43f5e" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Published TLS policy</h2>
              <p className="card-sub">From the latest TLS-RPT report</p>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              {data.policy ? <CopyButton value={policyText(data.policy)} label="Copy TLS policy" /> : null}
              <Badge tone={data.policy?.mode === "enforce" ? "good" : "warn"}>
                {data.policy?.mode ?? "unknown"}
              </Badge>
            </div>
          </div>
          <div className="card-body">
            {data.policy ? (
              <>
                <pre
                  style={{
                    margin: 0,
                    padding: "11px 12px",
                    borderRadius: 10,
                    background: "#fbfcff",
                    border: "1px solid var(--line)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    lineHeight: 1.7,
                    color: "#312e81",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {data.policy.string.length > 0
                    ? data.policy.string.join("\n")
                    : `${data.policy.type}\n${data.policy.mode}\n${data.policy.mx_hosts.join(", ")}`}
                </pre>
                <div className="kv-list" style={{ marginTop: 14 }}>
                  <div className="kv">
                    <span className="k">Policy type</span>
                    <span className="v">{data.policy.type ?? "—"}</span>
                  </div>
                  <div className="kv">
                    <span className="k">Mode</span>
                    <span className="v">{data.policy.mode ?? "—"}</span>
                  </div>
                  <div className="kv">
                    <span className="k">Max age</span>
                    <span className="v">
                      {data.policy.max_age ? `${formatNumber(data.policy.max_age)}s` : "—"}
                    </span>
                  </div>
                  <div className="kv">
                    <span className="k">Observed since</span>
                    <span className="v">{data.policy.observed_since ? longDate(data.policy.observed_since) : "—"}</span>
                  </div>
                </div>
              </>
            ) : (
              <p className="tiny muted">No policy has been observed yet.</p>
            )}
          </div>
        </section>
      </div>

      <div className="grid cols-8-4">
        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Delivery failures</h2>
              <p className="card-sub">Why senders could not establish encrypted delivery</p>
            </div>
            <span className="chip red">
              {formatNumber(kpis.failure)} failed sessions
            </span>
          </div>
          <div className="card-body" style={{ paddingTop: 12 }}>
            {data.failures.length === 0 ? (
              <EmptyState icon={<ShieldCheck size={20} />} title="No failed sessions">
                Every reported session to your MX hosts negotiated TLS successfully.
              </EmptyState>
            ) : (
              <div className="failure-list">
                {data.failures.map((failure) => (
                  <div className="failure-item" key={failure.result_type}>
                    <div className="f-top">
                      <span className="f-name">{failure.result_type}</span>
                      <span className="f-count">
                        {formatNumber(failure.count)} {failure.count === 1 ? "session" : "sessions"}
                      </span>
                    </div>
                    <div className="f-meta">
                      <span>{failure.ips.join(", ") || "unknown sender"}</span>
                      <span>{failure.hosts.join(", ")}</span>
                      {failure.last_seen ? <span>last seen {shortDate(failure.last_seen)}</span> : null}
                    </div>
                    {failure.reasons.length > 0 ? (
                      <div className="tiny muted">reason: {failure.reasons.join(", ")}</div>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Receiving hosts</h2>
              <p className="card-sub">Per MX, by session volume</p>
            </div>
          </div>
          <div className="card-body" style={{ paddingTop: 10 }}>
            {data.policies.some((host) => host.host === "(not reported)") ? (
              <p className="tiny muted" style={{ marginBottom: 10, lineHeight: 1.5 }}>
                Some TLS-RPT records did not include <code>mx-host</code> or a policy string with an
                <code>mx:</code> entry. Run <code>python -m app.cli tls-reparse</code> to backfill
                reports whose raw JSON contains the host.
              </p>
            ) : null}
            {data.policies.length === 0 ? (
              <p className="tiny muted">No MX hosts reported.</p>
            ) : (
              <div style={{ display: "grid", gap: 14 }}>
                {data.policies.map((host) => (
                  <div key={host.host}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                      <span style={{ fontSize: 12.5, fontWeight: 550 }}>{host.host}</span>
                      <span className="tiny muted num">
                        {formatNumber(host.success)} ok · {formatNumber(host.failure)} failed
                      </span>
                    </div>
                    <div className="track" style={{ marginTop: 7 }}>
                      <span
                        style={{
                          width: `${Math.max(2, host.success_pct)}%`,
                          background: "linear-gradient(90deg,#0f766e,#14b8a6)",
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      <section className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <h2 className="card-title">Recent TLS reports</h2>
            <p className="card-sub">Click a report to inspect its failure details</p>
          </div>
        </div>
        <div style={{ padding: "4px 8px 8px" }}>
          {data.reports.length === 0 ? (
            <EmptyState icon={<Lock size={20} />} title="No TLS reports yet">
              Nothing has arrived for this selection.
            </EmptyState>
          ) : (
            <table className="data report-table">
              <thead>
                <tr>
                  <th>Report</th>
                  <th className="hide-sm">Domain</th>
                  <th className="center">Sessions</th>
                  <th>Success</th>
                  <th className="center hide-sm">Failed</th>
                  <th className="hide-sm">Source</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(showAllReports ? data.reports : data.reports.slice(0, 8)).map((report) => (
                  <Row key={report.id} report={report} onOpen={() => setSelected(report.id)} />
                ))}
              </tbody>
            </table>
          )}
          {data.reports.length > 8 ? (
            <div className="page-foot" style={{ borderTop: 0 }}>
              <span>
                Showing {showAllReports ? data.reports.length : 8} of {data.reports.length} reports
              </span>
              <button className="btn soft" onClick={() => setShowAllReports((value) => !value)} type="button">
                {showAllReports ? "Show latest 8" : `Show all ${data.reports.length}`}
              </button>
            </div>
          ) : null}
        </div>
      </section>

      {selected !== null ? <TlsDrawer id={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}
