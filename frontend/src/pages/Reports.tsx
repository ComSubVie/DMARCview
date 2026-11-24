import { ChevronLeft, ChevronRight, Download, FileText, Search, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { api, ApiError, rawReportUrl } from "../api";
import { Drawer } from "../components/Drawer";
import { Badge, CheckCell, CopyButton, EmptyState, Skeleton } from "../components/ui";
import { dateTime, formatNumber, longDate, shortDate } from "../lib/format";
import { useData } from "../state";
import type { ReportDetail, ReportsPage as ReportsPageData, ReportRow } from "../types";

function SourceChip({ source }: { source: string }) {
  const tone = source === "jmap" ? "info" : source === "upload" ? "neutral" : "neutral";
  return <Badge tone={tone}>{source}</Badge>;
}

function ReportDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .report(id)
      .then((data) => !cancelled && setReport(data))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : "Could not load report"));
    return () => {
      cancelled = true;
    };
  }, [id]);

  return (
    <Drawer
      title={report ? `${report.org_name} · ${report.domain}` : "Report"}
      subtitle={report ? `${report.report_id}` : "Loading…"}
      onClose={onClose}
    >
      {error ? (
        <EmptyState icon={<ShieldAlert size={20} />} title="Could not load this report">
          {error}
        </EmptyState>
      ) : !report ? (
        <div style={{ display: "grid", gap: 12 }}>
          <Skeleton height={68} />
          <Skeleton height={68} />
          <Skeleton height={220} />
        </div>
      ) : (
        <>
          <div className="meta-grid">
            <div className="meta-cell">
              <div className="k">Report</div>
              <div
                className="v"
                style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, display: "flex", alignItems: "center", gap: 3 }}
              >
                <span style={{ overflowWrap: "anywhere" }}>{report.report_id}</span>
                <CopyButton value={report.report_id} label="Copy report ID" />
              </div>
            </div>
            <div className="meta-cell">
              <div className="k">Period</div>
              <div className="v">
                {longDate(report.date_begin)} – {longDate(report.date_end)}
              </div>
            </div>
            <div className="meta-cell">
              <div className="k">Ingested</div>
              <div className="v">{dateTime(report.ingested_at)}</div>
            </div>
            <div className="meta-cell">
              <div className="k">Source</div>
              <div className="v">
                <SourceChip source={report.source} />
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <Badge tone="neutral">p={report.policy.p}</Badge>
            <Badge tone="neutral">sp={report.policy.sp ?? "—"}</Badge>
            <Badge tone="neutral">pct={report.policy.pct ?? 100}</Badge>
            <Badge tone="neutral">adkim={report.policy.adkim ?? "r"}</Badge>
            <Badge tone="neutral">aspf={report.policy.aspf ?? "r"}</Badge>
            <CopyButton
              value={`p=${report.policy.p}; sp=${report.policy.sp ?? "—"}; pct=${report.policy.pct ?? 100}; adkim=${report.policy.adkim ?? "r"}; aspf=${report.policy.aspf ?? "r"}`}
              label="Copy report policy"
            />
            <span style={{ marginLeft: "auto" }}>
              <a className="btn ghost" href={rawReportUrl(report.id)} download>
                <Download size={14} />
                Original XML
              </a>
            </span>
          </div>

          <div>
            <h3 className="section-title">
              {formatNumber(report.message_count)} messages · {formatNumber(report.aligned_count)} aligned ·{" "}
              {formatNumber(report.failed_count)} failing
            </h3>
            <p className="tiny muted" style={{ marginTop: 3 }}>
              {report.records.length} records from {report.source_count} sending sources
            </p>
          </div>

          <table className="data">
            <thead>
              <tr>
                <th>Source IP</th>
                <th className="hide-sm">Country</th>
                <th className="center">Msgs</th>
                <th>Disposition</th>
                <th className="center">SPF</th>
                <th className="center">DKIM</th>
                <th className="hide-sm">Header from</th>
              </tr>
            </thead>
            <tbody>
              {report.records.map((record) => (
                <tr key={`${record.ip}-${record.header_from}`}>
                  <td>
                    <span className="source-ip">{record.ip}</span>
                    {record.reason ? (
                      <div className="tiny muted" style={{ marginTop: 2 }}>
                        {record.reason.type}
                        {record.reason.comment ? ` · ${record.reason.comment}` : ""}
                      </div>
                    ) : null}
                  </td>
                  <td className="hide-sm">
                    <span className="country">
                      <span className="flag">{record.country.flag || "🌐"}</span>
                      <span className="tiny">{record.country.name || "Unknown"}</span>
                    </span>
                  </td>
                  <td className="center num">{formatNumber(record.messages)}</td>
                  <td>
                    <span className="tiny">{record.disposition ?? "none"}</span>
                  </td>
                  <td className="center">
                    <CheckCell state={record.spf === "pass" ? "pass" : "fail"} label="SPF" />
                  </td>
                  <td className="center">
                    <CheckCell state={record.dkim === "pass" ? "pass" : "fail"} label="DKIM" />
                  </td>
                  <td className="hide-sm">
                    <span className="tiny" style={{ fontFamily: "var(--font-mono)" }}>
                      {record.header_from ?? "—"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="tiny muted" style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
            sha256 {report.raw_sha256}
          </div>
        </>
      )}
    </Drawer>
  );
}

function Row({ report, onOpen }: { report: ReportRow; onOpen: () => void }) {
  return (
    <tr className="report-row" onClick={onOpen} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onOpen()}>
      <td>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <span className="provider-dot" style={{ background: report.org_color, width: 8, height: 8 }} />
          <div>
            <div className="primary-cell">{report.org_name}</div>
            <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
              <span
                className="tiny muted"
                style={{ fontFamily: "var(--font-mono)" }}
                title={report.report_id}
              >
                {report.report_id.length > 34 ? `${report.report_id.slice(0, 34)}…` : report.report_id}
              </span>
              <CopyButton value={report.report_id} label="Copy report ID" />
            </div>
          </div>
        </div>
      </td>
      <td className="hide-sm">{report.domain}</td>
      <td className="hide-sm">
        {shortDate(report.date_begin)} – {shortDate(report.date_end)}
      </td>
      <td className="center num">{formatNumber(report.messages)}</td>
      <td>
        <span className="pct-pill">
          <span className="pct-bar">
            <span
              className={report.aligned_pct < 90 ? "low" : ""}
              style={{ width: `${Math.max(3, report.aligned_pct)}%` }}
            />
          </span>
          {report.aligned_pct.toFixed(1)}%
        </span>
      </td>
      <td className="center num hide-sm">{formatNumber(report.records)}</td>
      <td className="hide-sm">
        <SourceChip source={report.source} />
      </td>
      <td style={{ width: 28 }}>
        <ChevronRight size={15} className="chev" />
      </td>
    </tr>
  );
}

export function ReportsPage() {
  const { domain, days } = useData();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [data, setData] = useState<ReportsPageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    document.title = "DMARCView — Reports";
  }, []);

  useEffect(() => {
    setPage(1);
  }, [domain, days]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebounced(query);
      setPage(1);
    }, 280);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .reports({
        domain: domain === "all" ? undefined : domain,
        page,
        page_size: 20,
        q: debounced,
        days,
      })
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Could not load reports");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [domain, days, page, debounced]);

  const from = data ? (data.page - 1) * data.page_size + 1 : 0;
  const to = data ? Math.min(data.total, data.page * data.page_size) : 0;

  return (
    <div className="fade-in">
      <div className="section-head">
        <div>
          <h1>Reports</h1>
          <p>Original DMARC aggregate reports, exactly as reporters sent them.</p>
        </div>
        <span className="chip violet">{data ? `${formatNumber(data.total)} reports` : "—"}</span>
      </div>

      <section className="card">
        <div className="filters">
          <label className="search">
            <Search size={14} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search report ID or submitter…"
              aria-label="Search reports"
            />
          </label>
          <span className="tiny muted" style={{ marginLeft: "auto" }}>
            {domain === "all" ? "All domains" : domain} · last {days} days
          </span>
        </div>

        {error ? (
          <EmptyState icon={<ShieldAlert size={20} />} title="Could not load reports">
            {error}
          </EmptyState>
        ) : !data ? (
          <div style={{ padding: 20, display: "grid", gap: 10 }}>
            <Skeleton height={46} />
            <Skeleton height={46} />
            <Skeleton height={46} />
          </div>
        ) : data.items.length === 0 ? (
          <EmptyState icon={<FileText size={20} />} title="No reports match">
            Try a different period or domain, or clear the search.
          </EmptyState>
        ) : (
          <>
            <table className="data report-table">
              <thead>
                <tr>
                  <th>Report</th>
                  <th className="hide-sm">Domain</th>
                  <th className="hide-sm">Period</th>
                  <th className="center">Messages</th>
                  <th>Aligned</th>
                  <th className="center hide-sm">Records</th>
                  <th className="hide-sm">Source</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.items.map((report) => (
                  <Row key={report.id} report={report} onOpen={() => setSelected(report.id)} />
                ))}
              </tbody>
            </table>
            <div className="page-foot">
              <span>
                Showing {from}–{to} of {formatNumber(data.total)}
                {loading ? " · refreshing…" : ""}
              </span>
              <div className="pager">
                <button
                  className="btn ghost icon"
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                  disabled={data.page <= 1}
                  aria-label="Previous page"
                  type="button"
                >
                  <ChevronLeft size={15} />
                </button>
                <span className="tiny muted">
                  Page {data.page} of {data.pages}
                </span>
                <button
                  className="btn ghost icon"
                  onClick={() => setPage((value) => Math.min(data.pages, value + 1))}
                  disabled={data.page >= data.pages}
                  aria-label="Next page"
                  type="button"
                >
                  <ChevronRight size={15} />
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      {selected !== null ? <ReportDrawer id={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}
