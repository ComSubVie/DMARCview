import { ChevronDown, ChevronRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { Source, SourceActivity } from "../types";
import { formatNumber } from "../lib/format";
import { Drawer } from "./Drawer";
import { CheckCell, EmptyState, Skeleton } from "./ui";

function SourceDetailDrawer({
  ip,
  domain,
  days,
  onClose,
}: {
  ip: string;
  domain: string;
  days: number;
  onClose: () => void;
}) {
  const [data, setData] = useState<SourceActivity | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .sourceActivity(ip, { domain: domain === "all" ? undefined : domain, days })
      .then((result) => !cancelled && setData(result))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : "Could not load source records"));
    return () => {
      cancelled = true;
    };
  }, [ip, domain, days]);

  return (
    <Drawer title={ip} subtitle="Source evidence by report" onClose={onClose}>
      {error ? (
        <EmptyState icon={<ShieldAlert size={20} />} title="Could not load source records">
          {error}
        </EmptyState>
      ) : !data ? (
        <div style={{ display: "grid", gap: 10 }}>
          <Skeleton height={80} />
          <Skeleton height={120} />
        </div>
      ) : data.records.length === 0 ? (
        <EmptyState icon={<ShieldAlert size={20} />} title="No recent records">
          This IP has no source records in the selected period.
        </EmptyState>
      ) : (
        <div className="source-records">
          {data.records.map((record) => (
            <div className="source-record" key={`${record.report_id}-${record.messages}`}>
              <div className="source-record-head">
                <strong>{record.org}</strong>
                <span className="tiny muted">
                  {record.date} · {formatNumber(record.messages)} messages · report {record.report_code}
                </span>
              </div>
              <div className="record-detail">
                <div className="record-detail-grid">
                  <div>
                    <span className="record-detail-label">Header from</span>
                    <code>{record.header_from ?? "not reported"}</code>
                  </div>
                  <div>
                    <span className="record-detail-label">Envelope from</span>
                    <code>{record.envelope_from ?? "not reported"}</code>
                  </div>
                  <div>
                    <span className="record-detail-label">Disposition</span>
                    <span>{record.disposition ?? "none"}</span>
                  </div>
                  <div>
                    <span className="record-detail-label">DMARC</span>
                    <span>{record.aligned ? "aligned" : "not aligned"}</span>
                  </div>
                </div>
                <div className="signature-section">
                  <div className="record-detail-label">DKIM signatures</div>
                  {record.dkim_entries.length === 0 ? (
                    <p className="tiny muted">No per-signature details reported.</p>
                  ) : (
                    <div className="signature-list">
                      {record.dkim_entries.map((entry, index) => (
                        <div className="signature-row" key={`${entry.domain}-${entry.selector}-${index}`}>
                          <span className={`health-dot ${entry.result === "pass" ? "ok" : "bad"}`} />
                          <code>{entry.domain}</code>
                          <span className="tiny muted">selector {entry.selector}</span>
                          <span className={`signature-result ${entry.result === "pass" ? "pass" : "fail"}`}>
                            {entry.result}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div className="signature-section">
                  <div className="record-detail-label">SPF results</div>
                  {record.spf_entries.length === 0 ? (
                    <p className="tiny muted">No per-domain SPF details reported.</p>
                  ) : (
                    <div className="signature-list">
                      {record.spf_entries.map((entry, index) => (
                        <div className="signature-row" key={`${entry.domain}-${index}`}>
                          <span className={`health-dot ${entry.result === "pass" ? "ok" : "bad"}`} />
                          <code>{entry.domain}</code>
                          <span className={`signature-result ${entry.result === "pass" ? "pass" : "fail"}`}>
                            {entry.result}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                {record.reason ? (
                  <div className="signature-section">
                    <div className="record-detail-label">Reporter reason</div>
                    <span className="tiny">
                      {record.reason.type ?? "unknown"}
                      {record.reason.comment ? ` — ${record.reason.comment}` : ""}
                    </span>
                  </div>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      )}
    </Drawer>
  );
}

function SourceRow({ source, onOpen }: { source: Source; onOpen?: () => void }) {
  const name = source.providers.length > 0 ? source.providers.join(" · ") : "Unnamed sender";
  return (
    <tr
      className={onOpen ? "source-row" : undefined}
      onClick={onOpen}
      onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && onOpen?.()}
      tabIndex={onOpen ? 0 : undefined}
      role={onOpen ? "button" : undefined}
    >
      <td>
        <div className="primary-cell">{name}</div>
        <div className="tiny muted" style={{ fontFamily: "var(--font-mono)", marginTop: 2 }}>
          {source.header_from || source.envelope_from || "no identifiers"}
        </div>
      </td>
      <td className="hide-sm">
        <span className="source-ip">{source.ip}</span>
        {source.ptr ? (
          <div className="source-ptr" title={source.ptr}>
            {source.ptr}
          </div>
        ) : null}
        {source.fcrdns_status ? (
          <div
            className={`source-fcrdns ${source.fcrdns_status}`}
            title={source.fcrdns_forward ? `Forward: ${source.fcrdns_forward}` : "No forward match"}
          >
            FCrDNS {source.fcrdns_status === "none" ? "no PTR" : source.fcrdns_status}
          </div>
        ) : null}
      </td>
      <td className="hide-sm">
        <span className="country">
          <span className="flag" aria-hidden="true">
            {source.country.flag || "🌐"}
          </span>
          <span className="tiny" style={{ color: "var(--ink-2)" }}>
            {source.country.name || "Unknown"}
          </span>
        </span>
      </td>
      <td className="center">
        <span className="num" style={{ color: "var(--ink)", fontWeight: 600 }}>
          {formatNumber(source.messages)}
        </span>
      </td>
      <td className="center">
        <CheckCell state={source.spf} label="SPF" />
      </td>
      <td className="center">
        <CheckCell state={source.dkim} label="DKIM" />
      </td>
      <td className="center">
        <CheckCell state={source.dmarc} label="DMARC" />
      </td>
      <td>{onOpen ? <ChevronRight size={14} className="source-chev" /> : null}</td>
    </tr>
  );
}

function GroupRow({
  verified,
  messages,
  sources,
  open,
  onToggle,
}: {
  verified: boolean;
  messages: number;
  sources: number;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <tr className="source-group">
      <td colSpan={8}>
        <button className="group-head" onClick={onToggle} aria-expanded={open} type="button">
          <span className={`g-icon ${verified ? "ok" : "bad"}`}>
            {verified ? <ShieldCheck size={13} strokeWidth={2.4} /> : <ShieldAlert size={13} strokeWidth={2.4} />}
          </span>
          <span className="g-title">
            {verified ? "Verified" : "Not verified"}{" "}
            <span className="g-stat">
              {formatNumber(messages)} {messages === 1 ? "message" : "messages"} ·{" "}
              {sources} {sources === 1 ? "source" : "sources"}
            </span>
          </span>
          <ChevronDown size={15} className="g-chev" />
        </button>
      </td>
    </tr>
  );
}

export function SourcesCard({
  sources,
  exportHref,
  domain,
  days,
  interactive,
}: {
  sources: Source[];
  exportHref?: string;
  domain?: string;
  days?: number;
  interactive?: boolean;
}) {
  const [openVerified, setOpenVerified] = useState(true);
  const [openUnverified, setOpenUnverified] = useState(true);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const canOpen = interactive !== false;

  const verified = sources.filter((source) => source.dmarc === "pass");
  const unverified = sources.filter((source) => source.dmarc !== "pass");
  const verifiedMessages = verified.reduce((sum, source) => sum + source.messages, 0);
  const unverifiedMessages = unverified.reduce((sum, source) => sum + source.messages, 0);
  const unsigned = verified.reduce((sum, source) => sum + source.unsigned_messages, 0);

  if (sources.length === 0) {
    return (
      <section className="card">
        <div className="card-head">
          <div>
            <h2 className="card-title">Sending sources</h2>
            <p className="card-sub">Who is sending as you, and whether each message could be verified</p>
          </div>
        </div>
        <EmptyState icon={<ShieldCheck size={20} />} title="No sending sources yet">
          Import a DMARC report to see which IPs send mail on behalf of this domain.
        </EmptyState>
      </section>
    );
  }

  return (
    <>
    <section className="card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Sending sources</h2>
          <p className="card-sub">Who is sending as you, and whether each message could be verified</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {exportHref ? (
            <a className="btn ghost" href={exportHref} download>
              CSV
            </a>
          ) : null}
          <span className="chip violet">
            {sources.length} sources · {new Set(sources.flatMap((source) => source.providers)).size || sources.length} providers
          </span>
        </div>
      </div>
      <div className="card-body" style={{ paddingTop: 8, paddingBottom: 14 }}>
        <table className="data sources-table">
          <thead>
            <tr>
              <th>Source</th>
              <th className="hide-sm">IP</th>
              <th className="hide-sm">Country</th>
              <th className="center">Messages</th>
              <th className="center">SPF</th>
              <th className="center">DKIM</th>
              <th className="center">DMARC</th>
              <th />
            </tr>
          </thead>
          <tbody>
            <GroupRow
              verified
              messages={verifiedMessages}
              sources={verified.length}
              open={openVerified}
              onToggle={() => setOpenVerified((value) => !value)}
            />
            {openVerified && verified.length > 0 ? (
              <>
                <tr>
                  <td colSpan={8} style={{ paddingTop: 0, paddingBottom: 8, borderTop: 0 }}>
                    <div className="group-note">These proved they came from you.</div>
                    {unsigned > 0 ? (
                      <div className="chips">
                        <span className="chip">no DKIM signature counted <b>{formatNumber(unsigned)}</b></span>
                      </div>
                    ) : null}
                  </td>
                </tr>
                {verified.map((source) => (
                  <SourceRow
                    key={source.ip}
                    source={source}
                    onOpen={canOpen ? () => setSelectedIp(source.ip) : undefined}
                  />
                ))}
              </>
            ) : null}

            <GroupRow
              verified={false}
              messages={unverifiedMessages}
              sources={unverified.length}
              open={openUnverified}
              onToggle={() => setOpenUnverified((value) => !value)}
            />
            {openUnverified && unverified.length > 0 ? (
              <>
                <tr>
                  <td colSpan={8} style={{ paddingTop: 0, paddingBottom: 8, borderTop: 0 }}>
                    <div className="group-note">These could not prove they came from you.</div>
                    {unverifiedMessages > 0 ? (
                      <div className="chips">
                        <span className="chip red">
                          no aligned identity <b>{formatNumber(unverifiedMessages)}</b>
                        </span>
                      </div>
                    ) : null}
                  </td>
                </tr>
                {unverified.map((source) => (
                  <SourceRow
                    key={source.ip}
                    source={source}
                    onOpen={canOpen ? () => setSelectedIp(source.ip) : undefined}
                  />
                ))}
              </>
            ) : null}
          </tbody>
        </table>
        <p className="legend">
          <b>Each cell shows two things.</b> First, whether the check succeeded — ✓ it did, ✗ it
          didn’t. Second, whose domain the check was for: DMARC only counts a message as verified
          when the aligned check passes for your domain. Amber cells mean mixed results across the
          source’s messages. Hover any cell for its exact state.
        </p>
      </div>
    </section>
    {canOpen && selectedIp ? (
      <SourceDetailDrawer
        ip={selectedIp}
        domain={domain ?? "all"}
        days={days ?? 30}
        onClose={() => setSelectedIp(null)}
      />
    ) : null}
    </>
  );
}
