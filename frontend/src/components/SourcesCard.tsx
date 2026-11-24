import { ChevronDown, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { Source } from "../types";
import { formatNumber } from "../lib/format";
import { CheckCell, EmptyState } from "./ui";

function SourceRow({ source }: { source: Source }) {
  const name = source.providers.length > 0 ? source.providers.join(" · ") : "Unnamed sender";
  return (
    <tr>
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
      <td colSpan={7}>
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

export function SourcesCard({ sources }: { sources: Source[] }) {
  const [openVerified, setOpenVerified] = useState(true);
  const [openUnverified, setOpenUnverified] = useState(true);

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
    <section className="card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Sending sources</h2>
          <p className="card-sub">Who is sending as you, and whether each message could be verified</p>
        </div>
        <span className="chip violet">
          {sources.length} sources · {new Set(sources.flatMap((source) => source.providers)).size || sources.length} providers
        </span>
      </div>
      <div className="card-body" style={{ paddingTop: 8, paddingBottom: 14 }}>
        <table className="data">
          <thead>
            <tr>
              <th>Source</th>
              <th className="hide-sm">IP</th>
              <th className="hide-sm">Country</th>
              <th className="center">Messages</th>
              <th className="center">SPF</th>
              <th className="center">DKIM</th>
              <th className="center">DMARC</th>
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
                  <td colSpan={7} style={{ paddingTop: 0, paddingBottom: 8, borderTop: 0 }}>
                    <div className="group-note">These proved they came from you.</div>
                    {unsigned > 0 ? (
                      <div className="chips">
                        <span className="chip">no DKIM signature counted <b>{formatNumber(unsigned)}</b></span>
                      </div>
                    ) : null}
                  </td>
                </tr>
                {verified.map((source) => (
                  <SourceRow key={source.ip} source={source} />
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
                  <td colSpan={7} style={{ paddingTop: 0, paddingBottom: 8, borderTop: 0 }}>
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
                  <SourceRow key={source.ip} source={source} />
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
  );
}
