import { ArrowRight, Lock } from "lucide-react";
import { Link } from "react-router-dom";
import { formatNumber } from "../lib/format";
import type { TlsSummary } from "../types";

export function TlsTeaser({ tls, readonly = false }: { tls: TlsSummary; readonly?: boolean }) {
  const safe = tls.failure === 0 && tls.sessions > 0;
  return (
    <section className="card teaser">
      <div className="teaser-top">
        <span className="summary-label">
          <span className="dot" style={{ background: safe ? "#12b76a" : "#f79009" }} />
          {safe ? "Encrypted delivery" : "TLS-RPT"}
        </span>
        <Lock size={14} color="#98a2b3" />
      </div>
      <h3>Encrypted delivery (TLS-RPT)</h3>
      {tls.sessions === 0 ? (
        <p className="tiny muted" style={{ marginTop: 8, lineHeight: 1.6 }}>
          No TLS reports yet. Receiving mail servers will report negotiated TLS sessions here.
        </p>
      ) : (
        <>
          <div className="teaser-rate">
            <b className="num">{tls.success_pct.toFixed(1)}%</b>
            <span>
              of {formatNumber(tls.sessions)} sessions encrypted
            </span>
          </div>
          <div className="track green">
            <span style={{ width: `${Math.max(3, tls.success_pct)}%` }} />
          </div>
          <p className="tiny muted" style={{ lineHeight: 1.55 }}>
            {tls.failure > 0
              ? `${formatNumber(tls.failure)} sessions failed across ${tls.mx_hosts} MX host${tls.mx_hosts === 1 ? "" : "s"}.`
              : `All reported deliveries to ${tls.mx_hosts} MX host${tls.mx_hosts === 1 ? "" : "s"} were encrypted.`}
          </p>
        </>
      )}
      {!readonly ? (
        <Link className="link" to="/tls" style={{ marginTop: 10 }}>
          Open TLS delivery
          <ArrowRight size={13} />
        </Link>
      ) : null}
    </section>
  );
}
