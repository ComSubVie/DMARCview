import { useState } from "react";
import { Layers } from "lucide-react";
import type { Identities, Identity } from "../types";
import { formatNumber, shortDate } from "../lib/format";
import { Drawer } from "./Drawer";
import { Badge } from "./ui";

function pctTone(pct: number): "good" | "warn" | "bad" {
  return pct >= 95 ? "good" : pct >= 80 ? "warn" : "bad";
}

function IdentityTable({ items }: { items: Identity[] }) {
  return (
    <table className="data identities-table">
      <thead>
        <tr>
          <th>Identity</th>
          <th className="center">Messages</th>
          <th className="center">Aligned</th>
          <th className="center hide-sm">Sources</th>
          <th className="hide-sm">Network</th>
          <th className="hide-sm">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => (
          <tr key={item.key}>
            <td>
              <div className="primary-cell identity-name">{item.label}</div>
              {item.detail ? <div className="tiny muted">{item.detail}</div> : null}
            </td>
            <td className="center num">{formatNumber(item.messages)}</td>
            <td className="center">
              <Badge tone={pctTone(item.aligned_pct)}>{item.aligned_pct.toFixed(1)}%</Badge>
            </td>
            <td className="center num hide-sm">{formatNumber(item.sources)}</td>
            <td className="hide-sm">
              <span className="identity-network" title={item.network}>
                {item.network || "—"}
              </span>
            </td>
            <td className="tiny hide-sm">{item.last_seen ? shortDate(item.last_seen) : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function IdentitiesCard({ identities }: { identities: Identities }) {
  const [open, setOpen] = useState(false);
  const preview = identities.items.slice(0, 6);

  return (
    <section className="card identities-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Sending identities</h2>
          <p className="card-sub">Rotating IPs grouped by envelope domain and DKIM identity</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Badge tone="info">{identities.total} {identities.total === 1 ? "identity" : "identities"}</Badge>
          {identities.items.length > preview.length ? (
            <button className="btn ghost" onClick={() => setOpen(true)} type="button">
              <Layers size={13} />
              View all
            </button>
          ) : null}
        </div>
      </div>
      <div style={{ padding: "2px 8px 12px" }}>
        {preview.length === 0 ? (
          <p className="tiny muted" style={{ padding: "14px 10px" }}>
            No sending identities in this period.
          </p>
        ) : (
          <IdentityTable items={preview} />
        )}
        <p className="tiny muted" style={{ padding: "4px 10px 0" }}>
          A domain that rotates through 40 ESP addresses is one row; a different DKIM domain stays
          a separate identity. ASN/PTR is shown as network context.
        </p>
      </div>

      {open ? (
        <Drawer
          title="Sending identities"
          subtitle={`${identities.total} identities · envelope + DKIM`}
          onClose={() => setOpen(false)}
        >
          <IdentityTable items={identities.items} />
        </Drawer>
      ) : null}
    </section>
  );
}
