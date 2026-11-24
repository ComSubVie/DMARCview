import { useEffect, useState } from "react";
import { ScrollText, Search } from "lucide-react";
import { api } from "../api";
import { Badge, EmptyState, Skeleton } from "../components/ui";
import { dateTime, relativeTime } from "../lib/format";
import type { AuditItem } from "../types";

export function AuditPage() {
  const [items, setItems] = useState<AuditItem[]>([]);
  const [action, setAction] = useState("");
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.title = "DMARCView — Audit";
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(() => {
      api
        .audit({ limit: 200, action: action.trim() || undefined, domain: domain.trim() || undefined })
        .then((result) => {
          if (!cancelled) {
            setItems(result.items);
            setError(null);
          }
        })
        .catch((err) => {
          if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the audit log");
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [action, domain]);

  return (
    <div className="fade-in">
      <div className="section-head">
        <div>
          <h1>Audit</h1>
          <p>Admin actions recorded by the application.</p>
        </div>
        <Badge tone="info">{items.length} events</Badge>
      </div>

      <div className="audit-filters card">
        <label className="fleet-number">
          <Search size={13} />
          <input
            placeholder="Action (exact)…"
            value={action}
            onChange={(event) => setAction(event.target.value)}
          />
        </label>
        <label className="fleet-number">
          Domain
          <input
            placeholder="tgm.rocks"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
          />
        </label>
      </div>

      {error ? <p className="form-error">{error}</p> : null}
      {loading && items.length === 0 ? <Skeleton height={220} /> : null}
      {!loading && !error && items.length === 0 ? (
        <EmptyState icon={<ScrollText size={20} />} title="No audit events yet">
          Sign in, change a setting, create a share link or edit an alert to see entries here.
        </EmptyState>
      ) : (
        <section className="card">
          <div className="card-body" style={{ paddingTop: 8 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th className="hide-sm">Domain</th>
                  <th className="hide-sm">Target</th>
                  <th className="hide-sm">Detail</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td className="tiny">
                      <span title={item.at ?? undefined}>{relativeTime(item.at)}</span>
                      <div className="tiny muted">{dateTime(item.at)}</div>
                    </td>
                    <td>
                      <Badge tone="neutral">{item.action}</Badge>
                    </td>
                    <td className="tiny">{item.actor}</td>
                    <td className="tiny hide-sm">{item.domain ?? "—"}</td>
                    <td className="tiny hide-sm">{item.target ?? "—"}</td>
                    <td className="tiny muted hide-sm">
                      {Object.keys(item.detail ?? {}).length > 0
                        ? JSON.stringify(item.detail).slice(0, 140)
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
