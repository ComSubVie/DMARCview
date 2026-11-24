import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { useMemo, useState } from "react";
import { formatNumber, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { FleetItem } from "../types";
import { Badge } from "./ui";

type SortKey =
  | "domain"
  | "messages"
  | "aligned_pct"
  | "failing_sources"
  | "last_report"
  | "tls_pct"
  | "policy_p"
  | "health";

function healthTone(status: string | null): "good" | "warn" | "bad" | "neutral" {
  if (status === "pass") return "good";
  if (status === "warn") return "warn";
  if (status === "fail") return "bad";
  return "neutral";
}

function Sparkline({ item }: { item: FleetItem }) {
  const values = item.sparkline.map((point) => point.total);
  const max = Math.max(1, ...values);
  const width = 84;
  const height = 24;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((value, index) => `${(index * step).toFixed(1)},${(height - (value / max) * (height - 2) - 1).toFixed(1)}`)
    .join(" ");
  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`14-day volume for ${item.domain}`}
    >
      <polyline points={points} fill="none" stroke="#0f766e" strokeWidth="1.8" />
    </svg>
  );
}

function valueFor(item: FleetItem, key: SortKey): string | number {
  if (key === "domain") return (item.display_name || item.domain).toLowerCase();
  if (key === "last_report") return item.last_report ?? "";
  if (key === "tls_pct") return item.tls_pct ?? -1;
  if (key === "policy_p") return item.policy_p ?? "";
  if (key === "health") return item.health ?? "";
  return item[key];
}

export function FleetTable({ items }: { items: FleetItem[] }) {
  const { setDomain } = useData();
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({
    key: "messages",
    dir: "desc",
  });

  const sorted = useMemo(() => {
    const copy = [...items];
    copy.sort((left, right) => {
      const a = valueFor(left, sort.key);
      const b = valueFor(right, sort.key);
      const result =
        typeof a === "number" && typeof b === "number"
          ? a - b
          : String(a).localeCompare(String(b));
      return sort.dir === "asc" ? result : -result;
    });
    return copy;
  }, [items, sort]);

  function toggle(key: SortKey) {
    setSort((current) =>
      current.key === key
        ? { key, dir: current.dir === "asc" ? "desc" : "asc" }
        : { key, dir: key === "domain" ? "asc" : "desc" },
    );
  }

  function Header({ label, name, className = "" }: { label: string; name: SortKey; className?: string }) {
    const active = sort.key === name;
    return (
      <th className={className}>
        <button className={`th-sort ${active ? "active" : ""}`} onClick={() => toggle(name)} type="button">
          {label}
          {active ? (
            sort.dir === "asc" ? (
              <ArrowUp size={11} />
            ) : (
              <ArrowDown size={11} />
            )
          ) : (
            <ChevronsUpDown size={11} />
          )}
        </button>
      </th>
    );
  }

  return (
    <section className="card fleet-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Fleet comparison</h2>
          <p className="card-sub">Click a domain to drill down · click a heading to sort</p>
        </div>
        <Badge tone="info">{items.length} domains</Badge>
      </div>
      <div style={{ padding: "2px 8px 12px", overflowX: "auto" }}>
        <table className="data fleet-table">
          <thead>
            <tr>
              <Header label="Domain" name="domain" />
              <Header label="Messages" name="messages" className="center" />
              <Header label="Aligned" name="aligned_pct" className="center" />
              <Header label="Failing sources" name="failing_sources" className="center hide-sm" />
              <Header label="Last report" name="last_report" className="hide-sm" />
              <Header label="TLS" name="tls_pct" className="center hide-sm" />
              <Header label="Policy" name="policy_p" className="center hide-sm" />
              <Header label="Health" name="health" className="center hide-sm" />
              <th className="center">Trend</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((item) => (
              <tr
                key={item.domain}
                onClick={() => setDomain(item.domain)}
                onKeyDown={(event) => event.key === "Enter" && setDomain(item.domain)}
                tabIndex={0}
                role="link"
              >
                <td>
                  <div className="primary-cell">{item.display_name || item.domain}</div>
                  {item.display_name && item.display_name !== item.domain ? (
                    <div className="tiny muted">{item.domain}</div>
                  ) : null}
                </td>
                <td className="center num">{formatNumber(item.messages)}</td>
                <td className="center">
                  <Badge tone={item.aligned_pct >= 95 ? "good" : item.aligned_pct >= 80 ? "warn" : "bad"}>
                    {item.aligned_pct.toFixed(1)}%
                  </Badge>
                </td>
                <td className="center num hide-sm">
                  {item.failing_sources > 0 ? (
                    <span style={{ color: "var(--red)", fontWeight: 600 }}>{item.failing_sources}</span>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="tiny muted hide-sm">
                  {item.last_report ? relativeTime(item.last_report) : "—"}
                </td>
                <td className="center num hide-sm">
                  {item.tls_pct === null ? "—" : `${item.tls_pct.toFixed(1)}%`}
                </td>
                <td className="center hide-sm tiny">{item.policy_p ? `p=${item.policy_p}` : "—"}</td>
                <td className="center hide-sm">
                  <Badge tone={healthTone(item.health)}>{item.health ?? "unknown"}</Badge>
                </td>
                <td className="center">
                  <Sparkline item={item} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
