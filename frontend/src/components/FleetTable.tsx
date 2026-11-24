import { ArrowDown, ArrowUp, ChevronsUpDown, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { formatNumber, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { FleetItem, FleetViewFilters, SavedFleetView } from "../types";
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

const SORT_KEYS: SortKey[] = [
  "domain",
  "messages",
  "aligned_pct",
  "failing_sources",
  "last_report",
  "tls_pct",
  "policy_p",
  "health",
];

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
  const { setDomain, toast } = useData();
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({
    key: "messages",
    dir: "desc",
  });
  const [tag, setTag] = useState("");
  const [policy, setPolicy] = useState("");
  const [health, setHealth] = useState("");
  const [onlyFailing, setOnlyFailing] = useState(false);
  const [maxAlignment, setMaxAlignment] = useState("");
  const [maxTls, setMaxTls] = useState("");
  const [views, setViews] = useState<SavedFleetView[]>([]);
  const [activeView, setActiveView] = useState("");
  const [savingView, setSavingView] = useState(false);
  const [viewName, setViewName] = useState("");
  const tags = useMemo(
    () => Array.from(new Set(items.flatMap((item) => item.tags ?? []))).sort(),
    [items],
  );

  useEffect(() => {
    api
      .fleetViews()
      .then((result) => setViews(result.items))
      .catch(() => {
        /* saved views are optional; the table still works */
      });
  }, []);

  const filtered = useMemo(() => {
    let result = items;
    if (tag) result = result.filter((item) => (item.tags ?? []).includes(tag));
    if (policy) result = result.filter((item) => (item.policy_p ?? "none") === policy);
    if (health) result = result.filter((item) => (item.health ?? "unknown") === health);
    if (onlyFailing) result = result.filter((item) => item.failing_sources > 0);
    if (maxAlignment !== "") {
      const limit = Number(maxAlignment);
      if (Number.isFinite(limit)) result = result.filter((item) => item.aligned_pct < limit);
    }
    if (maxTls !== "") {
      const limit = Number(maxTls);
      if (Number.isFinite(limit)) {
        result = result.filter((item) => item.tls_pct === null || item.tls_pct < limit);
      }
    }
    return result;
  }, [items, tag, policy, health, onlyFailing, maxAlignment, maxTls]);

  function currentFilters(): FleetViewFilters {
    return {
      tag,
      policy,
      health,
      only_failing: onlyFailing,
      max_alignment: maxAlignment,
      max_tls: maxTls,
      sort_key: sort.key,
      sort_dir: sort.dir,
    };
  }

  function applyView(view: SavedFleetView) {
    const filters = view.filters ?? {};
    setActiveView(String(view.id));
    setTag(filters.tag ?? "");
    setPolicy(filters.policy ?? "");
    setHealth(filters.health ?? "");
    setOnlyFailing(Boolean(filters.only_failing));
    setMaxAlignment(filters.max_alignment ?? "");
    setMaxTls(filters.max_tls ?? "");
    const key = (filters.sort_key ?? "") as SortKey;
    setSort({
      key: SORT_KEYS.includes(key) ? key : "messages",
      dir: filters.sort_dir === "asc" ? "asc" : "desc",
    });
  }

  async function saveView() {
    if (!viewName.trim()) return;
    try {
      const saved = await api.createFleetView({ name: viewName.trim(), filters: currentFilters() });
      setViews((current) => [...current, saved].sort((a, b) => a.name.localeCompare(b.name)));
      setActiveView(String(saved.id));
      setSavingView(false);
      setViewName("");
      toast("Fleet view saved");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save the fleet view", "error");
    }
  }

  async function deleteView() {
    if (!activeView) return;
    try {
      await api.deleteFleetView(Number(activeView));
      setViews((current) => current.filter((view) => String(view.id) !== activeView));
      setActiveView("");
      toast("Fleet view deleted");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not delete the fleet view", "error");
    }
  }

  const sorted = useMemo(() => {
    const copy = [...filtered];
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
  }, [filtered, sort]);

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
        <Badge tone="info">{filtered.length} domains</Badge>
      </div>
      <div className="fleet-controls">
        <select value={tag} onChange={(event) => setTag(event.target.value)} aria-label="Filter by group">
          <option value="">All groups</option>
          {tags.map((item) => (
            <option value={item} key={item}>
              {item}
            </option>
          ))}
        </select>
        <select value={policy} onChange={(event) => setPolicy(event.target.value)} aria-label="Filter by policy">
          <option value="">Any policy</option>
          <option value="none">p=none</option>
          <option value="quarantine">p=quarantine</option>
          <option value="reject">p=reject</option>
        </select>
        <select value={health} onChange={(event) => setHealth(event.target.value)} aria-label="Filter by health">
          <option value="">Any health</option>
          <option value="pass">pass</option>
          <option value="warn">warn</option>
          <option value="fail">fail</option>
          <option value="unknown">unknown</option>
        </select>
        <label className="fleet-check">
          <input
            type="checkbox"
            checked={onlyFailing}
            onChange={(event) => setOnlyFailing(event.target.checked)}
          />
          Failing sources
        </label>
        <label className="fleet-number">
          Aligned &lt;
          <input
            type="number"
            min={0}
            max={100}
            value={maxAlignment}
            onChange={(event) => setMaxAlignment(event.target.value)}
            placeholder="100"
          />
        </label>
        <label className="fleet-number">
          TLS &lt;
          <input
            type="number"
            min={0}
            max={100}
            value={maxTls}
            onChange={(event) => setMaxTls(event.target.value)}
            placeholder="100"
          />
        </label>
        <div className="fleet-view-actions">
          <select
            value={activeView}
            onChange={(event) => {
              const view = views.find((item) => String(item.id) === event.target.value);
              if (view) applyView(view);
              else setActiveView("");
            }}
            aria-label="Saved fleet views"
          >
            <option value="">Saved views</option>
            {views.map((view) => (
              <option value={view.id} key={view.id}>
                {view.name}
              </option>
            ))}
          </select>
          <button className="btn ghost sm" type="button" onClick={() => setSavingView((value) => !value)}>
            Save view
          </button>
          {activeView ? (
            <button className="btn ghost icon" type="button" onClick={() => void deleteView()} aria-label="Delete saved view">
              <Trash2 size={13} />
            </button>
          ) : null}
        </div>
      </div>
      {savingView ? (
        <div className="fleet-save">
          <input
            value={viewName}
            placeholder="View name"
            maxLength={120}
            onChange={(event) => setViewName(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void saveView();
              if (event.key === "Escape") setSavingView(false);
            }}
          />
          <button className="btn primary sm" type="button" disabled={!viewName.trim()} onClick={() => void saveView()}>
            Save
          </button>
          <button className="btn ghost sm" type="button" onClick={() => setSavingView(false)}>
            Cancel
          </button>
        </div>
      ) : null}
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
                  {(item.tags ?? []).length > 0 ? (
                    <div className="tiny muted">{item.tags.join(" · ")}</div>
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
