import type { ReactNode } from "react";

const TONES: Record<string, [string, string]> = {
  blue: ["#6366f1", "#a5b4fc"],
  green: ["#0f766e", "#a7f3d0"],
  red: ["#ef4444", "#fecaca"],
  amber: ["#f59e0b", "#fde68a"],
};

export function KpiCard({
  icon,
  tone,
  value,
  suffix,
  label,
  pct,
}: {
  icon: ReactNode;
  tone: "blue" | "green" | "red" | "amber";
  value: string;
  suffix?: string;
  label: string;
  pct: number;
}) {
  const [from, to] = TONES[tone];
  const first = Math.max(4, Math.min(96, pct));
  return (
    <article className="card kpi">
      <div className={`kpi-icon tone-${tone}`}>{icon}</div>
      <div className="kpi-value num">
        {value}
        {suffix ? <small>{suffix}</small> : null}
      </div>
      <div className="kpi-label">{label}</div>
      <div
        className="kpi-bar"
        style={{ ["--bar-a" as string]: from, ["--bar-b" as string]: to }}
      >
        <i style={{ width: `${first}%` }} />
        <i className="alt" style={{ flex: 1 }} />
      </div>
    </article>
  );
}
