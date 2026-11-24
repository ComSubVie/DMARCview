import { Activity } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { formatNumber, shortDate } from "../lib/format";
import type { DailyPoint, VolumeAnomaly } from "../types";
import { Badge, EmptyState } from "./ui";

interface PayloadItem {
  dataKey?: string | number;
  value?: number;
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: PayloadItem[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const aligned = Number(payload.find((item) => item.dataKey === "aligned")?.value ?? 0);
  const failed = Number(payload.find((item) => item.dataKey === "failed")?.value ?? 0);
  return (
    <div className="chart-tooltip">
      <div className="tt-date">{label}</div>
      <div className="tt-row">
        <span className="swatch" style={{ background: "#14b8a6" }} />
        Aligned <b>{formatNumber(aligned)}</b>
      </div>
      <div className="tt-row">
        <span className="swatch" style={{ background: "#f43f5e" }} />
        Failing <b>{formatNumber(failed)}</b>
      </div>
      <div className="tt-row" style={{ borderTop: "1px solid rgba(255,255,255,.12)", marginTop: 4, paddingTop: 4 }}>
        Total <b>{formatNumber(aligned + failed)}</b>
      </div>
    </div>
  );
}

export function VolumeChart({
  daily,
  days,
  anomaly,
}: {
  daily: DailyPoint[];
  days: number;
  anomaly: VolumeAnomaly;
}) {
  const data = daily.map((point) => ({ ...point, label: shortDate(point.date) }));
  const total = daily.reduce((sum, point) => sum + point.total, 0);
  const peak = Math.max(4, ...daily.map((point) => Math.max(point.aligned, point.failed)));

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Compliant vs non-compliant volume</h2>
          <p className="card-sub">
            Daily messages · {days === 1 ? "single day" : `last ${days} days`}
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {anomaly.available && anomaly.z !== null && Math.abs(anomaly.z) >= 2 ? (
            <span title={`Latest day vs the trailing ${28}-day median`}>
              <Badge tone={anomaly.level === "high" ? "warn" : anomaly.level === "low" ? "info" : "neutral"}>
                {anomaly.z > 0 ? "+" : ""}
                {anomaly.z.toFixed(1)}σ
              </Badge>
            </span>
          ) : null}
          <div className="chart-legend">
            <span>
              <span className="swatch" style={{ background: "#0f766e" }} />
              Aligned
            </span>
            <span>
              <span className="swatch" style={{ background: "#e11d48" }} />
              Failing
            </span>
          </div>
        </div>
      </div>
      <div className="card-body" style={{ paddingTop: 8 }}>
        {total === 0 ? (
          <EmptyState icon={<Activity size={20} />} title="No messages in this period">
            Reports that arrive for this domain will be plotted here, one point per day.
          </EmptyState>
        ) : (
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height={292}>
              <AreaChart data={data} margin={{ top: 12, right: 10, left: -14, bottom: 0 }}>
                <defs>
                  <linearGradient id="fillAligned" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#14b8a6" stopOpacity={0.36} />
                    <stop offset="65%" stopColor="#14b8a6" stopOpacity={0.12} />
                    <stop offset="100%" stopColor="#14b8a6" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="fillFailed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.34} />
                    <stop offset="65%" stopColor="#f43f5e" stopOpacity={0.12} />
                    <stop offset="100%" stopColor="#f43f5e" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="2 6" vertical={false} stroke="#edf0f7" />
                <XAxis
                  dataKey="label"
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: "#98a2b3" }}
                  minTickGap={34}
                  interval="preserveStartEnd"
                  dy={6}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fontSize: 11, fill: "#98a2b3" }}
                  width={46}
                  allowDecimals={false}
                  domain={[0, Math.ceil(peak * 1.25)]}
                  tickCount={4}
                />
                <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#c7cbe0", strokeDasharray: "3 4" }} />
                <Area
                  type="monotone"
                  dataKey="aligned"
                  stroke="#0f766e"
                  strokeWidth={1.7}
                  fill="url(#fillAligned)"
                  dot={false}
                  activeDot={{ r: 3.5, strokeWidth: 2, stroke: "#fff" }}
                />
                <Area
                  type="monotone"
                  dataKey="failed"
                  stroke="#e11d48"
                  strokeWidth={1.7}
                  fill="url(#fillFailed)"
                  dot={false}
                  activeDot={{ r: 3.5, strokeWidth: 2, stroke: "#fff" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </section>
  );
}
