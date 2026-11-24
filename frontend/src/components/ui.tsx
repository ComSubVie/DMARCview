import { Check, Copy, Minus, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { checkLabel } from "../lib/format";
import type { CheckState } from "../types";

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: "good" | "warn" | "bad" | "info" | "neutral";
  children: ReactNode;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function CheckCell({ state, label }: { state: CheckState; label?: string }) {
  const description = `${label ?? "Result"} ${checkLabel[state]}`;
  return (
    <span className={`check ${state}`} title={description} aria-label={description} role="img">
      {state === "pass" && <Check size={14} strokeWidth={2.8} />}
      {state === "fail" && <X size={14} strokeWidth={2.8} />}
      {state === "none" && <Minus size={14} strokeWidth={2.6} />}
      {state === "mixed" && <span style={{ fontSize: 13, lineHeight: 1 }}>~</span>}
    </span>
  );
}

export function EmptyState({
  icon,
  title,
  children,
  action,
}: {
  icon: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

export function ProviderDots({ providers }: { providers: string[] }) {
  return (
    <span className="providers-inline">
      {providers.length === 0 ? (
        <span className="muted">Unknown</span>
      ) : (
        providers.map((provider) => (
          <span key={provider} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span className="provider-dot" style={{ background: providerColor(provider) }} />
            <span>{provider}</span>
          </span>
        ))
      )}
    </span>
  );
}

const PROVIDER_COLORS: Record<string, string> = {
  Google: "#4285f4",
  Microsoft: "#0f6cbd",
  Yahoo: "#6001d2",
  Mailgun: "#f04438",
  "Amazon SES": "#ff9900",
  SendGrid: "#1a82e2",
  Fastmail: "#0067b9",
  Apple: "#4b5563",
  "Proton Mail": "#6d4aff",
  Zoho: "#e42527",
  Proofpoint: "#f47b20",
  Mimecast: "#00a0df",
};

function providerColor(name: string): string {
  return PROVIDER_COLORS[name] ?? "#94a3b8";
}

export function Skeleton({ width, height, radius }: { width?: number | string; height: number; radius?: number }) {
  return (
    <div
      className="skeleton"
      style={{ width: width ?? "100%", height, borderRadius: radius ?? 8 }}
      aria-hidden="true"
    />
  );
}

export function DashboardSkeleton() {
  return (
    <div className="fade-in">
      <div style={{ padding: "26px 2px 18px", display: "grid", gap: 10 }}>
        <Skeleton width={220} height={11} />
        <Skeleton width={420} height={30} radius={10} />
      </div>
      <div className="kpis">
        {[0, 1, 2, 3].map((index) => (
          <div className="card kpi" key={index}>
            <Skeleton width={34} height={34} radius={10} />
            <div style={{ marginTop: 16 }}>
              <Skeleton width={90} height={30} radius={8} />
            </div>
            <div style={{ marginTop: 10 }}>
              <Skeleton width={120} height={11} />
            </div>
            <div style={{ marginTop: 18 }}>
              <Skeleton height={7} radius={99} />
            </div>
          </div>
        ))}
      </div>
      <div className="card" style={{ marginTop: 16, padding: 18 }}>
        <Skeleton width={160} height={11} />
        <div style={{ marginTop: 14 }}>
          <Skeleton height={6} radius={99} />
        </div>
      </div>
      <div className="grid cols-8-4">
        <div className="card" style={{ padding: 20, height: 380 }}>
          <Skeleton width={220} height={14} />
          <div style={{ marginTop: 28 }}>
            <Skeleton height={250} radius={12} />
          </div>
        </div>
        <div className="card" style={{ padding: 20, height: 380 }}>
          <Skeleton width={140} height={14} />
          <div style={{ marginTop: 20, display: "grid", gap: 10 }}>
            <Skeleton height={11} />
            <Skeleton height={11} />
            <Skeleton width="80%" height={11} />
            <Skeleton height={11} />
            <Skeleton width="60%" height={11} />
          </div>
        </div>
      </div>
    </div>
  );
}


export function CopyButton({
  value,
  label = "Copy",
  className = "",
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        fallbackCopy(value);
      }
    } catch {
      fallbackCopy(value);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button
      type="button"
      className={`copy-btn ${copied ? "copied" : ""} ${className}`}
      onClick={(event) => {
        event.stopPropagation();
        void copy();
      }}
      onKeyDown={(event) => {
        if (event.key === "Enter") event.stopPropagation();
      }}
      title={copied ? "Copied" : label}
      aria-label={copied ? "Copied" : label}
    >
      {copied ? <Check size={13} strokeWidth={2.6} /> : <Copy size={13} />}
    </button>
  );
}

function fallbackCopy(value: string) {
  const area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "-1000px";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  try {
    document.execCommand("copy");
  } finally {
    document.body.removeChild(area);
  }
}
