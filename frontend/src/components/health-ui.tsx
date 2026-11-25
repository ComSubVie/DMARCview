import {
  AtSign,
  BadgeCheck,
  Fingerprint,
  KeyRound,
  Lock,
  LockKeyhole,
  Mail,
  Server,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import type { HealthStatus } from "../types";

export const statusMeta: Record<
  HealthStatus,
  { label: string; tone: "good" | "warn" | "bad" | "info" | "neutral"; color: string }
> = {
  pass: { label: "Pass", tone: "good", color: "#0b7a63" },
  warn: { label: "Warn", tone: "warn", color: "#b54708" },
  fail: { label: "Fail", tone: "bad", color: "#d92d20" },
  info: { label: "Info", tone: "info", color: "#3538cd" },
  unknown: { label: "Unknown", tone: "neutral", color: "#98a2b3" },
  "n/a": { label: "n/a", tone: "neutral", color: "#98a2b3" },
};

export const overallMeta: Record<
  HealthStatus,
  { label: string; tone: "good" | "warn" | "bad" | "info" | "neutral" }
> = {
  pass: { label: "Healthy", tone: "good" },
  warn: { label: "Attention", tone: "warn" },
  fail: { label: "Action needed", tone: "bad" },
  info: { label: "Info", tone: "info" },
  unknown: { label: "Not checked", tone: "neutral" },
  "n/a": { label: "n/a", tone: "neutral" },
};

const ICONS: Record<string, LucideIcon> = {
  dmarc: ShieldCheck,
  spf: AtSign,
  dkim: KeyRound,
  mx: Server,
  mta_sts: Lock,
  tls_rpt: LockKeyhole,
  dnssec: Fingerprint,
  bimi: BadgeCheck,
  caa: Lock,
  dane: LockKeyhole,
  helo: Mail,
};

export function CheckIcon({ checkKey, size = 15 }: { checkKey: string; size?: number }) {
  const Icon = ICONS[checkKey] ?? ShieldCheck;
  return <Icon size={size} strokeWidth={2} />;
}

export function statusClass(status: HealthStatus): string {
  return status === "pass"
    ? "ok"
    : status === "warn"
      ? "warn"
      : status === "fail"
        ? "bad"
        : "neutral";
}

export function expiryTone(days: number | null | undefined): HealthStatus {
  if (days === null || days === undefined) return "unknown";
  if (days < 7) return "fail";
  if (days <= 21) return "warn";
  return "pass";
}

export function formatBytes(value: number): string {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}
