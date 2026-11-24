import type { CheckState } from "../types";

export const numberFormat = new Intl.NumberFormat("en-US");

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return numberFormat.format(value);
}

export function formatPct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${value.toFixed(digits)}%`;
}

function toDate(value: string): Date {
  // Date-only strings are report days in UTC; keep them stable across time zones.
  return new Date(value.length <= 10 ? `${value}T00:00:00Z` : value);
}

export function shortDate(value: string): string {
  return toDate(value).toLocaleDateString("en-GB", { day: "2-digit", month: "short", timeZone: "UTC" });
}

export function longDate(value: string): string {
  return toDate(value).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
}

export function dateTime(value: string | null): string {
  if (!value) return "—";
  return toDate(value).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
  }) + " UTC";
}

export function rangeLabel(start: string, end: string): string {
  const a = toDate(start);
  const b = toDate(end);
  const sameMonth = a.getUTCMonth() === b.getUTCMonth() && a.getUTCFullYear() === b.getUTCFullYear();
  const sameDay = a.toISOString().slice(0, 10) === b.toISOString().slice(0, 10);
  if (sameDay) return longDate(start);
  if (sameMonth) {
    const day = (date: Date) => String(date.getUTCDate()).padStart(2, "0");
    return `${day(a)} – ${day(b)} ${b.toLocaleDateString("en-GB", {
      month: "short",
      year: "numeric",
      timeZone: "UTC",
    })}`;
  }
  return `${longDate(start)} – ${longDate(end)}`;
}

export function relativeTime(value: string | null | undefined): string {
  if (!value) return "never";
  const date = toDate(value);
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
}

export const checkLabel: Record<CheckState, string> = {
  pass: "passed",
  fail: "failed",
  none: "not present",
  mixed: "mixed results",
};
