import type {
  Dashboard,
  IngestStatus,
  Meta,
  ProbeResult,
  ReportDetail,
  ReportsPage,
  TlsDashboard,
  TlsReportDetail,
} from "./types";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const BASE = "/api";

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    credentials: "same-origin",
    headers:
      init.body instanceof FormData
        ? { Accept: "application/json", ...(init.headers ?? {}) }
        : { "Content-Type": "application/json", Accept: "application/json", ...(init.headers ?? {}) },
    ...init,
  });

  if (response.status === 401 && !path.startsWith("/auth/login")) {
    window.dispatchEvent(new Event("dmarc:unauthorized"));
    throw new ApiError("Not signed in", 401);
  }

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? String((payload as { detail: unknown }).detail)
        : `Request failed (${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return payload as T;
}

function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export const api = {
  me: () => request<{ authenticated: boolean; username: string | null }>("/auth/me"),
  login: (username: string, password: string) =>
    request<{ authenticated: boolean; username: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>("/auth/logout", { method: "POST" }),

  meta: () => request<Meta>("/meta"),
  dashboard: (domain: string, days: number) =>
    request<Dashboard>(`/dashboard${query({ domain, days })}`),
  simulatePolicy: (
    domain: string,
    params: { days?: number; p?: string; sp?: string; np?: string; t?: string },
  ) =>
    request<import("./types").PolicySimulation>(
      `/domains/${encodeURIComponent(domain)}/simulation${query(params)}`,
    ),
  timeline: (domain: string, limit = 50) =>
    request<import("./types").Timeline>(
      `/domains/${encodeURIComponent(domain)}/timeline${query({ limit })}`,
    ),
  createAnnotation: (
    domain: string,
    payload: { kind: string; title: string; body?: string | null; occurred_at?: string | null },
  ) =>
    request<import("./types").TimelineItem>(
      `/domains/${encodeURIComponent(domain)}/annotations`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  updateAnnotation: (
    id: number,
    payload: { kind?: string; title?: string; body?: string | null; occurred_at?: string | null },
  ) =>
    request<import("./types").TimelineItem>(`/annotations/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deleteAnnotation: (id: number) =>
    request<{ ok: boolean }>(`/annotations/${id}`, { method: "DELETE" }),
  reports: (params: {
    domain?: string;
    page?: number;
    page_size?: number;
    q?: string;
    days?: number;
  }) => request<ReportsPage>(`/reports${query(params)}`),
  report: (id: number) => request<ReportDetail>(`/reports/${id}`),
  tls: (domain: string, days: number) => request<TlsDashboard>(`/tls${query({ domain, days })}`),
  tlsReport: (id: number) => request<TlsReportDetail>(`/tls/reports/${id}`),

  domainHealth: (domain: string) =>
    request<import("./types").DomainHealth>(`/domain-health${query({ domain })}`),
  runDomainHealth: (domain: string) =>
    request<import("./types").DomainHealth>(`/domain-health/run${query({ domain })}`, {
      method: "POST",
    }),
  fleetHealth: () =>
    request<{ items: import("./types").FleetHealthItem[] }>("/domain-health/fleet"),
  domainSettings: (domain: string) =>
    request<import("./types").DomainSettings>(
      `/domains/${encodeURIComponent(domain)}/settings`,
    ),
  saveDomainSettings: (
    domain: string,
    payload: {
      dkim_selectors?: string[];
      probe_targets?: string[];
      expected_report_hours?: number;
      dns_checks_enabled?: boolean;
      checks_muted_until?: string | null;
    },
  ) =>
    request<import("./types").DomainSettings>(
      `/domains/${encodeURIComponent(domain)}/settings`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  domainProfile: (domain: string) =>
    request<import("./types").DomainProfile>(`/domains/${encodeURIComponent(domain)}/profile`),
  expectations: (domain: string) =>
    request<{ items: import("./types").SourceExpectation[] }>(
      `/domains/${encodeURIComponent(domain)}/expectations`,
    ),
  createExpectation: (
    domain: string,
    payload: { match_type: string; value: string; label?: string | null },
  ) =>
    request<import("./types").SourceExpectation>(
      `/domains/${encodeURIComponent(domain)}/expectations`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  deleteExpectation: (id: number) =>
    request<{ ok: boolean }>(`/expectations/${id}`, { method: "DELETE" }),
  updateDomainProfile: (
    domain: string,
    payload: { display_name?: string | null; notes?: string | null; tags?: string[] },
  ) =>
    request<import("./types").DomainProfile>(`/domains/${encodeURIComponent(domain)}/profile`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  storage: () => request<import("./types").StorageInfo>("/storage"),
  jobs: () => request<import("./types").JobsResponse>("/jobs"),

  shareLinks: () =>
    request<{ items: import("./types").ShareLinkItem[] }>("/share-links"),
  createShareLink: (payload: { domain?: string | null; days?: number; include_sources?: boolean }) =>
    request<import("./types").CreatedShareLink>("/share-links", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  revokeShareLink: (id: number) =>
    request<import("./types").ShareLinkItem>(`/share-links/${id}/revoke`, { method: "POST" }),
  publicView: (token: string) =>
    request<import("./types").PublicShareView>(`/public/${encodeURIComponent(token)}`),

  alerts: () => request<import("./types").AlertsPayload>("/alerts"),
  updateAlertRule: (
    id: number,
    payload: {
      enabled?: boolean;
      condition?: Record<string, number>;
      cooldown_minutes?: number;
    },
  ) =>
    request<import("./types").AlertsPayload>(`/alerts/rules/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  alertOverrides: (domain: string) =>
    request<{ domain: string; rules: import("./types").AlertOverrideRule[] }>(
      `/alerts/overrides/${encodeURIComponent(domain)}`,
    ),
  setAlertOverride: (
    domain: string,
    kind: string,
    payload: { enabled?: boolean; condition?: Record<string, number>; cooldown_minutes?: number },
  ) =>
    request<{ domain: string; rules: import("./types").AlertOverrideRule[] }>(
      `/alerts/overrides/${encodeURIComponent(domain)}/${encodeURIComponent(kind)}`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  deleteAlertOverride: (domain: string, kind: string) =>
    request<{ domain: string; rules: import("./types").AlertOverrideRule[] }>(
      `/alerts/overrides/${encodeURIComponent(domain)}/${encodeURIComponent(kind)}`,
      { method: "DELETE" },
    ),
  runAlerts: () =>
    request<import("./types").AlertRunResult>("/alerts/run", { method: "POST" }),
  testAlertChannel: (channel?: string) =>
    request<import("./types").AlertTestResult>("/alerts/test", {
      method: "POST",
      body: JSON.stringify({ channel }),
    }),

  ingestStatus: () => request<IngestStatus>("/ingest/status"),
  syncNow: () => request<{ started: boolean }>("/ingest/run", { method: "POST" }),
  probe: () => request<ProbeResult>("/ingest/probe", { method: "POST" }),
  upload: async (files: FileList | File[]) => {
    const form = new FormData();
    for (const file of Array.from(files)) {
      form.append("files", file);
    }
    return request<{
      files: number;
      reports: number;
      tls_reports: number;
      duplicates: number;
      ignored: number;
      errors: string[];
      items: { file: string; status: string; reports: number; tls_reports: number }[];
    }>("/ingest/upload", { method: "POST", body: form });
  },
};

export function rawReportUrl(id: number): string {
  return `${BASE}/reports/${id}/raw`;
}

export function rawTlsReportUrl(id: number): string {
  return `${BASE}/tls/reports/${id}/raw`;
}
