import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useSearchParams } from "react-router-dom";
import { api, ApiError } from "./api";
import type { Dashboard, Meta } from "./types";

interface ToastMessage {
  id: number;
  text: string;
  tone: "ok" | "error";
}

interface DataContextValue {
  meta: Meta | null;
  domain: string;
  setDomain: (value: string) => void;
  days: number;
  setDays: (value: number) => void;
  dashboard: Dashboard | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  toast: (text: string, tone?: "ok" | "error") => void;
  toastMessage: ToastMessage | null;
  domainLabel: string;
}

const DataContext = createContext<DataContextValue | null>(null);

const DOMAIN_KEY = "dmarcview.domain";
const DAYS_KEY = "dmarcview.days";
const VALID_DAYS = [7, 14, 30, 90];

function storedDays(): number {
  const stored = Number(localStorage.getItem(DAYS_KEY));
  return VALID_DAYS.includes(stored) ? stored : 30;
}

export function DataProvider({ children }: { children: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [domain, setDomainState] = useState<string>(() => {
    return searchParams.get("domain") || localStorage.getItem(DOMAIN_KEY) || "all";
  });
  const [days, setDaysState] = useState<number>(() => {
    const fromUrl = Number(searchParams.get("days"));
    return VALID_DAYS.includes(fromUrl) ? fromUrl : storedDays();
  });
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<ToastMessage | null>(null);
  const ticket = useRef(0);

  const loadMeta = useCallback(async () => {
    try {
      const data = await api.meta();
      setMeta(data);
      setDomainState((current) => {
        if (current === "all") return current;
        return data.domains.some((item) => item.name === current) ? current : "all";
      });
    } catch {
      /* the dashboard request surfaces connectivity problems */
    }
  }, []);

  const load = useCallback(async () => {
    const current = ++ticket.current;
    setLoading(true);
    try {
      const data = await api.dashboard(domain, days);
      if (current !== ticket.current) return;
      setDashboard(data);
      setError(null);
    } catch (err) {
      if (current !== ticket.current) return;
      if (err instanceof ApiError && err.status === 401) return;
      setError(err instanceof Error ? err.message : "Could not load the dashboard");
    } finally {
      if (current === ticket.current) setLoading(false);
    }
  }, [domain, days]);

  useEffect(() => {
    const urlDomain = searchParams.get("domain");
    const urlDays = Number(searchParams.get("days"));
    if (urlDomain && meta && !meta.domains.some((item) => item.name === urlDomain)) {
      const next = new URLSearchParams(searchParams);
      next.delete("domain");
      setSearchParams(next, { replace: true });
      setDomainState("all");
      return;
    }
    if (
      urlDomain &&
      urlDomain !== domain &&
      (!meta || meta.domains.some((item) => item.name === urlDomain))
    ) {
      setDomainState(urlDomain);
      localStorage.setItem(DOMAIN_KEY, urlDomain);
    }
    if (VALID_DAYS.includes(urlDays) && urlDays !== days) {
      setDaysState(urlDays);
      localStorage.setItem(DAYS_KEY, String(urlDays));
    }
  }, [searchParams, meta, domain, days, setSearchParams]);

  useEffect(() => {
    void loadMeta();
  }, [loadMeta]);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = useCallback(async () => {
    await load();
    await loadMeta();
  }, [load, loadMeta]);

  const toast = useCallback((text: string, tone: "ok" | "error" = "ok") => {
    const id = Date.now();
    setToastMessage({ id, text, tone });
    window.setTimeout(() => {
      setToastMessage((current) => (current && current.id === id ? null : current));
    }, 3800);
  }, []);

  const setDomain = useCallback(
    (value: string) => {
      setDomainState(value);
      localStorage.setItem(DOMAIN_KEY, value);
      const next = new URLSearchParams(searchParams);
      if (value === "all") next.delete("domain");
      else next.set("domain", value);
      if (days === 30) next.delete("days");
      else next.set("days", String(days));
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams, days],
  );

  const setDays = useCallback(
    (value: number) => {
      setDaysState(value);
      localStorage.setItem(DAYS_KEY, String(value));
      const next = new URLSearchParams(searchParams);
      if (value === 30) next.delete("days");
      else next.set("days", String(value));
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const domainLabel = useMemo(() => {
    if (domain === "all") return "All domains";
    const entry = meta?.domains.find((item) => item.name === domain);
    return entry?.display_name || domain;
  }, [domain, meta]);

  const value = useMemo<DataContextValue>(
    () => ({
      meta,
      domain,
      setDomain,
      days,
      setDays,
      dashboard,
      loading,
      error,
      refresh,
      toast,
      toastMessage,
      domainLabel,
    }),
    [
      meta,
      domain,
      setDomain,
      days,
      setDays,
      dashboard,
      loading,
      error,
      refresh,
      toast,
      toastMessage,
      domainLabel,
    ],
  );

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export function useData(): DataContextValue {
  const context = useContext(DataContext);
  if (!context) throw new Error("useData must be used inside DataProvider");
  return context;
}
