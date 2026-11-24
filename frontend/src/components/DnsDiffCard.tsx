import { useEffect, useState } from "react";
import { ArrowRight, History } from "lucide-react";
import { api } from "../api";
import { dateTime, relativeTime } from "../lib/format";
import type { DnsDiff } from "../types";
import { Badge } from "./ui";

export function DnsDiffCard({ domain }: { domain: string }) {
  const [data, setData] = useState<DnsDiff | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    api
      .dnsDiff(domain)
      .then((result) => !cancelled && setData(result))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : "Could not load DNS history"));
    return () => {
      cancelled = true;
    };
  }, [domain]);

  return (
    <section className="card dnsdiff-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">DNS change history</h2>
          <p className="card-sub">DMARC, SPF, MTA-STS and TLS-RPT records across health snapshots</p>
        </div>
        <Badge tone="info">{data?.changes.length ?? 0} changes</Badge>
      </div>
      {error ? <p className="form-error">{error}</p> : null}
      {!data && !error ? <p className="tiny muted">Loading history…</p> : null}
      {data && data.current.length > 0 ? (
        <div className="dnsdiff-current">
          {data.current.map((entry) => (
            <div className="dnsdiff-current-row" key={entry.key}>
              <span className="dnsdiff-key">{entry.label}</span>
              <Badge tone={entry.status === "pass" ? "good" : entry.status === "warn" ? "warn" : entry.status === "fail" ? "bad" : "neutral"}>
                {entry.status}
              </Badge>
              <span className="tiny muted">{entry.summary}</span>
            </div>
          ))}
        </div>
      ) : null}
      {data && data.changes.length === 0 ? (
        <p className="tiny muted dnsdiff-empty">
          <History size={14} />
          No record changes in the retained snapshots.
        </p>
      ) : null}
      {data && data.changes.length > 0 ? (
        <ol className="dnsdiff-list">
          {data.changes.slice(0, 12).map((change) => (
            <li className="dnsdiff-item" key={change.id}>
              <div className="dnsdiff-meta">
                <Badge tone="neutral">{change.label}</Badge>
                <span className="tiny muted" title={change.checked_at ?? undefined}>
                  {relativeTime(change.checked_at)} · {dateTime(change.checked_at)}
                </span>
              </div>
              <div className="dnsdiff-diff">
                <span>{change.before.summary}</span>
                <ArrowRight size={13} />
                <span>{change.after.summary}</span>
              </div>
            </li>
          ))}
        </ol>
      ) : null}
    </section>
  );
}
