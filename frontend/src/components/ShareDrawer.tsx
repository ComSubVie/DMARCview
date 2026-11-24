import { useEffect, useState } from "react";
import { Share2, Trash2 } from "lucide-react";
import { api } from "../api";
import { dateTime, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { CreatedShareLink, ShareLinkItem } from "../types";
import { Drawer } from "./Drawer";
import { Badge, CopyButton } from "./ui";

export function ShareDrawer({ onClose }: { onClose: () => void }) {
  const { meta, domain, toast } = useData();
  const [links, setLinks] = useState<ShareLinkItem[]>([]);
  const [shareDomain, setShareDomain] = useState(domain === "all" ? "all" : domain);
  const [days, setDays] = useState(7);
  const [includeSources, setIncludeSources] = useState(false);
  const [created, setCreated] = useState<CreatedShareLink | null>(null);
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    api
      .shareLinks()
      .then((result) => {
        if (!cancelled) setLinks(result.items);
      })
      .catch(() => {
        /* the list is optional until the first link exists */
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function create() {
    setCreating(true);
    try {
      const result = await api.createShareLink({
        domain: shareDomain === "all" ? null : shareDomain,
        days,
        include_sources: includeSources,
      });
      setCreated(result);
      setLinks((current) => [result, ...current]);
      toast("Share link created");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not create the share link", "error");
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: number) {
    try {
      const updated = await api.revokeShareLink(id);
      setLinks((current) => current.map((item) => (item.id === id ? updated : item)));
      if (created?.id === id) setCreated(null);
      toast("Share link revoked");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not revoke the link", "error");
    }
  }

  return (
    <Drawer
      title="Share dashboard"
      subtitle="Signed, expiring read-only links — no account required"
      onClose={onClose}
    >
      <p className="tiny muted" style={{ lineHeight: 1.6 }}>
        Anyone with the URL can view aggregates for the chosen scope. Raw reports, search,
        alert settings and the admin area stay private. Links can be revoked at any time.
      </p>

      <div className="settings-grid" style={{ marginTop: 14 }}>
        <div className="field">
          <label htmlFor="share-domain">Domain</label>
          <select
            id="share-domain"
            value={shareDomain}
            onChange={(event) => setShareDomain(event.target.value)}
          >
            <option value="all">All domains</option>
            {meta?.domains.map((item) => (
              <option key={item.name} value={item.name}>
                {item.display_name}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="share-days">Expires after</label>
          <select
            id="share-days"
            value={days}
            onChange={(event) => setDays(Number(event.target.value))}
          >
            <option value={7}>7 days</option>
            <option value={14}>14 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </select>
        </div>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={includeSources}
          onChange={(event) => setIncludeSources(event.target.checked)}
        />
        Include sending sources (IPs and networks)
      </label>
      <div className="actions-row">
        <button className="btn primary" onClick={create} disabled={creating} type="button">
          {creating ? <span className="spinner" /> : <Share2 size={14} />}
          Create link
        </button>
      </div>

      {created ? (
        <div className="share-created">
          <div className="share-created-head">
            <Badge tone="good">Link ready</Badge>
            <span className="tiny muted">Copy it now — it is shown only once.</span>
          </div>
          <div className="share-url">
            <code>{`${window.location.origin}${created.url}`}</code>
            <CopyButton value={`${window.location.origin}${created.url}`} label="Copy share link" />
          </div>
          <div className="tiny muted">Expires {dateTime(created.expires_at)}</div>
        </div>
      ) : null}

      <div className="share-list-head">
        <h3 className="section-title">Active links</h3>
        <span className="tiny muted">{links.filter((item) => !item.revoked).length} active</span>
      </div>
      {loading ? (
        <p className="tiny muted">Loading…</p>
      ) : links.length === 0 ? (
        <p className="tiny muted">No links yet.</p>
      ) : (
        <div className="share-list">
          {links.map((item) => (
            <div className={`share-row ${item.revoked ? "revoked" : ""}`} key={item.id}>
              <div>
                <div className="share-row-title">
                  {item.domain ?? "All domains"}{" "}
                  {item.revoked ? <Badge tone="neutral">revoked</Badge> : <Badge tone="info">{item.days}d</Badge>}
                </div>
                <div className="tiny muted">
                  created {relativeTime(item.created_at)} · expires {dateTime(item.expires_at)} ·{" "}
                  {item.uses} view{item.uses === 1 ? "" : "s"}
                </div>
              </div>
              {!item.revoked ? (
                <button
                  className="btn ghost icon"
                  onClick={() => revoke(item.id)}
                  aria-label="Revoke share link"
                  title="Revoke"
                  type="button"
                >
                  <Trash2 size={14} />
                </button>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </Drawer>
  );
}
