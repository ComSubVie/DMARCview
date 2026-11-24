import { useEffect, useState } from "react";
import { CalendarClock, Pencil, Plus, Trash2 } from "lucide-react";
import { api } from "../api";
import { dateTime, relativeTime } from "../lib/format";
import { useData } from "../state";
import type { TimelineItem } from "../types";
import { Drawer } from "./Drawer";
import { Badge, EmptyState } from "./ui";

const KINDS = [
  { value: "note", label: "Note" },
  { value: "dns", label: "DNS change" },
  { value: "esp", label: "ESP / provider" },
  { value: "outage", label: "Outage" },
  { value: "other", label: "Other" },
];

const SOURCE_LABELS: Record<TimelineItem["source"], string> = {
  annotation: "Note",
  alert: "Alert",
  dns: "DNS change",
  identity: "New identity",
  report_gap: "Report gap",
};

function sourceTone(source: TimelineItem["source"]): "info" | "warn" | "bad" | "neutral" {
  if (source === "alert") return "warn";
  if (source === "report_gap") return "warn";
  if (source === "dns") return "info";
  return "neutral";
}

function NoteDrawer({
  domain,
  editing,
  onClose,
  onSaved,
}: {
  domain: string;
  editing: TimelineItem | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useData();
  const [kind, setKind] = useState(editing?.kind ?? "note");
  const [title, setTitle] = useState(editing?.title ?? "");
  const [body, setBody] = useState(editing?.body ?? "");
  const [saving, setSaving] = useState(false);

  async function save() {
    if (!title.trim()) return;
    setSaving(true);
    try {
      if (editing?.ref_id) {
        await api.updateAnnotation(editing.ref_id, { kind, title: title.trim(), body: body.trim() || null });
      } else {
        await api.createAnnotation(domain, { kind, title: title.trim(), body: body.trim() || null });
      }
      toast(editing ? "Note updated" : "Note added");
      onSaved();
      onClose();
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save the note", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Drawer
      title={editing ? "Edit timeline note" : "Add timeline note"}
      subtitle={`${domain} · private to this admin`}
      onClose={onClose}
    >
      <div className="settings-grid">
        <div className="field">
          <label htmlFor="note-kind">Kind</label>
          <select id="note-kind" value={kind} onChange={(event) => setKind(event.target.value)}>
            {KINDS.map((item) => (
              <option value={item.value} key={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field full">
          <label htmlFor="note-title">Title</label>
          <input
            id="note-title"
            value={title}
            maxLength={255}
            placeholder="ESP migration to a new relay"
            onChange={(event) => setTitle(event.target.value)}
          />
        </div>
        <div className="field full">
          <label htmlFor="note-body">Details (optional)</label>
          <textarea
            id="note-body"
            rows={5}
            value={body}
            maxLength={4000}
            placeholder="What changed, who was involved, and what to watch next."
            onChange={(event) => setBody(event.target.value)}
          />
        </div>
      </div>
      <div className="drawer-actions">
        <button className="btn ghost" type="button" onClick={onClose}>
          Cancel
        </button>
        <button className="btn primary" type="button" disabled={saving || !title.trim()} onClick={save}>
          {saving ? <span className="spinner" /> : null}
          {saving ? "Saving…" : "Save note"}
        </button>
      </div>
    </Drawer>
  );
}

export function TimelineCard({ domain }: { domain: string }) {
  const { toast } = useData();
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [drawer, setDrawer] = useState<"new" | TimelineItem | null>(null);

  function refresh() {
    if (domain === "all") {
      setItems([]);
      return;
    }
    setLoading(true);
    setError(null);
    api
      .timeline(domain, 50)
      .then((result) => setItems(result.items))
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load the timeline"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain]);

  async function remove(item: TimelineItem) {
    if (!item.ref_id) return;
    try {
      await api.deleteAnnotation(item.ref_id);
      toast("Note deleted");
      refresh();
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not delete the note", "error");
    }
  }

  if (domain === "all") {
    return (
      <section className="card timeline-card">
        <div className="card-head">
          <div>
            <h2 className="card-title">Domain timeline</h2>
            <p className="card-sub">Notes and operational events for the selected domain</p>
          </div>
        </div>
        <EmptyState icon={<CalendarClock size={20} />} title="Select a domain">
          The timeline is private and scoped to one domain.
        </EmptyState>
      </section>
    );
  }

  const visible = showAll ? items : items.slice(0, 6);

  return (
    <section className="card timeline-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Domain timeline</h2>
          <p className="card-sub">Notes, alerts, DNS changes and new senders in one place</p>
        </div>
        <div className="timeline-head-actions">
          <Badge tone="info">{items.length} events</Badge>
          <button className="btn ghost sm" type="button" onClick={() => setDrawer("new")}>
            <Plus size={13} />
            Add note
          </button>
        </div>
      </div>
      {loading && items.length === 0 ? <p className="tiny muted">Loading timeline…</p> : null}
      {error ? <p className="form-error">{error}</p> : null}
      {!loading && !error && items.length === 0 ? (
        <EmptyState icon={<CalendarClock size={20} />} title="No events yet">
          Add a note to record a migration, outage or DNS change; alerts and record changes appear
          automatically.
        </EmptyState>
      ) : (
        <>
          <ol className="timeline-list">
            {visible.map((item) => (
              <li className={`timeline-item ${item.source}`} key={item.id}>
                <span className={`timeline-dot ${item.source}`} />
                <div className="timeline-content">
                  <div className="timeline-meta">
                    <Badge tone={sourceTone(item.source)}>{SOURCE_LABELS[item.source]}</Badge>
                    <span className="tiny muted" title={item.occurred_at ?? undefined}>
                      {relativeTime(item.occurred_at)} · {dateTime(item.occurred_at)}
                    </span>
                  </div>
                  <strong>{item.title}</strong>
                  {item.body ? <p>{item.body}</p> : null}
                  {item.editable && item.ref_id ? (
                    <div className="timeline-actions">
                      <button className="link" type="button" onClick={() => setDrawer(item)}>
                        <Pencil size={12} /> Edit
                      </button>
                      <button className="link danger" type="button" onClick={() => void remove(item)}>
                        <Trash2 size={12} /> Delete
                      </button>
                    </div>
                  ) : null}
                </div>
              </li>
            ))}
          </ol>
          {items.length > 6 ? (
            <button className="link timeline-more" type="button" onClick={() => setShowAll((value) => !value)}>
              {showAll ? "Show fewer" : `Show all ${items.length} events`}
            </button>
          ) : null}
        </>
      )}
      {drawer ? (
        <NoteDrawer
          domain={domain}
          editing={drawer === "new" ? null : drawer}
          onClose={() => setDrawer(null)}
          onSaved={refresh}
        />
      ) : null}
    </section>
  );
}
