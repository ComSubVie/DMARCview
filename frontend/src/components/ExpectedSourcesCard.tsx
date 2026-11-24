import { useEffect, useState } from "react";
import { Plus, Trash2, Users } from "lucide-react";
import { api } from "../api";
import { useData } from "../state";
import type { SourceExpectation } from "../types";
import { Badge, EmptyState } from "./ui";

const TYPES = [
  { value: "cidr", label: "CIDR", placeholder: "192.0.2.0/24" },
  { value: "ip", label: "IP", placeholder: "192.0.2.10" },
  { value: "asn", label: "ASN", placeholder: "64500" },
  { value: "domain", label: "Domain", placeholder: "esp.example" },
];

export function ExpectedSourcesCard({ domain }: { domain: string }) {
  const { toast } = useData();
  const [items, setItems] = useState<SourceExpectation[]>([]);
  const [matchType, setMatchType] = useState("cidr");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    api
      .expectations(domain)
      .then((result) => setItems(result.items))
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load expectations"));
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain]);

  async function add() {
    if (!value.trim()) return;
    setSaving(true);
    setError(null);
    try {
      const item = await api.createExpectation(domain, {
        match_type: matchType,
        value: value.trim(),
        label: label.trim() || null,
      });
      setItems((current) => [...current, item]);
      setValue("");
      setLabel("");
      toast("Known sender added");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Could not add the expectation";
      setError(message);
      toast(message, "error");
    } finally {
      setSaving(false);
    }
  }

  async function remove(item: SourceExpectation) {
    try {
      await api.deleteExpectation(item.id);
      setItems((current) => current.filter((entry) => entry.id !== item.id));
      toast("Known sender removed");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not remove the expectation", "error");
    }
  }

  const selected = TYPES.find((item) => item.value === matchType) ?? TYPES[0];

  return (
    <section className="card settings-card">
      <div className="card-head">
        <div>
          <h2 className="card-title">Known senders</h2>
          <p className="card-sub">
            Suppress <code>new_source</code> alerts for expected IPs, networks, ASNs or domains.
          </p>
        </div>
        <Badge tone="info">{items.length} rules</Badge>
      </div>
      <div className="card-body">
        <div className="expectation-form">
          <div className="field">
            <label htmlFor="expectation-type">Match</label>
            <select
              id="expectation-type"
              value={matchType}
              onChange={(event) => setMatchType(event.target.value)}
            >
              {TYPES.map((item) => (
                <option value={item.value} key={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="expectation-value">Value</label>
            <input
              id="expectation-value"
              value={value}
              placeholder={selected.placeholder}
              onChange={(event) => setValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void add();
              }}
            />
          </div>
          <div className="field">
            <label htmlFor="expectation-label">Label</label>
            <input
              id="expectation-label"
              value={label}
              placeholder="Marketing ESP"
              onChange={(event) => setLabel(event.target.value)}
            />
          </div>
          <button className="btn primary" type="button" disabled={saving || !value.trim()} onClick={add}>
            <Plus size={14} />
            Add
          </button>
        </div>
        {error ? <p className="form-error">{error}</p> : null}
        {items.length === 0 ? (
          <EmptyState icon={<Users size={20} />} title="No known senders yet">
            Add an ESP network, ASN or sending domain so routine first-seen alerts stay quiet.
          </EmptyState>
        ) : (
          <div className="expectation-list">
            {items.map((item) => (
              <div className="expectation-row" key={item.id}>
                <Badge tone="neutral">{item.match_type}</Badge>
                <code>{item.value}</code>
                <span className="tiny muted">{item.label || "no label"}</span>
                <button
                  className="btn ghost icon close"
                  type="button"
                  aria-label={`Remove ${item.value}`}
                  onClick={() => void remove(item)}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
