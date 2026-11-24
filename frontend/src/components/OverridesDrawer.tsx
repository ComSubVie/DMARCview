import { useEffect, useState } from "react";
import { RotateCcw, Save, ShieldOff } from "lucide-react";
import { api } from "../api";
import { useData } from "../state";
import type { AlertOverrideRule } from "../types";
import { Drawer } from "./Drawer";
import { Badge } from "./ui";

type Draft = { condition: Record<string, string>; cooldown: string };

function draftFor(rule: AlertOverrideRule): Draft {
  const source = rule.override?.condition ?? rule.condition;
  return {
    condition: Object.fromEntries(
      (rule.fields ?? []).map((field) => [field.key, String(source[field.key] ?? field.default)]),
    ),
    cooldown: String(rule.override?.cooldown_minutes ?? rule.cooldown_minutes),
  };
}

export function OverridesDrawer({
  initialDomain,
  onClose,
}: {
  initialDomain: string;
  onClose: () => void;
}) {
  const { meta, toast } = useData();
  const domains = meta?.domains ?? [];
  const [domain, setDomain] = useState(
    initialDomain !== "all" ? initialDomain : domains[0]?.name ?? "",
  );
  const [rules, setRules] = useState<AlertOverrideRule[]>([]);
  const [drafts, setDrafts] = useState<Record<number, Draft>>({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState<number | null>(null);

  function apply(next: AlertOverrideRule[]) {
    setRules(next);
    setDrafts(Object.fromEntries(next.map((rule) => [rule.rule_id, draftFor(rule)])));
  }

  function load(name: string) {
    if (!name) return;
    setLoading(true);
    api
      .alertOverrides(name)
      .then((result) => apply(result.rules))
      .catch((err) => toast(err instanceof Error ? err.message : "Could not load overrides", "error"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load(domain);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain]);

  function update(ruleId: number, next: Partial<Draft>) {
    setDrafts((current) => ({ ...current, [ruleId]: { ...current[ruleId], ...next } }));
  }

  async function save(rule: AlertOverrideRule) {
    if (!domain) return;
    const draft = drafts[rule.rule_id];
    if (!draft) return;
    setSaving(rule.rule_id);
    try {
      const condition = Object.fromEntries(
        (rule.fields ?? []).map((field) => [field.key, Number(draft.condition[field.key])]),
      );
      const result = await api.setAlertOverride(domain, rule.kind, {
        enabled: true,
        condition,
        cooldown_minutes: Number(draft.cooldown),
      });
      apply(result.rules);
      toast(`${rule.label} override saved`);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save the override", "error");
    } finally {
      setSaving(null);
    }
  }

  async function reset(rule: AlertOverrideRule) {
    if (!domain) return;
    try {
      const result = await api.deleteAlertOverride(domain, rule.kind);
      apply(result.rules);
      toast(`${rule.label} uses the global rule again`);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not reset the override", "error");
    }
  }

  async function disable(rule: AlertOverrideRule) {
    if (!domain) return;
    try {
      const result = await api.setAlertOverride(domain, rule.kind, { enabled: false });
      apply(result.rules);
      toast(`${rule.label} disabled for ${domain}`);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not disable the rule", "error");
    }
  }

  return (
    <Drawer
      title="Per-domain alert overrides"
      subtitle="Silence or retune one rule for a domain without changing the global rule"
      onClose={onClose}
    >
      <div className="field">
        <label htmlFor="override-domain">Domain</label>
        <select id="override-domain" value={domain} onChange={(event) => setDomain(event.target.value)}>
          {domains.map((item) => (
            <option value={item.name} key={item.name}>
              {item.display_name ? `${item.name} — ${item.display_name}` : item.name}
            </option>
          ))}
        </select>
      </div>
      <p className="tiny muted" style={{ lineHeight: 1.6 }}>
        Values are stored only for the selected domain. “Use global” removes the override; “Disable”
        suppresses the rule here without affecting other domains.
      </p>
      {loading ? <p className="tiny muted">Loading…</p> : null}
      <div className="override-list">
        {rules.map((rule) => {
          const draft = drafts[rule.rule_id] ?? draftFor(rule);
          const badge = rule.override ? (rule.override.enabled ? "custom" : "disabled") : "global";
          return (
            <div className="override-card" key={rule.rule_id}>
              <div className="override-card-head">
                <div>
                  <div className="primary-cell">{rule.label}</div>
                  <div className="tiny muted">{rule.description}</div>
                </div>
                <Badge tone={badge === "global" ? "neutral" : badge === "disabled" ? "warn" : "info"}>
                  {badge}
                </Badge>
              </div>
              <div className="override-fields">
                {(rule.fields ?? []).map((field) => (
                  <label className="field" key={field.key}>
                    <span>
                      {field.label}
                      {field.unit ? ` (${field.unit})` : ""}
                    </span>
                    <input
                      type="number"
                      min={field.min}
                      max={field.max}
                      step={field.type === "int" ? 1 : 0.1}
                      value={draft.condition[field.key] ?? ""}
                      onChange={(event) =>
                        update(rule.rule_id, {
                          condition: { ...draft.condition, [field.key]: event.target.value },
                        })
                      }
                    />
                  </label>
                ))}
                <label className="field">
                  <span>Cooldown (minutes)</span>
                  <input
                    type="number"
                    min={0}
                    max={1440}
                    step={1}
                    value={draft.cooldown}
                    onChange={(event) => update(rule.rule_id, { cooldown: event.target.value })}
                  />
                </label>
              </div>
              <div className="override-actions">
                <button className="btn primary sm" type="button" disabled={saving === rule.rule_id} onClick={() => void save(rule)}>
                  {saving === rule.rule_id ? <span className="spinner" /> : <Save size={13} />}
                  Save override
                </button>
                {rule.override ? (
                  <button className="btn ghost sm" type="button" onClick={() => void reset(rule)}>
                    <RotateCcw size={13} />
                    Use global
                  </button>
                ) : null}
                {!rule.override || rule.override.enabled ? (
                  <button className="btn ghost sm" type="button" onClick={() => void disable(rule)}>
                    <ShieldOff size={13} />
                    Disable
                  </button>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>
    </Drawer>
  );
}
