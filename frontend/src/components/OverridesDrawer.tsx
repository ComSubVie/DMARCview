import { useEffect, useState } from "react";
import { RotateCcw, ShieldOff } from "lucide-react";
import { api } from "../api";
import { useData } from "../state";
import type { AlertOverrideRule } from "../types";
import { Drawer } from "./Drawer";
import { Badge } from "./ui";

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
  const [loading, setLoading] = useState(false);

  function load(name: string) {
    if (!name) return;
    setLoading(true);
    api
      .alertOverrides(name)
      .then((result) => setRules(result.rules))
      .catch((err) => toast(err instanceof Error ? err.message : "Could not load overrides", "error"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load(domain);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain]);

  async function toggle(rule: AlertOverrideRule) {
    if (!domain) return;
    try {
      const result = rule.override
        ? await api.deleteAlertOverride(domain, rule.kind)
        : await api.setAlertOverride(domain, rule.kind, { enabled: false });
      setRules(result.rules);
      toast(rule.override ? "Override removed" : "Rule disabled for this domain");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not update the override", "error");
    }
  }

  return (
    <Drawer
      title="Per-domain alert overrides"
      subtitle="Silence a rule for one domain without changing the global rule"
      onClose={onClose}
    >
      <div className="field">
        <label htmlFor="override-domain">Domain</label>
        <select
          id="override-domain"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
        >
          {domains.map((item) => (
            <option value={item.name} key={item.name}>
              {item.display_name ? `${item.name} — ${item.display_name}` : item.name}
            </option>
          ))}
        </select>
      </div>
      <p className="tiny muted" style={{ lineHeight: 1.6 }}>
        A domain override can disable a rule or replace its thresholds. This panel exposes the
        common mute operation; custom thresholds and cooldowns are available through the alerts
        API.
      </p>
      {loading ? <p className="tiny muted">Loading…</p> : null}
      <div className="override-list">
        {rules.map((rule) => (
          <div className="override-row" key={rule.rule_id}>
            <div>
              <div className="primary-cell">{rule.label}</div>
              <div className="tiny muted">{rule.description}</div>
            </div>
            <Badge tone={rule.override ? "warn" : "neutral"}>
              {rule.override ? "disabled for domain" : "global"}
            </Badge>
            <button
              className="btn ghost sm"
              type="button"
              onClick={() => void toggle(rule)}
              title={rule.override ? "Remove override" : "Disable for this domain"}
            >
              {rule.override ? <RotateCcw size={13} /> : <ShieldOff size={13} />}
              {rule.override ? "Use global" : "Disable"}
            </button>
          </div>
        ))}
      </div>
    </Drawer>
  );
}
