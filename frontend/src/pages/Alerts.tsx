import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Mail,
  MessageCircle,
  Pencil,
  Play,
  Send,
  Webhook,
} from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import { Drawer } from "../components/Drawer";
import { Badge, EmptyState, Skeleton } from "../components/ui";
import { relativeTime } from "../lib/format";
import { useData } from "../state";
import type {
  AlertEventItem,
  AlertKindSpec,
  AlertRuleItem,
  AlertsPayload,
  AlertSeverity,
} from "../types";

const CHANNEL_ICONS: Record<string, ReactNode> = {
  smtp: <Mail size={14} />,
  telegram: <Send size={14} />,
  signal: <MessageCircle size={14} />,
  webhook: <Webhook size={14} />,
};

function severityTone(severity: AlertSeverity): "bad" | "warn" | "info" {
  return severity === "critical" ? "bad" : severity === "warning" ? "warn" : "info";
}

function conditionSummary(rule: AlertRuleItem, kind: AlertKindSpec | undefined): string {
  if (!kind || kind.fields.length === 0) return "no thresholds";
  if (kind.kind === "report_gap") {
    const grace = rule.condition.grace_hours ?? 0;
    return grace > 0 ? `domain interval + ${grace}h` : "domain interval";
  }
  return kind.fields
    .map((field) => {
      const value = rule.condition[field.key] ?? field.default;
      const unit = field.unit ? (field.unit.length > 1 ? ` ${field.unit}` : field.unit) : "";
      return `${value}${unit}`;
    })
    .join(" · ");
}

function Incident({ event }: { event: AlertEventItem }) {
  return (
    <div className={`alert-item ${event.severity}`}>
      <span className="alert-sev">{event.severity}</span>
      <div style={{ minWidth: 0 }}>
        <div className="alert-title">{event.title}</div>
        <div className="alert-msg">{event.message}</div>
        <div className="alert-meta">
          {event.domain} · {relativeTime(event.triggered_at)}
          {event.delivery_error ? ` · delivery: ${event.delivery_error}` : ""}
        </div>
      </div>
    </div>
  );
}

function RuleDrawer({
  rule,
  kind,
  onClose,
  onSaved,
}: {
  rule: AlertRuleItem;
  kind: AlertKindSpec | undefined;
  onClose: () => void;
  onSaved: (payload: AlertsPayload) => void;
}) {
  const { toast } = useData();
  const [condition, setCondition] = useState<Record<string, number>>({ ...rule.condition });
  const [enabled, setEnabled] = useState(rule.enabled);
  const [cooldown, setCooldown] = useState(rule.cooldown_minutes);
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      const updated = await api.updateAlertRule(rule.id, {
        condition,
        enabled,
        cooldown_minutes: cooldown,
      });
      onSaved(updated);
      toast("Alert rule saved");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save the rule", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Drawer title={rule.label} subtitle="Alert rule" onClose={onClose}>
      <p className="tiny muted" style={{ lineHeight: 1.6 }}>
        {rule.description}
      </p>
      <div className="settings-grid">
        {kind?.fields.map((field) => (
          <div className="field" key={field.key}>
            <label htmlFor={`cond-${field.key}`}>{field.label}</label>
            <input
              id={`cond-${field.key}`}
              type="number"
              min={field.min}
              max={field.max}
              step={field.type === "float" ? 0.1 : 1}
              value={condition[field.key] ?? field.default}
              onChange={(event) =>
                setCondition((current) => ({ ...current, [field.key]: Number(event.target.value) }))
              }
            />
            {field.unit ? <span className="tiny muted">Unit: {field.unit}</span> : null}
          </div>
        ))}
        <div className="field">
          <label htmlFor="cooldown">Cooldown (minutes)</label>
          <input
            id="cooldown"
            type="number"
            min={0}
            max={1440}
            value={cooldown}
            onChange={(event) => setCooldown(Number(event.target.value))}
          />
        </div>
      </div>
      <label className="checkbox-row">
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        Rule enabled
      </label>
      <div className="actions-row">
        <button className="btn primary" onClick={save} disabled={saving} type="button">
          {saving ? <span className="spinner" /> : null}
          Save rule
        </button>
        <button className="btn ghost" onClick={onClose} type="button">
          Cancel
        </button>
      </div>
    </Drawer>
  );
}

export function AlertsPage() {
  const { toast } = useData();
  const [data, setData] = useState<AlertsPayload | null>(null);
  const [running, setRunning] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [editing, setEditing] = useState<AlertRuleItem | null>(null);

  useEffect(() => {
    document.title = "DMARCView — Alerts";
  }, []);

  const load = useCallback(async () => {
    try {
      setData(await api.alerts());
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not load alerts", "error");
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function runNow() {
    setRunning(true);
    try {
      const result = await api.runAlerts();
      setData(result.alerts);
      toast(
        `Evaluated: ${result.summary.created} new, ${result.summary.resolved} resolved`,
      );
    } catch (err) {
      toast(err instanceof Error ? err.message : "Evaluation failed", "error");
    } finally {
      setRunning(false);
    }
  }

  async function toggle(rule: AlertRuleItem) {
    try {
      setData(await api.updateAlertRule(rule.id, { enabled: !rule.enabled }));
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not update the rule", "error");
    }
  }

  async function testChannel(kind: string) {
    setTesting(kind);
    try {
      const result = await api.testAlertChannel(kind);
      if (result.ok) {
        toast(`Test message sent via ${kind}`);
      } else {
        const failure = result.results.find((item) => !item.ok);
        toast(result.error || failure?.error || `Could not send via ${kind}`, "error");
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Test failed", "error");
    } finally {
      setTesting(null);
    }
  }

  if (!data) {
    return (
      <div className="fade-in">
        <div className="section-head">
          <Skeleton width={220} height={28} />
        </div>
        <div style={{ display: "grid", gap: 14 }}>
          <Skeleton height={140} />
          <Skeleton height={260} />
        </div>
      </div>
    );
  }

  const kinds = new Map(data.kinds.map((kind) => [kind.kind, kind]));
  const configured = data.channels.filter((channel) => channel.configured).length;
  const open = data.events.filter((event) => event.open);
  const resolved = data.events.filter((event) => !event.open);

  return (
    <div className="fade-in">
      <div className="section-head">
        <div>
          <h1>Alerts</h1>
          <p>
            Compliance, sending sources, TLS and certificates
            {data.last_run ? ` · evaluated ${relativeTime(data.last_run)}` : ""}.
          </p>
        </div>
        <div style={{ display: "flex", gap: 9, alignItems: "center" }}>
          {data.unresolved > 0 ? (
            <Badge tone="bad">{data.unresolved} open</Badge>
          ) : (
            <Badge tone="good">All clear</Badge>
          )}
          <button className="btn primary" onClick={runNow} disabled={running} type="button">
            {running ? <span className="spinner" /> : <Play size={14} />}
            {running ? "Evaluating…" : "Run now"}
          </button>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <div>
            <h2 className="card-title">Notification channels</h2>
            <p className="card-sub">Configured with environment variables · credentials never stored</p>
          </div>
          <Badge tone={configured > 0 ? "good" : "warn"}>{configured}/4 ready</Badge>
        </div>
        <div className="card-body" style={{ paddingTop: 12 }}>
          <div className="channel-grid">
            {data.channels.map((channel) => (
              <div className={`channel-card ${channel.configured ? "on" : ""}`} key={channel.kind}>
                <div className="channel-head">
                  <span className="channel-name">
                    {CHANNEL_ICONS[channel.kind] ?? <Bell size={14} />}
                    {channel.label}
                  </span>
                  <span className={`health-dot ${channel.configured ? "ok" : "neutral"}`} />
                </div>
                <div className="channel-target">{channel.configured ? channel.target : channel.hint}</div>
                <button
                  className="btn ghost"
                  onClick={() => testChannel(channel.kind)}
                  disabled={!channel.configured || testing !== null}
                  type="button"
                >
                  {testing === channel.kind ? <span className="spinner dark" /> : null}
                  Send test
                </button>
              </div>
            ))}
          </div>
          {configured === 0 ? (
            <p className="callout info" style={{ marginTop: 12 }}>
              <AlertTriangle size={15} style={{ flex: "none", marginTop: 1 }} />
              <span>
                No channel is configured yet. Set <code>SMTP_HOST</code>/<code>ALERT_TO</code> or
                the Telegram/Signal/webhook variables in <code>.env</code>, then restart. Incidents
                are still recorded below.
              </span>
            </p>
          ) : null}
        </div>
      </section>

      <div className="grid cols-8-4">
        <section className="card">
          <div className="card-head">
            <div>
              <h2 className="card-title">Rules</h2>
              <p className="card-sub">Evaluated hourly in the background</p>
            </div>
            <span className="chip violet">{data.rules.filter((rule) => rule.enabled).length} enabled</span>
          </div>
          <div className="card-body" style={{ paddingTop: 8, paddingBottom: 12 }}>
            <table className="data rules-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th className="hide-sm">Condition</th>
                  <th className="center hide-sm">Open</th>
                  <th className="center">On</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <div className="primary-cell">{rule.label}</div>
                      <div className="tiny muted rule-description">{rule.description}</div>
                    </td>
                    <td className="hide-sm tiny muted">{conditionSummary(rule, kinds.get(rule.kind))}</td>
                    <td className="center hide-sm">
                      {rule.open > 0 ? <Badge tone="bad">{rule.open}</Badge> : "—"}
                    </td>
                    <td className="center">
                      <button
                        className={`switch ${rule.enabled ? "on" : ""}`}
                        onClick={() => toggle(rule)}
                        role="switch"
                        aria-checked={rule.enabled}
                        aria-label={`Toggle ${rule.label}`}
                        type="button"
                      />
                    </td>
                    <td style={{ width: 36 }}>
                      <button
                        className="btn ghost icon"
                        onClick={() => setEditing(rule)}
                        aria-label={`Edit ${rule.label}`}
                        type="button"
                      >
                        <Pencil size={13} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="card open-incidents">
          <div className="card-head">
            <div>
              <h2 className="card-title">Open incidents</h2>
              <p className="card-sub">Unresolved findings</p>
            </div>
            {data.unresolved > 0 ? <Badge tone="bad">{data.unresolved}</Badge> : null}
          </div>
          <div className="card-body" style={{ paddingTop: 10 }}>
            {open.length === 0 ? (
              <EmptyState icon={<CheckCircle2 size={20} />} title="All clear">
                No open incidents. Rules re-run every hour and after a manual evaluation.
              </EmptyState>
            ) : (
              <div className="alert-list">
                {open.map((event) => (
                  <Incident key={event.id} event={event} />
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      <section className="card" style={{ marginTop: 16 }}>
        <div className="card-head">
          <div>
            <h2 className="card-title">History</h2>
            <p className="card-sub">Most recent incidents, resolved or not</p>
          </div>
        </div>
        <div style={{ padding: "4px 8px 10px" }}>
          {resolved.length === 0 && open.length === 0 ? (
            <EmptyState icon={<Bell size={20} />} title="No alerts yet">
              Incidents appear here once a rule fires.
            </EmptyState>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Rule</th>
                  <th className="hide-sm">Domain</th>
                  <th>Severity</th>
                  <th className="hide-sm">Delivery</th>
                  <th>State</th>
                  <th className="hide-sm">Title</th>
                </tr>
              </thead>
              <tbody>
                {data.events.map((event) => (
                  <tr key={event.id}>
                    <td className="tiny">{relativeTime(event.triggered_at)}</td>
                    <td className="tiny">{kinds.get(event.kind)?.label ?? event.kind}</td>
                    <td className="tiny hide-sm">{event.domain}</td>
                    <td>
                      <Badge tone={severityTone(event.severity)}>{event.severity}</Badge>
                    </td>
                    <td className="hide-sm tiny">
                      {event.delivered_at ? (
                        <span style={{ color: "var(--green)" }}>sent</span>
                      ) : event.delivery_error?.startsWith("no notification") ? (
                        <span style={{ color: "var(--ink-4)" }}>not configured</span>
                      ) : event.delivery_error ? (
                        <span title={event.delivery_error} style={{ color: "var(--red)" }}>
                          failed
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      <Badge tone={event.open ? "bad" : "good"}>{event.open ? "open" : "resolved"}</Badge>
                    </td>
                    <td className="tiny hide-sm">{event.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {editing ? (
        <RuleDrawer
          rule={editing}
          kind={kinds.get(editing.kind)}
          onClose={() => setEditing(null)}
          onSaved={(payload) => {
            setData(payload);
            setEditing(null);
          }}
        />
      ) : null}
    </div>
  );
}
