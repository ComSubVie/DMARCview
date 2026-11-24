import { useEffect, useState } from "react";
import { Play, ShieldAlert } from "lucide-react";
import { api } from "../api";
import { formatNumber, formatPct } from "../lib/format";
import type { PolicySimulation } from "../types";
import { Drawer } from "./Drawer";
import { Badge } from "./ui";

const POLICY_OPTIONS = ["none", "quarantine", "reject"];

export function SimulationDrawer({
  domain,
  onClose,
}: {
  domain: string;
  onClose: () => void;
}) {
  const [days, setDays] = useState(30);
  const [p, setP] = useState("none");
  const [sp, setSp] = useState("none");
  const [np, setNp] = useState("");
  const [testing, setTesting] = useState("n");
  const [result, setResult] = useState<PolicySimulation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .simulatePolicy(domain, { days })
      .then((data) => {
        if (cancelled) return;
        setResult(data);
        if (data.current) {
          setP(data.current.p);
          setSp(data.current.sp);
          setNp(data.current.np || "");
          setTesting(data.current.testing === "y" ? "y" : "n");
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the simulation");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [domain, days]);

  async function run() {
    setLoading(true);
    setError(null);
    try {
      const data = await api.simulatePolicy(domain, {
        days,
        p,
        sp,
        np: np || undefined,
        t: testing,
      });
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not run the simulation");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Drawer
      title="Simulate policy change"
      subtitle={`${domain} · read-only projection over stored reports`}
      onClose={onClose}
    >
      <div className="sim-controls">
        <div className="field">
          <label htmlFor="sim-days">Window</label>
          <select id="sim-days" value={days} onChange={(event) => setDays(Number(event.target.value))}>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={180}>Last 180 days</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="sim-p">p=</label>
          <select id="sim-p" value={p} onChange={(event) => setP(event.target.value)}>
            {POLICY_OPTIONS.map((value) => (
              <option value={value} key={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="sim-sp">sp=</label>
          <select id="sim-sp" value={sp} onChange={(event) => setSp(event.target.value)}>
            {POLICY_OPTIONS.map((value) => (
              <option value={value} key={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="sim-np">np=</label>
          <select id="sim-np" value={np} onChange={(event) => setNp(event.target.value)}>
            <option value="">not set</option>
            {POLICY_OPTIONS.map((value) => (
              <option value={value} key={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="sim-t">t=</label>
          <select id="sim-t" value={testing} onChange={(event) => setTesting(event.target.value)}>
            <option value="n">n (apply policy)</option>
            <option value="y">y (testing)</option>
          </select>
        </div>
        <button className="btn primary" onClick={run} disabled={loading} type="button">
          {loading ? <span className="spinner" /> : <Play size={14} />}
          {loading ? "Simulating…" : "Run simulation"}
        </button>
      </div>

      {error ? <p className="form-error">{error}</p> : null}

      {result && !result.available ? (
        <div className="sim-empty">
          <ShieldAlert size={18} />
          <p>{result.message}</p>
        </div>
      ) : null}

      {result?.available ? (
        <>
          <div className={`sim-verdict ${result.verdict.level}`}>
            <div>
              <span className="sim-eyebrow">Projected outcome</span>
              <strong>{result.verdict.label}</strong>
              <p>{result.verdict.detail}</p>
            </div>
            <Badge tone={result.verdict.level}>{result.confidence} confidence</Badge>
          </div>

          <div className="sim-kpis">
            <div className="sim-kpi">
              <span>Observed mail</span>
              <strong>{formatNumber(result.totals.messages)}</strong>
              <small>{formatNumber(result.totals.failed)} failing</small>
            </div>
            <div className="sim-kpi accent">
              <span>Newly affected</span>
              <strong>{formatNumber(result.totals.newly_affected)}</strong>
              <small>{formatPct(result.newly_affected_pct, 2)} of observed</small>
            </div>
            <div className="sim-kpi">
              <span>Sources</span>
              <strong>{formatNumber(result.totals.affected_sources)}</strong>
              <small>of {formatNumber(result.totals.sources)} observed</small>
            </div>
            <div className="sim-kpi">
              <span>Newly rejected</span>
              <strong>{formatNumber(result.totals.newly_blocked)}</strong>
              <small>{formatNumber(result.totals.newly_quarantined)} quarantined</small>
            </div>
          </div>

          <div className="sim-policy-line">
            <span>{result.current?.label}</span>
            <span className="sim-arrow">→</span>
            <span>{result.proposed?.label}</span>
          </div>

          <h3 className="sim-heading">Most affected sources</h3>
          {result.sources.length === 0 ? (
            <p className="tiny muted">No failing sources observed in this window.</p>
          ) : (
            <div className="table-wrap">
              <table className="data sim-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th className="right">Messages</th>
                    <th className="right">Aligned</th>
                    <th>Action</th>
                    <th className="right">New</th>
                  </tr>
                </thead>
                <tbody>
                  {result.sources.slice(0, 10).map((source) => (
                    <tr key={`${source.ip}-${source.header_from ?? ""}`}>
                      <td>
                        <div className="primary-cell">{source.ip}</div>
                        <div className="tiny muted">{source.header_from || "no header-from"}</div>
                      </td>
                      <td className="right">{formatNumber(source.messages)}</td>
                      <td className="right">{formatPct(source.aligned_pct)}</td>
                      <td>
                        <span className="tiny muted">
                          {source.current_action} → {source.proposed_action}
                        </span>
                      </td>
                      <td className="right">
                        <strong>{formatNumber(source.newly_affected)}</strong>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.warnings.length > 0 ? (
            <ul className="sim-warnings">
              {result.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}

          <details className="sim-caveats">
            <summary>What this projection does not model</summary>
            <ul>
              {result.caveats.map((caveat) => (
                <li key={caveat}>{caveat}</li>
              ))}
            </ul>
          </details>
        </>
      ) : null}
    </Drawer>
  );
}
