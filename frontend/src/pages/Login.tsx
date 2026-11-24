import { ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "../api";

export function Login({ onSuccess }: { onSuccess: (username: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.login(username.trim(), password);
      onSuccess(result.username);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-brand">
          <span className="brand-mark" style={{ width: 34, height: 34, borderRadius: 10 }}>
            <ShieldCheck size={19} strokeWidth={2.2} />
          </span>
          <span className="brand-word" style={{ fontSize: 16 }}>
            DMARC<span>View</span>
          </span>
        </div>

        <h1>Sign in</h1>
        <p className="sub">
          Self-hosted DMARC and TLS-RPT reporting. Your report data never leaves this server.
        </p>

        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              autoFocus
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="admin"
              required
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          {error ? <div className="form-error">{error}</div> : null}

          <button className="btn primary" type="submit" disabled={loading}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <div className="login-foot">
          <span>DMARCView</span>
          <span>Credentials from ADMIN_PASSWORD</span>
        </div>
      </div>
    </div>
  );
}
