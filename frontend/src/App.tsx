import { useEffect, useState } from "react";
import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import { api } from "./api";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/Dashboard";
import { AlertsPage } from "./pages/Alerts";
import { HealthPage } from "./pages/Health";
import { IngestPage } from "./pages/Ingest";
import { Login } from "./pages/Login";
import { ReportsPage } from "./pages/Reports";
import { TlsPage } from "./pages/Tls";
import { DataProvider } from "./state";

function Splash() {
  return (
    <div className="login-wrap">
      <div style={{ display: "grid", justifyItems: "center", gap: 14 }}>
        <span className="brand-mark" style={{ width: 40, height: 40, borderRadius: 12 }}>
          <span className="spinner" style={{ width: 18, height: 18 }} />
        </span>
        <span className="tiny muted" style={{ letterSpacing: "0.14em", textTransform: "uppercase" }}>
          DMARCView
        </span>
      </div>
    </div>
  );
}

function NotFound() {
  return (
    <section className="card" style={{ marginTop: 28, padding: 40, textAlign: "center" }}>
      <h1 className="display" style={{ fontSize: 28 }}>
        Page not found
      </h1>
      <p className="muted" style={{ marginTop: 8 }}>
        That route does not exist.
      </p>
      <Link className="btn primary lg" to="/" style={{ marginTop: 18 }}>
        Back to overview
      </Link>
    </section>
  );
}

export default function App() {
  const [auth, setAuth] = useState<{ loading: boolean; user: string | null }>({
    loading: true,
    user: null,
  });

  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then((result) => {
        if (!cancelled) setAuth({ loading: false, user: result.authenticated ? result.username : null });
      })
      .catch(() => {
        if (!cancelled) setAuth({ loading: false, user: null });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const handler = () => setAuth({ loading: false, user: null });
    window.addEventListener("dmarc:unauthorized", handler);
    return () => window.removeEventListener("dmarc:unauthorized", handler);
  }, []);

  if (auth.loading) return <Splash />;
  if (!auth.user) return <Login onSuccess={(username) => setAuth({ loading: false, user: username })} />;

  return (
    <BrowserRouter>
      <DataProvider>
        <Layout user={auth.user} onSignOut={() => setAuth({ loading: false, user: null })}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/health" element={<HealthPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/tls" element={<TlsPage />} />
            <Route path="/ingest" element={<IngestPage />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Layout>
      </DataProvider>
    </BrowserRouter>
  );
}
