import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { get, post, setCsrf, setUnauthorisedHandler } from "./api";
import { Link, Loading, navigate, usePath } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import { AssetDetailPage, AssetForm, AssetsPage } from "./pages/Assets";
import { HostDetailPage, HostsPage } from "./pages/Hosts";
import { RepoDetailPage, ReposPage } from "./pages/Repos";
import { ScanDetailPage, ScansPage } from "./pages/Scans";
import { FindingDetailPage, VulnsPage } from "./pages/Vulns";
import SettingsPage from "./pages/Settings";
import "./styles.css";

const NAV = [
  ["/", "Dashboard"], ["/assets", "Assets"], ["/hosts", "Hosts"], ["/repositories", "Repositories"],
  ["/scans", "Scans"], ["/vulnerabilities", "Vulnerabilities"], ["/settings", "Settings"],
] as const;

function route(path: string) {
  const p = path.split("?")[0];
  const m = (re: RegExp) => p.match(re);
  let r;
  if (p === "/") return <Dashboard />;
  if (p === "/assets") return <AssetsPage />;
  if (p === "/assets/new") return <AssetForm />;
  if ((r = m(/^\/assets\/(\d+)\/edit$/))) return <AssetForm id={+r[1]} />;
  if ((r = m(/^\/assets\/(\d+)$/))) return <AssetDetailPage id={+r[1]} />;
  if (p === "/hosts") return <HostsPage />;
  if ((r = m(/^\/hosts\/(\d+)$/))) return <HostDetailPage id={+r[1]} />;
  if (p === "/repositories") return <ReposPage />;
  if ((r = m(/^\/repositories\/(\d+)$/))) return <RepoDetailPage id={+r[1]} />;
  if (p === "/scans") return <ScansPage />;
  if ((r = m(/^\/scans\/(\d+)$/))) return <ScanDetailPage id={+r[1]} />;
  if (p === "/vulnerabilities") return <VulnsPage />;
  if ((r = m(/^\/vulnerabilities\/(\d+)$/))) return <FindingDetailPage id={+r[1]} />;
  if (p === "/settings") return <SettingsPage />;
  return <p>Page not found. <Link to="/">Go to the dashboard</Link>.</p>;
}

function App() {
  const path = usePath();
  const [user, setUser] = useState<string | null | undefined>(undefined);
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    setUnauthorisedHandler(() => setUser(null));
    get<{ username: string; csrf_token: string }>("/api/auth/me")
      .then((me) => { setCsrf(me.csrf_token); setUser(me.username); })
      .catch(() => setUser(null));
  }, []);
  useEffect(() => setMenu(false), [path]);

  if (user === undefined) return <main className="center"><Loading /></main>;
  if (user === null) return <Login onLogin={(u, t) => { setCsrf(t); setUser(u); }} />;

  const active = (href: string) => (href === "/" ? path.split("?")[0] === "/" : path.startsWith(href));
  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <aside className={menu ? "side open" : "side"}>
        <div className="brand">
          <span className="logo" aria-hidden="true">P</span> Patchy
          <button className="btn small menu-btn" aria-expanded={menu} aria-controls="nav" onClick={() => setMenu(!menu)}>Menu</button>
        </div>
        <nav id="nav" aria-label="Main">
          {NAV.map(([href, label]) => (
            <Link key={href} to={href} className={active(href) ? "active" : ""}>{label}</Link>
          ))}
        </nav>
        <div className="side-foot">
          <span className="muted small">Signed in as {user}</span>
          <button className="btn small" onClick={async () => {
            await post("/api/auth/logout").catch(() => {});
            setUser(null);
            navigate("/");
          }}>Sign out</button>
        </div>
      </aside>
      <main id="main" tabIndex={-1}>{route(path)}</main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
