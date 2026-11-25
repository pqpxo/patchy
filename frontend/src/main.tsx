import { StrictMode, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { get, post, put, setCsrf, setUnauthorisedHandler, type Host, type Page, type Repo } from "./api";
import { Icon } from "./icons";
import { resolvedMode, setPrefs, usePrefs } from "./prefs";
import { Link, Skeleton, Toaster, errText, navigate, toast, usePath } from "./ui";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import { AssetDetailPage, AssetForm, AssetsPage } from "./pages/Assets";
import { HostDetailPage, HostsPage } from "./pages/Hosts";
import { RepoDetailPage, ReposPage } from "./pages/Repos";
import { ScanDetailPage, ScansPage } from "./pages/Scans";
import { FindingDetailPage, VulnsPage } from "./pages/Vulns";
import { FixPage } from "./pages/Fix";
import SettingsPage from "./pages/Settings";
import "./styles.css";

type Counts = { assets: number; hosts: number; repositories: number; findings: number; critical: number };

const NAV: { to: string; label: string; icon: string; count?: keyof Counts }[][] = [
  [{ to: "/", label: "Overview", icon: "dashboard" }],
  [{ to: "/assets", label: "Assets", icon: "assets", count: "assets" },
    { to: "/hosts", label: "Hosts", icon: "hosts", count: "hosts" },
    { to: "/repositories", label: "Repositories", icon: "repos", count: "repositories" }],
  [{ to: "/vulnerabilities", label: "Vulnerabilities", icon: "vulns", count: "findings" },
    { to: "/fix", label: "Fixes", icon: "fix" },
    { to: "/scans", label: "Scans", icon: "scans" }],
  [{ to: "/settings", label: "Settings", icon: "settings" }],
];

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
  if (p === "/fix") return <FixPage />;
  if (p === "/settings") return <SettingsPage />;
  return <p>Page not found. <Link to="/">Go to the overview</Link>.</p>;
}

// Ctrl+K / Cmd+K: jump to any page, host or repository, or search assets and findings.
function Palette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [targets, setTargets] = useState<{ label: string; to: string; kind: string }[]>([]);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    input.current?.focus();
    Promise.all([get<Page<Host>>("/api/hosts", { page_size: 200 }), get<Page<Repo>>("/api/repositories", { page_size: 200 })])
      .then(([h, r]) => setTargets([
        ...h.items.map((x) => ({ label: x.name, to: `/hosts/${x.id}`, kind: "Host" })),
        ...r.items.map((x) => ({ label: `${x.owner}/${x.name}`, to: `/repositories/${x.id}`, kind: "Repository" })),
      ])).catch(() => {});
  }, []);
  const items = useMemo(() => {
    const pages = [
      ...NAV.flat().map((n) => ({ label: n.label, to: n.to, kind: "Page" })),
      { label: "Add an asset", to: "/assets/new", kind: "Action" },
      { label: "Appearance and themes", to: "/settings?tab=appearance", kind: "Settings" },
      { label: "Sources and schedule", to: "/settings?tab=sources", kind: "Settings" },
      { label: "Accepted risk rules", to: "/settings?tab=risks", kind: "Settings" },
      { label: "Version and changelog", to: "/settings?tab=about", kind: "Settings" },
      { label: "Known exploited findings", to: "/vulnerabilities?kev=true", kind: "Filter" },
      { label: "Overdue findings", to: "/vulnerabilities?overdue=true", kind: "Filter" },
      { label: "Fix-by deadlines", to: "/settings?tab=deadlines", kind: "Settings" },
      { label: "End-of-life assets", to: "/assets?eol_state=eol", kind: "Filter" },
    ];
    const t = q.trim().toLowerCase();
    const found = [...pages, ...targets].filter((i) => !t || i.label.toLowerCase().includes(t)).slice(0, 12);
    if (t) {
      const v = encodeURIComponent(q.trim());
      found.push({ label: `Search assets for "${q.trim()}"`, to: `/assets?q=${v}`, kind: "Search" },
        { label: `Search findings for "${q.trim()}"`, to: `/vulnerabilities?q=${v}`, kind: "Search" });
    }
    return found;
  }, [q, targets]);
  const go = (to: string) => { onClose(); navigate(to); };
  return (
    <div className="palette-back" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Quick search">
        <div className="palette-in">
          <Icon name="search" />
          <input ref={input} value={q} placeholder="Go to a page, host or repository…" aria-label="Search"
            role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={`pi-${sel}`}
            onChange={(e) => { setQ(e.target.value); setSel(0); }}
            onKeyDown={(e) => {
              if (e.key === "Escape") onClose();
              else if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(items.length - 1, s + 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
              else if (e.key === "Enter" && items[sel]) go(items[sel].to);
            }} />
        </div>
        <ul id="palette-list" role="listbox">
          {items.map((i, n) => (
            <li key={i.kind + i.to + i.label}>
              <button id={`pi-${n}`} role="option" aria-selected={n === sel} onMouseEnter={() => setSel(n)} onClick={() => go(i.to)}>
                {i.label}<span className="kind">{i.kind}</span>
              </button>
            </li>
          ))}
          {items.length === 0 && <li className="muted small palette-none">Nothing matches.</li>}
        </ul>
        <div className="hint"><span><kbd>↑</kbd> <kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div>
      </div>
    </div>
  );
}

function App() {
  const path = usePath();
  const prefs = usePrefs();
  const [user, setUser] = useState<string | null | undefined>(undefined);
  const [menu, setMenu] = useState(false);
  const [palette, setPalette] = useState(false);
  const [counts, setCounts] = useState<Counts>();
  const [alertsPaused, setAlertsPaused] = useState(false);

  useEffect(() => {
    setUnauthorisedHandler(() => setUser(null));
    get<{ username: string; csrf_token: string }>("/api/auth/me")
      .then((me) => { setCsrf(me.csrf_token); setUser(me.username); })
      .catch(() => setUser(null));
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
      if (e.key === "Escape") setMenu(false);
    };
    // Close open dropdown menus (<details class="menu">) on outside click.
    const click = (e: MouseEvent) => document.querySelectorAll("details.menu[open]").forEach((d) => {
      if (!d.contains(e.target as Node)) d.removeAttribute("open");
    });
    window.addEventListener("keydown", key);
    document.addEventListener("click", click);
    return () => { window.removeEventListener("keydown", key); document.removeEventListener("click", click); };
  }, []);
  useEffect(() => setMenu(false), [path]);
  // Sidebar counts: refreshed on navigation, at most every 20 seconds.
  const last = useRef(0);
  useEffect(() => {
    if (!user || Date.now() - last.current < 20000) return;
    last.current = Date.now();
    get<{ severity: Record<string, number>; coverage: { total: number }; hosts: number; repositories: number; alerts_paused?: boolean }>("/api/dashboard")
      .then((d) => {
        setCounts({
          assets: d.coverage.total, hosts: d.hosts, repositories: d.repositories, critical: d.severity.critical ?? 0,
          findings: Object.values(d.severity).reduce((a, b) => a + b, 0),
        });
        setAlertsPaused(!!d.alerts_paused);
      }).catch(() => {});
  }, [user, path]);

  if (user === undefined) return <main className="center"><div style={{ width: 320 }}><Skeleton rows={3} /></div></main>;
  if (user === null) return <Login onLogin={(u, t) => { setCsrf(t); setUser(u); last.current = 0; }} />;

  const here = path.split("?")[0];
  const active = (href: string) => (href === "/" ? here === "/" : here === href || here.startsWith(href + "/"));
  const night = resolvedMode(prefs) === "night";
  return (
    <div className={prefs.rail ? "shell rail" : "shell"}>
      <a className="skip" href="#main">Skip to content</a>
      <div className="topbar">
        <button className="icon-btn" aria-label="Open menu" aria-expanded={menu} aria-controls="side" onClick={() => setMenu(true)}><Icon name="menu" size={20} /></button>
        <img className="logo" src="/logo.png" alt="" /><span className="grow">Patchy</span>
        <button className="icon-btn" aria-label="Quick search" onClick={() => setPalette(true)}><Icon name="search" size={18} /></button>
      </div>
      {menu && <div className="backdrop" onClick={() => setMenu(false)} />}
      <aside id="side" className={menu ? "side open" : "side"}>
        <div className="brand"><img className="logo" src="/logo.png" alt="" /><span>Patchy</span></div>
        <button className="search-btn" onClick={() => setPalette(true)} title="Quick search (Ctrl+K)">
          <Icon name="search" size={15} /><span className="label">Search</span><kbd>Ctrl K</kbd>
        </button>
        <nav aria-label="Main">
          {NAV.map((group, i) => (
            <div key={i}>
              {i > 0 && <div className="nav-sep" />}
              {group.map((n) => {
                const c = n.count && counts ? counts[n.count] : undefined;
                return (
                  <Link key={n.to} to={n.to} className={active(n.to) ? "nav-item on" : "nav-item"} title={n.label}>
                    <Icon name={n.icon} /><span className="label">{n.label}</span>
                    {c !== undefined && <span className={n.count === "findings" && counts!.critical ? "count hot" : "count"}>{c}</span>}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="side-foot">
          <div className="row">
            <button className="icon-btn" title={night ? "Switch to day" : "Switch to night"} aria-label={night ? "Switch to day mode" : "Switch to night mode"}
              onClick={() => setPrefs({ mode: night ? "day" : "night" })}><Icon name={night ? "sun" : "moon"} /></button>
            <button className={alertsPaused ? "icon-btn off" : "icon-btn"} aria-pressed={alertsPaused}
              title={alertsPaused ? "Alerts paused. Click to resume" : "Pause alerts"} aria-label="Pause alerts"
              onClick={async () => {
                try {
                  await put("/api/settings/alerts", { paused: !alertsPaused });
                  setAlertsPaused(!alertsPaused);
                  toast(alertsPaused ? "Alerts resumed." : "Alerts paused. Anything found meanwhile won't be sent later.");
                } catch (e) { toast(errText(e), "bad"); }
              }}><Icon name={alertsPaused ? "bell-off" : "bell"} /></button>
            <button className="icon-btn rail-toggle" title={prefs.rail ? "Expand sidebar" : "Collapse sidebar"} aria-label="Toggle sidebar width"
              onClick={() => setPrefs({ rail: !prefs.rail })}><Icon name="rail" /></button>
            <button className="icon-btn" title="Sign out" aria-label="Sign out" onClick={async () => {
              await post("/api/auth/logout").catch(() => {});
              setUser(null);
              navigate("/");
            }}><Icon name="out" /></button>
          </div>
        </div>
      </aside>
      <main id="main" tabIndex={-1}>{route(path)}</main>
      {palette && <Palette onClose={() => setPalette(false)} />}
      <Toaster />
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
