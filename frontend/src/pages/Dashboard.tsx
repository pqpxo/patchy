import { useState } from "react";
import { get, post, type Feed } from "../api";
import { SEVERITIES } from "../format";
import { ErrorBox, Link, Loading, PageHead, Sev, Status, When, errText, useLoad } from "../ui";

interface Dash {
  severity: Record<string, number>; match_status: Record<string, number>; status: Record<string, number>;
  kev_open: number; top_assets: { id: number; name: string; version: string | null; location: string | null; open: number; max_severity: string }[];
  coverage: { total: number; not_checkable: number; version_unknown: number; not_checked_yet: number; checked: number };
  feeds: Feed[]; feed_stale: boolean; recent_scans: { id: number; kind: string; status: string; target: string | null; created_at: string; finished_at: string | null }[];
  hosts: number; repositories: number; demo_data: boolean;
}

export function FeedPanel({ feeds, onRefreshed }: { feeds: Feed[]; onRefreshed?: () => void }) {
  const [msg, setMsg] = useState("");
  return (
    <section className="card">
      <div className="card-head">
        <h2>Feed freshness</h2>
        <button className="btn small" onClick={async () => {
          try { await post("/api/feeds/refresh"); setMsg("Refresh queued. Progress shows on the Scans page."); onRefreshed?.(); }
          catch (e) { setMsg(errText(e)); }
        }}>Refresh now</button>
      </div>
      {msg && <p className="small" role="status">{msg}</p>}
      <table className="table compact">
        <thead><tr><th>Source</th><th>Last success</th><th>State</th></tr></thead>
        <tbody>
          {feeds.map((f) => (
            <tr key={f.source}>
              <td>{f.source.toUpperCase()}</td>
              <td>{f.enabled ? <When iso={f.last_success_at} /> : <span className="muted">disabled</span>}</td>
              <td>
                {!f.enabled ? <span className="badge tone-muted">off</span>
                  : f.last_error ? <span className="badge tone-bad" title={f.last_error}>error</span>
                  : f.stale ? <span className="badge tone-warn">stale</span>
                  : <span className="badge tone-good">fresh</span>}
                {f.enabled && f.last_error && <div className="small muted">{f.last_error}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export default function Dashboard() {
  const { data, error, reload } = useLoad(() => get<Dash>("/api/dashboard"), []);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Loading />;
  const c = data.coverage;
  const unknownOpen = data.match_status.unknown_version ?? 0;
  const empty = c.total === 0;
  return (
    <>
      <PageHead title="Dashboard" sub={`${c.total} assets across ${data.hosts} hosts and ${data.repositories} repositories`} />
      {data.demo_data && <div className="alert warn">Demo data is loaded. Items marked DEMO are fictional. Remove with <code>python -m app.cli clear-demo</code>.</div>}
      {data.feed_stale && (
        <div className="alert warn" role="status">
          Vulnerability data is stale or has never been fetched. A low finding count here does <strong>not</strong> mean you are safe.
          Refresh feeds below or check Settings.
        </div>
      )}
      {empty && (
        <div className="card">
          <h2>Get started</h2>
          <ol className="steps">
            <li><Link to="/assets/new">Add an asset manually</Link></li>
            <li><Link to="/repositories">Scan a GitHub repository</Link></li>
            <li><Link to="/hosts">Enrol a Linux host agent</Link></li>
          </ol>
        </div>
      )}
      <section className="grid sev-grid" aria-label="Open findings by severity">
        {SEVERITIES.filter((s) => s !== "none").map((s) => (
          <Link key={s} to={`/vulnerabilities?severity=${s}&status=open`} className={`stat sev-card-${s}`}>
            <span className="stat-n">{data.severity[s] ?? 0}</span><span>{s}</span>
          </Link>
        ))}
        <Link to="/vulnerabilities?kev=true&status=open" className="stat kev-card">
          <span className="stat-n">{data.kev_open}</span><span>known exploited</span>
        </Link>
      </section>
      <p className="muted small">Counts are open and acknowledged findings with confirmed or possible matches.
        {unknownOpen > 0 && <> A further <Link to="/vulnerabilities?match_status=unknown_version">{unknownOpen} need a version</Link> to confirm.</>}</p>

      <div className="grid two">
        <section className="card">
          <h2>Most affected assets</h2>
          {data.top_assets.length === 0 ? <p className="muted">No open confirmed or possible findings.</p> : (
            <table className="table compact">
              <thead><tr><th>Asset</th><th>Location</th><th>Worst</th><th>Open</th></tr></thead>
              <tbody>{data.top_assets.map((a) => (
                <tr key={a.id}><td><Link to={`/assets/${a.id}`}>{a.name}</Link> <span className="muted">{a.version}</span></td>
                  <td>{a.location ?? "-"}</td><td><Sev s={a.max_severity} /></td><td>{a.open}</td></tr>
              ))}</tbody>
            </table>
          )}
        </section>
        <section className="card">
          <h2>Check coverage</h2>
          <p className="muted small">How much of your inventory Patchy can actually assess.</p>
          <ul className="bars">
            {([["Checked against feeds", c.checked, "good"], ["Waiting for first check", c.not_checked_yet, "warn"],
              ["Version unknown", c.version_unknown, "warn"], ["No vulnerability source", c.not_checkable, "muted"]] as const).map(([l, n, tone]) => (
              <li key={l}><span>{l}</span><span className={`bar tone-${tone}`} style={{ width: `${c.total ? (n / c.total) * 100 : 0}%` }} /><b>{n}</b></li>
            ))}
          </ul>
        </section>
        <FeedPanel feeds={data.feeds} onRefreshed={reload} />
        <section className="card">
          <h2>Recent scans</h2>
          {data.recent_scans.length === 0 ? <p className="muted">No scans yet.</p> : (
            <table className="table compact">
              <tbody>{data.recent_scans.map((s) => (
                <tr key={s.id}><td><Link to={`/scans/${s.id}`}>#{s.id}</Link> {s.kind}</td><td>{s.target}</td>
                  <td><Status s={s.status} /></td><td><When iso={s.finished_at ?? s.created_at} /></td></tr>
              ))}</tbody>
            </table>
          )}
        </section>
      </div>
    </>
  );
}
