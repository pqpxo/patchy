import { get, type Feed, type Finding, type Page } from "../api";
import { Icon } from "../icons";
import { Epss, ErrorBox, Kev, Link, PageHead, Sev, Skeleton, Status, When, useLoad } from "../ui";

interface Dash {
  severity: Record<string, number>; match_status: Record<string, number>; status: Record<string, number>;
  kev_open: number; top_assets: { id: number; name: string; version: string | null; location: string | null; open: number; max_severity: string }[];
  coverage: { total: number; not_checkable: number; version_unknown: number; not_checked_yet: number; checked: number };
  end_of_life: { eol: number; eol_soon: number; hosts_eol: number; hosts_eol_soon: number };
  feeds: Feed[]; feed_stale: boolean; recent_scans: { id: number; kind: string; status: string; target: string | null; created_at: string; finished_at: string | null }[];
  hosts: number; repositories: number; demo_data: boolean;
}

const LEVELS = ["critical", "high", "medium", "low"] as const;

function ExposureStrip({ d }: { d: Dash }) {
  const total = LEVELS.reduce((a, s) => a + (d.severity[s] ?? 0), 0);
  const unknownOpen = d.match_status.unknown_version ?? 0;
  return (
    <section className="card strip" aria-label="Open findings by severity">
      <div className="card-head"><h2>Open exposure</h2><span className="small muted">confirmed and possible matches</span></div>
      <div className={total ? "strip-bar" : "strip-bar clear"} aria-hidden="true">
        {LEVELS.map((s) => (d.severity[s] ?? 0) > 0 && <i key={s} className={`seg seg-${s}`} style={{ flexGrow: d.severity[s] }} />)}
      </div>
      <div className="strip-legend">
        {LEVELS.map((s) => (
          <Link key={s} to={`/vulnerabilities?severity=${s}&status=open`} className={d.severity[s] ? "" : "zero"}>
            <span className="n">{d.severity[s] ?? 0}</span><span className="l"><i className={`seg-${s}`} />{s}</span>
          </Link>
        ))}
        <Link to="/vulnerabilities?kev=true&status=open" className={d.kev_open ? "kev-n" : "zero"}>
          <span className="n">{d.kev_open}</span><span className="l">known exploited</span>
        </Link>
      </div>
      {unknownOpen > 0 && <p className="small muted">A further <Link to="/vulnerabilities?match_status=unknown_version">{unknownOpen} need a version</Link> before Patchy can confirm them.</p>}
    </section>
  );
}

function FixFirst() {
  const { data } = useLoad(() => get<Page<Finding>>("/api/findings", { sort: "priority", order: "desc", page_size: 8, status: ["open", "acknowledged"] }), []);
  return (
    <section className="card">
      <div className="card-head">
        <h2>Fix first</h2>
        <span className="actions small"><Link to="/fix">Fix plan</Link><Link to="/vulnerabilities">All findings</Link></span>
      </div>
      {!data ? <Skeleton rows={4} /> : data.items.length === 0 ? <p className="muted">Nothing open. Keep feeds fresh so this stays true.</p> : (
        <ol className="queue">{data.items.map((f, n) => (
          <li key={f.id}>
            <span className="rank">{n + 1}</span>
            <div className="what">
              <div className="top"><Sev s={f.advisory.severity} /><Link to={`/vulnerabilities/${f.id}`}>{f.advisory.id}</Link><Kev on={f.advisory.kev} /></div>
              <span className="small"><Link to={`/assets/${f.component_id}`}>{f.component_name}</Link> <span className="ver muted">{f.component_version}</span>
                {(f.host_name || f.repository_label) && <span className="muted"> on {f.host_name ?? f.repository_label}</span>}</span>
              <span className="fix">{f.fixed_versions.length ? <>Upgrade to <b>{f.fixed_versions[0]}</b></> : "No fixed version published"}
                {f.match_status === "possible" && " · possible match"}</span>
            </div>
            <div className="why"><Epss v={f.advisory.epss} p={f.advisory.epss_percentile} /></div>
          </li>
        ))}</ol>
      )}
    </section>
  );
}

export default function Dashboard() {
  const { data, error, reload } = useLoad(() => get<Dash>("/api/dashboard"), []);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton rows={8} />;
  const c = data.coverage, e = data.end_of_life;
  const share = (n: number) => `${c.total ? Math.max(n ? 2 : 0, (n / c.total) * 100) : 0}%`;
  const feedState = (f: Feed) => !f.enabled ? ["", "off"] : f.last_error ? ["bad", "error"] : f.stale ? ["warn", "stale"] : ["good", "fresh"];
  return (
    <>
      <PageHead title="Overview" sub={`${c.total} assets across ${data.hosts} hosts and ${data.repositories} repositories`} />
      {data.demo_data && <div className="alert warn">Demo data is loaded. Items marked DEMO are fictional. Remove with <code>python -m app.cli clear-demo</code>.</div>}
      {data.feed_stale && (
        <div className="alert warn" role="status">
          Vulnerability data is stale or has never been fetched. A low count here does <strong>not</strong> mean you are safe.{" "}
          <Link to="/settings?tab=sources">Check sources</Link>
        </div>
      )}
      {c.total === 0 && (
        <section className="card">
          <h2>Get started</h2>
          <ol>
            <li><Link to="/assets/new">Add an asset manually</Link></li>
            <li><Link to="/repositories">Scan a GitHub repository</Link></li>
            <li><Link to="/hosts">Enrol a Linux host agent</Link></li>
          </ol>
        </section>
      )}
      <ExposureStrip d={data} />
      <div className="grid dash">
        <div className="stack">
          <FixFirst />
          <section className="card">
            <div className="card-head"><h2>Most affected assets</h2><Link to="/assets?vulnerable=1&sort=severity&order=desc" className="small">All</Link></div>
            {data.top_assets.length === 0 ? <p className="muted">No open confirmed or possible findings.</p> : (
              <div className="table-wrap"><table className="table compact">
                <thead><tr><th>Asset</th><th>Location</th><th>Worst</th><th className="r">Open</th></tr></thead>
                <tbody>{data.top_assets.map((a) => (
                  <tr key={a.id}><td><Link to={`/assets/${a.id}`}>{a.name}</Link> <span className="ver muted">{a.version}</span></td>
                    <td>{a.location ?? <span className="muted">-</span>}</td><td><Sev s={a.max_severity} /></td><td className="r num">{a.open}</td></tr>
                ))}</tbody>
              </table></div>
            )}
          </section>
        </div>
        <div className="stack">
          <section className="card">
            <div className="card-head"><h2>End of life</h2><Link to="/fix" className="small">Upgrade advice</Link></div>
            <ul className="meter-list">
              <li><Link to="/assets?eol_state=eol">Components out of support</Link><b className={e.eol ? "sev-critical" : "muted"}>{e.eol}</b></li>
              <li><Link to="/assets?eol_state=eol_soon">Leaving support within 90 days</Link><b>{e.eol_soon}</b></li>
              <li><Link to="/hosts?sort=eol&order=desc">Hosts on an unsupported OS</Link><b className={e.hosts_eol ? "sev-critical" : "muted"}>{e.hosts_eol}</b></li>
            </ul>
          </section>
          <section className="card">
            <h2>Check coverage</h2>
            <ul className="meter-list">
              {([["Checked against a source", c.checked, "good"], ["Waiting for first check", c.not_checked_yet, "warn"],
                ["Version unknown", c.version_unknown, "warn"], ["No vulnerability source", c.not_checkable, ""]] as const).map(([l, n, tone]) => (
                <li key={l} className={tone}><span>{l}</span><b>{n}</b><span className="track"><i style={{ width: share(n) }} /></span></li>
              ))}
            </ul>
          </section>
          <section className="card">
            <div className="card-head"><h2>Sources</h2><Link to="/settings?tab=sources" className="small">Schedule</Link></div>
            <ul className="meter-list">{data.feeds.map((f) => {
              const [tone, word] = feedState(f);
              return (
                <li key={f.source}><span><span className={`dot ${tone}`} /> {f.label || f.source}</span>
                  <span className="small muted" title={f.last_error ?? undefined}>{f.enabled ? <>{word}, <When iso={f.last_success_at} /></> : "off"}</span></li>
              );
            })}</ul>
          </section>
          <section className="card">
            <div className="card-head"><h2>Recent activity</h2><Link to="/scans" className="small">All scans</Link></div>
            {data.recent_scans.length === 0 ? <p className="muted">No scans yet.</p> : (
              <ul className="activity">{data.recent_scans.map((s) => (
                <li key={s.id}><span className="what"><Link to={`/scans/${s.id}`}>#{s.id}</Link> {s.target ?? s.kind}</span>
                  <span className="when"><When iso={s.finished_at ?? s.created_at} /></span><Status s={s.status} /></li>
              ))}</ul>
            )}
          </section>
          <p className="small muted"><Icon name="search" size={12} /> Press <kbd>Ctrl</kbd> <kbd>K</kbd> to jump anywhere.</p>
        </div>
      </div>
    </>
  );
}
