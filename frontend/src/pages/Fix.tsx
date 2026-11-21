import { get, type FixItem, type FixPlan as Plan, type Host, type Page, type Repo } from "../api";
import { Icon } from "../icons";
import { safeUrl } from "../format";
import { CodeBlock, Empty, Epss, ErrorBox, Kev, Link, PageHead, Sev, Skeleton, useLoad, useQueryParam } from "../ui";

function Upgrade({ i }: { i: FixItem }) {
  return (
    <span className="upgrade">
      {i.current ?? "?"}<span className="arrow" aria-label="upgrade to">→</span><span className="to">{i.target ?? "no fix yet"}</span>
    </span>
  );
}

function Items({ items, fixed = true }: { items: FixItem[]; fixed?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table compact">
        <thead><tr><th>Component</th><th>{fixed ? "Upgrade" : "Installed"}</th><th>Worst</th><th>EPSS</th><th>{fixed ? "Fixes" : "Unfixed advisories"}</th></tr></thead>
        <tbody>{items.map((i) => (
          <tr key={`${i.component_id}-${fixed}`}>
            <td><Link to={`/assets/${i.component_id}`}>{i.name}</Link> <Kev on={i.kev} />
              {i.package !== i.name && <div className="cell-sub">package {i.package}</div>}
              {i.possible_only && <div className="cell-sub">possible matches only: confirm first</div>}</td>
            <td>{fixed ? <Upgrade i={i} /> : <span className="ver">{i.current ?? "?"}</span>}</td>
            <td><Sev s={i.worst} /></td>
            <td><Epss v={i.epss} /></td>
            <td className="small">{fixed ? `${i.findings} finding${i.findings === 1 ? "" : "s"}` : i.unfixed.join(", ")}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function FixPlan({ hostId, repositoryId }: { hostId?: number; repositoryId?: number }) {
  const { data: p, error, reload } = useLoad(() => get<Plan>("/api/fix-plan", { host_id: hostId, repository_id: repositoryId }), [hostId, repositoryId]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!p) return <Skeleton rows={5} />;
  const s = p.summary;
  if (!s.components && !s.end_of_life) {
    return <Empty title="Nothing to fix.">No open findings with a confirmed or possible match, and nothing out of support.</Empty>;
  }
  return (
    <div className="plan">
      <div className="plan-summary card">
        <div><b>{s.upgrade_steps}</b><span>upgrade steps</span></div>
        <div><b>{s.components}</b><span>components affected</span></div>
        <div><b>{s.findings}</b><span>findings</span></div>
        <div><b>{s.no_fix}</b><span>without a published fix</span></div>
        <div><b>{s.end_of_life}</b><span>end of life</span></div>
      </div>
      {p.groups.map((g, n) => (
        <section key={g.title} className="step">
          <div className="step-head">
            <span className="step-n">Step {n + 1}</span>
            <h3>{g.title}</h3>
            <Sev s={g.worst} /><Kev on={g.kev} />
            <span className="grow" />
            {g.host_id && !hostId && <Link to={`/hosts/${g.host_id}`} className="small">Open host</Link>}
            {g.repository_id && !repositoryId && <Link to={`/repositories/${g.repository_id}`} className="small">Open repository</Link>}
          </div>
          <div className="step-body">
            {g.command && <CodeBlock code={g.command} />}
            {g.notes.map((x) => <p key={x} className="small muted">{x}</p>)}
          </div>
          <Items items={g.items} />
        </section>
      ))}
      {p.no_fix.length > 0 && (
        <section className="card">
          <h2>No published fix yet</h2>
          <p className="small muted">Watch these advisories, reduce exposure (firewall, disable the feature) or replace the component.</p>
          <Items items={p.no_fix} fixed={false} />
        </section>
      )}
      {p.end_of_life.length > 0 && (
        <section className="card">
          <h2>End of life</h2>
          <ul className="queue">{p.end_of_life.map((e) => {
            const link = safeUrl(e.link);
            return (
              <li key={`${e.name}-${e.component_id ?? e.host_id}`}>
                <span className="rank"><Icon name="clock" size={14} /></span>
                <div className="what">
                  <div className="top">
                    {e.component_id ? <Link to={`/assets/${e.component_id}`}>{e.name}</Link> : e.host_id ? <Link to={`/hosts/${e.host_id}`}>{e.name}</Link> : e.name}
                    <span className="ver muted">{e.version}</span>
                    <span className={e.state === "eol" ? "badge tone-bad" : "badge tone-warn"}>{e.state === "eol" ? "End of life" : "EOL soon"}</span>
                  </div>
                  <span className="small">{e.advice}</span>
                </div>
                <div className="why">{link && <a href={link} target="_blank" rel="noopener noreferrer" className="small">Dates <Icon name="external" size={12} /></a>}</div>
              </li>
            );
          })}</ul>
        </section>
      )}
      {p.notes.map((x) => <p key={x} className="small muted">{x}</p>)}
    </div>
  );
}

export function FixPage() {
  const [scope, setScope] = useQueryParam("scope");
  const hosts = useLoad(() => get<Page<Host>>("/api/hosts", { page_size: 200 }), []);
  const repos = useLoad(() => get<Page<Repo>>("/api/repositories", { page_size: 200 }), []);
  const [kind, id] = scope.split(":");
  return (
    <>
      <PageHead title="How to fix" sub="Open findings grouped into the fewest upgrade steps, worst first. Known exploited items lead."
        actions={
          <select aria-label="Scope" value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="">Everything</option>
            {hosts.data?.items.length ? <optgroup label="Hosts">{hosts.data.items.map((h) => <option key={h.id} value={`host:${h.id}`}>{h.name}</option>)}</optgroup> : null}
            {repos.data?.items.length ? <optgroup label="Repositories">{repos.data.items.map((r) => <option key={r.id} value={`repo:${r.id}`}>{r.owner}/{r.name}</option>)}</optgroup> : null}
          </select>
        } />
      <FixPlan hostId={kind === "host" ? +id : undefined} repositoryId={kind === "repo" ? +id : undefined} />
    </>
  );
}
