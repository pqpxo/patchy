import type { ReactNode } from "react";
import { get, type Asset, type Page, type ScanRun } from "../api";
import { Empty, ErrorBox, KV, Link, Loading, PageHead, Pager, Status, When, useLoad, useQueryParam } from "../ui";
import { AssetTable } from "./Assets";

const active = (r: ScanRun) => r.status === "queued" || r.status === "running";

export function RunSummary({ run }: { run: ScanRun }) {
  const s = run.summary ?? {};
  return (
    <>
      <KV rows={[
        ["Status", <><Status s={run.status} /> {active(run) && <span className="muted small" role="status">{run.progress}</span>}</>],
        ["Started", <When iso={run.started_at} />], ["Finished", <When iso={run.finished_at} />],
        ["Revision", run.revision ? <code>{run.revision}</code> : null],
        ...(s.components !== undefined ? [["Components", s.components] as [string, unknown]] : []),
        ...(s.packages !== undefined ? [["Packages", s.packages] as [string, unknown]] : []),
      ] as [string, ReactNode][]} />
      {run.error && <div className="alert bad">{run.error}</div>}
      {run.status === "partial" && <div className="alert warn">Partial result: some items were skipped or failed. Details below.</div>}
      {Array.isArray(s.manifests) && s.manifests.length > 0 && (
        <details open><summary>Manifests parsed ({s.manifests.length})</summary>
          <ul className="paths">{s.manifests.map((m: { path: string; components: number }) => <li key={m.path}><code>{m.path}</code> <span className="muted small">{m.components} entries</span></li>)}</ul>
        </details>
      )}
      {Array.isArray(s.skipped) && s.skipped.length > 0 && (
        <details><summary>Skipped ({s.skipped.length})</summary>
          <ul className="paths">{s.skipped.map((m: { path: string; reason: string }, i: number) => <li key={i}><code>{m.path}</code> <span className="muted small">{m.reason}</span></li>)}</ul>
        </details>
      )}
      {s.tree_truncated && <p className="small">GitHub truncated the file listing for this very large repository; some manifests may be missing.</p>}
      {Array.isArray(s.agent_errors) && s.agent_errors.length > 0 && (
        <details open><summary>Agent notes ({s.agent_errors.length})</summary><ul>{s.agent_errors.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul></details>
      )}
      {s.unmapped_os && <p className="small">Packages were collected, but this OS has no supported vulnerability feed mapping, so they are inventory only.</p>}
      {s.failed_sources?.length > 0 && <div className="alert warn">Failed sources: {s.failed_sources.join(", ")}. See Settings for details.</div>}
      {s.osv && <p className="small muted">OSV: {s.osv.queries} queries, {s.osv.advisories_fetched} advisories fetched
        {s.osv.not_fetched_over_cap > 0 && `, ${s.osv.not_fetched_over_cap} deferred to the next refresh (cap)`}.</p>}
    </>
  );
}

export function ScansPage() {
  const [kind, setKind] = useQueryParam("kind");
  const [page, setPage] = useQueryParam("page");
  const { data, error, loading, reload } = useLoad(() => get<Page<ScanRun>>("/api/scans", { kind, page: page || 1 }),
    [kind, page], (d) => (d?.items.some(active) ? 3000 : null));
  return (
    <>
      <PageHead title="Scans" sub="Repository scans, agent reports and feed refreshes."
        actions={<select aria-label="Kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All kinds</option><option value="repo">Repository</option><option value="agent">Agent report</option><option value="feed">Feed refresh</option>
        </select>} />
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? <Empty title="No scans yet." /> : (
        <>
          <div className="table-wrap"><table className="table">
            <thead><tr><th>#</th><th>Kind</th><th>Target</th><th>Status</th><th>Progress</th><th>Queued</th><th>Finished</th></tr></thead>
            <tbody>{data.items.map((r) => (
              <tr key={r.id}>
                <td><Link to={`/scans/${r.id}`}>{r.id}</Link></td>
                <td>{r.kind}{r.params?.mode === "pending" && <span className="muted small"> (new items)</span>}</td>
                <td>{r.target_label ?? "-"}</td><td><Status s={r.status} /></td>
                <td className="small">{r.error ?? r.progress}</td><td><When iso={r.created_at} /></td><td><When iso={r.finished_at} /></td>
              </tr>
            ))}</tbody>
          </table></div>
          <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
        </>
      ))}
    </>
  );
}

export function ScanDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<{ run: ScanRun; components: Asset[] }>(`/api/scans/${id}`), [id],
    (d) => (d && active(d.run) ? 2000 : null));
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Loading />;
  const r = data.run;
  return (
    <>
      <PageHead title={`Scan #${r.id}`} sub={`${r.kind} · ${r.target_label ?? ""}`} />
      <section className="card">
        {r.repository_id && <p><Link to={`/repositories/${r.repository_id}`}>Open repository</Link></p>}
        {r.host_id && <p><Link to={`/hosts/${r.host_id}`}>Open host</Link></p>}
        <RunSummary run={r} />
      </section>
      {r.kind !== "feed" && (
        <section className="card">
          <h2>Components seen in this scan{data.components.length === 500 ? " (first 500)" : ""}</h2>
          {data.components.length ? <AssetTable items={data.components} /> : <p className="muted">None recorded.</p>}
        </section>
      )}
    </>
  );
}
