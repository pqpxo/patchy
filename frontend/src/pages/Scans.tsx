import type { ReactNode } from "react";
import { get, type Asset, type Page, type ScanRun } from "../api";
import { usePrefs } from "../prefs";
import { AssetTable } from "../tables";
import { DataTable, Empty, ErrorBox, KV, Link, PageHead, Pager, Skeleton, Status, When, useLoad, useQueryParam, type Col } from "../ui";

const active = (r: ScanRun) => r.status === "queued" || r.status === "running";
const LABELS: Record<string, string> = { osv: "OSV", kev: "CISA KEV", nvd: "NVD severity", nvd_cpe: "NVD products", eol: "End of life",
  epss: "EPSS", dependabot: "Dependabot", match: "Matching" };

const fmt = (v: unknown): string => Array.isArray(v) ? `${v.length}` : typeof v === "object" && v ? JSON.stringify(v) : String(v);

export function RunSummary({ run }: { run: ScanRun }) {
  const s = run.summary ?? {};
  const feedParts = run.kind === "feed" ? Object.entries(s).filter(([k, v]) => LABELS[k] && v && typeof v === "object") : [];
  return (
    <>
      <KV rows={[
        ["Status", <><Status s={run.status} /> {active(run) && <span className="muted small" role="status">{run.progress}</span>}</>],
        ["Started", <When iso={run.started_at} />], ["Finished", <When iso={run.finished_at} />],
        ["Revision", run.revision ? <code>{run.revision}</code> : null],
        ...(s.components !== undefined ? [["Components", s.components] as [string, unknown]] : []),
        ...(s.packages !== undefined ? [["Packages", s.packages] as [string, unknown]] : []),
        ...(Array.isArray(s.sources) ? [["Sources", s.sources.map((x: string) => LABELS[x] ?? x).join(", ")] as [string, unknown]] : []),
      ] as [string, ReactNode][]} />
      {run.error && <div className="alert bad">{run.error}</div>}
      {run.status === "partial" && <div className="alert warn">Partial result: some items were skipped or failed. Details below.</div>}
      {feedParts.length > 0 && (
        <div className="table-wrap"><table className="table compact"><thead><tr><th>Source</th><th>Result</th></tr></thead>
          <tbody>{feedParts.map(([k, v]) => (
            <tr key={k}><td>{LABELS[k]}</td><td className="small">{Object.entries(v as Record<string, unknown>)
              .filter(([, x]) => x !== null && x !== undefined && typeof x !== "object").map(([a, x]) => `${a.replace(/_/g, " ")}: ${fmt(x)}`).join(" · ")}</td></tr>
          ))}</tbody></table></div>
      )}
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
      {s.failed_sources?.length > 0 && <div className="alert warn">Failed sources: {s.failed_sources.map((x: string) => LABELS[x] ?? x).join(", ")}. See <Link to="/settings?tab=sources">Settings, Sources</Link>.</div>}
    </>
  );
}

const cols: Col<ScanRun>[] = [
  { id: "id", label: "#", fixed: true, cell: (r) => <Link to={`/scans/${r.id}`}>{r.id}</Link> },
  { id: "kind", label: "Kind", cell: (r) => <>{r.kind}{r.params?.mode === "pending" && <span className="cell-sub"> (new items)</span>}
    {Array.isArray(r.params?.only) && <span className="cell-sub"> ({r.params!.only.map((x: string) => LABELS[x] ?? x).join(", ")})</span>}</> },
  { id: "target", label: "Target", cell: (r) => r.target_label ?? <span className="muted">-</span> },
  { id: "status", label: "Status", fixed: true, cell: (r) => <Status s={r.status} /> },
  { id: "progress", label: "Progress", cell: (r) => <span className="small">{r.error ?? r.progress}</span> },
  { id: "queued", label: "Queued", cell: (r) => <When iso={r.created_at} /> },
  { id: "finished", label: "Finished", cell: (r) => <When iso={r.finished_at} /> },
];

export function ScansPage() {
  const [kind, setKind] = useQueryParam("kind");
  const [status, setStatus] = useQueryParam("status");
  const [page, setPage] = useQueryParam("page");
  const { pageSize } = usePrefs();
  const { data, error, loading, reload } = useLoad(() => get<Page<ScanRun>>("/api/scans", { kind, status, page: page || 1, page_size: pageSize }),
    [kind, status, page, pageSize], (d) => (d?.items.some(active) ? 3000 : null));
  return (
    <>
      <PageHead title="Scans" sub="Repository scans, agent reports and feed refreshes, newest first." />
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Skeleton /> : data && <>
        <DataTable table="scans" cols={cols} rows={data.items} rowKey={(r) => r.id} tools={<>
          <select aria-label="Kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All kinds</option><option value="repo">Repository</option><option value="agent">Agent report</option><option value="feed">Feed refresh</option>
          </select>
          <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any status</option><option value="queued">Queued</option><option value="running">Running</option>
            <option value="succeeded">Succeeded</option><option value="partial">Partial</option><option value="failed">Failed</option>
          </select>
        </>} />
        {data.items.length === 0 && <Empty title="No scans match." />}
        <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
      </>}
    </>
  );
}

export function ScanDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<{ run: ScanRun; components: Asset[] }>(`/api/scans/${id}`), [id],
    (d) => (d && active(d.run) ? 2000 : null));
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton />;
  const r = data.run;
  return (
    <>
      <PageHead title={`Scan #${r.id}`} crumbs={[["Scans", "/scans"]]} sub={`${r.kind}${r.target_label ? ` · ${r.target_label}` : ""}`}
        actions={<>
          {r.repository_id && <Link className="btn" to={`/repositories/${r.repository_id}`}>Open repository</Link>}
          {r.host_id && <Link className="btn" to={`/hosts/${r.host_id}`}>Open host</Link>}
        </>} />
      <section className="card"><RunSummary run={r} /></section>
      {r.kind !== "feed" && (
        <section className="card">
          <h2>Components seen in this scan{data.components.length === 500 ? " (first 500)" : ""}</h2>
          {data.components.length ? <AssetTable items={data.components} table="scan-assets" /> : <p className="muted">None recorded.</p>}
        </section>
      )}
    </>
  );
}
