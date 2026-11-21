import { useState } from "react";
import { del, get, post, type Asset, type Page, type Repo, type ScanRun } from "../api";
import {
  DangerButton, Empty, ErrorBox, Field, KV, Link, Loading, PageHead, Pager, Status, When, errText, fieldErrors,
  navigate, useLoad, useQueryParam,
} from "../ui";
import { AssetTable } from "./Assets";
import { RunSummary } from "./Scans";

const running = (s?: string | null) => s === "queued" || s === "running";

export function ReposPage() {
  const [page, setPage] = useQueryParam("page");
  const { data, error, loading, reload } = useLoad(() => get<Page<Repo>>("/api/repositories", { page: page || 1 }), [page],
    (d) => (d?.items.some((r) => running(r.last_scan_status)) ? 3000 : null));
  const [url, setUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState("");
  return (
    <>
      <PageHead title="Repositories" sub="GitHub repositories scanned for manifests and lockfiles. Code is never cloned, built or run." />
      <form className="card inline-form" onSubmit={async (e) => {
        e.preventDefault(); setErrs({}); setMsg("");
        try {
          const r = await post<Repo>("/api/repositories", { url, branch: branch || null });
          await post(`/api/repositories/${r.id}/scan`);
          navigate(`/repositories/${r.id}`);
        } catch (err) { setErrs(fieldErrors(err)); setMsg(errText(err)); }
      }}>
        <Field label="Repository URL" error={errs.url}>
          <input value={url} onChange={(e) => setUrl(e.target.value)} required maxLength={300} placeholder="https://github.com/owner/repo" />
        </Field>
        <Field label="Branch (optional)" hint="Default branch if blank." error={errs.branch}>
          <input value={branch} onChange={(e) => setBranch(e.target.value)} maxLength={200} />
        </Field>
        <button className="btn primary">Add and scan</button>
        {msg && <div className="alert bad" role="alert">{msg}</div>}
      </form>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? <Empty title="No repositories yet." /> : (
        <>
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Repository</th><th>Branch</th><th>Last scan</th><th>Status</th><th>Assets</th><th>Open findings</th></tr></thead>
            <tbody>{data.items.map((r) => (
              <tr key={r.id}>
                <td><Link to={`/repositories/${r.id}`}>{r.owner}/{r.name}</Link>{r.is_demo && <span className="badge tone-warn">DEMO</span>}
                  {r.is_private && <span className="badge tone-muted">private</span>}</td>
                <td>{r.branch ?? <span className="muted">default</span>}</td><td><When iso={r.last_scanned_at} /></td>
                <td>{r.last_scan_status ? <Status s={r.last_scan_status} /> : <span className="muted">never</span>}</td>
                <td>{r.component_count}</td><td>{r.open_findings}</td>
              </tr>
            ))}</tbody>
          </table></div>
          <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
        </>
      ))}
    </>
  );
}

export function RepoDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<{ repository: Repo; runs: ScanRun[] }>(`/api/repositories/${id}`), [id],
    (d) => (d?.runs.some((r) => running(r.status)) ? 2000 : null));
  const busy = data?.runs.some((r) => running(r.status));
  const assets = useLoad(() => get<Page<Asset>>("/api/assets", { repository_id: id, page_size: 200 }), [id, busy]);
  const [msg, setMsg] = useState("");
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Loading />;
  const r = data.repository;
  const last = data.runs[0];
  return (
    <>
      <PageHead title={`${r.owner}/${r.name}`} sub={<a href={r.url} rel="noopener noreferrer" target="_blank">{r.url}</a>}
        actions={<>
          <button className="btn primary" disabled={busy || r.is_demo} onClick={async () => {
            try { await post(`/api/repositories/${r.id}/scan`); setMsg(""); reload(); } catch (e) { setMsg(errText(e)); }
          }}>{busy ? "Scanning…" : "Scan now"}</button>
          <DangerButton question={`Stop tracking ${r.owner}/${r.name}? Its assets and findings are deleted.`}
            onConfirm={async () => { await del(`/api/repositories/${r.id}`); navigate("/repositories"); }}>Delete</DangerButton>
        </>} />
      {msg && <div className="alert bad" role="alert">{msg}</div>}
      <div className="grid two">
        <section className="card">
          <h2>Repository</h2>
          <KV rows={[["Branch", r.branch ?? "default"], ["Visibility", r.is_private == null ? null : r.is_private ? "private" : "public"],
            ["Last revision", r.last_revision ? <code>{r.last_revision.slice(0, 12)}</code> : null], ["Last scanned", <When iso={r.last_scanned_at} />],
            ["Languages", r.languages ? Object.keys(r.languages).join(", ") || "none" : null]]} />
        </section>
        <section className="card">
          <h2>Latest scan</h2>
          {last ? <RunSummary run={last} /> : <p className="muted">Not scanned yet.</p>}
        </section>
      </div>
      <section className="card">
        <h2>Detected components</h2>
        {assets.data ? (assets.data.items.length ? <AssetTable items={assets.data.items} /> : <p className="muted">Nothing detected yet.</p>) : <Loading />}
      </section>
      <section className="card">
        <h2>Scan history</h2>
        <table className="table compact"><tbody>{data.runs.map((x) => (
          <tr key={x.id}><td><Link to={`/scans/${x.id}`}>#{x.id}</Link></td><td><Status s={x.status} /></td>
            <td>{x.revision ? <code>{x.revision.slice(0, 10)}</code> : "-"}</td><td><When iso={x.finished_at ?? x.created_at} /></td></tr>
        ))}</tbody></table>
      </section>
    </>
  );
}
