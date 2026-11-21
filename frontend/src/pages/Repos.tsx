import { useState } from "react";
import { del, get, post, type Asset, type Dependabot, type Finding, type Page, type Repo, type ScanRun } from "../api";
import { Icon } from "../icons";
import { safeUrl } from "../format";
import { usePrefs } from "../prefs";
import { AssetTable, FindingTable } from "../tables";
import {
  DangerButton, DataTable, Empty, ErrorBox, Exposure, Field, KV, Link, PageHead, Pager, RunBanner, Sev, Skeleton, Status, Tabs, When,
  errText, fieldErrors, navigate, toast, useLoad, useQueryParam, useSort, type Col,
} from "../ui";
import { FixPlan } from "./Fix";
import { RunSummary } from "./Scans";

const running = (s?: string | null) => s === "queued" || s === "running";

const repoCols: Col<Repo>[] = [
  { id: "name", label: "Repository", sort: "name", fixed: true, cell: (r) => <>
    <Link to={`/repositories/${r.id}`}>{r.owner}/{r.name}</Link>{r.is_demo && <span className="badge tone-warn">DEMO</span>}
    {r.is_private && <span className="badge tone-muted">private</span>}
  </> },
  { id: "branch", label: "Branch", cell: (r) => r.branch ?? <span className="muted">default</span> },
  { id: "last_scanned", label: "Last scan", sort: "last_scanned", first: "desc", cell: (r) => <>
    <When iso={r.last_scanned_at} /> {r.last_scan_status && r.last_scan_status !== "succeeded" && <Status s={r.last_scan_status} />}
  </> },
  { id: "components", label: "Assets", sort: "components", first: "desc", num: true, cell: (r) => r.component_count },
  { id: "exposure", label: "Open findings", sort: "findings", first: "desc", cell: (r) => <Exposure e={r.exposure} /> },
  { id: "dependabot", label: "Dependabot", cell: (r) => r.dependabot_error ? <span className="badge tone-muted" title={r.dependabot_error}>not readable</span>
    : r.dependabot_total == null ? <span className="muted">-</span>
    : <span className="num" title="Open Dependabot alerts (alerts Patchy has not found itself)">{r.dependabot_total}{r.dependabot_only ? <span className="muted"> ({r.dependabot_only} only there)</span> : null}</span> },
];

export function ReposPage() {
  const [page, setPage] = useQueryParam("page");
  const [q, setQ] = useQueryParam("q");
  const [search, setSearch] = useState(q);
  const sort = useSort("name");
  const { pageSize } = usePrefs();
  const { data, error, loading, reload } = useLoad(() => get<Page<Repo>>("/api/repositories", {
    page: page || 1, q, sort: sort.sort, order: sort.order, page_size: pageSize,
  }), [page, q, sort.sort, sort.order, pageSize], (d) => (d?.items.some((r) => running(r.last_scan_status)) ? 3000 : null));
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
          toast("Repository added. Scan queued.");
          navigate(`/repositories/${r.id}`);
        } catch (err) { setErrs(fieldErrors(err)); setMsg(errText(err)); }
      }}>
        <Field label="Repository URL" error={errs.url}>
          <input value={url} onChange={(e) => setUrl(e.target.value)} required maxLength={300} placeholder="https://github.com/owner/repo" size={36} />
        </Field>
        <Field label="Branch (optional)" error={errs.branch}>
          <input value={branch} onChange={(e) => setBranch(e.target.value)} maxLength={200} placeholder="default" />
        </Field>
        <button className="btn primary"><Icon name="plus" size={14} /> Add and scan</button>
        {msg && <div className="alert bad" role="alert">{msg}</div>}
      </form>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Skeleton /> : data && <>
        <DataTable table="repos" cols={repoCols} rows={data.items} rowKey={(r) => r.id} sort={sort} tools={
          <form role="search" onSubmit={(e) => { e.preventDefault(); setQ(search); }}>
            <input type="search" aria-label="Search repositories" placeholder="Owner or name…" value={search}
              onChange={(e) => { setSearch(e.target.value); if (!e.target.value) setQ(""); }} maxLength={200} />
          </form>
        } />
        {data.items.length === 0 && <Empty title={q ? "No repositories match." : "No repositories yet."} />}
        <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
      </>}
    </>
  );
}

function DependabotPanel({ d }: { d: Dependabot | null }) {
  if (!d) return <Empty title="Not checked yet.">Dependabot alerts are read during feed refreshes when GITHUB_TOKEN is set (see Settings, Sources).</Empty>;
  if (d.error) return <div className="alert warn">{d.error}</div>;
  if (!d.alerts.length) return <Empty title="No open Dependabot alerts.">Checked <When iso={d.checked_at} />.</Empty>;
  return (
    <>
      <p className="small muted">{d.total} open alerts, {d.also_in_patchy ?? 0} also found by Patchy. Checked <When iso={d.checked_at} />.
        Alerts only Dependabot reports usually come from manifests Patchy can't parse, or advisories not yet in OSV.</p>
      <div className="table-wrap"><table className="table">
        <thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Manifest</th><th>Patched in</th><th>In Patchy</th></tr></thead>
        <tbody>{d.alerts.map((a) => {
          const u = safeUrl(a.url);
          return (
            <tr key={a.number}>
              <td><Sev s={a.severity} /></td>
              <td>{u ? <a href={u} target="_blank" rel="noopener noreferrer">{a.ghsa ?? `#${a.number}`}</a> : a.ghsa}
                {a.cve && <span className="cell-sub"> {a.cve}</span>}<div className="cell-sub clamp">{a.summary}</div></td>
              <td>{a.package} <span className="cell-sub">{a.ecosystem}</span></td>
              <td><code>{a.manifest}</code></td>
              <td className="ver">{a.patched ?? <span className="muted">none</span>}</td>
              <td>{a.in_patchy ? <span className="badge tone-good">yes</span> : <span className="badge tone-warn">only Dependabot</span>}</td>
            </tr>
          );
        })}</tbody>
      </table></div>
    </>
  );
}

export function RepoDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<{ repository: Repo; runs: ScanRun[]; dependabot: Dependabot | null }>(`/api/repositories/${id}`), [id],
    (d) => (d?.runs.some((r) => running(r.status)) ? 2000 : null));
  const busy = data?.runs.some((r) => running(r.status));
  const [tab, setTab] = useQueryParam("tab");
  const t = tab || "overview";
  const aSort = useSort("name", "asc", true);
  const fSort = useSort("priority", "desc", true);
  const assets = useLoad(() => t === "assets" ? get<Page<Asset>>("/api/assets", { repository_id: id, page_size: 200, sort: aSort.sort, order: aSort.order })
    : Promise.resolve(undefined), [id, t, busy, aSort.sort, aSort.order]);
  const findings = useLoad(() => t === "findings" ? get<Page<Finding>>("/api/findings", { repository_id: id, page_size: 200, status: ["open", "acknowledged"], sort: fSort.sort, order: fSort.order })
    : Promise.resolve(undefined), [id, t, busy, fSort.sort, fSort.order]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton />;
  const r = data.repository;
  const last = data.runs[0];
  const repoUrl = safeUrl(r.url);
  return (
    <>
      <PageHead title={`${r.owner}/${r.name}`} crumbs={[["Repositories", "/repositories"]]}
        sub={repoUrl && <a href={repoUrl} rel="noopener noreferrer" target="_blank">{r.url} <Icon name="external" size={12} /></a>}
        meta={<><Exposure e={r.exposure} size="wide" />{last && <Status s={last.status} />}<span className="small muted">scanned <When iso={r.last_scanned_at} /></span></>}
        actions={<>
          <button className="btn primary" disabled={busy || r.is_demo} onClick={async () => {
            try { await post(`/api/repositories/${r.id}/scan`); toast("Scan queued."); reload(); } catch (e) { toast(errText(e), "bad"); }
          }}><Icon name="refresh" size={14} /> {busy ? "Scanning…" : "Scan now"}</button>
          <DangerButton question={`Stop tracking ${r.owner}/${r.name}? Its assets and findings are deleted.`}
            onConfirm={async () => { await del(`/api/repositories/${r.id}`); toast("Repository removed."); navigate("/repositories"); }}>Delete</DangerButton>
        </>} />
      <RunBanner run={last} what="Scan" />
      <Tabs value={t} onChange={setTab} tabs={[
        ["overview", "Overview"], ["assets", <>Assets <span className="num">{r.component_count}</span></>],
        ["findings", <>Findings <span className="num">{r.open_findings}</span></>], ["fix", "How to fix"],
        ["dependabot", <>Dependabot {r.dependabot_total != null && <span className="num">{r.dependabot_total}</span>}</>], ["history", "Scan history"],
      ]} />
      {t === "overview" && <div className="grid two">
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
      </div>}
      {t === "assets" && (assets.data ? (assets.data.items.length
        ? <AssetTable items={assets.data.items} sort={aSort} table="repo-assets" where={false} />
        : <Empty title="Nothing detected yet." />) : <Skeleton />)}
      {t === "findings" && (findings.data ? (findings.data.items.length
        ? <FindingTable items={findings.data.items} sort={fSort} table="repo-findings" />
        : <Empty title="No open findings in this repository." />) : <Skeleton />)}
      {t === "fix" && <FixPlan repositoryId={id} />}
      {t === "dependabot" && <DependabotPanel d={data.dependabot} />}
      {t === "history" && (
        <div className="table-wrap"><table className="table compact"><thead><tr><th>Scan</th><th>Status</th><th>Revision</th><th>When</th></tr></thead>
          <tbody>{data.runs.map((x) => (
            <tr key={x.id}><td><Link to={`/scans/${x.id}`}>#{x.id}</Link></td><td><Status s={x.status} /></td>
              <td>{x.revision ? <code>{x.revision.slice(0, 10)}</code> : "-"}</td><td><When iso={x.finished_at ?? x.created_at} /></td></tr>
          ))}</tbody></table></div>
      )}
    </>
  );
}
