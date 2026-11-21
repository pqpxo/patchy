import { useState } from "react";
import { get, post, type AuditEntry, type Finding, type Page } from "../api";
import { MATCH_STATUS, SEVERITIES, fmtDate, safeUrl } from "../format";
import {
  Empty, ErrorBox, Field, KV, Kev, Link, Loading, Match, PageHead, Pager, Sev, Status, When, errText, useLoad,
  useQueryParam,
} from "../ui";
import { FindingTable } from "./Assets";

export function VulnsPage() {
  const [severity, setSeverity] = useQueryParam("severity");
  const [status, setStatus] = useQueryParam("status");
  const [match, setMatch] = useQueryParam("match_status");
  const [kev, setKev] = useQueryParam("kev");
  const [hostId] = useQueryParam("host_id");
  const [q, setQ] = useQueryParam("q");
  const [sort, setSort] = useQueryParam("sort");
  const [page, setPage] = useQueryParam("page");
  const [search, setSearch] = useState(q);
  const { data, error, loading, reload } = useLoad(() => get<Page<Finding>>("/api/findings", {
    severity: severity ? [severity] : undefined, status: status ? [status] : ["open", "acknowledged"],
    match_status: match ? [match] : undefined, kev: kev || undefined, host_id: hostId || undefined, q,
    sort: sort || "severity", page: page || 1,
  }), [severity, status, match, kev, hostId, q, sort, page]);
  const feeds = useLoad(() => get<{ stale: boolean; enabled: boolean; source: string }[]>("/api/feeds"), []);
  const stale = feeds.data?.find((f) => f.source === "osv")?.stale;

  return (
    <>
      <PageHead title="Vulnerabilities" sub="Findings from matching your inventory against OSV, enriched with CISA KEV and optionally NVD." />
      {stale && <div className="alert warn">OSV data is stale or has never been fetched, so this list may be incomplete. <Link to="/settings">Check feeds</Link>.</div>}
      <form className="filters" role="search" onSubmit={(e) => { e.preventDefault(); setQ(search); }}>
        <input aria-label="Search component or advisory" placeholder="Component or advisory ID…" value={search} onChange={(e) => setSearch(e.target.value)} maxLength={200} />
        <select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Open + acknowledged</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
        </select>
        <select aria-label="Match" value={match} onChange={(e) => setMatch(e.target.value)}>
          <option value="">All match types</option>{Object.entries(MATCH_STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <label className="check"><input type="checkbox" checked={kev === "true"} onChange={(e) => setKev(e.target.checked ? "true" : "")} /> Known exploited only</label>
        <select aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value)}>
          <option value="severity">Sort: severity</option><option value="published">Sort: published</option>
          <option value="component">Sort: component</option><option value="detected">Sort: first detected</option>
        </select>
        <button className="btn">Search</button>
      </form>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? (
        <Empty title="No findings match these filters.">
          {stale ? "Feed data is stale, so an empty list is not evidence of safety." : "Unknown-version and unchecked assets are listed on the Assets page."}
        </Empty>
      ) : (
        <><FindingTable items={data.items} /><Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} /></>
      ))}
    </>
  );
}

export function FindingDetailPage({ id }: { id: number }) {
  const { data, error, reload, setData } = useLoad(() => get<{ finding: Finding; history: AuditEntry[]; feed_stale: boolean }>(`/api/findings/${id}`), [id]);
  const [status, setStatus] = useState("");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState("");
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Loading />;
  const f = data.finding, a = f.advisory;
  const advisoryUrl = a.source === "osv" ? `https://osv.dev/vulnerability/${encodeURIComponent(a.id)}` : null;
  return (
    <>
      <PageHead title={a.id} sub={<><Sev s={a.severity} /> <Kev on={a.kev} /> <Match s={f.match_status} /> <Status s={f.status} /></>} />
      {a.source === "demo" && <div className="alert warn">DEMO advisory. Fictional, for trying out the interface only.</div>}
      {!f.currently_matching && <div className="alert">This finding no longer matches the current inventory (last checked <When iso={f.last_checked_at} />).</div>}
      {f.status === "resolved" && f.currently_matching && <div className="alert warn">Marked resolved, but the installed version still matches this advisory.</div>}
      {data.feed_stale && <div className="alert warn">Feed data is stale. Details below may be out of date.</div>}
      <div className="grid two">
        <section className="card">
          <h2>{a.summary ?? "Advisory"}</h2>
          <KV rows={[
            ["Affected asset", <><Link to={`/assets/${f.component_id}`}>{f.component_name}</Link> {f.component_version}</>],
            ["Location", f.host_id ? <Link to={`/hosts/${f.host_id}`}>{f.host_name}</Link> : f.repository_label],
            ["Ecosystem", f.ecosystem],
            ["Aliases", a.aliases.length ? a.aliases.join(", ") : null],
            ["Severity", <>{a.severity}{a.cvss_score != null && ` (${a.cvss_score})`} <span className="muted small">{a.severity_source ?? "no score in advisory"}</span></>],
            ["CVSS vector", a.cvss_vector ? <code>{a.cvss_vector}</code> : null],
            ["Published", fmtDate(a.published)], ["Modified", fmtDate(a.modified)],
            ["Data fetched", <When iso={a.fetched_at} />],
            ["Known exploited", a.kev ? `Yes, added ${a.kev_date_added}${a.kev_due_date ? `, CISA due date ${a.kev_due_date}` : ""}` : "Not in CISA KEV"],
          ]} />
          {a.details && <details><summary>Advisory text</summary><p className="pre">{a.details}</p></details>}
        </section>
        <section className="card">
          <h2>Why this matched</h2>
          <p>{f.evidence}</p>
          <h3>Affected ranges</h3>
          {f.affected_ranges.length ? <ul>{f.affected_ranges.map((r) => <li key={r}><code>{r}</code></li>)}</ul> : <p className="muted">The advisory lists no version ranges.</p>}
          <h3>Remediation</h3>
          <p className="pre">{f.remediation}</p>
          <h3>Sources</h3>
          <ul className="links">
            {advisoryUrl && <li><a href={advisoryUrl} target="_blank" rel="noopener noreferrer">OSV: {a.id}</a></li>}
            {a.cve_ids.map((c) => <li key={c}><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`} target="_blank" rel="noopener noreferrer">NVD: {c}</a></li>)}
            {a.references.map((r, i) => {
              const u = safeUrl(r.url);
              return u ? <li key={i}><a href={u} target="_blank" rel="noopener noreferrer">{r.type ?? "Link"}: {u}</a></li> : null;
            })}
          </ul>
        </section>
      </div>
      <section className="card">
        <h2>Status</h2>
        <p className="small muted">Last changed <When iso={f.status_changed_at} /> by {f.status_changed_by}. {f.status_note}</p>
        <form className="inline-form" onSubmit={async (e) => {
          e.preventDefault();
          try {
            const updated = await post<Finding>(`/api/findings/${f.id}/status`, { status: status || f.status, note: note || null });
            setData({ ...data, finding: updated }); setNote(""); setMsg("Saved."); reload();
          } catch (err) { setMsg(errText(err)); }
        }}>
          <Field label="Status">
            <select value={status || f.status} onChange={(e) => setStatus(e.target.value)}>
              <option value="open">Open</option><option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
            </select>
          </Field>
          <Field label="Note"><input value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} placeholder="Why?" /></Field>
          <button className="btn primary">Update</button>
          {msg && <span role="status">{msg}</span>}
        </form>
        <h3>History</h3>
        {data.history.length === 0 ? <p className="muted">No changes yet. First detected <When iso={f.first_detected_at} />.</p> : (
          <table className="table compact"><tbody>{data.history.map((h) => (
            <tr key={h.id}><td><When iso={h.at} /></td><td>{h.actor}</td>
              <td>{h.detail?.from ? `${h.detail.from} → ${h.detail.to}` : h.action}</td><td>{h.detail?.note ?? h.detail?.reason}</td></tr>
          ))}</tbody></table>
        )}
      </section>
    </>
  );
}
