import { useState } from "react";
import { get, post, qs, type DependabotAlert, type Feed, type Finding, type Page, type TimelineEvent } from "../api";
import { Icon } from "../icons";
import { MATCH_STATUS, SEVERITIES, fmtDate, pct, safeUrl } from "../format";
import { usePrefs } from "../prefs";
import { FindingTable } from "../tables";
import {
  Due, Empty, Epss, ErrorBox, Field, KV, Kev, Link, Match, Reach, PageHead, Pager, Sev, Skeleton, Status, When, errText, toast, useLoad,
  useQueryParam, useSort,
} from "../ui";

export function VulnsPage() {
  const [severity, setSeverity] = useQueryParam("severity");
  const [status, setStatus] = useQueryParam("status");
  const [match, setMatch] = useQueryParam("match_status");
  const [kev, setKev] = useQueryParam("kev");
  const [overdue, setOverdue] = useQueryParam("overdue");
  const [inUse, setInUse] = useQueryParam("in_use");
  const [hostId] = useQueryParam("host_id");
  const [q, setQ] = useQueryParam("q");
  const [page, setPage] = useQueryParam("page");
  const sort = useSort("priority", "desc");
  const { pageSize } = usePrefs();
  const [search, setSearch] = useState(q);
  const filters = {
    severity: severity ? [severity] : undefined, status: status ? [status] : ["open", "acknowledged"],
    match_status: match ? [match] : undefined, kev: kev || undefined, overdue: overdue || undefined,
    in_use: inUse || undefined,
    host_id: hostId || undefined, q,
    sort: sort.sort, order: sort.order,
  };
  const { data, error, loading, reload } = useLoad(() => get<Page<Finding>>("/api/findings", {
    ...filters, page: page || 1, page_size: pageSize,
  }), [severity, status, match, kev, overdue, inUse, hostId, q, sort.sort, sort.order, page, pageSize]);
  const feeds = useLoad(() => get<Feed[]>("/api/feeds"), []);
  const stale = feeds.data?.find((f) => f.source === "osv")?.stale;
  const [bulk, setBulk] = useState(false);
  const [bulkStatus, setBulkStatus] = useState("acknowledged");
  const [bulkNote, setBulkNote] = useState("");
  const [busy, setBusy] = useState(false);
  const total = data?.total ?? 0;

  async function applyBulk(e: React.FormEvent) {
    e.preventDefault();
    const label = STATUS_LABEL[bulkStatus];
    if (!window.confirm(`Set ${total} ${total === 1 ? "finding" : "findings"} to ${label}? This covers every page of the list, not just this one.`)) return;
    setBusy(true);
    try {
      const r = await post<{ changed: number; skipped: number }>(`/api/findings/bulk-status${qs(filters)}`,
        { status: bulkStatus, note: bulkNote || null, expected: total });
      toast(`${r.changed} set to ${label}.${r.skipped ? ` ${r.skipped} skipped (accepted risk, or already ${label}).` : ""}`);
      setBulk(false); setBulkNote(""); reload();
    } catch (err) { toast(errText(err), "bad"); } finally { setBusy(false); }
  }

  const tools = (
    <>
      <form role="search" onSubmit={(e) => { e.preventDefault(); setQ(search); }}>
        <input type="search" aria-label="Search component or advisory" placeholder="Component or advisory ID…" value={search}
          onChange={(e) => { setSearch(e.target.value); if (!e.target.value) setQ(""); }} maxLength={200} />
      </form>
      <select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
        <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
      <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">Open + acknowledged</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option>
        <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
        <option value="minor">Minor (distro rating)</option><option value="risk_accepted">Risk accepted</option>
        <option value="not_booted">Not booted (old kernel)</option>
      </select>
      <select aria-label="Running" value={inUse} onChange={(e) => setInUse(e.target.value)}
        title="Whether a running program comes from the package. Needs agent 1.5 or later.">
        <option value="">Running or not</option><option value="true">Running</option><option value="false">Not running</option>
      </select>
      <select aria-label="Match" value={match} onChange={(e) => setMatch(e.target.value)}>
        <option value="">All match types</option>{Object.entries(MATCH_STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
      </select>
      <label className="check"><input type="checkbox" checked={kev === "true"} onChange={(e) => setKev(e.target.checked ? "true" : "")} /> Known exploited</label>
      <label className="check"><input type="checkbox" checked={overdue === "true"} onChange={(e) => setOverdue(e.target.checked ? "true" : "")} /> Overdue</label>
    </>
  );
  return (
    <>
      <PageHead title="Vulnerabilities" sub="Findings from OSV and NVD, ranked by known exploitation (CISA KEV), likely exploitation (EPSS), then severity."
        actions={<>
          <button className="btn" onClick={() => setBulk(!bulk)} disabled={!total} aria-expanded={bulk}
            title="Change the status of every finding these filters match">Change status…</button>
          <a className="btn" href={`/api/findings/export${qs(filters)}`} download
            title="Download these findings, with the current filters and order, as CSV">Export CSV</a>
          <Link to="/fix" className="btn"><Icon name="fix" size={14} /> Fixes</Link>
        </>} />
      {stale && <div className="alert warn">OSV data is stale or has never been fetched, so this list may be incomplete. <Link to="/settings?tab=sources">Check sources</Link>.</div>}
      <ErrorBox error={error} onRetry={reload} />
      {bulk && total > 0 && (
        <section className="card">
          <form className="inline-form" onSubmit={applyBulk}>
            <Field label="Set status">
              <select value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value)}>
                {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </Field>
            <Field label="Note"><input value={bulkNote} onChange={(e) => setBulkNote(e.target.value)} maxLength={2000} placeholder="Why?" size={40} /></Field>
            <button className="btn primary" disabled={busy || total > BULK_MAX}>Apply to {total}</button>
            <button type="button" className="btn" onClick={() => setBulk(false)}>Cancel</button>
          </form>
          <p className="small muted">
            {total > BULK_MAX ? `${total} findings match. Narrow the filters to ${BULK_MAX} or fewer first.`
              : `Changes all ${total} findings these filters match, on every page. Findings an accepted-risk rule covers are skipped. Each change is kept in the finding's history.`}
          </p>
        </section>
      )}
      {loading && !data ? <Skeleton /> : data && <>
        <FindingTable items={data.items} sort={sort} tools={tools} />
        {data.items.length === 0 && (
          <Empty title="No findings match these filters.">
            {stale ? "Feed data is stale, so an empty list is not evidence of safety." : "Unknown-version and unchecked assets are listed on the Assets page."}
          </Empty>
        )}
        <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
      </>}
    </>
  );
}

const BULK_MAX = 1000;
const STATUS_LABEL: Record<string, string> = { open: "Open", acknowledged: "Acknowledged", resolved: "Resolved", false_positive: "False positive" };

function who(actor: string) {
  return actor === "system" ? "Patchy" : actor.startsWith("rule:") ? "an accepted-risk rule" : actor;
}

function Timeline({ events }: { events: TimelineEvent[] }) {
  return (
    <ol className="timeline">
      {events.map((e, i) => (
        <li key={i}>
          <div>
            {e.kind === "detected" ? <strong>Found</strong> : <Status s={e.to} />}
            <span className="muted small"> {e.kind === "detected" ? "by Patchy" : <>by {who(e.actor)}{e.from && e.from !== e.to && <>, was {e.from.replace("_", " ")}</>}</>}, <When iso={e.at} /></span>
          </div>
          {e.note && <p className="small">{e.note}</p>}
        </li>
      ))}
    </ol>
  );
}

function HowToFix({ f, dep }: { f: Finding; dep: DependabotAlert | null }) {
  const plan = f.host_id ? `/hosts/${f.host_id}?tab=fix` : f.repository_id ? `/repositories/${f.repository_id}?tab=fix` : "/fix";
  return (
    <section className="card">
      <div className="card-head"><h2>Fixes</h2><Link to={plan} className="small">Full fix plan</Link></div>
      {f.fixed_versions.length > 0 && (
        <p><span className="upgrade">{f.component_version ?? "?"}<span className="arrow">→</span>
          <span className="to">{f.fixed_versions.slice(0, 4).join(" or ")}</span></span></p>
      )}
      <p className="pre">{f.remediation}</p>
      {f.match_status === "possible" && <p className="small muted">This is a possible match. Check your vendor or distro security tracker before upgrading: the fix may already be backported.</p>}
      {f.advisory.kev_required_action && <p className="small"><strong>CISA required action:</strong> {f.advisory.kev_required_action}</p>}
      {dep && (
        <div className="alert info">
          <Icon name="repos" />
          <span>Dependabot also reports this{dep.patched && <> (patched in <span className="ver">{dep.patched}</span>)</>}.{" "}
            {safeUrl(dep.url) && <a href={safeUrl(dep.url)!} target="_blank" rel="noopener noreferrer">Open alert #{dep.number}</a>}</span>
        </div>
      )}
    </section>
  );
}

export function FindingDetailPage({ id }: { id: number }) {
  const { data, error, reload, setData } = useLoad(() => get<{ finding: Finding; timeline: TimelineEvent[]; feed_stale: boolean; dependabot: DependabotAlert | null }>(`/api/findings/${id}`), [id]);
  const [status, setStatus] = useState("");
  const [note, setNote] = useState("");
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton />;
  const f = data.finding, a = f.advisory;
  const advisoryUrl = a.source === "osv" ? `https://osv.dev/vulnerability/${encodeURIComponent(a.id)}` : null;
  return (
    <>
      <PageHead title={a.id} crumbs={[["Vulnerabilities", "/vulnerabilities"]]} sub={a.summary}
        meta={<><Sev s={a.severity} /><Kev on={a.kev} /><Reach e={f.exposure} note={f.exposure_note} inUse={f.in_use} /><Match s={f.match_status} /><Status s={f.status} />
          {a.epss != null && <Epss v={a.epss} p={a.epss_percentile} />}</>} />
      {a.source === "demo" && <div className="alert warn">DEMO advisory. Fictional, for trying out the interface only.</div>}
      {!f.currently_matching && <div className="alert">This finding no longer matches the current inventory (last checked <When iso={f.last_checked_at} />).</div>}
      {f.status === "resolved" && f.currently_matching && <div className="alert warn">Marked resolved, but the installed version still matches this advisory.</div>}
      {data.feed_stale && <div className="alert warn">Feed data is stale. Details below may be out of date.</div>}
      <div className="grid two">
        <div className="stack">
          <HowToFix f={f} dep={data.dependabot} />
          <section className="card">
            <h2>Why this matched</h2>
            <p>{f.evidence}</p>
            <h3>Affected ranges</h3>
            {f.affected_ranges.length ? <ul className="paths">{f.affected_ranges.map((r) => <li key={r}><code>{r}</code></li>)}</ul> : <p className="muted">The advisory lists no version ranges.</p>}
          </section>
        </div>
        <section className="card">
          <h2>Advisory</h2>
          <KV rows={[
            ["Affected asset", <><Link to={`/assets/${f.component_id}`}>{f.component_name}</Link> <span className="ver">{f.component_version}</span></>],
            ["Location", f.host_id ? <Link to={`/hosts/${f.host_id}`}>{f.host_name}</Link> : f.repository_id ? <Link to={`/repositories/${f.repository_id}`}>{f.repository_label}</Link> : null],
            ["Ecosystem", f.ecosystem],
            ["Aliases", a.aliases.length ? a.aliases.join(", ") : null],
            ["Severity", <>{a.severity}{a.cvss_score != null && <span className="num"> ({a.cvss_score})</span>} <span className="muted small">{a.severity_source ?? "no score in advisory"}</span></>],
            ["CVSS vector", a.cvss_vector ? <code>{a.cvss_vector}</code> : null],
            ["Exploit likelihood", a.epss != null ? <>{pct(a.epss)} in the next 30 days <span className="muted small">(EPSS, percentile {Math.round((a.epss_percentile ?? 0) * 100)})</span></> : "No EPSS score"],
            ["Known exploited", a.kev ? `Yes, added ${a.kev_date_added}${a.kev_due_date ? `, CISA due date ${a.kev_due_date}` : ""}` : "Not in CISA KEV"],
            ["Published", fmtDate(a.published)], ["Modified", fmtDate(a.modified)],
            ["Data fetched", <When iso={a.fetched_at} />],
          ]} />
          {a.details && <details><summary>Advisory text</summary><p className="pre">{a.details}</p></details>}
          <h3>Sources</h3>
          <ul className="links">
            {advisoryUrl && <li><a href={advisoryUrl} target="_blank" rel="noopener noreferrer">OSV: {a.id}</a></li>}
            {a.cve_ids.map((c) => <li key={c}><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`} target="_blank" rel="noopener noreferrer">NVD: {c}</a></li>)}
            {a.references.slice(0, 30).map((r, i) => {
              const u = safeUrl(r.url);
              return u ? <li key={i}><a href={u} target="_blank" rel="noopener noreferrer">{r.type ?? "Link"}: {u}</a></li> : null;
            })}
          </ul>
        </section>
      </div>
      <section className="card">
        <h2>Status</h2>
        <p className="small muted">Last changed <When iso={f.status_changed_at} /> by {f.status_changed_by}. {f.status_note}
          {f.vendor_priority && <> Distro rating: <strong>{f.vendor_priority}</strong>.</>}
          {f.due_at && <> Fix by <strong>{new Date(f.due_at).toLocaleDateString("en-GB", { dateStyle: "medium" })}</strong> (<Due iso={f.due_at} />).</>}</p>
        <form className="inline-form" onSubmit={async (e) => {
          e.preventDefault();
          try {
            const updated = await post<Finding>(`/api/findings/${f.id}/status`, { status: status || f.status, note: note || null });
            setData({ ...data, finding: updated }); setNote(""); toast("Status saved."); reload();
          } catch (err) { toast(errText(err), "bad"); }
        }}>
          <Field label="Status">
            <select value={status || f.status} onChange={(e) => setStatus(e.target.value)}>
              <option value="open">Open</option><option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
              {f.status === "minor" && <option value="minor" disabled>Minor (set by Patchy)</option>}
              {f.status === "risk_accepted" && <option value="risk_accepted" disabled>Risk accepted (by a rule)</option>}
              {f.status === "not_booted" && <option value="not_booted" disabled>Not booted (set by Patchy)</option>}
            </select>
          </Field>
          <Field label="Note"><input value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} placeholder="Why?" size={40} /></Field>
          <button className="btn primary">Update</button>
          {f.status === "risk_accepted"
            ? <Link className="btn small" to="/settings?tab=risks">Manage rules</Link>
            : <Link className="btn small" to={`/settings${qs({ tab: "risks", advisory: a.id, package: f.component_name, host: f.host_id ?? undefined })}`}>Accept risk…</Link>}
        </form>
        <h3>History</h3>
        <Timeline events={data.timeline} />
      </section>
    </>
  );
}
