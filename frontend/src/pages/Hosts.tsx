import { useState } from "react";
import { del, get, post, type Agent, type Asset, type Finding, type Host, type Page, type ScanRun } from "../api";
import { Icon } from "../icons";
import { fmtDate, safeUrl } from "../format";
import { usePrefs } from "../prefs";
import { AssetTable, FindingTable } from "../tables";
import {
  CodeBlock, Copy, DangerButton, DataTable, Empty, Eol, ErrorBox, Exposure, Field, KV, Link, PageHead, Pager, Skeleton, Status,
  Tabs, When, errText, fieldErrors, navigate, toast, useLoad, useQueryParam, useSort, type Col,
} from "../ui";
import { FixPlan } from "./Fix";

const hostCols: Col<Host>[] = [
  { id: "name", label: "Host", sort: "name", fixed: true, cell: (h) => <>
    <Link to={`/hosts/${h.id}`}>{h.name}</Link>{h.is_demo && <span className="badge tone-warn">DEMO</span>}
  </> },
  { id: "ip", label: "IP", sort: "ip", cell: (h) => h.ip ? <span className="num">{h.ip}</span> : <span className="muted">-</span> },
  { id: "os", label: "OS", sort: "os", cell: (h) => <>
    {h.os_name ?? <span className="muted">unknown</span>} <Eol s={h.os_eol_state} info={h.os_eol} />
  </> },
  { id: "agent", label: "Agent", cell: (h) => <AgentBadge a={h.agent} outdated={h.agent_outdated} /> },
  { id: "last_report", label: "Last report", sort: "last_report", first: "desc", cell: (h) => <When iso={h.last_report_at} /> },
  { id: "components", label: "Assets", sort: "components", first: "desc", num: true, cell: (h) => h.component_count },
  { id: "exposure", label: "Open findings", sort: "findings", first: "desc", cell: (h) => <Exposure e={h.exposure} /> },
  { id: "eol", label: "OS support", sort: "eol", first: "desc", hidden: true, cell: (h) => <Eol s={h.os_eol_state} info={h.os_eol} quiet={false} /> },
];

export function HostsPage() {
  const [page, setPage] = useQueryParam("page");
  const [q, setQ] = useQueryParam("q");
  const [search, setSearch] = useState(q);
  const sort = useSort("name");
  const { pageSize } = usePrefs();
  const { data, error, loading, reload } = useLoad(() => get<Page<Host>>("/api/hosts", {
    page: page || 1, q, sort: sort.sort, order: sort.order, page_size: pageSize,
  }), [page, q, sort.sort, sort.order, pageSize]);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [ip, setIp] = useState("");
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState("");
  return (
    <>
      <PageHead title="Hosts" sub="Machines you own or administer. Enrol an agent to keep their inventory current."
        actions={<button className="btn primary" aria-expanded={adding} onClick={() => setAdding(!adding)}><Icon name="plus" size={14} /> Add host</button>} />
      {adding && (
        <form className="card inline-form" onSubmit={async (e) => {
          e.preventDefault(); setErrs({}); setMsg("");
          try {
            const h = await post<Host>("/api/hosts", { name, ip: ip || null });
            toast(`Host ${h.name} added.`);
            navigate(`/hosts/${h.id}`);
          } catch (err) { setErrs(fieldErrors(err)); setMsg(errText(err)); }
        }}>
          <Field label="Host name" hint="Letters, digits, dot, dash, underscore." error={errs.name}>
            <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={255} pattern="[A-Za-z0-9._\-]+" autoFocus />
          </Field>
          <Field label="IP (optional)" error={errs.ip}><input value={ip} onChange={(e) => setIp(e.target.value)} maxLength={64} /></Field>
          <button className="btn primary">Add host</button>
          <button className="btn ghost" type="button" onClick={() => setAdding(false)}>Cancel</button>
          {msg && <div className="alert bad" role="alert">{msg}</div>}
        </form>
      )}
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Skeleton /> : data && <>
        <DataTable table="hosts" cols={hostCols} rows={data.items} rowKey={(h) => h.id} sort={sort} tools={
          <form role="search" onSubmit={(e) => { e.preventDefault(); setQ(search); }}>
            <input type="search" aria-label="Search hosts" placeholder="Name or IP…" value={search}
              onChange={(e) => { setSearch(e.target.value); if (!e.target.value) setQ(""); }} maxLength={200} />
          </form>
        } />
        {data.items.length === 0 && <Empty title={q ? "No hosts match." : "No hosts yet."}>Add a host, then enrol its agent.</Empty>}
        <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
      </>}
    </>
  );
}

function AgentBadge({ a, outdated }: { a: Agent | null; outdated?: boolean }) {
  if (!a) return <span className="badge tone-muted">none</span>;
  if (a.revoked_at) return <span className="badge tone-bad">revoked</span>;
  return <><span className="badge tone-good">active</span>{outdated && <span className="badge tone-warn" title="Older than the agent bundled with this server. Reinstall to update.">update</span>}</>;
}

function AgentPanel({ host, onChange }: { host: Host; onChange: () => void }) {
  const [token, setToken] = useState("");
  const [err, setErr] = useState("");
  const origin = window.location.origin;
  const a = host.agent;
  const issue = async (path: string) => {
    setErr("");
    try {
      const r = await post<{ token: string }>(`/api/hosts/${host.id}/${path}`);
      setToken(r.token); onChange();
    } catch (e) { setErr(errText(e)); }
  };
  const install = [
    `cd ~ && mkdir -p patchy-agent && cd patchy-agent`,
    ...["patchy_agent.py", "install.sh", "uninstall.sh", "config.example.json"].map((f) => `curl -fsSO ${origin}/api/agent/files/${f}`),
    `sudo sh install.sh ${origin}`,
  ].join("\n");
  return (
    <section className="card">
      <h2>Agent</h2>
      {a ? (
        <KV rows={[
          ["State", <AgentBadge a={a} outdated={host.agent_outdated} />], ["Token ends", <code>…{a.token_hint}</code>], ["Created", fmtDate(a.created_at)],
          ["Rotated", a.rotated_at ? fmtDate(a.rotated_at) : "never"], ["Last seen", <When iso={a.last_seen_at} />],
          ["From IP", a.last_ip], ["Agent version", a.agent_version],
        ]} />
      ) : <p className="muted">No agent enrolled. Create a credential, then install the agent on this host.</p>}
      {host.agent_outdated && <p className="small">A newer agent ships with this server. Re-run the install commands below on the host to update it (rotate the credential to see them again).</p>}
      <div className="actions">
        {(!a || a.revoked_at) && <button className="btn primary" onClick={() => issue("agent")}>{a ? "Re-enrol" : "Create agent credential"}</button>}
        {a && !a.revoked_at && <>
          <DangerButton question="Rotate the credential? The old token stops working immediately; update /etc/patchy-agent/token on the host."
            onConfirm={() => issue("agent/rotate")}>Rotate</DangerButton>
          <DangerButton question="Revoke this agent? Reports using its token will be rejected." onConfirm={async () => {
            try { await post(`/api/hosts/${host.id}/agent/revoke`); setToken(""); onChange(); toast("Agent revoked."); } catch (e) { setErr(errText(e)); }
          }}>Revoke</DangerButton>
        </>}
      </div>
      {err && <div className="alert bad" role="alert">{err}</div>}
      {token && (
        <div className="token-box">
          <div className="alert warn"><p><strong>Copy this token now.</strong> It is shown once; Patchy stores only a hash.</p></div>
          <div className="row"><code className="block grow">{token}</code><Copy text={token} /></div>
          <p className="small">Install on the host (needs python3 and systemd). Paste the whole block; the installer then asks for the token, so it stays out of shell history:</p>
          <CodeBlock code={install} />
          <p className="small muted">To read the scripts before installing, run the first five lines, then <code>less patchy_agent.py install.sh</code> (press <kbd>q</kbd> to quit), then the last line.</p>
          <p className="small">Test without sending real data: <code>python3 patchy_agent.py --dry-run --config /etc/patchy-agent/config.json</code>.
            For a plain-HTTP server the installer asks before allowing it.</p>
        </div>
      )}
    </section>
  );
}

type HostData = { host: Host; services: { name: string | null; protocol: string | null; listen_ip: string | null; port: number | null }[];
  paths: { root: string; path: string; is_dir: boolean }[]; runs: ScanRun[] };

export function HostDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<HostData>(`/api/hosts/${id}`), [id]);
  const [tab, setTab] = useQueryParam("tab");
  const t = tab || "overview";
  const aSort = useSort("name", "asc", true);
  const fSort = useSort("priority", "desc", true);
  const assets = useLoad(() => t === "assets" ? get<Page<Asset>>("/api/assets", { host_id: id, page_size: 200, sort: aSort.sort, order: aSort.order })
    : Promise.resolve(undefined), [id, t, aSort.sort, aSort.order]);
  const findings = useLoad(() => t === "findings" ? get<Page<Finding>>("/api/findings", { host_id: id, page_size: 200, status: ["open", "acknowledged"], sort: fSort.sort, order: fSort.order })
    : Promise.resolve(undefined), [id, t, fSort.sort, fSort.order]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton />;
  const h = data.host;
  const ports = data.services.filter((s) => s.port !== null);
  const units = data.services.filter((s) => s.port === null);
  const eolLink = safeUrl(h.os_eol?.link);
  return (
    <>
      <PageHead title={h.name} crumbs={[["Hosts", "/hosts"]]}
        sub={<>{h.os_name ?? "OS unknown until an agent reports"}{h.ip && <> · <span className="num">{h.ip}</span></>}</>}
        meta={<><Exposure e={h.exposure} size="wide" /><Eol s={h.os_eol_state} info={h.os_eol} /><AgentBadge a={h.agent} outdated={h.agent_outdated} />
          <span className="small muted">reported <When iso={h.last_report_at} /></span></>}
        actions={<DangerButton question={`Delete host ${h.name} and all its assets and findings?`}
          onConfirm={async () => { await del(`/api/hosts/${h.id}`); toast("Host deleted."); navigate("/hosts"); }}>Delete host</DangerButton>} />
      {h.is_demo && <div className="alert warn">DEMO host with fictional data.</div>}
      <Tabs value={t} onChange={setTab} tabs={[
        ["overview", "Overview"], ["assets", <>Assets <span className="num">{h.component_count}</span></>],
        ["findings", <>Findings <span className="num">{h.open_findings}</span></>], ["fix", "How to fix"], ["reports", "Reports"],
      ]} />
      {t === "overview" && <div className="host-grid">
        <section className="card">
          <h2>Host</h2>
          <KV rows={[["IP", h.ip], ["Reported hostname", h.reported_hostname], ["OS version", h.os_version], ["Kernel", h.kernel],
            ["Architecture", h.arch], ["Last report", <When iso={h.last_report_at} />],
            ["OS support", h.os_eol ? <><Eol s={h.os_eol_state} info={h.os_eol} quiet={false} /> {h.os_eol.eol_from && <span className="small muted">ends {h.os_eol.eol_from}</span>}
              {eolLink && <> <a className="small" href={eolLink} target="_blank" rel="noopener noreferrer">dates</a></>}</> : null]]} />
          {h.notes && <p className="pre">{h.notes}</p>}
        </section>
        <AgentPanel host={h} onChange={reload} />
        <section className="card fill">
          <h2>Listening ports <span className="num muted">{ports.length}</span></h2>
          <div className="fill-body">
            {ports.length === 0 ? <p className="muted">None reported.</p> : (
              <table className="table compact"><thead><tr><th>Address</th><th>Protocol</th><th>Process</th></tr></thead>
                <tbody>{ports.map((s, i) => <tr key={i}><td className="num">{s.listen_ip}:{s.port}</td><td>{s.protocol}</td>
                  <td>{s.name ?? <span className="muted" title="The agent runs unprivileged and can't see other users' processes">unknown</span>}</td></tr>)}</tbody></table>
            )}
            <h2 className="gap-top">Running services</h2>
            {units.length === 0 ? <p className="muted">None reported.</p> : <p className="small">{units.map((u) => u.name).join(", ")}</p>}
          </div>
        </section>
        <section className="card wide">
          <h2>Application directories</h2>
          <p className="muted small">Names only, from directories listed in the agent config. Sensitive names are excluded.</p>
          {data.paths.length === 0 ? <p className="muted">No directories configured.</p> : (
            <ul className="paths scroll">{data.paths.map((p) => <li key={p.path}><code>{p.path}{p.is_dir ? "/" : ""}</code></li>)}</ul>
          )}
        </section>
      </div>}
      {t === "assets" && (assets.data ? <>
        <AssetTable items={assets.data.items} sort={aSort} table="host-assets" where={false} />
        {assets.data.total > 200 && <p><Link to={`/assets?host_id=${id}`}>Showing 200 of {assets.data.total}. Open in Assets</Link></p>}
      </> : <Skeleton />)}
      {t === "findings" && (findings.data ? (findings.data.items.length
        ? <FindingTable items={findings.data.items} sort={fSort} showAsset={false} table="host-findings" />
        : <Empty title="No open findings on this host." />) : <Skeleton />)}
      {t === "fix" && <FixPlan hostId={id} />}
      {t === "reports" && (data.runs.length === 0 ? <Empty title="No reports yet." /> : (
        <div className="table-wrap"><table className="table compact"><thead><tr><th>Report</th><th>Status</th><th>Packages</th><th>When</th></tr></thead>
          <tbody>{data.runs.map((r) => (
            <tr key={r.id}><td><Link to={`/scans/${r.id}`}>#{r.id}</Link></td><td><Status s={r.status} /></td>
              <td className="num">{r.summary?.packages ?? "-"}</td><td><When iso={r.finished_at ?? r.created_at} /></td></tr>
          ))}</tbody></table></div>
      ))}
    </>
  );
}
