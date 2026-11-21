import { useState } from "react";
import { del, get, post, type Agent, type Asset, type Host, type Page, type ScanRun } from "../api";
import { fmtDate } from "../format";
import {
  Copy, DangerButton, Empty, ErrorBox, Field, KV, Link, Loading, PageHead, Pager, Status, When, errText, fieldErrors,
  navigate, useLoad, useQueryParam,
} from "../ui";
import { AssetTable } from "./Assets";

export function HostsPage() {
  const [page, setPage] = useQueryParam("page");
  const { data, error, loading, reload } = useLoad(() => get<Page<Host>>("/api/hosts", { page: page || 1 }), [page]);
  const [name, setName] = useState("");
  const [ip, setIp] = useState("");
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState("");
  return (
    <>
      <PageHead title="Hosts" sub="Machines you own or administer. Enrol an agent to keep their inventory current." />
      <form className="card inline-form" onSubmit={async (e) => {
        e.preventDefault(); setErrs({}); setMsg("");
        try {
          const h = await post<Host>("/api/hosts", { name, ip: ip || null });
          navigate(`/hosts/${h.id}`);
        } catch (err) { setErrs(fieldErrors(err)); setMsg(errText(err)); }
      }}>
        <Field label="Host name" hint="Letters, digits, dot, dash, underscore." error={errs.name}>
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={255} pattern="[A-Za-z0-9._\-]+" />
        </Field>
        <Field label="IP (optional)" error={errs.ip}><input value={ip} onChange={(e) => setIp(e.target.value)} maxLength={64} /></Field>
        <button className="btn primary">Add host</button>
        {msg && <div className="alert bad" role="alert">{msg}</div>}
      </form>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? <Empty title="No hosts yet." /> : (
        <>
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Host</th><th>IP</th><th>OS</th><th>Agent</th><th>Last report</th><th>Assets</th><th>Open findings</th></tr></thead>
            <tbody>{data.items.map((h) => (
              <tr key={h.id}>
                <td><Link to={`/hosts/${h.id}`}>{h.name}</Link>{h.is_demo && <span className="badge tone-warn">DEMO</span>}</td>
                <td>{h.ip ?? "-"}</td><td>{h.os_name ?? <span className="muted">unknown</span>}</td>
                <td><AgentBadge a={h.agent} /></td><td><When iso={h.last_report_at} /></td>
                <td>{h.component_count}</td><td>{h.open_findings}</td>
              </tr>
            ))}</tbody>
          </table></div>
          <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
        </>
      ))}
    </>
  );
}

function AgentBadge({ a }: { a: Agent | null }) {
  if (!a) return <span className="badge tone-muted">none</span>;
  if (a.revoked_at) return <span className="badge tone-bad">revoked</span>;
  return <span className="badge tone-good">active</span>;
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
    `mkdir patchy-agent && cd patchy-agent`,
    ...["patchy_agent.py", "install.sh", "uninstall.sh", "config.example.json"].map((f) => `curl -fsSO ${origin}/api/agent/files/${f}`),
    `less patchy_agent.py install.sh   # review before running`,
    `sudo sh install.sh ${origin}`,
  ].join("\n");
  return (
    <section className="card">
      <h2>Agent credential</h2>
      {a ? (
        <KV rows={[
          ["State", <AgentBadge a={a} />], ["Token ends", `…${a.token_hint}`], ["Created", fmtDate(a.created_at)],
          ["Rotated", a.rotated_at ? fmtDate(a.rotated_at) : "never"], ["Last seen", <When iso={a.last_seen_at} />],
          ["From IP", a.last_ip], ["Agent version", a.agent_version],
        ]} />
      ) : <p className="muted">No agent enrolled. Create a credential, then install the agent on this host.</p>}
      <div className="actions">
        {(!a || a.revoked_at) && <button className="btn primary" onClick={() => issue("agent")}>{a ? "Re-enrol" : "Create agent credential"}</button>}
        {a && !a.revoked_at && <>
          <DangerButton question="Rotate the credential? The old token stops working immediately; update /etc/patchy-agent/token on the host."
            onConfirm={() => issue("agent/rotate")}>Rotate</DangerButton>
          <DangerButton question="Revoke this agent? Reports using its token will be rejected." onConfirm={async () => {
            try { await post(`/api/hosts/${host.id}/agent/revoke`); setToken(""); onChange(); } catch (e) { setErr(errText(e)); }
          }}>Revoke</DangerButton>
        </>}
      </div>
      {err && <div className="alert bad" role="alert">{err}</div>}
      {token && (
        <div className="alert warn token-box">
          <p><strong>Copy this token now.</strong> It is shown once; Patchy stores only a hash.</p>
          <div className="row"><code className="block grow">{token}</code><Copy text={token} /></div>
          <p>Install on the host (needs python3 and systemd). The installer prompts for the token so it stays out of shell history:</p>
          <div className="row"><pre className="block grow">{install}</pre><Copy text={install} /></div>
          <p className="small">Test without sending real data: <code>python3 patchy_agent.py --dry-run --config /etc/patchy-agent/config.json</code>.
            Plain-HTTP portals need <code>"allow_insecure_http": true</code> in the agent config.</p>
        </div>
      )}
    </section>
  );
}

export function HostDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<{ host: Host; services: { name: string | null; protocol: string | null; listen_ip: string | null; port: number | null }[];
    paths: { root: string; path: string; is_dir: boolean }[]; runs: ScanRun[] }>(`/api/hosts/${id}`), [id]);
  const assets = useLoad(() => get<Page<Asset>>("/api/assets", { host_id: id, page_size: 200, sort: "name" }), [id]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Loading />;
  const h = data.host;
  const ports = data.services.filter((s) => s.port !== null);
  const units = data.services.filter((s) => s.port === null);
  return (
    <>
      <PageHead title={h.name} sub={h.os_name ?? "OS unknown until an agent reports"}
        actions={<DangerButton question={`Delete host ${h.name} and all its assets and findings?`}
          onConfirm={async () => { await del(`/api/hosts/${h.id}`); navigate("/hosts"); }}>Delete host</DangerButton>} />
      {h.is_demo && <div className="alert warn">DEMO host with fictional data.</div>}
      <div className="grid two">
        <section className="card">
          <h2>Host</h2>
          <KV rows={[["IP", h.ip], ["Reported hostname", h.reported_hostname], ["OS version", h.os_version], ["Kernel", h.kernel],
            ["Architecture", h.arch], ["Last report", <When iso={h.last_report_at} />], ["Assets", h.component_count],
            ["Open findings", h.open_findings]]} />
          {h.notes && <p className="pre">{h.notes}</p>}
        </section>
        <AgentPanel host={h} onChange={reload} />
        <section className="card">
          <h2>Listening ports</h2>
          {ports.length === 0 ? <p className="muted">None reported.</p> : (
            <table className="table compact"><thead><tr><th>Address</th><th>Protocol</th><th>Process</th></tr></thead>
              <tbody>{ports.map((s, i) => <tr key={i}><td>{s.listen_ip}:{s.port}</td><td>{s.protocol}</td>
                <td>{s.name ?? <span className="muted" title="The agent runs unprivileged and can't see other users' processes">unknown</span>}</td></tr>)}</tbody></table>
          )}
          <h2>Running services</h2>
          {units.length === 0 ? <p className="muted">None reported.</p> : <p className="small">{units.map((u) => u.name).join(", ")}</p>}
        </section>
        <section className="card">
          <h2>Application directory listing</h2>
          <p className="muted small">Names only, from directories listed in the agent config. Sensitive names are excluded.</p>
          {data.paths.length === 0 ? <p className="muted">No directories configured.</p> : (
            <ul className="paths scroll">{data.paths.map((p) => <li key={p.path}><code>{p.path}{p.is_dir ? "/" : ""}</code></li>)}</ul>
          )}
        </section>
      </div>
      <section className="card">
        <h2>Assets on this host</h2>
        {assets.data ? (assets.data.items.length ? <AssetTable items={assets.data.items} /> : <p className="muted">No assets yet.</p>) : <Loading />}
        {assets.data && assets.data.total > 200 && <p><Link to={`/assets?host_id=${id}`}>Showing 200 of {assets.data.total}</Link></p>}
      </section>
      <section className="card">
        <h2>Report history</h2>
        {data.runs.length === 0 ? <p className="muted">No reports yet.</p> : (
          <table className="table compact"><tbody>{data.runs.map((r) => (
            <tr key={r.id}><td><Link to={`/scans/${r.id}`}>#{r.id}</Link></td><td><Status s={r.status} /></td>
              <td>{r.summary?.packages ?? "-"} packages</td><td><When iso={r.finished_at ?? r.created_at} /></td></tr>
          ))}</tbody></table>
        )}
      </section>
    </>
  );
}
