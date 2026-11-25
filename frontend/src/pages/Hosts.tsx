import { useEffect, useRef, useState } from "react";
import { del, get, post, qs, type AddedApp, type Agent, type Asset, type Container, type Finding, type Host, type HostUpdates, type Page, type ScanRun,
  type UpgradeRun } from "../api";
import { Icon } from "../icons";
import { fmtDate, safeUrl } from "../format";
import { usePrefs } from "../prefs";
import { AssetTable, FindingTable } from "../tables";
import {
  CodeBlock, DangerButton, DataTable, Empty, Eol, ErrorBox, Exposure, Field, KV, Kev, Link, PageHead, Pager, RunBanner, Sev, Skeleton, Status,
  TAB_PAGE, TabPager, Tabs, When, errText, fieldErrors, navigate, toast, useLoad, usePage, useQueryParam, useSort, type Col,
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
  { id: "updates", label: "Updates", hidden: true, cell: (h) => h.pending_updates == null ? <span className="muted">-</span> : <>
    <span className="num">{h.pending_updates}</span>{h.security_updates > 0 && <span className="badge tone-bad">{h.security_updates} security</span>}
    {h.reboot_required && <span className="badge tone-warn">Reboot</span>}
  </> },
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
  if (!a) return <span className="badge tone-muted">None</span>;
  if (a.revoked_at) return <span className="badge tone-bad">Revoked</span>;
  return <><span className="badge tone-good">Active</span>{outdated && <span className="badge tone-warn" title="Older than the agent bundled with this server. See the update command on the host page.">Update</span>}</>;
}

const DOCKER_ON = [
  "sudo usermod -aG docker patchy-agent",
  `sudo sed -i 's/"docker_images": false/"docker_images": true/' /etc/patchy-agent/config.json`,
].join("\n");

const SYFT_ON = "sudo rm -f /usr/local/lib/patchy-agent/syft.declined && cd ~/patchy-agent && sudo sh install.sh";
const UPGRADES_ASK = "sudo rm -f /etc/patchy-agent/upgrades && cd ~/patchy-agent && sudo sh install.sh";
const APT_UPGRADE = "sudo apt-get update && sudo apt-get upgrade";

type ImageSummary = { packages: number; total: number; worst: string | null; kev: boolean };

const longDate = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });

const agentAtLeast = (v: string | null | undefined, major: number, minor: number) => {
  const [a, b] = (v ?? "").split(".").map(Number);
  return a > major || (a === major && b >= minor);
};

/** Agents before 1.2 have no 5-minute poll, so they never see a Rescan. Unknown (never reported) counts as able. */
const ignoresRescan = (v?: string | null) => !!v && !agentAtLeast(v, 1, 2);

function ImageFindings({ s, c, host, onScan }: { s?: ImageSummary; c: Container; host: Host; onScan: (imageId: string) => void }) {
  const known = host.image_scans?.[c.image];
  if (!s) {
    if (c.image_id && host.image_scan_requests?.includes(c.image_id))
      return <><span className="badge tone-info">Queued</span>
        <div className="cell-sub">{known && known.image_id !== c.image_id ? "new image, " : ""}within 5 minutes</div></>;
    if (c.image_id && host.agent && !host.agent.revoked_at && agentAtLeast(host.agent.agent_version, 1, 4))
      return <button className="btn small" onClick={() => onScan(c.image_id!)} title="List this image's packages on the host and check them for vulnerabilities">Scan</button>;
    return <span className="muted">Not scanned</span>;
  }
  return <>
    {s.total ? <span><Sev s={s.worst} /> <span className="num">{s.total}</span> <Kev on={s.kev} /></span>
      : <span className="badge tone-good">None found</span>}
    <div className="cell-sub">{s.packages} package{s.packages === 1 ? "" : "s"}
      {known && known.image_id === c.image_id && <>, scanned <When iso={known.scanned_at} /></>}
      , <a href={`/api/sbom${qs({ host_id: host.id, image: c.image })}`} download title="CycloneDX SBOM of this image's packages">SBOM</a></div>
  </>;
}

function ContainersCard({ host, items, images, updates, docker, onChange }: {
  host: Host; items: Container[]; images: Record<string, ImageSummary>; updates: Record<string, { checked_at: string | null }>;
  docker: boolean; onChange: () => void;
}) {
  const scan = async (imageId: string) => {
    try { await post(`/api/hosts/${host.id}/images/scan`, { image_id: imageId }); toast("Scan requested. The agent picks it up within 5 minutes."); onChange(); }
    catch (e) { toast(errText(e), "bad"); }
  };
  const canScan = !!host.agent && !host.agent.revoked_at && agentAtLeast(host.agent.agent_version, 1, 4);
  const unscanned = new Set(items.filter((c) => c.image_id && !images[c.image] && !host.image_scan_requests?.includes(c.image_id))
    .map((c) => c.image_id)).size;
  const scanAll = async () => {
    try { await post(`/api/hosts/${host.id}/images/scan-all`, {}); toast(`${unscanned} image${unscanned === 1 ? "" : "s"} queued. The agent starts within 5 minutes; anything it can't finish in one run carries over to the next.`); onChange(); }
    catch (e) { toast(errText(e), "bad"); }
  };
  return (
    <section className="card wide">
      <div className="card-head"><h2>Containers <span className="num muted">{items.length}</span></h2>
        {canScan && unscanned > 0 && <button className="btn small" onClick={scanAll}
          title="Queue every image that hasn't been scanned. Each one uses a CPU core on the host while it is read.">Scan all ({unscanned})</button>}</div>
      {items.length === 0 ? (docker ? <>
        <p className="muted">None reported. To list containers, give the agent Docker access on the host (root-equivalent), then press Rescan:</p>
        <CodeBlock code={DOCKER_ON} />
      </> : <p className="muted">Docker isn't running on this host.</p>) : (
        <div className="table-wrap"><table className="table compact">
          <thead><tr><th>Name</th><th>Image</th><th>Image vulnerabilities</th><th>State</th><th>Ports</th><th>Volumes and mounts</th></tr></thead>
          <tbody>{items.map((c, i) => (
            <tr key={c.name ?? i}>
              <td><strong>{c.name ?? "unnamed"}</strong>
                {c.compose_project && <div className="cell-sub">{c.compose_project}{c.compose_service ? ` / ${c.compose_service}` : ""}</div>}</td>
              <td><span className="ver">{c.image}</span>
                {updates[c.name ?? c.image] && <> <span className="badge tone-info" title="The registry has a newer build of this tag. Pull and recreate the container to use it.">Newer image</span></>}
                {c.version && <div className="cell-sub">version {c.version}</div>}</td>
              <td className="nowrap"><ImageFindings s={images[c.image]} c={c} host={host} onScan={scan} /></td>
              <td><span className={`badge ${c.state === "running" ? "tone-good" : "tone-muted"}`}>{c.state ? c.state[0].toUpperCase() + c.state.slice(1) : "Unknown"}</span>
                {c.status && <div className="cell-sub">{c.status}</div>}</td>
              <td className="num nowrap">{c.ports.length ? c.ports.map((p, j) =>
                <div key={j}>{p.public ? <>{p.public} <span className="muted">→</span> {p.private}</> : p.private}<span className="muted">/{p.type}</span></div>)
                : <span className="muted">none</span>}</td>
              <td>{c.mounts.length ? <ul className="mounts">{c.mounts.map((m, j) => (
                <li key={j}>{m.type === "volume" && m.name && <span className="muted">{m.name.length > 24 ? "volume" : m.name}: </span>}
                  <code>{m.source ?? "hidden"}</code> <span className="muted">→</span> <code>{m.destination}</code>
                  {!m.rw && <span className="badge tone-muted">Read-only</span>}</li>
              ))}</ul> : <span className="muted">none</span>}</td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
      {items.length > 0 && <p className="muted small gap-top">{canScan
        ? "Scan lists an image's packages on the host and checks them for vulnerabilities. The agent starts within 5 minutes and a large image can take a few more. When a scanned image is replaced by a pull or rebuild, the new one is scanned automatically. It needs Syft on the host; the ? on the Agent card shows how to add it."
        : "To scan container images on request, update the agent to 1.4 or later from the Agent card."}</p>}
    </section>
  );
}

function AppsCard({ host, items }: { host: Host; items: AddedApp[] }) {
  return (
    <section className="card wide">
      <h2>Added software <span className="num muted">{items.length}</span></h2>
      <p className="muted small">Installed on top of the base OS: packages someone chose to install, plus Snap and Flatpak apps. Base system packages are left out.</p>
      {items.length === 0 ? <p className="muted">{!host.agent || host.agent_outdated ? "Needs agent 1.2 or later." : "None found."}</p> : (
        <div className="scroll-box"><table className="table compact">
          <thead><tr><th>Name</th><th>Version</th><th>Installed with</th></tr></thead>
          <tbody>{items.map((a) => (
            <tr key={`${a.manager}:${a.name}`}>
              <td><Link to={`/assets?host_id=${host.id}&q=${encodeURIComponent(a.name)}`}>{a.name}</Link></td>
              <td className="ver">{a.version ?? <span className="muted">-</span>}</td>
              <td>{a.manager === "dpkg" ? "apt" : a.manager[0].toUpperCase() + a.manager.slice(1)}</td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
    </section>
  );
}

function AgentHelp() {
  const ref = useRef<HTMLDialogElement>(null);
  return <>
    <button type="button" className="btn help-btn" title="About the agent" aria-label="About the agent" onClick={() => ref.current?.showModal()}>?</button>
    <dialog ref={ref} className="sheet" aria-labelledby="agent-help-title" onClick={(e) => { if (e.target === ref.current) ref.current.close(); }}>
      <div className="card-head"><h2 id="agent-help-title">About the agent</h2>
        <button type="button" className="icon-btn" aria-label="Close" onClick={() => ref.current?.close()}><Icon name="close" /></button></div>
      <p>A small Python script that keeps this host's inventory current. It runs every 6 hours (and a few minutes after boot) and sends one report to Patchy.</p>
      <h3>What it collects</h3>
      <ul>
        <li>Installed OS packages, which Patchy checks against OSV.</li>
        <li>Listening ports and running services.</li>
        <li>Versions of common servers and runtimes, such as nginx, OpenSSH, OpenSSL, Python and Node.js.</li>
        <li>Software added to the base OS: packages someone chose to install, plus Snap and Flatpak apps.</li>
        <li>Pending apt updates, from a simulated <code>apt-get upgrade</code> that changes nothing, and whether a reboot is waiting.</li>
        <li>Optional: Docker containers (name, image, state, ports and mount locations), and file names in folders listed under <code>app_dirs</code>.</li>
      </ul>
      <h3>How it stays safe</h3>
      <ul>
        <li>It only connects out to this server and opens no ports. It changes nothing on the host, unless you allow Run upgrade (below).</li>
        <li>It runs as the unprivileged <code>patchy-agent</code> user in a locked-down systemd service.</li>
        <li>The token is shown once. Patchy stores only a hash; the host keeps it in <code>/etc/patchy-agent/token</code>.</li>
      </ul>
      <h3>States</h3>
      <ul>
        <li><strong>Active</strong>: enrolled and allowed to report.</li>
        <li><strong>Update</strong>: this server bundles a newer agent. Run the update command shown on this card.</li>
        <li><strong>Revoked</strong>: reports are rejected. Re-enrol to issue a new token.</li>
      </ul>
      <h3>Rescan</h3>
      <p><strong>Rescan</strong> re-checks this host's inventory against the latest vulnerability data straight away. Agents from 1.2 also check in every 5 minutes (every minute with Run upgrade allowed) and send a fresh report when a rescan is waiting.</p>
      <h3>Run upgrade</h3>
      <p>Off unless you allow it at install time (agent 1.6 and later, apt hosts only). Then a separate root service runs one fixed command,
        <code>apt-get update && apt-get upgrade</code>, when you press <strong>Run upgrade</strong> on the Updates tab. Patchy can't make it run
        anything else: the agent only touches a request file, and the service reads nothing but its timestamp. To change your answer:</p>
      <CodeBlock code={UPGRADES_ASK} />
      <h3>Docker containers</h3>
      <p>Reading the Docker socket needs the docker group, which is root-equivalent, so it is off unless you allow it at install time. To turn it on later:</p>
      <CodeBlock code={DOCKER_ON} />
      <p>With containers on, <strong>Scan</strong> on a container asks the agent to list the packages inside its image with Syft, so they are checked for vulnerabilities too. Each image is scanned once and kept until it changes. When a pull or rebuild (Watchtower, <code>docker compose pull</code>) replaces a scanned image, Patchy queues the new one automatically, so its scan isn't lost. <strong>Scan all</strong> queues every image not yet scanned. To scan every new image automatically instead, set <code>"image_scan": "auto"</code> under <code>collect</code> in the config. The installer offers Syft once. To add it later:</p>
      <CodeBlock code={SYFT_ON} />
      <h3>Rotate or revoke</h3>
      <p><strong>Rotate</strong> issues a new token and stops the old one at once; paste the new token into <code>/etc/patchy-agent/token</code>. <strong>Revoke</strong> stops the agent reporting.</p>
      <h3>Useful commands on the host</h3>
      <p>Open the agent's menu (agent 1.7 or later) to see its status, change what it collects, replace the token, update or remove it:</p>
      <CodeBlock code="sudo patchy-agent" />
      <p>Send a report now:</p><CodeBlock code="sudo systemctl start patchy-agent" />
      <p>Read the logs:</p><CodeBlock code="journalctl -u patchy-agent" />
      <p>Change what is collected:</p><CodeBlock code="sudo nano /etc/patchy-agent/config.json" />
      <p>Remove the agent, then revoke it here:</p><CodeBlock code="sudo sh ~/patchy-agent/uninstall.sh" />
    </dialog>
  </>;
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
      <div className="card-head"><h2>Agent</h2><AgentHelp /></div>
      {a ? (
        <KV rows={[
          ["State", <AgentBadge a={a} outdated={host.agent_outdated} />], ["Token ends", <code>…{a.token_hint}</code>], ["Created", fmtDate(a.created_at)],
          ["Rotated", a.rotated_at ? fmtDate(a.rotated_at) : "never"], ["Last seen", <When iso={a.last_seen_at} />],
          ["From IP", a.last_ip], ["Agent version", a.agent_version],
        ]} />
      ) : <p className="muted">No agent enrolled. Create a credential, then install the agent on this host.</p>}
      {host.agent_outdated && a && !a.revoked_at && !token && <div className="token-box">
        <div className="alert warn"><p><strong>Update available.</strong> This server bundles a newer agent. Run this on the host; it keeps the existing token and settings, so nothing needs rotating.</p>
          <details><summary>Update command</summary><CodeBlock code={install} /></details></div>
      </div>}
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
          <CodeBlock code={token} />
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

const WAITING = (r?: UpgradeRun) => r?.status === "queued" || r?.status === "sent";

function UpdatesTab({ host, onChange }: { host: Host; onChange: () => void }) {
  const { data, error, reload } = useLoad(() => get<HostUpdates>(`/api/hosts/${host.id}/updates`), [host.id],
    (d) => (WAITING(d?.runs[0]) ? 5000 : null));
  const last = data?.runs[0];
  const was = useRef<UpgradeRun | undefined>(undefined);
  useEffect(() => {  // a run that was waiting has finished: say so, and refresh the host (its update count changed)
    if (was.current && WAITING(was.current) && last?.id === was.current.id && !WAITING(last)) {
      toast(last.status === "succeeded" ? "Upgrade finished." : `Upgrade failed${last.note ? `: ${last.note}` : "."}`, last.status === "succeeded" ? "good" : "bad");
      onChange();
    }
    was.current = last;
  }, [last, onChange]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton />;
  const u = data.updates;
  if (!u) return <Empty title="No update information for this host.">
    {!host.agent ? "Enrol an agent on this host to see its pending updates."
      : agentAtLeast(host.agent.agent_version, 1, 6) ? <>Pending updates are listed for apt hosts (Debian, Ubuntu, Raspberry Pi OS). This host doesn't use apt,
        {" "}<code>updates</code> is turned off in the agent config, or apt couldn't list them (the latest report on the Reports tab says if so).</>
      : "Agents from 1.6 list pending apt updates. Update the agent from the Agent card on the Overview tab."}
  </Empty>;
  const pkgs = data.packages;
  const security = pkgs.filter((p) => p.security).length;
  const run = async () => {
    if (!window.confirm(`Run apt-get update && apt-get upgrade on ${host.name}? Packages are upgraded straight away and their services may restart.`)) return;
    try { await post(`/api/hosts/${host.id}/upgrade`); toast("Upgrade requested. The agent passes it on within a minute."); reload(); }
    catch (e) { toast(errText(e), "bad"); reload(); }
  };
  return <>
    <section className="card">
      <div className="card-head"><h2>Pending updates</h2>
        {data.can_upgrade && <button className="btn primary" onClick={run} disabled={WAITING(last)}
          title="apt-get update && apt-get upgrade on this host"><Icon name="download" size={14} /> Run upgrade</button>}</div>
      <div className="plan-summary">
        <div><b>{pkgs.length}</b><span>updates</span></div>
        <div><b>{security}</b><span>security</span></div>
        <div><b>{data.fixes}</b><span>open findings fixed</span></div>
        <div><b>{u.held_back.length}</b><span>kept back</span></div>
      </div>
      <p className="small muted">As of the last report, <When iso={u.reported_at} />. Package lists refreshed <When iso={u.lists_at} />;
        apt's daily timer keeps them current, and Run upgrade refreshes them first.</p>
      {u.failed_at && <div className="alert warn"><p><strong>Out of date.</strong> The report <When iso={u.failed_at} /> couldn't list pending updates,
        so this list is from <When iso={u.reported_at} />. To see why, run <code>apt-get -s upgrade</code> on the host.</p></div>}
      {WAITING(last) && <div className="alert info run" role="status" aria-live="polite"><span className="spin" aria-hidden="true" />
        <span className="grow">{last!.status === "queued"
          ? <>Upgrade requested by {last!.requested_by} <When iso={last!.requested_at} />. Waiting for the agent, which checks in every minute.</>
          : <>Upgrading since <When iso={last!.sent_at} />. The result appears here when apt finishes.</>}</span></div>}
      {u.reboot_required && <div className="alert warn"><p><strong>Reboot needed</strong>{u.reboot_packages.length ? <> for {u.reboot_packages.join(", ")}</> : null}.
        Patchy doesn't reboot hosts; run <code>sudo reboot</code> when it suits.</p></div>}
      {!data.can_upgrade && <details>
        <summary>Run upgrade is off for this host</summary>
        <p className="small">Run this on the host yourself:</p><CodeBlock code={APT_UPGRADE} />
        <p className="small">Or allow Run upgrade (agent 1.6 or later). The installer asks again; answer <kbd>y</kbd>. It adds a root service that runs only
          <code> apt-get update && apt-get upgrade</code>, and only when you press the button here.</p><CodeBlock code={UPGRADES_ASK} />
      </details>}
    </section>
    {pkgs.length === 0 ? <Empty title="Up to date.">Nothing for apt-get upgrade to install.</Empty> : (
      <div className="table-wrap"><table className="table compact"><thead><tr><th>Package</th><th>Installed</th><th>Available</th>
        <th className="num" title="Open findings on this host that this version fixes">Fixes</th></tr></thead>
        <tbody>{pkgs.map((p) => <tr key={p.name}>
          <td className="nowrap">{p.name}{p.security && <span className="badge tone-bad">Security</span>}</td>
          <td className="num muted nowrap">{p.installed ?? "-"}</td><td className="num nowrap">{p.available}</td>
          <td className="num">{p.fixes || <span className="muted">-</span>}</td></tr>)}</tbody></table></div>
    )}
    {u.held_back.length > 0 && <p className="small muted gap-top">Kept back by apt, so Run upgrade leaves them alone: {u.held_back.join(", ")}.
      They need packages added or removed, or are being phased in. <code>sudo apt-get dist-upgrade</code> on the host installs them; check what it would remove first.</p>}
    {data.runs.length > 0 && <section className="card gap-top">
      <h2>Upgrade history</h2>
      {data.runs.map((r) => <details key={r.id} className="run-log">
        <summary><Status s={r.status === "sent" ? "running" : r.status} /> #{r.id} by {r.requested_by} <When iso={r.requested_at} />
          {r.exit_code != null && r.exit_code !== 0 && <span className="muted"> · exit code {r.exit_code}</span>}</summary>
        {r.note && <p className="small">{r.note}</p>}
        {r.output ? <CodeBlock code={r.output} wrap={false} /> : !r.note && <p className="small muted">{WAITING(r) ? "Still running." : "No output."}</p>}
      </details>)}
    </section>}
  </>;
}

type HostData = { host: Host; services: { name: string | null; protocol: string | null; listen_ip: string | null; port: number | null }[];
  paths: { root: string; path: string; is_dir: boolean }[]; runs: ScanRun[]; containers: Container[]; apps: AddedApp[]; images: Record<string, ImageSummary>;
  image_updates?: Record<string, { checked_at: string | null }> };

export function HostDetailPage({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => get<HostData>(`/api/hosts/${id}`), [id],
    (d) => (d?.host.rescan_requested_at || d?.host.image_scan_requests?.length ? 5000 : null));
  const [tab, setTab] = useQueryParam("tab");
  const t = tab || "overview";
  const aSort = useSort("name", "asc", true);
  const fSort = useSort("priority", "desc", true);
  const [aPage, setAPage] = usePage([id, aSort.sort, aSort.order]);
  const [fPage, setFPage] = usePage([id, fSort.sort, fSort.order]);
  const assets = useLoad(() => t === "assets" ? get<Page<Asset>>("/api/assets", { host_id: id, page: aPage, page_size: TAB_PAGE, sort: aSort.sort, order: aSort.order })
    : Promise.resolve(undefined), [id, t, aPage, aSort.sort, aSort.order]);
  const findings = useLoad(() => t === "findings" ? get<Page<Finding>>("/api/findings", { host_id: id, page: fPage, page_size: TAB_PAGE, status: ["open", "acknowledged"], sort: fSort.sort, order: fSort.order })
    : Promise.resolve(undefined), [id, t, fPage, fSort.sort, fSort.order]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return <Skeleton />;
  const h = data.host;
  const ports = data.services.filter((s) => s.port !== null);
  const units = data.services.filter((s) => s.port === null);
  const eolLink = safeUrl(h.os_eol?.link);
  const eolDate = typeof h.os_eol?.eol_from === "string" ? h.os_eol.eol_from : null;
  const canRescan = !!h.agent && !h.agent.revoked_at;
  const rescan = async () => {
    try {
      await post(`/api/hosts/${h.id}/rescan`);
      toast(h.agent_outdated ? "Findings re-checked. Update the agent so it can send a fresh report on request."
        : "Rescan requested. Findings re-checked; the agent sends a fresh report within 5 minutes.");
      reload();
    } catch (e) { toast(errText(e), "bad"); }
  };
  return (
    <>
      <PageHead title={h.name} crumbs={[["Hosts", "/hosts"]]}
        sub={<>{h.os_name ?? "OS unknown until an agent reports"}{h.ip && <> · <span className="num">{h.ip}</span></>}</>}
        meta={<><Exposure e={h.exposure} size="wide" /><Eol s={h.os_eol_state} info={h.os_eol} /><AgentBadge a={h.agent} outdated={h.agent_outdated} />
          <span className="small muted">reported <When iso={h.last_report_at} /></span></>}
        actions={<>
          {canRescan && <button className="btn" onClick={rescan} disabled={!!h.rescan_requested_at}
            title="Re-check findings now and ask the agent for a fresh report"><Icon name="refresh" size={14} /> Rescan</button>}
          <DangerButton question={`Delete host ${h.name} and all its assets and findings?`}
            onConfirm={async () => { await del(`/api/hosts/${h.id}`); toast("Host deleted."); navigate("/hosts"); }}>Delete host</DangerButton>
        </>} />
      {h.rescan_requested_at ? (
        <div className="alert info run" role="status" aria-live="polite"><span className="spin" aria-hidden="true" />
          <span className="grow">Rescan requested <When iso={h.rescan_requested_at} />. {ignoresRescan(h.agent?.agent_version)
            ? <>This agent version only reports on its 6-hour schedule. Update it from the Agent card, or run <code>sudo systemctl start patchy-agent</code> on the host.</>
            : "Waiting for the agent, which checks in every 5 minutes. Scanning new container images can add several minutes."}</span></div>
      ) : <RunBanner run={data.runs[0]} what="Report" />}
      {h.is_demo && <div className="alert warn">DEMO host with fictional data.</div>}
      <Tabs value={t} onChange={setTab} tabs={[
        ["overview", "Overview"], ["assets", <>Assets <span className="num">{h.component_count}</span></>],
        ["findings", <>Findings <span className="num">{h.open_findings}</span></>], ["fix", "Fixes"],
        ["updates", <>Updates {h.pending_updates != null && <span className="num">{h.pending_updates}</span>}</>], ["reports", "Reports"],
      ]} />
      {t === "overview" && <div className="host-grid">
        <section className="card">
          <h2>Host</h2>
          <KV rows={[["IP", h.ip], ["Reported hostname", h.reported_hostname], ["OS version", h.os_version], ["Kernel", h.kernel],
            ["Architecture", h.arch], ["Last report", <When iso={h.last_report_at} />],
            ["OS support", h.os_eol ? <span className="eol-line"><Eol s={h.os_eol_state} info={h.os_eol} quiet={false} />
              {eolDate && <span className="muted">{h.os_eol_state === "eol" ? "ended" : "until"} {longDate(eolDate)}</span>}
              {eolLink && <a href={eolLink} target="_blank" rel="noopener noreferrer" title="Support dates on endoflife.date"
                aria-label="Support dates on endoflife.date"><Icon name="external" size={13} /></a>}</span> : null]]} />
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
        <ContainersCard host={h} items={data.containers} images={data.images ?? {}} updates={data.image_updates ?? {}} docker={units.some((u) => u.name?.startsWith("docker."))} onChange={reload} />
        <AppsCard host={h} items={data.apps} />
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
        <TabPager data={assets.data} onPage={setAPage} />
      </> : <Skeleton />)}
      {t === "findings" && (findings.data ? (findings.data.items.length
        ? <><FindingTable items={findings.data.items} sort={fSort} showAsset={false} table="host-findings"
            tools={<a className="btn small" href={`/api/findings/export${qs({ host_id: id, status: ["open", "acknowledged"], sort: fSort.sort, order: fSort.order })}`} download>Export CSV</a>} />
          <TabPager data={findings.data} onPage={setFPage} /></>
        : <Empty title="No open findings on this host." />) : <Skeleton />)}
      {t === "fix" && <FixPlan hostId={id} />}
      {t === "updates" && <UpdatesTab host={h} onChange={reload} />}
      {t === "reports" && <>
        <section className="card">
          <div className="card-head"><h2>Software bill of materials</h2>
            <a className="btn small" href={`/api/sbom?host_id=${h.id}`} download><Icon name="download" size={14} /> Download SBOM</a></div>
          <p className="small muted">CycloneDX JSON of every package, image and asset on this host, with its open vulnerabilities.
            Use it with tools such as Dependency-Track, or keep it as a record of what was installed.</p>
        </section>
        {data.runs.length === 0 ? <Empty title="No reports yet." /> : (
          <div className="table-wrap"><table className="table compact"><thead><tr><th>Report</th><th>Status</th><th>Packages</th><th>When</th></tr></thead>
            <tbody>{data.runs.map((r) => (
              <tr key={r.id}><td><Link to={`/scans/${r.id}`}>#{r.id}</Link></td><td><Status s={r.status} /></td>
                <td className="num">{r.summary?.packages ?? "-"}</td><td><When iso={r.finished_at ?? r.created_at} /></td></tr>
            ))}</tbody></table></div>
        )}
      </>}
    </>
  );
}
