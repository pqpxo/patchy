import { useEffect, useState } from "react";
import { del, get, post, put, type Asset, type AssetDetail, type Page } from "../api";
import { Icon } from "../icons";
import { TYPES, label, safeUrl, versionText } from "../format";
import { usePrefs, NAME } from "../prefs";
import { AssetTable, FindingTable } from "../tables";
import {
  CheckState, DangerButton, Empty, ErrorBox, Eol, Field, KV, Link, PageHead, Pager, Skeleton, Tabs, When, errText,
  fieldErrors, navigate, toast, useLoad, useQueryParam, useSort,
} from "../ui";

const ECOSYSTEMS = ["PyPI", "npm", "Go", "crates.io", "Packagist", "Maven", "RubyGems", "NuGet"];

export function AssetsPage() {
  const [q, setQ] = useQueryParam("q");
  const [type, setType] = useQueryParam("type");
  const [source, setSource] = useQueryParam("source");
  const [eolState, setEol] = useQueryParam("eol_state");
  const [vuln, setVuln] = useQueryParam("vulnerable");
  const [missing, setMissing] = useQueryParam("missing");
  const [page, setPage] = useQueryParam("page");
  const [hostId] = useQueryParam("host_id");
  const [repoId] = useQueryParam("repository_id");
  const sort = useSort("name");
  const { pageSize } = usePrefs();
  const [search, setSearch] = useState(q);
  const { data, error, loading, reload } = useLoad(() => get<Page<Asset>>("/api/assets", {
    q, component_type: type, source, vulnerable_only: vuln === "1", include_missing: missing === "1", page: page || 1,
    host_id: hostId, repository_id: repoId, eol_state: eolState ? [eolState] : undefined,
    sort: sort.sort, order: sort.order, page_size: pageSize,
  }), [q, type, source, vuln, missing, page, hostId, repoId, eolState, sort.sort, sort.order, pageSize]);

  const tools = (
    <>
      <form role="search" onSubmit={(e) => { e.preventDefault(); setQ(search); }}>
        <input type="search" aria-label="Search by name" placeholder="Search name…" value={search}
          onChange={(e) => { setSearch(e.target.value); if (!e.target.value) setQ(""); }} maxLength={200} />
      </form>
      <select aria-label="Type" value={type} onChange={(e) => setType(e.target.value)}>
        <option value="">All types</option>
        {Object.entries(TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select>
      <select aria-label="Source" value={source} onChange={(e) => setSource(e.target.value)}>
        <option value="">All sources</option><option value="manual">Manual</option><option value="repo">Repository</option>
        <option value="agent">Agent</option><option value="demo">Demo</option>
      </select>
      <select aria-label="Support" value={eolState} onChange={(e) => setEol(e.target.value)}>
        <option value="">Any support state</option><option value="eol">End of life</option><option value="eol_soon">EOL soon</option>
        <option value="supported">Supported</option>
      </select>
      <label className="check"><input type="checkbox" checked={vuln === "1"} onChange={(e) => setVuln(e.target.checked ? "1" : "")} /> Vulnerable</label>
      <label className="check"><input type="checkbox" checked={missing === "1"} onChange={(e) => setMissing(e.target.checked ? "1" : "")} /> Include removed</label>
    </>
  );
  return (
    <>
      <PageHead title="Assets" sub="Every tracked language, library, server, package and image."
        actions={<Link to="/assets/new" className="btn primary"><Icon name="plus" size={14} /> Add asset</Link>} />
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Skeleton /> : data && <>
        <AssetTable items={data.items} sort={sort} tools={tools} />
        {data.items.length === 0 && <Empty title="No assets match.">Change the filters, add one manually, scan a repository or enrol a host agent.</Empty>}
        <Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} />
      </>}
    </>
  );
}

type Form = Record<string, string>;
const BLANK: Form = { name: "", component_type: "application", vendor: "", ecosystem: "", version: "", version_status: "exact",
  host_name: "", host_ip: "", listen_ip: "", port: "", protocol: "", install_path: "", repository_url: "", branch: "", cpe: "", notes: "" };

export function AssetForm({ id }: { id?: number }) {
  const [f, setF] = useState<Form>(BLANK);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [detected, setDetected] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!id) return;
    get<AssetDetail>(`/api/assets/${id}`).then((a) => {
      setDetected(a.source !== "manual");
      setF({ ...BLANK, ...Object.fromEntries(Object.entries({
        name: a.name, component_type: a.component_type, vendor: a.vendor, ecosystem: a.ecosystem, version: a.version ?? a.version_spec,
        version_status: a.version_status === "unknown" ? "exact" : a.version_status, host_name: a.host_name, host_ip: a.host_ip,
        listen_ip: a.listen_ip, port: a.port, protocol: a.protocol, install_path: a.install_path,
        repository_url: a.repository_url, cpe: a.cpe, notes: a.notes,
      }).map(([k, v]) => [k, v == null ? "" : String(v)])) });
    }).catch((e) => setError(errText(e)));
  }, [id]);
  const set = (k: string) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const input = (k: string, props: Record<string, unknown> = {}) =>
    <input value={f[k]} onChange={set(k)} disabled={detected && k !== "notes"} aria-invalid={!!errors[k]} {...props} />;

  return (
    <>
      <PageHead title={id ? "Edit asset" : "Add asset"} crumbs={[["Assets", "/assets"]]}
        sub={detected ? "This asset was discovered by a scan; only notes can be edited." : undefined} />
      <form className="card form" onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true); setErrors({}); setError("");
        const body: Record<string, unknown> = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.trim() === "" ? null : v.trim()]));
        body.port = f.port ? Number(f.port) : null;
        body.version_status = f.version ? f.version_status : "unknown";
        try {
          const a = id ? await put<Asset>(`/api/assets/${id}`, body) : await post<Asset>("/api/assets", body);
          toast(id ? "Asset saved." : "Asset added.");
          navigate(`/assets/${a.id}`);
        } catch (err) {
          setErrors(fieldErrors(err)); setError(errText(err));
        } finally { setBusy(false); }
      }}>
        <div className="form-grid">
          <Field label="Name *" error={errors.name}>{input("name", { required: true, maxLength: 255 })}</Field>
          <Field label="Type *" error={errors.component_type}>
            <select value={f.component_type} onChange={set("component_type")} disabled={detected}>
              {Object.entries(TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          <Field label="Ecosystem" hint="Needed for OSV matching. Leave blank if none applies." error={errors.ecosystem}>
            <select value={f.ecosystem} onChange={set("ecosystem")} disabled={detected}>
              <option value="">None / not a package</option>
              {ECOSYSTEMS.map((e) => <option key={e}>{e}</option>)}
            </select>
          </Field>
          <Field label="Vendor" error={errors.vendor}>{input("vendor", { maxLength: 255 })}</Field>
          <Field label="Version" hint="Leave blank if unknown. Unknown versions are flagged, not treated as safe." error={errors.version}>{input("version", { maxLength: 200 })}</Field>
          <Field label="Version is" error={errors.version_status}>
            <select value={f.version_status} onChange={set("version_status")} disabled={detected || !f.version}>
              <option value="exact">Exact installed version</option><option value="constraint">Approximate / range</option>
            </select>
          </Field>
          <Field label="CPE product" error={errors.cpe}
            hint={<>Optional <code>vendor:product</code> from NVD, for apps OSV doesn't cover (for example <code>home-assistant:home-assistant</code>).</>}>
            {input("cpe", { maxLength: 200, placeholder: "vendor:product", pattern: "[A-Za-z0-9_.\\-]+:[A-Za-z0-9_.\\-]+" })}
          </Field>
          <Field label="Host name" hint="Creates the host if it doesn't exist." error={errors.host_name}>{input("host_name", { maxLength: 255 })}</Field>
          <Field label="Host IP" error={errors.host_ip}>{input("host_ip", { maxLength: 64, inputMode: "decimal" })}</Field>
          <Field label="Listening IP" error={errors.listen_ip}>{input("listen_ip", { maxLength: 64 })}</Field>
          <Field label="Port" error={errors.port}>{input("port", { type: "number", min: 1, max: 65535 })}</Field>
          <Field label="Protocol" error={errors.protocol}>
            <select value={f.protocol} onChange={set("protocol")} disabled={detected}><option value="">-</option><option>tcp</option><option>udp</option></select>
          </Field>
          <Field label="Install path" error={errors.install_path}>{input("install_path", { maxLength: 1024 })}</Field>
          <Field label="GitHub repository URL" error={errors.repository_url}>{input("repository_url", { maxLength: 300, placeholder: "https://github.com/owner/repo" })}</Field>
          <Field label="Branch" error={errors.branch}>{input("branch", { maxLength: 200 })}</Field>
        </div>
        <Field label="Notes" error={errors.notes}><textarea rows={3} value={f.notes} onChange={set("notes")} maxLength={5000} /></Field>
        {error && <div className="alert bad" role="alert">{error}</div>}
        <div className="actions">
          <button className="btn primary" disabled={busy}>{busy ? "Saving…" : "Save"}</button>
          <Link to={id ? `/assets/${id}` : "/assets"} className="btn">Cancel</Link>
        </div>
      </form>
    </>
  );
}

const NO_FINDINGS: Record<string, string> = {
  no_known_vulns: "No advisory matches this exact version as of the last check.",
  stale: "No matches at the last check, but feed data is stale. Refresh feeds before relying on this.",
  not_checked_yet: "Not checked yet. Run a feed refresh.",
  version_unknown: `No findings, but the version is unknown so ${NAME} cannot confirm this is unaffected.`,
  not_checkable: "No supported vulnerability source covers this component. Add a CPE product to check it against NVD.",
};

export function AssetDetailPage({ id }: { id: number }) {
  const { data: a, error, reload } = useLoad(() => get<AssetDetail>(`/api/assets/${id}`), [id]);
  const [tab, setTab] = useQueryParam("tab");
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!a) return <Skeleton />;
  const details = a.details ?? {};
  const eolLink = safeUrl(a.eol?.link);
  const open = a.findings.filter((f) => f.currently_matching && (f.status === "open" || f.status === "acknowledged")).length;
  const where = a.host_id ? { label: a.host_name, to: `/hosts/${a.host_id}?tab=fix` }
    : a.repository_id ? { label: a.repository_label, to: `/repositories/${a.repository_id}?tab=fix` } : null;
  return (
    <>
      <PageHead title={a.name} crumbs={[["Assets", "/assets"]]}
        sub={<>{label(TYPES, a.component_type)}{a.ecosystem && ` · ${a.ecosystem}`} · <span className="ver">{versionText(a.version, a.version_status, a.version_spec)}</span></>}
        meta={<><CheckState s={a.check_state} /><Eol s={a.eol_state} info={a.eol} quiet={false} /></>}
        actions={<>
          <Link to={`/assets/${a.id}/edit`} className="btn">Edit</Link>
          <DangerButton question={`Delete ${a.name}? Its findings and history are removed too.`}
            onConfirm={async () => { await del(`/api/assets/${a.id}`); toast("Asset deleted."); navigate("/assets"); }}>Delete</DangerButton>
        </>} />
      {a.missing_since && <div className="alert warn">Not present in the latest scan (since <When iso={a.missing_since} />). Its findings were auto-resolved.</div>}
      <Tabs value={tab || "overview"} onChange={setTab} tabs={[
        ["overview", "Overview"], ["findings", <>Findings <span className="num">{open}</span></>], ["history", "History"],
      ]} />
      {(tab || "overview") === "overview" && <div className="grid two">
        <section className="card">
          <h2>Details</h2>
          <KV rows={[
            ["Version", <span className="ver">{versionText(a.version, a.version_status, a.version_spec)}</span>],
            ["Version status", a.version_status],
            ["Ecosystem", a.ecosystem],
            ["Matched as", a.source_package && a.source_package !== a.name ? `${a.source_package} (source package)` : null],
            ["CPE product", a.cpe ? <code>{a.cpe}</code> : null],
            ["Vendor", a.vendor],
            ["Host", a.host_id ? <Link to={`/hosts/${a.host_id}`}>{a.host_name}</Link> : null],
            ["Host IP", a.host_ip],
            ["Listening", a.port ? `${a.listen_ip ?? "*"}:${a.port}/${a.protocol}` : null],
            ["Repository", a.repository_id ? <Link to={`/repositories/${a.repository_id}`}>{a.repository_label}</Link> : null],
            ["Source", `${a.source} (${a.detection})`],
            ["Last scanned", <When iso={a.last_scanned_at} />],
            ["Vulnerability check", a.vuln_checked_at ? <When iso={a.vuln_checked_at} /> : "not yet"],
          ]} />
          {Array.isArray(details.binaries) && <p className="small">Installed binary packages: {(details.binaries as string[]).join(", ")}</p>}
          {typeof details.note === "string" && <p className="small muted">{details.note}</p>}
          {a.notes && <><h3>Notes</h3><p className="pre">{a.notes}</p></>}
        </section>
        <div className="stack">
          {a.eol && (
            <section className="card">
              <h2>Support</h2>
              <KV rows={[
                ["Product", a.eol.label], ["Release cycle", a.eol.cycle], ["Support ends", a.eol.eol_from ?? "not announced"],
                ["Latest in cycle", a.eol.latest_in_cycle], ["Newest supported", a.eol.newest_supported],
              ]} />
              {eolLink && <p className="small"><a href={eolLink} target="_blank" rel="noopener noreferrer">endoflife.date <Icon name="external" size={12} /></a></p>}
            </section>
          )}
          <section className="card">
            <h2>Paths</h2>
            {a.paths.length === 0 ? <p className="muted">No file or folder paths recorded.</p> : (
              <ul className="paths">{a.paths.map((p) => <li key={p.path}><code>{p.path}</code> <span className="muted small">{p.kind}</span></li>)}</ul>
            )}
          </section>
        </div>
      </div>}
      {tab === "findings" && (a.findings.length > 0 ? <>
        {where && open > 0 && <div className="alert info"><Icon name="fix" /> <span>Upgrade steps for this asset are in the <Link to={where.to}>{where.label} fix plan</Link>.</span></div>}
        <FindingTable items={a.findings} showAsset={false} table="asset-findings" />
      </> : <Empty title="No findings.">{NO_FINDINGS[a.check_state] ?? ""}</Empty>)}
      {tab === "history" && (a.history.length === 0 ? <Empty title="No scan history.">Entered manually.</Empty> : (
        <div className="table-wrap"><table className="table compact"><thead><tr><th>Scan</th><th>Version seen</th><th>When</th></tr></thead>
          <tbody>{a.history.map((h) => (
            <tr key={h.scan_run_id + h.seen_at}><td><Link to={`/scans/${h.scan_run_id}`}>#{h.scan_run_id}</Link> {h.kind}</td>
              <td className="ver">{h.version ?? "unknown"}</td><td><When iso={h.seen_at} /></td></tr>
          ))}</tbody></table></div>
      ))}
    </>
  );
}
