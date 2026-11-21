import { useEffect, useState } from "react";
import { del, get, post, put, type Asset, type AssetDetail, type Page } from "../api";
import { TYPES, label, versionText } from "../format";
import {
  CheckState, DangerButton, Empty, ErrorBox, Field, Kev, KV, Link, Loading, Match, PageHead, Pager, Sev, Status, When,
  errText, fieldErrors, navigate, useLoad, useQueryParam,
} from "../ui";

const ECOSYSTEMS = ["PyPI", "npm", "Go", "crates.io", "Packagist", "Maven", "RubyGems", "NuGet"];

export function AssetTable({ items }: { items: Asset[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Name</th><th>Version</th><th>Type</th><th>Location</th><th>Source</th><th>Vulnerability check</th><th>Findings</th></tr></thead>
        <tbody>{items.map((a) => (
          <tr key={a.id}>
            <td><Link to={`/assets/${a.id}`}>{a.name}</Link>{a.ecosystem && <div className="muted small">{a.ecosystem}</div>}</td>
            <td className={a.version_status !== "exact" ? "muted" : ""}>{versionText(a.version, a.version_status, a.version_spec)}</td>
            <td>{label(TYPES, a.component_type)}</td>
            <td>{a.host_name ?? a.repository_label ?? "-"}{a.port ? <span className="muted"> :{a.port}/{a.protocol}</span> : null}</td>
            <td>{a.source}</td>
            <td><CheckState s={a.check_state} /></td>
            <td>{a.open_findings ? <><Sev s={a.max_severity} /> {a.open_findings}</> : <span className="muted">0</span>}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function AssetsPage() {
  const [q, setQ] = useQueryParam("q");
  const [type, setType] = useQueryParam("type");
  const [source, setSource] = useQueryParam("source");
  const [vuln, setVuln] = useQueryParam("vulnerable");
  const [missing, setMissing] = useQueryParam("missing");
  const [page, setPage] = useQueryParam("page");
  const [hostId] = useQueryParam("host_id");
  const [repoId] = useQueryParam("repository_id");
  const [search, setSearch] = useState(q);
  const { data, error, loading, reload } = useLoad(() => get<Page<Asset>>("/api/assets", {
    q, component_type: type, source, vulnerable_only: vuln === "1", include_missing: missing === "1", page: page || 1,
    host_id: hostId, repository_id: repoId,
  }), [q, type, source, vuln, missing, page, hostId, repoId]);

  return (
    <>
      <PageHead title="Assets" sub="Every tracked language, library, server, package and image."
        actions={<Link to="/assets/new" className="btn primary">Add asset</Link>} />
      <form className="filters" role="search" onSubmit={(e) => { e.preventDefault(); setQ(search); }}>
        <input aria-label="Search by name" placeholder="Search name…" value={search} onChange={(e) => setSearch(e.target.value)} maxLength={200} />
        <select aria-label="Type" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">All types</option>
          {Object.entries(TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select aria-label="Source" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All sources</option><option value="manual">Manual</option><option value="repo">Repository</option>
          <option value="agent">Agent</option><option value="demo">Demo</option>
        </select>
        <label className="check"><input type="checkbox" checked={vuln === "1"} onChange={(e) => setVuln(e.target.checked ? "1" : "")} /> Vulnerable only</label>
        <label className="check"><input type="checkbox" checked={missing === "1"} onChange={(e) => setMissing(e.target.checked ? "1" : "")} /> Include removed</label>
        <button className="btn">Search</button>
      </form>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? (
        <Empty title="No assets match.">Add one manually, scan a repository or enrol a host agent.</Empty>
      ) : (
        <><AssetTable items={data.items} /><Pager page={data.page} total={data.total} size={data.page_size} onPage={(p) => setPage(String(p))} /></>
      ))}
    </>
  );
}

type Form = Record<string, string>;
const BLANK: Form = { name: "", component_type: "application", vendor: "", ecosystem: "", version: "", version_status: "exact",
  host_name: "", host_ip: "", listen_ip: "", port: "", protocol: "", install_path: "", repository_url: "", branch: "", notes: "" };

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
        repository_url: a.repository_url, notes: a.notes,
      }).map(([k, v]) => [k, v == null ? "" : String(v)])) });
    }).catch((e) => setError(errText(e)));
  }, [id]);
  const set = (k: string) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const input = (k: string, props: Record<string, unknown> = {}) =>
    <input value={f[k]} onChange={set(k)} disabled={detected && k !== "notes"} aria-invalid={!!errors[k]} {...props} />;

  return (
    <>
      <PageHead title={id ? "Edit asset" : "Add asset"} sub={detected ? "This asset was discovered by a scan; only notes can be edited." : undefined} />
      <form className="card form" onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true); setErrors({}); setError("");
        const body: Record<string, unknown> = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.trim() === "" ? null : v.trim()]));
        body.port = f.port ? Number(f.port) : null;
        body.version_status = f.version ? f.version_status : "unknown";
        try {
          const a = id ? await put<Asset>(`/api/assets/${id}`, body) : await post<Asset>("/api/assets", body);
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
          <Field label="Ecosystem" hint="Needed for vulnerability matching. Leave blank if none applies." error={errors.ecosystem}>
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

export function FindingTable({ items, showAsset = true }: { items: AssetDetail["findings"]; showAsset?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Severity</th><th>Advisory</th>{showAsset && <th>Asset</th>}<th>Match</th><th>Fixed in</th><th>Status</th></tr></thead>
        <tbody>{items.map((f) => (
          <tr key={f.id} className={f.currently_matching ? "" : "dim"}>
            <td><Sev s={f.advisory.severity} /> {f.advisory.cvss_score ?? ""}</td>
            <td><Link to={`/vulnerabilities/${f.id}`}>{f.advisory.id}</Link> <Kev on={f.advisory.kev} />
              <div className="small muted clamp">{f.advisory.summary}</div></td>
            {showAsset && <td><Link to={`/assets/${f.component_id}`}>{f.component_name}</Link> <span className="muted">{f.component_version}</span>
              <div className="small muted">{f.host_name ?? f.repository_label}</div></td>}
            <td><Match s={f.match_status} /></td>
            <td>{f.fixed_versions.length ? f.fixed_versions.slice(0, 3).join(", ") : <span className="muted">not listed</span>}</td>
            <td><Status s={f.status} />{!f.currently_matching && <div className="small muted">no longer matches</div>}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}


export function AssetDetailPage({ id }: { id: number }) {
  const { data: a, error, reload } = useLoad(() => get<AssetDetail>(`/api/assets/${id}`), [id]);
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!a) return <Loading />;
  const details = a.details ?? {};
  return (
    <>
      <PageHead title={a.name} sub={<>{label(TYPES, a.component_type)} · <CheckState s={a.check_state} /></>}
        actions={<>
          <Link to={`/assets/${a.id}/edit`} className="btn">Edit</Link>
          <DangerButton question={`Delete ${a.name}? Its findings and history are removed too.`}
            onConfirm={async () => { await del(`/api/assets/${a.id}`); navigate("/assets"); }}>Delete</DangerButton>
        </>} />
      {a.missing_since && <div className="alert warn">Not present in the latest scan (since <When iso={a.missing_since} />). Its findings were auto-resolved.</div>}
      <div className="grid two">
        <section className="card">
          <h2>Details</h2>
          <KV rows={[
            ["Version", versionText(a.version, a.version_status, a.version_spec)],
            ["Version status", a.version_status],
            ["Ecosystem", a.ecosystem],
            ["Matched as", a.source_package && a.source_package !== a.name ? `${a.source_package} (source package)` : null],
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
        <section className="card">
          <h2>Paths</h2>
          {a.paths.length === 0 ? <p className="muted">No file or folder paths recorded.</p> : (
            <ul className="paths">{a.paths.map((p) => <li key={p.path}><code>{p.path}</code> <span className="muted small">{p.kind}</span></li>)}</ul>
          )}
          <h2>Scan history</h2>
          {a.history.length === 0 ? <p className="muted">Manually entered; no scan history.</p> : (
            <table className="table compact"><tbody>{a.history.map((h) => (
              <tr key={h.scan_run_id + h.seen_at}><td><Link to={`/scans/${h.scan_run_id}`}>#{h.scan_run_id}</Link> {h.kind}</td>
                <td>{h.version ?? "unknown"}</td><td><When iso={h.seen_at} /></td></tr>
            ))}</tbody></table>
          )}
        </section>
      </div>
      <section className="card">
        <h2>Vulnerability findings</h2>
        {a.findings.length > 0 ? <FindingTable items={a.findings} showAsset={false} /> : (
          <p className="muted">{{
            no_known_vulns: "No advisory in OSV matches this exact version as of the last check.",
            stale: "No matches at the last check, but feed data is stale. Refresh feeds before relying on this.",
            not_checked_yet: "Not checked yet. Run a feed refresh.",
            version_unknown: "No findings, but the version is unknown so Patchy cannot confirm this is unaffected.",
            not_checkable: "No supported vulnerability source covers this component. Patchy cannot assess it.",
          }[a.check_state] ?? "No findings."}</p>
        )}
      </section>
    </>
  );
}
