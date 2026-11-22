import { useState, type ReactNode } from "react";
import { get, post, put, type AuditEntry, type Feed, type Page, type ScanRun } from "../api";
import { Icon } from "../icons";
import { HOURS_LABEL, safeUrl } from "../format";
import { FONTS, PAGE_SIZES, SCHEMES, resolvedMode, setPrefs, usePrefs, type Mode } from "../prefs";
import { CodeBlock, ErrorBox, Field, KV, PageHead, Pager, RunBanner, Skeleton, Switch, When, errText, toast, useLoad, useQueryParam } from "../ui";

interface SettingsData {
  github_token_configured: boolean; nvd_api_key_configured: boolean; feed_stale_hours: number; cookie_secure: boolean;
  repo_limits: Record<string, number>; hour_choices: number[]; version: string;
  worker: { version: string; started_at: string } | null;
  coverage: { local_version_comparison: string[]; osv_queried: string[]; nvd_products?: string; inventory_only: string[] };
}

const SECTIONS: [string, string][] = [
  ["appearance", "Appearance"], ["sources", "Sources and schedule"], ["system", "System"],
  ["account", "Account"], ["audit", "Audit log"], ["about", "About"],
];

function Appearance() {
  const p = usePrefs();
  const mode = resolvedMode(p);
  const modes: [Mode, string, string][] = [["system", "System", "settings"], ["day", "Day", "sun"], ["night", "Night", "moon"]];
  return (
    <>
      <section className="card">
        <div className="setting-row">
          <div><div className="label">Mode</div><div className="help">Day, night, or follow your device. Saved in this browser.</div></div>
          <div className="seg-ctl" role="group" aria-label="Mode">
            {modes.map(([id, l, icon]) => (
              <button key={id} aria-pressed={p.mode === id} onClick={() => setPrefs({ mode: id })}><Icon name={icon} size={14} />{l}</button>
            ))}
          </div>
        </div>
        <div className="setting-row">
          <div><div className="label">Density</div><div className="help">Compact fits more rows on screen.</div></div>
          <div className="seg-ctl" role="group" aria-label="Density">
            {(["comfortable", "compact"] as const).map((d) => (
              <button key={d} aria-pressed={p.density === d} onClick={() => setPrefs({ density: d })}>{d === "compact" ? "Compact" : "Comfortable"}</button>
            ))}
          </div>
        </div>
        <div className="setting-row">
          <div><div className="label">Rows per page</div><div className="help">Default for every table.</div></div>
          <select aria-label="Rows per page" value={p.pageSize} onChange={(e) => setPrefs({ pageSize: +e.target.value })}>
            {PAGE_SIZES.map((n) => <option key={n}>{n}</option>)}
          </select>
        </div>
        <div className="setting-row">
          <div><div className="label">Sidebar</div><div className="help">Icons only gives tables more room.</div></div>
          <Switch on={p.rail} onChange={(v) => setPrefs({ rail: v })} label="Icons-only sidebar" />
        </div>
      </section>
      <section className="card">
        <h2>Colour scheme</h2>
        <div className="themes">
          {SCHEMES.map((s) => (
            <button key={s.id} className="theme-card" data-scheme={s.id} data-mode={mode} aria-pressed={p.scheme === s.id}
              onClick={() => setPrefs({ scheme: s.id })}>
              <span className="pv" aria-hidden="true">
                <span className="pv-side"><i /><i /><i /></span>
                <span className="pv-main">
                  <span className="pv-panel"><i className="seg-critical" /><i className="seg-high" /><i className="seg-medium" /><i className="seg-low" /></span>
                  <span className="pv-line" /><span className="pv-line" />
                </span>
              </span>
              <span className="name">{s.label}<small>{s.note}</small></span>
            </button>
          ))}
        </div>
      </section>
      <section className="card">
        <h2>Font</h2>
        <p className="small muted">Uses fonts already on your device, so nothing is downloaded. Numbers and versions always use a monospaced font.</p>
        <div className="fonts">
          {FONTS.map((f) => (
            <button key={f.id} className="font-card" data-font={f.id} aria-pressed={p.font === f.id} onClick={() => setPrefs({ font: f.id })}>
              <span className="sample">Patch 1.2.3</span><small>{f.label}</small>
            </button>
          ))}
        </div>
      </section>
    </>
  );
}

function Sources({ choices }: { choices: number[] }) {
  const feeds = useLoad(() => get<Feed[]>("/api/feeds"), []);
  const runs = useLoad(() => get<Page<ScanRun>>("/api/scans", { kind: "feed", page_size: 1 }), [],
    (d) => (d?.items[0] && ["queued", "running"].includes(d.items[0].status) ? 2000 : null));
  const [busy, setBusy] = useState("");
  const save = async (source: string, change: { enabled?: boolean; hours?: number }) => {
    setBusy(source);
    try { await put("/api/settings/sources", { [source]: change }); toast("Schedule saved."); feeds.reload(); }
    catch (e) { toast(errText(e), "bad"); }
    finally { setBusy(""); }
  };
  const refresh = async (sources?: string[]) => {
    try { await post("/api/feeds/refresh", sources ? { sources } : {}); runs.reload(); }
    catch (e) { toast(errText(e), "bad"); }
  };
  if (feeds.error) return <ErrorBox error={feeds.error} onRetry={feeds.reload} />;
  if (!feeds.data) return <Skeleton rows={7} />;
  return (
    <section className="card">
      <div className="card-head">
        <h2>Vulnerability and support sources</h2>
        <button className="btn small" onClick={() => refresh()}><Icon name="refresh" size={14} /> Refresh all now</button>
      </div>
      <RunBanner run={runs.data?.items[0]} what="Refresh" onFinished={feeds.reload} />
      <p className="small muted">Each source refreshes on its own schedule. After a refresh, Patchy re-matches your inventory.
        Changes here override <code>FEED_REFRESH_HOURS</code> and the <code>*_ENABLED</code> variables.</p>
      <div className="sources">
        {feeds.data.map((f) => {
          const tone = !f.enabled ? "" : f.last_error ? "bad" : f.stale ? "warn" : "good";
          const facts = Object.entries(f.detail ?? {}).filter(([, v]) => typeof v === "number").slice(0, 3);
          return (
            <div key={f.source} className="src">
              <Switch on={f.enabled} disabled={!!f.unavailable || busy === f.source} label={`Enable ${f.label}`} onChange={(v) => save(f.source, { enabled: v })} />
              <div>
                <div className="src-title"><span className={`dot ${tone}`} />{f.label}
                  {f.enabled && f.stale && !f.last_error && <span className="badge tone-warn">Stale</span>}
                  {f.enabled && f.last_error && <span className="badge tone-bad">Error</span>}</div>
                <div className="small">{f.about}</div>
                {f.unavailable && <div className="small text-warn">{f.unavailable}</div>}
                {f.enabled && f.last_error && <div className="small text-bad">{f.last_error}</div>}
                <div className="src-meta">
                  <span>Last success <When iso={f.last_success_at} /></span>
                  {facts.map(([k, v]) => <span key={k}>{k.replace(/_/g, " ")}: <span className="num">{v as number}</span></span>)}
                </div>
              </div>
              <div className="src-ctl">
                <select aria-label={`${f.label} schedule`} value={f.hours} disabled={!f.enabled || busy === f.source}
                  onChange={(e) => save(f.source, { hours: +e.target.value })}>
                  {choices.map((h) => <option key={h} value={h}>{HOURS_LABEL(h)}</option>)}
                </select>
                <button className="btn small" disabled={!f.enabled} onClick={() => refresh([f.source])} title={`Refresh ${f.label} now`}>Refresh</button>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function System({ s }: { s: SettingsData }) {
  const yes = (b: boolean) => (b ? <span className="badge tone-good">Set</span> : <span className="badge tone-muted">Not set</span>);
  return (
    <div className="grid two">
      <section className="card">
        <h2>Server configuration</h2>
        <p className="small muted">Set with environment variables on the server (see <code>.env.example</code>). Secrets are never shown here.</p>
        <KV rows={[
          ["GITHUB_TOKEN", yes(s.github_token_configured)],
          ["NVD_API_KEY", yes(s.nvd_api_key_configured)],
          ["Stale after", `${s.feed_stale_hours} h (or twice the schedule)`],
          ["Secure cookies", s.cookie_secure ? "Yes" : "No"],
          ["Repo scan limits", `${s.repo_limits.max_manifests} manifests, ${Math.round(s.repo_limits.max_file_bytes / 1048576)} MB per file, ${s.repo_limits.timeout_seconds} s`],
        ]} />
      </section>
      <section className="card">
        <h2>What Patchy can and can't assess</h2>
        <p><strong>Exact local version comparison:</strong> {s.coverage.local_version_comparison.join(", ")}.</p>
        <p><strong>Queried in OSV:</strong> {s.coverage.osv_queried.join(", ")}.</p>
        {s.coverage.nvd_products && <p><strong>NVD product matching:</strong> {s.coverage.nvd_products}.</p>}
        <p><strong>Inventory only:</strong> {s.coverage.inventory_only.join("; ")}.</p>
      </section>
    </div>
  );
}

function Account() {
  const [pw, setPw] = useState({ current: "", next: "", again: "" });
  const [msg, setMsg] = useState("");
  return (
    <section className="card">
      <h2>Change password</h2>
      <form className="form narrow" onSubmit={async (e) => {
        e.preventDefault(); setMsg("");
        if (pw.next !== pw.again) return setMsg("New passwords do not match.");
        try {
          await post("/api/auth/password", { current_password: pw.current, new_password: pw.next });
          setPw({ current: "", next: "", again: "" }); toast("Password changed. Other sessions were signed out.");
        } catch (err) { setMsg(errText(err)); }
      }}>
        <Field label="Current password"><input type="password" autoComplete="current-password" required value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></Field>
        <Field label="New password" hint="At least 12 characters."><input type="password" autoComplete="new-password" minLength={12} maxLength={256} required value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /></Field>
        <Field label="Repeat new password"><input type="password" autoComplete="new-password" required value={pw.again} onChange={(e) => setPw({ ...pw, again: e.target.value })} /></Field>
        {msg && <div className="alert bad" role="alert">{msg}</div>}
        <button className="btn primary">Change password</button>
      </form>
    </section>
  );
}

function Audit() {
  const [page, setPage] = useState(1);
  const audit = useLoad(() => get<Page<AuditEntry>>("/api/audit", { page, page_size: 25 }), [page]);
  if (audit.error) return <ErrorBox error={audit.error} onRetry={audit.reload} />;
  if (!audit.data) return <Skeleton />;
  return (
    <>
      <div className="table-wrap"><table className="table compact">
        <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead>
        <tbody>{audit.data.items.map((x) => (
          <tr key={x.id}><td><When iso={x.at} /></td><td>{x.actor}</td><td>{x.action}</td>
            <td>{x.target_type ? `${x.target_type} ${x.target_id}` : "-"}</td>
            <td className="small"><code>{x.detail ? JSON.stringify(x.detail) : ""}</code></td><td className="num">{x.ip}</td></tr>
        ))}</tbody>
      </table></div>
      <Pager page={audit.data.page} total={audit.data.total} size={audit.data.page_size} onPage={setPage} sizes={false} />
    </>
  );
}

// Just enough Markdown for CHANGELOG.md: headings, bullets, bold, italics, code and links. Builds React nodes, never HTML.
function inline(text: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g).map((t, i) => {
    if (t.startsWith("**")) return <strong key={i}>{t.slice(2, -2)}</strong>;
    if (t.startsWith("`")) return <code key={i}>{t.slice(1, -1)}</code>;
    const link = t.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (link) { const u = safeUrl(link[2]); return u ? <a key={i} href={u} target="_blank" rel="noopener noreferrer">{link[1]}</a> : link[1]; }
    if (t.startsWith("*") && t.endsWith("*") && t.length > 2) return <em key={i}>{t.slice(1, -1)}</em>;
    return t;
  });
}

export function Changelog({ text }: { text: string }) {
  const out: ReactNode[] = [];
  let list: ReactNode[] = [];
  const flush = () => { if (list.length) { out.push(<ul key={out.length}>{list}</ul>); list = []; } };
  text.split("\n").forEach((line, i) => {
    const bullet = line.match(/^(\s*)- (.*)$/);
    if (bullet) { list.push(<li key={i} className={bullet[1] ? "nested" : undefined}>{inline(bullet[2])}</li>); return; }
    flush();
    if (line.startsWith("### ")) out.push(<h3 key={i}>{line.slice(4)}</h3>);
    else if (line.startsWith("## ")) out.push(<h2 key={i}>{line.slice(3)}</h2>);
    else if (line.startsWith("# ") || !line.trim()) return;
    else out.push(<p key={i} className="small muted">{inline(line)}</p>);
  });
  flush();
  return <div className="changelog">{out}</div>;
}

function About() {
  const v = useLoad(() => get<{ version: string; agent_version: string | null; changelog: string }>("/api/version"), []);
  if (v.error) return <ErrorBox error={v.error} onRetry={v.reload} />;
  if (!v.data) return <Skeleton />;
  return (
    <>
      <section className="card">
        <h2>Version</h2>
        <KV rows={[["Patchy", <span className="num">{v.data.version}</span>], ["Bundled agent", <span className="num">{v.data.agent_version ?? "unknown"}</span>]]} />
      </section>
      <section className="card">
        <h2>Changelog</h2>
        {v.data.changelog ? <Changelog text={v.data.changelog} /> : <p className="muted">CHANGELOG.md is not bundled with this build.</p>}
      </section>
    </>
  );
}

export default function SettingsPage() {
  const s = useLoad(() => get<SettingsData>("/api/settings"), []);
  const [tab, setTab] = useQueryParam("tab");
  const t = SECTIONS.some(([id]) => id === tab) ? tab : "appearance";
  return (
    <>
      <PageHead title="Settings" sub={s.data ? <>Patchy <span className="num">{s.data.version}</span></> : undefined} />
      <div className="settings">
        <nav className="settings-nav" aria-label="Settings sections">
          {SECTIONS.map(([id, label]) => <button key={id} aria-current={t === id} onClick={() => setTab(id)}>{label}</button>)}
        </nav>
        <div>
          <ErrorBox error={s.error} onRetry={s.reload} />
          {t === "appearance" && <Appearance />}
          {t === "sources" && s.data && s.data.worker?.version !== s.data.version && <div className="alert warn" role="alert">
            <p>{s.data.worker
              ? <>The worker is running Patchy <span className="num">{s.data.worker.version}</span> but the app is <span className="num">{s.data.version}</span>, so sources refresh with old code. On the server, in the Patchy folder, run:</>
              : <>The worker hasn't checked in since this update, so sources may not refresh. If this stays, run this on the server, in the Patchy folder:</>}</p>
            <CodeBlock code="docker compose up -d --force-recreate worker" />
          </div>}
          {t === "sources" && (s.data ? <Sources choices={s.data.hour_choices} /> : <Skeleton />)}
          {t === "system" && (s.data ? <System s={s.data} /> : <Skeleton />)}
          {t === "account" && <Account />}
          {t === "audit" && <Audit />}
          {t === "about" && <About />}
        </div>
      </div>
    </>
  );
}
