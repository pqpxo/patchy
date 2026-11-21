import { useState } from "react";
import { get, post, type AuditEntry, type Feed, type Page } from "../api";
import { ErrorBox, Field, KV, Loading, PageHead, Pager, When, errText, useLoad } from "../ui";
import { FeedPanel } from "./Dashboard";

interface SettingsData {
  github_token_configured: boolean; nvd_api_key_configured: boolean; osv_enabled: boolean; kev_enabled: boolean;
  nvd_enabled: boolean; feed_refresh_hours: number; feed_stale_hours: number; cookie_secure: boolean;
  repo_limits: Record<string, number>;
  coverage: { local_version_comparison: string[]; osv_queried: string[]; inventory_only: string[] };
}

export default function SettingsPage() {
  const s = useLoad(() => get<SettingsData>("/api/settings"), []);
  const feeds = useLoad(() => get<Feed[]>("/api/feeds"), []);
  const [auditPage, setAuditPage] = useState(1);
  const audit = useLoad(() => get<Page<AuditEntry>>("/api/audit", { page: auditPage, page_size: 25 }), [auditPage]);
  const [pw, setPw] = useState({ current: "", next: "", again: "" });
  const [pwMsg, setPwMsg] = useState("");
  const yes = (b: boolean) => (b ? "Yes" : "No");

  return (
    <>
      <PageHead title="Settings" sub="Configuration is set with environment variables on the server (see .env.example). Secrets are never shown here." />
      <ErrorBox error={s.error ?? feeds.error} />
      <div className="grid two">
        {feeds.data ? <FeedPanel feeds={feeds.data} onRefreshed={feeds.reload} /> : <Loading />}
        <section className="card">
          <h2>Configuration</h2>
          {s.data ? <KV rows={[
            ["GitHub token configured", yes(s.data.github_token_configured)],
            ["NVD API key configured", yes(s.data.nvd_api_key_configured)],
            ["Feeds enabled", ["OSV", "KEV", "NVD"].filter((_, i) => [s.data!.osv_enabled, s.data!.kev_enabled, s.data!.nvd_enabled][i]).join(", ") || "none"],
            ["Periodic refresh", s.data.feed_refresh_hours ? `every ${s.data.feed_refresh_hours} h` : "off"],
            ["Stale after", `${s.data.feed_stale_hours} h`],
            ["Secure cookies", yes(s.data.cookie_secure)],
            ["Repo scan limits", `${s.data.repo_limits.max_manifests} manifests, ${Math.round(s.data.repo_limits.max_file_bytes / 1048576)} MB per file, ${s.data.repo_limits.timeout_seconds} s`],
          ]} /> : <Loading />}
        </section>
        <section className="card">
          <h2>What Patchy can and can't assess</h2>
          {s.data && <>
            <p><strong>Exact local version comparison:</strong> {s.data.coverage.local_version_comparison.join(", ")}.</p>
            <p><strong>Queried in OSV:</strong> {s.data.coverage.osv_queried.join(", ")}. Ecosystems without a local comparator rely on OSV's own version matching, otherwise results are shown as "possible".</p>
            <p><strong>Inventory only, no vulnerability source:</strong> {s.data.coverage.inventory_only.join("; ")}.</p>
          </>}
        </section>
        <section className="card">
          <h2>Change password</h2>
          <form className="form" onSubmit={async (e) => {
            e.preventDefault(); setPwMsg("");
            if (pw.next !== pw.again) return setPwMsg("New passwords do not match.");
            try {
              await post("/api/auth/password", { current_password: pw.current, new_password: pw.next });
              setPw({ current: "", next: "", again: "" }); setPwMsg("Password changed. Other sessions were signed out.");
            } catch (err) { setPwMsg(errText(err)); }
          }}>
            <Field label="Current password"><input type="password" autoComplete="current-password" required value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></Field>
            <Field label="New password" hint="At least 12 characters."><input type="password" autoComplete="new-password" minLength={12} maxLength={256} required value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} /></Field>
            <Field label="Repeat new password"><input type="password" autoComplete="new-password" required value={pw.again} onChange={(e) => setPw({ ...pw, again: e.target.value })} /></Field>
            <button className="btn primary">Change password</button>
            {pwMsg && <p role="status">{pwMsg}</p>}
          </form>
        </section>
      </div>
      <section className="card">
        <h2>Audit log</h2>
        {audit.data ? <>
          <div className="table-wrap"><table className="table compact">
            <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead>
            <tbody>{audit.data.items.map((x) => (
              <tr key={x.id}><td><When iso={x.at} /></td><td>{x.actor}</td><td>{x.action}</td>
                <td>{x.target_type ? `${x.target_type} ${x.target_id}` : "-"}</td>
                <td className="small"><code>{x.detail ? JSON.stringify(x.detail) : ""}</code></td><td>{x.ip}</td></tr>
            ))}</tbody>
          </table></div>
          <Pager page={audit.data.page} total={audit.data.total} size={audit.data.page_size} onPage={setAuditPage} />
        </> : <Loading />}
      </section>
    </>
  );
}
