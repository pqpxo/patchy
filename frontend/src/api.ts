// Thin fetch wrapper: same-origin cookies, CSRF header on writes, consistent errors.

export class ApiError extends Error {
  constructor(public status: number, message: string, public fields: { loc: string[]; msg: string }[] = []) {
    super(message);
  }
}

let csrf = "";
export const setCsrf = (t: string) => (csrf = t);
let onUnauthorised: () => void = () => {};
export const setUnauthorisedHandler = (fn: () => void) => (onUnauthorised = fn);

type Params = Record<string, string | number | boolean | (string | number)[] | undefined | null>;

export function qs(params: Params = {}): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => u.append(k, String(x)));
    else u.append(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  const res = await fetch(path, {
    method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/api/auth/login")) onUnauthorised();
    throw new ApiError(res.status, typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`,
      data.errors ?? []);
  }
  return data as T;
}

export const get = <T>(path: string, params?: Params) => api<T>("GET", path + qs(params));
export const post = <T>(path: string, body?: unknown) => api<T>("POST", path, body ?? {});
export const put = <T>(path: string, body: unknown) => api<T>("PUT", path, body);
export const del = (path: string) => api<void>("DELETE", path);

// ---------- types (mirror backend/app/schemas.py) ----------

export interface Page<T> { items: T[]; total: number; page: number; page_size: number }

export interface Asset {
  id: number; name: string; component_type: string; vendor: string | null; ecosystem: string | null;
  version: string | null; version_status: string; version_spec: string | null; source_package: string | null;
  source: string; detection: string; host_id: number | null; host_name: string | null; host_ip: string | null;
  repository_id: number | null; repository_label: string | null; repository_url: string | null; image?: string | null;
  listen_ip: string | null; port: number | null; protocol: string | null; install_path: string | null;
  notes: string | null; details: Record<string, unknown> | null; missing_since: string | null;
  last_scanned_at: string | null; vuln_checked_at: string | null; created_at: string; updated_at: string;
  check_state: string; open_findings: number; max_severity: string | null;
  cpe: string | null; eol_state: string | null; eol: EolInfo | null;
}

export interface EolInfo {
  state: string; product: string; label: string; cycle: string; eol_from: string | null; latest_in_cycle: string | null;
  newest_supported: string | null; newest_supported_latest: string | null; link: string;
}

export type Exposure = Record<string, number>;

export interface Advisory {
  id: string; source: string; aliases: string[]; cve_ids: string[]; summary: string | null; details: string | null;
  published: string | null; modified: string | null; severity: string; cvss_score: number | null;
  cvss_vector: string | null; severity_source: string | null; references: { type: string; url: string }[];
  kev: boolean; kev_date_added: string | null; kev_due_date: string | null; kev_required_action: string | null;
  epss: number | null; epss_percentile: number | null; fetched_at: string;
}

export interface Finding {
  id: number; component_id: number; component_name: string; component_version: string | null;
  component_type: string; ecosystem: string | null; host_id: number | null; host_name: string | null;
  repository_id: number | null; repository_label: string | null; image?: string | null; advisory: Advisory; match_status: string;
  evidence: string; affected_ranges: string[]; fixed_versions: string[]; remediation: string;
  currently_matching: boolean; status: string; status_note: string | null; status_changed_at: string;
  status_changed_by: string; first_detected_at: string; last_checked_at: string;
}

export interface AssetDetail extends Asset {
  paths: { path: string; kind: string }[];
  history: { scan_run_id: number; version: string | null; seen_at: string; kind: string | null; status: string | null }[];
  findings: Finding[];
}

export interface Agent {
  id: number; token_hint: string; created_at: string; rotated_at: string | null; revoked_at: string | null;
  last_seen_at: string | null; last_ip: string | null; agent_version: string | null;
}

export interface Host {
  id: number; name: string; ip: string | null; reported_hostname: string | null; os_name: string | null;
  os_version: string | null; kernel: string | null; arch: string | null; notes: string | null; is_demo: boolean;
  last_report_at: string | null; created_at: string; agent: Agent | null; component_count: number; open_findings: number;
  os_id: string | null; os_eol_state: string | null; os_eol: EolInfo | null; agent_outdated: boolean; exposure: Exposure | null;
  rescan_requested_at: string | null;
}

export interface Container {
  name: string | null; image: string; state: string | null; status: string | null; version: string | null;
  compose_project: string | null; compose_service: string | null;
  ports: { ip: string | null; private: number; public: number | null; type: string | null }[];
  mounts: { type: string | null; name: string | null; source: string | null; destination: string; rw: boolean }[];
}

export interface AddedApp { manager: "dpkg" | "snap" | "flatpak"; name: string; version: string | null }

export interface ScanRun {
  id: number; kind: string; status: string; repository_id: number | null; host_id: number | null;
  target_label: string | null; revision: string | null; progress: string | null;
  summary: Record<string, any> | null; error: string | null; params: Record<string, any> | null;
  created_at: string; started_at: string | null; finished_at: string | null;
}

export interface Repo {
  id: number; url: string; owner: string; name: string; branch: string | null; is_private: boolean | null;
  last_revision: string | null; last_scanned_at: string | null; languages: Record<string, number> | null;
  notes: string | null; is_demo: boolean; created_at: string; component_count: number; open_findings: number;
  last_scan_status: string | null; exposure: Exposure | null;
  dependabot_total: number | null; dependabot_only: number | null; dependabot_error: string | null;
}

export interface Feed {
  source: string; label: string; about: string; hours: number; unavailable: string | null; enabled: boolean; last_attempt_at: string | null; last_success_at: string | null;
  last_error: string | null; stale: boolean; detail: Record<string, any> | null;
}

export interface AuditEntry {
  id: number; at: string; actor: string; action: string; target_type: string | null; target_id: string | null;
  detail: Record<string, any> | null; ip: string | null;
}

export interface DependabotAlert {
  number: number; url: string | null; ghsa: string | null; cve: string | null; summary: string; severity: string;
  package: string | null; ecosystem: string | null; manifest: string | null; vulnerable_range: string | null;
  patched: string | null; in_patchy: boolean;
}

export interface Dependabot {
  checked_at: string; error: string | null; alerts: DependabotAlert[]; total: number; also_in_patchy?: number;
}

export interface FixItem {
  component_id: number; name: string; package: string; current: string | null; target: string | null; findings: number;
  worst: string; kev: boolean; epss: number | null; possible_only: boolean; advisories: string[]; unfixed: string[];
}

export interface FixPlan {
  summary: { components: number; findings: number; upgrade_steps: number; no_fix: number; end_of_life: number };
  groups: { title: string; kind: string; base: string; path: string | null; host_id: number | null; repository_id: number | null;
    items: FixItem[]; command: string | null; notes: string[]; worst: string; kev: boolean }[];
  no_fix: FixItem[];
  end_of_life: { name: string; version: string | null; component_id: number | null; host_id: number | null; state: string;
    cycle: string; eol_from: string | null; advice: string; link: string | null }[];
  notes: string[];
}
