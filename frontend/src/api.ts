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
  repository_id: number | null; repository_label: string | null; repository_url: string | null;
  listen_ip: string | null; port: number | null; protocol: string | null; install_path: string | null;
  notes: string | null; details: Record<string, unknown> | null; missing_since: string | null;
  last_scanned_at: string | null; vuln_checked_at: string | null; created_at: string; updated_at: string;
  check_state: string; open_findings: number; max_severity: string | null;
}

export interface Advisory {
  id: string; source: string; aliases: string[]; cve_ids: string[]; summary: string | null; details: string | null;
  published: string | null; modified: string | null; severity: string; cvss_score: number | null;
  cvss_vector: string | null; severity_source: string | null; references: { type: string; url: string }[];
  kev: boolean; kev_date_added: string | null; kev_due_date: string | null; kev_required_action: string | null;
  fetched_at: string;
}

export interface Finding {
  id: number; component_id: number; component_name: string; component_version: string | null;
  component_type: string; ecosystem: string | null; host_id: number | null; host_name: string | null;
  repository_id: number | null; repository_label: string | null; advisory: Advisory; match_status: string;
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
}

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
  last_scan_status: string | null;
}

export interface Feed {
  source: string; enabled: boolean; last_attempt_at: string | null; last_success_at: string | null;
  last_error: string | null; stale: boolean; detail: Record<string, any> | null;
}

export interface AuditEntry {
  id: number; at: string; actor: string; action: string; target_type: string | null; target_id: string | null;
  detail: Record<string, any> | null; ip: string | null;
}
