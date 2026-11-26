import { NAME } from "./prefs";
// Pure display helpers (unit-tested in format.test.ts).

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "Unknown" : d.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"] as const;

export const CHECK_STATES: Record<string, { label: string; tone: string; help: string }> = {
  vulnerable: { label: "Vulnerable", tone: "bad", help: "Has open findings that match current data." },
  no_known_vulns: { label: "No known vulns", tone: "good", help: "Checked against OSV; no advisory matches this exact version." },
  stale: { label: "Feed stale", tone: "warn", help: "Last check found nothing, but feed data is older than the stale threshold." },
  not_checked_yet: { label: "Not checked yet", tone: "warn", help: "Waiting for a feed refresh. This is not a clean result." },
  version_unknown: { label: "Version unknown", tone: "warn", help: `Without an exact version ${NAME} cannot confirm whether it is affected.` },
  not_checkable: { label: "No vuln source", tone: "muted", help: "No supported vulnerability feed covers this component type." },
  not_present: { label: "Not in latest scan", tone: "muted", help: "Not seen in the most recent scan of its host or repository." },
};

export const MATCH_STATUS: Record<string, { label: string; help: string }> = {
  confirmed: { label: "Confirmed", help: "Installed version is inside the advisory's affected range." },
  possible: { label: "Possible", help: "Package matches but the version could not be compared reliably." },
  unknown_version: { label: "Version unknown", help: "Package matches; record the installed version to confirm." },
};

export const TYPES: Record<string, string> = {
  language: "Language/runtime", library: "Framework/library", web_server: "Web server", database: "Database",
  os_package: "OS package", container_image: "Container image", application: "Application",
  service: "Service", other: "Other",
};

export const label = (map: Record<string, string>, key: string | null | undefined) =>
  key ? map[key] ?? key.replace(/_/g, " ") : "-";

export function versionText(v: string | null, status: string, spec?: string | null): string {
  if (status === "exact" && v) return v;
  if (status === "constraint") return `${spec ?? v ?? "?"} (constraint)`;
  return "unknown";
}

// Only allow http(s) links from advisory data; anything else is shown as text.
export function safeUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch {
    return null;
  }
}

// EPSS probability (0-1) as a short percentage.
export function pct(v: number | null | undefined): string {
  if (v == null) return "-";
  const p = v * 100;
  if (p > 0 && p < 0.1) return "<0.1%";
  if (p >= 99.5 && p < 100) return ">99%";
  return `${p < 10 ? p.toFixed(1) : Math.round(p)}%`;
}

export const EOL_STATES: Record<string, { label: string; tone: string }> = {
  eol: { label: "End of life", tone: "bad" },
  eol_soon: { label: "EOL soon", tone: "warn" },
  supported: { label: "Supported", tone: "good" },
};

export const HOURS_LABEL = (h: number) =>
  h === 0 ? "Manual only" : h === 1 ? "Every hour" : h < 24 ? `Every ${h} hours` : h === 24 ? "Daily"
    : h === 168 ? "Weekly" : `Every ${h / 24} days`;
