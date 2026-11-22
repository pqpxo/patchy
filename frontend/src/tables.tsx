// Asset and finding tables shared by list and detail pages.
import type { ReactNode } from "react";
import type { Asset, Finding } from "./api";
import { TYPES, label, versionText } from "./format";
import { CheckState, DataTable, Eol, Epss, Kev, Link, Match, Sev, Status, When, type Col, type SortState } from "./ui";

const assetCols: Col<Asset>[] = [
  { id: "name", label: "Name", sort: "name", fixed: true, cell: (a) => <>
    <Link to={`/assets/${a.id}`}>{a.name}</Link>
    {(a.ecosystem || a.image) && <div className="cell-sub">{a.ecosystem}{a.ecosystem && a.image && " · "}{a.image && `in image ${a.image}`}</div>}
  </> },
  { id: "version", label: "Version", sort: "version", cell: (a) =>
    <span className={a.version_status === "exact" ? "ver" : "ver muted"}>{versionText(a.version, a.version_status, a.version_spec)}</span> },
  { id: "type", label: "Type", sort: "type", cell: (a) => label(TYPES, a.component_type) },
  { id: "ecosystem", label: "Ecosystem", sort: "ecosystem", hidden: true, cell: (a) => a.ecosystem ?? <span className="muted">-</span> },
  { id: "location", label: "Location", sort: "location", cell: (a) => <>
    {a.host_id ? <Link to={`/hosts/${a.host_id}`}>{a.host_name}</Link>
      : a.repository_id ? <Link to={`/repositories/${a.repository_id}`}>{a.repository_label}</Link> : <span className="muted">-</span>}
    {a.port ? <span className="muted num"> :{a.port}/{a.protocol}</span> : null}
  </> },
  { id: "source", label: "Source", sort: "source", cell: (a) => a.source },
  { id: "check", label: "Check", sort: "checked", first: "desc", cell: (a) => <CheckState s={a.check_state} /> },
  { id: "eol", label: "Support", sort: "eol", first: "desc", cell: (a) => <Eol s={a.eol_state} info={a.eol} /> },
  { id: "findings", label: "Findings", sort: "severity", first: "desc", cell: (a) =>
    a.open_findings ? <><Sev s={a.max_severity} /> <span className="num muted">×{a.open_findings}</span></> : <span className="muted num">0</span> },
  { id: "cpe", label: "CPE", hidden: true, cell: (a) => a.cpe ? <code>{a.cpe}</code> : <span className="muted">-</span> },
  { id: "updated", label: "Updated", sort: "updated", first: "desc", hidden: true, cell: (a) => <When iso={a.updated_at} /> },
];

export function AssetTable({ items, sort, tools, table = "assets", where = true }: {
  items: Asset[]; sort?: SortState; tools?: ReactNode; table?: string; where?: boolean;
}) {
  const cols = where ? assetCols : assetCols.filter((c) => c.id !== "location");
  return <DataTable table={table} cols={cols} rows={items} rowKey={(a) => a.id} sort={sort} tools={tools}
    rowClass={(a) => (a.missing_since ? "dim" : "")} />;
}

const findingCols: Col<Finding>[] = [
  { id: "severity", label: "Severity", sort: "severity", first: "desc", fixed: true, cell: (f) => <Sev s={f.advisory.severity} /> },
  { id: "advisory", label: "Advisory", fixed: true, cell: (f) => <>
    <Link to={`/vulnerabilities/${f.id}`} className="id">{f.advisory.id}</Link> <Kev on={f.advisory.kev} />
    {f.advisory.summary && <div className="cell-sub clamp">{f.advisory.summary}</div>}
  </> },
  { id: "asset", label: "Asset", sort: "component", cell: (f) => <>
    <Link to={`/assets/${f.component_id}`}>{f.component_name}</Link> <span className="ver muted">{f.component_version}</span>
    {f.image && <div className="cell-sub">in image {f.image}</div>}
  </> },
  { id: "location", label: "Location", sort: "location", cell: (f) => <>
    {f.host_id ? <Link to={`/hosts/${f.host_id}`}>{f.host_name}</Link>
      : f.repository_id ? <Link to={`/repositories/${f.repository_id}`}>{f.repository_label}</Link> : <span className="muted">-</span>}
  </> },
  { id: "epss", label: "EPSS", sort: "epss", first: "desc", cell: (f) => <Epss v={f.advisory.epss} p={f.advisory.epss_percentile} /> },
  { id: "cvss", label: "CVSS", sort: "cvss", first: "desc", num: true, hidden: true, cell: (f) => f.advisory.cvss_score ?? <span className="muted">-</span> },
  { id: "match", label: "Match", sort: "match", cell: (f) => <Match s={f.match_status} /> },
  { id: "fixed", label: "Fixed in", cell: (f) => f.fixed_versions.length
    ? <span className="ver">{f.fixed_versions.slice(0, 3).join(", ")}{f.fixed_versions.length > 3 ? "…" : ""}</span>
    : <span className="muted">no fix listed</span> },
  { id: "status", label: "Status", sort: "status", cell: (f) => <>
    <Status s={f.status} />{!f.currently_matching && <div className="cell-sub">no longer matches</div>}
  </> },
  { id: "detected", label: "First seen", sort: "detected", first: "desc", hidden: true, cell: (f) => <When iso={f.first_detected_at} /> },
  { id: "published", label: "Published", sort: "published", first: "desc", hidden: true,
    cell: (f) => f.advisory.published ? f.advisory.published.slice(0, 10) : <span className="muted">-</span> },
];

export function FindingTable({ items, sort, tools, table = "findings", showAsset = true }: {
  items: Finding[]; sort?: SortState; tools?: ReactNode; table?: string; showAsset?: boolean;
}) {
  const cols = showAsset ? findingCols : findingCols.filter((c) => c.id !== "asset" && c.id !== "location");
  return <DataTable table={table} cols={cols} rows={items} rowKey={(f) => f.id} sort={sort} tools={tools}
    rowClass={(f) => (f.currently_matching ? "" : "dim")} />;
}
