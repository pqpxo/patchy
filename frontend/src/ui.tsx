import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { ApiError, type ScanRun } from "./api";
import { CHECK_STATES, EOL_STATES, MATCH_STATUS, ago, fmtDate, pct } from "./format";
import { Icon } from "./icons";
import { PAGE_SIZES, loadColumns, saveColumns, setPrefs, usePrefs } from "./prefs";

// ---------- router (History API; the server falls back to index.html) ----------

const subscribe = (cb: () => void) => {
  window.addEventListener("popstate", cb);
  return () => window.removeEventListener("popstate", cb);
};
export const usePath = () => useSyncExternalStore(subscribe, () => window.location.pathname + window.location.search);

export function navigate(to: string) {
  window.history.pushState(null, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo(0, 0);
}

export function Link({ to, children, className, title }: { to: string; children: ReactNode; className?: string; title?: string }) {
  return (
    <a href={to} className={className} title={title} onClick={(e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      navigate(to);
    }}>{children}</a>
  );
}

// Replace several query parameters at once. Changing anything but the page resets to page 1.
export function setQuery(patch: Record<string, string>) {
  const u = new URL(window.location.href);
  for (const [k, v] of Object.entries(patch)) {
    if (v) u.searchParams.set(k, v); else u.searchParams.delete(k);
  }
  if (!("page" in patch)) u.searchParams.delete("page");
  window.history.replaceState(null, "", u.pathname + u.search);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function useQueryParam(name: string): [string, (v: string) => void] {
  const path = usePath();
  const value = new URLSearchParams(path.split("?")[1] ?? "").get(name) ?? "";
  return [value, (v: string) => setQuery({ [name]: v })];
}

// ---------- data loading ----------

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[], pollMs?: (d: T | undefined) => number | null) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    let live = true;
    setLoading(true);
    fn().then((d) => { if (live) { setData(d); setError(undefined); } })
      .catch((e) => { if (live) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  const interval = pollMs?.(data);
  useEffect(() => {
    if (!interval) return;
    const t = setTimeout(reload, interval);
    return () => clearTimeout(t);
  }, [interval, data, reload]);
  return { data, error, loading, reload, setData };
}

// ---------- toasts ----------

type Toast = { id: number; text: string; tone: "good" | "bad" | "info" };
let toasts: Toast[] = [];
const toastListeners = new Set<() => void>();
const emit = () => toastListeners.forEach((l) => l());

export function toast(text: string, tone: Toast["tone"] = "good") {
  const id = Date.now() + Math.random();
  toasts = [...toasts, { id, text, tone }].slice(-4);
  emit();
  setTimeout(() => { toasts = toasts.filter((t) => t.id !== id); emit(); }, tone === "bad" ? 8000 : 4000);
}

export function Toaster() {
  const list = useSyncExternalStore((cb) => { toastListeners.add(cb); return () => toastListeners.delete(cb); }, () => toasts);
  return (
    <div className="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} className={`toast tone-${t.tone}`}>
          <span>{t.text}</span>
          <button className="icon-btn" aria-label="Dismiss" onClick={() => { toasts = toasts.filter((x) => x.id !== t.id); emit(); }}>
            <Icon name="close" size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

// ---------- layout ----------

export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="skeleton" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="sk-row"><i /><i /><i /><i /></div>)}
    </div>
  );
}

export function Loading({ what }: { what?: string }) {
  return what ? <p className="muted" role="status" aria-live="polite">{what}…</p> : <Skeleton rows={4} />;
}

export function ErrorBox({ error, onRetry }: { error?: string; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="alert bad" role="alert">
      <span>{error}</span> {onRetry && <button className="btn small" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><strong>{title}</strong>{children && <div>{children}</div>}</div>;
}

export function PageHead({ title, sub, actions, crumbs, meta }: {
  title: ReactNode; sub?: ReactNode; actions?: ReactNode; crumbs?: [string, string][]; meta?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="page-title">
        {crumbs && (
          <nav className="crumbs" aria-label="Breadcrumb">
            {crumbs.map(([label, to]) => <span key={to}><Link to={to}>{label}</Link><span aria-hidden="true">/</span></span>)}
          </nav>
        )}
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
        {meta && <div className="head-meta">{meta}</div>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Tabs({ tabs, value, onChange }: { tabs: [string, ReactNode][]; value: string; onChange: (v: string) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(([id, label]) => (
        <button key={id} role="tab" aria-selected={value === id} className={value === id ? "tab on" : "tab"}
          onClick={() => onChange(id)}>{label}</button>
      ))}
    </div>
  );
}

// ---------- badges ----------

export function Sev({ s }: { s: string | null | undefined }) {
  const v = s || "unknown";
  return <span className={`sev sev-${v}`}><i aria-hidden="true" />{v}</span>;
}

export function Kev({ on }: { on: boolean }) {
  return on ? <span className="badge kev" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span> : null;
}

/** Network exposure from the agent: a process listening beyond loopback, or a container publishing a port. */
export function Reach({ e, note, inUse }: { e?: string | null; note?: string | null; inUse?: boolean | null }) {
  const idle = inUse === false
    && <span className="badge st-minor" title="No running program comes from this package, so it ranks lower">Not running</span>;
  if (e === "network") return <><span className="badge tone-warn" title={note ?? "Reachable over the network"}>Network</span>{idle}</>;
  if (e === "local") return <><span className="badge tone-muted" title={note ?? "Listens on loopback only"}>Local</span>{idle}</>;
  return idle || null;
}

export function CheckState({ s }: { s: string }) {
  const c = CHECK_STATES[s] ?? { label: s, tone: "muted", help: "" };
  return <span className={`badge tone-${c.tone}`} title={c.help}>{c.label}</span>;
}

export function Match({ s }: { s: string }) {
  const m = MATCH_STATUS[s] ?? { label: s, help: "" };
  return <span className={`badge match-${s}`} title={m.help}>{m.label}</span>;
}

/** A fix-by deadline: "in 12 d", "today", or "3 d overdue" in red. */
export function Due({ iso }: { iso?: string | null }) {
  if (!iso) return <span className="muted">-</span>;
  const days = Math.floor((new Date(iso).getTime() - Date.now()) / 864e5);
  const title = `Fix by ${new Date(iso).toLocaleDateString("en-GB", { dateStyle: "medium" })}`;
  if (days < 0) return <span className="due-over" title={title}>{-days} d overdue</span>;
  return <span className={days < 7 ? "due-soon" : "muted"} title={title}>{days === 0 ? "today" : `in ${days} d`}</span>;
}

export function Status({ s }: { s: string }) {
  return <span className={`badge st-${s}`}>{s.charAt(0).toUpperCase() + s.slice(1).replace("_", " ")}</span>;
}

export function Eol({ s, info, quiet = true }: { s: string | null | undefined; info?: Record<string, any> | null; quiet?: boolean }) {
  if (!s || (quiet && s === "supported")) return null;
  const e = EOL_STATES[s] ?? { label: s, tone: "muted" };
  const title = info ? `${info.label ?? ""} ${info.cycle ?? ""}${info.eol_from ? `: support ends ${info.eol_from}` : ""}` : undefined;
  return <span className={`badge tone-${e.tone}`} title={title}>{e.label}</span>;
}

export function Epss({ v, p }: { v: number | null | undefined; p?: number | null }) {
  if (v == null) return <span className="muted">-</span>;
  const tone = v >= 0.1 ? "hot" : v >= 0.01 ? "warm" : "cool";
  return (
    <span className={`epss epss-${tone}`} title={`EPSS: ${pct(v)} chance of exploitation in the next 30 days${p != null ? `, higher than ${Math.round(p * 100)}% of CVEs` : ""}`}>
      <span className="epss-meter" aria-hidden="true"><i style={{ width: `${Math.max(4, Math.min(100, v * 100))}%` }} /></span>
      <span className="num">{pct(v)}</span>
    </span>
  );
}

export function When({ iso }: { iso: string | null | undefined }) {
  return <time dateTime={iso ?? undefined} title={fmtDate(iso)}>{ago(iso)}</time>;
}

// The exposure strip: open findings as a segmented severity bar, with a notch when any are known exploited.
const STRIP = ["critical", "high", "medium", "low"] as const;
export function Exposure({ e, size = "row" }: { e?: Record<string, number> | null; size?: "row" | "wide" }) {
  const total = e?.total ?? 0;
  const parts: [string, number][] = STRIP.map((s) => [s, e?.[s] ?? 0]);
  const other = total - parts.reduce((a, [, n]) => a + n, 0);
  if (other > 0) parts.push(["other", other]);
  const kev = e?.kev ?? 0;
  const text = total ? parts.filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(", ") + (kev ? `, ${kev} known exploited` : "")
    : "No open findings";
  return (
    <span className={`expo expo-${size}${total ? "" : " clear"}`} title={text} aria-label={text} role="img">
      {kev > 0 && <i className="expo-notch" aria-hidden="true" />}
      <span className="expo-bar" aria-hidden="true">
        {parts.map(([s, n]) => n > 0 && <i key={s} className={`seg seg-${s}`} style={{ flexGrow: n }} />)}
      </span>
      <span className="expo-n num" aria-hidden="true">{total}</span>
    </span>
  );
}

// ---------- tables ----------

export type Order = "asc" | "desc";
export interface SortState { sort: string; order: Order; set: (sort: string, order: Order) => void }

// Sort state lives in the URL for list pages and in memory for tables inside detail pages.
export function useSort(def: string, defOrder: Order = "asc", local = false): SortState {
  const [qs] = useQueryParam("sort");
  const [qo] = useQueryParam("order");
  const [mem, setMem] = useState({ sort: def, order: defOrder });
  if (local) return { ...mem, set: (sort, order) => setMem({ sort, order }) };
  return {
    sort: qs || def, order: (qo === "asc" || qo === "desc" ? qo : qs ? "asc" : defOrder),
    set: (sort, order) => setQuery({ sort: sort === def && order === defOrder ? "" : sort, order: sort === def && order === defOrder ? "" : order }),
  };
}

export interface Col<T> {
  id: string; label: string; cell: (row: T) => ReactNode;
  sort?: string; first?: Order; num?: boolean; hidden?: boolean; fixed?: boolean;
}

export function DataTable<T>({ table, cols, rows, rowKey, sort, tools, rowClass, compact }: {
  table: string; cols: Col<T>[]; rows: T[]; rowKey: (r: T) => string | number; sort?: SortState;
  tools?: ReactNode; rowClass?: (r: T) => string; compact?: boolean;
}) {
  const defaults = cols.filter((c) => !c.hidden).map((c) => c.id);
  const [shown, setShown] = useState<string[]>(() => loadColumns(table) ?? defaults);
  const visible = cols.filter((c) => c.fixed || shown.includes(c.id));
  const toggle = (id: string) => {
    const next = shown.includes(id) ? shown.filter((x) => x !== id) : [...shown, id];
    setShown(next);
    saveColumns(table, next);
  };
  const optional = cols.filter((c) => !c.fixed);
  return (
    <div className="dt">
      {(tools || optional.length > 1) && (
        <div className="dt-tools">
          <div className="dt-left">{tools}</div>
          {optional.length > 1 && (
            <details className="menu">
              <summary className="btn small ghost"><Icon name="columns" size={14} /> Columns</summary>
              <div className="menu-pop" role="group" aria-label="Visible columns">
                {optional.map((c) => (
                  <label key={c.id} className="check"><input type="checkbox" checked={shown.includes(c.id)} onChange={() => toggle(c.id)} /> {c.label}</label>
                ))}
                <button className="btn small ghost" type="button" onClick={() => { setShown(defaults); saveColumns(table, null); }}>Reset</button>
              </div>
            </details>
          )}
        </div>
      )}
      <div className="table-wrap">
        <table className={compact ? "table compact" : "table"}>
          <thead><tr>{visible.map((c) => {
            const on = sort && c.sort && sort.sort === c.sort;
            return (
              <th key={c.id} className={c.num ? "r" : undefined}
                aria-sort={on ? (sort!.order === "asc" ? "ascending" : "descending") : undefined}>
                {sort && c.sort ? (
                  <button className={on ? "th-sort on" : "th-sort"} onClick={() =>
                    sort.set(c.sort!, on ? (sort.order === "asc" ? "desc" : "asc") : c.first ?? "asc")}>
                    {c.label}<Icon name={on ? (sort.order === "asc" ? "up" : "down") : "updown"} size={12} />
                  </button>
                ) : c.label}
              </th>
            );
          })}</tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={rowKey(r)} className={rowClass?.(r)}>
              {visible.map((c) => <td key={c.id} className={c.num ? "r num" : undefined}>{c.cell(r)}</td>)}
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  );
}

/** A page number that goes back to 1 whenever `key` changes (another sort order, another record). */
export function usePage(key: unknown[]): [number, (p: number) => void] {
  const k = JSON.stringify(key);
  const [s, set] = useState({ page: 1, k });
  return [s.k === k ? s.page : 1, (page) => { set({ page, k }); window.scrollTo({ top: 0 }); }];
}

export const TAB_PAGE = 200;

/** Pager for a tab that shows up to 200 rows a page. Hidden when everything fits on one page. */
export function TabPager({ data, onPage }: { data: { page: number; total: number; page_size: number }; onPage: (p: number) => void }) {
  return data.total > data.page_size ? <Pager page={data.page} total={data.total} size={data.page_size} sizes={false} onPage={onPage} /> : null;
}

export function Pager({ page, total, size, onPage, sizes = true }: { page: number; total: number; size: number; onPage: (p: number) => void; sizes?: boolean }) {
  const pages = Math.max(1, Math.ceil(total / size));
  const prefs = usePrefs();
  const from = total ? (page - 1) * size + 1 : 0;
  return (
    <nav className="pager" aria-label="Pagination">
      <span className="muted num">{from}-{Math.min(total, page * size)} of {total}</span>
      {sizes && (
        <label className="pager-size muted">Rows
          <select value={prefs.pageSize} onChange={(e) => { setPrefs({ pageSize: +e.target.value }); onPage(1); }}>
            {PAGE_SIZES.map((n) => <option key={n}>{n}</option>)}
          </select>
        </label>
      )}
      {pages > 1 && <>
        <button className="btn small" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span className="num">{page} / {pages}</span>
        <button className="btn small" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </>}
    </nav>
  );
}

// ---------- forms ----------

export function Field({ label, children, hint, error }: { label: string; children: ReactNode; hint?: ReactNode; error?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small className="muted">{hint}</small>}
      {error && <small className="field-error">{error}</small>}
    </label>
  );
}

export function Switch({ on, onChange, label, disabled }: { on: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled}
      className={on ? "switch on" : "switch"} onClick={() => onChange(!on)}><i /></button>
  );
}

export function fieldErrors(e: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (e instanceof ApiError) for (const f of e.fields) out[f.loc[f.loc.length - 1]] = f.msg;
  return out;
}

export function errText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

export function DangerButton({ onConfirm, children, question }: { onConfirm: () => void; children: ReactNode; question: string }) {
  return <button className="btn danger" onClick={() => { if (window.confirm(question)) onConfirm(); }}>{children}</button>;
}

// The Clipboard API only exists on HTTPS and localhost. Plain-HTTP LAN installs fall back to a hidden textarea.
export async function copyText(text: string): Promise<boolean> {
  try {
    if (window.isSecureContext && navigator.clipboard) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* fall through */ }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.className = "offscreen";
  // An open modal <dialog> makes the rest of the page inert, so the textarea must live inside it.
  (document.querySelector("dialog[open]") ?? document.body).appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  ta.remove();
  return ok;
}

export function Copy({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn small ghost" type="button" aria-label={label} onClick={async () => {
      if (await copyText(text)) { setDone(true); setTimeout(() => setDone(false), 1500); }
      else toast("Couldn't copy. Select the text and copy it instead.", "info");
    }}><Icon name={done ? "check" : "copy"} size={14} />{done ? "Copied" : label}</button>
  );
}

const ACTIVE = (r?: ScanRun | null) => !!r && (r.status === "queued" || r.status === "running");

// Live status of the latest scan or refresh started from this page: progress while it runs, then the result.
export function RunBanner({ run, what = "Scan", onFinished }: { run?: ScanRun | null; what?: string; onFinished?: (r: ScanRun) => void }) {
  const seen = useRef<{ id: number; active: boolean } | null>(null);
  useEffect(() => {
    if (!run) return;
    const before = seen.current;
    if (before && before.id === run.id && before.active && !ACTIVE(run)) {
      toast(`${what} #${run.id} ${run.status === "succeeded" ? "finished" : run.status}.`, run.status === "failed" ? "bad" : "good");
      onFinished?.(run);
    }
    seen.current = { id: run.id, active: ACTIVE(run) };
  }, [run, what, onFinished]);
  if (!run) return null;
  const recent = run.finished_at && Date.now() - new Date(run.finished_at).getTime() < 10 * 60 * 1000;
  if (!ACTIVE(run) && !recent) return null;
  const tone = ACTIVE(run) ? "info" : run.status === "failed" ? "bad" : run.status === "partial" ? "warn" : "info";
  return (
    <div className={`alert ${tone} run`} role="status" aria-live="polite">
      {ACTIVE(run) ? <span className="spin" aria-hidden="true" /> : <Status s={run.status} />}
      <span className="grow">
        <strong>{what} #{run.id}</strong>{" "}
        {ACTIVE(run) ? (run.status === "queued" ? "is queued…" : run.progress || "is running…")
          : <>{run.status === "succeeded" ? "finished" : run.status} <When iso={run.finished_at} />{run.error ? `: ${run.error}` : "."}</>}
      </span>
      <Link to={`/scans/${run.id}`} className="small">Details</Link>
    </div>
  );
}

export function CodeBlock({ code, wrap = true }: { code: string; wrap?: boolean }) {
  return <div className={wrap ? "code" : "code nowrap"}><pre>{code}</pre><Copy text={code} /></div>;
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v ?? <span className="muted">unknown</span>}</dd></div>)}
    </dl>
  );
}
