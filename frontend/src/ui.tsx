import { useCallback, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { ApiError } from "./api";
import { CHECK_STATES, MATCH_STATUS, ago, fmtDate } from "./format";

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

export function Link({ to, children, className }: { to: string; children: ReactNode; className?: string }) {
  return (
    <a href={to} className={className} onClick={(e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      navigate(to);
    }}>{children}</a>
  );
}

export function useQueryParam(name: string): [string, (v: string) => void] {
  const path = usePath();
  const value = new URLSearchParams(path.split("?")[1] ?? "").get(name) ?? "";
  const set = (v: string) => {
    const u = new URL(window.location.href);
    if (v) u.searchParams.set(name, v); else u.searchParams.delete(name);
    if (name !== "page") u.searchParams.delete("page");
    window.history.replaceState(null, "", u.pathname + u.search);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };
  return [value, set];
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

// ---------- components ----------

export function Loading({ what = "Loading" }: { what?: string }) {
  return <p className="muted" role="status" aria-live="polite">{what}…</p>;
}

export function ErrorBox({ error, onRetry }: { error?: string; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="alert bad" role="alert">
      {error} {onRetry && <button className="btn small" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><strong>{title}</strong>{children && <div>{children}</div>}</div>;
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div><h1>{title}</h1>{sub && <p className="muted">{sub}</p>}</div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Sev({ s }: { s: string | null | undefined }) {
  const v = s || "unknown";
  return <span className={`badge sev-${v}`}>{v}</span>;
}

export function Kev({ on }: { on: boolean }) {
  return on ? <span className="badge kev" title="Listed in CISA Known Exploited Vulnerabilities">KEV</span> : null;
}

export function CheckState({ s }: { s: string }) {
  const c = CHECK_STATES[s] ?? { label: s, tone: "muted", help: "" };
  return <span className={`badge tone-${c.tone}`} title={c.help}>{c.label}</span>;
}

export function Match({ s }: { s: string }) {
  const m = MATCH_STATUS[s] ?? { label: s, help: "" };
  return <span className={`badge match-${s}`} title={m.help}>{m.label}</span>;
}

export function Status({ s }: { s: string }) {
  return <span className={`badge st-${s}`}>{s.replace("_", " ")}</span>;
}

export function When({ iso }: { iso: string | null | undefined }) {
  return <time dateTime={iso ?? undefined} title={fmtDate(iso)}>{ago(iso)}</time>;
}

export function Pager({ page, total, size, onPage }: { page: number; total: number; size: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  if (pages <= 1) return <p className="muted small">{total} item{total === 1 ? "" : "s"}</p>;
  return (
    <nav className="pager" aria-label="Pagination">
      <button className="btn small" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
      <span>Page {page} of {pages} ({total})</span>
      <button className="btn small" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </nav>
  );
}

export function Field({ label, children, hint, error }: { label: string; children: ReactNode; hint?: string; error?: string }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small className="muted">{hint}</small>}
      {error && <small className="field-error">{error}</small>}
    </label>
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

export function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn small" type="button" onClick={async () => {
      try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); } catch { /* insecure context */ }
    }}>{done ? "Copied" : "Copy"}</button>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v ?? <span className="muted">unknown</span>}</dd></div>)}
    </dl>
  );
}
