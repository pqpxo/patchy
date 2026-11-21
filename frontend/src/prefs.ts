// Per-browser appearance and view preferences. theme-init.js applies the same keys before first paint.
import { useSyncExternalStore } from "react";

export type Mode = "system" | "day" | "night";
export interface Prefs {
  scheme: string; mode: Mode; font: string; density: "comfortable" | "compact"; rail: boolean; pageSize: number;
}

export const SCHEMES: { id: string; label: string; note: string }[] = [
  { id: "navy", label: "Navy", note: "Patchy's default" },
  { id: "graphite", label: "Graphite", note: "Neutral greys" },
  { id: "harbour", label: "Harbour", note: "Teal and slate" },
  { id: "fern", label: "Fern", note: "Muted greens" },
  { id: "plum", label: "Plum", note: "Violet tint" },
  { id: "ember", label: "Ember", note: "Warm rust" },
  { id: "sand", label: "Sand", note: "Paper and ink" },
  { id: "steel", label: "Steel", note: "Cool blue-grey" },
  { id: "indigo", label: "Indigo", note: "Deep blue-violet" },
  { id: "midnight", label: "Midnight", note: "Navy with cyan" },
  { id: "ocean", label: "Ocean", note: "Bright sea blue" },
  { id: "mint", label: "Mint", note: "Fresh green-teal" },
  { id: "forest", label: "Forest", note: "Deep greens" },
  { id: "moss", label: "Moss", note: "Olive and lichen" },
  { id: "copper", label: "Copper", note: "Burnished orange" },
  { id: "rose", label: "Rose", note: "Dusty pink" },
  { id: "berry", label: "Berry", note: "Magenta tint" },
  { id: "contrast", label: "High contrast", note: "Maximum legibility" },
];

export const FONTS: { id: string; label: string }[] = [
  { id: "system", label: "System" }, { id: "humanist", label: "Humanist" }, { id: "geometric", label: "Geometric" },
  { id: "industrial", label: "Industrial" }, { id: "rounded", label: "Rounded" }, { id: "mono", label: "Monospace" },
];

export const PAGE_SIZES = [25, 50, 100, 200];
const KEY = "patchy.prefs";
const DEFAULTS: Prefs = { scheme: "navy", mode: "system", font: "system", density: "comfortable", rail: false, pageSize: 50 };

function read(): Prefs {
  try {
    const p = { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || "{}") };
    if (!SCHEMES.some((s) => s.id === p.scheme)) p.scheme = DEFAULTS.scheme;
    if (!FONTS.some((f) => f.id === p.font)) p.font = DEFAULTS.font;
    if (!PAGE_SIZES.includes(p.pageSize)) p.pageSize = DEFAULTS.pageSize;
    return p;
  } catch {
    return DEFAULTS;
  }
}

let current = read();
const listeners = new Set<() => void>();
const light = typeof window !== "undefined" ? window.matchMedia?.("(prefers-color-scheme: light)") : undefined;

export function resolvedMode(p: Prefs = current): "day" | "night" {
  return p.mode === "system" ? (light?.matches ? "day" : "night") : p.mode;
}

function apply() {
  const d = document.documentElement, mode = resolvedMode();
  Object.assign(d.dataset, { scheme: current.scheme, mode, font: current.font, density: current.density });
  d.style.colorScheme = mode === "day" ? "light" : "dark";
}

export function setPrefs(patch: Partial<Prefs>) {
  current = { ...current, ...patch };
  try { localStorage.setItem(KEY, JSON.stringify(current)); } catch { /* storage blocked: still applies this session */ }
  apply();
  listeners.forEach((l) => l());
}

light?.addEventListener("change", () => { if (current.mode === "system") { apply(); listeners.forEach((l) => l()); } });

export function usePrefs(): Prefs {
  return useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb); }, () => current);
}

// Visible table columns, per table, per browser.
export function loadColumns(table: string): string[] | null {
  try { return JSON.parse(localStorage.getItem(`patchy.cols.${table}`) || "null"); } catch { return null; }
}
export function saveColumns(table: string, cols: string[] | null) {
  try {
    if (cols) localStorage.setItem(`patchy.cols.${table}`, JSON.stringify(cols));
    else localStorage.removeItem(`patchy.cols.${table}`);
  } catch { /* ignore */ }
}
