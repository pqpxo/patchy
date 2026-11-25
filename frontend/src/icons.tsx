// Inline stroke icons (24px grid, drawn for Patchy). No icon font or external sprite, so the CSP stays strict.
const P: Record<string, string> = {
  dashboard: "M4 13h6V4H4zM14 20h6v-9h-6zM4 20h6v-3H4zM14 7h6V4h-6z",
  assets: "M12 3l8 4.5v9L12 21l-8-4.5v-9zM4 7.5l8 4.5 8-4.5M12 12v9",
  hosts: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  repos: "M6 3v12M18 9a3 3 0 1 0 0-.01M6 21a3 3 0 1 0 0-.01M18 12c0 4-6 3-12 6",
  scans: "M3 12h4l3-8 4 16 3-8h4",
  vulns: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM12 8v5M12 16.5h.01",
  fix: "M14.5 6.5a4 4 0 0 0 5 5L11 20a2.1 2.1 0 0 1-3-3l8.5-8.5a4 4 0 0 0-2-2z",
  settings: "M4 7h10M18 7h2M4 17h4M12 17h8M14 4.5v5M8 14.5v5",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4",
  menu: "M4 6h16M4 12h16M4 18h16",
  rail: "M4 4h16v16H4zM9 4v16",
  sun: "M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4",
  moon: "M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z",
  columns: "M4 4h16v16H4zM10 4v16M15 4v16",
  close: "M6 6l12 12M18 6L6 18",
  plus: "M12 5v14M5 12h14",
  refresh: "M20 11a8 8 0 0 0-14.6-4.5M4 4v3h3M4 13a8 8 0 0 0 14.6 4.5M20 20v-3h-3",
  out: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  external: "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
  copy: "M8 8h12v12H8zM16 8V4H4v12h4",
  up: "M12 19V5M6 11l6-6 6 6",
  down: "M12 5v14M6 13l6 6 6-6",
  updown: "M8 9l4-4 4 4M8 15l4 4 4-4",
  check: "M5 12.5l4.5 4.5L19 7",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  filter: "M4 5h16l-6 7.5V19l-4 1v-7.5z",
  bell: "M6 16v-5a6 6 0 0 1 12 0v5l2 2H4zM10 21h4",
  "bell-off": "M6 16v-5a6 6 0 0 1 12 0v5l2 2H4zM10 21h4M4 3l16 16",
  download: "M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19h14",
};

export type IconName = keyof typeof P;

export function Icon({ name, size = 16, label }: { name: string; size?: number; label?: string }) {
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" role={label ? "img" : undefined}
      aria-label={label} aria-hidden={label ? undefined : true}>
      <path d={P[name] ?? ""} />
    </svg>
  );
}
