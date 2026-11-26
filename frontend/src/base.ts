// Where Patchy is mounted: "" at a site root, "/patchy" behind the SWSuite portal.
// The server writes it into <base href> from X-Forwarded-Prefix, so one build works in both.
export const BASE = typeof document === "undefined" ? "" : new URL(document.baseURI).pathname.replace(/\/$/, "");

// "/api/x" -> "/patchy/api/x". Leaves anything that isn't root-absolute alone.
export const withBase = (path: string) => (path.startsWith("/") && !path.startsWith("//") ? BASE + path : path);

// The address other machines use to reach this Patchy (agent installs, Home Assistant).
export const appUrl = () => window.location.origin + BASE;
