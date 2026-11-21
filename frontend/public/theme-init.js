// Applies saved appearance before first paint. External file because the CSP allows only same-origin scripts.
(function () {
  var p = {};
  try { p = JSON.parse(localStorage.getItem("patchy.prefs") || "{}") || {}; } catch (e) { /* private mode */ }
  var mode = p.mode === "day" || p.mode === "night" ? p.mode
    : window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "day" : "night";
  var d = document.documentElement;
  d.dataset.scheme = p.scheme || "navy";
  d.dataset.mode = mode;
  d.dataset.font = p.font || "system";
  d.dataset.density = p.density || "comfortable";
  d.style.colorScheme = mode === "day" ? "light" : "dark";
})();
