import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the API so the browser stays same-origin (no CORS needed).
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:8080" } },
  // Relative asset URLs resolve against <base href>, so one build serves any mount path.
  base: "./",
  build: { outDir: "dist", sourcemap: false },
});
