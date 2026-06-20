import path from "path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { readModuleVersion } from "./scripts/module-version";

export default defineConfig({
  // Inject the release version from module.prop at build time (see module-version.ts).
  define: {
    __MODULE_VERSION__: JSON.stringify(readModuleVersion()),
  },
  plugins: [
    react(),
    // Remove `crossorigin` from module scripts so the UI loads from file://
    // contexts (KernelSU WebView) where CORS headers aren't available.
    {
      name: "remove-crossorigin",
      transformIndexHtml(html) {
        return html.replace(/\s+crossorigin(="[^"]*")?/gi, "");
      },
    },
  ],
  // Relative asset paths — the bundle is served by BusyBox httpd at
  // http://127.17.1.3 and may also load under WebView/file-like contexts.
  base: "./",
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Keep relative asset paths so async chunks continue to resolve under
    // BusyBox httpd and WebView/file-like contexts.
    sourcemap: false,
  },
  // Ensure all assets are self-hosted (no CDN)
  css: {
    devSourcemap: true,
  },
});
