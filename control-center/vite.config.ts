import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
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
