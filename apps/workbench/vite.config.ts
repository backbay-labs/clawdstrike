import react from "@vitejs/plugin-react";
import { resolve } from "path";
import { defineConfig } from "vite";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  clearScreen: false,
  server: {
    port: 1421,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1422 }
      : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
    proxy: {
      // Proxy fleet API requests to avoid CORS in dev mode.
      // The fleet-client rewrites URLs to use these prefixes.
      "/_proxy/hushd": {
        target: "http://localhost:9876",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/_proxy\/hushd/, ""),
      },
      "/_proxy/control": {
        target: "http://localhost:8080",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/_proxy\/control/, ""),
      },
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    target:
      process.env.TAURI_ENV_PLATFORM === "windows"
        ? "chrome105"
        : "safari13",
    minify: !process.env.TAURI_ENV_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
    rollupOptions: {
      output: {
        manualChunks: {
          "vendor-codemirror": [
            "codemirror",
            "@codemirror/autocomplete",
            "@codemirror/lang-yaml",
            "@codemirror/language",
            "@codemirror/lint",
            "@codemirror/search",
            "@codemirror/state",
            "@codemirror/theme-one-dark",
            "@codemirror/view",
          ],
          "vendor-ui": [
            "react-resizable-panels",
            "react-syntax-highlighter",
            "lucide-react",
            "@tabler/icons-react",
            "motion",
          ],
          "vendor-yaml": ["yaml"],
        },
      },
    },
  },
});
