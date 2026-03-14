import react from "@vitejs/plugin-react";
import { resolve } from "path";
import { defineConfig } from "vite";

const host = process.env.TAURI_DEV_HOST;
const hushdProxyTarget =
  process.env.WORKBENCH_HUSHD_PROXY_TARGET ??
  process.env.HUSHD_URL ??
  "http://localhost:9876";
const controlProxyTarget =
  process.env.WORKBENCH_CONTROL_PROXY_TARGET ??
  process.env.CONTROL_API_URL ??
  "http://localhost:8090";
const hushdProxyAuthorization =
  process.env.WORKBENCH_HUSHD_PROXY_AUTHORIZATION ??
  (process.env.HUSHD_API_KEY ? `Bearer ${process.env.HUSHD_API_KEY}` : undefined);
const controlProxyAuthorization =
  process.env.WORKBENCH_CONTROL_PROXY_AUTHORIZATION ??
  (process.env.WORKBENCH_CONTROL_PROXY_TOKEN
    ? `Bearer ${process.env.WORKBENCH_CONTROL_PROXY_TOKEN}`
    : undefined);

function forwardAuthorizationHeader(proxy: any, fallbackAuthorization?: string) {
  proxy.on("proxyReq", (proxyReq: any, req: { headers: { authorization?: string } }) => {
    const authorization = req.headers.authorization ?? fallbackAuthorization;
    if (authorization) {
      proxyReq.setHeader("authorization", authorization);
    }
  });
}

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
        target: hushdProxyTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/_proxy\/hushd/, ""),
        configure: (proxy) => forwardAuthorizationHeader(proxy, hushdProxyAuthorization),
      },
      "/_proxy/control": {
        target: controlProxyTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/_proxy\/control/, ""),
        configure: (proxy) => forwardAuthorizationHeader(proxy, controlProxyAuthorization),
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
