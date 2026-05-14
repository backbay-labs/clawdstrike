import react from "@vitejs/plugin-react";
import { resolve } from "path";
import { defineConfig } from "vite";
import { pluginEvalMiddleware } from "./src/lib/plugins/playground/playground-eval-server";
import {
  resolveWorkbenchManualChunk,
  resolveWorkbenchModulePreloadDependencies,
} from "./build/workbench-chunking";

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
  plugins: [
    react(),
    {
      name: "clawdstrike-plugin-eval",
      configureServer(server) {
        server.middlewares.use("/__plugin-eval", pluginEvalMiddleware);
      },
    },
  ],
  resolve: {
    alias: [
      { find: /^@\//, replacement: `${resolve(__dirname, "src")}/` },
      {
        find: /^@clawdstrike\/plugin-sdk$/,
        replacement: resolve(__dirname, "../../packages/sdk/plugin-sdk/src/index.ts"),
      },
      {
        find: /^@clawdstrike\/plugin-sdk\/testing$/,
        replacement: resolve(__dirname, "../../packages/sdk/plugin-sdk/src/testing.ts"),
      },
    ],
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
        ws: true,
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
    modulePreload: {
      resolveDependencies: resolveWorkbenchModulePreloadDependencies,
    },
    target:
      process.env.TAURI_ENV_PLATFORM === "windows"
        ? "chrome105"
        : "safari13",
    minify: !process.env.TAURI_ENV_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
    rollupOptions: {
      output: {
        manualChunks: resolveWorkbenchManualChunk,
      },
    },
  },
});
