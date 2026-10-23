/**
 * Production build used only by the OrcaRouter GUI evidence run.
 *
 * The shipping build splits vendor code into many chunks. In the current
 * dependency set that split leaves React and its consumers in chunks with a
 * circular initialization order, so the bundle throws at module init before
 * the app renders in a browser. Bundling all of `node_modules` into one chunk
 * removes the cycle. Nothing here is shipped; `npm run build` keeps the normal
 * chunking.
 */

import { defineConfig, mergeConfig } from "vite";
import base from "../vite.config";

export default mergeConfig(
  base as never,
  defineConfig({
    build: {
      outDir: "dist-evidence",
      rollupOptions: {
        output: {
          manualChunks: (id: string) =>
            id.includes("/node_modules/") ? "vendor-evidence" : undefined,
        },
      },
    },
  }) as never,
);
