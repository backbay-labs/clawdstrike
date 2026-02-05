import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      // Tauri v2: `invoke` lives in `@tauri-apps/api/core`
      "@tauri-apps/api/tauri": "@tauri-apps/api/core",
    },
    dedupe: ["react", "react-dom", "three", "@react-three/fiber", "@react-three/drei"],
  },
  define: {
    "process.env": {},
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV || "development"),
  },
  css: {
    postcss: "./postcss.config.js",
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: ["es2021", "chrome105", "safari13"],
    minify: process.env.TAURI_DEBUG ? false : "esbuild",
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
