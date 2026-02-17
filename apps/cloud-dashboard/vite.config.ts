import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const base = process.env.VITE_BASE_PATH || "/";

export default defineConfig({
  base,
  plugins: [react(), tailwindcss()],
  server: {
    port: 3100,
    proxy: {
      "/api": {
        target: "http://localhost:9876",
        changeOrigin: true,
      },
      "/health": {
        target: "http://localhost:9876",
        changeOrigin: true,
      },
    },
  },
});
