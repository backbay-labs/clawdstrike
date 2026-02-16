import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
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
