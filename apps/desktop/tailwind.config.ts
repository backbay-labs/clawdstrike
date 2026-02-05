import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // SDR color scheme
        sdr: {
          bg: {
            primary: "#0a0a0f",
            secondary: "#12121a",
            tertiary: "#1a1a24",
          },
          border: {
            DEFAULT: "#2a2a3a",
            subtle: "#1f1f2a",
          },
          text: {
            primary: "#f0f0f5",
            secondary: "#9090a0",
            muted: "#606070",
          },
          accent: {
            blue: "#3b82f6",
            green: "#22c55e",
            amber: "#f59e0b",
            orange: "#f97316",
            red: "#ef4444",
            purple: "#a855f7",
          },
        },
        // Trust level colors
        trust: {
          system: "#22c55e",
          high: "#3b82f6",
          medium: "#f59e0b",
          low: "#f97316",
          untrusted: "#ef4444",
        },
        // Verdict colors
        verdict: {
          allowed: "#22c55e",
          blocked: "#ef4444",
          warn: "#f59e0b",
        },
        // Severity colors
        severity: {
          info: "#3b82f6",
          warning: "#f59e0b",
          error: "#f97316",
          critical: "#ef4444",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        glow: {
          "0%": { opacity: "0.5" },
          "100%": { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
