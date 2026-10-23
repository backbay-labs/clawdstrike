import { existsSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

// Prefer an explicit browser path (CI images often ship a system Chromium and
// no Playwright browser download), then fall back to Playwright's own browser.
const chromiumExecutable =
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ??
  (existsSync("/usr/bin/chromium") ? "/usr/bin/chromium" : undefined);

export default defineConfig({
  testDir: ".",
  testMatch: ["e2e/**/*.spec.ts", "tests/e2e/**/*.spec.ts"],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:1421",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    launchOptions: chromiumExecutable
      ? { executablePath: chromiumExecutable, args: ["--no-sandbox"] }
      : undefined,
  },
  webServer: {
    // E2E normally runs against the dev server; point
    // PLAYWRIGHT_WEB_SERVER_COMMAND at `npm run preview -- …` to run the same
    // specs against a production build instead.
    command:
      process.env.PLAYWRIGHT_WEB_SERVER_COMMAND ??
      "npm run dev -- --host 127.0.0.1 --port 1421",
    url: "http://127.0.0.1:1421",
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
