/**
 * UI evidence for the OrcaRouter Cyber Inference provider.
 *
 * Drives the real Workbench (Vite dev server from playwright.config.ts):
 *   policy editor → Visual panel → Trustprint guard → provider wizard →
 *   OrcaRouter step 2 (auth methods + catalogue-driven model selectors).
 *
 * `GET /v1/models` is served from the live catalogue when ORCAROUTER_API_KEY is
 * available to the test runner, otherwise from the recorded fixture captured
 * from the same endpoint. No credential ever enters the page.
 *
 * Writes:
 *   orca-evidence/auth-methods.png
 *   orca-evidence/text-model-dropdown.png
 *   orca-evidence/manifest.json
 */

import { expect, test, type Locator, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { seedWorkbench } from "./helpers/workbench-e2e";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EVIDENCE_DIR = path.resolve(HERE, "../../../orca-evidence");
const FIXTURE = path.resolve(HERE, "fixtures/orcarouter-models.json");
const MODELS_URL = "https://api.orcarouter.ai/v1/models?capability=chat";
const PLACEHOLDER_KEY = "sk-orca-e2e-placeholder-0000";

const POLICY = [
  'version: "1.5.0"',
  "name: orcarouter-evidence",
  'description: "OrcaRouter provider evidence"',
  "guards:",
  "  spider_sense:",
  "    enabled: true",
  "    similarity_threshold: 0.85",
  "    ambiguity_band: 0.10",
  'settings: {}',
  "",
].join("\n");

test.use({ viewport: { width: 1440, height: 960 }, video: "off", trace: "off" });

let catalogSource: "live" | "fixture" = "fixture";
let catalogCount = 0;

async function loadCatalog(page: Page): Promise<void> {
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8")) as {
    data: { id: string }[];
  };
  let payload: { data: unknown[] } = { data: fixture.data };

  const apiKey = process.env.ORCAROUTER_API_KEY ?? "";
  if (apiKey) {
    const response = await page.request.get(MODELS_URL, {
      headers: { Authorization: `Bearer ${apiKey}`, accept: "application/json" },
    });
    if (response.ok()) {
      const live = (await response.json()) as { data?: unknown[] };
      if (Array.isArray(live.data) && live.data.length > 0) {
        payload = { data: live.data };
        catalogSource = "live";
      }
    }
  }
  catalogCount = payload.data.length;

  await page.route("**/api.orcarouter.ai/v1/models*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(payload),
    }),
  );
}

/** Screenshot a region around `target` that is at least 800x450. */
async function capture(
  page: Page,
  target: Locator,
  fileName: string,
): Promise<{ width: number; height: number; path: string }> {
  await target.scrollIntoViewIfNeeded();
  const box = await target.boundingBox();
  if (!box) throw new Error(`no bounding box for ${fileName}`);
  const viewport = page.viewportSize() ?? { width: 1440, height: 960 };

  const width = Math.min(Math.max(box.width + 120, 900), viewport.width);
  const height = Math.min(Math.max(box.height + 120, 520), viewport.height);
  const x = Math.min(Math.max(box.x + box.width / 2 - width / 2, 0), viewport.width - width);
  const y = Math.min(Math.max(box.y + box.height / 2 - height / 2, 0), viewport.height - height);

  await page.mouse.move(page.viewportSize()!.width - 5, page.viewportSize()!.height - 5);
  const file = path.join(EVIDENCE_DIR, fileName);
  await page.screenshot({ path: file, clip: { x, y, width, height } });
  return { width: Math.round(width), height: Math.round(height), path: file };
}

async function sha256(file: string): Promise<string> {
  return createHash("sha256").update(await readFile(file)).digest("hex");
}

async function openOrcaRouterPanel(page: Page): Promise<Locator> {
  await page.goto("/#/file//workspace/policies/orcarouter.yml");
  await expect(page.locator(".cm-content").first()).toContainText("orcarouter-evidence");

  await page.getByRole("button", { name: "Visual / YAML Split" }).click();
  await page.getByText("Trustprint", { exact: true }).first().click();
  await expect(page.getByText("Trustprint Profile", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Configure" }).click();
  await expect(page.getByTestId("trustprint-provider-wizard")).toBeVisible();

  await page.getByTestId("provider-card-orcarouter").click();
  await page.getByRole("button", { name: /next/i }).click();
  await expect(page.getByTestId("orcarouter-panel")).toBeVisible();

  // Both authentication choices and the credential seam.
  await page.getByTestId("orcarouter-api-key-input").fill(PLACEHOLDER_KEY);
  await page.getByTestId("orcarouter-save-key").click();
  await expect(page.getByTestId("orcarouter-masked-key")).toBeVisible();
  await expect(page.getByTestId("orcarouter-chat-model-trigger")).toBeEnabled();

  return page.getByTestId("orcarouter-panel");
}

test.beforeEach(async ({ page }) => {
  await mkdir(EVIDENCE_DIR, { recursive: true });
  // The workbench loads web fonts from Google; the evidence run must not
  // depend on external network access, so let the browser fall back to the
  // bundled/system fonts instead of waiting on a stylesheet request.
  await page.route(/fonts\.(googleapis|gstatic)\.com/, (route) => route.abort());
  await seedWorkbench(page, {
    files: [
      {
        path: "workspace/policies/orcarouter.yml",
        content: POLICY,
        fileType: "clawdstrike_policy",
      },
    ],
    tabs: [
      {
        id: "tab-orcarouter",
        documentId: "doc-orcarouter",
        name: "orcarouter.yml",
        filePath: "workspace/policies/orcarouter.yml",
        yaml: POLICY,
        fileType: "clawdstrike_policy",
      },
    ],
    activeTabId: "tab-orcarouter",
  });
  await loadCatalog(page);
});

test("captures auth methods and the live model dropdown", async ({ page }) => {
  await openOrcaRouterPanel(page);

  // ---- auth-methods.png ----
  const apiKeyTab = page.getByTestId("orcarouter-auth-tab-api-key");
  const pkceTab = page.getByTestId("orcarouter-auth-tab-pkce");
  await expect(apiKeyTab).toBeVisible();
  await expect(pkceTab).toBeVisible();
  await expect(pkceTab).toContainText("Connect with OrcaRouter");
  await expect(page.getByTestId("orcarouter-api-key-input")).toHaveAttribute("type", "password");
  await expect(pkceTab).toHaveAttribute("aria-selected", "false");

  const authAnchor = page.getByTestId("orcarouter-auth-tab-api-key");
  const authShot = await capture(page, authAnchor, "auth-methods.png");

  const masked = (await page.getByTestId("orcarouter-masked-key").textContent()) ?? "";
  const secret_masked = masked.length > 0 && !masked.includes(PLACEHOLDER_KEY);
  const controls_enabled =
    (await page.getByTestId("orcarouter-chat-model-trigger").isEnabled()) &&
    (await page.getByTestId("orcarouter-embedding-model-trigger").isEnabled());

  // The PKCE entry point is present and usable, not a dead label.
  await page.getByTestId("orcarouter-auth-tab-pkce").click();
  await expect(page.getByTestId("orcarouter-connect-button")).toBeEnabled();
  await page.getByTestId("orcarouter-auth-tab-api-key").click();

  // ---- text-model-dropdown.png ----
  const trigger = page.getByTestId("orcarouter-chat-model-trigger");
  await trigger.click();
  const dropdown = page.getByTestId("orcarouter-chat-model-panel");
  await expect(dropdown).toBeVisible();

  const options = dropdown.getByRole("option");
  const itemCount = await options.count();
  expect(itemCount).toBeGreaterThan(0);
  // Every chat-capable model in the served catalogue is selectable, so the
  // dropdown count is the catalogue count.
  expect(itemCount).toBe(catalogCount);
  // The default tier leads; dedicated cyber models follow it.
  await expect(options.first()).toContainText("orcarouter/auto");

  const dropdownShot = await capture(page, dropdown, "text-model-dropdown.png");

  const styles = await dropdown.evaluate((node) => {
    const dropdownEl = node as HTMLElement;
    const triggerEl = document.querySelector('[data-testid="orcarouter-chat-model-trigger"]') as HTMLElement | null;
    const cs = getComputedStyle(dropdownEl);
    const rect = dropdownEl.getBoundingClientRect();
    const triggerRect = triggerEl?.getBoundingClientRect();
    return {
      background: cs.backgroundColor,
      borderStyle: cs.borderTopStyle,
      borderWidth: cs.borderTopWidth,
      borderColor: cs.borderTopColor,
      panelRight: rect.right,
      triggerRight: triggerRect?.right ?? rect.right,
    };
  });

  const alpha = (color: string): number => {
    const match = color.match(/rgba?\(([^)]+)\)/);
    if (!match) return 1;
    const parts = match[1].split(",").map((part) => Number(part.trim()));
    return parts.length === 4 ? parts[3] : 1;
  };

  const manifest = {
    automation: {
      framework: "playwright",
      passed: true,
      catalog_source: MODELS_URL,
      catalog_model_count: catalogCount,
      image_model_count: 0,
      catalog_origin: catalogSource,
    },
    artifacts: [
      {
        kind: "auth-methods",
        path: "auth-methods.png",
        sha256: await sha256(authShot.path),
        width: authShot.width,
        height: authShot.height,
        ui: {
          api_key_visible: true,
          secret_masked,
          controls_enabled,
          pkce_visible: true,
        },
      },
      {
        kind: "text-model-dropdown",
        path: "text-model-dropdown.png",
        sha256: await sha256(dropdownShot.path),
        width: dropdownShot.width,
        height: dropdownShot.height,
        ui: {
          dropdown_open: true,
          item_count: itemCount,
          opaque_background: alpha(styles.background) === 1,
          visible_border:
            styles.borderStyle !== "none" &&
            parseFloat(styles.borderWidth) >= 1 &&
            alpha(styles.borderColor) > 0,
          trigger_panel_right_delta: Math.round(Math.abs(styles.panelRight - styles.triggerRight)),
        },
      },
    ],
  };

  expect(authShot.width).toBeGreaterThanOrEqual(800);
  expect(authShot.height).toBeGreaterThanOrEqual(450);
  expect(dropdownShot.width).toBeGreaterThanOrEqual(800);
  expect(dropdownShot.height).toBeGreaterThanOrEqual(450);
  expect(manifest.artifacts[1].ui.opaque_background).toBe(true);
  expect(manifest.artifacts[1].ui.visible_border).toBe(true);
  expect(manifest.artifacts[1].ui.trigger_panel_right_delta).toBeLessThanOrEqual(2);

  await writeFile(path.join(EVIDENCE_DIR, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
});
