import { expect, test } from "@playwright/test";
import { expectEditorToContain, makePolicyYaml, seedWorkbench } from "./helpers/workbench-e2e";

const alphaFresh = makePolicyYaml("alpha-fresh", "explorer fixture");
const alphaStale = makePolicyYaml("alpha-stale", "persisted tab snapshot");
const signalsFresh = makePolicyYaml("signals-fresh", "needle in the haystack");
const signalsStale = makePolicyYaml("signals-stale", "outdated search snapshot");
const unicodeWholeWord = makePolicyYaml("unicode-whole-word", "ẞ");
const unicodeInsideWord = makePolicyYaml("unicode-inside-word", "maßstab");
const unicodeCombiningPrefix = makePolicyYaml("unicode-combining-prefix", "ͅß");
const truncatedPreview = makePolicyYaml(
  "truncated-preview",
  `${"x".repeat(610)}deepneedle`,
);
const alphaFileRoute = "/#/file//workspace/policies/alpha.yml";

test.use({ viewport: { width: 1440, height: 960 } });

test.beforeEach(async ({ page }) => {
  await seedWorkbench(page, {
    files: [
      {
        path: "workspace/policies/alpha.yml",
        content: alphaFresh,
        fileType: "clawdstrike_policy",
      },
      {
        path: "workspace/policies/signals.yml",
        content: signalsFresh,
        fileType: "clawdstrike_policy",
      },
      {
        path: "workspace/policies/unicode-word.yml",
        content: unicodeWholeWord,
        fileType: "clawdstrike_policy",
      },
      {
        path: "workspace/policies/unicode-inside-word.yml",
        content: unicodeInsideWord,
        fileType: "clawdstrike_policy",
      },
      {
        path: "workspace/policies/unicode-combining-prefix.yml",
        content: unicodeCombiningPrefix,
        fileType: "clawdstrike_policy",
      },
      {
        path: "workspace/policies/truncated-preview.yml",
        content: truncatedPreview,
        fileType: "clawdstrike_policy",
      },
    ],
    tabs: [
      {
        id: "tab-alpha",
        documentId: "doc-alpha",
        name: "alpha.yml",
        filePath: "workspace/policies/alpha.yml",
        yaml: alphaStale,
        fileType: "clawdstrike_policy",
      },
      {
        id: "tab-signals",
        documentId: "doc-signals",
        name: "signals.yml",
        filePath: "workspace/policies/signals.yml",
        yaml: signalsStale,
        fileType: "clawdstrike_policy",
      },
    ],
    activeTabId: "tab-alpha",
  });
});

test("sidebar explorer opens the latest file content from the workspace", async ({ page }) => {
  await page.goto(alphaFileRoute);

  await expectEditorToContain(page, "name: alpha-stale");
  await expect(page.locator("#sidebar-panel")).toContainText("Explorer");

  await page.locator("#sidebar-panel button").filter({ hasText: "signals.yml" }).first().click();

  await expectEditorToContain(page, "name: signals-fresh");
  await expectEditorToContain(page, "description: needle in the haystack");
});

test("sidebar explorer creates a file and loads it into the editor", async ({ page }) => {
  await page.goto(alphaFileRoute);

  await expect(page.locator("#sidebar-panel")).toContainText("Explorer");
  await page.locator("#sidebar-panel").getByTitle("New File").click();
  await page.getByPlaceholder("filename.yaml").fill("fresh-policy.yml");
  await page.getByPlaceholder("filename.yaml").press("Enter");

  await expect(page.locator("text=fresh-policy.yml").first()).toBeVisible();
  await expectEditorToContain(page, "name: fresh-policy");
});

test("sidebar search opens the match and queues an editor reveal target", async ({ page }) => {
  await page.goto(alphaFileRoute);

  await page.getByTitle("Search (Cmd+Shift+F)").click();
  await page.getByPlaceholder("Search files...").fill("needle");

  await expect(page.getByText("1 results in 1 files")).toBeVisible();
  await page.locator("#sidebar-panel button").filter({ hasText: "needle in the haystack" }).first().click();

  await expectEditorToContain(page, "name: signals-fresh");

  await expect
    .poll(async () =>
      page.evaluate(() => (window as Window & { __WORKBENCH_E2E_LAST_REVEAL__?: unknown }).__WORKBENCH_E2E_LAST_REVEAL__),
    )
    .toEqual({
      filePath: "/workspace/policies/signals.yml",
      lineNumber: 3,
      startColumn: 14,
      endColumn: 20,
    });
});

test("sidebar search whole-word matching stays aligned with the unicode-aware backend", async ({
  page,
}) => {
  await page.goto(alphaFileRoute);

  await page.getByTitle("Search (Cmd+Shift+F)").click();
  await page.getByPlaceholder("Search files...").fill("ß");
  await page.getByTitle("Match Whole Word").click();

  await expect(page.getByText("1 results in 1 files")).toBeVisible();
  await expect(page.locator("#sidebar-panel")).toContainText("unicode-word.yml");
  await expect(page.locator("#sidebar-panel")).not.toContainText("unicode-inside-word.yml");
  await expect(page.locator("#sidebar-panel")).not.toContainText("unicode-combining-prefix.yml");
  await expect(page.locator("#sidebar-panel")).toContainText("ẞ");
});

test("sidebar search preserves source offsets when preview lines are truncated", async ({
  page,
}) => {
  await page.goto(alphaFileRoute);

  await page.getByTitle("Search (Cmd+Shift+F)").click();
  await page.getByPlaceholder("Search files...").fill("deepneedle");

  await expect(page.getByText("1 results in 1 files")).toBeVisible();
  await page.locator("#sidebar-panel [role='button']").filter({ hasText: "truncated-preview.yml" }).first().click();

  await expectEditorToContain(page, "name: truncated-preview");

  await expect
    .poll(async () =>
      page.evaluate(() => (window as Window & { __WORKBENCH_E2E_LAST_REVEAL__?: unknown }).__WORKBENCH_E2E_LAST_REVEAL__),
    )
    .toEqual({
      filePath: "/workspace/policies/truncated-preview.yml",
      lineNumber: 3,
      startColumn: 624,
      endColumn: 634,
    });
});

test("settings renders the Claude Code tab without crashing", async ({ page }) => {
  await page.goto("/#/settings");

  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await page.getByRole("button", { name: "Claude Code" }).click();
  await expect(page.getByText("Show Claude Code Hints")).toBeVisible();
  await expect(page.getByText("Dashboard & Editor")).toBeVisible();
});

test("observatory route mounts without tripping the error boundary", async ({ page }) => {
  await page.goto("/#/observatory");

  await expect(page.getByTestId("observatory-status-strip")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Observatory Error")).toHaveCount(0);
  await expect(page.locator("[data-observatory-mode]")).toBeVisible();
});
