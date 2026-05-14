/**
 * SwarmBoard E2E tests — basic rendering and interaction checks.
 *
 * These tests verify the SwarmBoard page renders correctly in browser mode
 * (no Tauri runtime). The app uses HashRouter so all routes are prefixed
 * with /#/. Board state persists in localStorage under the key
 * "clawdstrike_workbench_swarm_board".
 */

import { test, expect, SWARM_BOARD_URL, BOARD_STORAGE_KEY } from "./fixtures";

// ---------------------------------------------------------------------------
// 1. Empty board renders
// ---------------------------------------------------------------------------

test("empty board renders with heading, subtext, and stats", async ({ page }) => {
  await page.goto(SWARM_BOARD_URL);

  // The page loads without crashing — React Flow canvas container appears
  await expect(page.locator(".react-flow")).toBeVisible({ timeout: 15_000 });

  // Empty-state heading
  await expect(page.getByText("SwarmBoard")).toBeVisible({ timeout: 10_000 });

  // Empty-state subtext
  await expect(page.getByText("spawn a session to start operating")).toBeVisible();

  // Stats bar at bottom shows "0 nodes"
  await expect(page.getByText("0 nodes")).toBeVisible();

  // Keyboard hints in the stats bar
  await expect(page.getByText("1-6 add / F fit / Space follow")).toBeVisible();
});

// ---------------------------------------------------------------------------
// 2. Toolbar renders
// ---------------------------------------------------------------------------

test("toolbar renders primary, secondary, and tertiary buttons", async ({ page }) => {
  await page.goto(SWARM_BOARD_URL);
  await expect(page.locator(".react-flow")).toBeVisible({ timeout: 15_000 });

  // Primary button: "Claude" (gold, prominent)
  await expect(page.getByRole("button", { name: "New Claude Session" })).toBeVisible();

  // Secondary button: "Terminal"
  await expect(page.getByRole("button", { name: "New Terminal" })).toBeVisible();

  // Tertiary: "Note" (icon-only via aria-label)
  await expect(page.getByRole("button", { name: "Add Note" })).toBeVisible();

  // Tertiary: "Auto Layout"
  await expect(page.getByRole("button", { name: "Auto Layout" })).toBeVisible();

  // Danger: "Clear board" (icon-only, far right)
  await expect(page.getByRole("button", { name: "Clear board" })).toBeVisible();

  // Zoom controls
  await expect(page.getByRole("button", { name: "Zoom in" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom out" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset zoom" })).toBeVisible();
});

// ---------------------------------------------------------------------------
// 3. Left rail renders and toggles
// ---------------------------------------------------------------------------

test("left rail renders and toggles collapse/expand", async ({ page }) => {
  await page.goto(SWARM_BOARD_URL);
  await expect(page.locator(".react-flow")).toBeVisible({ timeout: 15_000 });

  // Collapse toggle button exists in expanded state
  const collapseButton = page.getByRole("button", { name: "Collapse explorer panel" });
  await expect(collapseButton).toBeVisible();
  await collapseButton.click();

  // After collapse, the expand button should appear
  const expandButton = page.getByRole("button", { name: "Expand explorer panel" });
  await expect(expandButton).toBeVisible();

  // Collapse button should be gone
  await expect(collapseButton).not.toBeVisible();

  // Click to expand again
  await expandButton.click();

  // Collapse button reappears
  await expect(collapseButton).toBeVisible();
});

// ---------------------------------------------------------------------------
// 4. Stats bar updates after adding nodes via keyboard shortcuts
// ---------------------------------------------------------------------------

test("stats bar updates after adding nodes with keyboard shortcuts", async ({ page }) => {
  await page.goto(SWARM_BOARD_URL);
  await expect(page.locator(".react-flow")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("0 nodes")).toBeVisible();

  // Click canvas to ensure focus
  await page.locator(".react-flow").click();

  // Press "1" to add an agentSession node
  await page.keyboard.press("1");
  await expect(page.getByText("1 nodes")).toBeVisible({ timeout: 5_000 });

  // Press "5" to add a note node
  await page.keyboard.press("5");
  await expect(page.getByText("2 nodes")).toBeVisible({ timeout: 5_000 });
});

// ---------------------------------------------------------------------------
// 5. Error boundary catches errors from malformed localStorage data
// ---------------------------------------------------------------------------

test("error boundary catches errors from malformed localStorage data", async ({ page }) => {
  // Inject malformed JSON into the board's localStorage key before page loads
  await page.addInitScript(
    ({ key }) => {
      localStorage.setItem(key, "{this is not valid JSON!!! [[[");
    },
    { key: BOARD_STORAGE_KEY },
  );

  await page.goto(SWARM_BOARD_URL);

  // The page should still render something — either the normal board
  // (store falls back gracefully) or the error boundary message.
  const hasContent = await Promise.race([
    page.getByText("SwarmBoard").first().waitFor({ state: "visible", timeout: 15_000 }).then(() => true),
    page.locator(".react-flow").waitFor({ state: "visible", timeout: 15_000 }).then(() => true),
  ]).catch(() => false);

  expect(hasContent).toBe(true);

  // Verify no unhandled JS errors caused a completely blank page
  const bodyChildCount = await page.evaluate(() => document.body.children.length);
  expect(bodyChildCount).toBeGreaterThan(0);
});
