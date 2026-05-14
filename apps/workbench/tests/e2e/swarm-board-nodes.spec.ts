/**
 * SwarmBoard node operations — E2E tests.
 *
 * Covers keyboard quick-add (1-6), toolbar buttons, inspector panel,
 * context menu actions (inspect / duplicate / delete), and board
 * management (clear, auto layout, fit view).
 *
 * The app uses HashRouter (`/#/swarm-board`) and no Tauri runtime is
 * available, so spawn actions (Claude, Terminal) fall back to offline
 * placeholder nodes.
 */

import { test, expect, gotoBoard, pressOnCanvas } from "./fixtures";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("SwarmBoard node operations", () => {
  test.beforeEach(async ({ page }) => {
    await gotoBoard(page);
  });

  // 1. Quick-add nodes via keyboard (1-6)
  test("quick-add nodes via keyboard 1-6", async ({ page }) => {
    const types = [
      { key: "1", cls: ".react-flow__node-agentSession" },
      { key: "2", cls: ".react-flow__node-terminalTask" },
      { key: "3", cls: ".react-flow__node-artifact" },
      { key: "4", cls: ".react-flow__node-diff" },
      { key: "5", cls: ".react-flow__node-note" },
      { key: "6", cls: ".react-flow__node-receipt" },
    ];

    for (const { key, cls } of types) {
      await pressOnCanvas(page, key);
      await expect(page.locator(cls).first()).toBeVisible({ timeout: 5_000 });
    }

    // All six node types should now exist on the board.
    await expect(page.locator(".react-flow__node")).toHaveCount(6);
  });

  // 2. Node selection opens inspector
  test("clicking a node opens the inspector panel", async ({ page }) => {
    await pressOnCanvas(page, "1"); // add agentSession node
    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible();

    await node.click();

    // Inspector panel slides in from the right.
    const inspector = page.locator('[aria-label="Node inspector"]');
    await expect(inspector).toBeVisible({ timeout: 5_000 });

    // Inspector should display the node title.
    await expect(inspector.getByText("New Session")).toBeVisible();

    // Escape closes the inspector.
    await page.keyboard.press("Escape");
    await expect(inspector).not.toBeVisible({ timeout: 3_000 });
  });

  // 3. Node deletion via context menu
  test("delete node via context menu", async ({ page }) => {
    await pressOnCanvas(page, "5"); // add note node
    const node = page.locator(".react-flow__node-note").first();
    await expect(node).toBeVisible();

    // Right-click opens context menu.
    await node.click({ button: "right" });

    const menu = page.locator('[aria-label="Delete"]');
    await expect(menu).toBeVisible({ timeout: 3_000 });

    // Verify other context menu items are present.
    await expect(page.locator('[aria-label="Inspect"]')).toBeVisible();
    await expect(page.locator('[aria-label="Duplicate"]')).toBeVisible();

    // Click Delete.
    await menu.click();

    // Node should be removed.
    await expect(page.locator(".react-flow__node")).toHaveCount(0, { timeout: 5_000 });
    await expect(page.locator("text=0 nodes")).toBeVisible();
  });

  // 4. Node duplication via context menu
  test("duplicate node via context menu", async ({ page }) => {
    await pressOnCanvas(page, "1"); // add agentSession node
    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible();

    await node.click({ button: "right" });
    const duplicateBtn = page.locator('[aria-label="Duplicate"]');
    await expect(duplicateBtn).toBeVisible({ timeout: 3_000 });
    await duplicateBtn.click();

    // Should now have 2 agentSession nodes.
    await expect(page.locator(".react-flow__node-agentSession")).toHaveCount(2, { timeout: 5_000 });

    // The duplicated node should include "(copy)" in its title.
    await expect(page.locator("text=(copy)").first()).toBeVisible();
  });

  // 5. Claude button spawns offline node in web mode
  test("Claude button spawns offline fallback node", async ({ page }) => {
    const claudeBtn = page.locator('[aria-label="New Claude Session"]');
    await expect(claudeBtn).toBeVisible();
    await claudeBtn.click();

    // Without Tauri, the handler catches the error and adds an offline node.
    const offlineNode = page.locator("text=Claude (offline)");
    await expect(offlineNode.first()).toBeVisible({ timeout: 10_000 });
  });

  // 6. Terminal button spawns offline node in web mode
  test("Terminal button spawns offline fallback node", async ({ page }) => {
    const terminalBtn = page.locator('[aria-label="New Terminal"]');
    await expect(terminalBtn).toBeVisible();
    await terminalBtn.click();

    const offlineNode = page.locator("text=Terminal (offline)");
    await expect(offlineNode.first()).toBeVisible({ timeout: 10_000 });
  });

  // 7. Note button adds a note node
  test("Note toolbar button adds a note node", async ({ page }) => {
    const noteBtn = page.locator('[aria-label="Add Note"]');
    await expect(noteBtn).toBeVisible();
    await noteBtn.click();

    await expect(page.locator(".react-flow__node-note").first()).toBeVisible({ timeout: 5_000 });
  });

  // 8. Clear board removes all nodes
  test("clear board removes all nodes", async ({ page }) => {
    await pressOnCanvas(page, "1");
    await pressOnCanvas(page, "2");
    await pressOnCanvas(page, "5");
    await expect(page.locator(".react-flow__node")).toHaveCount(3, { timeout: 5_000 });

    const clearBtn = page.locator('[aria-label="Clear board"]');
    await expect(clearBtn).toBeVisible();
    await clearBtn.click();

    await expect(page.locator(".react-flow__node")).toHaveCount(0, { timeout: 5_000 });
    await expect(page.locator("text=spawn a session to start operating")).toBeVisible();
  });

  // 9. Auto Layout repositions nodes without removing them
  test("auto layout repositions nodes", async ({ page }) => {
    await pressOnCanvas(page, "1");
    await pressOnCanvas(page, "1");
    await pressOnCanvas(page, "2");
    await pressOnCanvas(page, "5");
    await expect(page.locator(".react-flow__node")).toHaveCount(4, { timeout: 5_000 });

    const layoutBtn = page.locator('[aria-label="Auto Layout"]');
    await expect(layoutBtn).toBeVisible();
    await layoutBtn.click();

    // All 4 nodes should still be present after layout.
    await expect(page.locator(".react-flow__node")).toHaveCount(4);
  });

  // 10. Keyboard shortcut F fits view
  test("pressing F fits view without removing nodes", async ({ page }) => {
    await pressOnCanvas(page, "1");
    await pressOnCanvas(page, "1");
    await expect(page.locator(".react-flow__node")).toHaveCount(2, { timeout: 5_000 });

    await pressOnCanvas(page, "f");

    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    await expect(page.locator(".react-flow__node").first()).toBeVisible();
  });
});
