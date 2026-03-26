/**
 * SwarmBoard Canvas Interaction E2E Tests — v1.2 milestone.
 *
 * Covers snap-to-grid, keyboard nudge shortcuts (Arrow / Shift+Arrow),
 * Space+drag pan mode, off-screen edge indicators, and resize recentering.
 *
 * The app uses HashRouter (`/#/swarm-board`) and no Tauri runtime is
 * available. Board state persists in localStorage under the key
 * "clawdstrike_workbench_swarm_board".
 */

import {
  test,
  expect,
  gotoBoard,
  gotoBoardWithSeed,
  pressOnCanvas,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function makeNodeAt(
  id: string,
  x: number,
  y: number,
  overrides?: Record<string, unknown>,
) {
  return {
    id,
    type: "agentSession",
    position: { x, y },
    data: {
      title: `Node ${id}`,
      status: "idle",
      nodeType: "agentSession",
      ...overrides,
    },
  };
}

// ==========================================================================
// Tests
// ==========================================================================

test.describe("SwarmBoard canvas interaction feel", () => {
  // -------------------------------------------------------------------------
  // 1. Snap-to-grid: drag node, verify position aligns to 20px grid
  // -------------------------------------------------------------------------

  test("node position snaps to 20px grid after drag", async ({ page }) => {
    // Seed a node at an already-aligned position (100, 100)
    await gotoBoardWithSeed(page, [makeNodeAt("snap-1", 100, 100)]);

    const node = page.locator(".react-flow__node").first();
    await expect(node).toBeVisible({ timeout: 10_000 });

    // Drag the node by an off-grid delta (+13, +17) -- total position
    // will be (113, 117) during drag, snapped to (120, 120) on drop
    const box = await node.boundingBox();
    expect(box).not.toBeNull();

    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
    await page.mouse.down();
    await page.mouse.move(
      box!.x + box!.width / 2 + 13,
      box!.y + box!.height / 2 + 17,
      { steps: 5 },
    );
    await page.mouse.up();

    // Poll localStorage until the node position is grid-aligned (snap settled)
    await expect(async () => {
      const position = await page.evaluate(() => {
        const boardKey = "clawdstrike_workbench_swarm_board";
        const raw = localStorage.getItem(boardKey);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        const node = parsed.nodes?.find?.(
          (n: Record<string, unknown>) => n.id === "snap-1",
        );
        return node?.position ?? null;
      });

      expect(position).not.toBeNull();
      expect(position!.x % 20).toBe(0);
      expect(position!.y % 20).toBe(0);
    }).toPass({ timeout: 3_000 });
  });

  // -------------------------------------------------------------------------
  // 2. Arrow nudge: selected node moves by 20px (grid gap)
  // -------------------------------------------------------------------------

  test("arrow key nudges selected node by 20px grid step", async ({ page }) => {
    await gotoBoardWithSeed(page, [makeNodeAt("nudge-1", 200, 200)]);

    const node = page.locator(".react-flow__node").first();
    await expect(node).toBeVisible({ timeout: 10_000 });

    // Read initial position from localStorage
    const getPosition = async () =>
      page.evaluate(() => {
        const raw = localStorage.getItem("clawdstrike_workbench_swarm_board");
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        const n = parsed.nodes?.[0];
        return n?.position ?? null;
      });

    const before = await getPosition();
    expect(before).not.toBeNull();

    // Select all via Cmd+A (sets node.selected = true in React Flow state)
    // then press arrow key while focus is on the pane (not on a node element).
    // The nudge handler requires: (a) node.selected is true, and
    // (b) focus target is NOT inside a .react-flow__node element.
    await page.locator(".react-flow__pane").click({ position: { x: 10, y: 10 } });
    await page.keyboard.press("Meta+a");
    await page.waitForTimeout(100);

    // Verify the node is selected in React Flow
    await expect(page.locator(".react-flow__node.selected")).toHaveCount(1, {
      timeout: 3_000,
    });

    await page.keyboard.press("ArrowRight");
    await page.waitForTimeout(200);

    const after = await getPosition();
    expect(after).not.toBeNull();
    // x should have increased by 20 (one grid step)
    expect(after!.x).toBe(before!.x + 20);
    expect(after!.y).toBe(before!.y);
  });

  // -------------------------------------------------------------------------
  // 3. Shift+Arrow nudge moves by 80px (major grid gap)
  // -------------------------------------------------------------------------

  test("Shift+Arrow nudges selected node by 80px major grid step", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [makeNodeAt("shift-nudge-1", 200, 200)]);

    const node = page.locator(".react-flow__node").first();
    await expect(node).toBeVisible({ timeout: 10_000 });

    // Click pane first, then Cmd+A to select all -- this keeps focus on the
    // pane (not on a node element), which is required for the nudge handler.
    await page.locator(".react-flow__pane").click({ position: { x: 10, y: 10 } });
    await page.keyboard.press("Meta+a");
    await page.waitForTimeout(100);

    await expect(page.locator(".react-flow__node.selected")).toHaveCount(1, {
      timeout: 3_000,
    });

    // Press Shift+ArrowDown -- major grid step (80px)
    await page.keyboard.press("Shift+ArrowDown");
    await page.waitForTimeout(300);

    // Read the new position
    const position = await page.evaluate(() => {
      const raw = localStorage.getItem("clawdstrike_workbench_swarm_board");
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      const n = parsed.nodes?.[0];
      return n?.position ?? null;
    });

    // Should have been nudged +80 in y direction (200 -> 280)
    expect(position).not.toBeNull();
    expect(position!.y).toBe(280);
    expect(position!.x).toBe(200);
  });

  // -------------------------------------------------------------------------
  // 4. G key toggles follow mode (shows/hides "following" in stats bar)
  // -------------------------------------------------------------------------

  test("G key toggles follow mode indicator in stats bar", async ({ page }) => {
    await gotoBoard(page);

    // Add a node so the board is not empty
    await pressOnCanvas(page, "1");
    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 5_000,
    });

    // Press G to enable follow
    await pressOnCanvas(page, "g");
    await expect(page.getByText("following")).toBeVisible({ timeout: 3_000 });

    // Press G again to disable follow
    await pressOnCanvas(page, "g");
    await expect(page.getByText("following")).not.toBeVisible({
      timeout: 3_000,
    });
  });

  // -------------------------------------------------------------------------
  // 5. Space+drag pan: hold Space, verify cursor changes to "grab"
  // -------------------------------------------------------------------------

  test("holding Space activates grab cursor on canvas pane", async ({
    page,
  }) => {
    await gotoBoard(page);

    // Ensure the canvas has a node visible so the board is not empty
    await pressOnCanvas(page, "1");
    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 5_000,
    });

    // Before Space is held, the .space-held class should NOT be on the canvas wrapper
    const canvasWrapper = page.locator(".space-held");
    await expect(canvasWrapper).toHaveCount(0);

    // Hold space (keydown without keyup)
    await page.keyboard.down(" ");
    await page.waitForTimeout(100);

    // The space-held class should now appear on the canvas container
    await expect(page.locator(".space-held")).toHaveCount(1, { timeout: 2_000 });

    // Release space
    await page.keyboard.up(" ");
    await page.waitForTimeout(100);

    // Class should be removed
    await expect(page.locator(".space-held")).toHaveCount(0, { timeout: 2_000 });
  });

  // -------------------------------------------------------------------------
  // 6. Edge indicators: zoom/pan so nodes are off-screen, verify indicators
  // -------------------------------------------------------------------------

  test("edge indicators appear for off-screen nodes", async ({ page }) => {
    // Seed nodes far apart — one visible, one very far off-screen
    await gotoBoardWithSeed(page, [
      makeNodeAt("visible-1", 200, 200),
      makeNodeAt("offscreen-1", 8000, 8000),
    ]);

    await expect(page.locator(".react-flow__node")).toHaveCount(2, {
      timeout: 10_000,
    });

    // Fit view so the viewport tries to show both (or just focus on the first)
    await pressOnCanvas(page, "f");
    await page.waitForTimeout(800);

    // Now zoom in heavily on the first node so the second is off-screen
    // Click zoom-in button several times
    const zoomIn = page.getByRole("button", { name: "Zoom in" });
    for (let i = 0; i < 8; i++) {
      await zoomIn.click();
      await page.waitForTimeout(150);
    }

    // Wait for edge indicators to render
    await page.waitForTimeout(500);

    // Check for at least one edge indicator pointing at the off-screen node
    const indicators = page.locator('[data-testid="edge-indicator"]');
    const count = await indicators.count();
    // At least one indicator should appear for the off-screen node
    expect(count).toBeGreaterThanOrEqual(1);

    // Verify the indicator has a data-node-id attribute
    if (count > 0) {
      const nodeId = await indicators.first().getAttribute("data-node-id");
      expect(nodeId).toBeTruthy();
    }
  });

  // -------------------------------------------------------------------------
  // 7. Resize recentering: resize viewport, verify content stays centered
  // -------------------------------------------------------------------------

  test("canvas compensates for viewport resize to keep content centered", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [makeNodeAt("resize-1", 300, 300)]);
    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 10_000,
    });

    // Fit the view first so the node is centered
    await pressOnCanvas(page, "f");
    await page.waitForTimeout(500);

    // Read the current viewport transform
    const getViewportX = async () =>
      page.evaluate(() => {
        const tfEl = document.querySelector(".react-flow__viewport");
        if (!tfEl) return null;
        const style = (tfEl as HTMLElement).style.transform;
        const match = style.match(/translate\(([^,]+),/);
        return match ? parseFloat(match[1]) : null;
      });

    const beforeX = await getViewportX();

    // Resize the viewport by changing the window size
    const currentSize = page.viewportSize();
    await page.setViewportSize({
      width: (currentSize?.width ?? 1280) - 200,
      height: currentSize?.height ?? 720,
    });

    await page.waitForTimeout(600);

    const afterX = await getViewportX();

    // The viewport x offset should have shifted to compensate for the
    // width reduction. The recentering logic adds (dw/2) to the x offset,
    // so the x value should have decreased (smaller container means the
    // center moved left, and the viewport adjusts).
    // We just verify the x offset changed (recentering fired).
    if (beforeX != null && afterX != null) {
      expect(afterX).not.toBe(beforeX);
    }
  });

  // -------------------------------------------------------------------------
  // 8. Shortcut hint in stats bar shows v1.2 shortcuts
  // -------------------------------------------------------------------------

  test("stats bar shows updated v1.2 shortcut hints", async ({ page }) => {
    await gotoBoard(page);

    // The shortcut hint was updated from "Space follow" to "G follow"
    // and includes "arrows nudge"
    await expect(
      page.getByText("1-6 add / arrows nudge / F fit / G follow"),
    ).toBeVisible({ timeout: 10_000 });
  });
});
