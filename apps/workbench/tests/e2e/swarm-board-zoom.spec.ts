/**
 * SwarmBoard Semantic Zoom E2E Tests — v1.2 milestone.
 *
 * Covers the four zoom tiers (full >= 0.6, compact 0.35-0.6, chip 0.18-0.35,
 * dot < 0.18), verifying that node chrome adapts appropriately, and the
 * "Connect to" right-click workflow that creates edges between nodes.
 *
 * The app uses HashRouter (`/#/swarm-board`) and no Tauri runtime is
 * available. Board state persists in localStorage under the key
 * "clawdstrike_workbench_swarm_board".
 */

import {
  test,
  expect,
  gotoBoardWithSeed,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function makeAgentNode(
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
      title: `Agent ${id}`,
      status: "running",
      nodeType: "agentSession",
      agentModel: "opus-4.6",
      branch: "main",
      receiptCount: 3,
      blockedActionCount: 1,
      changedFilesCount: 5,
      risk: "medium",
      previewLines: ["$ cargo test", "test result: ok. 42 passed"],
      ...overrides,
    },
  };
}

function makeTwoConnectableNodes() {
  return [
    {
      id: "connect-source",
      type: "agentSession",
      position: { x: 100, y: 100 },
      data: {
        title: "Source Agent",
        status: "idle",
        nodeType: "agentSession",
      },
    },
    {
      id: "connect-target",
      type: "agentSession",
      position: { x: 500, y: 100 },
      data: {
        title: "Target Agent",
        status: "idle",
        nodeType: "agentSession",
      },
    },
  ];
}

// ==========================================================================
// Tests
// ==========================================================================

test.describe("SwarmBoard semantic zoom tiers", () => {
  // -------------------------------------------------------------------------
  // 1. Full tier (zoom >= 0.6): verify full node chrome visible
  // -------------------------------------------------------------------------

  test("full tier shows complete node chrome at default zoom", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("full-1", 200, 200),
    ]);

    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible({ timeout: 10_000 });

    // At default zoom (1.0), the node is in "full" tier.
    // Full tier shows: title bar, terminal body, footer metrics, window controls.

    // Title bar content — agent model and branch should be visible
    await expect(node.locator("text=opus-4.6")).toBeVisible();
    await expect(node.locator("text=main")).toBeVisible();

    // Status label in title bar
    await expect(node.locator("text=RUN")).toBeVisible();

    // Footer metrics should be visible (files changed, receipts, blocked)
    await expect(node.locator('[title="5 files changed"]')).toBeVisible();
    await expect(node.locator('[title="3 receipts"]')).toBeVisible();

    // Window controls (maximize/close buttons)
    await node.click(); // Select to show controls
    await expect(
      node.locator('[aria-label="Maximize session"]'),
    ).toBeVisible();
    await expect(node.locator('[aria-label="Close session"]')).toBeVisible();

    // Terminal body area should exist (preview lines)
    await expect(node.locator("text=cargo test")).toBeVisible();
  });

  // -------------------------------------------------------------------------
  // 2. Compact tier (0.35-0.6): verify metrics condensed, labels removed
  // -------------------------------------------------------------------------

  test("compact tier condenses node at medium zoom", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("compact-1", 200, 200),
    ]);

    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 10_000,
    });

    // Zoom out to reach compact tier (0.35-0.6).
    // Click zoom out button repeatedly. Each click typically reduces by ~20%.
    const zoomOut = page.getByRole("button", { name: "Zoom out" });
    for (let i = 0; i < 4; i++) {
      await zoomOut.click();
      await page.waitForTimeout(200);
    }

    // Wait for the zoom indicator to appear and show a value in compact range
    await page.waitForTimeout(500);

    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible();

    // In compact tier:
    // - Title bar still visible (status dot + model + status label)
    // - Terminal body is hidden
    // - Footer metrics are condensed (reduced height)
    // - Window controls (maximize/close) are hidden

    // The status label should still be visible
    await expect(node.locator("text=RUN")).toBeVisible({ timeout: 3_000 });

    // Terminal preview lines should NOT be visible in compact tier
    // (terminal body is only rendered in "full" tier)
    const terminalContent = node.locator("text=cargo test");
    await expect(terminalContent).not.toBeVisible({ timeout: 3_000 });
  });

  // -------------------------------------------------------------------------
  // 3. Chip tier (0.18-0.35): verify summary chip rendering
  // -------------------------------------------------------------------------

  test("chip tier renders minimal summary chip at low zoom", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("chip-1", 200, 200),
    ]);

    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 10_000,
    });

    // Zoom out significantly to reach chip tier (0.18-0.35)
    const zoomOut = page.getByRole("button", { name: "Zoom out" });
    for (let i = 0; i < 7; i++) {
      await zoomOut.click();
      await page.waitForTimeout(200);
    }

    await page.waitForTimeout(500);

    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible();

    // In chip tier, the node renders as a single compact row:
    // - Status dot (small colored circle)
    // - Truncated title
    // - Status label (RUN, IDLE, etc.)
    // The node should still contain the status label text
    // but the full chrome (footer metrics, terminal) is gone

    // Terminal preview lines should NOT be visible
    await expect(node.locator("text=cargo test")).not.toBeVisible({ timeout: 2_000 });
    // Footer metrics should NOT be visible
    await expect(node.locator('[title="5 files changed"]')).not.toBeVisible({ timeout: 2_000 });
  });

  // -------------------------------------------------------------------------
  // 4. Dot tier (< 0.18): verify minimal dot rendering
  // -------------------------------------------------------------------------

  test("dot tier renders minimal rectangle at very low zoom", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("dot-1", 200, 200),
    ]);

    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 10_000,
    });

    // Zoom out very aggressively to reach dot tier (< 0.18)
    const zoomOut = page.getByRole("button", { name: "Zoom out" });
    for (let i = 0; i < 12; i++) {
      await zoomOut.click();
      await page.waitForTimeout(150);
    }

    await page.waitForTimeout(500);

    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible();

    // In dot tier, the node is a minimal colored rectangle.
    // - No text content visible (title, model, status label all gone)
    // - Just a colored border-left indicator with handles
    // Verify: no visible model text ("opus-4.6") or status labels ("RUN") remain
    await expect(node.locator("text=opus-4.6")).not.toBeVisible({ timeout: 2_000 });
    await expect(node.locator("text=RUN")).not.toBeVisible({ timeout: 2_000 });
  });

  // -------------------------------------------------------------------------
  // 5. Zoom indicator appears during zoom transitions
  // -------------------------------------------------------------------------

  test("zoom indicator shows zoom level during zoom transitions", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("zoom-ind-1", 200, 200),
    ]);

    await expect(page.locator(".react-flow__node")).toHaveCount(1, {
      timeout: 10_000,
    });

    // Click zoom in
    const zoomIn = page.getByRole("button", { name: "Zoom in" });
    await zoomIn.click();

    // The zoom indicator should appear briefly
    const indicator = page.locator('[data-testid="canvas-zoom-indicator"]');
    await expect(indicator).toBeVisible({ timeout: 3_000 });
    // It should contain a percentage or zoom level
    const text = await indicator.textContent();
    expect(text).toBeTruthy();
  });
});

test.describe("SwarmBoard connect-to workflow", () => {
  // -------------------------------------------------------------------------
  // 6. Connect-to: right-click -> Connect to -> click target -> verify edge
  // -------------------------------------------------------------------------

  test("Connect to workflow creates an edge between two nodes", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, makeTwoConnectableNodes());

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(2, { timeout: 10_000 });

    const sourceNode = nodes.nth(0);
    const targetNode = nodes.nth(1);

    // Verify no edges exist initially
    const initialEdgeCount = await page.locator(".react-flow__edge").count();
    expect(initialEdgeCount).toBe(0);

    // Right-click the source node to open context menu
    await sourceNode.click({ button: "right" });

    // The context menu should appear with "Connect to..." option
    const connectOption = page.locator('[aria-label="Connect to\u2026"]');
    await expect(connectOption).toBeVisible({ timeout: 3_000 });

    // Click "Connect to..."
    await connectOption.click();
    await page.waitForTimeout(200);

    // Verify the connecting indicator appears
    const connectIndicator = page.locator('[data-testid="connecting-indicator"]');
    await expect(connectIndicator).toBeVisible({ timeout: 3_000 });
    await expect(connectIndicator).toContainText("Click a target node to connect");

    // Click the target node to complete the connection
    await targetNode.click();
    await page.waitForTimeout(300);

    // Connecting indicator should disappear
    await expect(connectIndicator).not.toBeVisible({ timeout: 3_000 });

    // An edge should now exist between source and target
    const finalEdgeCount = await page.locator(".react-flow__edge").count();
    expect(finalEdgeCount).toBe(1);

    // Verify edge is persisted in the stats bar
    await expect(page.getByText("1 edges")).toBeVisible({ timeout: 3_000 });
  });

  // -------------------------------------------------------------------------
  // 7. Connect-to can be cancelled with Escape
  // -------------------------------------------------------------------------

  test("Connect to workflow can be cancelled with Escape", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, makeTwoConnectableNodes());

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(2, { timeout: 10_000 });

    // Right-click source node
    await nodes.nth(0).click({ button: "right" });
    const connectOption = page.locator('[aria-label="Connect to\u2026"]');
    await expect(connectOption).toBeVisible({ timeout: 3_000 });
    await connectOption.click();

    // Connecting indicator should appear
    const connectIndicator = page.locator('[data-testid="connecting-indicator"]');
    await expect(connectIndicator).toBeVisible({ timeout: 3_000 });

    // Press Escape to cancel
    await page.keyboard.press("Escape");

    // Indicator should disappear and no edge should be created
    await expect(connectIndicator).not.toBeVisible({ timeout: 3_000 });
    const edgeCount = await page.locator(".react-flow__edge").count();
    expect(edgeCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 8. Connect-to Cancel button works
  // -------------------------------------------------------------------------

  test("Connect to Cancel button dismisses connecting mode", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, makeTwoConnectableNodes());

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(2, { timeout: 10_000 });

    // Trigger connecting mode
    await nodes.nth(0).click({ button: "right" });
    await page.locator('[aria-label="Connect to\u2026"]').click();

    const connectIndicator = page.locator('[data-testid="connecting-indicator"]');
    await expect(connectIndicator).toBeVisible({ timeout: 3_000 });

    // Click the Cancel button inside the connecting indicator
    await connectIndicator.locator("text=Cancel (Esc)").click();

    await expect(connectIndicator).not.toBeVisible({ timeout: 3_000 });
    const edgeCount = await page.locator(".react-flow__edge").count();
    expect(edgeCount).toBe(0);
  });
});
