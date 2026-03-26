/**
 * SwarmBoard Multi-Select & Comparison E2E Tests — v1.2 milestone.
 *
 * Covers Shift+click multi-selection, comparison inspector mode (680px wide),
 * mixed-type comparison, single-node regression (340px), and overflow guard
 * for selections exceeding MAX_COMPARISON_NODES (6).
 *
 * The app uses HashRouter (`/#/swarm-board`) and no Tauri runtime is
 * available. Board state persists in localStorage under the key
 * "clawdstrike_workbench_swarm_board".
 */

import {
  test,
  expect,
  gotoBoardWithSeed,
  inspector,
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
      status: "idle",
      nodeType: "agentSession",
      agentModel: "claude",
      ...overrides,
    },
  };
}

function makeReceiptNode(
  id: string,
  x: number,
  y: number,
  overrides?: Record<string, unknown>,
) {
  return {
    id,
    type: "receipt",
    position: { x, y },
    data: {
      title: `Receipt ${id}`,
      status: "idle",
      nodeType: "receipt",
      verdict: "allow",
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
      ],
      ...overrides,
    },
  };
}

function makeNoteNode(id: string, x: number, y: number) {
  return {
    id,
    type: "note",
    position: { x, y },
    data: {
      title: `Note ${id}`,
      status: "idle",
      nodeType: "note",
      content: `Content of ${id}`,
    },
  };
}

// ==========================================================================
// Tests
// ==========================================================================

test.describe("SwarmBoard multi-select and comparison", () => {
  // -------------------------------------------------------------------------
  // 1. Shift+click multi-select: select 2+ nodes, verify selection state
  // -------------------------------------------------------------------------

  test("Shift+click selects multiple nodes", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("ms-agent-1", 100, 100),
      makeAgentNode("ms-agent-2", 500, 100),
      makeAgentNode("ms-agent-3", 100, 400),
    ]);

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(3, { timeout: 10_000 });

    // Click first node (normal click)
    await nodes.nth(0).click();
    await page.waitForTimeout(200);

    // Shift+click second node to add to selection
    await nodes.nth(1).click({ modifiers: ["Shift"] });
    await page.waitForTimeout(200);

    // Both nodes should be selected (React Flow adds .selected class)
    const selectedNodes = page.locator(".react-flow__node.selected");
    await expect(selectedNodes).toHaveCount(2, { timeout: 5_000 });

    // Shift+click third node
    await nodes.nth(2).click({ modifiers: ["Shift"] });
    await page.waitForTimeout(200);

    await expect(selectedNodes).toHaveCount(3, { timeout: 5_000 });
  });

  // -------------------------------------------------------------------------
  // 2. Comparison inspector: select 2 same-type nodes, verify 680px width
  // -------------------------------------------------------------------------

  test("comparison inspector opens at 680px when 2 same-type nodes are selected", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("comp-agent-1", 100, 100, { agentModel: "opus-4.6" }),
      makeAgentNode("comp-agent-2", 500, 100, { agentModel: "sonnet-3.5" }),
    ]);

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(2, { timeout: 10_000 });

    // Select first node
    await nodes.nth(0).click();
    await page.waitForTimeout(200);

    // Shift+click second node
    await nodes.nth(1).click({ modifiers: ["Shift"] });
    await page.waitForTimeout(300);

    // The comparison panel should appear with aria-label "Node comparison"
    const comparisonPanel = page.locator('[aria-label="Node comparison"]');
    await expect(comparisonPanel).toBeVisible({ timeout: 5_000 });

    // Verify the panel width is 680px
    const box = await comparisonPanel.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBe(680);
  });

  // -------------------------------------------------------------------------
  // 3. Mixed selection: select different node types, verify comparison view
  // -------------------------------------------------------------------------

  test("mixed-type selection shows mixed comparison view", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("mix-agent-1", 100, 100),
      makeReceiptNode("mix-receipt-1", 500, 100),
      makeNoteNode("mix-note-1", 100, 400),
    ]);

    await expect(page.locator(".react-flow__node")).toHaveCount(3, {
      timeout: 10_000,
    });

    const agentNode = page.locator(".react-flow__node-agentSession").first();
    const receiptNode = page.locator(".react-flow__node-receipt").first();

    // Select first node (agent)
    await agentNode.click();
    await page.waitForTimeout(200);

    // Shift+click receipt node (different type)
    await receiptNode.click({ modifiers: ["Shift"] });
    await page.waitForTimeout(300);

    // Comparison panel should open with "Node comparison" label
    const comparisonPanel = page.locator('[aria-label="Node comparison"]');
    await expect(comparisonPanel).toBeVisible({ timeout: 5_000 });

    // It should contain the MixedComparison view — both node types present
    await expect(comparisonPanel).toContainText("Agent mix-agent-1");
    await expect(comparisonPanel).toContainText("Receipt mix-receipt-1");
  });

  // -------------------------------------------------------------------------
  // 4. Single-node regression: click single node, verify 340px inspector
  // -------------------------------------------------------------------------

  test("single node click opens 340px inspector (not comparison mode)", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("single-agent-1", 200, 200, { agentModel: "opus-4.6" }),
    ]);

    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible({ timeout: 10_000 });

    await node.click();

    // The standard inspector should appear with aria-label "Node inspector"
    const panel = inspector(page);
    await expect(panel).toBeVisible({ timeout: 5_000 });

    // Verify the panel width is 340px (standard inspector, not comparison)
    const box = await panel.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBe(340);

    // Verify content shows the single node's data
    await expect(panel).toContainText("Agent single-agent-1");
    await expect(panel).toContainText("opus-4.6");
  });

  // -------------------------------------------------------------------------
  // 5. Overflow: select 7+ nodes, verify overflow message
  // -------------------------------------------------------------------------

  test("selecting more than 6 nodes shows overflow message in comparison", async ({
    page,
  }) => {
    // Create 7 nodes (exceeds MAX_COMPARISON_NODES = 6)
    const nodes = Array.from({ length: 7 }, (_, i) =>
      makeAgentNode(`overflow-${i + 1}`, 100 + i * 200, 100 + (i % 3) * 200),
    );

    await gotoBoardWithSeed(page, nodes);
    await expect(page.locator(".react-flow__node")).toHaveCount(7, {
      timeout: 10_000,
    });

    // Select all nodes via Cmd+A
    await page.locator(".react-flow__pane").click({ position: { x: 10, y: 10 } });
    await page.keyboard.press("Meta+a");
    await page.waitForTimeout(500);

    const selectedNodes = page.locator(".react-flow__node.selected");
    await expect(selectedNodes).toHaveCount(7, { timeout: 5_000 });

    // The comparison panel should show the overflow message
    const comparisonPanel = page.locator('[aria-label="Node comparison"]');
    await expect(comparisonPanel).toBeVisible({ timeout: 5_000 });

    // Look for the overflow message: "Too many nodes"
    await expect(comparisonPanel).toContainText("Too many nodes");
    await expect(comparisonPanel).toContainText("Select 6 or fewer nodes to compare");
    await expect(comparisonPanel).toContainText("7 selected");
  });

  // -------------------------------------------------------------------------
  // 6. Comparison inspector can be closed via its close button
  // -------------------------------------------------------------------------

  test("comparison inspector close button deselects nodes", async ({
    page,
  }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("close-agent-1", 100, 100),
      makeAgentNode("close-agent-2", 500, 100),
    ]);

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(2, { timeout: 10_000 });

    // Multi-select
    await nodes.nth(0).click();
    await nodes.nth(1).click({ modifiers: ["Shift"] });

    const comparisonPanel = page.locator('[aria-label="Node comparison"]');
    await expect(comparisonPanel).toBeVisible({ timeout: 5_000 });

    // Click the close button — comparison views use aria-label="Close comparison"
    const closeBtn = comparisonPanel.locator('[aria-label="Close comparison"]');
    await expect(closeBtn).toBeVisible({ timeout: 3_000 });
    await closeBtn.click();

    await expect(comparisonPanel).not.toBeVisible({ timeout: 3_000 });
  });

  // -------------------------------------------------------------------------
  // 7. Escape key closes comparison inspector
  // -------------------------------------------------------------------------

  test("Escape key closes comparison inspector", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      makeAgentNode("esc-agent-1", 100, 100),
      makeAgentNode("esc-agent-2", 500, 100),
    ]);

    const nodes = page.locator(".react-flow__node-agentSession");
    await expect(nodes).toHaveCount(2, { timeout: 10_000 });

    await nodes.nth(0).click();
    await nodes.nth(1).click({ modifiers: ["Shift"] });

    const comparisonPanel = page.locator('[aria-label="Node comparison"]');
    await expect(comparisonPanel).toBeVisible({ timeout: 5_000 });

    await page.keyboard.press("Escape");
    await expect(comparisonPanel).not.toBeVisible({ timeout: 3_000 });
  });
});
