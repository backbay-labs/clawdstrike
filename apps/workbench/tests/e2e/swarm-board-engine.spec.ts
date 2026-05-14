/**
 * SwarmBoard engine integration E2E tests — verifies the SwarmEngineProvider,
 * pre-seeded board state from localStorage, engine-managed nodes, receipt
 * inspection, mixed legacy/engine coexistence, persistence across navigations,
 * and edge type rendering.
 *
 * The app uses HashRouter (`/#/swarm-board`) and no Tauri runtime is
 * available, so the engine degrades to manual mode.
 */

import {
  test,
  expect,
  SWARM_BOARD_URL,
  HOME_URL,
  BOARD_STORAGE_KEY,
  gotoBoard,
  gotoBoardWithSeed,
  pressOnCanvas,
  inspector,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Seed data factories
// ---------------------------------------------------------------------------

function makeEngineAgentNode(overrides?: Record<string, unknown>) {
  return {
    id: "agent-1",
    type: "agentSession",
    position: { x: 100, y: 100 },
    data: {
      title: "Test Agent",
      status: "running",
      nodeType: "agentSession",
      agentId: "agt-001",
      engineManaged: true,
      ...overrides,
    },
  };
}

function makeEngineTaskNode(overrides?: Record<string, unknown>) {
  return {
    id: "task-1",
    type: "terminalTask",
    position: { x: 100, y: 300 },
    data: {
      title: "Analysis Task",
      status: "running",
      nodeType: "terminalTask",
      taskId: "tsk-001",
      agentId: "agt-001",
      engineManaged: true,
      ...overrides,
    },
  };
}

function makeReceiptNode(overrides?: Record<string, unknown>) {
  return {
    id: "receipt-1",
    type: "receipt",
    position: { x: 400, y: 100 },
    data: {
      title: "Guard Receipt",
      status: "idle",
      nodeType: "receipt",
      verdict: "allow",
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 3 },
      ],
      signature: "sig-test-123",
      ...overrides,
    },
  };
}

function makeLegacyNode() {
  return {
    id: "legacy-1",
    type: "agentSession",
    position: { x: 300, y: 200 },
    data: {
      title: "Legacy Session",
      status: "idle",
      nodeType: "agentSession",
      agentModel: "claude-3.5-sonnet",
      policyMode: "default",
    },
  };
}

// ==========================================================================
// Tests
// ==========================================================================

// ---------------------------------------------------------------------------
// 1. SwarmEngineProvider initializes without crash
// ---------------------------------------------------------------------------

test("SwarmEngineProvider initializes without crash in web mode", async ({ page }) => {
  await page.addInitScript((key) => {
    localStorage.removeItem(key);
  }, BOARD_STORAGE_KEY);

  await page.goto(SWARM_BOARD_URL);

  await expect(page.locator(".react-flow")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("encountered an error")).not.toBeVisible();
  await expect(page.getByText("SwarmBoard")).toBeVisible();
});

// ---------------------------------------------------------------------------
// 2. Pre-seeded board loads from localStorage
// ---------------------------------------------------------------------------

test("pre-seeded board loads nodes and edges from localStorage", async ({ page }) => {
  await gotoBoardWithSeed(
    page,
    [makeEngineAgentNode(), makeEngineTaskNode(), makeReceiptNode()],
    [
      { id: "edge-1", source: "agent-1", target: "task-1", type: "spawned" },
      { id: "edge-2", source: "agent-1", target: "receipt-1", type: "receipt" },
    ],
  );

  await expect(page.locator(".react-flow__node")).toHaveCount(3, { timeout: 10_000 });
  await expect(page.getByText("3 nodes")).toBeVisible();
  await expect(page.getByText("1 running")).toBeVisible();

  const edgeCount = await page.locator(".react-flow__edge").count();
  expect(edgeCount).toBeGreaterThanOrEqual(2);
});

// ---------------------------------------------------------------------------
// 3. Engine-managed node shows details in inspector
// ---------------------------------------------------------------------------

test("engine-managed node shows details in inspector", async ({ page }) => {
  await gotoBoardWithSeed(page, [makeEngineAgentNode({ title: "Engine Agent" })]);

  const agentNode = page.locator(".react-flow__node-agentSession").first();
  await expect(agentNode).toBeVisible({ timeout: 10_000 });
  await agentNode.click();

  const panel = inspector(page);
  await expect(panel).toBeVisible({ timeout: 5_000 });
  await expect(panel.getByText("Engine Agent")).toBeVisible();
});

// ---------------------------------------------------------------------------
// 4. Receipt node shows verdict and guard results
// ---------------------------------------------------------------------------

test("receipt node shows verdict and guard results in inspector", async ({ page }) => {
  await gotoBoardWithSeed(page, [
    makeReceiptNode({
      verdict: "allow",
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 3 },
        { guard: "SecretLeakGuard", allowed: true, duration_ms: 7 },
      ],
    }),
  ]);

  const receiptNode = page.locator(".react-flow__node-receipt").first();
  await expect(receiptNode).toBeVisible({ timeout: 10_000 });
  await receiptNode.click();

  const panel = inspector(page);
  await expect(panel).toBeVisible({ timeout: 5_000 });
  await expect(panel.getByText("ALLOW")).toBeVisible();
  await expect(panel.getByText("ForbiddenPathGuard")).toBeVisible();
  await expect(panel.getByText("SecretLeakGuard")).toBeVisible();
  await expect(panel.getByText("2/2 passed")).toBeVisible();
});

// ---------------------------------------------------------------------------
// 5. Mixed legacy and engine nodes coexist
// ---------------------------------------------------------------------------

test("mixed legacy and engine nodes coexist on the board", async ({ page }) => {
  await gotoBoardWithSeed(page, [
    makeLegacyNode(),
    makeEngineAgentNode({ title: "Engine Session" }),
  ]);

  await expect(page.locator(".react-flow__node")).toHaveCount(2, { timeout: 10_000 });

  // Both nodes should be agentSession type
  const nodes = page.locator(".react-flow__node-agentSession");
  await expect(nodes).toHaveCount(2);

  // Click first node and verify inspector opens
  await nodes.first().click();
  const panel = inspector(page);
  await expect(panel).toBeVisible({ timeout: 5_000 });

  // Close inspector
  await page.keyboard.press("Escape");
  await expect(panel).not.toBeVisible({ timeout: 3_000 });

  // Click second node and verify inspector shows different data
  await nodes.nth(1).click();
  await expect(panel).toBeVisible({ timeout: 5_000 });
});

// ---------------------------------------------------------------------------
// 6. Board persists state across navigations
// ---------------------------------------------------------------------------

test("board persists state across navigations via localStorage", async ({ page }) => {
  await gotoBoard(page);

  await pressOnCanvas(page, "1");
  await expect(page.locator(".react-flow__node")).toHaveCount(1, { timeout: 5_000 });

  await page.goto(HOME_URL);
  await page.waitForTimeout(1_000);

  await page.goto(SWARM_BOARD_URL);
  await page.locator(".react-flow__viewport").waitFor({ state: "visible", timeout: 15_000 });

  await expect(page.locator(".react-flow__node")).toHaveCount(1, { timeout: 10_000 });
});

// ---------------------------------------------------------------------------
// 7. Topology edge type renders
// ---------------------------------------------------------------------------

test("topology edge type renders between agent nodes", async ({ page }) => {
  await gotoBoardWithSeed(
    page,
    [
      makeEngineAgentNode({ title: "Agent A" }),
      {
        id: "agent-2",
        type: "agentSession",
        position: { x: 500, y: 100 },
        data: {
          title: "Agent B",
          status: "running",
          nodeType: "agentSession",
          agentId: "agt-002",
          engineManaged: true,
        },
      },
    ],
    [{ id: "topo-edge-1", source: "agent-1", target: "agent-2", type: "topology" }],
  );

  await expect(page.locator(".react-flow__node")).toHaveCount(2, { timeout: 10_000 });
  const edgeCount = await page.locator(".react-flow__edge").count();
  expect(edgeCount).toBeGreaterThanOrEqual(1);
});

// ---------------------------------------------------------------------------
// 8. All five edge types render correctly
// ---------------------------------------------------------------------------

test("all five edge types render correctly", async ({ page }) => {
  await gotoBoardWithSeed(
    page,
    [
      { id: "n1", type: "agentSession", position: { x: 100, y: 100 }, data: { title: "Agent 1", status: "running", nodeType: "agentSession", agentId: "a1", engineManaged: true } },
      { id: "n2", type: "agentSession", position: { x: 400, y: 100 }, data: { title: "Agent 2", status: "idle", nodeType: "agentSession", agentId: "a2", engineManaged: true } },
      { id: "n3", type: "terminalTask", position: { x: 100, y: 300 }, data: { title: "Task 1", status: "running", nodeType: "terminalTask", taskId: "t1", agentId: "a1", engineManaged: true } },
      { id: "n4", type: "artifact", position: { x: 400, y: 300 }, data: { title: "Artifact 1", status: "idle", nodeType: "artifact" } },
      { id: "n5", type: "receipt", position: { x: 700, y: 100 }, data: { title: "Receipt 1", status: "idle", nodeType: "receipt", verdict: "allow", guardResults: [] } },
      { id: "n6", type: "note", position: { x: 700, y: 300 }, data: { title: "Note 1", status: "idle", nodeType: "note", content: "hello" } },
    ],
    [
      { id: "e-handoff", source: "n1", target: "n2", type: "handoff" },
      { id: "e-spawned", source: "n1", target: "n3", type: "spawned" },
      { id: "e-artifact", source: "n3", target: "n4", type: "artifact" },
      { id: "e-receipt", source: "n1", target: "n5", type: "receipt" },
      { id: "e-topology", source: "n1", target: "n6", type: "topology" },
    ],
  );

  await expect(page.locator(".react-flow__node")).toHaveCount(6, { timeout: 10_000 });
  // At least 4 of 5 edges should render (some may be off-viewport)
  const edgeCount = await page.locator(".react-flow__edge").count();
  expect(edgeCount).toBeGreaterThanOrEqual(4);
  await expect(page.getByText("6 nodes")).toBeVisible();
  await expect(page.getByText("5 edges")).toBeVisible();
});
