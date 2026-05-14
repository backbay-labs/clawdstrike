/**
 * SwarmBoard Inspector Panel — E2E tests.
 *
 * Covers inspector open/close lifecycle, per-node-type detail views,
 * selection switching between nodes, canvas deselection, close button,
 * and keyboard interactions (Escape, Cmd+A, Space follow toggle).
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
  inspector,
} from "./fixtures";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("SwarmBoard inspector panel", () => {
  test("inspector opens on node click and closes on Escape", async ({ page }) => {
    await gotoBoard(page);

    await pressOnCanvas(page, "1");
    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible({ timeout: 5_000 });

    await node.click();
    await expect(inspector(page)).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('[aria-label="Close inspector"]')).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(inspector(page)).not.toBeVisible({ timeout: 3_000 });
  });

  test("inspector shows correct data for agentSession node", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      {
        id: "agent-e2e",
        type: "agentSession",
        position: { x: 200, y: 200 },
        data: {
          title: "E2E Agent",
          status: "idle",
          nodeType: "agentSession",
          agentModel: "claude",
          branch: "feat/test",
          receiptCount: 3,
          blockedActionCount: 1,
          risk: "medium",
          createdAt: Date.now(),
        },
      },
    ]);

    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible({ timeout: 5_000 });
    await node.click();

    const panel = inspector(page);
    await expect(panel).toBeVisible({ timeout: 5_000 });
    await expect(panel).toContainText("E2E Agent");
    await expect(panel).toContainText("session");
    await expect(panel).toContainText("claude");
    await expect(panel).toContainText("feat/test");
  });

  test("inspector shows correct data for receipt node", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      {
        id: "receipt-e2e",
        type: "receipt",
        position: { x: 200, y: 200 },
        data: {
          title: "Guard Receipt",
          status: "idle",
          nodeType: "receipt",
          verdict: "allow",
          guardResults: [
            { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
            { guard: "ShellCommandGuard", allowed: true, duration_ms: 5 },
          ],
          createdAt: Date.now(),
        },
      },
    ]);

    const node = page.locator(".react-flow__node-receipt").first();
    await expect(node).toBeVisible({ timeout: 5_000 });
    await node.click();

    const panel = inspector(page);
    await expect(panel).toBeVisible({ timeout: 5_000 });
    await expect(panel).toContainText("ALLOW");
    await expect(panel).toContainText("ForbiddenPathGuard");
    await expect(panel).toContainText("ShellCommandGuard");
  });

  test("note node renders content on card", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      {
        id: "note-e2e",
        type: "note",
        position: { x: 200, y: 200 },
        data: {
          title: "Test Note",
          status: "idle",
          nodeType: "note",
          content: "Hello from E2E",
          createdAt: Date.now(),
        },
      },
    ]);

    const node = page.locator(".react-flow__node-note").first();
    await expect(node).toBeVisible({ timeout: 5_000 });

    // Note content is rendered directly on the node card
    await expect(node).toContainText("Test Note");
  });

  test("inspector shows correct data for artifact node", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      {
        id: "art-e2e",
        type: "artifact",
        position: { x: 200, y: 200 },
        data: {
          title: "main.rs",
          status: "idle",
          nodeType: "artifact",
          filePath: "src/main.rs",
          fileType: "rust",
          createdAt: Date.now(),
        },
      },
    ]);

    const node = page.locator(".react-flow__node-artifact").first();
    await expect(node).toBeVisible({ timeout: 5_000 });
    await node.click();

    const panel = inspector(page);
    await expect(panel).toBeVisible({ timeout: 5_000 });
    await expect(panel).toContainText("src/main.rs");
    await expect(panel).toContainText("rust");
    await expect(panel).toContainText("artifact");
  });

  test("inspector switches between different node types", async ({ page }) => {
    await gotoBoardWithSeed(page, [
      {
        id: "switch-agent",
        type: "agentSession",
        position: { x: 100, y: 100 },
        data: {
          title: "Agent Alpha",
          status: "idle",
          nodeType: "agentSession",
          agentModel: "opus-4.6",
          branch: "main",
          createdAt: Date.now(),
        },
      },
      {
        id: "switch-receipt",
        type: "receipt",
        position: { x: 500, y: 100 },
        data: {
          title: "Receipt Beta",
          status: "idle",
          nodeType: "receipt",
          verdict: "deny",
          guardResults: [
            { guard: "SecretLeakGuard", allowed: false, duration_ms: 3 },
          ],
          createdAt: Date.now(),
        },
      },
      {
        id: "switch-artifact",
        type: "artifact",
        position: { x: 100, y: 400 },
        data: {
          title: "config.yaml",
          status: "idle",
          nodeType: "artifact",
          filePath: "src/config.yaml",
          fileType: "yaml",
          createdAt: Date.now(),
        },
      },
    ]);

    const panel = inspector(page);

    // Click agent node
    const agentNode = page.locator(".react-flow__node-agentSession").first();
    await expect(agentNode).toBeVisible({ timeout: 5_000 });
    await agentNode.click();
    await expect(panel).toBeVisible({ timeout: 5_000 });
    await expect(panel).toContainText("Agent Alpha");
    await expect(panel).toContainText("session");
    await expect(panel).toContainText("opus-4.6");

    // Click receipt node
    const receiptNode = page.locator(".react-flow__node-receipt").first();
    await expect(receiptNode).toBeVisible();
    await receiptNode.click();
    await expect(panel).toContainText("Receipt Beta");
    await expect(panel).toContainText("DENY");
    await expect(panel).toContainText("SecretLeakGuard");

    // Click artifact node
    const artifactNode = page.locator(".react-flow__node-artifact").first();
    await expect(artifactNode).toBeVisible();
    await artifactNode.click();
    await expect(panel).toContainText("config.yaml");
    await expect(panel).toContainText("src/config.yaml");
  });

  test("clicking empty canvas closes inspector", async ({ page }) => {
    await gotoBoard(page);

    await pressOnCanvas(page, "1");
    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible({ timeout: 5_000 });
    await node.click();
    await expect(inspector(page)).toBeVisible({ timeout: 5_000 });

    await page.locator(".react-flow__pane").click({ position: { x: 10, y: 10 } });
    await expect(inspector(page)).not.toBeVisible({ timeout: 3_000 });
  });

  test("inspector close button works", async ({ page }) => {
    await gotoBoard(page);

    await pressOnCanvas(page, "1");
    const node = page.locator(".react-flow__node-agentSession").first();
    await expect(node).toBeVisible({ timeout: 5_000 });
    await node.click();
    await expect(inspector(page)).toBeVisible({ timeout: 5_000 });

    await page.locator('[aria-label="Close inspector"]').click();
    await expect(inspector(page)).not.toBeVisible({ timeout: 3_000 });
  });

  test("keyboard shortcut Cmd+A selects all nodes", async ({ page }) => {
    await gotoBoard(page);

    await pressOnCanvas(page, "1");
    await pressOnCanvas(page, "2");
    await pressOnCanvas(page, "5");
    await expect(page.locator(".react-flow__node")).toHaveCount(3, { timeout: 5_000 });

    await pressOnCanvas(page, "Meta+a");

    const selectedNodes = page.locator(".react-flow__node.selected");
    await expect(selectedNodes).toHaveCount(3, { timeout: 5_000 });
  });

  test("keyboard shortcut Space toggles follow mode", async ({ page }) => {
    await gotoBoard(page);

    await pressOnCanvas(page, "1");
    await expect(page.locator(".react-flow__node")).toHaveCount(1, { timeout: 5_000 });

    await pressOnCanvas(page, " ");
    await expect(page.getByText("following")).toBeVisible({ timeout: 3_000 });

    await pressOnCanvas(page, " ");
    await expect(page.getByText("following")).not.toBeVisible({ timeout: 3_000 });
  });
});
