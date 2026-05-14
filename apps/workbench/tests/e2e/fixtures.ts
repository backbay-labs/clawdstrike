/**
 * Shared E2E test fixtures for the ClawdStrike Workbench.
 *
 * Seeds the operator identity in localStorage so the IdentityPrompt modal
 * does not block navigation, and provides helpers for board state seeding.
 */

import { test as base, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const SWARM_BOARD_URL = "/#/swarm-board";
export const HOME_URL = "/#/home";
export const BOARD_STORAGE_KEY = "clawdstrike_workbench_swarm_board";
const OPERATOR_STORAGE_KEY = "clawdstrike_workbench_operator";

/**
 * Minimal OperatorIdentity that satisfies the store's validation
 * (requires `publicKey` as 64-char hex and `fingerprint` as 16-char hex).
 */
const E2E_OPERATOR = {
  publicKey: "a".repeat(64),
  fingerprint: "b".repeat(16),
  sigil: "E2E",
  nickname: "e2e-tester",
  displayName: "E2E Test Operator",
  idpClaims: null,
  createdAt: Date.now(),
  originDeviceId: "e2e-device-01",
  devices: [
    {
      deviceId: "e2e-device-01",
      deviceName: "playwright",
      addedAt: Date.now(),
      lastSeenAt: Date.now(),
    },
  ],
};

// ---------------------------------------------------------------------------
// Custom test fixture
// ---------------------------------------------------------------------------

/**
 * Extended Playwright test that auto-seeds the operator identity before
 * every test, preventing the "Create Your Operator Identity" modal from
 * blocking the UI.
 */
export const test = base.extend<{ seedOperator: void }>({
  seedOperator: [
    async ({ page }, use) => {
      await page.addInitScript(
        ({ key, value }) => {
          localStorage.setItem(key, JSON.stringify(value));
        },
        { key: OPERATOR_STORAGE_KEY, value: E2E_OPERATOR },
      );
      await use();
    },
    { auto: true },
  ],
});

export { expect } from "@playwright/test";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Navigate to the swarm board with a clean board state. */
export async function gotoBoard(page: Page) {
  await page.addInitScript((key) => {
    localStorage.removeItem(key);
  }, BOARD_STORAGE_KEY);

  await page.goto(SWARM_BOARD_URL);
  await page.locator(".react-flow__viewport").waitFor({ state: "visible", timeout: 15_000 });
}

/** Navigate to the swarm board with pre-seeded nodes/edges. */
export async function gotoBoardWithSeed(
  page: Page,
  nodes: Array<Record<string, unknown>>,
  edges: Array<Record<string, unknown>> = [],
) {
  await page.addInitScript(
    ({ key, payload }) => {
      localStorage.setItem(key, JSON.stringify(payload));
    },
    {
      key: BOARD_STORAGE_KEY,
      payload: {
        boardId: "e2e-test-board",
        repoRoot: "",
        nodes,
        edges,
      },
    },
  );

  await page.goto(SWARM_BOARD_URL);
  await page.locator(".react-flow__viewport").waitFor({ state: "visible", timeout: 15_000 });
}

/** Press a key on the React Flow canvas (not inside an input). */
export async function pressOnCanvas(page: Page, key: string) {
  await page.locator(".react-flow__pane").click({ position: { x: 10, y: 10 } });
  await page.keyboard.press(key);
}

/** Return the current number of rendered React Flow nodes. */
export async function nodeCount(page: Page): Promise<number> {
  return page.locator(".react-flow__node").count();
}

/** Locate the inspector panel. */
export function inspector(page: Page) {
  return page.locator('[aria-label="Node inspector"]');
}
