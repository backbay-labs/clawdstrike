/**
 * Bridge hooks unchanged -- verifies that the 4 existing bridge hooks have
 * unchanged signatures and behavior after the swarm-engine integration.
 *
 * The 5th bridge hook (useEngineBoardBridge) is verified to coexist alongside
 * the existing 4 without conflicts.
 *
 * Requirements: BKWD-04
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, cleanup } from "@testing-library/react";
import { useCoordinatorBoardBridge } from "../use-coordinator-board-bridge";
import { usePolicyEvalBoardBridge } from "../use-policy-eval-board-bridge";
import { useReceiptFlowBridge } from "../use-receipt-flow-bridge";
import { useTrustGraphBridge } from "../use-trust-graph-bridge";
import { useEngineBoardBridge } from "../use-engine-board-bridge";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";

// Mock Tauri terminal service
vi.mock("@/lib/workbench/terminal-service", () => ({
  terminalService: {
    getCwd: vi.fn().mockResolvedValue("/mock/cwd"),
    create: vi.fn().mockResolvedValue({ id: "mock-session", branch: "main" }),
    write: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    onExit: vi.fn().mockResolvedValue(() => {}),
  },
  worktreeService: {
    create: vi.fn().mockResolvedValue({ path: "/mock/worktree", branch: "test-branch" }),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock swarm-feed-store (needed by useReceiptFlowBridge)
vi.mock("@/features/swarm/stores/swarm-feed-store", () => ({
  useSwarmFeedStore: Object.assign(
    () => ({ findingEnvelopes: [] }),
    {
      getState: () => ({ findingEnvelopes: [] }),
      subscribe: vi.fn(() => vi.fn()),
      setState: vi.fn(),
    },
  ),
}));

// Mock topology layout (needed by useEngineBoardBridge)
vi.mock("@/features/swarm/layout/topology-layout", () => ({
  computeLayout: vi.fn().mockReturnValue({ positions: new Map() }),
}));

function resetStore(): void {
  useSwarmBoardStore.getState().actions.clearBoard();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Existing bridge hook signatures", () => {
  beforeEach(() => {
    resetStore();
  });
  afterEach(() => {
    cleanup();
  });

  it("useCoordinatorBoardBridge is a function with arity 1", () => {
    expect(typeof useCoordinatorBoardBridge).toBe("function");
    expect(useCoordinatorBoardBridge.length).toBe(1);
  });

  it("usePolicyEvalBoardBridge is a function with arity 1", () => {
    expect(typeof usePolicyEvalBoardBridge).toBe("function");
    expect(usePolicyEvalBoardBridge.length).toBe(1);
  });

  it("useReceiptFlowBridge is a function with arity 0", () => {
    expect(typeof useReceiptFlowBridge).toBe("function");
    expect(useReceiptFlowBridge.length).toBe(0);
  });

  it("useTrustGraphBridge is a function with arity 1", () => {
    expect(typeof useTrustGraphBridge).toBe("function");
    expect(useTrustGraphBridge.length).toBe(1);
  });
});

describe("Null coordinator safety", () => {
  beforeEach(() => {
    resetStore();
  });
  afterEach(() => {
    cleanup();
  });

  it("useCoordinatorBoardBridge(null) does not throw", () => {
    expect(() => {
      const { unmount } = renderHook(() => useCoordinatorBoardBridge(null));
      unmount();
    }).not.toThrow();
  });

  it("usePolicyEvalBoardBridge(null) does not throw", () => {
    expect(() => {
      const { unmount } = renderHook(() => usePolicyEvalBoardBridge(null));
      unmount();
    }).not.toThrow();
  });

  it("useReceiptFlowBridge() does not throw", () => {
    expect(() => {
      const { unmount } = renderHook(() => useReceiptFlowBridge());
      unmount();
    }).not.toThrow();
  });

  it("useTrustGraphBridge(null) does not throw", () => {
    expect(() => {
      const { unmount } = renderHook(() => useTrustGraphBridge(null));
      unmount();
    }).not.toThrow();
  });
});

describe("Engine bridge coexistence", () => {
  beforeEach(() => {
    resetStore();
  });
  afterEach(() => {
    cleanup();
  });

  it("useEngineBoardBridge(null) coexists with useCoordinatorBoardBridge(null)", () => {
    expect(() => {
      const { unmount: u1 } = renderHook(() => useCoordinatorBoardBridge(null));
      const { unmount: u2 } = renderHook(() => useEngineBoardBridge(null));
      u2();
      u1();
    }).not.toThrow();
  });

  it("all 5 bridge hooks can be rendered simultaneously without conflict", () => {
    expect(() => {
      const hooks = [
        renderHook(() => useCoordinatorBoardBridge(null)),
        renderHook(() => usePolicyEvalBoardBridge(null)),
        renderHook(() => useReceiptFlowBridge()),
        renderHook(() => useTrustGraphBridge(null)),
        renderHook(() => useEngineBoardBridge(null)),
      ];

      // All rendered without error -- now unmount all
      hooks.forEach((h) => h.unmount());
    }).not.toThrow();
  });
});
