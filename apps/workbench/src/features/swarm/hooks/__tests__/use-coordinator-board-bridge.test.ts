/**
 * Tests for useCoordinatorBoardBridge -- the hook that bridges SwarmCoordinator
 * typed message handlers (intel, detection) to the Zustand board store.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, cleanup } from "@testing-library/react";
import { useCoordinatorBoardBridge } from "../use-coordinator-board-bridge";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type {
  IntelHandler,
  DetectionHandler,
  DetectionMessage,
} from "@/features/swarm/swarm-coordinator";
import type { Intel } from "@/lib/workbench/sentinel-types";

// ---------------------------------------------------------------------------
// Mock SwarmCoordinator
// ---------------------------------------------------------------------------

function createMockCoordinator() {
  const intelHandlers = new Set<IntelHandler>();
  const detectionHandlers = new Set<DetectionHandler>();

  return {
    onIntelReceived: vi.fn((handler: IntelHandler) => {
      intelHandlers.add(handler);
    }),
    offIntelReceived: vi.fn((handler: IntelHandler) => {
      intelHandlers.delete(handler);
    }),
    onDetectionReceived: vi.fn((handler: DetectionHandler) => {
      detectionHandlers.add(handler);
    }),
    offDetectionReceived: vi.fn((handler: DetectionHandler) => {
      detectionHandlers.delete(handler);
    }),
    onSignalReceived: vi.fn(),
    offSignalReceived: vi.fn(),
    // Helpers for tests to simulate incoming messages
    _fireIntel(swarmId: string, intel: Intel) {
      for (const h of intelHandlers) h(swarmId, intel);
    },
    _fireDetection(swarmId: string, detection: DetectionMessage) {
      for (const h of detectionHandlers) h(swarmId, detection);
    },
    _intelHandlerCount() {
      return intelHandlers.size;
    },
    _detectionHandlerCount() {
      return detectionHandlers.size;
    },
  };
}

type MockCoordinator = ReturnType<typeof createMockCoordinator>;

// ---------------------------------------------------------------------------
// Minimal Intel factory
// ---------------------------------------------------------------------------

function makeIntel(overrides: Partial<Intel> = {}): Intel {
  return {
    id: "int_test_001",
    type: "detection_rule",
    title: "Test Detection Rule",
    description: "A test intel artifact",
    content: { format: "sigma", body: "rule: test" } as unknown as Intel["content"],
    derivedFrom: [],
    confidence: 0.85,
    tags: ["test"],
    mitre: [],
    shareability: { scope: "swarm" } as unknown as Intel["shareability"],
    signature: "abcd".repeat(32),
    signerPublicKey: "ef01".repeat(16),
    receipt: {} as unknown as Intel["receipt"],
    author: "abcdef0123456789",
    createdAt: Date.now(),
    version: 1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Minimal DetectionMessage factory
// ---------------------------------------------------------------------------

function makeDetection(overrides: Partial<DetectionMessage> = {}): DetectionMessage {
  return {
    ruleId: "det_rule_001",
    action: "publish",
    format: "sigma",
    content: "rule: sigma_test",
    contentHash: "abc123",
    ruleVersion: 1,
    authorFingerprint: "abcdef0123456789",
    confidence: 0.9,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Store reset helper
// ---------------------------------------------------------------------------

function resetStore() {
  const { actions } = useSwarmBoardStore.getState();
  actions.clearBoard();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useCoordinatorBoardBridge", () => {
  let coordinator: MockCoordinator;

  beforeEach(() => {
    coordinator = createMockCoordinator();
    resetStore();
  });

  afterEach(() => {
    cleanup();
  });

  // Test 1: Intel received -> artifact node added
  it("adds an artifact node when intel is received", () => {
    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    const intel = makeIntel({ id: "int_abc" });

    act(() => {
      coordinator._fireIntel("swarm-1", intel);
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const intelNode = nodes.find(
      (n) => n.data.documentId === "int_abc",
    );
    expect(intelNode).toBeDefined();
    expect(intelNode!.data.nodeType).toBe("artifact");
    expect(intelNode!.data.confidence).toBe(0.85);

    unmount();
  });

  // Test 2: Detection with action "publish" -> artifact node with artifactKind
  it("adds an artifact node with artifactKind='detection_rule' on detection publish", () => {
    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    const detection = makeDetection({
      ruleId: "det_pub_001",
      action: "publish",
      format: "sigma",
      content: "sigma rule content",
      confidence: 0.92,
    });

    act(() => {
      coordinator._fireDetection("swarm-1", detection);
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const detNode = nodes.find(
      (n) => n.data.documentId === "det_pub_001",
    );
    expect(detNode).toBeDefined();
    expect(detNode!.data.nodeType).toBe("artifact");
    expect(detNode!.data.artifactKind).toBe("detection_rule");
    expect(detNode!.data.confidence).toBe(0.92);

    unmount();
  });

  // Test 3: Detection with action "update" -> existing node updated, not duplicated
  it("updates existing detection node on detection update action", () => {
    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    // First publish
    act(() => {
      coordinator._fireDetection("swarm-1", makeDetection({
        ruleId: "det_upd_001",
        action: "publish",
        confidence: 0.8,
      }));
    });

    const nodesBefore = useSwarmBoardStore.getState().nodes;
    const countBefore = nodesBefore.filter(
      (n) => n.data.documentId === "det_upd_001",
    ).length;
    expect(countBefore).toBe(1);

    // Then update
    act(() => {
      coordinator._fireDetection("swarm-1", makeDetection({
        ruleId: "det_upd_001",
        action: "update",
        confidence: 0.95,
        content: "updated rule content",
      }));
    });

    const nodesAfter = useSwarmBoardStore.getState().nodes;
    const detNodes = nodesAfter.filter(
      (n) => n.data.documentId === "det_upd_001",
    );
    expect(detNodes.length).toBe(1); // no duplicate
    expect(detNodes[0]!.data.confidence).toBe(0.95);

    unmount();
  });

  // Test 4: Detection with action "deprecate" -> status set to "completed"
  it("sets status to completed on detection deprecate action", () => {
    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    // Publish first
    act(() => {
      coordinator._fireDetection("swarm-1", makeDetection({
        ruleId: "det_dep_001",
        action: "publish",
      }));
    });

    // Deprecate
    act(() => {
      coordinator._fireDetection("swarm-1", makeDetection({
        ruleId: "det_dep_001",
        action: "deprecate",
      }));
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const detNode = nodes.find(
      (n) => n.data.documentId === "det_dep_001",
    );
    expect(detNode).toBeDefined();
    expect(detNode!.data.status).toBe("completed");

    unmount();
  });

  // Test 5: Duplicate intel messages do not create duplicate nodes
  it("does not create duplicate nodes for the same intel ID", () => {
    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    const intel = makeIntel({ id: "int_dup_001" });

    act(() => {
      coordinator._fireIntel("swarm-1", intel);
      coordinator._fireIntel("swarm-1", intel);
      coordinator._fireIntel("swarm-1", intel);
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const matching = nodes.filter(
      (n) => n.data.documentId === "int_dup_001",
    );
    expect(matching.length).toBe(1);

    unmount();
  });

  // Test 6: Auto-positioned nodes offset from rightmost existing node
  it("auto-positions new nodes relative to rightmost existing node", () => {
    // Pre-seed a node at a known position
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Existing Session",
      position: { x: 500, y: 200 },
    });

    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    act(() => {
      coordinator._fireIntel("swarm-1", makeIntel({ id: "int_pos_001" }));
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const newNode = nodes.find(
      (n) => n.data.documentId === "int_pos_001",
    );
    expect(newNode).toBeDefined();
    // Should be to the right of x=500
    expect(newNode!.position.x).toBeGreaterThan(500);

    unmount();
  });

  // Test 7: On unmount, all handlers are unregistered
  it("unregisters all handlers from coordinator on unmount", () => {
    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    expect(coordinator.onIntelReceived).toHaveBeenCalledTimes(1);
    expect(coordinator.onDetectionReceived).toHaveBeenCalledTimes(1);

    unmount();

    expect(coordinator.offIntelReceived).toHaveBeenCalledTimes(1);
    expect(coordinator.offDetectionReceived).toHaveBeenCalledTimes(1);

    // Handlers should actually be removed from the set
    expect(coordinator._intelHandlerCount()).toBe(0);
    expect(coordinator._detectionHandlerCount()).toBe(0);
  });

  // Test 8: When coordinator is null, hook is a no-op
  it("does not throw when coordinator is null", () => {
    expect(() => {
      const { unmount } = renderHook(() =>
        useCoordinatorBoardBridge(null),
      );
      unmount();
    }).not.toThrow();
  });

  // Test 9: Edge created between matching session node and new intel node
  it("creates an edge between session node and intel node when swarmId matches huntId", () => {
    // Pre-seed an agent session node with huntId matching swarmId
    const { actions } = useSwarmBoardStore.getState();
    const sessionNode = actions.addNode({
      nodeType: "agentSession",
      title: "Hunter Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-hunt-1" },
    });

    const { unmount } = renderHook(() =>
      useCoordinatorBoardBridge(coordinator as any),
    );

    act(() => {
      coordinator._fireIntel("swarm-hunt-1", makeIntel({ id: "int_edge_001" }));
    });

    const edges = useSwarmBoardStore.getState().edges;
    const bridgeEdge = edges.find(
      (e) => e.source === sessionNode.id && e.label === "intel",
    );
    expect(bridgeEdge).toBeDefined();
    expect(bridgeEdge!.type).toBe("artifact");

    unmount();
  });
});
