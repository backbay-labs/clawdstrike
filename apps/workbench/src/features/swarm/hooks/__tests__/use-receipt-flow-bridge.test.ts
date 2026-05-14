/**
 * Tests for useReceiptFlowBridge -- the hook that bridges swarm-feed-store
 * findings to the Zustand board store, auto-creating receipt nodes and
 * linking them to source agent session nodes.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act, cleanup } from "@testing-library/react";
import { useReceiptFlowBridge } from "../use-receipt-flow-bridge";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import { useSwarmFeedStore } from "@/features/swarm/stores/swarm-feed-store";
import type { SwarmFindingEnvelopeRecord } from "@/features/swarm/stores/swarm-feed-store";
import type { FindingEnvelope, ProtocolDigest } from "@/features/swarm/swarm-protocol";

// ---------------------------------------------------------------------------
// Finding envelope factory
// ---------------------------------------------------------------------------

let findingSeq = 0;

function makeFindingEnvelope(overrides: Partial<FindingEnvelope> = {}): FindingEnvelope {
  findingSeq += 1;
  return {
    schema: "https://clawdstrike.dev/schemas/finding-envelope/v1" as FindingEnvelope["schema"],
    findingId: `finding-${findingSeq}`,
    issuerId: "issuer-1",
    feedId: "feed-1",
    feedSeq: findingSeq,
    publishedAt: Date.now(),
    title: "Test Finding",
    summary: "A test finding for receipt flow bridge",
    severity: "high" as FindingEnvelope["severity"],
    confidence: 0.9,
    status: "active" as FindingEnvelope["status"],
    signalCount: 1,
    tags: ["test"],
    blobRefs: [],
    ...overrides,
  };
}

function makeFindingRecord(
  swarmId: string,
  overrides: Partial<FindingEnvelope> = {},
  digest?: ProtocolDigest,
): SwarmFindingEnvelopeRecord {
  return {
    swarmId,
    envelope: makeFindingEnvelope(overrides),
    receivedAt: Date.now(),
    digest: digest ?? (`0x${Math.random().toString(16).slice(2)}` as ProtocolDigest),
  };
}

// ---------------------------------------------------------------------------
// Store reset helper
// ---------------------------------------------------------------------------

function resetStores() {
  useSwarmBoardStore.getState().actions.clearBoard();
  // Reset feed store findings by setting state directly
  useSwarmFeedStore.setState({
    findingEnvelopes: [],
    headAnnouncements: [],
    revocationEnvelopes: [],
    quarantinedFindingEnvelopes: [],
    quarantinedHeadAnnouncements: [],
    quarantinedRevocationEnvelopes: [],
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useReceiptFlowBridge", () => {
  beforeEach(() => {
    findingSeq = 0;
    resetStores();
  });

  afterEach(() => {
    cleanup();
  });

  // Test 1: When a new finding is ingested, a receipt node is created on the board
  it("creates a receipt node when a finding is added to the feed store", () => {
    // Pre-seed an agent session node
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-1", sessionId: "sess-1" },
    });

    const { unmount } = renderHook(() => useReceiptFlowBridge());

    // Simulate a new finding being added to the feed store
    const record = makeFindingRecord("swarm-1", { severity: "high" as FindingEnvelope["severity"] });

    act(() => {
      useSwarmFeedStore.setState({
        findingEnvelopes: [record],
      });
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const receiptNode = nodes.find((n) => n.data.nodeType === "receipt");
    expect(receiptNode).toBeDefined();

    unmount();
  });

  // Test 2: Receipt node has correct verdict extracted from finding envelope
  it("extracts verdict from finding severity", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-1", sessionId: "sess-1" },
    });

    const { unmount } = renderHook(() => useReceiptFlowBridge());

    // High severity -> "deny" verdict
    const record = makeFindingRecord("swarm-1", {
      severity: "high" as FindingEnvelope["severity"],
    });

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record] });
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const receiptNode = nodes.find((n) => n.data.nodeType === "receipt");
    expect(receiptNode).toBeDefined();
    expect(receiptNode!.data.verdict).toBeDefined();
    // Verdict should be one of "allow", "deny", or "warn"
    expect(["allow", "deny", "warn"]).toContain(receiptNode!.data.verdict);

    unmount();
  });

  // Test 3: Receipt node is linked to the source agent session node via a "receipt" edge
  it("creates a receipt edge from session node to receipt node", () => {
    const { actions } = useSwarmBoardStore.getState();
    const sessionNode = actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-1", sessionId: "sess-1" },
    });

    const { unmount } = renderHook(() => useReceiptFlowBridge());

    const record = makeFindingRecord("swarm-1");

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record] });
    });

    const edges = useSwarmBoardStore.getState().edges;
    const receiptEdge = edges.find(
      (e) => e.source === sessionNode.id && e.type === "receipt",
    );
    expect(receiptEdge).toBeDefined();

    unmount();
  });

  // Test 4: Agent session node's receiptCount is incremented when a receipt is created
  it("increments receiptCount on the source session node", () => {
    const { actions } = useSwarmBoardStore.getState();
    const sessionNode = actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-1", sessionId: "sess-1", receiptCount: 0 },
    });

    const { unmount } = renderHook(() => useReceiptFlowBridge());

    const record = makeFindingRecord("swarm-1");

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record] });
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const updatedSession = nodes.find((n) => n.id === sessionNode.id);
    expect(updatedSession).toBeDefined();
    expect(updatedSession!.data.receiptCount).toBe(1);

    unmount();
  });

  // Test 5: Duplicate findings (same digest) do not create duplicate receipt nodes
  it("does not create duplicate receipt nodes for the same finding digest", () => {
    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-1", sessionId: "sess-1" },
    });

    const { unmount } = renderHook(() => useReceiptFlowBridge());

    const digest = "0xaabbccdd" as ProtocolDigest;
    const record1 = makeFindingRecord("swarm-1", {}, digest);
    const record2 = makeFindingRecord("swarm-1", {}, digest);

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record1] });
    });

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record1, record2] });
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const receiptNodes = nodes.filter((n) => n.data.nodeType === "receipt");
    expect(receiptNodes.length).toBe(1);

    unmount();
  });

  // Test 6: Receipt node is positioned below the source session node
  it("positions receipt node below the source session node", () => {
    const { actions } = useSwarmBoardStore.getState();
    const sessionNode = actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 200, y: 150 },
      data: { huntId: "swarm-1", sessionId: "sess-1" },
    });

    const { unmount } = renderHook(() => useReceiptFlowBridge());

    const record = makeFindingRecord("swarm-1");

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record] });
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const receiptNode = nodes.find((n) => n.data.nodeType === "receipt");
    expect(receiptNode).toBeDefined();
    expect(receiptNode!.position.y).toBeGreaterThan(sessionNode.position.y);

    unmount();
  });

  // Test 7: On unmount, the subscription is cleaned up
  it("cleans up subscription on unmount", () => {
    const { unmount } = renderHook(() => useReceiptFlowBridge());

    // Add a finding after unmount -- no receipt node should appear
    unmount();

    const { actions } = useSwarmBoardStore.getState();
    actions.addNode({
      nodeType: "agentSession",
      title: "Test Session",
      position: { x: 100, y: 100 },
      data: { huntId: "swarm-1", sessionId: "sess-1" },
    });

    const record = makeFindingRecord("swarm-1");

    act(() => {
      useSwarmFeedStore.setState({ findingEnvelopes: [record] });
    });

    const nodes = useSwarmBoardStore.getState().nodes;
    const receiptNodes = nodes.filter((n) => n.data.nodeType === "receipt");
    expect(receiptNodes.length).toBe(0);
  });
});
