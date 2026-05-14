/**
 * useReceiptFlowBridge -- React hook that bridges swarm-feed-store findings
 * to the Zustand board store, auto-creating receipt nodes when new findings
 * arrive.
 *
 * When the feed store's findingEnvelopes array grows (new findings ingested),
 * this hook processes the new entries and:
 * 1. Maps finding severity to a verdict (allow/deny/warn)
 * 2. Finds the source agent session node by matching swarmId to huntId
 * 3. Creates a receipt node positioned below the session node
 * 4. Creates a receipt edge from session to receipt
 * 5. Increments the session's receiptCount
 *
 * Deduplication: Tracks processed finding digests (or findingIds as fallback)
 * in a ref-backed Set to avoid creating duplicate receipt nodes.
 *
 * Lifecycle: Subscribes to the feed store on mount, unsubscribes on unmount.
 *
 * @see src/features/swarm/stores/swarm-feed-store.tsx -- findings source
 * @see src/features/swarm/stores/swarm-board-store.tsx -- board target
 */

import { useEffect, useRef } from "react";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import { useSwarmFeedStore } from "@/features/swarm/stores/swarm-feed-store";
import type { SwarmFindingEnvelopeRecord } from "@/features/swarm/stores/swarm-feed-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import type { Node } from "@xyflow/react";

// ---------------------------------------------------------------------------
// Receipt edge timestamps — module-level singleton for activity pulse
// ---------------------------------------------------------------------------

/**
 * Tracks the creation timestamp of receipt edges (edgeId -> Date.now()).
 * Exported so that swarm-board-page.tsx can enrich edge data with lastActivityAt
 * for edges created within the activity recency window.
 */
export const receiptEdgeTimestamps = new Map<string, number>();

// ---------------------------------------------------------------------------
// Severity-to-verdict mapping
// ---------------------------------------------------------------------------

/**
 * Map a FindingEnvelope severity to a board receipt verdict.
 * High severity -> deny, medium -> warn, low/info -> allow.
 */
function severityToVerdict(
  severity: string | undefined,
): "allow" | "deny" | "warn" {
  switch (severity) {
    case "critical":
    case "high":
      return "deny";
    case "medium":
      return "warn";
    case "low":
    case "info":
    default:
      return "allow";
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Bridge findings from the swarm feed store to receipt nodes on the board.
 * Call this hook inside the SwarmBoardCanvas component.
 */
export function useReceiptFlowBridge(): void {
  const processedDigests = useRef<Set<string>>(new Set());

  useEffect(() => {
    // Process any findings that already exist in the store
    const currentFindings = useSwarmFeedStore.getState().findingEnvelopes;
    processFindings(currentFindings, processedDigests.current);

    // Subscribe to future changes -- use basic Zustand subscribe (full state listener)
    // since the feed store does not use subscribeWithSelector middleware.
    const unsubscribe = useSwarmFeedStore.subscribe((state) => {
      processFindings(state.findingEnvelopes, processedDigests.current);
    });

    return () => {
      unsubscribe();
    };
  }, []);
}

// ---------------------------------------------------------------------------
// Finding processor
// ---------------------------------------------------------------------------

function processFindings(
  findings: SwarmFindingEnvelopeRecord[],
  processedDigests: Set<string>,
): void {
  for (const record of findings) {
    // Deduplicate by digest (preferred) or findingId as fallback
    const dedupeKey = record.digest ?? record.envelope.findingId;
    if (processedDigests.has(dedupeKey)) continue;
    processedDigests.add(dedupeKey);

    const { nodes, actions } = useSwarmBoardStore.getState();

    // Find the source agent session node by matching swarmId to huntId
    const sessionNode = nodes.find(
      (n: Node<SwarmBoardNodeData>) =>
        n.data.nodeType === "agentSession" &&
        (n.data.huntId === record.swarmId ||
          n.data.sessionId === record.swarmId),
    );

    if (!sessionNode) continue;

    // Map severity to verdict
    const verdict = severityToVerdict(record.envelope.severity);

    // Create receipt node positioned below the session node
    const receiptNode = actions.addNode({
      nodeType: "receipt",
      title: `Receipt: ${verdict.toUpperCase()}`,
      position: {
        x: sessionNode.position.x,
        y: sessionNode.position.y + 340,
      },
      data: {
        verdict,
        guardResults: [],
        sessionId: sessionNode.data.sessionId,
        status: "completed",
      },
    });

    // Create receipt edge from session to receipt
    const receiptEdgeId = `edge-receipt-${receiptNode.id}-${sessionNode.id}`;
    actions.addEdge({
      id: receiptEdgeId,
      source: sessionNode.id,
      target: receiptNode.id,
      type: "receipt",
      label: verdict,
    });

    // Stamp creation time for activity pulse (3s bright glow on new edges)
    receiptEdgeTimestamps.set(receiptEdgeId, Date.now());

    // Increment the session's receiptCount
    actions.updateNode(sessionNode.id, {
      receiptCount: ((sessionNode.data.receiptCount as number) ?? 0) + 1,
    });
  }
}
