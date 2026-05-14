/**
 * useTrustGraphBridge -- React hook that bridges SwarmCoordinator's member
 * join/leave events to the Zustand board store for live trust graph updates.
 *
 * When a member joins, a new agentSession node is added to the board with a
 * fade+scale entry animation. When a member leaves, the node fades to
 * "completed" opacity (0.7) and is removed after a 3-second delay.
 *
 * Lifecycle: registers handlers on mount, unregisters on unmount. Safe to call
 * with a null coordinator (no-op).
 *
 * @see src/features/swarm/swarm-coordinator.ts -- MemberJoined/MemberLeft events
 * @see src/features/swarm/stores/swarm-board-store.tsx -- Zustand board store
 */

import { useEffect, useRef } from "react";
import type {
  SwarmCoordinator,
  MemberJoinedHandler,
  MemberLeftHandler,
  MemberJoinedEvent,
  MemberLeftEvent,
} from "@/features/swarm/swarm-coordinator";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import type { Node } from "@xyflow/react";
import { nextNodePosition } from "./node-position";

/** Delay (ms) before removing a left-member's node from the board. */
const REMOVAL_DELAY_MS = 3000;

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Bridge SwarmCoordinator member join/leave events to the Zustand board store.
 *
 * @param coordinator - The SwarmCoordinator instance, or null if unavailable.
 */
export function useTrustGraphBridge(
  coordinator: SwarmCoordinator | null,
): void {
  // Track removal timeouts so we can clean them up on unmount
  const removalTimeouts = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );

  useEffect(() => {
    if (!coordinator) return;

    const store = useSwarmBoardStore.getState;

    // ----- Member joined handler -----
    const handleMemberJoined: MemberJoinedHandler = (
      swarmId: string,
      event: MemberJoinedEvent,
    ) => {
      const { nodes, actions } = store();

      // Deduplicate: skip if a node with this memberId already exists
      if (
        nodes.some(
          (n: Node<SwarmBoardNodeData>) =>
            n.data.sessionId === event.memberId,
        )
      ) {
        return;
      }

      const position = nextNodePosition(nodes);

      const newNode = actions.addNode({
        nodeType: "agentSession",
        title: event.agentModel ?? "Agent",
        position,
        data: {
          sessionId: event.memberId,
          agentModel: event.agentModel,
          policyMode: event.policyMode,
          status: "idle",
          huntId: swarmId,
          createdAt: event.timestamp,
        },
      });

      // Create a handoff edge from the first existing agentSession node
      // to the new node, representing the trust relationship
      const existingSession = nodes.find(
        (n: Node<SwarmBoardNodeData>) =>
          n.data.nodeType === "agentSession" &&
          n.id !== newNode.id,
      );
      if (existingSession) {
        actions.addEdge({
          id: `edge-trust-${existingSession.id}-${newNode.id}-${Date.now().toString(36)}`,
          source: existingSession.id,
          target: newNode.id,
          type: "handoff",
          label: "trust",
        });
      }
    };

    // ----- Member left handler -----
    const handleMemberLeft: MemberLeftHandler = (
      _swarmId: string,
      event: MemberLeftEvent,
    ) => {
      const { nodes, actions } = store();

      // Find the node with this memberId
      const node = nodes.find(
        (n: Node<SwarmBoardNodeData>) =>
          n.data.sessionId === event.memberId,
      );
      if (!node) return;

      // Set status to "completed" to trigger the 0.7 opacity fade
      actions.updateNode(node.id, { status: "completed" });

      // Schedule actual removal after the fade-out delay
      const timeout = setTimeout(() => {
        removalTimeouts.current.delete(event.memberId);
        // Use fresh store state for removal
        useSwarmBoardStore.getState().actions.removeNode(node.id);
      }, REMOVAL_DELAY_MS);

      // Cancel any previous timeout for this member (defensive)
      const existing = removalTimeouts.current.get(event.memberId);
      if (existing) clearTimeout(existing);
      removalTimeouts.current.set(event.memberId, timeout);
    };

    // Register handlers
    coordinator.onMemberJoined(handleMemberJoined);
    coordinator.onMemberLeft(handleMemberLeft);

    // Cleanup: unregister handlers + clear all pending removal timeouts
    return () => {
      coordinator.offMemberJoined(handleMemberJoined);
      coordinator.offMemberLeft(handleMemberLeft);

      for (const timeout of removalTimeouts.current.values()) {
        clearTimeout(timeout);
      }
      removalTimeouts.current.clear();
    };
  }, [coordinator]);
}
