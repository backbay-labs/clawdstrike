/**
 * usePolicyEvalBoardBridge -- React hook that bridges SwarmCoordinator's
 * policyEvaluated events to the Zustand board store, driving the "evaluating"
 * glow state on agent session nodes.
 *
 * When the coordinator emits a policyEvaluated event, this hook:
 *   1. Finds the matching agent session node (by huntId or sessionId)
 *   2. Sets its status to "evaluating" (triggers gold glow ring CSS)
 *   3. After 2000ms, resets the status back to the previous value
 *
 * Handles rapid consecutive evaluations by clearing existing timeouts
 * before setting new ones.
 *
 * Lifecycle: registers handler on mount, unregisters + clears all timeouts on
 * unmount. Safe to call with a null coordinator (no-op).
 *
 * @see src/features/swarm/swarm-coordinator.ts -- PolicyEvaluatedHandler
 * @see src/features/swarm/stores/swarm-board-store.tsx -- Zustand board store
 */

import { useEffect, useRef } from "react";
import type {
  SwarmCoordinator,
  PolicyEvaluatedHandler,
  PolicyEvaluatedEvent,
} from "@/features/swarm/swarm-coordinator";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData, SessionStatus } from "@/features/swarm/swarm-board-types";
import type { Node } from "@xyflow/react";

/** Duration in ms that the evaluating glow remains visible. */
const EVAL_GLOW_DURATION_MS = 2000;

/**
 * Bridge SwarmCoordinator policyEvaluated events to board node glow state.
 *
 * @param coordinator - The SwarmCoordinator instance, or null if unavailable.
 */
export function usePolicyEvalBoardBridge(
  coordinator: SwarmCoordinator | null,
): void {
  // Track active reset timeouts per node ID so we can clear on rapid re-eval
  const timeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  // Track the "restore" status per node so the reset goes back to the right state
  const restoreStatusRef = useRef<Map<string, SessionStatus>>(new Map());

  useEffect(() => {
    if (!coordinator) return;

    const store = useSwarmBoardStore.getState;
    const timeouts = timeoutsRef.current;
    const restoreStatuses = restoreStatusRef.current;

    const handlePolicyEvaluated: PolicyEvaluatedHandler = (
      swarmId: string,
      event: PolicyEvaluatedEvent,
    ) => {
      const { nodes, actions } = store();

      // Find the matching agent session node
      const sessionNode = nodes.find(
        (n: Node<SwarmBoardNodeData>) =>
          n.data.nodeType === "agentSession" &&
          (n.data.huntId === swarmId || n.data.sessionId === event.agentId),
      );

      if (!sessionNode) return;

      const nodeId = sessionNode.id;
      const currentStatus = (sessionNode.data as SwarmBoardNodeData).status;

      // If there is already an active timeout for this node, clear it
      // (the node is being re-evaluated before the previous glow faded)
      const existingTimeout = timeouts.get(nodeId);
      if (existingTimeout != null) {
        clearTimeout(existingTimeout);
      } else {
        // Only save the restore status if this is a fresh evaluation
        // (not a rapid re-trigger while already evaluating)
        restoreStatuses.set(
          nodeId,
          currentStatus === "evaluating" ? "running" : currentStatus,
        );
      }

      // Set the node to evaluating status (triggers gold glow ring)
      actions.updateNode(nodeId, { status: "evaluating" });

      // Schedule reset back to previous status after the glow duration
      const timeout = setTimeout(() => {
        timeouts.delete(nodeId);
        const restoreTo = restoreStatuses.get(nodeId) ?? "running";
        restoreStatuses.delete(nodeId);
        actions.updateNode(nodeId, { status: restoreTo });
      }, EVAL_GLOW_DURATION_MS);

      timeouts.set(nodeId, timeout);
    };

    coordinator.onPolicyEvaluated(handlePolicyEvaluated);

    // Cleanup: unregister handler and clear all pending timeouts
    return () => {
      coordinator.offPolicyEvaluated(handlePolicyEvaluated);

      for (const timeout of timeouts.values()) {
        clearTimeout(timeout);
      }
      timeouts.clear();
      restoreStatuses.clear();
    };
  }, [coordinator]);
}
