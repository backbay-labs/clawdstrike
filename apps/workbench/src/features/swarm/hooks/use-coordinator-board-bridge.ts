/**
 * useCoordinatorBoardBridge -- React hook that bridges SwarmCoordinator's typed
 * message handlers (intel, detection) to the Zustand board store.
 *
 * When the coordinator receives an intel or detection message, this hook
 * auto-creates or updates artifact nodes on the board graph, creating edges
 * to matching agent session nodes when the swarmId maps to a session's huntId.
 *
 * Lifecycle: registers handlers on mount, unregisters on unmount. Safe to call
 * with a null coordinator (no-op).
 *
 * @see src/features/swarm/swarm-coordinator.ts -- SwarmCoordinator handler API
 * @see src/features/swarm/stores/swarm-board-store.tsx -- Zustand board store
 */

import { useEffect, useRef } from "react";
import type {
  SwarmCoordinator,
  IntelHandler,
  DetectionHandler,
  DetectionMessage,
} from "@/features/swarm/swarm-coordinator";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";
import type { Intel } from "@/lib/workbench/sentinel-types";
import type { Node } from "@xyflow/react";
import { nextNodePosition } from "./node-position";

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Bridge SwarmCoordinator message handlers to the Zustand board store.
 *
 * @param coordinator - The SwarmCoordinator instance, or null if unavailable.
 */
export function useCoordinatorBoardBridge(
  coordinator: SwarmCoordinator | null,
): void {
  // Use refs to hold stable handler references so cleanup works correctly
  const intelHandlerRef = useRef<IntelHandler | null>(null);
  const detectionHandlerRef = useRef<DetectionHandler | null>(null);

  useEffect(() => {
    if (!coordinator) return;

    const store = useSwarmBoardStore.getState;

    // ----- Intel handler -----
    const handleIntel: IntelHandler = (swarmId: string, intel: Intel) => {
      const { nodes, actions } = store();

      // Deduplicate: skip if a node with this intel ID already exists
      if (nodes.some((n) => n.data.documentId === intel.id)) return;

      const position = nextNodePosition(nodes);

      const newNode = actions.addNode({
        nodeType: "artifact",
        title: intel.title || intel.type || "Intel",
        position,
        data: {
          artifactKind: "detection_rule",
          documentId: intel.id,
          status: "idle",
          confidence: intel.confidence,
        },
      });

      // Create edge from matching agent session (huntId === swarmId)
      const sessionNode = nodes.find(
        (n: Node<SwarmBoardNodeData>) =>
          n.data.nodeType === "agentSession" && n.data.huntId === swarmId,
      );
      if (sessionNode) {
        actions.addEdge({
          id: `edge-intel-${newNode.id}-${Date.now().toString(36)}`,
          source: sessionNode.id,
          target: newNode.id,
          type: "artifact",
          label: "intel",
        });
      }
    };

    // ----- Detection handler -----
    const handleDetection: DetectionHandler = (
      swarmId: string,
      detection: DetectionMessage,
    ) => {
      const { nodes, actions } = store();

      switch (detection.action) {
        case "publish": {
          // Deduplicate
          if (nodes.some((n) => n.data.documentId === detection.ruleId)) return;

          const position = nextNodePosition(nodes);

          const newNode = actions.addNode({
            nodeType: "artifact",
            title: `Detection: ${detection.ruleId}`,
            position,
            data: {
              artifactKind: "detection_rule",
              documentId: detection.ruleId,
              status: "idle",
              confidence: detection.confidence,
              format: detection.format as SwarmBoardNodeData["format"],
              content: detection.content,
            },
          });

          // Create edge from matching agent session
          const sessionNode = nodes.find(
            (n: Node<SwarmBoardNodeData>) =>
              n.data.nodeType === "agentSession" && n.data.huntId === swarmId,
          );
          if (sessionNode) {
            actions.addEdge({
              id: `edge-det-${newNode.id}-${Date.now().toString(36)}`,
              source: sessionNode.id,
              target: newNode.id,
              type: "artifact",
              label: "detection",
            });
          }
          break;
        }

        case "update": {
          const existingNode = nodes.find(
            (n) => n.data.documentId === detection.ruleId,
          );
          if (existingNode) {
            actions.updateNode(existingNode.id, {
              confidence: detection.confidence,
              content: detection.content,
            });
          }
          break;
        }

        case "deprecate": {
          const existingNode = nodes.find(
            (n) => n.data.documentId === detection.ruleId,
          );
          if (existingNode) {
            actions.updateNode(existingNode.id, {
              status: "completed",
            });
          }
          break;
        }
      }
    };

    // Store refs for cleanup
    intelHandlerRef.current = handleIntel;
    detectionHandlerRef.current = handleDetection;

    // Register handlers
    coordinator.onIntelReceived(handleIntel);
    coordinator.onDetectionReceived(handleDetection);

    // Cleanup: unregister on unmount or coordinator change
    return () => {
      coordinator.offIntelReceived(handleIntel);
      coordinator.offDetectionReceived(handleDetection);
      intelHandlerRef.current = null;
      detectionHandlerRef.current = null;
    };
  }, [coordinator]);
}
