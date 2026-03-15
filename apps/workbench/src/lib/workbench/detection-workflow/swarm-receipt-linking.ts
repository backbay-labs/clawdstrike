/**
 * Receipt linking — connects receipt nodes to publication nodes on the
 * SwarmBoard, updating publish state after verification.
 */

import type { SwarmBoardNodeData, SwarmBoardEdge } from "../swarm-board-types";
import type { verifyPublishState } from "./swarm-detection-nodes";

// ---------------------------------------------------------------------------
// Types — accept the minimal store interface to avoid circular deps
// ---------------------------------------------------------------------------

interface SwarmBoardStoreHandle {
  state: {
    nodes: Array<{ id: string; data: SwarmBoardNodeData }>;
    edges: SwarmBoardEdge[];
  };
  addEdge: (edge: SwarmBoardEdge) => void;
  updateNode: (nodeId: string, patch: Partial<SwarmBoardNodeData>) => void;
}

type VerifyFn = typeof verifyPublishState;

// ---------------------------------------------------------------------------
// linkReceiptToPublication
// ---------------------------------------------------------------------------

/**
 * Link a receipt node to a publication node on the board.
 *
 * Creates an edge between the two nodes and, if publish state verification
 * succeeds, transitions the publication node to "published".
 *
 * @param boardStore - The board store handle (dispatch surface)
 * @param receiptNodeId - ID of the receipt node
 * @param publicationNodeId - ID of the publication node
 * @param verify - Optional verifyPublishState function (injectable for testing)
 */
export async function linkReceiptToPublication(
  boardStore: SwarmBoardStoreHandle,
  receiptNodeId: string,
  publicationNodeId: string,
  verify?: VerifyFn,
): Promise<void> {
  const receiptNode = boardStore.state.nodes.find((n) => n.id === receiptNodeId);
  const pubNode = boardStore.state.nodes.find((n) => n.id === publicationNodeId);

  if (!receiptNode) {
    throw new Error(`Receipt node "${receiptNodeId}" not found on board`);
  }
  if (!pubNode) {
    throw new Error(`Publication node "${publicationNodeId}" not found on board`);
  }

  // Validate node types
  const receiptData = receiptNode.data as SwarmBoardNodeData;
  const pubData = pubNode.data as SwarmBoardNodeData;

  if (receiptData.nodeType !== "receipt") {
    throw new Error(`Node "${receiptNodeId}" is not a receipt node (type: ${receiptData.nodeType})`);
  }
  if (pubData.artifactKind !== "publication_manifest") {
    throw new Error(
      `Node "${publicationNodeId}" is not a publication manifest node (artifactKind: ${pubData.artifactKind ?? "none"})`,
    );
  }

  // Create the edge
  const edgeId = `edge-receipt-${receiptNodeId}-${publicationNodeId}`;
  const existingEdge = boardStore.state.edges.find((e) => e.id === edgeId);
  if (!existingEdge) {
    boardStore.addEdge({
      id: edgeId,
      source: receiptNodeId,
      target: publicationNodeId,
      type: "receipt",
      label: "receipt",
    });
  }

  // Attempt to transition publishState to "published" after verification
  if (verify) {
    // Temporarily set publishState for verification
    const tempNode = {
      ...pubNode,
      data: { ...pubData, publishState: "published" as const },
    };
    const result = await verify(tempNode as Parameters<VerifyFn>[0]);
    if (result.valid) {
      boardStore.updateNode(publicationNodeId, { publishState: "published" });
    }
    // If verification fails, we still created the edge — just don't
    // transition the state. The user can investigate.
  }
}
