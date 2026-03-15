// ---------------------------------------------------------------------------
// SwarmBoard edge type registry — exports all custom React Flow edges
// and the edgeTypes map for <ReactFlow edgeTypes={...} />
// ---------------------------------------------------------------------------

import type { EdgeTypes } from "@xyflow/react";
import { SwarmEdge } from "./swarm-edge";

export { SwarmEdge } from "./swarm-edge";

/**
 * Edge type map passed to `<ReactFlow edgeTypes={swarmBoardEdgeTypes} />`.
 */
export const swarmBoardEdgeTypes: EdgeTypes = {
  swarmEdge: SwarmEdge,
};
