// ---------------------------------------------------------------------------
// SwarmBoard node type registry — exports all custom React Flow nodes
// and the nodeTypes map for <ReactFlow nodeTypes={...} />
// ---------------------------------------------------------------------------

import type { NodeTypes } from "@xyflow/react";
import { AgentSessionNode } from "./agent-session-node";
import { TerminalTaskNode } from "./terminal-task-node";
import { ArtifactNode } from "./artifact-node";
import { DiffNode } from "./diff-node";
import { NoteNode } from "./note-node";
import { ReceiptNode } from "./receipt-node";

export { AgentSessionNode } from "./agent-session-node";
export { TerminalTaskNode } from "./terminal-task-node";
export { ArtifactNode } from "./artifact-node";
export { DiffNode } from "./diff-node";
export { NoteNode } from "./note-node";
export { ReceiptNode } from "./receipt-node";

/**
 * Node type map passed to `<ReactFlow nodeTypes={swarmBoardNodeTypes} />`.
 * Keys must match the `SwarmNodeType` union and the `type` field on each node.
 */
export const swarmBoardNodeTypes: NodeTypes = {
  agentSession: AgentSessionNode,
  terminalTask: TerminalTaskNode,
  artifact: ArtifactNode,
  diff: DiffNode,
  note: NoteNode,
  receipt: ReceiptNode,
};
