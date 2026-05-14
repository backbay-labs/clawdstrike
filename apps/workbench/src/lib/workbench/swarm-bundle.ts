/**
 * Swarm Bundle type definitions.
 *
 * A `.swarm` directory is a bundle that encapsulates a swarm board
 * (visual agent-orchestration canvas), its manifest metadata, and
 * any associated artifacts. These types define the on-disk persistence
 * format consumed by the SwarmBoardPage and D2 serialization layer.
 */

export interface SwarmBundleManifest {
  version: "1.0.0";
  name: string;
  description?: string;
  created: string; // ISO 8601
  modified: string; // ISO 8601
  policyRef?: string; // path or name of associated policy
  agents?: string[]; // agent model names
  status?: "draft" | "active" | "archived";
}

export interface SwarmBoardPersisted {
  boardId: string;
  repoRoot: string;
  nodes: Array<{
    id: string;
    type: string;
    position: { x: number; y: number };
    data: Record<string, unknown>;
    width?: number;
    height?: number;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    label?: string;
    type?: string;
  }>;
  viewport?: { x: number; y: number; zoom: number };
}
