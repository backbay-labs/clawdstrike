// ---------------------------------------------------------------------------
// Org/Team/Agent hierarchy types for policy inheritance visualization
// ---------------------------------------------------------------------------

export type OrgNodeType = "org" | "team" | "agent";

export interface OrgNode {
  id: string;
  name: string;
  type: OrgNodeType;
  parentId: string | null;
  /** ID of a SavedPolicy linked to this node. */
  policyId?: string;
  /** Display name of the linked policy (cached for quick display). */
  policyName?: string;
  /** Ordered child node IDs. */
  children: string[];
  metadata?: {
    description?: string;
    memberCount?: number;
    agentCount?: number;
    compliance?: string[];
  };
}

export interface PolicyHierarchy {
  nodes: Record<string, OrgNode>;
  rootId: string;
}

export interface EffectivePolicySource {
  nodeId: string;
  nodeName: string;
  level: OrgNodeType;
}

export interface EffectivePolicyEntry {
  value: unknown;
  inheritedFrom: string; // node name
  overridden: boolean;
}

export interface EffectivePolicy {
  /** Ordered list of nodes from root to the target node. */
  source: EffectivePolicySource[];
  /** Per-guard effective values with provenance. */
  guards: Record<string, EffectivePolicyEntry>;
  /** Per-setting effective values with provenance. */
  settings: Record<string, EffectivePolicyEntry>;
}
