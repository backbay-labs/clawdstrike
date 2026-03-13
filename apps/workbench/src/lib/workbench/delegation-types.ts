/**
 * Delegation Graph type definitions.
 *
 * These mirror the Rust `hush-multi-agent` crate's delegation model:
 * AgentIdentity, AgentCapability, DelegationGraphNode, DelegationGraphEdge.
 */

export type AgentRole =
  | "Planner"
  | "Coder"
  | "Tester"
  | "Reviewer"
  | "Deployer"
  | "Monitor"
  | "Custom";

export type TrustLevel =
  | "Untrusted"
  | "Low"
  | "Medium"
  | "High"
  | "System";

export type NodeKind =
  | "Principal"
  | "Session"
  | "Grant"
  | "Approval"
  | "Event"
  | "ResponseAction";

export type EdgeKind =
  | "IssuedGrant"
  | "ReceivedGrant"
  | "DerivedFromGrant"
  | "SpawnedPrincipal"
  | "ApprovedBy"
  | "RevokedBy"
  | "ExercisedInSession"
  | "ExercisedInEvent"
  | "TriggeredResponseAction";

export type Capability =
  | "FileRead"
  | "FileWrite"
  | "NetworkEgress"
  | "CommandExec"
  | "SecretAccess"
  | "McpTool"
  | "DeployApproval"
  | "AgentAdmin"
  | "Custom";

export interface DelegationNode {
  id: string;
  kind: NodeKind;
  label: string;
  role?: AgentRole;
  trustLevel?: TrustLevel;
  capabilities?: Capability[];
  metadata?: Record<string, unknown>;
}

export interface DelegationEdge {
  id: string;
  from: string;
  to: string;
  kind: EdgeKind;
  capabilities?: Capability[];
  metadata?: Record<string, unknown>;
}

export interface DelegationGraph {
  nodes: DelegationNode[];
  edges: DelegationEdge[];
}
