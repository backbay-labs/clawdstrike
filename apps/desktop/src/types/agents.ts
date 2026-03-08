/**
 * Agent Types - Multi-agent identity and delegation
 */

export type AgentRole =
  | "Planner"
  | "Coder"
  | "Tester"
  | "Reviewer"
  | "Deployer"
  | "Monitor"
  | "Custom";

export type TrustLevel = "Untrusted" | "Low" | "Medium" | "High" | "System";

export interface AgentCapability {
  type: AgentCapabilityType;
  params?: Record<string, unknown>;
}

export type AgentCapabilityType =
  | "FileRead"
  | "FileWrite"
  | "NetworkEgress"
  | "CommandExec"
  | "SecretAccess"
  | "McpTool"
  | "DeployApproval"
  | "AgentAdmin"
  | "Custom";

export interface AgentIdentity {
  id: string;
  name: string;
  role: AgentRole;
  trust_level: TrustLevel;
  public_key: string; // Ed25519 hex
  capabilities: AgentCapability[];
  metadata?: Record<string, string>;
  created_at?: string;
}

export interface AgentNode extends AgentIdentity {
  position: [number, number, number]; // 3D coords
  threat_score: number; // 0-1, based on recent violations
  last_activity?: string;
  event_count?: number;
  blocked_count?: number;
}

export interface DelegationEdge {
  id: string; // token jti
  from: string; // issuer agent id
  to: string; // subject agent id
  capabilities: AgentCapability[];
  issued_at: number; // Unix timestamp
  expires_at: number;
  purpose?: string;
  revoked?: boolean;
}

export interface DelegationClaims {
  iss: string; // issuer
  sub: string; // subject
  aud: string; // "clawdstrike:delegation"
  iat: number;
  exp: number;
  nbf?: number;
  jti: string;
  cap: AgentCapability[];
  chn: string[]; // delegation chain
  cel: AgentCapability[]; // capability ceiling
  pur?: string; // purpose
  ctx?: Record<string, unknown>;
}

export interface SignedDelegationToken {
  claims: DelegationClaims;
  signature: string;
  public_key?: string;
}

export interface SwarmState {
  agents: AgentNode[];
  delegations: DelegationEdge[];
  updated_at: string;
}

// Trust level colors for visualization
export const TRUST_COLORS: Record<TrustLevel, string> = {
  System: "#22c55e", // green
  High: "#3b82f6", // blue
  Medium: "#f59e0b", // amber
  Low: "#f97316", // orange
  Untrusted: "#ef4444", // red
};

// Role icons/sigils
export const ROLE_ICONS: Record<AgentRole, string> = {
  Planner: "map",
  Coder: "code",
  Tester: "beaker",
  Reviewer: "eye",
  Deployer: "rocket",
  Monitor: "activity",
  Custom: "puzzle",
};
