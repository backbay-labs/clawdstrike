// Public types for the fleet-client. Sub-modules and the barrel re-export
// from here; consumers should keep importing from "@/features/fleet/fleet-client".

export interface AuditEvent {
  id: string;
  timestamp: string;
  action_type: string;
  target?: string;
  decision: string;
  guard?: string;
  severity?: string;
  session_id?: string;
  agent_id?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditFilters {
  since?: string;
  until?: string;
  action_type?: string;
  decision?: string;
  agent_id?: string;
  limit?: number;
}

export interface FleetConnection {
  hushdUrl: string;
  controlApiUrl: string;
  apiKey: string;          // hushd Bearer token
  controlApiToken: string; // control-api JWT or API key
  connected: boolean;
  hushdHealth: HealthResponse | null;
  agentCount: number;
}

/**
 * Credential-free projection of FleetConnection, safe for context exposure.
 * Consumers that need credentials should call `getCredentials()` from the
 * fleet connection hook instead of reading them from this object.
 */
export type FleetConnectionInfo = Omit<FleetConnection, "apiKey" | "controlApiToken">;

export interface HealthResponse {
  status: string;
  version?: string;
  uptime_secs?: number;
  policy_hash?: string;
  /** Total evaluations processed by the daemon (reported by newer hushd builds). */
  total_evaluations?: number;
}

export interface PolicyResponse {
  name?: string;
  version?: string;
  description?: string;
  policy_hash?: string;
  yaml?: string;
  source?: { kind: string; path?: string; path_exists?: boolean };
  policy?: unknown;
}

export interface ValidateResponse {
  valid: boolean;
  errors: string[];
  warnings?: string[];
}

export interface DeployResponse {
  success: boolean;
  hash?: string;
  error?: string;
}

export interface AgentDriftFlags {
  policy_drift: boolean;
  daemon_drift: boolean;
  stale: boolean;
}

export interface AgentInfo {
  endpoint_agent_id: string;
  last_heartbeat_at: string;
  last_seen_ip?: string;
  last_session_id?: string;
  posture?: string;
  policy_version?: string;
  daemon_version?: string;
  runtime_count?: number;
  seconds_since_heartbeat?: number;
  online: boolean;
  drift: AgentDriftFlags;
}

export interface AgentStatusResponse {
  generated_at: string;
  stale_after_secs: number;
  endpoints: AgentInfo[];
  runtimes: unknown[];
}

export interface PrincipalInfo {
  id: string;
  name?: string;
  kind?: string;
  role?: string;
  trust_level?: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

/** A scoped policy bound to a scope within the org hierarchy. */
export interface ScopedPolicy {
  id: string;
  scope_type: "org" | "team" | "agent" | "endpoint" | "runtime";
  scope_id: string;
  scope_name: string;
  policy_yaml: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

export interface ScopedPolicyInput {
  scope_type: "org" | "team" | "agent" | "endpoint" | "runtime";
  scope_id: string;
  scope_name: string;
  policy_yaml: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface PolicyAssignment {
  id: string;
  scope_id: string;
  scope_name: string;
  scope_type: "org" | "team" | "agent" | "endpoint" | "runtime";
  policy_id?: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  children?: string[];
  created_at?: string;
}

export interface PolicyAssignmentInput {
  scope_id: string;
  scope_name: string;
  scope_type: "org" | "team" | "agent" | "endpoint" | "runtime";
  policy_id?: string;
  policy_name?: string;
  parent_scope_id?: string | null;
  children?: string[];
}

/** Backend receipt shape (snake_case wire format). */
export interface FleetReceipt {
  id: string;
  timestamp: string;
  verdict: string;
  guard: string;
  policy_name: string;
  evidence?: Record<string, unknown>;
  signature: string;
  public_key: string;
  chain_hash?: string;
  metadata?: Record<string, unknown>;
  signed_receipt?: Record<string, unknown>;
  action_type?: string;
  action_target?: string;
  valid?: boolean;
}

export interface FleetReceiptListResponse {
  receipts: FleetReceipt[];
  total: number;
  offset: number;
  limit: number;
}

export interface FleetReceiptVerifyResponse {
  receipt_id: string;
  valid: boolean;
  signer_valid?: boolean;
  errors?: string[];
  reason?: string;
  verified_at: string;
}

/** Catalog template (snake_case wire format). */
export interface CatalogTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  tags: string[];
  author: string;
  version: string;
  yaml: string;
  guard_summary: string[];
  use_cases: string[];
  compliance: string[];
  difficulty: string;
  downloads: number;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

export interface CatalogCategoryInfo {
  id: string;
  label: string;
  color: string;
  count: number;
}

/** Backend hierarchy node (snake_case wire format). Children may be nested nodes or child ids. */
export type HierarchyNodeChild = HierarchyNode | string;

export interface HierarchyNode {
  id: string;
  name: string;
  node_type: string; // "org" | "team" | "project" | "agent" | "endpoint" | "runtime"
  external_id?: string | null;
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  children?: HierarchyNodeChild[];
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

export interface HierarchyNodeInput {
  name: string;
  node_type: string;
  external_id?: string | null;
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  metadata?: Record<string, unknown>;
}

export interface HierarchyNodeUpdate {
  name?: string;
  node_type?: string;
  external_id?: string | null;
  parent_id?: string | null;
  policy_id?: string | null;
  policy_name?: string | null;
  metadata?: Record<string, unknown>;
}

export interface HierarchyTreeResponse {
  root_id: string | null;
  nodes: HierarchyNode[];
}

export interface SwarmFindingPublishResponse {
  accepted: boolean;
  idempotent: boolean;
  feedId: string;
  issuerId: string;
  feedSeq: number;
  findingId: string;
  headAnnouncement: import("@/features/swarm/swarm-protocol").HeadAnnouncement;
}
