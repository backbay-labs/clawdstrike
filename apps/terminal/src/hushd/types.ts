/**
 * Hushd Types - TypeScript interfaces for hushd API
 *
 * Mirrors the hushd daemon's HTTP API response shapes.
 */

// =============================================================================
// CHECK API
// =============================================================================

export interface CheckRequest {
  action_type: "file" | "network" | "shell" | "patch" | "mcp_tool"
  target: string
  context?: Record<string, unknown>
  metadata?: Record<string, string>
}

export interface GuardResult {
  guard: string
  decision: "allow" | "deny"
  reason?: string
  severity?: "info" | "warning" | "error" | "critical"
  evidence?: Record<string, unknown>
}

export interface CheckResponse {
  decision: "allow" | "deny"
  policy: string
  policy_version: string
  guards: GuardResult[]
  receipt_id?: string
  timestamp: string
}

// =============================================================================
// POSTURE API
// =============================================================================

export interface PostureInfo {
  policy: string
  policy_version: string
  policy_hash: string
  guards: string[]
  loaded_at: string
}

// =============================================================================
// AUDIT API
// =============================================================================

export interface AuditQuery {
  event_type?: string
  limit?: number
  offset?: number
  cursor?: string
  since?: string
  until?: string
  action_type?: string
  decision?: "allowed" | "blocked" | "allow" | "deny"
  guard?: string
  session_id?: string
  agent_id?: string
  runtime_agent_id?: string
  runtime_agent_kind?: string
  format?: "json" | "csv" | "jsonl"
}

export interface AuditEvent {
  id: string
  timestamp: string
  event_type: string
  action_type: string
  target?: string | null
  decision: "allowed" | "blocked"
  guard?: string | null
  severity?: "info" | "warning" | "error" | "critical" | null
  message?: string | null
  session_id?: string | null
  agent_id?: string | null
  metadata?: Record<string, unknown> | null
}

export interface AuditResponse {
  events: AuditEvent[]
  total: number
  offset?: number
  limit?: number
  next_cursor?: string
  has_more?: boolean
}

export interface AuditBatchRequest {
  events: Array<Record<string, unknown>>
}

export interface AuditBatchResponse {
  accepted: number
  duplicates: number
  rejected: number
  accepted_ids?: string[]
  duplicate_ids?: string[]
  rejected_ids?: string[]
}

export interface AuditStats {
  total_events: number
  violations: number
  allowed: number
  session_id: string
  uptime_secs: number
}

// =============================================================================
// POLICY API
// =============================================================================

export interface PolicyResponse {
  name: string
  version: string
  hash: string
  schema_version: string
  guards: PolicyGuardConfig[]
  extends?: string[]
  loaded_at: string | null
  description?: string
  yaml?: string
  source?: unknown
  schema?: unknown
}

export interface PolicyGuardConfig {
  id: string
  enabled: boolean
  config?: Record<string, unknown>
}

// =============================================================================
// SSE EVENTS
// =============================================================================

export type DaemonEventType =
  | "check"
  | "violation"
  | "eval"
  | "policy_reload"
  | "policy_reloaded"
  | "agent_heartbeat"
  | "error"
  | (string & {})

export interface DaemonEvent {
  type: DaemonEventType
  timestamp: string
  data: DaemonEventData
}

export type DaemonEventData =
  | CheckEventData
  | PolicyReloadData
  | AgentHeartbeatData
  | ErrorData
  | Record<string, unknown>

export interface CheckEventData {
  event_id?: string
  action_type: string
  target: string
  decision: "allow" | "deny"
  guard?: string | null
  severity?: "info" | "warning" | "error" | "critical" | null
  reason?: string
  message?: string
  session_id?: string | null
  agent_id?: string | null
  endpoint_agent_id?: string | null
  runtime_agent_id?: string | null
  runtime_agent_kind?: string | null
}

export interface PolicyReloadData {
  policy?: string
  version?: string
  guards?: string[]
  [key: string]: unknown
}

export interface AgentHeartbeatData {
  timestamp?: string
  session_id?: string | null
  endpoint_agent_id?: string | null
  runtime_agent_id?: string | null
  runtime_agent_kind?: string | null
  posture?: string | null
  policy_version?: string | null
  daemon_version?: string | null
  [key: string]: unknown
}

export interface ErrorData {
  message: string
  code?: string
  [key: string]: unknown
}

// =============================================================================
// CONNECTION STATE
// =============================================================================

export type HushdConnectionState =
  | "not_configured"
  | "connecting"
  | "connected"
  | "degraded"
  | "stale"
  | "disconnected"
  | "unauthorized"
  | "error"
