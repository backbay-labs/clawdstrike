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
  limit?: number
  offset?: number
  action_type?: string
  decision?: "allow" | "deny"
  guard?: string
  since?: string
  until?: string
}

export interface AuditEvent {
  id: string
  timestamp: string
  action_type: string
  target: string
  decision: "allow" | "deny"
  guard: string
  severity: "info" | "warning" | "error" | "critical"
  reason?: string
  receipt_id?: string
}

export interface AuditResponse {
  events: AuditEvent[]
  total: number
  offset: number
  limit: number
}

export interface AuditStats {
  total_checks: number
  allowed: number
  denied: number
  by_guard: Record<string, { allowed: number; denied: number }>
  by_action_type: Record<string, { allowed: number; denied: number }>
  since: string
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
  loaded_at: string
}

export interface PolicyGuardConfig {
  id: string
  enabled: boolean
  config?: Record<string, unknown>
}

// =============================================================================
// SSE EVENTS
// =============================================================================

export interface DaemonEvent {
  type: "check" | "policy_reload" | "error"
  timestamp: string
  data: CheckEventData | PolicyReloadData | ErrorData
}

export interface CheckEventData {
  action_type: string
  target: string
  decision: "allow" | "deny"
  guard: string
  severity: "info" | "warning" | "error" | "critical"
  reason?: string
}

export interface PolicyReloadData {
  policy: string
  version: string
  guards: string[]
}

export interface ErrorData {
  message: string
  code?: string
}

// =============================================================================
// CONNECTION STATE
// =============================================================================

export type HushdConnectionState = "disconnected" | "connecting" | "connected" | "error"
