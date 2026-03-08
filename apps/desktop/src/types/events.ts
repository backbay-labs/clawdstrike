/**
 * Event and Audit Types - Core data model for SDR events
 */

export type ActionType =
  | "file_access"
  | "file_write"
  | "egress"
  | "shell"
  | "mcp_tool"
  | "patch"
  | "secret_access"
  | "custom";

export type Severity = "info" | "warning" | "error" | "critical";

export type Decision = "allowed" | "blocked";

export interface AuditEvent {
  id: string;
  timestamp: string;
  event_type: string;
  action_type: ActionType;
  target?: string;
  decision: Decision;
  guard?: string;
  severity?: Severity;
  message?: string;
  session_id?: string;
  agent_id?: string;
  content?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditFilter {
  action_type?: ActionType;
  decision?: Decision;
  guard?: string;
  severity?: Severity;
  agent_id?: string;
  session_id?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

export interface AuditResponse {
  events: AuditEvent[];
  total: number;
  has_more: boolean;
}

export interface AuditStats {
  total_events: number;
  allowed_count: number;
  blocked_count: number;
  events_by_guard: Record<string, number>;
  events_by_action_type: Record<string, number>;
  events_by_severity: Record<string, number>;
}

export interface DaemonEventData {
  action_type?: string;
  target?: string;
  allowed?: boolean;
  guard?: string;
  policy_hash?: string;
  event_id?: string;
  event_type?: string;
  [key: string]: unknown;
}

export interface DaemonEvent {
  type: string;
  timestamp: string;
  data: DaemonEventData | PolicyReloadEvent | SessionEvent | ErrorEvent;
}

export interface PolicyReloadEvent {
  policy_hash?: string;
  policy_name?: string;
  guard_count?: number;
}

export interface SessionEvent {
  session_id: string;
  agent_id?: string;
  action: "start" | "end";
}

export interface ErrorEvent {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}
