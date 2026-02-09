export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type EvaluationMode = 'deterministic' | 'advisory' | 'audit';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface GuardToggles {
  forbidden_path?: boolean;
  egress?: boolean;
  secret_leak?: boolean;
  patch_integrity?: boolean;
  mcp_tool?: boolean;
}

export interface ClawdstrikeConfig {
  policy?: string;
  mode?: EvaluationMode;
  logLevel?: LogLevel;
  guards?: GuardToggles;
}

export type Policy = Record<string, unknown>;

export type EventType =
  | 'file_read'
  | 'file_write'
  | 'command_exec'
  | 'network_egress'
  | 'tool_call'
  | 'patch_apply'
  | 'secret_access'
  | 'custom';

export interface PolicyEvent {
  eventId: string;
  eventType: EventType;
  timestamp: string;
  sessionId?: string;
  data: EventData;
  metadata?: Record<string, unknown>;
}

export type EventData =
  | FileEventData
  | CommandEventData
  | NetworkEventData
  | ToolEventData
  | PatchEventData
  | SecretEventData
  | CustomEventData;

export interface FileEventData {
  type: 'file';
  path: string;
  content?: string;
  contentBase64?: string;
  contentHash?: string;
  operation: 'read' | 'write';
}

export interface CommandEventData {
  type: 'command';
  command: string;
  args: string[];
  workingDir?: string;
}

export interface NetworkEventData {
  type: 'network';
  host: string;
  port: number;
  protocol?: string;
  url?: string;
}

export interface ToolEventData {
  type: 'tool';
  toolName: string;
  parameters: Record<string, unknown>;
  result?: string;
}

export interface PatchEventData {
  type: 'patch';
  filePath: string;
  patchContent: string;
  patchHash?: string;
}

export interface SecretEventData {
  type: 'secret';
  secretName: string;
  scope: string;
}

export interface CustomEventData {
  type: 'custom';
  customType: string;
  [key: string]: unknown;
}

// ============================================================
// Decision type with status enum
// ============================================================

/**
 * Decision status for security checks.
 * - 'allow': Operation is permitted
 * - 'warn': Operation is permitted but flagged for review
 * - 'deny': Operation is blocked
 */
export type DecisionStatus = 'allow' | 'warn' | 'deny';

/**
 * Decision returned from policy evaluation.
 *
 * Use the `status` field to determine the outcome:
 * - `status === 'allow'`: Operation permitted
 * - `status === 'warn'`: Operation permitted with warning
 * - `status === 'deny'`: Operation blocked
 */
export interface Decision {
  /** The decision status: 'allow', 'warn', or 'deny' */
  status: DecisionStatus;
  /** Name of the guard that made this decision */
  guard?: string;
  /** Severity level of the violation */
  severity?: Severity;
  /** Human-readable message describing the decision */
  message?: string;
  /** Additional reason for the decision */
  reason?: string;
  /** Additional structured details */
  details?: unknown;
}

/**
 * Create a Decision.
 */
export function createDecision(
  status: DecisionStatus,
  options: {
    guard?: string;
    severity?: Severity;
    message?: string;
    reason?: string;
    details?: unknown;
  } = {},
): Decision {
  return {
    status,
    guard: options.guard,
    severity: options.severity,
    message: options.message,
    reason: options.reason,
    details: options.details,
  };
}

/**
 * Helper to create an allow decision.
 */
export function allowDecision(options: { guard?: string; message?: string } = {}): Decision {
  return createDecision('allow', { severity: 'low', ...options });
}

/**
 * Helper to create a deny decision.
 */
export function denyDecision(options: {
  guard?: string;
  severity?: Severity;
  message?: string;
  reason?: string;
  details?: unknown;
}): Decision {
  return createDecision('deny', { severity: 'high', ...options });
}

/**
 * Helper to create a warn decision.
 */
export function warnDecision(options: {
  guard?: string;
  severity?: Severity;
  message?: string;
  reason?: string;
  details?: unknown;
}): Decision {
  return createDecision('warn', { severity: 'medium', ...options });
}
