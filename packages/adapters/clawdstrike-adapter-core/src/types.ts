export type Severity = "low" | "medium" | "high" | "critical";

export type EvaluationMode = "deterministic" | "advisory" | "audit";

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface GuardToggles {
  forbidden_path?: boolean;
  egress?: boolean;
  secret_leak?: boolean;
  patch_integrity?: boolean;
  mcp_tool?: boolean;
  spider_sense?: boolean;
}

export interface ClawdstrikeConfig {
  policy?: string;
  mode?: EvaluationMode;
  logLevel?: LogLevel;
  guards?: GuardToggles;
}

export type Policy = Record<string, unknown>;

export type EventType =
  | "file_read"
  | "file_write"
  | "command_exec"
  | "network_egress"
  | "tool_call"
  | "patch_apply"
  | "secret_access"
  | "custom"
  | "remote.session.connect"
  | "remote.session.disconnect"
  | "remote.session.reconnect"
  | "input.inject"
  | "remote.clipboard"
  | "remote.file_transfer"
  | "remote.audio"
  | "remote.drive_mapping"
  | "remote.printing"
  | "remote.session_share"
  | "spider_sense.screen"
  | "spider_sense.deep_analysis";

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
  | CustomEventData
  | CuaEventData;

export interface FileEventData {
  type: "file";
  path: string;
  content?: string;
  contentBase64?: string;
  contentHash?: string;
  operation: "read" | "write";
}

export interface CommandEventData {
  type: "command";
  command: string;
  args: string[];
  workingDir?: string;
}

export interface NetworkEventData {
  type: "network";
  host: string;
  port: number;
  protocol?: string;
  url?: string;
}

export interface ToolEventData {
  type: "tool";
  toolName: string;
  parameters: Record<string, unknown>;
  result?: string;
}

export interface PatchEventData {
  type: "patch";
  filePath: string;
  patchContent: string;
  patchHash?: string;
}

export interface SecretEventData {
  type: "secret";
  secretName: string;
  scope: string;
}

export interface CustomEventData {
  type: "custom";
  customType: string;
  [key: string]: unknown;
}

export interface CuaEventData {
  type: "cua";
  cuaAction: string;
  direction?: "read" | "write" | "upload" | "download" | "inbound" | "outbound";
  continuityPrevSessionHash?: string;
  postconditionProbeHash?: string;
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
export type DecisionStatus = "allow" | "warn" | "deny" | "sanitize";

export type DecisionReasonCode = string;

interface DecisionBase {
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
 * Decision returned from policy evaluation.
 *
 * Use the `status` field to determine the outcome:
 * - `status === 'allow'`: Operation permitted
 * - `status === 'warn'`: Operation permitted with warning
 * - `status === 'deny'`: Operation blocked
 */
export type Decision =
  | (DecisionBase & {
      /** The decision status: 'allow' */
      status: "allow";
      /** Optional machine-readable code for allow results */
      reason_code?: DecisionReasonCode;
    })
  | (DecisionBase & {
      /** The decision status: 'warn' or 'deny' */
      status: "warn" | "deny";
      /** Required machine-readable code for non-allow results */
      reason_code: DecisionReasonCode;
    })
  | (DecisionBase & {
      /** The decision status: 'sanitize' */
      status: "sanitize";
      /** Required machine-readable code for sanitize results */
      reason_code: DecisionReasonCode;
      /** Original content before sanitization */
      original?: string;
      /** Sanitized content */
      sanitized?: string;
    });

/**
 * Create a Decision.
 */
export function createDecision(
  status: "allow",
  options?: {
    reason_code?: DecisionReasonCode;
    guard?: string;
    severity?: Severity;
    message?: string;
    reason?: string;
    details?: unknown;
  },
): Decision;
export function createDecision(
  status: "warn" | "deny",
  options: {
    reason_code: DecisionReasonCode;
    guard?: string;
    severity?: Severity;
    message?: string;
    reason?: string;
    details?: unknown;
  },
): Decision;
export function createDecision(
  status: "sanitize",
  options: {
    reason_code: DecisionReasonCode;
    original?: string;
    sanitized?: string;
    guard?: string;
    severity?: Severity;
    message?: string;
    reason?: string;
    details?: unknown;
  },
): Decision;
export function createDecision(
  status: DecisionStatus,
  options: {
    reason_code?: DecisionReasonCode;
    original?: string;
    sanitized?: string;
    guard?: string;
    severity?: Severity;
    message?: string;
    reason?: string;
    details?: unknown;
  } = {},
): Decision {
  if (status !== "allow" && (!options.reason_code || options.reason_code.trim().length === 0)) {
    throw new Error(`Decision reason_code is required for status '${status}'`);
  }
  if (status === "allow") {
    return {
      status: "allow",
      ...(options.reason_code !== undefined && { reason_code: options.reason_code }),
      guard: options.guard,
      severity: options.severity,
      message: options.message,
      reason: options.reason,
      details: options.details,
    };
  }
  return {
    status,
    reason_code: options.reason_code as DecisionReasonCode,
    guard: options.guard,
    severity: options.severity,
    message: options.message,
    reason: options.reason,
    details: options.details,
    ...(status === "sanitize" && options.original !== undefined && { original: options.original }),
    ...(status === "sanitize" &&
      options.sanitized !== undefined && { sanitized: options.sanitized }),
  } as Decision;
}

/**
 * Helper to create an allow decision.
 */
export function allowDecision(options: { guard?: string; message?: string } = {}): Decision {
  return createDecision("allow", { severity: "low", ...options });
}

/**
 * Helper to create a deny decision.
 */
export function denyDecision(options: {
  reason_code: DecisionReasonCode;
  guard?: string;
  severity?: Severity;
  message?: string;
  reason?: string;
  details?: unknown;
}): Decision {
  return createDecision("deny", { severity: "high", ...options });
}

/**
 * Helper to create a warn decision.
 */
export function warnDecision(options: {
  reason_code: DecisionReasonCode;
  guard?: string;
  severity?: Severity;
  message?: string;
  reason?: string;
  details?: unknown;
}): Decision {
  return createDecision("warn", { severity: "medium", ...options });
}

/**
 * Helper to create a sanitize decision.
 */
export function sanitizeDecision(options: {
  reason_code: DecisionReasonCode;
  original?: string;
  sanitized?: string;
  guard?: string;
  severity?: Severity;
  message?: string;
  reason?: string;
  details?: unknown;
}): Decision {
  return createDecision("sanitize", { severity: "medium", ...options });
}
