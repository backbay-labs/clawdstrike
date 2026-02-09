import { randomBytes } from "node:crypto";

export type Outcome = "success" | "failure" | "unknown";

export type SecuritySeverity = "info" | "low" | "medium" | "high" | "critical";

export type SecurityEventType =
  | "policy_violation"
  | "policy_allow"
  | "guard_block"
  | "guard_warn"
  | "secret_detected"
  | "egress_blocked"
  | "forbidden_path"
  | "patch_rejected"
  | "session_start"
  | "session_end";

export type EventCategory =
  | "authentication"
  | "authorization"
  | "file"
  | "network"
  | "process"
  | "tool"
  | "configuration"
  | "session";

export type ThreatIndicatorType = "domain" | "file_path" | "pattern";

export interface ThreatIndicator {
  type: ThreatIndicatorType;
  value: string;
}

export interface ThreatInfo {
  indicator?: ThreatIndicator;
  tactic?: string;
  technique?: string;
}

export interface AgentInfo {
  id: string;
  name: string;
  version: string;
  type: "clawdstrike";
}

export interface SessionInfo {
  id: string;
  user_id?: string;
  tenant_id?: string;
  environment?: string;
}

export interface DecisionInfo {
  allowed: boolean;
  guard: string;
  severity: SecuritySeverity;
  reason: string;
  policy_hash?: string;
  ruleset?: string;
}

export type ResourceType = "file" | "network" | "process" | "tool" | "configuration";

export interface ResourceInfo {
  type: ResourceType;
  name: string;
  path?: string;
  host?: string;
  port?: number;
}

export interface SecurityEvent {
  schema_version: string;

  event_id: string;
  event_type: SecurityEventType;
  event_category: EventCategory;

  timestamp: string;
  ingested_at?: string;

  agent: AgentInfo;
  session: SessionInfo;

  outcome: Outcome;
  action: string;

  threat: ThreatInfo;
  decision: DecisionInfo;
  resource: ResourceInfo;

  metadata: Record<string, unknown>;
  labels: Record<string, string>;
}

export interface SecurityEventContext {
  schema_version: string;
  environment?: string;
  tenant_id?: string;
  agent_name?: string;
  agent_version: string;
  policy_hash?: string;
  ruleset?: string;
  default_session_id: string;
  default_agent_id: string;
  labels: Record<string, string>;
}

export function createDefaultSecurityEventContext(options: {
  default_session_id: string;
  default_agent_id?: string;
  agent_name?: string;
  agent_version: string;
  schema_version?: string;
  environment?: string;
  tenant_id?: string;
  policy_hash?: string;
  ruleset?: string;
  labels?: Record<string, string>;
}): SecurityEventContext {
  return {
    schema_version: options.schema_version ?? "1.0.0",
    environment: options.environment,
    tenant_id: options.tenant_id,
    agent_name: options.agent_name,
    agent_version: options.agent_version,
    policy_hash: options.policy_hash,
    ruleset: options.ruleset,
    default_session_id: options.default_session_id,
    default_agent_id: options.default_agent_id ?? "clawdstrike",
    labels: options.labels ?? {},
  };
}

export class SecurityEventValidationError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.field = field;
  }
}

export function validateSecurityEvent(event: SecurityEvent): void {
  if (!event.schema_version.trim()) {
    throw new SecurityEventValidationError("schema_version", "missing schema_version");
  }
  if (!event.event_id.trim()) {
    throw new SecurityEventValidationError("event_id", "missing event_id");
  }
  if (!event.action.trim()) {
    throw new SecurityEventValidationError("action", "missing action");
  }
  if (!event.agent?.id?.trim()) {
    throw new SecurityEventValidationError("agent.id", "missing agent.id");
  }
  if (!event.session?.id?.trim()) {
    throw new SecurityEventValidationError("session.id", "missing session.id");
  }
  if (!event.resource?.name?.trim()) {
    throw new SecurityEventValidationError("resource.name", "missing resource.name");
  }
}

export interface AuditEventLike {
  id: string;
  type: string;
  timestamp: Date | string;
  sessionId?: string;
  decision?: {
    allowed: boolean;
    denied: boolean;
    warn: boolean;
    reason?: string;
    guard?: string;
    severity?: "low" | "medium" | "high" | "critical";
    message?: string;
  };
  toolName?: string;
  details?: Record<string, unknown>;
}

export function securityEventFromAuditEvent(audit: AuditEventLike, ctx: SecurityEventContext): SecurityEvent {
  const timestamp = typeof audit.timestamp === "string" ? audit.timestamp : audit.timestamp.toISOString();

  const decisionAllowed = audit.decision?.allowed ?? true;
  const decisionWarn = audit.decision?.warn ?? false;
  const decisionDenied = audit.decision?.denied ?? false;

  const severity: SecuritySeverity = decisionDenied
    ? mapDecisionSeverity(audit.decision?.severity) ?? "high"
    : decisionWarn
      ? "medium"
      : "info";

  const guard = audit.decision?.guard ?? "engine";
  const reason = audit.decision?.reason ?? audit.decision?.message ?? audit.type;

  const event_type = mapAuditTypeToEventType(audit.type, decisionAllowed, decisionWarn);
  const { event_category, resource } = mapAuditTypeToCategoryAndResource(audit);

  const outcome: Outcome = decisionDenied ? "failure" : decisionAllowed ? "success" : "unknown";

  const agentId = ctx.default_agent_id;
  const agentName = ctx.agent_name ?? agentId;

  return {
    schema_version: ctx.schema_version,
    event_id: isUuidLike(audit.id) ? audit.id : uuidv7(),
    event_type,
    event_category,
    timestamp,
    ingested_at: undefined,
    agent: {
      id: agentId,
      name: agentName,
      version: ctx.agent_version,
      type: "clawdstrike",
    },
    session: {
      id: audit.sessionId ?? ctx.default_session_id,
      tenant_id: ctx.tenant_id,
      environment: ctx.environment,
    },
    outcome,
    action: audit.type,
    threat: {},
    decision: {
      allowed: decisionAllowed,
      guard,
      severity,
      reason,
      policy_hash: ctx.policy_hash,
      ruleset: ctx.ruleset,
    },
    resource,
    metadata: audit.details ?? {},
    labels: ctx.labels,
  };
}

type AuditDecisionSeverity = "low" | "medium" | "high" | "critical" | undefined;

function mapDecisionSeverity(s: AuditDecisionSeverity): SecuritySeverity | null {
  switch (s) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return null;
  }
}

function mapAuditTypeToEventType(type: string, allowed: boolean, warned: boolean): SecurityEventType {
  if (type === "session_start") {
    return "session_start";
  }
  if (type === "session_end") {
    return "session_end";
  }

  if (type.startsWith("prompt_security_") && !allowed) {
    return "policy_violation";
  }

  if (!allowed) {
    if (type === "prompt_security_output_sanitized" || type === "output_sanitized") {
      return "secret_detected";
    }
    if (type === "tool_call_blocked") {
      return "guard_block";
    }
    return "policy_violation";
  }

  if (warned) {
    return "guard_warn";
  }

  return "policy_allow";
}

function mapAuditTypeToCategoryAndResource(audit: AuditEventLike): {
  event_category: EventCategory;
  resource: ResourceInfo;
} {
  if (audit.type === "session_start" || audit.type === "session_end") {
    return {
      event_category: "session",
      resource: { type: "configuration", name: "session" },
    };
  }

  if (audit.type.startsWith("tool_call_")) {
    return {
      event_category: "tool",
      resource: { type: "tool", name: audit.toolName ?? "unknown_tool" },
    };
  }

  return {
    event_category: "configuration",
    resource: { type: "configuration", name: audit.type },
  };
}

function isUuidLike(value: string): boolean {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
    value
  );
}

export function uuidv7(): string {
  const time = BigInt(Date.now());
  const bytes = new Uint8Array(16);

  // 48-bit timestamp (big-endian)
  bytes[0] = Number((time >> 40n) & 0xffn);
  bytes[1] = Number((time >> 32n) & 0xffn);
  bytes[2] = Number((time >> 24n) & 0xffn);
  bytes[3] = Number((time >> 16n) & 0xffn);
  bytes[4] = Number((time >> 8n) & 0xffn);
  bytes[5] = Number(time & 0xffn);

  const r = randomBytes(10);
  bytes[6] = 0x70 | (r[0] & 0x0f);
  bytes[7] = r[1];
  bytes[8] = 0x80 | (r[2] & 0x3f);
  bytes[9] = r[3];
  bytes[10] = r[4];
  bytes[11] = r[5];
  bytes[12] = r[6];
  bytes[13] = r[7];
  bytes[14] = r[8];
  bytes[15] = r[9];

  return formatUuid(bytes);
}

function formatUuid(bytes: Uint8Array): string {
  const hex = [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
