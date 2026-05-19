/**
 * @clawdstrike/openclaw - Tool Guard Hook Handler
 *
 * Intercepts tool results and enforces security policy.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { inferEventTypeFromName } from "../../classification.js";
import { getSharedEngine, initializeEngine } from "../../engine-holder.js";
import type { PolicyEngine } from "../../policy/engine.js";
import type {
  ClawdstrikeConfig,
  Decision,
  HookEvent,
  HookHandler,
  ModernToolResultPersistEvent,
  OpenClawHookContext,
  PolicyEvent,
  ToolResultPersistEvent,
  ToolResultPersistHookResult,
} from "../../types.js";
import { checkAndConsumeApproval } from "../approval-state.js";
import { extractPath, normalizeApprovalResource } from "../approval-utils.js";
import { clearAllToolInvocations, takeToolInvocationParams } from "../tool-invocation-state.js";

// ── LRU Decision Cache ──────────────────────────────────────────────

interface CacheEntry {
  decision: Decision;
  expiresAt: number;
}

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_CACHE_MAX = 256;

function stableStringify(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null) return "null";

  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "number" || t === "boolean") return String(value);
  if (t === "bigint") return JSON.stringify(String(value));
  if (t === "undefined") return '"__undefined__"';
  if (t === "symbol") return JSON.stringify(String(value));
  if (t === "function") return '"__function__"';

  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v, seen)).join(",")}]`;
  }

  if (t !== "object") {
    return JSON.stringify(String(value));
  }

  if (seen.has(value as object)) {
    return '"__cycle__"';
  }
  seen.add(value as object);

  // Only stable-sort plain objects; for other objects (Date, Buffer, etc) defer to
  // JSON.stringify where possible.
  const tag = Object.prototype.toString.call(value);
  if (tag !== "[object Object]") {
    try {
      return JSON.stringify(value);
    } catch {
      return JSON.stringify(String(value));
    }
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const entries = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k], seen)}`);
  return `{${entries.join(",")}}`;
}

function shortSha256(value: unknown): string {
  const h = createHash("sha256");
  if (typeof value === "string") h.update(value);
  else h.update(stableStringify(value));
  return h.digest("hex").slice(0, 16);
}

function policyCacheKey(policy: unknown): string {
  const version =
    policy &&
    typeof policy === "object" &&
    "version" in policy &&
    typeof (policy as { version?: unknown }).version === "string"
      ? (policy as { version: string }).version
      : "unknown";

  return `${version}@${shortSha256(policy)}`;
}

/** Event types that must never be cached (destructive / non-idempotent). */
const UNCACHEABLE_EVENT_TYPES = new Set(["command_exec", "patch_apply", "file_write"]);

export class DecisionCache {
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly map = new Map<string, CacheEntry>();

  constructor(maxSize = DEFAULT_CACHE_MAX, ttlMs = DEFAULT_CACHE_TTL_MS) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  /** Build a cache key from event type + resource identifier + policy fingerprint. */
  static key(eventType: string, resource: string, policyKey: string): string {
    return `${eventType}:${resource}:${policyKey}`;
  }

  get(key: string): Decision | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    // Move to end (most-recently-used).
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.decision;
  }

  set(key: string, decision: Decision): void {
    // Evict oldest when at capacity.
    if (this.map.size >= this.maxSize) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    this.map.set(key, { decision, expiresAt: Date.now() + this.ttlMs });
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

// ── Module State ─────────────────────────────────────────────────────

let currentConfig: ClawdstrikeConfig = {};
let cachedPolicyKey = "unknown";

/** Shared decision cache (reset on initialize) */
export let decisionCache = new DecisionCache();

/**
 * Initialize the hook with configuration.
 * Delegates to the shared engine holder so all hooks share one PolicyEngine.
 */
export function initialize(config: ClawdstrikeConfig): void {
  const engine = initializeEngine(config);
  currentConfig = config;
  decisionCache = new DecisionCache();
  clearAllToolInvocations();
  cachedPolicyKey = policyCacheKey(engine.getPolicy());
}

/**
 * Get or create the policy engine.
 * Delegates to the shared engine holder.
 */
function getEngine(config?: ClawdstrikeConfig): PolicyEngine {
  const engine = getSharedEngine(config);
  const nextPolicyKey = policyCacheKey(engine.getPolicy());
  if (cachedPolicyKey !== nextPolicyKey) {
    // Policy changed (or first access): invalidate cached allow decisions to avoid stale bypasses.
    decisionCache.clear();
    cachedPolicyKey = nextPolicyKey;
  }
  return engine;
}

/**
 * Extract a stable resource identifier from a policy event for cache keying.
 */
function extractResourceKey(event: PolicyEvent): string {
  switch (event.data.type) {
    case "file":
      return event.data.path;
    case "network":
      return event.data.host + ":" + event.data.port;
    case "tool":
      // Tool-call decisions depend on parameters and outputs (e.g., secret leak checks).
      // Include both so cached allows cannot be reused for a different invocation.
      return `${event.data.toolName}:${shortSha256(event.data.parameters)}:${shortSha256(event.data.result ?? "")}`;
    case "command":
      return event.data.command + " " + event.data.args.join(" ");
    case "patch":
      return event.data.filePath;
    case "secret":
      return event.data.secretName;
    default:
      return "";
  }
}

function sanitizeUnknown(
  value: unknown,
  sanitizeString: (s: string) => string,
  seen: WeakSet<object>,
  depth: number,
): { value: unknown; changed: boolean } {
  if (typeof value === "string") {
    const sanitized = sanitizeString(value);
    return { value: sanitized, changed: sanitized !== value };
  }

  if (!value || typeof value !== "object") {
    return { value, changed: false };
  }

  if (seen.has(value)) {
    return { value, changed: false };
  }

  if (depth > 32) {
    return { value, changed: false };
  }

  const isArray = Array.isArray(value);
  const isPlainObject = Object.prototype.toString.call(value) === "[object Object]";
  if (!isArray && !isPlainObject) {
    return { value, changed: false };
  }

  seen.add(value);

  if (isArray) {
    let changed = false;
    const out = (value as unknown[]).map((item) => {
      const result = sanitizeUnknown(item, sanitizeString, seen, depth + 1);
      changed = changed || result.changed;
      return result.value;
    });
    return { value: changed ? out : value, changed };
  }

  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  let changed = false;
  for (const [key, entry] of Object.entries(obj)) {
    const result = sanitizeUnknown(entry, sanitizeString, seen, depth + 1);
    out[key] = result.value;
    changed = changed || result.changed;
  }
  return { value: changed ? out : value, changed };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function asNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function isLegacyToolResultEvent(
  event: HookEvent | ModernToolResultPersistEvent,
): event is ToolResultPersistEvent {
  return (
    typeof event === "object" &&
    event !== null &&
    "type" in event &&
    (event as { type?: unknown }).type === "tool_result_persist"
  );
}

function isModernToolResultPersistEvent(
  event: HookEvent | ModernToolResultPersistEvent,
): event is ModernToolResultPersistEvent {
  return typeof event === "object" && event !== null && !("type" in event) && "message" in event;
}

function extractTextContent(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (!Array.isArray(value)) {
    return undefined;
  }

  const textParts = value
    .map((entry) => {
      const record = asRecord(entry);
      return typeof record?.text === "string" ? record.text : undefined;
    })
    .filter((entry): entry is string => typeof entry === "string" && entry.length > 0);

  return textParts.length > 0 ? textParts.join("\n\n") : undefined;
}

function extractModernToolParams(message: Record<string, unknown>): Record<string, unknown> {
  const details = asRecord(message.details);
  const candidates = [details?.params, details?.input, details?.arguments, details];

  for (const candidate of candidates) {
    const record = asRecord(candidate);
    if (record) {
      return { ...record };
    }
  }

  return {};
}

function extractModernToolResult(message: unknown): unknown {
  if (typeof message === "string") {
    return message;
  }

  const record = asRecord(message);
  if (!record) {
    return message;
  }

  if ("result" in record) {
    return record.result;
  }
  if ("output" in record) {
    return record.output;
  }

  const details = asRecord(record.details);
  if (details && "result" in details) {
    return details.result;
  }
  if (details && "output" in details) {
    return details.output;
  }

  const contentText = extractTextContent(record.content);
  if (contentText !== undefined) {
    return contentText;
  }
  if (typeof record.text === "string") {
    return record.text;
  }

  return message;
}

function mergeToolParams(
  explicitParams: Record<string, unknown>,
  rememberedParams: Record<string, unknown> | null,
): Record<string, unknown> {
  if (!rememberedParams) {
    return explicitParams;
  }

  return {
    ...rememberedParams,
    ...explicitParams,
  };
}

function sanitizeModernToolMessage(
  message: unknown,
  sanitizeString: (value: string) => string,
): { message: unknown; changed: boolean } {
  if (typeof message === "string") {
    const sanitized = sanitizeString(message);
    return { message: sanitized, changed: sanitized !== message };
  }

  const record = asRecord(message);
  if (!record) {
    return { message, changed: false };
  }

  const next: Record<string, unknown> = { ...record };
  let changed = false;

  if (typeof record.content === "string") {
    const sanitized = sanitizeString(record.content);
    if (sanitized !== record.content) {
      next.content = sanitized;
      changed = true;
    }
  } else if (Array.isArray(record.content)) {
    let contentChanged = false;
    const nextContent = record.content.map((entry) => {
      const item = asRecord(entry);
      if (!item || typeof item.text !== "string") {
        return entry;
      }
      const sanitized = sanitizeString(item.text);
      if (sanitized === item.text) {
        return entry;
      }
      contentChanged = true;
      return { ...item, text: sanitized };
    });
    if (contentChanged) {
      next.content = nextContent;
      changed = true;
    }
  }

  if (typeof record.text === "string") {
    const sanitized = sanitizeString(record.text);
    if (sanitized !== record.text) {
      next.text = sanitized;
      changed = true;
    }
  }

  if (typeof record.result === "string") {
    const sanitized = sanitizeString(record.result);
    if (sanitized !== record.result) {
      next.result = sanitized;
      changed = true;
    }
  } else if (record.result && typeof record.result === "object") {
    const sanitized = sanitizeUnknown(record.result, sanitizeString, new WeakSet<object>(), 0);
    if (sanitized.changed) {
      next.result = sanitized.value;
      changed = true;
    }
  }

  if (typeof record.output === "string") {
    const sanitized = sanitizeString(record.output);
    if (sanitized !== record.output) {
      next.output = sanitized;
      changed = true;
    }
  }

  if (typeof record.details === "string") {
    const sanitized = sanitizeString(record.details);
    if (sanitized !== record.details) {
      next.details = sanitized;
      changed = true;
    }
  } else if (record.details && typeof record.details === "object") {
    const sanitized = sanitizeUnknown(record.details, sanitizeString, new WeakSet<object>(), 0);
    if (sanitized.changed) {
      next.details = sanitized.value;
      changed = true;
    }
  }

  return { message: changed ? next : message, changed };
}

function buildBlockedToolResultMessage(
  message: unknown,
  toolName: string,
  guard: string | undefined,
  reason: string,
): unknown {
  const blockedText = `[clawdstrike] Blocked by ${guard ?? "policy"}: ${reason}`;
  const base = asRecord(message);
  const next: Record<string, unknown> = base ? { ...base } : {};

  next.role = typeof next.role === "string" ? next.role : "toolResult";
  next.toolName = asNonEmptyString(next.toolName) ?? toolName;
  next.isError = true;
  next.content = [{ type: "text", text: blockedText }];
  next.text = blockedText;
  if ("result" in next) {
    next.result = blockedText;
  }
  if ("output" in next) {
    next.output = blockedText;
  }
  if ("details" in next) {
    delete next.details;
  }

  return next;
}

function annotateWarningOnToolResultMessage(message: unknown, warning: string): unknown {
  const base = asRecord(message);
  if (!base) {
    return message;
  }

  const details = asRecord(base.details);
  return {
    ...base,
    details: {
      ...(details ?? {}),
      clawdstrikeWarning: warning,
    },
  };
}

type NormalizedToolPersistEvent = {
  sessionId: string;
  toolName: string;
  toolCallId?: string;
  hostId?: string;
  userId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  params: Record<string, unknown>;
  result: unknown;
  deny: (decision: Decision) => void;
  warn: (decision: Decision) => void;
  sanitize: (policyEngine: PolicyEngine) => void;
  flush: () => ToolResultPersistHookResult | void;
};

function normalizeToolResultEvent(
  event: HookEvent | ModernToolResultPersistEvent,
  hookCtx?: OpenClawHookContext,
): NormalizedToolPersistEvent | null {
  if (isLegacyToolResultEvent(event)) {
    const sessionId =
      event.context.sessionId || hookCtx?.sessionKey || hookCtx?.agentId || "openclaw-runtime";
    const toolResult = event.context.toolResult;

    return {
      sessionId,
      toolName: toolResult.toolName,
      toolCallId: hookCtx?.toolCallId,
      hostId: toolResultTelemetryString(
        hookCtx?.hostId,
        process.env.CLAWDSTRIKE_HOST_ID,
        process.env.CLAWDSTRIKE_ENDPOINT_ID,
      ),
      userId: toolResultTelemetryString(
        hookCtx?.userId,
        process.env.CLAWDSTRIKE_USER_ID,
        process.env.CLAWDSTRIKE_PRINCIPAL_ID,
      ),
      agentId: toolResultTelemetryString(hookCtx?.agentId, process.env.CLAWDSTRIKE_AGENT_ID),
      workloadId: toolResultTelemetryString(
        hookCtx?.workloadId,
        process.env.CLAWDSTRIKE_WORKLOAD_ID,
      ),
      approvalId: toolResultTelemetryString(
        hookCtx?.approvalId,
        process.env.CLAWDSTRIKE_APPROVAL_ID,
      ),
      params: toolResult.params,
      result: toolResult.result,
      deny(decision) {
        toolResult.error = decision.reason ?? "Policy violation";
        event.messages.push(
          `[clawdstrike] Blocked by ${decision.guard ?? "policy"}: ${decision.reason ?? "Policy violation"}`,
        );
      },
      warn(decision) {
        event.messages.push(`[clawdstrike] Warning: ${decision.message ?? decision.reason}`);
      },
      sanitize(policyEngine) {
        const result = toolResult.result;
        if (typeof result === "string") {
          const sanitized = policyEngine.sanitizeOutput(result);
          if (sanitized !== result) {
            toolResult.result = sanitized;
          }
          return;
        }
        if (result && typeof result === "object") {
          const sanitized = sanitizeUnknown(
            result,
            (value) => policyEngine.sanitizeOutput(value),
            new WeakSet<object>(),
            0,
          );
          if (sanitized.changed) {
            toolResult.result = sanitized.value;
          }
        }
      },
      flush() {
        return;
      },
    };
  }

  if (!isModernToolResultPersistEvent(event)) {
    return null;
  }

  let currentMessage = event.message;
  let changed = false;
  const messageRecord = asRecord(currentMessage);
  const toolName =
    asNonEmptyString(event.toolName) ??
    asNonEmptyString(hookCtx?.toolName) ??
    asNonEmptyString(messageRecord?.toolName) ??
    "unknown";
  const sessionId =
    asNonEmptyString((event as { sessionId?: unknown }).sessionId) ??
    hookCtx?.sessionKey ??
    hookCtx?.agentId ??
    "openclaw-runtime";
  const toolCallId = asNonEmptyString(event.toolCallId) ?? hookCtx?.toolCallId;
  const explicitParams = messageRecord ? extractModernToolParams(messageRecord) : {};
  const rememberedParams = takeToolInvocationParams(sessionId, toolName, toolCallId);

  return {
    sessionId,
    toolName,
    toolCallId,
    hostId: toolResultTelemetryString(
      hookCtx?.hostId,
      process.env.CLAWDSTRIKE_HOST_ID,
      process.env.CLAWDSTRIKE_ENDPOINT_ID,
    ),
    userId: toolResultTelemetryString(
      hookCtx?.userId,
      process.env.CLAWDSTRIKE_USER_ID,
      process.env.CLAWDSTRIKE_PRINCIPAL_ID,
    ),
    agentId: toolResultTelemetryString(hookCtx?.agentId, process.env.CLAWDSTRIKE_AGENT_ID),
    workloadId: toolResultTelemetryString(hookCtx?.workloadId, process.env.CLAWDSTRIKE_WORKLOAD_ID),
    approvalId: toolResultTelemetryString(hookCtx?.approvalId, process.env.CLAWDSTRIKE_APPROVAL_ID),
    params: mergeToolParams(explicitParams, rememberedParams),
    result: extractModernToolResult(currentMessage),
    deny(decision) {
      currentMessage = buildBlockedToolResultMessage(
        currentMessage,
        toolName,
        decision.guard,
        decision.reason ?? "Policy violation",
      );
      changed = true;
    },
    warn(decision) {
      const warning = `[clawdstrike] Warning: ${decision.message ?? decision.reason ?? "Policy warning"}`;
      const nextMessage = annotateWarningOnToolResultMessage(currentMessage, warning);
      if (nextMessage !== currentMessage) {
        currentMessage = nextMessage;
        changed = true;
      }
    },
    sanitize(policyEngine) {
      const sanitized = sanitizeModernToolMessage(currentMessage, (value) =>
        policyEngine.sanitizeOutput(value),
      );
      if (sanitized.changed) {
        currentMessage = sanitized.message;
        changed = true;
      }
    },
    flush() {
      return changed ? { message: currentMessage } : undefined;
    },
  };
}

function maybeRunAsyncFollowUp(
  policyEngine: PolicyEngine,
  policyEvent: PolicyEvent,
  toolName: string,
): void {
  if (!policyEngine.hasAsyncGuards()) {
    return;
  }

  void policyEngine
    .evaluateAsyncGuards(policyEvent)
    .then((decision) => {
      if (decision.status === "allow") {
        return;
      }

      const detail = decision.message ?? decision.reason ?? "policy follow-up violation";
      console.warn(
        `[clawdstrike] Async post-persist guard for ${toolName} returned ${decision.status}: ${detail}`,
      );
    })
    .catch((error: unknown) => {
      const detail = error instanceof Error ? error.message : String(error);
      console.warn(`[clawdstrike] Async post-persist evaluation failed for ${toolName}: ${detail}`);
    });
}

/**
 * Hook handler for tool_result_persist events
 */
const handler: HookHandler = (
  event: HookEvent | ModernToolResultPersistEvent,
  hookCtx?: OpenClawHookContext,
): ToolResultPersistHookResult | void => {
  const toolEvent = normalizeToolResultEvent(event, hookCtx);
  if (!toolEvent) {
    return;
  }

  const { sessionId, toolName, toolCallId, agentId, params, result } = toolEvent;
  const policyEngine = getEngine();

  // Check if preflight already approved this action — skip policy evaluation
  // but still run output sanitization below.
  const resource = normalizeApprovalResource(policyEngine, toolName, params);
  const priorApproval = checkAndConsumeApproval(sessionId, toolName, resource);
  const policyEvent = createPolicyEvent(sessionId, toolName, params, result);
  const telemetryIdentity = {
    hostId: toolEvent.hostId,
    userId: toolEvent.userId,
    sessionId,
    agentId,
    workloadId: toolEvent.workloadId ?? "openclaw-tool-result",
    approvalId: toolEvent.approvalId,
    toolCallId,
  };
  let telemetryDecision: Decision = {
    status: "allow",
    guard: priorApproval ? "approval" : undefined,
    reason: priorApproval ? `prior ${priorApproval} approval` : undefined,
  };

  if (!priorApproval) {
    // Check decision cache (skip for destructive ops and advisory/audit modes)
    const mode = currentConfig.mode ?? "deterministic";
    const useCache =
      mode === "deterministic" && !UNCACHEABLE_EVENT_TYPES.has(policyEvent.eventType);
    const cacheKey = useCache
      ? DecisionCache.key(policyEvent.eventType, extractResourceKey(policyEvent), cachedPolicyKey)
      : "";

    let decision = useCache ? decisionCache.get(cacheKey) : undefined;
    if (!decision) {
      decision = policyEngine.evaluateSync(policyEvent);
      if (useCache && decision.status === "allow") {
        decisionCache.set(cacheKey, decision);
      }
    }
    telemetryDecision = decision;

    if (decision.status === "deny") {
      publishToolResultTelemetry(
        policyEvent,
        toolName,
        params,
        result,
        decision,
        telemetryIdentity,
        false,
      );
      toolEvent.deny(decision);
      return toolEvent.flush();
    }

    if (decision.status === "warn") {
      toolEvent.warn(decision);
    }

    if (decision.status === "allow") {
      maybeRunAsyncFollowUp(policyEngine, policyEvent, toolName);
    }
  }

  publishToolResultTelemetry(
    policyEvent,
    toolName,
    params,
    result,
    telemetryDecision,
    telemetryIdentity,
    Boolean(priorApproval),
  );
  toolEvent.sanitize(policyEngine);
  return toolEvent.flush();
};

type EdrDeveloperActivity = Record<string, unknown>;

type ToolResultTelemetryIdentity = {
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  toolCallId?: string;
};

function toolResultTelemetryString(...values: unknown[]): string | undefined {
  for (const value of values) {
    const trimmed = asNonEmptyString(value);
    if (trimmed) return trimmed;
  }
  return undefined;
}

type CredentialActivityCandidate = {
  kind: "repo_secret" | "ci_token" | "local_api_key" | "browser_cookie";
  path?: string;
  name?: string;
  credentialKind?: string;
  classifier: string;
};

const MAX_TOOL_RESULT_DEVELOPER_ACTIVITIES = 16;
const RESULT_STRING_SCAN_LIMIT = 512_000;
const REDACTED = "[REDACTED]";
const SECRET_LIKE_VALUE =
  /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

function publishToolResultTelemetry(
  policyEvent: PolicyEvent,
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
  decision: Decision,
  identity: ToolResultTelemetryIdentity,
  priorApproval: boolean,
): void {
  void publishToolResultPolicyEvent(
    buildToolResultPolicyEventForEdr(policyEvent, toolName, decision, identity, priorApproval),
  );

  const activities = buildToolResultDeveloperActivitiesForEdr(
    policyEvent,
    toolName,
    params,
    result,
    decision,
    identity,
    priorApproval,
  );
  if (activities.length > 0) {
    void publishToolResultDeveloperActivities(activities);
  }
}

export function buildToolResultPolicyEventForEdr(
  policyEvent: PolicyEvent,
  toolName: string,
  decision: Decision,
  identity: ToolResultTelemetryIdentity = {},
  priorApproval = false,
): PolicyEvent {
  const scrubbed = scrubPolicyEventDataForEdr(policyEvent.data);

  return {
    ...policyEvent,
    data: scrubbed.data,
    metadata: {
      ...(policyEvent.metadata ?? {}),
      ...scrubbed.metadata,
      collectorKind: "openclaw_tool_result",
      toolName,
      postExecution: true,
      policyAllowed: decision.status !== "deny",
      policyStatus: decision.status,
      policyGuard: decision.guard,
      policySeverity: decision.severity,
      policyReason: decision.reason,
      hostId: identity.hostId,
      userId: identity.userId,
      sessionId: identity.sessionId ?? policyEvent.sessionId,
      agentId: identity.agentId,
      workloadId: identity.workloadId ?? "openclaw-tool-result",
      approvalId: identity.approvalId,
      toolCallId: identity.toolCallId,
      priorApproval,
    },
  };
}

export function buildToolResultDeveloperActivitiesForEdr(
  policyEvent: PolicyEvent,
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
  decision: Decision,
  identity: ToolResultTelemetryIdentity = {},
  priorApproval = false,
): EdrDeveloperActivity[] {
  const activities: EdrDeveloperActivity[] = [];
  const metadata = toolResultTelemetryMetadata(toolName, result, decision, identity, priorApproval);
  const common = {
    observedAt: policyEvent.timestamp,
    hostId: identity.hostId,
    userId: identity.userId,
    sessionId: policyEvent.sessionId,
    agentId: identity.agentId,
    workloadId: identity.workloadId ?? "openclaw-tool-result",
    approvalId: identity.approvalId,
  };

  const download = findDownloadActivityCandidate(toolName, params, result);
  if (download) {
    activities.push({
      ...common,
      activityId: `${policyEvent.eventId}:download:${sha256Hex(download.path).slice(0, 16)}`,
      kind: "browser_download",
      browser: download.browser,
      path: download.path,
      sourceUrl: download.sourceUrl ? redactTelemetryUrl(download.sourceUrl) : undefined,
      metadata: {
        ...metadata,
        activityClassifier: "browser_download",
      },
    });
  }

  const browserExtension = findBrowserExtensionActivityCandidate(toolName, params, result);
  if (browserExtension) {
    activities.push({
      ...common,
      activityId: `${policyEvent.eventId}:browser-extension:${sha256Hex(browserExtension.path).slice(0, 16)}`,
      kind: "browser_extension",
      browser: browserExtension.browser,
      extensionId: browserExtension.extensionId,
      path: browserExtension.path,
      source: browserExtension.source ? redactTelemetryUrl(browserExtension.source) : undefined,
      metadata: {
        ...metadata,
        activityClassifier: "browser_extension",
      },
    });
  }

  const credentialCandidates = collectCredentialActivityCandidates(params, result);
  const seenCredentials = new Set<string>();
  for (const candidate of credentialCandidates) {
    const key = `${candidate.kind}\0${candidate.path ?? ""}\0${candidate.name ?? ""}`;
    if (seenCredentials.has(key)) continue;
    seenCredentials.add(key);

    activities.push({
      ...common,
      activityId: `${policyEvent.eventId}:credential:${sha256Hex(key).slice(0, 16)}`,
      kind: candidate.kind,
      path: candidate.path,
      name: candidate.name,
      credentialKind: candidate.credentialKind,
      metadata: {
        ...metadata,
        activityClassifier: candidate.classifier,
        rawSecretOmitted: true,
      },
    });

    if (activities.length >= MAX_TOOL_RESULT_DEVELOPER_ACTIVITIES) {
      return activities;
    }
  }

  const secretOutputNames = detectStrongSecretOutputNames(result, decision);
  for (const name of secretOutputNames) {
    const key = `local_api_key\0\0${name}`;
    if (seenCredentials.has(key)) continue;
    seenCredentials.add(key);

    activities.push({
      ...common,
      activityId: `${policyEvent.eventId}:secret-output:${sha256Hex(key).slice(0, 16)}`,
      kind: "local_api_key",
      name,
      credentialKind: credentialKindForSecretName(name),
      metadata: {
        ...metadata,
        activityClassifier: "secret_output",
        rawSecretOmitted: true,
      },
    });

    if (activities.length >= MAX_TOOL_RESULT_DEVELOPER_ACTIVITIES) {
      return activities;
    }
  }

  return activities;
}

function scrubPolicyEventDataForEdr(data: PolicyEvent["data"]): {
  data: PolicyEvent["data"];
  metadata: Record<string, unknown>;
} {
  if (data.type === "tool") {
    const result = typeof data.result === "string" ? data.result : undefined;
    if (!result) {
      return { data, metadata: {} };
    }
    return {
      data: {
        ...data,
        result: `[omitted by openclaw_tool_result sha256:${sha256Hex(result)}]`,
      },
      metadata: {
        resultOmitted: true,
        resultHash: sha256Hex(result),
        resultSizeBytes: Buffer.byteLength(result, "utf8"),
      },
    };
  }

  if (data.type === "file") {
    const content = data.content ?? data.contentBase64;
    if (!content) {
      return { data, metadata: {} };
    }
    return {
      data: {
        ...data,
        content: undefined,
        contentBase64: undefined,
        contentHash: data.contentHash ?? sha256Hex(content),
      },
      metadata: {
        artifactContentOmitted: true,
        artifactContentHash: sha256Hex(content),
        artifactContentEncoding: data.contentBase64 ? "base64" : "utf8",
        artifactContentSizeBytes: Buffer.byteLength(content, "utf8"),
      },
    };
  }

  if (data.type === "patch" && data.patchContent) {
    return {
      data: {
        ...data,
        patchContent: `[omitted by openclaw_tool_result sha256:${sha256Hex(data.patchContent)}]`,
        patchHash: data.patchHash ?? sha256Hex(data.patchContent),
      },
      metadata: {
        patchContentOmitted: true,
        patchContentHash: sha256Hex(data.patchContent),
        patchContentSizeBytes: Buffer.byteLength(data.patchContent, "utf8"),
      },
    };
  }

  return { data, metadata: {} };
}

function toolResultTelemetryMetadata(
  toolName: string,
  result: unknown,
  decision: Decision,
  identity: ToolResultTelemetryIdentity,
  priorApproval: boolean,
): Record<string, unknown> {
  const resultEvidence = resultEvidenceMetadata(result);
  return {
    collectorKind: "openclaw_tool_result",
    toolName,
    postExecution: true,
    policyAllowed: decision.status !== "deny",
    policyStatus: decision.status,
    policyGuard: decision.guard,
    policySeverity: decision.severity,
    policyReason: decision.reason,
    agentId: identity.agentId,
    workloadId: identity.workloadId ?? "openclaw-tool-result",
    approvalId: identity.approvalId,
    toolCallId: identity.toolCallId,
    priorApproval,
    ...resultEvidence,
  };
}

function resultEvidenceMetadata(result: unknown): Record<string, unknown> {
  if (result === undefined) {
    return { resultKind: "undefined" };
  }

  const encoded = typeof result === "string" ? result : stableStringify(result);
  return {
    resultKind: Array.isArray(result) ? "array" : result === null ? "null" : typeof result,
    resultHash: sha256Hex(encoded),
    resultSizeBytes: Buffer.byteLength(encoded, "utf8"),
    resultOmitted: true,
  };
}

function redactSensitiveTelemetryString(value: string): string {
  if (SECRET_LIKE_VALUE.test(value)) return REDACTED;
  return value.replace(
    /((?:token|secret|password|passwd|api[_-]?key|authorization|cookie)=)[^\s&]+/gi,
    `$1${REDACTED}`,
  );
}

function redactTelemetryUrl(value: string): string {
  if (!value) return "";
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return redactSensitiveTelemetryString(value);
  }
}

function findDownloadActivityCandidate(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): { browser: string; path: string; sourceUrl?: string } | null {
  const hasDownloadSignal =
    /\b(download|browser|fetch|receive[_-]?file|get[_-]?file)\b/i.test(toolName) ||
    hasKeyRecursive(result, ["downloadPath", "download_path", "localPath", "local_path"]) ||
    hasKeyRecursive(params, ["downloadPath", "download_path", "localPath", "local_path"]);

  const strongPath =
    firstStringForKeys(result, [
      "downloadPath",
      "download_path",
      "localPath",
      "local_path",
      "saveAs",
      "save_as",
      "outputPath",
      "output_path",
      "destination",
    ]) ??
    firstStringForKeys(params, [
      "downloadPath",
      "download_path",
      "localPath",
      "local_path",
      "saveAs",
      "save_as",
      "outputPath",
      "output_path",
      "destination",
    ]);

  const genericPath = hasDownloadSignal
    ? (firstStringForKeys(result, ["path", "filePath", "file_path", "target"]) ??
      firstStringForKeys(params, ["path", "filePath", "file_path", "target"]))
    : undefined;
  const path = strongPath ?? genericPath;
  if (!path || !hasDownloadSignal) {
    return null;
  }

  const sourceUrl =
    firstStringForKeys(result, ["sourceUrl", "source_url", "remoteUrl", "remote_url", "url"]) ??
    firstStringForKeys(params, ["sourceUrl", "source_url", "remoteUrl", "remote_url", "url"]);

  return {
    browser: firstStringForKeys(params, ["browser", "browserName", "browser_name"]) ?? "openclaw",
    path,
    sourceUrl,
  };
}

function findBrowserExtensionActivityCandidate(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): { browser: string; path: string; extensionId?: string; source?: string } | null {
  const hasExtensionSignal =
    /\b(extension|addon|add-on|crx|xpi)\b/i.test(toolName) ||
    hasKeyRecursive(result, ["extensionId", "extension_id", "extensionPath", "extension_path"]) ||
    hasKeyRecursive(params, ["extensionId", "extension_id", "extensionPath", "extension_path"]);
  if (!hasExtensionSignal) {
    return null;
  }

  const path =
    firstStringForKeys(result, [
      "extensionPath",
      "extension_path",
      "installPath",
      "install_path",
      "path",
      "filePath",
      "file_path",
      "crxPath",
      "crx_path",
      "xpiPath",
      "xpi_path",
    ]) ??
    firstStringForKeys(params, [
      "extensionPath",
      "extension_path",
      "installPath",
      "install_path",
      "path",
      "filePath",
      "file_path",
      "crxPath",
      "crx_path",
      "xpiPath",
      "xpi_path",
    ]);
  if (!path) {
    return null;
  }

  return {
    browser: firstStringForKeys(params, ["browser", "browserName", "browser_name"]) ?? "openclaw",
    extensionId:
      firstStringForKeys(result, ["extensionId", "extension_id", "id"]) ??
      firstStringForKeys(params, ["extensionId", "extension_id", "id"]),
    path,
    source:
      firstStringForKeys(result, ["source", "sourceUrl", "source_url", "url"]) ??
      firstStringForKeys(params, ["source", "sourceUrl", "source_url", "url"]),
  };
}

function collectCredentialActivityCandidates(
  params: Record<string, unknown>,
  result: unknown,
): CredentialActivityCandidate[] {
  const candidates: CredentialActivityCandidate[] = [];
  const strings = collectStrings([params, result], 96);

  for (const value of strings) {
    const candidate = classifyCredentialString(value);
    if (candidate) {
      candidates.push(candidate);
    }
  }

  return candidates;
}

function classifyCredentialString(value: string): CredentialActivityCandidate | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 4096) {
    return null;
  }

  const urlCandidate = classifyCredentialUrl(trimmed);
  if (urlCandidate) {
    return urlCandidate;
  }

  const lower = trimmed.toLowerCase();
  const looksPath =
    /^(?:\/|~\/|\.{1,2}\/|[a-z]:\\)/i.test(trimmed) ||
    /^\.env(?:\.|$)/i.test(trimmed) ||
    /^(?:\.npmrc|\.pypirc|\.netrc)$/i.test(trimmed) ||
    (/[\\/]/.test(trimmed) &&
      /(secret|token|credential|cookie|\.env|\.npmrc|\.pypirc|id_rsa)/i.test(trimmed));
  if (!looksPath) {
    return null;
  }

  if (
    /(?:^|[\\/])(cookies(?:\.sqlite)?|login data)(?:$|[\\/])/i.test(trimmed) ||
    /[\\/]application support[\\/](google[\\/]chrome|chromium|brave|microsoft edge|firefox|safari)/i.test(
      lower,
    )
  ) {
    return {
      kind: "browser_cookie",
      path: trimmed,
      name: "browser_cookie_store",
      credentialKind: "browser_cookie",
      classifier: "browser_cookie_path",
    };
  }

  if (
    /[\\/]\.github[\\/]/i.test(trimmed) ||
    /[\\/](github-actions|gitlab-ci|circleci|buildkite|jenkins)[\\/]/i.test(lower) ||
    (/\bci\b/i.test(lower) && /(token|secret|credential)/i.test(lower))
  ) {
    return {
      kind: "ci_token",
      path: trimmed,
      name: credentialNameFromPath(trimmed, "ci_token"),
      credentialKind: "api_token",
      classifier: "ci_token_path",
    };
  }

  if (
    /(?:^|[\\/])(\.aws[\\/]credentials|\.azure|\.config[\\/]gcloud|application_default_credentials\.json|credentials\.json|token\.json|\.npmrc|\.pypirc|\.netrc)(?:$|[\\/])/i.test(
      trimmed,
    )
  ) {
    return {
      kind: "local_api_key",
      path: trimmed,
      name: credentialNameFromPath(trimmed, "local_api_key"),
      credentialKind: lower.includes(".npmrc") ? "package_registry_token" : "cloud_credential",
      classifier: "local_api_key_path",
    };
  }

  if (
    /(?:^|[\\/])\.env(?:\.|$)/i.test(trimmed) ||
    /(secret|credential|private[_-]?key|api[_-]?key|token|id_rsa)/i.test(lower)
  ) {
    return {
      kind: "repo_secret",
      path: trimmed,
      name: credentialNameFromPath(trimmed, "repo_secret"),
      credentialKind: /id_rsa|private[_-]?key/i.test(lower) ? "ssh_key" : "api_token",
      classifier: "repo_secret_path",
    };
  }

  return null;
}

function classifyCredentialUrl(value: string): CredentialActivityCandidate | null {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    return null;
  }
  try {
    const parsed = new URL(value);
    const sensitive =
      Boolean(parsed.username || parsed.password) ||
      [...parsed.searchParams.keys()].some((key) =>
        /(?:secret|token|password|passwd|credential|api[_-]?key|authorization|cookie)/i.test(key),
      ) ||
      SECRET_LIKE_VALUE.test(value);
    if (!sensitive) {
      return null;
    }
    return {
      kind: "local_api_key",
      path: redactTelemetryUrl(value),
      name: "url_credential",
      credentialKind: "api_token",
      classifier: "url_secret",
    };
  } catch {
    return null;
  }
}

function credentialNameFromPath(path: string, fallback: string): string {
  const name = basename(path.replace(/[/\\]+$/, ""));
  return name && name !== "." && name !== "/" ? name : fallback;
}

function detectStrongSecretOutputNames(result: unknown, decision: Decision): string[] {
  const names = new Set<string>();
  if (decision.guard === "secret_leak") {
    for (const name of String(decision.reason ?? decision.message ?? "")
      .split(/[^A-Za-z0-9_-]+/)
      .filter(Boolean)) {
      if (
        /^(?:aws|github|openai|anthropic|google|gcp|private|stripe|slack|azure|gitlab|jwt|database)/i.test(
          name,
        )
      ) {
        names.add(name.toLowerCase());
      }
    }
    if (names.size === 0) {
      names.add("tool_result_secret");
    }
  }

  const text = resultTextForSecretScan(result);
  if (!text) {
    return [...names];
  }

  const patterns: Array<[string, RegExp]> = [
    ["github_token", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/],
    ["github_fine_grained_token", /\bgithub_pat_[A-Za-z0-9_]{20,}\b/],
    ["openai_api_key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/],
    ["anthropic_api_key", /\bsk-ant-[A-Za-z0-9_-]{32,}\b/],
    ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
    ["private_key", /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/],
    ["stripe_secret_key", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/],
    ["slack_token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
    ["gitlab_token", /\bglpat-[A-Za-z0-9_-]{20,}\b/],
    ["jwt_token", /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/],
    ["database_url", /\b(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@/],
  ];
  for (const [name, pattern] of patterns) {
    if (pattern.test(text)) {
      names.add(name);
    }
  }
  return [...names];
}

function credentialKindForSecretName(name: string): string {
  if (/aws|gcp|google|azure|database/i.test(name)) return "cloud_credential";
  if (/npm|pypi|registry/i.test(name)) return "package_registry_token";
  if (/private_key|ssh/i.test(name)) return "ssh_key";
  if (/cookie/i.test(name)) return "browser_cookie";
  return "api_token";
}

function resultTextForSecretScan(result: unknown): string | null {
  if (typeof result === "string") {
    return result.slice(0, RESULT_STRING_SCAN_LIMIT);
  }
  if (!result || typeof result !== "object") {
    return null;
  }
  return stableStringify(result).slice(0, RESULT_STRING_SCAN_LIMIT);
}

function collectStrings(value: unknown, limit: number, out: string[] = [], depth = 0): string[] {
  if (out.length >= limit || depth > 8) {
    return out;
  }
  if (typeof value === "string") {
    out.push(value);
    return out;
  }
  if (!value || typeof value !== "object") {
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, limit, out, depth + 1);
      if (out.length >= limit) break;
    }
    return out;
  }
  for (const entry of Object.values(value as Record<string, unknown>)) {
    collectStrings(entry, limit, out, depth + 1);
    if (out.length >= limit) break;
  }
  return out;
}

function firstStringForKeys(value: unknown, keys: string[], depth = 0): string | undefined {
  if (depth > 6 || !value || typeof value !== "object") {
    return undefined;
  }
  const wanted = new Set(keys.map((key) => key.toLowerCase()));
  const record = Array.isArray(value) ? null : (value as Record<string, unknown>);
  if (record) {
    for (const [key, entry] of Object.entries(record)) {
      if (wanted.has(key.toLowerCase()) && typeof entry === "string" && entry.trim()) {
        return entry.trim();
      }
    }
    for (const entry of Object.values(record)) {
      const nested = firstStringForKeys(entry, keys, depth + 1);
      if (nested) return nested;
    }
    return undefined;
  }
  for (const entry of value as unknown[]) {
    const nested = firstStringForKeys(entry, keys, depth + 1);
    if (nested) return nested;
  }
  return undefined;
}

function hasKeyRecursive(value: unknown, keys: string[], depth = 0): boolean {
  if (depth > 6 || !value || typeof value !== "object") {
    return false;
  }
  const wanted = new Set(keys.map((key) => key.toLowerCase()));
  if (Array.isArray(value)) {
    return value.some((entry) => hasKeyRecursive(entry, keys, depth + 1));
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => wanted.has(key.toLowerCase()))) {
    return true;
  }
  return Object.values(record).some((entry) => hasKeyRecursive(entry, keys, depth + 1));
}

async function publishToolResultDeveloperActivities(
  activities: EdrDeveloperActivity[],
): Promise<void> {
  const endpoint = resolveDeveloperActivityEndpoint();
  if (!endpoint) return;

  try {
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(250),
      body: JSON.stringify({ activities }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // Tool-result telemetry is enrichment only. Synchronous post-result
    // enforcement above remains the authoritative block/redact path.
  }
}

async function publishToolResultPolicyEvent(policyEvent: PolicyEvent): Promise<void> {
  const endpoint = resolvePolicyEventsEndpoint();
  if (!endpoint) return;

  try {
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(250),
      body: JSON.stringify({ events: [policyEvent] }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // EDR capture is evidence enrichment only. The tool-result guard still
    // returns its synchronous policy decision and sanitization result.
  }
}

function resolveDeveloperActivityEndpoint(): { url: string; token: string } | null {
  const token = localAgentToken();
  if (!token) return null;

  const explicitUrl = process.env.CLAWDSTRIKE_DEVELOPER_ACTIVITY_URL?.trim();
  if (explicitUrl) {
    return { url: explicitUrl, token };
  }

  const baseUrl =
    process.env.CLAWDSTRIKE_AGENT_URL?.trim() ??
    process.env.CLAWDSTRIKE_APPROVAL_URL?.trim() ??
    "http://127.0.0.1:9878";
  return {
    url: `${baseUrl.replace(/\/+$/, "")}/api/v1/agent/edr/developer-activity`,
    token,
  };
}

function resolvePolicyEventsEndpoint(): { url: string; token: string } | null {
  const token = localAgentToken();
  if (!token) return null;

  const explicitUrl = process.env.CLAWDSTRIKE_POLICY_EVENTS_URL?.trim();
  if (explicitUrl) {
    return { url: explicitUrl, token };
  }

  const baseUrl =
    process.env.CLAWDSTRIKE_AGENT_URL?.trim() ??
    process.env.CLAWDSTRIKE_APPROVAL_URL?.trim() ??
    "http://127.0.0.1:9878";
  return {
    url: `${baseUrl.replace(/\/+$/, "")}/api/v1/agent/edr/policy-events`,
    token,
  };
}

function localAgentToken(): string | null {
  const envToken = process.env.CLAWDSTRIKE_AGENT_TOKEN?.trim();
  if (envToken) return envToken;

  const tokenPath =
    process.env.CLAWDSTRIKE_AGENT_TOKEN_PATH?.trim() ??
    join(
      process.env.XDG_CONFIG_HOME?.trim() || join(homedir(), ".config"),
      "clawdstrike",
      "agent-local-token",
    );
  try {
    const token = readFileSync(tokenPath, "utf8").trim();
    return token || null;
  } catch {
    return null;
  }
}

function sha256Hex(value: unknown): string {
  const h = createHash("sha256");
  if (typeof value === "string") h.update(value);
  else h.update(stableStringify(value));
  return h.digest("hex");
}

/**
 * Create a PolicyEvent from tool execution context
 */
function createPolicyEvent(
  sessionId: string,
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): PolicyEvent {
  const eventId = `${sessionId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const timestamp = new Date().toISOString();

  // Determine event type based on tool name
  const eventType = inferEventType(toolName);

  // Create appropriate event data
  const data = createEventData(toolName, params, result);

  return {
    eventId,
    eventType,
    timestamp,
    sessionId,
    data,
    metadata: {
      toolName,
      originalParams: params,
    },
  };
}

/**
 * Infer event type from tool name using the shared token-based classifier.
 */
function inferEventType(toolName: string): PolicyEvent["eventType"] {
  return inferEventTypeFromName(toolName) ?? "tool_call";
}

/**
 * Create event data based on tool name and params
 */
function createEventData(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): PolicyEvent["data"] {
  const eventType = inferEventType(toolName);

  switch (eventType) {
    case "file_read":
    case "file_write": {
      const path = extractPath(params);
      const contentHash = typeof params.contentHash === "string" ? params.contentHash : undefined;
      const { content, contentBase64 } = extractFileContent(params, result, eventType);
      return {
        type: "file",
        path: path ?? "",
        content,
        contentBase64,
        contentHash,
        operation: eventType === "file_read" ? "read" : "write",
      };
    }

    case "network_egress": {
      const { host, port, url } = extractNetworkInfo(params);
      return {
        type: "network",
        host,
        port,
        url,
      };
    }

    case "command_exec": {
      const { command, args, workingDir } = extractCommandInfo(params);
      return {
        type: "command",
        command,
        args,
        workingDir,
      };
    }

    case "patch_apply": {
      const { filePath, patchContent } = extractPatchInfo(params, result);
      return {
        type: "patch",
        filePath,
        patchContent,
      };
    }

    case "tool_call":
    default: {
      return {
        type: "tool",
        toolName,
        parameters: params,
        result: typeof result === "string" ? result : JSON.stringify(result ?? ""),
      };
    }
  }
}

function extractFileContent(
  params: Record<string, unknown>,
  result: unknown,
  eventType: PolicyEvent["eventType"],
): { content?: string; contentBase64?: string } {
  const maxChars = 2_000_000; // Best-effort cap: avoid huge payloads.

  const contentBase64 =
    typeof params.contentBase64 === "string"
      ? params.contentBase64
      : typeof params.base64 === "string"
        ? params.base64
        : undefined;

  if (contentBase64) {
    return {
      contentBase64:
        contentBase64.length > maxChars ? contentBase64.slice(0, maxChars) : contentBase64,
    };
  }

  const content =
    typeof params.content === "string"
      ? params.content
      : typeof params.text === "string"
        ? params.text
        : eventType === "file_read" && typeof result === "string"
          ? result
          : undefined;

  if (!content) return {};
  return { content: content.length > maxChars ? content.slice(0, maxChars) : content };
}

/**
 * Extract network info from tool params
 */
function extractNetworkInfo(params: Record<string, unknown>): {
  host: string;
  port: number;
  url?: string;
} {
  // Try to get URL first
  const url =
    typeof params.url === "string"
      ? params.url
      : typeof params.endpoint === "string"
        ? params.endpoint
        : typeof params.href === "string"
          ? params.href
          : undefined;

  if (url) {
    try {
      const parsed = new URL(url);
      return {
        host: parsed.hostname,
        port: parsed.port
          ? parseInt(parsed.port, 10)
          : parsed.protocol === "https:" || parsed.protocol === "wss:"
            ? 443
            : 80,
        url,
      };
    } catch {
      // Not a valid URL
    }
  }

  // Try to extract from command
  if (typeof params.command === "string") {
    const urlMatch = params.command.match(/https?:\/\/[^\s'"]+/);
    if (urlMatch) {
      try {
        const parsed = new URL(urlMatch[0]);
        return {
          host: parsed.hostname,
          port: parsed.port
            ? parseInt(parsed.port, 10)
            : parsed.protocol === "https:" || parsed.protocol === "wss:"
              ? 443
              : 80,
          url: urlMatch[0],
        };
      } catch {
        // Not a valid URL
      }
    }
  }

  // Fallback
  const host =
    typeof params.host === "string"
      ? params.host
      : typeof params.hostname === "string"
        ? params.hostname
        : "unknown";
  const port = typeof params.port === "number" ? params.port : 80;
  return { host, port, url };
}

function extractCommandInfo(params: Record<string, unknown>): {
  command: string;
  args: string[];
  workingDir?: string;
} {
  const workingDir =
    typeof params.cwd === "string"
      ? params.cwd
      : typeof params.workingDir === "string"
        ? params.workingDir
        : undefined;

  const args =
    Array.isArray(params.args) && params.args.every((a) => typeof a === "string")
      ? (params.args as string[])
      : Array.isArray(params.argv) && params.argv.every((a) => typeof a === "string")
        ? (params.argv as string[])
        : undefined;

  const cmdLine =
    typeof params.command === "string"
      ? params.command
      : typeof params.cmd === "string"
        ? params.cmd
        : undefined;

  if (cmdLine) {
    const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
      return { command: "", args: [], workingDir };
    }
    const [command, ...rest] = parts;
    return { command, args: args ?? rest, workingDir };
  }

  if (typeof params.tool === "string" && args) {
    return { command: params.tool, args, workingDir };
  }

  return { command: "", args: args ?? [], workingDir };
}

function extractPatchInfo(
  params: Record<string, unknown>,
  result: unknown,
): { filePath: string; patchContent: string } {
  const filePath =
    (typeof params.filePath === "string" && params.filePath) ||
    (typeof params.path === "string" && params.path) ||
    (typeof params.file === "string" && params.file) ||
    "";

  const patchContent =
    (typeof params.patch === "string" && params.patch) ||
    (typeof params.diff === "string" && params.diff) ||
    (typeof params.content === "string" && params.content) ||
    (typeof result === "string" ? result : JSON.stringify(result ?? ""));

  return { filePath, patchContent };
}

export default handler;
