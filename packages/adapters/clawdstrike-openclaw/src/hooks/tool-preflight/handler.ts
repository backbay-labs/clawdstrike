/**
 * @clawdstrike/openclaw - Tool Pre-flight Hook Handler
 *
 * Intercepts tool calls BEFORE execution and enforces security policy
 * on risky operations (filesystem access, command execution, patch apply, egress).
 *
 * Most read-only operations are skipped here and handled by the post-execution
 * tool-guard hook for output sanitization, but we still preflight-check
 * forbidden paths when a read targets a sensitive location.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  classifyTool,
  DESTRUCTIVE_EVENT_MAP,
  NETWORK_TOKENS,
  tokenize,
} from "../../classification.js";
import { getSharedEngine, initializeEngine } from "../../engine-holder.js";
import type {
  BeforeToolCallHookEvent,
  BeforeToolCallHookResult,
  ClawdstrikeConfig,
  Decision,
  EventType,
  HookEvent,
  HookHandler,
  OpenClawHookContext,
  PolicyEvent,
  ToolCallEvent,
} from "../../types.js";
import {
  type ApprovalResolutionType,
  peekApproval,
  recordApproval,
} from "../approval-state.js";
import { extractPath, normalizeApprovalResource } from "../approval-utils.js";
import {
  clearAllToolInvocations,
  rememberToolInvocation,
} from "../tool-invocation-state.js";

const REDACTED = "[REDACTED]";
const SECRET_LIKE_VALUE =
  /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const SENSITIVE_COMMAND_KEY =
  /(?:^|[:._/-])(?:_?auth[_-]?token|secret|token|password|passwd|credential|api[_-]?key|authorization|cookie|access[_-]?key|refresh[_-]?token|id[_-]?token|client[_-]?secret|body|value|data|from[_-]?literal|data[_-]?file)$/i;
const SENSITIVE_VALUE_FLAG =
  /^-+(?:token|auth[_-]?token|password|passwd|credential|api[_-]?key|authorization|cookie|access[_-]?key|refresh[_-]?token|id[_-]?token|client[_-]?secret|body|value|data|from[_-]?literal|data[_-]?file)$/i;
const RAW_TELEMETRY_CONTENT_KEY =
  /^(?:content|file[_-]?content|body|payload|patch|patch[_-]?content|diff)$/i;
const SENSITIVE_TELEMETRY_KEY =
  /(?:secret|token|password|passwd|credential|api[_-]?key|authorization|cookie|access[_-]?key|refresh[_-]?token|id[_-]?token|client[_-]?secret)/i;

/**
 * Initialize the hook with configuration.
 * Delegates to the shared engine holder so all hooks share one PolicyEngine.
 */
export function initialize(config: ClawdstrikeConfig): void {
  initializeEngine(config);
  clearAllToolInvocations();
}

/**
 * Get or create the policy engine.
 * Delegates to the shared engine holder.
 */
export function getEngine(config?: ClawdstrikeConfig): PolicyEngine {
  return getSharedEngine(config);
}

// Re-export PolicyEngine type so existing `getEngine` callers can use it.
import type { PolicyEngine } from "../../policy/engine.js";

/**
 * Infer the event type for a tool based on its name tokens and parameters.
 *
 * Returns null for confirmed read-only tools that do not appear to touch the filesystem.
 * Unknown/unclassified tools are still evaluated (best-effort inference).
 */
function inferPolicyEventType(
  toolName: string,
  params: Record<string, unknown>,
): EventType | null {
  const tokens = tokenize(toolName);
  const classification = classifyTool(tokens);

  if (classification === "read_only") {
    // Read-only tools can still be risky if they touch forbidden paths OR perform network egress.
    // Do not skip preflight egress checks (eg. web_search/http_get) just because the tool name
    // contains a read-only token like "get" or "search".
    if (
      tokens.some((t) => NETWORK_TOKENS.has(t)) ||
      looksLikeNetworkEgress(params)
    ) {
      return "network_egress";
    }

    // If it looks like a filesystem read, evaluate it as file_read.
    const p = extractPath(params);
    if (p) return "file_read";
    return null;
  }

  // Check specific destructive event types
  for (const { tokens: matchTokens, eventType } of DESTRUCTIVE_EVENT_MAP) {
    if (tokens.some((t) => matchTokens.has(t))) {
      return eventType;
    }
  }

  // Check network tokens
  if (tokens.some((t) => NETWORK_TOKENS.has(t))) {
    return "network_egress";
  }

  // Unknown/unclassified tools: infer from parameters (do not skip).
  if (looksLikePatchApply(params)) return "patch_apply";
  if (looksLikeCommandExec(params)) return "command_exec";
  if (looksLikeNetworkEgress(params)) return "network_egress";

  const p = extractPath(params);
  if (p) {
    return looksLikeFileWrite(params) ? "file_write" : "file_read";
  }

  // Fall back to tool_call so tool allow/deny lists and defense-in-depth checks can run.
  return "tool_call";
}

/**
 * Build a PolicyEvent from pre-execution context
 */
function buildPolicyEvent(
  sessionId: string,
  toolName: string,
  params: Record<string, unknown>,
  eventType: EventType,
): PolicyEvent {
  const eventId = `preflight-${sessionId}-${Date.now()}-${crypto.randomUUID()}`;
  const timestamp = new Date().toISOString();

  switch (eventType) {
    case "file_read": {
      const path = extractPath(params) ?? "";
      return {
        eventId,
        eventType: "file_read",
        timestamp,
        sessionId,
        data: { type: "file", path, operation: "read" },
        metadata: { toolName, preflight: true },
      };
    }
    case "file_write": {
      const path = extractPath(params) ?? "";
      return {
        eventId,
        eventType: "file_write",
        timestamp,
        sessionId,
        data: {
          type: "file",
          path,
          operation: "write",
          content:
            typeof params.content === "string" ? params.content : undefined,
        },
        metadata: { toolName, preflight: true },
      };
    }
    case "command_exec": {
      const cmdLine =
        typeof params.command === "string"
          ? params.command
          : typeof params.cmd === "string"
            ? params.cmd
            : "";

      // Some tools pass argv-style params (args/argv) instead of a shell command line.
      const argv =
        Array.isArray(params.argv) &&
        params.argv.every((a) => typeof a === "string")
          ? (params.argv as string[])
          : Array.isArray(params.args) &&
              params.args.every((a) => typeof a === "string")
            ? (params.args as string[])
            : null;

      let command = "";
      let args: string[] = [];

      if (cmdLine.trim()) {
        const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
        command = parts[0] ?? "";
        const inlineArgs = parts.slice(1);

        if (inlineArgs.length > 0) {
          // Treat `command`/`cmd` as the full command line when it includes args.
          args = inlineArgs;
        } else if (argv && argv.length > 0) {
          // Otherwise, if args/argv is present, treat it as args unless it redundantly includes the command.
          args = argv[0] === command ? argv.slice(1) : argv;
        }
      } else if (argv && argv.length > 0) {
        [command, ...args] = argv;
      }
      return {
        eventId,
        eventType: "command_exec",
        timestamp,
        sessionId,
        data: { type: "command", command, args },
        metadata: { toolName, preflight: true },
      };
    }
    case "patch_apply": {
      const filePath =
        typeof params.filePath === "string"
          ? params.filePath
          : typeof params.path === "string"
            ? params.path
            : "";
      const patchContent =
        typeof params.patch === "string"
          ? params.patch
          : typeof params.content === "string"
            ? params.content
            : "";
      return {
        eventId,
        eventType: "patch_apply",
        timestamp,
        sessionId,
        data: { type: "patch", filePath, patchContent },
        metadata: { toolName, preflight: true },
      };
    }
    case "network_egress": {
      const { host, port, url } = extractNetworkInfo(params);
      return {
        eventId,
        eventType: "network_egress",
        timestamp,
        sessionId,
        data: { type: "network", host, port, url },
        metadata: { toolName, preflight: true },
      };
    }
    default: {
      return {
        eventId,
        eventType: "tool_call",
        timestamp,
        sessionId,
        data: { type: "tool", toolName, parameters: params },
        metadata: { toolName, preflight: true },
      };
    }
  }
}

function extractNetworkInfo(params: Record<string, unknown>): {
  host: string;
  port: number;
  url?: string;
} {
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
  const host =
    typeof params.host === "string"
      ? params.host
      : typeof params.hostname === "string"
        ? params.hostname
        : "unknown";
  const port = typeof params.port === "number" ? params.port : 80;
  return { host, port, url };
}

function looksLikePatchApply(params: Record<string, unknown>): boolean {
  return (
    typeof params.patch === "string" ||
    typeof params.diff === "string" ||
    typeof params.patchContent === "string"
  );
}

function looksLikeCommandExec(params: Record<string, unknown>): boolean {
  if (typeof params.command === "string" || typeof params.cmd === "string")
    return true;
  if (
    Array.isArray(params.args) &&
    params.args.every((a) => typeof a === "string")
  )
    return true;
  if (
    Array.isArray(params.argv) &&
    params.argv.every((a) => typeof a === "string")
  )
    return true;
  return false;
}

function looksLikeNetworkEgress(params: Record<string, unknown>): boolean {
  if (
    typeof params.url === "string" ||
    typeof params.endpoint === "string" ||
    typeof params.href === "string"
  )
    return true;
  if (typeof params.host === "string" || typeof params.hostname === "string")
    return true;
  return false;
}

function looksLikeFileWrite(params: Record<string, unknown>): boolean {
  // Common write payload keys used by various tool APIs.
  if (typeof params.content === "string") return true;
  if (typeof params.text === "string") return true;
  if (typeof params.contentBase64 === "string") return true;
  if (typeof params.base64 === "string") return true;
  if (typeof params.patch === "string" || typeof params.diff === "string")
    return true;
  if (typeof params.operation === "string") {
    const op = params.operation.toLowerCase();
    if (
      op === "write" ||
      op === "append" ||
      op === "delete" ||
      op === "remove" ||
      op === "truncate"
    )
      return true;
  }
  return false;
}

// Approval flow:
// 1. Pre-flight guard denies a non-critical action
// 2. If the agent's approval API is configured (CLAWDSTRIKE_APPROVAL_URL env),
//    submit an approval request and poll for resolution
// 3. If no approval system configured or timeout, deny immediately
//
// The desktop agent's ApprovalQueue (/api/v1/approval/*) surfaces these
// to users via OS notifications and tray menu. The OpenClaw gateway
// exec_approval_queue is a separate system for gateway-specific flows.

const APPROVAL_POLL_INTERVAL_MS = 1_000;
const APPROVAL_POLL_TIMEOUT_MS = 60_000;

interface ApprovalStatusResponse {
  id: string;
  status: "pending" | "resolved" | "expired";
  resolution: "allow-once" | "allow-session" | "allow-always" | "deny" | null;
  tool: string;
  resource: string;
  guard: string;
  reason: string;
  severity: string;
}

/**
 * Submit an approval request and poll until resolved or expired.
 * Returns the resolved approval status if the user approved, null otherwise.
 */
async function requestApproval(details: {
  toolName: string;
  resource: string;
  guard: string;
  reason: string;
  severity: string;
  sessionId: string;
}): Promise<ApprovalStatusResponse | null> {
  const approvalUrl = process.env.CLAWDSTRIKE_APPROVAL_URL;
  if (!approvalUrl) {
    return null;
  }

  const token = process.env.CLAWDSTRIKE_AGENT_TOKEN;
  if (!token) {
    console.warn(
      "[clawdstrike] CLAWDSTRIKE_APPROVAL_URL is set but CLAWDSTRIKE_AGENT_TOKEN is missing — skipping approval request",
    );
    return null;
  }

  const authHeaders = {
    "Content-Type": "application/json",
    Authorization: "Bearer " + token,
  };

  let id: string;
  try {
    const submitRes = await fetch(`${approvalUrl}/api/v1/approval/request`, {
      method: "POST",
      headers: authHeaders,
      signal: AbortSignal.timeout(10_000),
      body: JSON.stringify({
        tool: details.toolName,
        resource: details.resource,
        guard: details.guard,
        reason: details.reason,
        severity: details.severity,
        session_id: details.sessionId,
      }),
    });
    if (!submitRes.ok) {
      return null;
    }
    const body = (await submitRes.json()) as ApprovalStatusResponse;
    id = body.id;
  } catch {
    return null;
  }

  const deadline = Date.now() + APPROVAL_POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await new Promise((resolve) =>
      setTimeout(resolve, APPROVAL_POLL_INTERVAL_MS),
    );

    try {
      const pollRes = await fetch(
        `${approvalUrl}/api/v1/approval/${id}/status`,
        {
          headers: { Authorization: "Bearer " + token },
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!pollRes.ok) {
        return null;
      }
      const status = (await pollRes.json()) as ApprovalStatusResponse;

      if (status.status === "resolved") {
        if (status.resolution !== null && status.resolution !== "deny") {
          return status;
        }
        return null;
      }
      if (status.status === "expired") {
        return null;
      }
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Hook handler for tool_call (pre-execution) events.
 *
 * If the tool is destructive, evaluates the policy engine.
 * On deny: submits an approval request if the approval API is configured,
 *          and blocks unless the user approves.
 * On warn: adds a warning message but allows execution.
 * On allow / read-only: no-op.
 */
const handler: HookHandler = async (
  event: HookEvent | BeforeToolCallHookEvent,
  hookCtx?: OpenClawHookContext,
): Promise<void | BeforeToolCallHookResult> => {
  const isModernBeforeToolCallEvent = (
    value: HookEvent | BeforeToolCallHookEvent,
  ): value is BeforeToolCallHookEvent => {
    return Boolean(
      value &&
      typeof value === "object" &&
      typeof (value as { toolName?: unknown }).toolName === "string" &&
      typeof (value as { params?: unknown }).params === "object" &&
      (value as { params?: unknown }).params !== null,
    );
  };

  const isModern = isModernBeforeToolCallEvent(event);
  if (!isModern) {
    if (event.type !== "tool_call" && event.type !== "before_tool_call") {
      return;
    }
  }

  const legacyToolEvent = isModern ? null : (event as ToolCallEvent);

  // Skip if already handled by another hook registration (e.g. before_tool_call + tool_call dual registration)
  if (!isModern && legacyToolEvent!.preventDefault) return;

  // Skip if the CUA bridge handler already evaluated this tool call.
  // CUA tools receive specialized policy evaluation via the bridge; running
  // the general preflight handler as well would cause double evaluation.
  if ((event as any).__cuaBridgeEvaluated) return;

  const toolName = isModern
    ? event.toolName
    : legacyToolEvent!.context.toolCall.toolName;
  const params = isModern
    ? event.params
    : legacyToolEvent!.context.toolCall.params;
  const sessionId = isModern
    ? (hookCtx?.sessionKey ?? hookCtx?.agentId ?? "openclaw-runtime")
    : legacyToolEvent!.context.sessionId;
  const toolCallId =
    isModern &&
    typeof hookCtx?.toolCallId === "string" &&
    hookCtx.toolCallId.length > 0
      ? hookCtx.toolCallId
      : undefined;
  const telemetryIdentity = preflightTelemetryIdentity(
    hookCtx,
    sessionId,
    toolCallId,
  );

  if (isModern) {
    rememberToolInvocation(sessionId, toolName, params, toolCallId);
  }

  // Determine if this tool is destructive
  const eventType = inferPolicyEventType(toolName, params);
  if (eventType === null) {
    // Confirmed read-only tool: skip pre-flight, let post-execution handle it
    return;
  }

  const policyEngine = getEngine();
  const policyEvent = buildPolicyEvent(sessionId, toolName, params, eventType);
  const decision = await policyEngine.evaluate(policyEvent);
  void publishPreflightPolicyEvent(
    buildPreflightPolicyEventForEdr(
      policyEvent,
      toolName,
      decision,
      telemetryIdentity,
    ),
  );
  const developerActivity = buildPreflightDeveloperActivityForCommand(
    policyEvent,
    toolName,
    decision,
    telemetryIdentity,
  );
  if (developerActivity) {
    void publishPreflightDeveloperActivity(developerActivity);
  }

  if (decision.status === "deny") {
    const resource = normalizeApprovalResource(policyEngine, toolName, params);
    const guard = decision.guard ?? "unknown";
    const severity = decision.severity ?? "high";

    // If the user previously approved this exact action for this session (or globally),
    // honor it and avoid re-prompting.
    if (severity !== "critical") {
      const prior = peekApproval(sessionId, toolName, resource);
      if (prior) {
        if (!isModern) {
          legacyToolEvent!.messages.push(
            `[clawdstrike] Pre-flight check: using prior ${prior.resolution} approval for ${toolName} on ${resource}`,
          );
        }
        return;
      }
    }

    // If the denial is non-critical and the approval API is configured,
    // submit an approval request and wait for user resolution.
    if (severity !== "critical" && process.env.CLAWDSTRIKE_APPROVAL_URL) {
      const approvalResult = await requestApproval({
        toolName,
        resource,
        guard,
        reason: decision.reason ?? "Policy denied",
        severity,
        sessionId,
      });
      if (approvalResult) {
        const resolution = approvalResult.resolution as ApprovalResolutionType;
        recordApproval(sessionId, toolName, resource, resolution);
        if (!isModern) {
          legacyToolEvent!.messages.push(
            `[clawdstrike] Pre-flight check: ${toolName} on ${resource} was approved by user`,
          );
        }
        return;
      }
    }

    const blockReason = `blocked ${toolName} on ${resource}${decision.reason ? ` — ${decision.reason}` : ""}`;
    if (isModern) {
      return { block: true, blockReason, params };
    }
    legacyToolEvent!.preventDefault = true;
    legacyToolEvent!.messages.push(
      `[clawdstrike] Pre-flight check: ${blockReason}`,
    );
    if (legacyToolEvent!.type === "before_tool_call") {
      return { block: true, blockReason, params };
    }
    return;
  }

  if (!isModern && decision.status === "warn") {
    legacyToolEvent!.messages.push(
      `[clawdstrike] Pre-flight warning: ${decision.message ?? decision.reason ?? "Policy warning"} (${toolName})`,
    );
  }
};

export default handler;

type EdrDeveloperActivity = Record<string, unknown>;

export type PreflightTelemetryIdentity = {
  hostId?: string;
  userId?: string;
  sessionId?: string;
  agentId?: string;
  workloadId?: string;
  approvalId?: string;
  toolCallId?: string;
};

function preflightTelemetryIdentity(
  hookCtx: OpenClawHookContext | undefined,
  sessionId: string,
  toolCallId: string | undefined,
): PreflightTelemetryIdentity {
  return {
    hostId: firstNonEmptyString(
      hookCtx?.hostId,
      process.env.CLAWDSTRIKE_HOST_ID,
      process.env.CLAWDSTRIKE_ENDPOINT_ID,
    ),
    userId: firstNonEmptyString(
      hookCtx?.userId,
      process.env.CLAWDSTRIKE_USER_ID,
      process.env.CLAWDSTRIKE_PRINCIPAL_ID,
    ),
    sessionId: firstNonEmptyString(
      sessionId,
      hookCtx?.sessionKey,
      process.env.CLAWDSTRIKE_SESSION_ID,
    ),
    agentId: firstNonEmptyString(
      hookCtx?.agentId,
      process.env.CLAWDSTRIKE_AGENT_ID,
    ),
    workloadId:
      firstNonEmptyString(
        hookCtx?.workloadId,
        process.env.CLAWDSTRIKE_WORKLOAD_ID,
      ) ?? "openclaw-tool-preflight",
    approvalId: firstNonEmptyString(
      hookCtx?.approvalId,
      process.env.CLAWDSTRIKE_APPROVAL_ID,
    ),
    toolCallId,
  };
}

function firstNonEmptyString(
  ...values: Array<string | undefined>
): string | undefined {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
}

export function buildPreflightDeveloperActivityForCommand(
  policyEvent: PolicyEvent,
  toolName: string,
  decision: Decision,
  identity: PreflightTelemetryIdentity = {},
): EdrDeveloperActivity | null {
  if (policyEvent.eventType !== "command_exec") return null;
  const command = commandTokensFromPolicyEvent(policyEvent);
  if (command.length === 0) return null;

  const scrubbedCommand = scrubCommandArgs(command);
  const commandLine = scrubbedCommand.join(" ");
  const scrubbedArgs = scrubbedCommand.slice(1);
  const metadata = {
    collectorKind: "openclaw_tool_preflight",
    policyAllowed: decision.status !== "deny",
    policyStatus: decision.status,
    policyGuard: decision.guard,
    policySeverity: decision.severity,
    policyReason: decision.reason,
    toolName,
    toolCallId: identity.toolCallId,
  };
  const common = {
    hostId: identity.hostId,
    userId: identity.userId,
    sessionId: policyEvent.sessionId,
    agentId: identity.agentId,
    workloadId: identity.workloadId ?? "openclaw-tool-preflight",
    approvalId: identity.approvalId,
  };

  const packageCommand = classifyPackageCommand(command);
  if (packageCommand) {
    return {
      ...common,
      kind: "package_script",
      manager: packageCommand.manager,
      package: packageCommand.packageName,
      phase: packageCommand.phase,
      script: commandLine,
      image: command[0],
      commandLine,
      metadata: {
        ...metadata,
        shellClassifier: "package_script",
      },
    };
  }

  const packageRegistryTokenCommand =
    classifyPackageRegistryTokenCommand(command);
  if (packageRegistryTokenCommand) {
    return {
      ...common,
      kind: packageRegistryTokenCommand.kind,
      path: packageRegistryTokenCommand.path,
      name: packageRegistryTokenCommand.name,
      credentialKind: packageRegistryTokenCommand.credentialKind,
      image: command[0],
      commandLine,
      args: scrubbedArgs,
      metadata: {
        ...metadata,
        shellClassifier: packageRegistryTokenCommand.classifier,
      },
    };
  }

  const cloudCommand = classifyCloudCommand(command);
  if (cloudCommand) {
    return {
      ...common,
      kind: "cloud_cli",
      provider: cloudCommand.provider,
      operation: cloudCommand.operation,
      args: scrubCommandArgs(cloudCommand.args),
      image: command[0],
      commandLine,
      metadata: {
        ...metadata,
        shellClassifier: "cloud_cli",
      },
    };
  }

  return null;
}

export function buildPreflightPolicyEventForEdr(
  policyEvent: PolicyEvent,
  toolName: string,
  decision: Decision,
  identity: PreflightTelemetryIdentity = {},
): PolicyEvent {
  return {
    ...policyEvent,
    metadata: {
      ...(policyEvent.metadata ?? {}),
      collectorKind: "openclaw_tool_preflight",
      toolName,
      policyAllowed: decision.status !== "deny",
      policyStatus: decision.status,
      policyGuard: decision.guard,
      policySeverity: decision.severity,
      policyReason: decision.reason,
      hostId: identity.hostId,
      userId: identity.userId,
      sessionId: identity.sessionId ?? policyEvent.sessionId,
      agentId: identity.agentId,
      workloadId: identity.workloadId,
      approvalId: identity.approvalId,
      toolCallId: identity.toolCallId,
    },
  };
}

async function publishPreflightDeveloperActivity(
  activity: EdrDeveloperActivity,
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
      body: JSON.stringify({ activities: [activity] }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // Developer-activity telemetry is enrichment only. Preflight policy
    // enforcement above remains the authoritative allow/block path.
  }
}

async function publishPreflightPolicyEvent(
  policyEvent: PolicyEvent,
): Promise<void> {
  const endpoint = resolvePolicyEventsEndpoint();
  if (!endpoint) return;

  try {
    const telemetryEvent =
      sanitizePreflightPolicyEventForTelemetry(policyEvent);
    const response = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${endpoint.token}`,
      },
      signal: AbortSignal.timeout(250),
      body: JSON.stringify({ events: [telemetryEvent] }),
    });
    if (!response.ok) {
      return;
    }
  } catch {
    // EDR capture is evidence enrichment only. Preflight policy enforcement
    // above remains the authoritative allow/block path.
  }
}

function sanitizePreflightPolicyEventForTelemetry(
  policyEvent: PolicyEvent,
): PolicyEvent {
  const scrubbedFields: string[] = [];
  const data = sanitizeTelemetryEventData(policyEvent.data, scrubbedFields);
  if (scrubbedFields.length === 0) {
    return policyEvent;
  }

  return {
    ...policyEvent,
    data: data as PolicyEvent["data"],
    metadata: {
      ...(policyEvent.metadata ?? {}),
      telemetryScrubbed: true,
      telemetryRedaction: "hashes_and_summaries",
      telemetryScrubbedFields: [...new Set(scrubbedFields)].sort(),
    },
  };
}

function sanitizeTelemetryEventData(
  value: PolicyEvent["data"],
  scrubbedFields: string[],
): Record<string, unknown> {
  const data = asRecord(value);
  if (!data) return {};

  switch (data.type) {
    case "file":
      return sanitizeFileTelemetryData(data, scrubbedFields);
    case "patch":
      return sanitizePatchTelemetryData(data, scrubbedFields);
    case "command":
      return sanitizeCommandTelemetryData(data, scrubbedFields);
    case "network":
      return sanitizeNetworkTelemetryData(data, scrubbedFields);
    case "tool":
      return sanitizeToolTelemetryData(data, scrubbedFields);
    default:
      return sanitizeTelemetryValue(data, "data", scrubbedFields) as Record<
        string,
        unknown
      >;
  }
}

function sanitizeFileTelemetryData(
  data: Record<string, unknown>,
  scrubbedFields: string[],
): Record<string, unknown> {
  const sanitized = { ...data };
  if (typeof sanitized.content === "string") {
    const content = sanitized.content;
    delete sanitized.content;
    sanitized.contentHash = sha256Hex(content);
    sanitized.contentBytes = Buffer.byteLength(content);
    scrubbedFields.push("data.content");
  }
  return sanitizeTelemetryValue(sanitized, "data", scrubbedFields) as Record<
    string,
    unknown
  >;
}

function sanitizePatchTelemetryData(
  data: Record<string, unknown>,
  scrubbedFields: string[],
): Record<string, unknown> {
  const sanitized = { ...data };
  if (typeof sanitized.patchContent === "string") {
    const patchContent = sanitized.patchContent;
    delete sanitized.patchContent;
    sanitized.patchHash = sha256Hex(patchContent);
    sanitized.patchBytes = Buffer.byteLength(patchContent);
    scrubbedFields.push("data.patchContent");
  }
  return sanitizeTelemetryValue(sanitized, "data", scrubbedFields) as Record<
    string,
    unknown
  >;
}

function sanitizeCommandTelemetryData(
  data: Record<string, unknown>,
  scrubbedFields: string[],
): Record<string, unknown> {
  const sanitized = { ...data };
  const command =
    typeof sanitized.command === "string" ? sanitized.command : "";
  const args = Array.isArray(sanitized.args)
    ? sanitized.args.filter(
        (value): value is string => typeof value === "string",
      )
    : [];
  const scrubbed = scrubCommandArgs(
    [command, ...args].filter((value) => value.trim() !== ""),
  );
  if (scrubbed.length > 0) {
    const [scrubbedCommand, ...scrubbedArgs] = scrubbed;
    if (scrubbedCommand !== command) {
      sanitized.command = scrubbedCommand;
      scrubbedFields.push("data.command");
    }
    if (JSON.stringify(scrubbedArgs) !== JSON.stringify(args)) {
      sanitized.args = scrubbedArgs;
      scrubbedFields.push("data.args");
    }
  }
  return sanitizeTelemetryValue(sanitized, "data", scrubbedFields) as Record<
    string,
    unknown
  >;
}

function sanitizeNetworkTelemetryData(
  data: Record<string, unknown>,
  scrubbedFields: string[],
): Record<string, unknown> {
  const sanitized = { ...data };
  if (typeof sanitized.url === "string") {
    const redacted = redactTelemetryUrl(sanitized.url);
    if (redacted !== sanitized.url) {
      sanitized.url = redacted;
      scrubbedFields.push("data.url");
    }
  }
  return sanitizeTelemetryValue(sanitized, "data", scrubbedFields) as Record<
    string,
    unknown
  >;
}

function sanitizeToolTelemetryData(
  data: Record<string, unknown>,
  scrubbedFields: string[],
): Record<string, unknown> {
  const sanitized = { ...data };
  if (sanitized.parameters !== undefined) {
    sanitized.parameters = sanitizeTelemetryValue(
      sanitized.parameters,
      "data.parameters",
      scrubbedFields,
    );
  }
  return sanitizeTelemetryValue(sanitized, "data", scrubbedFields) as Record<
    string,
    unknown
  >;
}

function sanitizeTelemetryValue(
  value: unknown,
  path: string,
  scrubbedFields: string[],
  depth = 0,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    const redacted = redactTelemetryString(value);
    if (redacted !== value) scrubbedFields.push(path);
    return redacted;
  }
  if (typeof value !== "object") return value;
  if (depth >= 6) {
    scrubbedFields.push(path);
    return { redaction: "omitted", reason: "max_depth" };
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, 25)
      .map((entry, index) =>
        sanitizeTelemetryValue(
          entry,
          `${path}[${index}]`,
          scrubbedFields,
          depth + 1,
        ),
      );
  }

  const record = value as Record<string, unknown>;
  const sanitized: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(record)) {
    const entryPath = `${path}.${key}`;
    if (RAW_TELEMETRY_CONTENT_KEY.test(key) && typeof entry === "string") {
      sanitized[key] = {
        redaction: "hash_only",
        sha256: sha256Hex(entry),
        byteLength: Buffer.byteLength(entry),
      };
      scrubbedFields.push(entryPath);
      continue;
    }
    if (SENSITIVE_TELEMETRY_KEY.test(key)) {
      sanitized[key] =
        typeof entry === "string"
          ? REDACTED
          : { redaction: "omitted", reason: "sensitive_key" };
      scrubbedFields.push(entryPath);
      continue;
    }
    sanitized[key] = sanitizeTelemetryValue(
      entry,
      entryPath,
      scrubbedFields,
      depth + 1,
    );
  }
  return sanitized;
}

function redactTelemetryString(value: string): string {
  const trimmed = value.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    return redactTelemetryUrl(value);
  }
  return redactSensitiveCommandString(value);
}

function redactTelemetryUrl(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.username) parsed.username = REDACTED;
    if (parsed.password) parsed.password = REDACTED;
    for (const [key, parameterValue] of parsed.searchParams.entries()) {
      if (
        SENSITIVE_TELEMETRY_KEY.test(key) ||
        SECRET_LIKE_VALUE.test(parameterValue)
      ) {
        parsed.searchParams.set(key, REDACTED);
      }
    }
    return parsed.toString();
  } catch {
    return redactSensitiveCommandString(value);
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function sha256Hex(value: string): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function resolveDeveloperActivityEndpoint(): {
  url: string;
  token: string;
} | null {
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

function commandTokensFromPolicyEvent(policyEvent: PolicyEvent): string[] {
  const data = policyEvent.data as {
    type?: unknown;
    command?: unknown;
    args?: unknown;
  };
  if (
    data.type !== "command" ||
    typeof data.command !== "string" ||
    !data.command.trim()
  ) {
    return [];
  }
  const args = Array.isArray(data.args)
    ? data.args.filter(
        (value): value is string =>
          typeof value === "string" && value.trim() !== "",
      )
    : [];
  return [data.command.trim(), ...args.map((value) => value.trim())];
}

function scrubCommandArgs(args: string[]): string[] {
  const scrubbed: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    const next = args[index + 1];
    const keyValue = /^(-{1,2}[^=\s]+)=([\s\S]*)$/.exec(arg);
    if (keyValue) {
      const [, key, value] = keyValue;
      scrubbed.push(
        SENSITIVE_COMMAND_KEY.test(key) || SECRET_LIKE_VALUE.test(value)
          ? `${key}=${REDACTED}`
          : redactSensitiveCommandString(arg),
      );
      continue;
    }

    if (SENSITIVE_VALUE_FLAG.test(arg)) {
      scrubbed.push(arg);
      if (typeof next === "string" && next.trim() && !next.startsWith("-")) {
        scrubbed.push(REDACTED);
        index += 1;
      }
      continue;
    }

    scrubbed.push(redactSensitiveCommandString(arg));
  }
  return scrubbed;
}

function redactSensitiveCommandString(value: string): string {
  const withoutUrlUserinfo = redactUrlUserinfo(value);
  if (SECRET_LIKE_VALUE.test(withoutUrlUserinfo)) return REDACTED;
  return withoutUrlUserinfo.replace(
    /((?:token|secret|password|passwd|api[_-]?key|authorization|cookie)=)[^\s&]+/gi,
    `$1${REDACTED}`,
  );
}

function redactUrlUserinfo(value: string): string {
  return value.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s@]+)@/gi,
    `$1${REDACTED}@`,
  );
}

function classifyPackageCommand(command: string[]): {
  manager: string;
  phase: string;
  packageName?: string;
} | null {
  const [image, ...rawArgs] = command;
  const executable = executableName(image);
  let manager: string;
  let args = rawArgs;
  if (
    ["python", "python2", "python3"].includes(executable) &&
    rawArgs[0] === "-m" &&
    executableName(rawArgs[1] ?? "") === "pip"
  ) {
    manager = "pip";
    args = rawArgs.slice(2);
  } else if (
    [
      "npm",
      "pnpm",
      "yarn",
      "bun",
      "pip",
      "pip3",
      "cargo",
      "brew",
      "go",
      "gem",
      "composer",
      "mvn",
      "mvnw",
      "gradle",
      "gradlew",
      "uv",
      "poetry",
      "pipenv",
      "dotnet",
      "nuget",
      "swift",
      "mix",
    ].includes(executable)
  ) {
    if (executable === "pip3") {
      manager = "pip";
    } else if (["mvn", "mvnw"].includes(executable)) {
      manager = "maven";
    } else if (["gradle", "gradlew"].includes(executable)) {
      manager = "gradle";
    } else {
      manager = executable;
    }
  } else {
    return null;
  }

  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const commandName = args[commandIndex]?.toLowerCase();
  if (!commandName) return null;
  const afterCommand = args.slice(commandIndex + 1);
  const phase = packagePhase(manager, commandName, afterCommand);
  if (!phase) return null;

  return {
    manager,
    phase,
    packageName: packageNameFromPackageCommand(
      manager,
      commandName,
      afterCommand,
    ),
  };
}

function classifyPackageRegistryTokenCommand(command: string[]): {
  kind: "repo_secret";
  path: string;
  name: string;
  credentialKind: "package_registry_token";
  classifier: string;
} | null {
  const [image, ...args] = command;
  const manager = packageRegistryManager(image);
  if (!manager) return null;

  const commandIndex = firstNonOptionArgIndex(args);
  if (commandIndex === null) return null;
  const commandName = args[commandIndex]?.toLowerCase();
  if (!commandName) return null;
  const commandArgs = args.slice(commandIndex + 1);
  if (!packageRegistryTokenCommandIsSensitive(commandName, commandArgs))
    return null;

  return {
    kind: "repo_secret",
    path: `${manager}:token`,
    name: `${manager}-token`,
    credentialKind: "package_registry_token",
    classifier: "package_registry_token_command",
  };
}

function classifyCloudCommand(command: string[]): {
  provider: string;
  operation: string;
  args: string[];
} | null {
  const [image, ...args] = command;
  const executable = executableName(image);
  const provider =
    executable === "flyctl"
      ? "fly"
      : executable === "sentry-cli"
        ? "sentry"
        : executable === "bw"
          ? "bitwarden"
          : executable === "buildkite-agent" || executable === "bk"
            ? "buildkite"
            : executable === "tofu"
              ? "opentofu"
              : executable;
  if (
    ![
      "aws",
      "gcloud",
      "az",
      "gh",
      "vercel",
      "netlify",
      "wrangler",
      "doctl",
      "fly",
      "op",
      "vault",
      "doppler",
      "heroku",
      "supabase",
      "firebase",
      "railway",
      "sentry",
      "snyk",
      "bitwarden",
      "kubectl",
      "pulumi",
      "circleci",
      "glab",
      "buildkite",
      "terraform",
      "terragrunt",
      "opentofu",
    ].includes(provider)
  )
    return null;
  const operationIndex = firstNonOptionArgIndex(args);
  if (operationIndex === null) return null;
  const operation = args[operationIndex];
  if (!operation) return null;
  const operationArgs = args.slice(operationIndex + 1);
  const sensitiveArgs = [operation, ...operationArgs];
  if (!cloudCliArgsAreSensitive(provider, sensitiveArgs)) return null;
  return { provider, operation, args: operationArgs };
}

function packageRegistryManager(image: string): string | null {
  const executable = executableName(image);
  return ["npm", "pnpm", "yarn"].includes(executable) ? executable : null;
}

function packageRegistryTokenCommandIsSensitive(
  commandName: string,
  args: string[],
): boolean {
  const joined = args.join(" ").toLowerCase();
  if (commandName === "token") {
    return ["list", "create", "revoke", "delete"].includes(
      args[0]?.toLowerCase() ?? "",
    );
  }
  if (commandName === "config") {
    const subcommand = args[0]?.toLowerCase();
    return (
      ["get", "set", "delete"].includes(subcommand ?? "") &&
      packageRegistryAuthConfigReference(joined)
    );
  }
  return false;
}

function packageRegistryAuthConfigReference(value: string): boolean {
  return (
    value.includes("_authtoken") ||
    value.includes("node_auth_token") ||
    value.includes("npm_token") ||
    value.includes("npm_config_")
  );
}

function packagePhase(
  manager: string,
  commandName: string,
  args: string[],
): string | null {
  switch (manager) {
    case "npm":
    case "pnpm":
      if (["install", "i", "ci", "add", "rebuild"].includes(commandName))
        return "install";
      if (["run", "run-script", "exec", "dlx"].includes(commandName)) {
        return packageScriptName(args) ?? commandName;
      }
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "yarn":
      if (["install", "add", "upgrade"].includes(commandName)) return "install";
      if (commandName === "run") return packageScriptName(args) ?? "run";
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "pip":
      if (commandName === "install") return "install";
      if (commandName === "wheel") return "build";
      return null;
    case "cargo":
      return ["install", "build", "run", "test"].includes(commandName)
        ? commandName
        : null;
    case "brew":
      return ["install", "reinstall", "upgrade", "bundle"].includes(commandName)
        ? "install"
        : null;
    case "go":
      if (["install", "get"].includes(commandName)) return "install";
      return ["run", "build", "test"].includes(commandName)
        ? commandName
        : null;
    case "gem":
      return ["install", "build"].includes(commandName) ? commandName : null;
    case "composer":
      if (
        ["install", "update", "require", "create-project"].includes(commandName)
      ) {
        return "install";
      }
      if (["run-script", "exec"].includes(commandName))
        return packageScriptName(args) ?? commandName;
      return packageLifecyclePhase(commandName) ? commandName : null;
    case "maven":
      return [
        "validate",
        "compile",
        "test",
        "package",
        "verify",
        "install",
        "deploy",
      ].includes(commandName)
        ? commandName
        : null;
    case "gradle":
      return ["build", "test", "check", "assemble", "publish", "run"].includes(
        commandName,
      )
        ? commandName
        : null;
    case "uv":
      if (commandName === "pip") {
        const pipCommand = args[0]?.toLowerCase();
        if (["install", "sync"].includes(pipCommand ?? "")) return "install";
        if (pipCommand === "compile") return "build";
        return null;
      }
      if (["add", "sync"].includes(commandName)) return "install";
      if (["run", "build", "test"].includes(commandName)) return commandName;
      if (commandName === "tool") {
        const toolCommand = args[0]?.toLowerCase();
        if (toolCommand === "install") return "install";
        if (toolCommand === "run") return "run";
      }
      return null;
    case "poetry":
      if (["install", "add", "update"].includes(commandName)) return "install";
      if (commandName === "run") return packageScriptName(args) ?? "run";
      return ["build", "test"].includes(commandName) ? commandName : null;
    case "pipenv":
      if (["install", "sync", "update"].includes(commandName)) return "install";
      if (commandName === "run") return packageScriptName(args) ?? "run";
      return null;
    case "dotnet":
      if (commandName === "restore") return "install";
      if (commandName === "add" && args[0]?.toLowerCase() === "package")
        return "install";
      return ["build", "test", "pack", "publish", "run"].includes(commandName)
        ? commandName
        : null;
    case "nuget":
      if (["install", "restore"].includes(commandName)) return "install";
      if (commandName === "pack") return "build";
      if (commandName === "push") return "publish";
      return null;
    case "swift":
      if (commandName === "package") {
        const packageCommand = args[0]?.toLowerCase();
        if (["resolve", "update"].includes(packageCommand ?? ""))
          return "install";
        return null;
      }
      return ["build", "test", "run"].includes(commandName)
        ? commandName
        : null;
    case "mix":
      if (["deps.get", "deps.update"].includes(commandName)) return "install";
      if (
        commandName === "deps" &&
        ["get", "update"].includes(args[0]?.toLowerCase() ?? "")
      ) {
        return "install";
      }
      if (commandName === "compile") return "build";
      return ["test", "release"].includes(commandName) ? commandName : null;
    default:
      return null;
  }
}

function packageScriptName(args: string[]): string | null {
  return args.find((arg) => !arg.startsWith("-") && !arg.includes("=")) ?? null;
}

function packageLifecyclePhase(value: string): boolean {
  return [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "build",
    "build.rs",
    "setup.py",
    "test",
  ].some((phase) => value.includes(phase));
}

function packageNameFromPackageCommand(
  manager: string,
  commandName: string,
  args: string[],
): string | undefined {
  switch (manager) {
    case "uv":
      if (["pip", "tool"].includes(commandName))
        return packageNameFromArgs(args.slice(1));
      return packageNameFromArgs(args);
    case "dotnet":
      if (commandName === "add" && args[0]?.toLowerCase() === "package") {
        return packageNameFromArgs(args.slice(1));
      }
      return packageNameFromArgs(args);
    case "swift":
      return commandName === "package"
        ? packageNameFromArgs(args.slice(1))
        : packageNameFromArgs(args);
    case "mix":
      return commandName === "deps"
        ? packageNameFromArgs(args.slice(1))
        : packageNameFromArgs(args);
    default:
      return packageNameFromArgs(args);
  }
}

function packageNameFromArgs(args: string[]): string | undefined {
  const packageArg = args.find((arg) => {
    const lower = arg.toLowerCase();
    return (
      !arg.startsWith("-") &&
      !arg.includes("=") &&
      arg !== "." &&
      arg !== "--" &&
      !packageLifecyclePhase(lower)
    );
  });
  return packageArg ? redactSensitiveCommandString(packageArg) : undefined;
}

function cloudCliArgsAreSensitive(provider: string, args: string[]): boolean {
  const joined = args.join(" ").toLowerCase();
  const operation = args[0]?.toLowerCase() ?? "";
  return (
    terraformCliArgsAreSensitive(provider, args, joined) ||
    (provider === "az" && operation === "login") ||
    [
      "secretsmanager get-secret-value",
      "ssm get-parameter",
      "ssm get-parameters",
      "iam create-access-key",
      "iam put-user-policy",
      "iam attach-user-policy",
      "ecr get-login-password",
      "eks update-kubeconfig",
      "codeartifact login",
      "sso login",
      "sts get-session-token",
      "sts assume-role",
      "auth login",
      "auth print-access-token",
      "auth application-default login",
      "auth configure-docker",
      "container clusters get-credentials",
      "secrets versions access",
      "iam service-accounts keys create",
      "keyvault secret show",
      "keyvault secret download",
      "account get-access-token",
      "acr login",
      "aks get-credentials",
      "ad app credential reset",
      "secret set",
      "secret put",
      "secret bulk",
      "secret list",
      "secret delete",
      "versions secret put",
      "versions secret bulk",
      "registry docker-config",
      "registry login",
      "kubernetes cluster kubeconfig save",
      "secrets set",
      "secrets import",
      "secrets unset",
      "secrets list",
      "tokens create",
      "tokens revoke",
      "auth token",
      "variable set",
      "variable update",
      "variable delete",
      "variable get",
      "variable list",
      "variable export",
      "variables",
      "secret get",
      "secret create",
      "secret update",
      "env pull",
      "env add",
      "env rm",
      "env remove",
      "env ls",
      "env:get",
      "env:list",
      "env:set",
      "env:import",
      "env:unset",
      "item get",
      "get item",
      "document get",
      "op://",
      "kv get",
      "read secret/",
      "token create",
      "secrets download",
      "configs tokens create",
      "config:get",
      "config:set",
      "secrets pull",
      "get secret",
      "describe secret",
      "config view --raw",
      "--show-secrets",
      "context store-secret",
      "context remove-secret",
      "runner token create",
      "runner token list",
    ].some((needle) => joined.includes(needle)) ||
    args.some((arg) => {
      const lower = arg.toLowerCase();
      return (
        lower.includes("secret") ||
        lower.includes("token") ||
        lower.includes("credential") ||
        lower.includes("access-key") ||
        lower === "iam" ||
        lower === "sts" ||
        lower === "keyvault"
      );
    })
  );
}

function terraformCliArgsAreSensitive(
  provider: string,
  args: string[],
  joined: string,
): boolean {
  if (!["terraform", "terragrunt", "opentofu"].includes(provider)) return false;
  return (
    [
      "login",
      "output -json",
      "output -raw",
      "state pull",
      "state show",
      "show -json",
      "run-all output",
      "run-all state",
    ].some((needle) => joined.includes(needle)) ||
    args.some((arg) => {
      const lower = arg.toLowerCase();
      return (
        lower.includes("tf_token") ||
        lower.includes("terraform_cloud_token") ||
        lower.includes("terraform_token") ||
        lower.includes("tfe_token")
      );
    })
  );
}

function firstNonOptionArgIndex(args: string[]): number | null {
  let index = 0;
  while (index < args.length) {
    const arg = args[index];
    if (!arg) return null;
    if (arg === "--") return index + 1 < args.length ? index + 1 : null;
    if (shellAssignment(arg)) {
      index += 1;
      continue;
    }
    if (arg.startsWith("--")) {
      index += optionTakesValue(arg) && !arg.includes("=") ? 2 : 1;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      index += shortOptionTakesValue(arg) ? 2 : 1;
      continue;
    }
    return index;
  }
  return null;
}

function optionTakesValue(arg: string): boolean {
  return [
    "--prefix",
    "--cwd",
    "--directory",
    "--project",
    "--profile",
    "--region",
    "--subscription",
    "--account",
    "--configuration",
    "--workspace",
  ].includes(arg);
}

function shortOptionTakesValue(arg: string): boolean {
  return ["-C", "-p", "-r", "-c", "-m"].includes(arg);
}

function shellAssignment(arg: string): boolean {
  const [name, value] = arg.split("=", 2);
  return Boolean(name && value && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
}

function executableName(value: string): string {
  const basename = value.split(/[\\/]/).pop() ?? value;
  return basename.replace(/\.(exe|cmd|bat)$/i, "").toLowerCase();
}
