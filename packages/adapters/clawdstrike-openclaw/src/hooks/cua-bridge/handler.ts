/**
 * @clawdstrike/openclaw - CUA Bridge Hook Handler
 *
 * Detects CUA (Computer Use Agent) actions from OpenClaw tool calls and emits
 * canonical CUA policy events via PolicyEventFactory from adapter-core.
 *
 * CUA actions are identified by toolName prefix or explicit metadata. When
 * detected, the bridge creates the appropriate canonical CUA event, evaluates
 * it through the policy engine, and applies the decision (allow/warn/deny).
 *
 * Design: fail-closed on unknown CUA action types. Non-CUA tool calls are
 * passed through unchanged (no regression on existing behavior).
 */

import {
  parseNetworkTarget,
  PolicyEventFactory,
  type CuaEventData,
  type Decision,
  type PolicyEvent,
} from '@clawdstrike/adapter-core';
import type {
  HookHandler,
  HookEvent,
  ToolCallEvent,
  BeforeToolCallHookEvent,
  BeforeToolCallHookResult,
  OpenClawHookContext,
  ClawdstrikeConfig,
} from '../../types.js';
import { initializeEngine, getSharedEngine } from '../../engine-holder.js';
import { peekApproval } from '../approval-state.js';
import { normalizeApprovalResource } from '../approval-utils.js';

// ── Stable Error Codes ──────────────────────────────────────────────

export const CUA_ERROR_CODES = {
  UNKNOWN_ACTION: 'OCLAW_CUA_UNKNOWN_ACTION',
  MISSING_METADATA: 'OCLAW_CUA_MISSING_METADATA',
  SESSION_MISSING: 'OCLAW_CUA_SESSION_MISSING',
} as const;

// ── CUA Action Classification ───────────────────────────────────────

/** CUA tool name prefixes that trigger CUA bridge routing. */
const CUA_TOOL_PREFIXES = [
  'cua_', 'cua.', 'computer_use_', 'computer_use.',
  'remote_desktop_', 'remote_desktop.', 'rdp_', 'rdp.',
] as const;
const CUA_TOOL_NAMES = new Set(['computer', 'computer_use', 'computer.use', 'computer-use']);

/** Maps recognized CUA action tokens to factory method selectors. */
type CuaActionKind =
  | 'connect'
  | 'disconnect'
  | 'reconnect'
  | 'input_inject'
  | 'clipboard_read'
  | 'clipboard_write'
  | 'file_upload'
  | 'file_download'
  | 'session_share'
  | 'audio'
  | 'drive_mapping'
  | 'printing';

const ACTION_TOKEN_MAP: ReadonlyArray<{ tokens: ReadonlyArray<string>; kind: CuaActionKind }> = [
  { tokens: ['connect', 'session_start', 'open', 'launch'], kind: 'connect' },
  { tokens: ['disconnect', 'session_end', 'close', 'terminate'], kind: 'disconnect' },
  { tokens: ['reconnect', 'session_resume', 'resume'], kind: 'reconnect' },
  { tokens: ['click', 'type', 'key', 'mouse', 'keyboard', 'input', 'scroll', 'drag', 'move_mouse'], kind: 'input_inject' },
  { tokens: ['clipboard_read', 'clipboard_get', 'paste_from', 'copy_from_remote'], kind: 'clipboard_read' },
  { tokens: ['clipboard_write', 'clipboard_set', 'copy_to', 'paste_to_remote'], kind: 'clipboard_write' },
  { tokens: ['file_upload', 'upload', 'send_file'], kind: 'file_upload' },
  { tokens: ['file_download', 'download', 'receive_file', 'get_file'], kind: 'file_download' },
  { tokens: ['session_share', 'share_session', 'share'], kind: 'session_share' },
  { tokens: ['audio', 'audio_stream', 'stream_audio'], kind: 'audio' },
  { tokens: ['drive_mapping', 'map_drive', 'mount_drive'], kind: 'drive_mapping' },
  { tokens: ['printing', 'print', 'remote_print'], kind: 'printing' },
];

// ── Module State ────────────────────────────────────────────────────

const factory = new PolicyEventFactory();

/**
 * Initialize the hook with configuration.
 * Delegates to the shared engine holder so all hooks share one PolicyEngine.
 */
export function initialize(config: ClawdstrikeConfig): void {
  initializeEngine(config);
}

/**
 * Get or create the policy engine.
 * Delegates to the shared engine holder.
 */
function getEngine(config?: ClawdstrikeConfig): PolicyEngine {
  return getSharedEngine(config);
}

// Import PolicyEngine type for return type annotations.
import type { PolicyEngine } from '../../policy/engine.js';

// ── CUA Detection ───────────────────────────────────────────────────

/**
 * Check if a tool call is a CUA action (by prefix or explicit cua metadata).
 */
export function isCuaToolCall(
  toolName: string,
  params: Record<string, unknown>,
): boolean {
  const lower = toolName.toLowerCase();
  if (CUA_TOOL_NAMES.has(lower)) {
    return true;
  }
  if (CUA_TOOL_PREFIXES.some((p) => lower.startsWith(p))) {
    return true;
  }
  if (params.__cua === true || params.cua_action !== undefined) {
    return true;
  }
  return false;
}

/**
 * Extract the CUA action token from a tool name or params.
 */
function extractActionToken(
  toolName: string,
  params: Record<string, unknown>,
): string | null {
  // Explicit action from params takes precedence
  if (typeof params.cua_action === 'string' && params.cua_action.trim()) {
    return params.cua_action.trim().toLowerCase();
  }

  if (CUA_TOOL_NAMES.has(toolName.toLowerCase())) {
    if (typeof params.action === 'string' && params.action.trim()) {
      return params.action.trim().toLowerCase();
    }
  }

  // Strip known CUA prefix and use remaining as action token
  const lower = toolName.toLowerCase();
  for (const prefix of CUA_TOOL_PREFIXES) {
    if (lower.startsWith(prefix)) {
      const remainder = lower.slice(prefix.length);
      if (remainder) return remainder;
    }
  }

  return null;
}

/**
 * Classify a CUA action token into a known CuaActionKind.
 * Returns null for unknown actions (fail-closed).
 */
function classifyCuaAction(token: string): CuaActionKind | null {
  for (const { tokens, kind } of ACTION_TOKEN_MAP) {
    if (tokens.includes(token)) {
      return kind;
    }
  }
  return null;
}

// ── Event Building ──────────────────────────────────────────────────

/**
 * Build a canonical CUA PolicyEvent using the PolicyEventFactory.
 */
export function buildCuaEvent(
  sessionId: string,
  kind: CuaActionKind,
  params: Record<string, unknown>,
): PolicyEvent {
  const extraData: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>> = {};

  if (typeof params.continuityPrevSessionHash === 'string') {
    extraData.continuityPrevSessionHash = params.continuityPrevSessionHash;
  }
  if (typeof params.postconditionProbeHash === 'string') {
    extraData.postconditionProbeHash = params.postconditionProbeHash;
  }
  // Preserve input_type so the InputInjectionCapabilityGuard (fail-closed on
  // missing input_type) receives it through the canonical CUA event data.
  const inputType = typeof params.input_type === 'string'
    ? params.input_type
    : typeof params.inputType === 'string'
      ? params.inputType
      : undefined;
  if (typeof inputType === 'string') {
    (extraData as Record<string, unknown>).input_type = inputType;
  }

  const transferSize = coerceTransferSize(params.transfer_size ?? params.transferSize);
  if (transferSize !== null) {
    (extraData as Record<string, unknown>).transfer_size = transferSize;
  }

  switch (kind) {
    case 'connect': {
      const connectMeta = extractConnectMetadata(params);
      return factory.createCuaConnectEvent(sessionId, { ...extraData, ...connectMeta });
    }
    case 'disconnect':
      return factory.createCuaDisconnectEvent(sessionId, extraData);
    case 'reconnect':
      return factory.createCuaReconnectEvent(sessionId, extraData);
    case 'input_inject':
      return factory.createCuaInputInjectEvent(sessionId, extraData);
    case 'clipboard_read':
      return factory.createCuaClipboardEvent(sessionId, 'read', extraData);
    case 'clipboard_write':
      return factory.createCuaClipboardEvent(sessionId, 'write', extraData);
    case 'file_upload':
      return factory.createCuaFileTransferEvent(sessionId, 'upload', extraData);
    case 'file_download':
      return factory.createCuaFileTransferEvent(sessionId, 'download', extraData);
    case 'session_share':
      return factory.createCuaSessionShareEvent(sessionId, extraData);
    case 'audio':
      return factory.createCuaAudioEvent(sessionId, extraData);
    case 'drive_mapping':
      return factory.createCuaDriveMappingEvent(sessionId, extraData);
    case 'printing':
      return factory.createCuaPrintingEvent(sessionId, extraData);
  }
}

// ── Hook Handler ────────────────────────────────────────────────────

function beforeToolCallBlockResult(
  toolEvent: ToolCallEvent,
  blockReason: string,
): BeforeToolCallHookResult | void {
  if (toolEvent.type !== 'before_tool_call') {
    return;
  }
  return {
    block: true,
    blockReason,
    params: toolEvent.context.toolCall.params,
  };
}

/**
 * CUA bridge hook handler for tool_call (pre-execution) events.
 *
 * Only activates for CUA tool calls. Non-CUA tools pass through untouched
 * so existing preflight behavior is preserved.
 *
 * Fail-closed: unknown CUA action types are denied with stable error code.
 * Missing session ID or CUA metadata also fail closed.
 */
const handler: HookHandler = async (
  event: HookEvent | BeforeToolCallHookEvent,
  hookCtx?: OpenClawHookContext,
): Promise<void | BeforeToolCallHookResult> => {
  const isModernBeforeToolCallEvent = (value: HookEvent | BeforeToolCallHookEvent): value is BeforeToolCallHookEvent => {
    if (value && typeof value === 'object' && 'type' in value) return false;
    return Boolean(
      value &&
      typeof value === 'object' &&
      typeof (value as { toolName?: unknown }).toolName === 'string' &&
      typeof (value as { params?: unknown }).params === 'object' &&
      (value as { params?: unknown }).params !== null,
    );
  };

  const isModern = isModernBeforeToolCallEvent(event);
  if (!isModern) {
    if (event.type !== 'tool_call' && event.type !== 'before_tool_call') {
      return;
    }
  }

  const legacyToolEvent = isModern ? null : event as ToolCallEvent;

  // Skip if already handled by another hook registration (e.g. before_tool_call + tool_call dual registration)
  if (!isModern && legacyToolEvent!.preventDefault) return;
  const toolName = isModern ? event.toolName : legacyToolEvent!.context.toolCall.toolName;
  const params = isModern ? event.params : legacyToolEvent!.context.toolCall.params;
  const sessionId = isModern
    ? (hookCtx?.sessionKey ?? hookCtx?.agentId ?? '')
    : legacyToolEvent!.context.sessionId;

  // Only intercept CUA tool calls
  if (!isCuaToolCall(toolName, params)) {
    return;
  }

  // Mark this event as evaluated by the CUA bridge so the general preflight
  // handler skips it (avoids double policy evaluation).  Set this early —
  // before any fail-closed exits — because even a CUA denial here means the
  // tool was already handled and the preflight handler should not re-evaluate.
  (event as any).__cuaBridgeEvaluated = true;

  // Fail closed: session ID required for CUA actions
  if (!sessionId) {
    const blockReason = `Denied ${toolName}: missing session ID (${CUA_ERROR_CODES.SESSION_MISSING})`;
    if (isModern) {
      return { block: true, blockReason, params };
    }
    legacyToolEvent!.preventDefault = true;
    legacyToolEvent!.messages.push(`[clawdstrike:cua-bridge] ${blockReason}`);
    return beforeToolCallBlockResult(legacyToolEvent!, blockReason);
  }

  // Extract and classify the CUA action
  const actionToken = extractActionToken(toolName, params);
  if (!actionToken) {
    const blockReason =
      `Denied ${toolName}: unable to extract CUA action from tool name or params (${CUA_ERROR_CODES.MISSING_METADATA})`;
    if (isModern) {
      return { block: true, blockReason, params };
    }
    legacyToolEvent!.preventDefault = true;
    legacyToolEvent!.messages.push(`[clawdstrike:cua-bridge] ${blockReason}`);
    return beforeToolCallBlockResult(legacyToolEvent!, blockReason);
  }

  const kind = classifyCuaAction(actionToken);
  if (!kind) {
    // Fail closed on unknown CUA action type
    const blockReason =
      `Denied ${toolName}: unknown CUA action '${actionToken}' (${CUA_ERROR_CODES.UNKNOWN_ACTION})`;
    if (isModern) {
      return { block: true, blockReason, params };
    }
    legacyToolEvent!.preventDefault = true;
    legacyToolEvent!.messages.push(`[clawdstrike:cua-bridge] ${blockReason}`);
    return beforeToolCallBlockResult(legacyToolEvent!, blockReason);
  }

  // Build canonical CUA event via PolicyEventFactory
  const cuaEvent = buildCuaEvent(sessionId, kind, params);

  // Evaluate through policy engine first to get severity before consulting prior approvals.
  const policyEngine = getEngine();
  const decision: Decision = await policyEngine.evaluate(cuaEvent);

  // Check prior approvals for non-critical denials only.
  // Critical denials must always be re-evaluated and never short-circuited.
  if (decision.status === 'deny' && decision.severity !== 'critical') {
    const resource = normalizeApprovalResource(policyEngine, toolName, params);
    const prior = peekApproval(sessionId, toolName, resource);
    if (prior) {
      if (!isModern) {
        legacyToolEvent!.messages.push(
          `[clawdstrike:cua-bridge] CUA ${kind}: using prior ${prior.resolution} approval for ${toolName}`,
        );
      }
      return;
    }
  }

  if (decision.status === 'deny') {
    const blockReason =
      `CUA ${kind} denied${decision.guard ? ` by ${decision.guard}` : ''}${decision.reason ? `: ${decision.reason}` : ''} (${toolName})`;
    if (isModern) {
      return { block: true, blockReason, params };
    }
    legacyToolEvent!.preventDefault = true;
    legacyToolEvent!.messages.push(`[clawdstrike:cua-bridge] ${blockReason}`);
    return beforeToolCallBlockResult(legacyToolEvent!, blockReason);
  }

  if (!isModern && decision.status === 'warn') {
    legacyToolEvent!.messages.push(
      `[clawdstrike:cua-bridge] CUA ${kind} warning: ${decision.message ?? decision.reason ?? 'Policy warning'} (${toolName})`,
    );
  }

  // Allow: record for potential post-exec parity
  if (!isModern && decision.status === 'allow') {
    legacyToolEvent!.messages.push(
      `[clawdstrike:cua-bridge] CUA ${kind} allowed (${toolName})`,
    );
  }
};

export default handler;

// Re-export for testing
export {
  classifyCuaAction,
  extractActionToken,
  type CuaActionKind,
};

function coerceTransferSize(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return null;
}

function coercePort(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const port = Math.trunc(value);
    if (port > 0 && port <= 65535) return port;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^[0-9]+$/.test(trimmed)) {
      const parsed = Number.parseInt(trimmed, 10);
      if (Number.isFinite(parsed) && parsed > 0 && parsed <= 65535) return parsed;
    }
  }
  return null;
}

function firstNonEmptyString(values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return null;
}

function extractConnectMetadata(params: Record<string, unknown>): Partial<CuaEventData> {
  const url = firstNonEmptyString([
    params.url,
    params.endpoint,
    params.href,
    params.target_url,
    params.targetUrl,
  ]);
  const parsed = parseNetworkTarget(url ?? '', { emptyPort: 'default' });
  const host = firstNonEmptyString([
    params.host,
    params.hostname,
    params.remote_host,
    params.remoteHost,
    params.destination_host,
    params.destinationHost,
    parsed.host,
  ])?.toLowerCase();
  const protocol = firstNonEmptyString([params.protocol, params.scheme])?.toLowerCase();
  const explicitPort = coercePort(
    params.port
      ?? params.remote_port
      ?? params.remotePort
      ?? params.destination_port
      ?? params.destinationPort,
  );

  const out: Partial<CuaEventData> = {};
  if (host) (out as Record<string, unknown>).host = host;
  if (explicitPort !== null) {
    (out as Record<string, unknown>).port = explicitPort;
  } else if (parsed.host) {
    (out as Record<string, unknown>).port = parsed.port;
  }
  if (url) (out as Record<string, unknown>).url = url;
  if (protocol) (out as Record<string, unknown>).protocol = protocol;
  return out;
}
