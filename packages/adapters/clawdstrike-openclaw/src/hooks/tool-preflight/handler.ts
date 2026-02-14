/**
 * @clawdstrike/openclaw - Tool Pre-flight Hook Handler
 *
 * Intercepts tool calls BEFORE execution and enforces security policy
 * on destructive operations (file_write, file_delete, shell, bash, command).
 *
 * Read-only operations are skipped here; they are handled by the
 * post-execution tool-guard hook for output sanitization.
 */

import type {
  HookHandler,
  HookEvent,
  ToolCallEvent,
  ClawdstrikeConfig,
  PolicyEvent,
  EventType,
} from '../../types.js';
import { PolicyEngine } from '../../policy/engine.js';

/** Shared policy engine instance */
let engine: PolicyEngine | null = null;

/**
 * Initialize the hook with configuration
 */
export function initialize(config: ClawdstrikeConfig): void {
  engine = new PolicyEngine(config);
}

/**
 * Get or create the policy engine
 */
function getEngine(config?: ClawdstrikeConfig): PolicyEngine {
  if (!engine) {
    engine = new PolicyEngine(config ?? {});
  }
  return engine;
}

/** Read-only tokens: if ANY token matches and no destructive token is present, tool is read-only */
const READ_ONLY_TOKENS = new Set([
  'read', 'list', 'get', 'search', 'view', 'show', 'find', 'describe',
  'info', 'status', 'check', 'ls', 'cat', 'head', 'tail', 'type',
  'which', 'echo', 'pwd', 'env', 'whoami', 'hostname', 'uname', 'date',
  'glob', 'grep',
]);

/** Destructive tokens: if ANY token matches, tool is destructive */
const DESTRUCTIVE_TOKENS = new Set([
  'write', 'delete', 'remove', 'rm', 'kill', 'exec', 'run', 'install',
  'uninstall', 'create', 'update', 'modify', 'patch', 'put', 'post',
  'move', 'mv', 'rename', 'chmod', 'chown', 'drop', 'truncate',
]);

/** Destructive token-to-event-type mapping for specific policy routing */
const DESTRUCTIVE_EVENT_MAP: Array<{ tokens: Set<string>; eventType: EventType }> = [
  { tokens: new Set(['write', 'edit', 'create', 'save', 'overwrite']), eventType: 'file_write' },
  { tokens: new Set(['delete', 'remove', 'unlink', 'rm']), eventType: 'file_write' },
  { tokens: new Set(['shell', 'bash', 'exec', 'command', 'terminal', 'run']), eventType: 'command_exec' },
  { tokens: new Set(['patch', 'diff']), eventType: 'patch_apply' },
];

/** Network tokens for egress classification */
const NETWORK_TOKENS = new Set(['fetch', 'http', 'web', 'curl', 'request']);

/**
 * Tokenize a tool name by splitting on common delimiters.
 */
function tokenize(toolName: string): string[] {
  return toolName.toLowerCase().split(/[_\-/\s.]+/).filter(Boolean);
}

type ToolClassification = 'read_only' | 'destructive' | 'unknown';

/**
 * Classify a tool based on its name tokens.
 * - If ANY token is destructive → destructive
 * - If ANY token is read-only and NO token is destructive → read-only
 * - Otherwise → unknown (treated as potentially destructive)
 */
function classifyTool(tokens: string[]): ToolClassification {
  let hasReadOnly = false;
  let hasDestructive = false;

  for (const token of tokens) {
    if (DESTRUCTIVE_TOKENS.has(token)) {
      hasDestructive = true;
    }
    if (READ_ONLY_TOKENS.has(token)) {
      hasReadOnly = true;
    }
  }

  if (hasDestructive) return 'destructive';
  if (hasReadOnly) return 'read_only';
  return 'unknown';
}

/**
 * Infer the event type for a tool based on its name tokens.
 * Returns null only for confirmed read-only tools.
 * Unknown/unclassified tools return 'tool_call' so they are evaluated.
 */
function inferDestructiveEventType(toolName: string): EventType | null {
  const tokens = tokenize(toolName);
  const classification = classifyTool(tokens);

  if (classification === 'read_only') {
    return null;
  }

  // Check specific destructive event types
  for (const { tokens: matchTokens, eventType } of DESTRUCTIVE_EVENT_MAP) {
    if (tokens.some(t => matchTokens.has(t))) {
      return eventType;
    }
  }

  // Check network tokens
  if (tokens.some(t => NETWORK_TOKENS.has(t))) {
    return 'network_egress';
  }

  // Unknown or unclassified tools: treat as generic tool_call for evaluation
  return 'tool_call';
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
  const eventId = `preflight-${sessionId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const timestamp = new Date().toISOString();

  switch (eventType) {
    case 'file_write': {
      const path = extractPath(params) ?? '';
      return {
        eventId,
        eventType: 'file_write',
        timestamp,
        sessionId,
        data: { type: 'file', path, operation: 'write', content: typeof params.content === 'string' ? params.content : undefined },
        metadata: { toolName, preflight: true },
      };
    }
    case 'command_exec': {
      const cmdLine = typeof params.command === 'string' ? params.command : typeof params.cmd === 'string' ? params.cmd : '';
      const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
      const [command, ...args] = parts.length > 0 ? parts : [''];
      return {
        eventId,
        eventType: 'command_exec',
        timestamp,
        sessionId,
        data: { type: 'command', command, args },
        metadata: { toolName, preflight: true },
      };
    }
    case 'patch_apply': {
      const filePath = typeof params.filePath === 'string' ? params.filePath : typeof params.path === 'string' ? params.path : '';
      const patchContent = typeof params.patch === 'string' ? params.patch : typeof params.content === 'string' ? params.content : '';
      return {
        eventId,
        eventType: 'patch_apply',
        timestamp,
        sessionId,
        data: { type: 'patch', filePath, patchContent },
        metadata: { toolName, preflight: true },
      };
    }
    case 'network_egress': {
      const { host, port, url } = extractNetworkInfo(params);
      return {
        eventId,
        eventType: 'network_egress',
        timestamp,
        sessionId,
        data: { type: 'network', host, port, url },
        metadata: { toolName, preflight: true },
      };
    }
    default: {
      return {
        eventId,
        eventType: 'tool_call',
        timestamp,
        sessionId,
        data: { type: 'tool', toolName, parameters: params },
        metadata: { toolName, preflight: true },
      };
    }
  }
}

function extractPath(params: Record<string, unknown>): string | undefined {
  const pathKeys = ['path', 'file', 'file_path', 'filepath', 'filename', 'target'];
  for (const key of pathKeys) {
    const value = params[key];
    if (typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}

function extractNetworkInfo(params: Record<string, unknown>): { host: string; port: number; url?: string } {
  const url = typeof params.url === 'string' ? params.url
    : typeof params.endpoint === 'string' ? params.endpoint
    : typeof params.href === 'string' ? params.href
    : undefined;
  if (url) {
    try {
      const parsed = new URL(url);
      return {
        host: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80),
        url,
      };
    } catch {
      // Not a valid URL
    }
  }
  const host = typeof params.host === 'string' ? params.host : 'unknown';
  const port = typeof params.port === 'number' ? params.port : 80;
  return { host, port, url };
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
  status: 'pending' | 'resolved' | 'expired';
  resolution: 'allow-once' | 'allow-session' | 'allow-always' | 'deny' | null;
  tool: string;
  resource: string;
  guard: string;
  reason: string;
  severity: string;
}

/**
 * Submit an approval request and poll until resolved or expired.
 * Returns true if the user approved, false otherwise.
 */
async function requestApproval(details: {
  toolName: string;
  resource: string;
  guard: string;
  reason: string;
  severity: string;
  sessionId: string;
}): Promise<boolean> {
  const approvalUrl = process.env.CLAWDSTRIKE_APPROVAL_URL;
  if (!approvalUrl) {
    return false;
  }

  let id: string;
  try {
    const submitRes = await fetch(`${approvalUrl}/api/v1/approval/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
      return false;
    }
    const body = (await submitRes.json()) as ApprovalStatusResponse;
    id = body.id;
  } catch {
    return false;
  }

  const deadline = Date.now() + APPROVAL_POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, APPROVAL_POLL_INTERVAL_MS));

    try {
      const pollRes = await fetch(`${approvalUrl}/api/v1/approval/${id}/status`);
      if (!pollRes.ok) {
        return false;
      }
      const status = (await pollRes.json()) as ApprovalStatusResponse;

      if (status.status === 'resolved') {
        return status.resolution !== null && status.resolution !== 'deny';
      }
      if (status.status === 'expired') {
        return false;
      }
    } catch {
      return false;
    }
  }

  return false;
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
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'tool_call') {
    return;
  }

  const toolEvent = event as ToolCallEvent;
  const { toolName, params } = toolEvent.context.toolCall;
  const sessionId = toolEvent.context.sessionId;

  // Determine if this tool is destructive
  const eventType = inferDestructiveEventType(toolName);
  if (eventType === null) {
    // Confirmed read-only tool: skip pre-flight, let post-execution handle it
    return;
  }

  const policyEngine = getEngine();
  const policyEvent = buildPolicyEvent(sessionId, toolName, params, eventType);
  const decision = await policyEngine.evaluate(policyEvent);

  if (decision.status === 'deny') {
    const resource = extractPath(params) ?? (typeof params.command === 'string' ? params.command : toolName);
    const guard = decision.guard ?? 'unknown';
    const severity = decision.severity ?? 'high';

    // If the denial is non-critical and the approval API is configured,
    // submit an approval request and wait for user resolution.
    if (severity !== 'critical' && process.env.CLAWDSTRIKE_APPROVAL_URL) {
      const approved = await requestApproval({
        toolName,
        resource,
        guard,
        reason: decision.reason ?? 'Policy denied',
        severity,
        sessionId,
      });
      if (approved) {
        toolEvent.messages.push(
          `[clawdstrike] Pre-flight check: ${toolName} on ${resource} was approved by user`,
        );
        return;
      }
    }

    toolEvent.preventDefault = true;
    toolEvent.messages.push(
      `[clawdstrike] Pre-flight check: blocked ${toolName} on ${resource}${decision.reason ? ` — ${decision.reason}` : ''}`,
    );
    return;
  }

  if (decision.status === 'warn') {
    toolEvent.messages.push(
      `[clawdstrike] Pre-flight warning: ${decision.message ?? decision.reason ?? 'Policy warning'} (${toolName})`,
    );
  }
};

export default handler;
