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

import type {
  HookHandler,
  HookEvent,
  ToolCallEvent,
  ClawdstrikeConfig,
  PolicyEvent,
  EventType,
} from '../../types.js';
import { PolicyEngine } from '../../policy/engine.js';
import { peekApproval, recordApproval, type ApprovalResolutionType } from '../approval-state.js';
import { extractPath, normalizeApprovalResource } from '../approval-utils.js';

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
  'edit', 'command', 'bash', 'save', 'overwrite', 'unlink', 'terminal',
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
 * Tokenize a tool name by splitting on common delimiters and camel-case boundaries.
 */
function tokenize(toolName: string): string[] {
  return toolName
    // Split `fooBar` -> `foo Bar`, `HTTPFetch` -> `HTTP Fetch`
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[_\-/\s.]+/)
    .filter(Boolean);
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
 * Infer the event type for a tool based on its name tokens and parameters.
 *
 * Returns null for confirmed read-only tools that do not appear to touch the filesystem.
 * Unknown/unclassified tools are still evaluated (best-effort inference).
 */
function inferPolicyEventType(toolName: string, params: Record<string, unknown>): EventType | null {
  const tokens = tokenize(toolName);
  const classification = classifyTool(tokens);

  if (classification === 'read_only') {
    // Read-only tools can still be risky if they touch forbidden paths OR perform network egress.
    // Do not skip preflight egress checks (eg. web_search/http_get) just because the tool name
    // contains a read-only token like "get" or "search".
    if (tokens.some(t => NETWORK_TOKENS.has(t)) || looksLikeNetworkEgress(params)) {
      return 'network_egress';
    }

    // If it looks like a filesystem read, evaluate it as file_read.
    const p = extractPath(params);
    if (p) return 'file_read';
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

  // Unknown/unclassified tools: infer from parameters (do not skip).
  if (looksLikePatchApply(params)) return 'patch_apply';
  if (looksLikeCommandExec(params)) return 'command_exec';
  if (looksLikeNetworkEgress(params)) return 'network_egress';

  const p = extractPath(params);
  if (p) {
    return looksLikeFileWrite(params) ? 'file_write' : 'file_read';
  }

  // Fall back to tool_call so tool allow/deny lists and defense-in-depth checks can run.
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
    case 'file_read': {
      const path = extractPath(params) ?? '';
      return {
        eventId,
        eventType: 'file_read',
        timestamp,
        sessionId,
        data: { type: 'file', path, operation: 'read' },
        metadata: { toolName, preflight: true },
      };
    }
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
      const cmdLine =
        typeof params.command === 'string'
          ? params.command
          : typeof params.cmd === 'string'
            ? params.cmd
            : '';

      // Some tools pass argv-style params (args/argv) instead of a shell command line.
      const argv =
        Array.isArray(params.argv) && params.argv.every((a) => typeof a === 'string')
          ? (params.argv as string[])
          : Array.isArray(params.args) && params.args.every((a) => typeof a === 'string')
            ? (params.args as string[])
            : null;

      let command = '';
      let args: string[] = [];

      if (cmdLine.trim()) {
        const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
        command = parts[0] ?? '';
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
        port: parsed.port
          ? parseInt(parsed.port, 10)
          : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80),
        url,
      };
    } catch {
      // Not a valid URL
    }
  }
  const host =
    typeof params.host === 'string'
      ? params.host
      : typeof params.hostname === 'string'
        ? params.hostname
        : 'unknown';
  const port = typeof params.port === 'number' ? params.port : 80;
  return { host, port, url };
}

function looksLikePatchApply(params: Record<string, unknown>): boolean {
  return typeof params.patch === 'string'
    || typeof params.diff === 'string'
    || typeof params.patchContent === 'string'
    || typeof params.filePath === 'string';
}

function looksLikeCommandExec(params: Record<string, unknown>): boolean {
  if (typeof params.command === 'string' || typeof params.cmd === 'string') return true;
  if (Array.isArray(params.args) && params.args.every((a) => typeof a === 'string')) return true;
  if (Array.isArray(params.argv) && params.argv.every((a) => typeof a === 'string')) return true;
  return false;
}

function looksLikeNetworkEgress(params: Record<string, unknown>): boolean {
  if (typeof params.url === 'string' || typeof params.endpoint === 'string' || typeof params.href === 'string') return true;
  if (typeof params.host === 'string' || typeof params.hostname === 'string') return true;
  return false;
}

function looksLikeFileWrite(params: Record<string, unknown>): boolean {
  // Common write payload keys used by various tool APIs.
  if (typeof params.content === 'string') return true;
  if (typeof params.text === 'string') return true;
  if (typeof params.contentBase64 === 'string') return true;
  if (typeof params.base64 === 'string') return true;
  if (typeof params.patch === 'string' || typeof params.diff === 'string') return true;
  if (typeof params.operation === 'string') {
    const op = params.operation.toLowerCase();
    if (op === 'write' || op === 'append' || op === 'delete' || op === 'remove' || op === 'truncate') return true;
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
    console.warn('[clawdstrike] CLAWDSTRIKE_APPROVAL_URL is set but CLAWDSTRIKE_AGENT_TOKEN is missing — skipping approval request');
    return null;
  }

  const authHeaders = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token,
  };

  let id: string;
  try {
    const submitRes = await fetch(`${approvalUrl}/api/v1/approval/request`, {
      method: 'POST',
      headers: authHeaders,
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
    await new Promise((resolve) => setTimeout(resolve, APPROVAL_POLL_INTERVAL_MS));

    try {
      const pollRes = await fetch(`${approvalUrl}/api/v1/approval/${id}/status`, {
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (!pollRes.ok) {
        return null;
      }
      const status = (await pollRes.json()) as ApprovalStatusResponse;

      if (status.status === 'resolved') {
        if (status.resolution !== null && status.resolution !== 'deny') {
          return status;
        }
        return null;
      }
      if (status.status === 'expired') {
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
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'tool_call') {
    return;
  }

  const toolEvent = event as ToolCallEvent;
  const { toolName, params } = toolEvent.context.toolCall;
  const sessionId = toolEvent.context.sessionId;

  // Determine if this tool is destructive
  const eventType = inferPolicyEventType(toolName, params);
  if (eventType === null) {
    // Confirmed read-only tool: skip pre-flight, let post-execution handle it
    return;
  }

  const policyEngine = getEngine();
  const policyEvent = buildPolicyEvent(sessionId, toolName, params, eventType);
  const decision = await policyEngine.evaluate(policyEvent);

  if (decision.status === 'deny') {
    const resource = normalizeApprovalResource(policyEngine, toolName, params);
    const guard = decision.guard ?? 'unknown';
    const severity = decision.severity ?? 'high';

    // If the user previously approved this exact action for this session (or globally),
    // honor it and avoid re-prompting.
    if (severity !== 'critical') {
      const prior = peekApproval(sessionId, toolName, resource);
      if (prior) {
        toolEvent.messages.push(
          `[clawdstrike] Pre-flight check: using prior ${prior.resolution} approval for ${toolName} on ${resource}`,
        );
        return;
      }
    }

    // If the denial is non-critical and the approval API is configured,
    // submit an approval request and wait for user resolution.
    if (severity !== 'critical' && process.env.CLAWDSTRIKE_APPROVAL_URL) {
      const approvalResult = await requestApproval({
        toolName,
        resource,
        guard,
        reason: decision.reason ?? 'Policy denied',
        severity,
        sessionId,
      });
      if (approvalResult) {
        const resolution = approvalResult.resolution as ApprovalResolutionType;
        recordApproval(sessionId, toolName, resource, resolution);
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
