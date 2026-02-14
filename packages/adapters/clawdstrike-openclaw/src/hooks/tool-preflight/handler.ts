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

/** Tool names that map to destructive action types */
const DESTRUCTIVE_PATTERNS: Array<{ pattern: RegExp; eventType: EventType }> = [
  { pattern: /write|edit|create|save|overwrite/i, eventType: 'file_write' },
  { pattern: /delete|remove|unlink|rm\b/i, eventType: 'file_write' },
  { pattern: /shell|bash|exec|command|terminal|run/i, eventType: 'command_exec' },
  { pattern: /patch|apply_patch|diff/i, eventType: 'patch_apply' },
];

/** Tool names that are known read-only */
const READ_ONLY_PATTERNS = /read|cat|head|tail|glob|grep|search|list|ls|find|view|inspect/i;

/**
 * Infer whether a tool is destructive and what event type it maps to.
 * Returns null if the tool is read-only or unknown (skip pre-flight).
 */
function inferDestructiveEventType(toolName: string): EventType | null {
  const lower = toolName.toLowerCase();

  // Skip known read-only tools
  if (READ_ONLY_PATTERNS.test(lower)) {
    return null;
  }

  for (const { pattern, eventType } of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(lower)) {
      return eventType;
    }
  }

  // Network-related tools
  if (/fetch|http|web|curl|request/i.test(lower)) {
    return 'network_egress';
  }

  return null;
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

/**
 * Hook handler for tool_call (pre-execution) events.
 *
 * If the tool is destructive, evaluates the policy engine.
 * On deny: sets preventDefault = true and adds a block message.
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
    // Read-only or unknown tool: skip pre-flight, let post-execution handle it
    return;
  }

  const policyEngine = getEngine();
  const policyEvent = buildPolicyEvent(sessionId, toolName, params, eventType);
  const decision = await policyEngine.evaluate(policyEvent);

  if (decision.status === 'deny') {
    toolEvent.preventDefault = true;
    const resource = extractPath(params) ?? (typeof params.command === 'string' ? params.command : toolName);
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
