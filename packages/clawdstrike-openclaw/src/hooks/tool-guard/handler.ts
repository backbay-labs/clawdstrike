/**
 * @clawdstrike/openclaw - Tool Guard Hook Handler
 *
 * Intercepts tool results and enforces security policy.
 */

import type {
  HookHandler,
  HookEvent,
  ToolResultPersistEvent,
  ClawdstrikeConfig,
  PolicyEvent,
  ToolEventData,
  FileEventData,
  CommandEventData,
  NetworkEventData,
  PatchEventData,
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

/**
 * Hook handler for tool_result_persist events
 */
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'tool_result_persist') {
    return;
  }

  const toolEvent = event as ToolResultPersistEvent;
  const { toolName, params, result } = toolEvent.context.toolResult;
  const policyEngine = getEngine();

  // Create policy event from tool result
  const policyEvent = createPolicyEvent(
    toolEvent.context.sessionId,
    toolName,
    params,
    result,
  );

  // Evaluate policy
  const decision = await policyEngine.evaluate(policyEvent);

  if (decision.denied) {
    // Block the tool result
    toolEvent.context.toolResult.error = decision.reason ?? 'Policy violation';
    toolEvent.messages.push(
      `[clawdstrike] Blocked by ${decision.guard}: ${decision.reason}`,
    );
    return;
  }

  if (decision.warn) {
    // Add warning message
    toolEvent.messages.push(
      `[clawdstrike] Warning: ${decision.message ?? decision.reason}`,
    );
  }

  function sanitizeUnknown(
    value: unknown,
    sanitizeString: (s: string) => string,
    seen: WeakSet<object>,
    depth: number,
  ): { value: unknown; changed: boolean } {
    if (typeof value === 'string') {
      const sanitized = sanitizeString(value);
      return { value: sanitized, changed: sanitized !== value };
    }

    if (!value || typeof value !== 'object') {
      return { value, changed: false };
    }

    if (seen.has(value)) {
      return { value, changed: false };
    }

    if (depth > 32) {
      return { value, changed: false };
    }

    // Preserve non-plain objects (Dates, Buffers, class instances, etc).
    const isArray = Array.isArray(value);
    const isPlainObject = Object.prototype.toString.call(value) === '[object Object]';
    if (!isArray && !isPlainObject) {
      return { value, changed: false };
    }

    seen.add(value);

    if (isArray) {
      let changed = false;
      const out = (value as unknown[]).map((item) => {
        const r = sanitizeUnknown(item, sanitizeString, seen, depth + 1);
        changed = changed || r.changed;
        return r.value;
      });
      return { value: changed ? out : value, changed };
    }

    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    let changed = false;
    for (const [k, v] of Object.entries(obj)) {
      const r = sanitizeUnknown(v, sanitizeString, seen, depth + 1);
      out[k] = r.value;
      changed = changed || r.changed;
    }
    return { value: changed ? out : value, changed };
  }

  // Redact secrets from output
  if (result && typeof result === 'string') {
    const sanitized = policyEngine.sanitizeOutput(result);
    if (sanitized !== result) {
      toolEvent.context.toolResult.result = sanitized;
    }
  } else if (result && typeof result === 'object') {
    const { value: sanitized, changed } = sanitizeUnknown(
      result,
      (s) => policyEngine.sanitizeOutput(s),
      new WeakSet<object>(),
      0,
    );
    if (changed) {
      toolEvent.context.toolResult.result = sanitized;
    }
  }
};

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
 * Infer event type from tool name
 */
function inferEventType(
  toolName: string,
): PolicyEvent['eventType'] {
  const lowerName = toolName.toLowerCase();

  if (lowerName.includes('patch') || lowerName.includes('diff') || lowerName.includes('apply_patch')) {
    return 'patch_apply';
  }
  if (lowerName.includes('read') || lowerName.includes('cat') || lowerName.includes('head') || lowerName.includes('tail')) {
    return 'file_read';
  }
  if (lowerName.includes('write') || lowerName.includes('edit')) {
    return 'file_write';
  }
  if (lowerName.includes('exec') || lowerName.includes('bash') || lowerName.includes('shell')) {
    return 'command_exec';
  }
  if (lowerName.includes('fetch') || lowerName.includes('http') || lowerName.includes('web') || lowerName.includes('curl')) {
    return 'network_egress';
  }

  return 'tool_call';
}

/**
 * Create event data based on tool name and params
 */
function createEventData(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown,
): PolicyEvent['data'] {
  const eventType = inferEventType(toolName);

  switch (eventType) {
    case 'file_read':
    case 'file_write': {
      const path = extractPath(params);
      const contentHash = typeof params.contentHash === 'string' ? params.contentHash : undefined;
      const { content, contentBase64 } = extractFileContent(params, result, eventType);
      return {
        type: 'file',
        path: path ?? '',
        content,
        contentBase64,
        contentHash,
        operation: eventType === 'file_read' ? 'read' : 'write',
      } as FileEventData;
    }

    case 'network_egress': {
      const { host, port, url } = extractNetworkInfo(params);
      return {
        type: 'network',
        host,
        port,
        url,
      } as NetworkEventData;
    }

    case 'command_exec': {
      const { command, args, workingDir } = extractCommandInfo(params);
      return {
        type: 'command',
        command,
        args,
        workingDir,
      } as CommandEventData;
    }

    case 'patch_apply': {
      const { filePath, patchContent } = extractPatchInfo(params, result);
      return {
        type: 'patch',
        filePath,
        patchContent,
      } as PatchEventData;
    }

    case 'tool_call':
    default: {
      return {
        type: 'tool',
        toolName,
        parameters: params,
        result: typeof result === 'string' ? result : JSON.stringify(result ?? ''),
      } as ToolEventData;
    }
  }
}

/**
 * Extract file path from tool params
 */
function extractPath(params: Record<string, unknown>): string | undefined {
  // Common parameter names for file paths
  const pathKeys = ['path', 'file', 'file_path', 'filepath', 'filename', 'target'];

  for (const key of pathKeys) {
    if (typeof params[key] === 'string') {
      return params[key] as string;
    }
  }

  // Check for path in command string
  if (typeof params.command === 'string') {
    const command = params.command as string;
    // Try to extract path from commands like "cat /path/to/file"
    const match = command.match(/(?:cat|head|tail|less|more|vim|nano|read)\s+([^\s|><]+)/);
    if (match) {
      return match[1];
    }
  }

  return undefined;
}

function extractFileContent(
  params: Record<string, unknown>,
  result: unknown,
  eventType: PolicyEvent['eventType'],
): { content?: string; contentBase64?: string } {
  const maxChars = 2_000_000; // Best-effort cap: avoid huge payloads.

  const contentBase64 =
    typeof params.contentBase64 === 'string'
      ? params.contentBase64
      : typeof params.base64 === 'string'
        ? params.base64
        : undefined;

  if (contentBase64) {
    return { contentBase64: contentBase64.length > maxChars ? contentBase64.slice(0, maxChars) : contentBase64 };
  }

  const content =
    typeof params.content === 'string'
      ? params.content
      : typeof params.text === 'string'
        ? params.text
        : eventType === 'file_read' && typeof result === 'string'
          ? result
          : undefined;

  if (!content) return {};
  return { content: content.length > maxChars ? content.slice(0, maxChars) : content };
}

/**
 * Extract network info from tool params
 */
function extractNetworkInfo(
  params: Record<string, unknown>,
): { host: string; port: number; url?: string } {
  // Try to get URL first
  const url =
    (params.url as string) ??
    (params.endpoint as string) ??
    (params.href as string);

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

  // Try to extract from command
  if (typeof params.command === 'string') {
    const command = params.command as string;
    const urlMatch = command.match(/https?:\/\/[^\s'"]+/);
    if (urlMatch) {
      try {
        const parsed = new URL(urlMatch[0]);
        return {
          host: parsed.hostname,
          port: parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80),
          url: urlMatch[0],
        };
      } catch {
        // Not a valid URL
      }
    }
  }

  // Fallback
  return {
    host: (params.host as string) ?? (params.hostname as string) ?? 'unknown',
    port: (params.port as number) ?? 80,
    url,
  };
}

function extractCommandInfo(
  params: Record<string, unknown>,
): { command: string; args: string[]; workingDir?: string } {
  const workingDir =
    typeof params.cwd === 'string'
      ? params.cwd
      : typeof params.workingDir === 'string'
        ? params.workingDir
        : undefined;

  const args =
    Array.isArray(params.args) && params.args.every((a) => typeof a === 'string')
      ? (params.args as string[])
      : Array.isArray(params.argv) && params.argv.every((a) => typeof a === 'string')
        ? (params.argv as string[])
        : undefined;

  const cmdLine =
    typeof params.command === 'string'
      ? params.command
      : typeof params.cmd === 'string'
        ? params.cmd
        : undefined;

  if (cmdLine) {
    const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
      return { command: '', args: [], workingDir };
    }
    const [command, ...rest] = parts;
    return { command, args: args ?? rest, workingDir };
  }

  if (typeof params.tool === 'string' && args) {
    return { command: params.tool, args, workingDir };
  }

  return { command: '', args: args ?? [], workingDir };
}

function extractPatchInfo(
  params: Record<string, unknown>,
  result: unknown,
): { filePath: string; patchContent: string } {
  const filePath =
    (typeof params.filePath === 'string' && params.filePath) ||
    (typeof params.path === 'string' && params.path) ||
    (typeof params.file === 'string' && params.file) ||
    '';

  const patchContent =
    (typeof params.patch === 'string' && params.patch) ||
    (typeof params.diff === 'string' && params.diff) ||
    (typeof params.content === 'string' && params.content) ||
    (typeof result === 'string' ? result : JSON.stringify(result ?? ''));

  return { filePath, patchContent };
}

export default handler;
