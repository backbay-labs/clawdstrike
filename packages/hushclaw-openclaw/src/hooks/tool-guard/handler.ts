/**
 * @hushclaw/openclaw - Tool Guard Hook Handler
 *
 * Intercepts tool results and enforces security policy.
 */

import type {
  HookHandler,
  HookEvent,
  ToolResultPersistEvent,
  HushClawConfig,
  PolicyEvent,
  ToolEventData,
  FileEventData,
  NetworkEventData,
} from '../../types.js';
import { PolicyEngine } from '../../policy/engine.js';

/** Shared policy engine instance */
let engine: PolicyEngine | null = null;

/**
 * Initialize the hook with configuration
 */
export function initialize(config: HushClawConfig): void {
  engine = new PolicyEngine(config);
}

/**
 * Get or create the policy engine
 */
function getEngine(config?: HushClawConfig): PolicyEngine {
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
      `[hushclaw] Blocked by ${decision.guard}: ${decision.reason}`,
    );
    return;
  }

  if (decision.warn) {
    // Add warning message
    toolEvent.messages.push(
      `[hushclaw] Warning: ${decision.message ?? decision.reason}`,
    );
  }

  // Redact secrets from output
  if (result && typeof result === 'string') {
    const redacted = policyEngine.redactSecrets(result);
    if (redacted !== result) {
      toolEvent.context.toolResult.result = redacted;
    }
  } else if (result && typeof result === 'object') {
    // Try to redact secrets in JSON result
    try {
      const stringified = JSON.stringify(result);
      const redacted = policyEngine.redactSecrets(stringified);
      if (redacted !== stringified) {
        toolEvent.context.toolResult.result = JSON.parse(redacted);
      }
    } catch {
      // Ignore JSON errors
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

  if (lowerName.includes('read') || lowerName.includes('cat') || lowerName.includes('head') || lowerName.includes('tail')) {
    return 'file_read';
  }
  if (lowerName.includes('write') || lowerName.includes('edit') || lowerName.includes('patch')) {
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
      return {
        type: 'file',
        path: path ?? '',
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

export default handler;
