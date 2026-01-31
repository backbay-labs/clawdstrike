/**
 * @hushclaw/openclaw - Policy Check Tool
 *
 * Agent-callable tool to query security policy before risky operations.
 */

import type {
  ToolDefinition,
  PolicyEvent,
  Decision,
  HushClawConfig,
} from '../types.js';
import { PolicyEngine } from '../policy/engine.js';

/**
 * Create the policy_check tool for agent use
 */
export function policyCheckTool(engine: PolicyEngine): ToolDefinition {
  return {
    name: 'policy_check',
    description:
      'Check if an action is allowed by the security policy. Use before risky operations like file access, network requests, or command execution.',
    schema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: [
            'file_read',
            'file_write',
            'network',
            'command',
            'tool_call',
          ],
          description: 'Type of action to check',
        },
        resource: {
          type: 'string',
          description:
            'Resource to check (file path, domain, command, or tool name)',
        },
        params: {
          type: 'object',
          description: 'Additional parameters for the check (optional)',
        },
      },
      required: ['action', 'resource'],
    },
    execute: async (params: Record<string, unknown>) => {
      const action = params.action as string;
      const resource = params.resource as string;
      const extraParams = (params.params as Record<string, unknown>) ?? {};

      // Create policy event for evaluation
      const event = createPolicyEvent(action, resource, extraParams);

      // Evaluate against policy
      const decision = await engine.evaluate(event);

      // Return simplified result for agent
      return {
        allowed: decision.allowed,
        denied: decision.denied,
        reason: decision.reason,
        guard: decision.guard,
        severity: decision.severity,
        message: formatMessage(decision),
      };
    },
  };
}

/**
 * Create a PolicyEvent from action and resource
 */
function createPolicyEvent(
  action: string,
  resource: string,
  params: Record<string, unknown>,
): PolicyEvent {
  const eventId = `check-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const timestamp = new Date().toISOString();

  switch (action) {
    case 'file_read':
      return {
        eventId,
        eventType: 'file_read',
        timestamp,
        data: {
          type: 'file',
          path: resource,
          operation: 'read',
        },
      };

    case 'file_write':
      return {
        eventId,
        eventType: 'file_write',
        timestamp,
        data: {
          type: 'file',
          path: resource,
          operation: 'write',
        },
      };

    case 'network':
      return {
        eventId,
        eventType: 'network_egress',
        timestamp,
        data: {
          type: 'network',
          host: extractHost(resource),
          port: extractPort(resource),
          url: resource.includes('://') ? resource : undefined,
        },
      };

    case 'command':
      return {
        eventId,
        eventType: 'command_exec',
        timestamp,
        data: {
          type: 'command',
          command: resource,
          args: (params.args as string[]) ?? [],
        },
      };

    case 'tool_call':
    default:
      return {
        eventId,
        eventType: 'tool_call',
        timestamp,
        data: {
          type: 'tool',
          toolName: resource,
          parameters: params,
        },
      };
  }
}

/**
 * Extract hostname from URL or domain string
 */
function extractHost(resource: string): string {
  try {
    if (resource.includes('://')) {
      return new URL(resource).hostname;
    }
    // Assume it's already a hostname
    return resource.split(':')[0];
  } catch {
    return resource;
  }
}

/**
 * Extract port from URL or domain:port string
 */
function extractPort(resource: string): number {
  try {
    if (resource.includes('://')) {
      const url = new URL(resource);
      if (url.port) {
        return parseInt(url.port, 10);
      }
      return url.protocol === 'https:' ? 443 : 80;
    }
    // Check for domain:port format
    const parts = resource.split(':');
    if (parts.length === 2) {
      return parseInt(parts[1], 10);
    }
    return 443; // Default to HTTPS
  } catch {
    return 443;
  }
}

/**
 * Format a human-readable message from decision
 */
function formatMessage(decision: Decision): string {
  if (decision.denied) {
    return `Denied by ${decision.guard}: ${decision.reason}`;
  }
  if (decision.warn) {
    return `Warning: ${decision.message ?? decision.reason}`;
  }
  return 'Action is allowed by policy';
}

/**
 * Standalone policy check function (for use without full plugin)
 */
export async function checkPolicy(
  config: HushClawConfig,
  action: string,
  resource: string,
  params: Record<string, unknown> = {},
): Promise<{
  allowed: boolean;
  denied: boolean;
  reason?: string;
  guard?: string;
  message: string;
}> {
  const engine = new PolicyEngine(config);
  const event = createPolicyEvent(action, resource, params);
  const decision = await engine.evaluate(event);

  return {
    allowed: decision.allowed,
    denied: decision.denied,
    reason: decision.reason,
    guard: decision.guard,
    message: formatMessage(decision),
  };
}
