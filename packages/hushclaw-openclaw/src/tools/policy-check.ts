import type { Decision, HushClawConfig, PolicyEvent, ToolDefinition } from '../types.js';
import { PolicyEngine } from '../policy/engine.js';

export type PolicyCheckAction =
  | 'file_read'
  | 'file_write'
  | 'network'
  | 'network_egress'
  | 'command'
  | 'command_exec'
  | 'tool_call';

export interface PolicyCheckResult extends Decision {
  message: string;
  suggestion?: string;
}

function parseNetworkTarget(target: string): { host: string; port: number; url?: string } {
  const trimmed = target.trim();
  if (!trimmed) return { host: '', port: 0 };

  const tryParse = (value: string): { host: string; port: number; url?: string } | null => {
    try {
      const parsed = new URL(value);
      const port = parsed.port ? Number.parseInt(parsed.port, 10) : parsed.protocol === 'http:' ? 80 : 443;
      return { host: parsed.hostname, port, url: value };
    } catch {
      return null;
    }
  };

  return (
    tryParse(trimmed) ??
    tryParse(`https://${trimmed}`) ??
    { host: trimmed.split('/')[0] ?? trimmed, port: 443 }
  );
}

function buildEvent(action: PolicyCheckAction, resource: string): PolicyEvent {
  const now = new Date();
  const eventId = `policy-check-${now.getTime()}-${Math.random().toString(36).slice(2, 8)}`;
  const timestamp = now.toISOString();

  switch (action) {
    case 'file_read':
      return {
        eventId,
        eventType: 'file_read',
        timestamp,
        data: { type: 'file', path: resource, operation: 'read' },
      };
    case 'file_write':
      return {
        eventId,
        eventType: 'file_write',
        timestamp,
        data: { type: 'file', path: resource, operation: 'write' },
      };
    case 'network':
    case 'network_egress': {
      const { host, port, url } = parseNetworkTarget(resource);
      return {
        eventId,
        eventType: 'network_egress',
        timestamp,
        data: { type: 'network', host, port, url },
      };
    }
    case 'command':
    case 'command_exec': {
      const parts = resource.trim().split(/\s+/).filter(Boolean);
      const [command, ...args] = parts;
      return {
        eventId,
        eventType: 'command_exec',
        timestamp,
        data: { type: 'command', command: command ?? '', args },
      };
    }
    case 'tool_call':
    default:
      return {
        eventId,
        eventType: 'tool_call',
        timestamp,
        data: { type: 'tool', toolName: resource, parameters: {} },
      };
  }
}

function formatDecision(decision: Decision): string {
  if (decision.denied) {
    const guard = decision.guard ? ` by ${decision.guard}` : '';
    const reason = decision.reason ? `: ${decision.reason}` : '';
    return `Denied${guard}${reason}`;
  }
  if (decision.warn) {
    const msg = decision.message ?? decision.reason ?? 'Policy warning';
    return `Warning: ${msg}`;
  }
  return 'Action allowed';
}

export async function checkPolicy(
  config: HushClawConfig,
  action: PolicyCheckAction,
  resource: string,
): Promise<PolicyCheckResult> {
  const engine = new PolicyEngine(config);
  const event = buildEvent(action, resource);
  const decision = await engine.evaluate(event);
  return { ...decision, message: formatDecision(decision), suggestion: decision.denied ? getSuggestion(action, resource) : undefined };
}

export function policyCheckTool(engine: PolicyEngine): ToolDefinition {
  return {
    name: 'policy_check',
    description: 'Check if an action is allowed by the security policy. Use this BEFORE attempting potentially restricted operations.',
    schema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['file_read', 'file_write', 'network', 'command', 'tool_call'],
          description: 'The type of action to check',
        },
        resource: {
          type: 'string',
          description: 'The resource to check (path, domain, command, or tool name)',
        },
      },
      required: ['action', 'resource'],
    },
    execute: async (params) => {
      const action = (params.action as PolicyCheckAction) ?? 'tool_call';
      const resource = typeof params.resource === 'string' ? params.resource : '';
      const event = buildEvent(action, resource);
      const decision = await engine.evaluate(event);
      return {
        ...decision,
        message: formatDecision(decision),
        suggestion: decision.denied ? getSuggestion(action, resource) : undefined,
      };
    },
  };
}

function getSuggestion(action: string, resource: string): string {
  if ((action === 'file_write' || action === 'file_read') && resource.includes('.ssh')) {
    return 'SSH keys are protected. Consider using a different credential storage method.';
  }
  if ((action === 'file_write' || action === 'file_read') && resource.includes('.aws')) {
    return 'AWS credentials are protected. Use environment variables or IAM roles instead.';
  }
  if (action === 'network_egress' || action === 'network') {
    return 'Try using an allowed domain like api.github.com or pypi.org.';
  }
  if ((action === 'command_exec' || action === 'command') && resource.includes('sudo')) {
    return 'Privileged commands are restricted. Try running without sudo.';
  }
  if ((action === 'command_exec' || action === 'command') && (resource.includes('rm -rf') || resource.includes('dd if='))) {
    return 'Destructive commands are blocked. Consider safer alternatives.';
  }
  return 'Consider an alternative approach that works within the security policy.';
}
