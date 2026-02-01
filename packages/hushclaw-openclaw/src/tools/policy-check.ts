import type { PolicyEngine } from '../policy/engine.js';
import type { ActionType } from '../policy/types.js';

interface ToolSchema {
  type: 'object';
  properties: Record<string, unknown>;
  required: string[];
}

interface Tool {
  name: string;
  description: string;
  schema: ToolSchema;
  execute: (params: { action: string; resource: string; params?: Record<string, unknown> }) => Promise<PolicyCheckResult>;
}

interface PolicyCheckResult {
  allowed: boolean;
  denied: boolean;
  reason: string;
  guard?: string;
  severity?: string;
  suggestion?: string;
}

export function policyCheckTool(engine: PolicyEngine): Tool {
  return {
    name: 'policy_check',
    description: 'Check if an action is allowed by the security policy. Use this BEFORE attempting potentially restricted operations.',
    schema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['file_read', 'file_write', 'network_egress', 'command_exec', 'tool_call'],
          description: 'The type of action to check',
        },
        resource: {
          type: 'string',
          description: 'The resource to check (path, domain, command, or tool name)',
        },
        params: {
          type: 'object',
          description: 'Optional additional parameters',
        },
      },
      required: ['action', 'resource'],
    },
    execute: async ({ action, resource, params }) => {
      const event = engine.createEvent(action as ActionType, resource, params);
      const decision = await engine.evaluate(event);

      return {
        allowed: decision.allowed,
        denied: decision.denied,
        reason: decision.reason || (decision.allowed ? 'Action is permitted' : 'Action is not permitted'),
        guard: decision.guard,
        severity: decision.severity,
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
  if (action === 'network_egress') {
    return 'Try using an allowed domain like api.github.com or pypi.org.';
  }
  if (action === 'command_exec' && resource.includes('sudo')) {
    return 'Privileged commands are restricted. Try running without sudo.';
  }
  if (action === 'command_exec' && (resource.includes('rm -rf') || resource.includes('dd if='))) {
    return 'Destructive commands are blocked. Consider safer alternatives.';
  }
  return 'Consider an alternative approach that works within the security policy.';
}
