/**
 * @hushclaw/openclaw - Agent Bootstrap Hook Handler
 *
 * Injects security context into agent prompts at bootstrap time.
 */

import type {
  HookHandler,
  HookEvent,
  AgentBootstrapEvent,
  HushClawConfig,
  Policy,
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
 * Hook handler for agent:bootstrap events
 */
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'agent:bootstrap') {
    return;
  }

  const bootstrapEvent = event as AgentBootstrapEvent;
  const policyEngine = getEngine(bootstrapEvent.context.cfg);
  const policy = policyEngine.getPolicy();

  // Generate security prompt content
  const securityContent = generateSecurityPrompt(policy, policyEngine.enabledGuards());

  // Add SECURITY.md to bootstrap files
  bootstrapEvent.context.bootstrapFiles.push({
    path: 'SECURITY.md',
    content: securityContent,
  });
};

/**
 * Generate security prompt content from policy
 */
function generateSecurityPrompt(policy: Policy, enabledGuards: string[]): string {
  const sections: string[] = [];

  sections.push('# Security Policy');
  sections.push('');
  sections.push('You are subject to the following security constraints enforced by HushClaw.');
  sections.push('Violations will be blocked or logged depending on the enforcement mode.');
  sections.push('');

  // Active guards
  sections.push('## Active Security Guards');
  sections.push('');
  for (const guard of enabledGuards) {
    const description = getGuardDescription(guard);
    sections.push(`- **${guard}**: ${description}`);
  }
  sections.push('');

  // Forbidden paths
  if (policy.filesystem?.forbidden_paths?.length) {
    sections.push('## Forbidden Paths');
    sections.push('');
    sections.push('You MUST NOT access these paths:');
    sections.push('');
    for (const path of policy.filesystem.forbidden_paths.slice(0, 10)) {
      sections.push(`- \`${path}\``);
    }
    if (policy.filesystem.forbidden_paths.length > 10) {
      sections.push(`- ... and ${policy.filesystem.forbidden_paths.length - 10} more`);
    }
    sections.push('');
  }

  // Network restrictions
  if (policy.egress) {
    sections.push('## Network Restrictions');
    sections.push('');

    if (policy.egress.mode === 'allowlist') {
      sections.push('Only the following domains are accessible:');
      sections.push('');
      for (const domain of policy.egress.allowed_domains?.slice(0, 10) ?? []) {
        sections.push(`- \`${domain}\``);
      }
      if ((policy.egress.allowed_domains?.length ?? 0) > 10) {
        sections.push(`- ... and ${(policy.egress.allowed_domains?.length ?? 0) - 10} more`);
      }
    } else if (policy.egress.mode === 'deny_all') {
      sections.push('**All network access is denied.**');
    } else if (policy.egress.mode === 'open') {
      sections.push('Network access is unrestricted.');
    }

    if (policy.egress.denied_domains?.length) {
      sections.push('');
      sections.push('The following domains are explicitly blocked:');
      sections.push('');
      for (const domain of policy.egress.denied_domains.slice(0, 5)) {
        sections.push(`- \`${domain}\``);
      }
    }
    sections.push('');
  }

  // Execution restrictions
  if (policy.execution?.denied_patterns?.length) {
    sections.push('## Execution Restrictions');
    sections.push('');
    sections.push('The following command patterns are blocked:');
    sections.push('');
    for (const pattern of policy.execution.denied_patterns.slice(0, 5)) {
      sections.push(`- \`${pattern}\``);
    }
    sections.push('');
  }

  // Tool usage guidance
  sections.push('## Using the policy_check Tool');
  sections.push('');
  sections.push('Before performing risky operations, use the `policy_check` tool to verify:');
  sections.push('');
  sections.push('```');
  sections.push('policy_check({ action: "file_read", resource: "~/.ssh/id_rsa" })');
  sections.push('// Returns: { allowed: false, reason: "Forbidden path" }');
  sections.push('');
  sections.push('policy_check({ action: "network", resource: "api.github.com" })');
  sections.push('// Returns: { allowed: true }');
  sections.push('```');
  sections.push('');

  // Violation handling
  sections.push('## On Policy Violation');
  sections.push('');
  const action = policy.on_violation ?? 'cancel';
  switch (action) {
    case 'cancel':
      sections.push('Policy violations will **block** the operation and return an error.');
      break;
    case 'warn':
      sections.push('Policy violations will **warn** but allow the operation to proceed.');
      break;
    case 'isolate':
      sections.push('Policy violations will **isolate** the session for human review.');
      break;
    case 'escalate':
      sections.push('Policy violations will **escalate** to human review before proceeding.');
      break;
  }
  sections.push('');

  return sections.join('\n');
}

/**
 * Get human-readable description for a guard
 */
function getGuardDescription(guard: string): string {
  const descriptions: Record<string, string> = {
    forbidden_path: 'Blocks access to sensitive files (SSH keys, credentials, etc.)',
    egress: 'Enforces network egress allowlist/denylist',
    secret_leak: 'Detects and redacts secrets in outputs',
    patch_integrity: 'Blocks dangerous code patterns in patches',
    mcp_tool: 'Controls which MCP tools can be invoked',
  };

  return descriptions[guard] ?? 'Security enforcement';
}

export default handler;
