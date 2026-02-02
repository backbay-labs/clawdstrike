import type { Policy } from './types.js';

export function generateSecurityPrompt(policy: Policy): string {
  const sections: string[] = [];

  sections.push(`# Security Policy

You are protected by hushclaw security enforcement. The following constraints apply:`);

  // Network Access section
  sections.push(`
## Network Access`);

  if (policy.egress?.mode === 'allowlist' && policy.egress.allowed_domains?.length) {
    sections.push(`- Only these domains are allowed: ${policy.egress.allowed_domains.join(', ')}`);
  } else if (policy.egress?.mode === 'denylist' && policy.egress.denied_domains?.length) {
    sections.push(`- These domains are blocked: ${policy.egress.denied_domains.join(', ')}`);
  } else if (policy.egress?.mode === 'deny_all') {
    sections.push(`- All network access is BLOCKED`);
  } else {
    sections.push(`- Network access follows default policy`);
  }

  // Forbidden Paths section
  sections.push(`
## Forbidden Paths`);

  if (policy.filesystem?.forbidden_paths?.length) {
    sections.push(`- These paths are FORBIDDEN and will be blocked:`);
    for (const path of policy.filesystem.forbidden_paths) {
      sections.push(`  - ${path}`);
    }
  } else {
    sections.push(`- Default protected paths: ~/.ssh, ~/.aws, ~/.gnupg, .env files`);
  }

  if (policy.filesystem?.allowed_write_roots?.length) {
    sections.push(`- Writes are only allowed in: ${policy.filesystem.allowed_write_roots.join(', ')}`);
  }

  // Security Tools section
  sections.push(`
## Security Tools
You have access to the \`policy_check\` tool. Use it BEFORE attempting:
- File operations on unfamiliar paths
- Network requests to unfamiliar domains
- Execution of shell commands

Example:
\`\`\`
policy_check({ action: "file_write", resource: "/etc/passwd" })
-> { allowed: false, reason: "Path is forbidden" }
\`\`\``);

  // Violation Handling section
  const blockAction =
    policy.on_violation === 'cancel' ? 'BLOCKED' :
      policy.on_violation === 'warn' ? 'logged with a warning' :
        policy.on_violation === 'isolate' ? 'ISOLATED' :
          policy.on_violation === 'escalate' ? 'ESCALATED' :
            'logged';

  sections.push(`
## Violation Handling
When a security violation occurs:
1. The operation will be ${blockAction}
2. You will see an error message explaining why
3. Try an alternative approach that respects the policy`);

  // Tips section
  sections.push(`
## Tips
- Prefer working within /workspace or /tmp
- Use known package registries (npm, pypi, crates.io)
- Never attempt to access credentials or keys
- When unsure, use \`policy_check\` first`);

  return sections.join('\n');
}
