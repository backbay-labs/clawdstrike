import type { PolicyConfig } from './policy/types.js';

export function generateSecurityPrompt(config: PolicyConfig): string {
  const sections: string[] = [];

  sections.push(`# Security Policy

You are protected by hushclaw security enforcement. The following constraints apply:`);

  // Network Access section
  sections.push(`
## Network Access`);

  if (config.egress?.mode === 'allowlist' && config.egress.allowed_domains?.length) {
    sections.push(`- Only these domains are allowed: ${config.egress.allowed_domains.join(', ')}`);
  } else if (config.egress?.mode === 'denylist' && config.egress.denied_domains?.length) {
    sections.push(`- These domains are blocked: ${config.egress.denied_domains.join(', ')}`);
  } else {
    sections.push(`- Network access follows default policy`);
  }

  // Filesystem Access section
  sections.push(`
## Filesystem Access`);

  if (config.filesystem?.forbidden_paths?.length) {
    sections.push(`- These paths are FORBIDDEN and will be blocked:`);
    for (const path of config.filesystem.forbidden_paths) {
      sections.push(`  - ${path}`);
    }
  } else {
    sections.push(`- Default protected paths: ~/.ssh, ~/.aws, ~/.gnupg, .env files`);
  }

  if (config.filesystem?.allowed_write_roots?.length) {
    sections.push(`- Writes are only allowed in: ${config.filesystem.allowed_write_roots.join(', ')}`);
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
  const blockAction = config.on_violation === 'cancel' ? 'BLOCKED' :
                      config.on_violation === 'warn' ? 'logged with a warning' : 'logged';

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
