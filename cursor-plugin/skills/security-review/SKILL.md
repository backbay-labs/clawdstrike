---
description: "Security review for risky code changes"
---

# Security Review

<trigger>
This skill activates when the user or conversation involves:
- Multi-file edits touching security-sensitive paths (auth, config, credentials, .env, keys)
- Shell commands that modify system state, install packages, or change permissions
- New dependency additions or version changes
- Changes to CI/CD, Docker, or infrastructure configuration
- File writes to sensitive directories (/etc, ~/.ssh, ~/.aws, ~/.config)
- File reads of sensitive paths (private keys, credential stores, token caches, certificate files)
- Any content containing these keywords: "secret", "credential", "API key", "token", "password", "private key", "certificate", ".env", "auth", "permission"
</trigger>

## Security Checklist

Before proceeding with risky actions, use the `clawdstrike_check` MCP tool to verify policy compliance:

1. **Pre-flight check**: Call `clawdstrike_check` with the action_type and target before executing
2. **Secret scanning**: Verify no secrets, API keys, or credentials are being written to files
3. **Dependency audit**: For new dependencies, check for known vulnerabilities
4. **Permission scope**: Ensure file operations stay within allowed paths
5. **Shell safety**: Validate shell commands against the ShellCommandGuard policy

## Action Type Mapping

Use these action_type values when calling `clawdstrike_check`:

| Scenario | action_type | target |
|----------|-------------|--------|
| Writing/reading files | `file` | Absolute file path |
| Running shell commands | `shell` | The command string |
| HTTP/network requests | `egress` | Domain or URL |
| Installing packages | `shell` | Install command |
| MCP tool invocation | `mcp_tool` | Tool name |

## Response Guidelines

When this skill is active:
- Proactively call `clawdstrike_check` before file writes to sensitive paths
- Flag potential security issues with severity levels (Critical/High/Medium/Low)
- Suggest safer alternatives when an action would be blocked by policy
- Reference specific guards that would evaluate the action

## Recommended Tools

Use these MCP tools in order of priority when this skill activates:

| Tool | When to Use |
|------|-------------|
| `clawdstrike_check` | Before any file write, shell command, or egress -- the primary enforcement tool |
| `clawdstrike_policy_eval` | To test hypothetical actions without executing them -- use for planning |
| `clawdstrike_policy_show` | To understand which guards are active and what the current restrictions are |
| `clawdstrike_scan` | To audit all MCP server configs for misconfigurations before a review |
| `clawdstrike_policy_lint` | To validate policy YAML files for syntax/schema errors |

## Guard Reference

These guards are evaluated during checks:
- **ForbiddenPathGuard** - Blocks access to sensitive filesystem paths
- **PathAllowlistGuard** - Enforces allowlist-based path access
- **SecretLeakGuard** - Detects secrets/credentials in file content
- **ShellCommandGuard** - Blocks dangerous shell commands
- **EgressAllowlistGuard** - Controls outbound network access
- **PatchIntegrityGuard** - Validates patch/diff safety
