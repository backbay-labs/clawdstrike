---
description: "Analyze and tighten ClawdStrike security policies"
---

# Tighten Policy

## Workflow

### Step 1: Assess Current State

1. **Validate** — Call `workbench_validate_policy` to check for errors.
2. **List guards** — Call `workbench_list_guards` to see all 13 available guards.
3. **Check compliance** — Call `workbench_compliance_check` to identify framework gaps.

### Step 2: Identify Gaps

Compare the policy against the guard registry to find:
- **Disabled guards** that should be enabled for the use case
- **Missing configuration** (e.g., egress allowlist with no domains listed)
- **Overly permissive defaults** (e.g., `default_action: allow` on MCP tools)
- **Missing patterns** (e.g., forbidden paths not covering cloud credentials)

### Step 3: Generate Test Scenarios

Call `workbench_suggest_scenarios` to automatically generate scenarios for enabled guards, then add custom scenarios targeting identified gaps.

### Step 4: Run Scenarios and Verify

Use `workbench_run_all_scenarios` to batch-test. Focus on:
- Attack scenarios that should be **denied** but are **allowed** (false negatives)
- Benign scenarios that should be **allowed** but are **denied** (false positives)

### Step 5: Apply Tightening Changes

For each identified gap, recommend specific YAML changes.

## Guard-by-Guard Tightening Checklist

### Forbidden Path (filesystem)
- [ ] Cover SSH keys: `**/.ssh/**`
- [ ] Cover cloud credentials: `**/.aws/**`, `**/.config/gcloud/**`, `**/.azure/**`
- [ ] Cover environment files: `**/.env`, `**/.env.*`
- [ ] Cover git credentials: `**/.git-credentials`, `**/.gitconfig`
- [ ] Cover Docker/K8s: `**/.docker/**`, `**/.kube/**`
- [ ] Cover system files: `/etc/shadow`, `/etc/passwd`

### Egress Allowlist (network)
- [ ] Set `default_action: block` (not allow)
- [ ] Only allow domains the agent actually needs
- [ ] Use specific domains instead of broad wildcards where possible
- [ ] Consider blocking high-risk TLDs

### Secret Leak (content)
- [ ] Enable with patterns for: AWS keys, GitHub tokens, private keys
- [ ] Add patterns for: API keys, database URLs, JWTs
- [ ] Set severity levels appropriately (critical for keys, warning for potential)

### Shell Command (tools)
- [ ] Enable to block: `rm -rf /`, reverse shells, `curl|bash`, `chmod 777`
- [ ] Consider adding custom patterns for project-specific dangerous commands

### MCP Tool (tools)
- [ ] Set `default_action: block` for high-security environments
- [ ] Explicitly allow only needed tools
- [ ] Use `require_confirmation` for write/execute tools
- [ ] Block dangerous tools: `shell_exec`, `eval`

### Prompt Injection (detection)
- [ ] Enable for agent-facing deployments
- [ ] Set `block_at_or_above: high` at minimum
- [ ] Set `warn_at_or_above: suspicious` for visibility

### Jailbreak (detection)
- [ ] Enable for user-facing deployments
- [ ] Set `block_threshold` to 40-50 for production
- [ ] Set `warn_threshold` to 15-20

### Patch Integrity (content)
- [ ] Set reasonable `max_additions` and `max_deletions` limits
- [ ] Enable `require_balance` for production
- [ ] Add `forbidden_patterns` for dangerous code changes

### Settings
- [ ] Set `session_timeout_secs` (1800 for production, 3600 for dev)
- [ ] Enable `verbose_logging` for audit compliance
- [ ] Consider `fail_fast: true` for high-security

## Policy Comparison

When tightening, always compare the before and after using `workbench_diff_policies` to verify:
- No unintended changes were introduced
- All intended tightening was applied
- No existing protections were accidentally removed

## Instructions

- Start by validating the current policy with `workbench_validate_policy`
- Provide exact YAML snippets for each recommended change
- Prioritize by risk: critical gaps first, then high, then medium
- Run scenarios before and after changes to verify improvements
- Use `workbench_diff_policies` to show before/after comparison
- Warn about false positives when tightening aggressively
