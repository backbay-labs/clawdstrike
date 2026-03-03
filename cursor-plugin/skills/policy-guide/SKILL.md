---
description: "Guide to ClawdStrike security policies and guard configuration"
---

# Policy Guide

<trigger>
This skill activates when the user or conversation involves:
- Questions about what actions are allowed or blocked
- Policy configuration, guard behavior, or security rules
- Choosing or comparing security rulesets
- Understanding why an action was denied
- Customizing guard settings or thresholds
- Denial errors such as "action denied", "blocked by guard", or "policy violation"
- Questions like "why was X blocked", "why can't I access Y", or "how do I allow Z"
</trigger>

## The 12 Built-in Guards

| Guard | Action Type | Purpose | Default Status |
|-------|-------------|---------|----------------|
| **ForbiddenPathGuard** | file | Blocks access to sensitive filesystem paths (e.g., /etc/shadow, ~/.ssh/id_rsa) | permissive: ON, default: ON, strict: ON |
| **PathAllowlistGuard** | file | Only allows file access to explicitly permitted paths | permissive: OFF, default: OFF, strict: ON |
| **EgressAllowlistGuard** | egress | Controls outbound network access by domain allowlist | permissive: OFF, default: ON, strict: ON |
| **SecretLeakGuard** | file | Detects secrets, API keys, and credentials in file writes | permissive: ON, default: ON, strict: ON |
| **PatchIntegrityGuard** | file | Validates that patches/diffs don't introduce unsafe changes | permissive: OFF, default: ON, strict: ON |
| **ShellCommandGuard** | shell | Blocks dangerous shell commands (rm -rf, sudo, etc.) | permissive: OFF, default: ON, strict: ON |
| **McpToolGuard** | mcp_tool | Restricts which MCP tools can be invoked | permissive: OFF, default: OFF, strict: ON |
| **PromptInjectionGuard** | prompt | Detects prompt injection attempts in inputs | permissive: OFF, default: ON, strict: ON |
| **JailbreakGuard** | prompt | 4-layer jailbreak detection (heuristic + statistical + ML + LLM-judge) | permissive: OFF, default: OFF, strict: ON |
| **ComputerUseGuard** | computer_use | Controls Computer Use Agent actions for remote desktop | permissive: OFF, default: OFF, strict: ON |
| **RemoteDesktopSideChannelGuard** | remote_desktop | Side-channel controls (clipboard, audio, drive mapping, file transfer) | permissive: OFF, default: OFF, strict: ON |
| **InputInjectionCapabilityGuard** | computer_use | Restricts input injection capabilities in CUA environments | permissive: OFF, default: OFF, strict: ON |

## Available Rulesets

Use `clawdstrike_policy_show` to inspect any ruleset.

| Ruleset | Use Case |
|---------|----------|
| `permissive` | Development/testing -- minimal restrictions |
| `default` | General purpose -- balanced security |
| `strict` | High-security environments -- maximum restrictions |
| `ai-agent` | AI coding agents -- tuned for agent workflows |
| `cicd` | CI/CD pipelines -- restricted to build/deploy operations |
| `ai-agent-posture` | Agent posture assessment -- monitoring without blocking |
| `remote-desktop` | Remote desktop sessions -- balanced CUA controls |
| `remote-desktop-permissive` | Permissive CUA -- fewer restrictions for trusted environments |
| `remote-desktop-strict` | Strict CUA -- maximum restrictions for untrusted environments |

## How to Check Policies

### Show active policy
Call `clawdstrike_policy_show` with no arguments to see the currently loaded policy, or pass a ruleset name to inspect a specific one.

### Evaluate a hypothetical action
Call `clawdstrike_policy_eval` with an action_type and target to see which guards would fire and what the verdict would be, without actually executing the action.

## Policy Inheritance

Policies support inheritance via the `extends` field:
- Built-in rulesets can be referenced by name (e.g., `extends: strict`)
- Local files can be referenced by path
- Remote URLs and git refs are supported
- Child policies override parent settings; guards merge by name

## Design Philosophy: Fail-Closed

ClawdStrike follows a fail-closed design:
- **Invalid policies** are rejected at load time (not silently ignored)
- **Errors during guard evaluation** result in deny (not allow)
- **Unknown action types** are denied by default
- **Missing configuration** causes startup failure, not permissive fallback

This means if something goes wrong, the system errs on the side of security rather than availability.

## What To Do When Too Strict

If the active policy is blocking legitimate actions, follow these steps to relax it safely:

1. **Identify the blocking guard**: Call `clawdstrike_policy_eval` with the denied action to see exactly which guard is blocking it.
2. **Check if the action is expected**: Verify the action is genuinely needed and not a misconfigured command or wrong path.
3. **Try a less restrictive ruleset**: If on `strict`, try `default` or `ai-agent`. Use `clawdstrike_policy_show` to compare what changes.
4. **Create a custom override**: Extend the current ruleset and override only the specific guard:
   ```yaml
   schema_version: "1.2.0"
   extends: strict
   guards:
     ForbiddenPathGuard:
       additional_allowed_paths:
         - "/path/that/was/blocked"
   ```
5. **Add path-specific exceptions**: For file guards, add paths to allowlists rather than disabling the guard entirely.
6. **Disable a single guard as last resort**: Set `enabled: false` for a specific guard only if the above options do not work. Never disable SecretLeakGuard in production.
7. **Re-verify**: After changes, run `clawdstrike_policy_eval` again to confirm the action is now allowed without opening unintended gaps.

## Response Guidelines

When this skill is active:
- Use `clawdstrike_policy_show` and `clawdstrike_policy_eval` to give concrete answers
- Explain guard behavior in terms of what the user is trying to do
- Recommend the most appropriate ruleset for the user's use case
- When an action is denied, explain which guard blocked it and why
