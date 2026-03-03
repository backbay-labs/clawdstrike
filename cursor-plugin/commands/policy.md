---
description: "Show active security policy and guard details"
---

# ClawdStrike Policy

Display the active security policy with guard configuration details.

## Steps

1. Call `clawdstrike_policy_show` MCP tool to retrieve the current policy
2. Present the policy metadata:
   - Policy name and schema version
   - Base ruleset (if using `extends`)
   - Number of enabled/disabled guards

3. Format guard configurations as a table:

| Guard | Status | Key Settings |
|-------|--------|-------------|
| ForbiddenPathGuard | Enabled/Disabled | Blocked paths list |
| PathAllowlistGuard | Enabled/Disabled | Allowed paths list |
| EgressAllowlistGuard | Enabled/Disabled | Allowed domains |
| SecretLeakGuard | Enabled/Disabled | Detection patterns |
| PatchIntegrityGuard | Enabled/Disabled | Validation rules |
| ShellCommandGuard | Enabled/Disabled | Blocked commands |
| McpToolGuard | Enabled/Disabled | Tool allowlist/denylist |
| PromptInjectionGuard | Enabled/Disabled | Detection threshold |
| JailbreakGuard | Enabled/Disabled | Detection layers |
| ComputerUseGuard | Enabled/Disabled | Allowed actions |
| RemoteDesktopSideChannelGuard | Enabled/Disabled | Channel restrictions |
| InputInjectionCapabilityGuard | Enabled/Disabled | Capability restrictions |

4. If any guards are disabled, note what action types are unprotected as a result.

## Per-Guard Impact

For each guard, explain what changes when it is enabled vs disabled:

| Guard | When Enabled | When Disabled |
|-------|-------------|---------------|
| **ForbiddenPathGuard** | Access to sensitive paths (e.g., /etc/shadow, ~/.ssh) is blocked | All file paths accessible; rely on OS-level permissions only |
| **PathAllowlistGuard** | Only explicitly listed paths are accessible; everything else is denied | File access governed only by ForbiddenPathGuard (denylist) |
| **EgressAllowlistGuard** | Only listed domains can be contacted; all other egress is blocked | Unrestricted outbound network access |
| **SecretLeakGuard** | File writes are scanned for secrets; matches are denied | Secrets can be written to files without detection |
| **PatchIntegrityGuard** | Patches/diffs are validated for unsafe patterns before application | Patches applied without safety checks |
| **ShellCommandGuard** | Dangerous commands (rm -rf, sudo, curl\|bash) are blocked | All shell commands allowed without restriction |
| **McpToolGuard** | Only allowlisted MCP tools can be invoked | All MCP tools accessible |
| **PromptInjectionGuard** | Input text is scanned for injection patterns | Prompt injection attempts pass through undetected |
| **JailbreakGuard** | Multi-layer jailbreak detection active (heuristic + statistical + ML + LLM-judge) | No jailbreak detection |
| **ComputerUseGuard** | CUA actions restricted to allowed types | Unrestricted computer use actions |
| **RemoteDesktopSideChannelGuard** | Side channels (clipboard, audio, drives, file transfer) restricted | No side-channel controls |
| **InputInjectionCapabilityGuard** | Input injection capabilities restricted in CUA environments | Unrestricted input injection |

## Guard Dependencies

Some guards interact with or override each other:

- **PathAllowlistGuard overrides ForbiddenPathGuard**: When PathAllowlistGuard is enabled, it acts as the primary file access control. ForbiddenPathGuard still runs as a second layer, but PathAllowlistGuard's allowlist is the first gate. A path must pass both guards.
- **ShellCommandGuard and ForbiddenPathGuard**: Shell commands that reference file paths are checked by ShellCommandGuard for the command itself, but the file paths within the command are not separately checked by ForbiddenPathGuard. Use both guards for defense-in-depth.
- **McpToolGuard and other guards**: McpToolGuard controls which tools can be called, but does not inspect the arguments. Other guards (e.g., ShellCommandGuard for a shell tool, EgressAllowlistGuard for a fetch tool) evaluate the action the tool performs.
- **PromptInjectionGuard and JailbreakGuard**: Both evaluate prompt/input content but use different detection strategies. JailbreakGuard is more comprehensive (4 layers) but higher latency. They can run independently or together for layered defense.
