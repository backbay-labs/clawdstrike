# ClawdStrike Cursor Plugin

Runtime security enforcement for AI coding agents. This plugin integrates ClawdStrike's policy engine, threat hunting, and audit system directly into Cursor.

## What It Does

- **12 lifecycle hooks** -- every tool call, shell command, file read, file edit, MCP invocation, and prompt is policy-checked
- **Post-action audit receipts** -- signed attestations of every action for compliance and forensics
- **15 MCP tools** -- security scanning, threat hunting, event correlation, and policy management
- **3 auto-triggering skills** -- contextual security guidance that activates when relevant
- **6 slash commands** -- quick access to scanning, auditing, posture assessment, and diagnostics
- **1 specialist agent** -- deep security review with OWASP and policy compliance checks
- **2 .mdc rules** -- persistent AI guidance for security awareness and sensitive file protection

## Installation

### From the Cursor Marketplace

> **Coming soon.** The plugin has been submitted to the [Cursor Marketplace](https://cursor.com/marketplace) and is pending review. Once approved, it will be installable directly from Cursor Settings → Plugins.

### From a local clone

```bash
git clone https://github.com/backbay-labs/clawdstrike.git
cd clawdstrike
# Open Cursor Settings → Plugins → Install from folder → select cursor-plugin/
```

## Quick Reference

### Slash Commands

| Command | Description |
|---------|-------------|
| `/clawdstrike:scan` | Scan MCP server configurations for security issues |
| `/clawdstrike:audit` | Show security audit trail for the current session |
| `/clawdstrike:posture` | Assess overall security posture (A-F grade) |
| `/clawdstrike:policy` | Show active security policy and guard details |
| `/clawdstrike:selftest` | Run diagnostic checks on all components |
| `/clawdstrike:tui` | Launch the ClawdStrike TUI dashboard |

### Hooks (12 lifecycle events)

| Hook | Script | Purpose |
|------|--------|---------|
| `sessionStart` | session-start.sh | Initialize enforcement, probe hushd, set env vars |
| `sessionEnd` | session-end.sh | Finalize receipts and summarize session |
| `preToolUse` | pre-tool-check.sh | Policy enforcement before tool execution |
| `postToolUse` | post-tool-receipt.sh | Audit logging after tool execution |
| `beforeSubmitPrompt` | prompt-check.sh | Prompt injection detection |
| `stop` | stop-handler.sh | Graceful shutdown with session summary |
| `beforeShellExecution` | before-shell.sh | Policy check before shell commands |
| `afterShellExecution` | after-shell.sh | Receipt for shell command outcome |
| `beforeMCPExecution` | before-mcp.sh | Policy check before MCP tool calls (fail-closed) |
| `afterMCPExecution` | after-mcp.sh | Receipt for MCP tool outcome |
| `beforeReadFile` | before-read-file.sh | Policy check before file reads (fail-closed) |
| `afterFileEdit` | after-file-edit.sh | Receipt for file edits |

### MCP Tools (15)

| Tool | Description |
|------|-------------|
| `clawdstrike_check` | Evaluate an action against the active policy |
| `clawdstrike_scan` | Scan MCP server configurations |
| `clawdstrike_query` | Query security events with filters |
| `clawdstrike_timeline` | Get chronological event timeline |
| `clawdstrike_correlate` | Correlate events to detect attack patterns |
| `clawdstrike_ioc` | Check indicators of compromise |
| `clawdstrike_policy_show` | Show policy and guard configuration |
| `clawdstrike_policy_eval` | Evaluate a hypothetical action against policy |
| `clawdstrike_policy_lint` | Lint policy for errors and warnings |
| `clawdstrike_policy_simulate` | Dry-run events against a policy |
| `clawdstrike_hunt_diff` | Diff security state between baselines |
| `clawdstrike_report` | Generate a structured security report |
| `clawdstrike_verify_receipt` | Verify Ed25519-signed receipts |
| `clawdstrike_merkle_verify` | Verify Merkle inclusion proofs |
| `clawdstrike_guard_inspect` | Inspect guard metadata |

### Skills (Auto-Triggering)

| Skill | Triggers On |
|-------|-------------|
| Security Review | Edits to sensitive paths, shell commands, dependency changes |
| Threat Hunt | Security events, suspicious activity, IOC investigation |
| Policy Guide | Questions about what's allowed, guard behavior, rulesets |

### Rules (.mdc)

| Rule | Type | Description |
|------|------|-------------|
| `clawdstrike-security` | Always-on | Security awareness context and available commands |
| `clawdstrike-sensitive-files` | Glob-triggered | Extra caution for .env, .pem, .key, credentials, etc. |

### Agent

| Agent | Purpose |
|-------|---------|
| `security-reviewer` | Deep code security review with OWASP checks and policy verification |

## Architecture

```
cursor
    |
    v
+-------------------+
| cursor-plugin     |
+-------------------+
|                   |
| hooks/            |--- pre-tool-check.sh -------> ClawdStrike CLI / hushd
|   hooks.json      |<-- {permission, message} ----/
|   (12 hooks)      |
|                   |--- before-shell.sh ---------> Shell command policy check
|                   |--- before-mcp.sh -----------> MCP tool policy check
|                   |--- before-read-file.sh -----> File read policy check
|                   |
|                   |--- post-tool-receipt.sh ----> Signed receipt
|                   |--- after-shell.sh ----------> Shell receipt
|                   |--- after-mcp.sh ------------> MCP receipt
|                   |--- after-file-edit.sh ------> File edit receipt
|                   |
| scripts/          |--- session-start.sh --------> Initialize session
|   mcp-server.ts   |--- session-end.sh ----------> Finalize + report
|                   |
| skills/           |--- security-review/  (auto-trigger on risky edits)
|                   |--- threat-hunt/      (auto-trigger on investigations)
|                   |--- policy-guide/     (auto-trigger on policy questions)
|                   |
| commands/         |--- /scan, /audit, /posture, /policy, /selftest, /tui
|                   |
| rules/            |--- clawdstrike-security.mdc     (always-on)
|                   |--- clawdstrike-sensitive-files.mdc (glob-triggered)
|                   |
| agents/           |--- security-reviewer (deep code review agent)
+-------------------+
         |
         v
  MCP Server (stdio)
  15 tools via @modelcontextprotocol/sdk
         |
         v
  ClawdStrike CLI / hushd API
```

## Cursor-Specific Features

### Granular Hook Coverage

The Cursor plugin provides 6 additional hooks beyond the Claude Code plugin:

- **`beforeShellExecution`** / **`afterShellExecution`**: Direct shell command checking without needing to extract commands from tool_input. Gets `{command, cwd}` directly.
- **`beforeMCPExecution`** / **`afterMCPExecution`**: Dedicated MCP tool gatekeeping. Automatically skips ClawdStrike's own tools. Fail-closed by default.
- **`beforeReadFile`**: File-level read protection. Fail-closed by default. Gets `{file_path}` directly.
- **`afterFileEdit`**: Audit trail for file modifications with edit counts and diffs.

### .mdc Rules

Two persistent rules provide always-on security context:

- **`clawdstrike-security.mdc`**: Always active. Injects security awareness, available commands, and denial handling guidance.
- **`clawdstrike-sensitive-files.mdc`**: Activates on glob patterns matching sensitive files (`.env`, `.pem`, `.key`, etc.). Warns about hardcoded secrets and policy checks.

### Cursor Output Formats

All hooks output Cursor-compatible JSON:

- **Deny**: `{"permission":"deny","user_message":"...","agent_message":"..."}`
- **Session start**: `{"env":{"CLAWDSTRIKE_SESSION_ID":"..."},"additional_context":"...","continue":true}`
- **Stop**: `{"followup_message":"ClawdStrike session summary: N actions, M denied"}`

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAWDSTRIKE_ENDPOINT` | hushd API endpoint | `http://127.0.0.1:9878` |
| `CLAWDSTRIKE_TOKEN_FILE` | Agent auth token path | `~/.config/clawdstrike/agent-local-token` |
| `CLAWDSTRIKE_SESSION_ID` | Session identifier | Auto-generated UUID |
| `CLAWDSTRIKE_HOOK_FAIL_OPEN` | Allow on error | `false` (fail-closed) |
| `CLAWDSTRIKE_CLI` | CLI binary path | `clawdstrike` |
| `CLAWDSTRIKE_RECEIPT_DIR` | Receipt storage | `~/.clawdstrike/receipts` |
| `CLAWDSTRIKE_SIGNING_KEY` | Ed25519 key for receipt signing | (optional) |
| `CLAWDSTRIKE_POLICY_BUNDLE` | Policy bundle for verification | (optional) |

### Fail-Closed by Default

The plugin follows ClawdStrike's fail-closed design philosophy:
- If the ClawdStrike CLI is unavailable, tool calls are **blocked** (unless `CLAWDSTRIKE_HOOK_FAIL_OPEN=true`)
- If a policy fails to parse, the session **refuses to start**
- If a guard errors during evaluation, the verdict is **deny**
- `beforeMCPExecution` and `beforeReadFile` are fail-closed by Cursor platform convention

Set `CLAWDSTRIKE_HOOK_FAIL_OPEN=true` only in development environments where security enforcement is not required.

## Development

```bash
# Install dependencies
bun install

# Run MCP server standalone
bun run mcp

# Type check
bun run typecheck

# Run tests
bun test
```

## License

Apache-2.0
