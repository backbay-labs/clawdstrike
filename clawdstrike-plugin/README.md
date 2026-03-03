# ClawdStrike Claude Code Plugin

Runtime security enforcement for AI coding agents. This plugin integrates ClawdStrike's policy engine, threat hunting, and audit system directly into Claude Code.

## What It Does

- **Pre-tool policy checks** -- every tool call is evaluated against your security policy before execution
- **Post-tool audit receipts** -- signed attestations of every action for compliance and forensics
- **10 MCP tools** -- security scanning, threat hunting, event correlation, and policy management
- **3 auto-triggering skills** -- contextual security guidance that activates when relevant
- **5 slash commands** -- quick access to scanning, auditing, and posture assessment
- **1 specialist agent** -- deep security review with OWASP and policy compliance checks

## Installation

### From the marketplace (recommended)

```shell
# Add the ClawdStrike marketplace
/plugin marketplace add backbay-labs/clawdstrike

# Install the plugin
/plugin install clawdstrike@clawdstrike
```

### From a local clone

```bash
claude --plugin-dir ./clawdstrike-plugin
```

## Quick Reference

### Slash Commands

| Command | Description |
|---------|-------------|
| `/clawdstrike:scan` | Scan MCP server configurations for security issues |
| `/clawdstrike:audit` | Show security audit trail for the current session |
| `/clawdstrike:posture` | Assess overall security posture (A-F grade) |
| `/clawdstrike:policy` | Show active security policy and guard details |
| `/clawdstrike:tui` | Launch the ClawdStrike TUI dashboard |

### MCP Tools

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
| `clawdstrike_hunt_diff` | Diff security state between two points in time |
| `clawdstrike_report` | Generate a structured security report |

### Skills (Auto-Triggering)

| Skill | Triggers On |
|-------|-------------|
| Security Review | Edits to sensitive paths, shell commands, dependency changes |
| Threat Hunt | Security events, suspicious activity, IOC investigation |
| Policy Guide | Questions about what's allowed, guard behavior, rulesets |

### Agent

| Agent | Purpose |
|-------|---------|
| `security-reviewer` | Deep code security review with OWASP checks and policy verification |

## Architecture

```
claude code
    |
    v
+-------------------+
| clawdstrike-plugin|
+-------------------+
|                   |
| hooks/            |--- pre-tool-check.sh ----> ClawdStrike CLI
|   hooks.json      |<-- allow/deny verdict ----/
|                   |
|                   |--- post-tool-receipt.sh -> ClawdStrike CLI
|                   |<-- signed receipt --------/
|                   |
| scripts/          |--- session-start.sh ----> Initialize session
|   mcp-server.ts   |--- session-end.sh ------> Finalize + report
|                   |
| skills/           |--- security-review/  (auto-trigger on risky edits)
|                   |--- threat-hunt/      (auto-trigger on investigations)
|                   |--- policy-guide/     (auto-trigger on policy questions)
|                   |
| commands/         |--- /scan     (MCP config scanning)
|                   |--- /audit    (session audit trail)
|                   |--- /posture  (security posture grade)
|                   |--- /policy   (active policy details)
|                   |--- /tui      (interactive dashboard)
|                   |
| agents/           |--- security-reviewer (deep code review agent)
+-------------------+
         |
         v
  MCP Server (stdio)
  10 tools via @modelcontextprotocol/sdk
         |
         v
  ClawdStrike CLI / API
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAWDSTRIKE_ENDPOINT` | ClawdStrike API endpoint (CLI path or HTTP URL) | `clawdstrike` (PATH lookup) |
| `CLAWDSTRIKE_SESSION_ID` | Session identifier for audit trail continuity | Auto-generated UUID |
| `CLAWDSTRIKE_HOOK_FAIL_OPEN` | Allow actions when ClawdStrike is unavailable. Accepts `true`, `1`, or `yes` | `false` (fail-closed) |

### Fail-Closed by Default

The plugin follows ClawdStrike's fail-closed design philosophy:
- If the ClawdStrike CLI is unavailable, tool calls are **blocked** (unless `CLAWDSTRIKE_HOOK_FAIL_OPEN=true`)
- If a policy fails to parse, the session **refuses to start**
- If a guard errors during evaluation, the verdict is **deny**

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

MIT
