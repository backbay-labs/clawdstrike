# Default

**Ruleset ID:** `default` (also accepted as `hushclaw:default`)

**Source:** `rulesets/default.yaml`

Balanced baseline suitable for general development and agent runtimes.

## What it does (high level)

- Blocks access to common credential/secret file paths (SSH keys, AWS creds, `.env`, etc.)
- Allows egress only to a curated list (AI APIs, GitHub, common registries) and blocks everything else by default
- Scans patches/file writes for common secret patterns
- Blocks obviously dangerous patch patterns (e.g. destructive shell snippets)
- Restricts risky MCP tools (blocks `shell_exec`, `run_command`, raw file ops; requires confirmation for some tools)

## Defaults worth knowing

- `guards.egress_allowlist.default_action: block`
- `settings.fail_fast: false`
- `settings.verbose_logging: false`

## View the exact policy

```bash
hush policy show default
```
