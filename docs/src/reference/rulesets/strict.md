# Strict

**Ruleset ID:** `strict` (also accepted as `hushclaw:strict`)

**Source:** `rulesets/strict.yaml`

Deny-by-default policy intended for sensitive environments.

## What it does (high level)

- Uses an empty egress allowlist with `default_action: block` (no network egress unless you extend/override)
- Uses strict patch integrity limits (smaller diffs, balanced changes, more forbidden patterns)
- Sets `settings.fail_fast: true` (stop evaluating guards after the first block)
- Sets a shorter `settings.session_timeout_secs`
- Locks down MCP tools by default (`default_action: block`)

## View the exact policy

```bash
hush policy show strict
```
