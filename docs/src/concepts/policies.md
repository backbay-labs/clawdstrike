# Policies

Policies are YAML files parsed into `clawdstrike::Policy`. They configure the built-in guards and engine settings.

## Structure

At a high level:

```yaml
version: "1.0.0"
name: Example
description: Optional

extends: clawdstrike:default     # optional
merge_strategy: deep_merge    # optional (default)

guards:                       # optional (defaults apply if omitted)
  forbidden_path: {}
  egress_allowlist: {}
  secret_leak: {}
  patch_integrity: {}
  mcp_tool: {}

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600
```

See the [Policy Schema](../reference/policy-schema.md) for exact fields.

## Inheritance (`extends`)

`extends` supports:

- built-in rulesets (`clawdstrike:default`, `clawdstrike:strict`, …)
- local files (relative to the policy file)

## Merge strategy

- `deep_merge` (default): merge nested fields; guard configs may use `additional_*`/`remove_*` fields
- `merge`: shallow merge (top-level override)
- `replace`: ignore the base entirely

## Pattern validation (fail closed)

When loading a policy, invalid glob/regex patterns are treated as errors. This prevents silent weakening due to typos.
