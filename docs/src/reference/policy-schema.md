# Policy Schema

Reference for the Rust policy type `clawdstrike::Policy`.

## Top-level fields

- `version` (string): policy version (defaults to `1.0.0`)
- `name` (string)
- `description` (string)
- `extends` (string, optional): a built-in ruleset id (e.g. `clawdstrike:default`) or a file path
- `merge_strategy` (`replace` | `merge` | `deep_merge`)
- `guards` (object): guard configurations (see below)
- `settings` (object): engine settings (see below)

## Full schema (example)

```yaml
version: "1.0.0"
name: Example
description: Example policy showing all fields
extends: clawdstrike:default
merge_strategy: deep_merge

guards:
  forbidden_path:
    patterns: ["**/.ssh/**"]
    exceptions: []
    additional_patterns: []
    remove_patterns: []

  egress_allowlist:
    allow: ["api.github.com", "*.openai.com"]
    block: []
    default_action: block # allow|block|log
    additional_allow: []
    remove_allow: []
    additional_block: []
    remove_block: []

  secret_leak:
    patterns:
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical # info|warning|error|critical
    skip_paths: ["**/tests/**"]

  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    forbidden_patterns: ["(?i)rm\\s+-rf\\s+/"]
    require_balance: false
    max_imbalance_ratio: 10.0

  mcp_tool:
    allow: []
    block: ["shell_exec"]
    require_confirmation: ["git_push"]
    default_action: allow # allow|block
    max_args_size: 1048576
    additional_allow: []
    remove_allow: []
    additional_block: []
    remove_block: []

  prompt_injection:
    warn_at_or_above: suspicious # safe|suspicious|high|critical
    block_at_or_above: high      # safe|suspicious|high|critical
    max_scan_bytes: 200000

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600
```

## Patterns and validation

Policy loading validates patterns and fails closed:

- Forbidden paths (`guards.forbidden_path.*`) and `secret_leak.skip_paths` use Rust `glob` patterns.
- `secret_leak.patterns[].pattern` and `patch_integrity.forbidden_patterns[]` use Rust `regex`.
- Egress domain patterns (`guards.egress_allowlist.*`) use `globset` glob patterns (matched case-insensitively).
