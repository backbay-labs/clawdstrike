# Policy Schema

Reference for the Rust policy type `clawdstrike::Policy`.

## Top-level fields

- `version` (string): policy version (defaults to `1.1.0`)
- `name` (string)
- `description` (string)
- `extends` (string, optional): a built-in ruleset id (e.g. `clawdstrike:default`), a file path, or a pinned remote reference (e.g. `https://…/policy.yaml#sha256=…` / `git+…#sha256=…`) when enabled
- `merge_strategy` (`replace` | `merge` | `deep_merge`)
- `custom_guards` (list, optional): policy-driven custom guards (resolved via a `CustomGuardRegistry`; fail-closed if required but unavailable)
- `guards` (object): guard configurations (see below)
- `settings` (object): engine settings (see below)

## Remote `extends` (security)

Remote `extends` is **disabled by default** and must be explicitly enabled via an **allowlist**:

- `hushd`: configure `remote_extends.allowed_hosts`
- `hush`: pass `--remote-extends-allow-host` (repeatable)

Remote references must be **integrity pinned** with `#sha256=<64-hex>`. By default, the resolver is hardened:

- HTTPS-only (HTTP requires explicit opt-in)
- blocks private/loopback/link-local IP resolution by default
- limits redirects and re-validates scheme/host allowlists on each hop

## Full schema (example)

```yaml
version: "1.1.0"
name: Example
description: Example policy showing all fields
extends: clawdstrike:default
merge_strategy: deep_merge
custom_guards: []

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

  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "${VT_API_KEY}"
        min_detections: 2
      async:
        timeout_ms: 3000
        on_timeout: warn
        execution_mode: parallel
        cache:
          enabled: true
          ttl_seconds: 3600
          max_size_mb: 64
        rate_limit:
          requests_per_minute: 60
          burst: 5
        circuit_breaker:
          failure_threshold: 5
          reset_timeout_ms: 60000
          success_threshold: 1
        retry:
          max_retries: 2
          initial_backoff_ms: 200
          max_backoff_ms: 2000
          multiplier: 2

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

## Custom guards (policy-driven)

`guards.custom[]` is the canonical way to configure plugin-shaped guards in policy:

```yaml
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config: { ... }
      async:  { ... }
```

**Hybrid mode note:** for now, `package` is treated as a reserved built-in identifier (unknown packages fail closed).

## Async guard configuration

Each `guards.custom[]` entry can include an `async` block:

- `timeout_ms` (number): per-guard timeout (100–300000).
- `on_timeout` (`allow` | `deny` | `warn` | `defer`): what to do if the guard does not complete in time.
- `execution_mode` (`parallel` | `sequential` | `background`):
  - `parallel`: run async guards concurrently.
  - `sequential`: run in order.
  - `background`: does not change the immediate decision; runs asynchronously to warm cache + emit audit.
- `cache`:
  - `enabled` (bool)
  - `ttl_seconds` (int, >= 1)
  - `max_size_mb` (int, >= 1)
- `rate_limit`:
  - `requests_per_second` (number, > 0) **or** `requests_per_minute` (number, > 0)
  - `burst` (int, >= 1)
- `circuit_breaker`:
  - `failure_threshold` (int, >= 1)
  - `reset_timeout_ms` (int, >= 1000)
  - `success_threshold` (int, >= 1)
- `retry`:
  - `max_retries` (int, >= 0)
  - `initial_backoff_ms` (int, >= 100)
  - `max_backoff_ms` (int, >= 100)
  - `multiplier` (number, >= 1)

## Secrets / placeholders

Policy YAML supports placeholders in string values:

- `${ENV_NAME}` → environment variable `ENV_NAME`
- `${secrets.NAME}` → environment variable `NAME` (MVP)

Missing placeholders fail policy validation (fail closed). Placeholders are resolved at runtime for guard configuration (the stored/serialized policy does not inline secret values).
