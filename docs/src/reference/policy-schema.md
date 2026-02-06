# Policy Schema

Reference for `clawdstrike::Policy`.

## Supported versions

- `1.1.0`
- `1.2.0` (current)

Default serialized version is `1.2.0`.

## Top-level fields

- `version` (string)
- `name` (string)
- `description` (string)
- `extends` (string, optional): a built-in ruleset id (e.g. `clawdstrike:default`), a file path, or a pinned remote reference (e.g. `https://…/policy.yaml#sha256=…` / `git+…#sha256=…`) when enabled
- `merge_strategy` (`replace` | `merge` | `deep_merge`)
- `guards` (object)
- `custom_guards` (array)
- `settings` (object)
- `posture` (object, optional, `1.2.0+`)

## Remote `extends` (security)

Remote `extends` is **disabled by default** and must be explicitly enabled via an **allowlist**:

- `hushd`: configure `remote_extends.allowed_hosts`
- `hush`: pass `--remote-extends-allow-host` (repeatable)

Remote references must be **integrity pinned** with `#sha256=<64-hex>`. By default, the resolver is hardened:

- HTTPS-only (HTTP requires explicit opt-in)
- blocks private/loopback/link-local IP resolution by default
- limits redirects and re-validates scheme/host allowlists on each hop

## Full schema example

```yaml
version: "1.2.0"
name: Example
description: Example policy showing key fields
extends: clawdstrike:default
merge_strategy: deep_merge

guards:
  forbidden_path:
    patterns: ["**/.ssh/**"]

  path_allowlist:
    enabled: true
    file_access_allow: ["**/workspace/**"]
    file_write_allow: ["**/workspace/**"]
    patch_allow: ["**/workspace/**"]

  egress_allowlist:
    allow: ["api.github.com", "*.openai.com"]
    block: []
    default_action: block

  secret_leak:
    patterns:
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical

  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    forbidden_patterns: ["(?i)rm\\s+-rf\\s+/"]

  mcp_tool:
    allow: []
    block: ["shell_exec"]
    require_confirmation: ["git_push"]
    default_action: allow

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 3600

posture:
  initial: work
  states:
    work:
      capabilities: [file_access, file_write, egress, mcp_tool]
      budgets:
        file_writes: 100
        egress_calls: 50
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: critical_violation }
```

## Version-gated fields

- `version: "1.1.0"`:
  - `posture` is rejected
  - `guards.path_allowlist` is rejected
- `version: "1.2.0"`:
  - `posture` and `guards.path_allowlist` are available

## Patterns and validation

- Forbidden paths and path allowlists use Rust `glob` patterns.
- Secret and patch regex patterns use Rust `regex`.
- Egress host patterns use `globset` globs.
- Unknown fields are rejected (`deny_unknown_fields`).

## Posture

See [`Posture Schema`](posture-schema.md) for full fields and validation.
