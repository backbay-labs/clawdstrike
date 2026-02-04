# Your First Policy

Policies are YAML files parsed into `clawdstrike::Policy`. They configure the built-in guards under `guards.*` and engine settings under `settings.*`.

## Minimal policy (inherit a ruleset)

```yaml
version: "1.1.0"
name: My Policy
extends: clawdstrike:default
```

To see what you’re inheriting:

```bash
hush policy show default
```

## Add an allowed domain (egress)

```yaml
guards:
  egress_allowlist:
    additional_allow:
      - "api.stripe.com"
```

Notes:

- Egress patterns use `globset` globs and are matched case-insensitively (e.g. `api.github.com`, `*.github.com`, `api-?.example.com`).
- `*.example.com` does **not** match `example.com`; list both if you want both.
- Default behavior is deny unless a rule matches (or you set `default_action: allow`).

## Add forbidden paths (filesystem)

```yaml
guards:
  forbidden_path:
    additional_patterns:
      - "**/secrets/**"
      - "**/.env.production"
    exceptions:
      - "**/secrets/README.md"
```

Notes:

- Forbidden paths use Rust `glob` patterns (the same syntax as the built-in rulesets).
- Paths are matched against a normalized string (backslashes become `/`). `~` is not expanded.

## Tune secret scanning (patch/file writes)

```yaml
guards:
  secret_leak:
    patterns:
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
    skip_paths:
      - "**/tests/**"
```

Notes:

- `pattern` is a Rust `regex` string; invalid regexes are rejected when loading the policy.
- `severity` values: `info`, `warning`, `error`, `critical`.

## Tune patch safety checks

```yaml
guards:
  patch_integrity:
    max_additions: 1500
    max_deletions: 750
    require_balance: false
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)curl.*\\|.*bash"
```

Notes:

- `forbidden_patterns` are Rust `regex` strings; invalid regexes are rejected when loading the policy.

## Restrict MCP tools

```yaml
guards:
  mcp_tool:
    allow: []                 # empty => allow all except `block`
    block: ["shell_exec"]     # takes precedence
    require_confirmation:
      - "git_push"
    default_action: allow     # allow|block
    max_args_size: 1048576    # bytes
```

## Merge strategy

When your policy uses `extends`, the child can choose a merge strategy:

```yaml
merge_strategy: deep_merge # default
```

Values:

- `replace`: ignore the base entirely
- `merge`: shallow merge of top-level fields
- `deep_merge`: recursively merge nested structures (default)

## Validate and inspect

Validate a policy file:

```bash
hush policy validate policy.yaml
```

Resolve `extends` and show the merged result:

```bash
hush policy validate --resolve policy.yaml
hush policy show --merged policy.yaml
```
