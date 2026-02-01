# Policies

Policies are YAML files that configure security rules for hushclaw.

## Policy Structure

Every policy has these sections:

```yaml
version: "hushclaw-v1.0"     # Schema version
extends: hushclaw:default     # Optional base policy

egress:                        # Network rules
  mode: allowlist
  allowed_domains: [...]

filesystem:                    # File access rules
  forbidden_paths: [...]
  allowed_write_roots: [...]

execution:                     # Command rules
  denied_patterns: [...]

tools:                         # Tool access rules
  allowed: [...]
  denied: [...]

limits:                        # Resource limits
  max_execution_seconds: 300

on_violation: cancel           # What to do on violation
```

## Policy Inheritance

Use `extends` to build on base policies:

```yaml
# Your policy
version: "1.0.0"
name: My Custom Policy
extends: strict

# Only specify overrides
guards:
  forbidden_path:
    additional_patterns:
      - "**/my-secrets/**"
```

### Built-in Rulesets

| Name | Description |
|------|-------------|
| `default` | Balanced security |
| `strict` | Maximum security, blocks by default |
| `permissive` | Development-friendly, logs but allows |

### Extending Files

You can extend from local files:

```yaml
extends: ./base-policy.yaml
```

Paths are resolved relative to the current policy file.

### Merge Strategies

Control how child policy merges with base:

```yaml
merge_strategy: deep_merge  # default
```

| Strategy | Behavior |
|----------|----------|
| `replace` | Child completely replaces base |
| `merge` | Child values override base at top level |
| `deep_merge` | Recursively merge nested structures |

### Adding and Removing Patterns

Use `additional_patterns` and `remove_patterns` to modify base:

```yaml
extends: strict
guards:
  forbidden_path:
    additional_patterns:
      - "**/company-secrets/**"
    remove_patterns:
      - "**/.env"  # Allow .env in this project
```

## Policy Merging

When extending with `deep_merge`, values are merged:

```yaml
# Base policy
guards:
  egress_allowlist:
    allow:
      - "api.github.com"

# Your policy
extends: base
guards:
  egress_allowlist:
    additional_allow:
      - "api.stripe.com"

# Effective policy
guards:
  egress_allowlist:
    allow:
      - "api.github.com"    # From base
      - "api.stripe.com"    # Added from yours
```

For forbidden paths, use `additional_patterns` and `remove_patterns`:

```yaml
# Base
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"

# Yours
extends: ./base.yaml
guards:
  forbidden_path:
    additional_patterns:
      - "**/secrets/**"

# Effective
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/secrets/**"
```

## Environment Variables

Use variables in policies:

```yaml
filesystem:
  allowed_write_roots:
    - "${WORKSPACE}"       # Expands to current directory
    - "${TMPDIR}"          # System temp directory
    - "${HOME}/.cache"     # User cache directory
```

## Policy Modes

Three enforcement modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `deterministic` | Block violations | Production |
| `advisory` | Warn but allow | Testing |
| `audit` | Log only | Rollout |

Set via CLI:

```bash
hush run --mode advisory --policy policy.yaml -- command
```

Or environment:

```bash
HUSHCLAW_MODE=advisory hush run --policy policy.yaml -- command
```

## Policy Loading

Policies are loaded from (in order):

1. CLI flag: `--policy ./custom.yaml`
2. Environment: `HUSHCLAW_POLICY=/path/to/policy.yaml`
3. Project: `.hush/policy.yaml`
4. User: `~/.config/hush/policy.yaml`
5. System: `/etc/hush/policy.yaml`
6. Built-in: `hushclaw:default`

## Hot Reload

Policies can be reloaded without restart:

```bash
# Signal daemon to reload
hush policy reload

# Or via API
curl -X POST http://localhost:9090/policy/reload
```

## Validation

Always validate before deployment:

```bash
hush policy lint policy.yaml
```

Checks:
- YAML syntax
- Schema compliance
- Path format validity
- Domain format validity
- Logical conflicts

## Best Practices

1. **Start with a base policy** - Use `extends:` instead of from scratch
2. **Use environment variables** - `${WORKSPACE}` over hardcoded paths
3. **Test in advisory mode** - Before enforcing
4. **Version control policies** - Track changes
5. **Validate in CI** - Catch errors early

## Next Steps

- [Decisions](./decisions.md) - How violations are handled
- [Policy Schema](../reference/policy-schema.md) - Full schema reference
- [Policy Inheritance](../guides/policy-inheritance.md) - Advanced inheritance
