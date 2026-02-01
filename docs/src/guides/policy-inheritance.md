# Policy Inheritance

Build on base policies with the `extends` keyword.

## Overview

Policy inheritance lets you:

- Start from a secure baseline
- Override only what you need
- Maintain consistency across projects
- Share policies across teams

## Basic Inheritance

```yaml
# my-policy.yaml
version: "1.0.0"
name: My Custom Policy
extends: strict

# Your customizations here
guards:
  egress_allowlist:
    additional_allow:
      - "api.mycompany.com"
```

## Built-in Rulesets

| Ruleset | Description | Use Case |
|---------|-------------|----------|
| `default` | Balanced security | General development |
| `strict` | Maximum security | Production |
| `ai-agent` | AI agent optimized | AI coding agents |

## Merge Strategies

Control how child policies merge with base using `merge_strategy`:

```yaml
extends: strict
merge_strategy: deep_merge  # default
```

| Strategy | Behavior |
|----------|----------|
| `replace` | Child completely replaces base |
| `merge` | Child values override base at top level |
| `deep_merge` | Recursively merge nested structures (default) |

### Replace Strategy

```yaml
extends: strict
merge_strategy: replace

# This policy ignores all base settings
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
```

### Deep Merge Strategy (Default)

```yaml
extends: strict
merge_strategy: deep_merge

settings:
  verbose_logging: true  # Added to base settings
  # fail_fast: true      # Inherited from strict
```

## Adding and Removing Patterns

Use `additional_patterns` and `remove_patterns` to modify base guard configs:

### Adding Patterns

```yaml
extends: strict

guards:
  forbidden_path:
    additional_patterns:
      - "**/company-secrets/**"
      - "**/credentials/**"
```

### Removing Patterns

```yaml
extends: strict

guards:
  forbidden_path:
    remove_patterns:
      - "**/.env"  # Allow .env in this project
```

### Combined Example

```yaml
extends: ./base-policy.yaml

guards:
  forbidden_path:
    additional_patterns:
      - "**/production-secrets/**"
    remove_patterns:
      - "**/.env"  # Allow for local dev
```

## Egress Allowlist Inheritance

For egress guards, use `additional_allow`, `remove_allow`, `additional_block`, `remove_block`:

```yaml
extends: strict

guards:
  egress_allowlist:
    additional_allow:
      - "api.stripe.com"
      - "*.internal.company.com"
    remove_allow:
      - "example.com"  # Remove from base allowlist
```

## MCP Tool Inheritance

Similar pattern for MCP tool guards:

```yaml
extends: strict

guards:
  mcp_tool:
    additional_block:
      - "dangerous_tool"
    remove_require_confirmation:
      - "git_push"  # Don't require confirmation in CI
```

## File-Based Inheritance

Extend from local files using relative or absolute paths:

```yaml
# Relative path (resolved from current policy file)
extends: ./base-policy.yaml

# Absolute path
extends: /etc/hush/company-policy.yaml
```

## Multi-Level Inheritance

Chain policies for layered configuration:

```yaml
# company-base.yaml
version: "1.0.0"
name: Company Base
extends: strict

guards:
  egress_allowlist:
    additional_allow:
      - "*.company.com"

# team-policy.yaml
version: "1.0.0"
name: Team Policy
extends: ./company-base.yaml

guards:
  egress_allowlist:
    additional_allow:
      - "api.team-vendor.com"

# project-policy.yaml
version: "1.0.0"
name: Project Policy
extends: ./team-policy.yaml

guards:
  egress_allowlist:
    additional_allow:
      - "api.project-specific.com"
```

The final effective policy includes all domains from the inheritance chain.

## View Effective Policy

See the merged result with the `--merged` flag:

```bash
hush policy show --merged my-policy.yaml
```

Output shows the fully resolved policy after all inheritance is applied.

## Validate with Resolution

Validate a policy and resolve its inheritance chain:

```bash
hush policy validate --resolve my-policy.yaml
```

## Circular Dependency Detection

Hushclaw detects and rejects circular extends:

```yaml
# policy-a.yaml
extends: ./policy-b.yaml

# policy-b.yaml
extends: ./policy-a.yaml

# Error: Circular extends detected
```

## Best Practices

### 1. Start from Built-in Rulesets

```yaml
extends: strict  # Not from scratch
```

### 2. Use Deep Merge for Additions

```yaml
extends: strict
merge_strategy: deep_merge  # default, keeps base protections

guards:
  forbidden_path:
    additional_patterns:
      - "**/my-secrets/**"
```

### 3. Document Your Extensions

```yaml
# This policy extends strict with:
# - Additional allowed domains for our APIs
# - Removed .env restriction for local dev
version: "1.0.0"
name: My Dev Policy
extends: strict
```

### 4. Use Version Control

Store policies in git alongside your code.

### 5. Validate Before Deploy

```bash
hush policy validate --resolve my-policy.yaml
```

## Common Patterns

### Development Policy

```yaml
version: "1.0.0"
name: Dev Policy
extends: ./base-policy.yaml
merge_strategy: deep_merge

guards:
  forbidden_path:
    remove_patterns:
      - "**/.env"  # Allow .env locally
    additional_patterns:
      - "**/.env.production"  # But not production env

  egress_allowlist:
    additional_allow:
      - "localhost"
      - "127.0.0.1"

settings:
  verbose_logging: true
  session_timeout_secs: 7200  # 2 hours for dev
```

### CI/CD Policy

```yaml
version: "1.0.0"
name: CI Policy
extends: strict

guards:
  mcp_tool:
    remove_require_confirmation:
      - "git_push"  # Automated, no confirmation needed

settings:
  fail_fast: true
  session_timeout_secs: 600
```

### Team Base Policy

```yaml
version: "1.0.0"
name: Team Base
extends: strict

guards:
  egress_allowlist:
    additional_allow:
      - "*.internal.company.com"
      - "api.github.com"

  forbidden_path:
    additional_patterns:
      - "**/team-secrets/**"
```

## Next Steps

- [Policies Concepts](../concepts/policies.md) - Policy fundamentals
- [Policy Schema](../reference/policy-schema.md) - Full schema reference
- [Rulesets](../reference/rulesets/README.md) - Built-in ruleset details
