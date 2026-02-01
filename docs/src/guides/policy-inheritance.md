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
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Your customizations here
egress:
  allowed_domains:
    - "api.mycompany.com"
```

## Built-in Base Policies

| Policy | Description | Use Case |
|--------|-------------|----------|
| `hushclaw:minimal` | Bare minimum | Debugging |
| `hushclaw:default` | Balanced security | General development |
| `hushclaw:strict` | Maximum security | Production |
| `hushclaw:ai-agent` | AI agent optimized | AI coding agents |
| `hushclaw:cicd` | CI/CD pipelines | Automation |

## Merge Behavior

### Lists Are Combined

```yaml
# Base policy
egress:
  allowed_domains:
    - "api.github.com"

# Your policy
extends: base
egress:
  allowed_domains:
    - "api.stripe.com"

# Effective policy
egress:
  allowed_domains:
    - "api.github.com"    # From base
    - "api.stripe.com"    # From yours
```

### Scalars Are Overwritten

```yaml
# Base policy
limits:
  max_execution_seconds: 300

# Your policy
extends: base
limits:
  max_execution_seconds: 120

# Effective: 120 (your value wins)
```

### Objects Are Merged Recursively

```yaml
# Base policy
egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"

# Your policy
extends: base
egress:
  allowed_domains:
    - "api.stripe.com"
  # mode inherits from base (allowlist)

# Effective
egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "api.stripe.com"
```

## Multi-Level Inheritance

Chain policies:

```yaml
# company-base.yaml
version: "hushclaw-v1.0"
extends: hushclaw:strict

egress:
  allowed_domains:
    - "*.company.com"

# team-policy.yaml
version: "hushclaw-v1.0"
extends: file://company-base.yaml

egress:
  allowed_domains:
    - "api.team-vendor.com"

# project-policy.yaml
version: "hushclaw-v1.0"
extends: file://team-policy.yaml

egress:
  allowed_domains:
    - "api.project-specific.com"
```

## Override Patterns

### Add to forbidden paths

```yaml
extends: hushclaw:default

filesystem:
  forbidden_paths:
    - "./secrets"           # Added to base list
    - "./credentials.json"  # Added to base list
```

### Restrict allowed domains

```yaml
extends: hushclaw:default

egress:
  mode: allowlist
  allowed_domains:
    # Only these are allowed (replaces base list)
    - "api.github.com"
  _replace: true  # Special flag to replace instead of merge
```

### Disable a guard

```yaml
extends: hushclaw:default

guards:
  patch_integrity: false  # Disable this guard
```

## Remote Policies

Extend from URLs:

```yaml
extends: https://policies.company.com/base-policy.yaml
```

Or from git:

```yaml
extends: git://github.com/company/policies.git#main:security/base.yaml
```

## Local File Inheritance

```yaml
# Relative path
extends: file://./base-policy.yaml

# Absolute path
extends: file:///etc/hush/company-policy.yaml
```

## View Effective Policy

See the merged result:

```bash
hush policy show --effective
```

Output:

```yaml
# Effective policy (merged from inheritance chain)
version: "hushclaw-v1.0"
# Base: hushclaw:ai-agent → company-base.yaml → this file

egress:
  mode: allowlist
  allowed_domains:
    - "api.anthropic.com"      # from hushclaw:ai-agent
    - "api.openai.com"         # from hushclaw:ai-agent
    - "*.company.com"          # from company-base.yaml
    - "api.project.com"        # from this file

filesystem:
  forbidden_paths:
    - "~/.ssh"                 # from hushclaw:ai-agent
    - "~/.aws"                 # from hushclaw:ai-agent
    - "./secrets"              # from this file
```

## Best Practices

### 1. Start from Built-in Policies

```yaml
extends: hushclaw:ai-agent  # Not from scratch
```

### 2. Document Your Extensions

```yaml
# This policy extends ai-agent with:
# - Additional allowed domains for our APIs
# - Stricter file restrictions for secrets
extends: hushclaw:ai-agent
```

### 3. Use Version Control

Store policies in git alongside your code.

### 4. Validate Before Deploy

```bash
hush policy lint my-policy.yaml
```

### 5. Test Inheritance Chain

```bash
hush policy show --effective --policy my-policy.yaml
```

## Common Patterns

### Project-Specific Policy

```yaml
extends: hushclaw:ai-agent

egress:
  allowed_domains:
    - "api.stripe.com"       # Payment processing
    - "sentry.io"            # Error tracking

filesystem:
  forbidden_paths:
    - "./.env.production"
    - "./secrets/*"
```

### Team Base Policy

```yaml
extends: hushclaw:strict

egress:
  allowed_domains:
    - "*.internal.company.com"
    - "api.github.com"

limits:
  max_execution_seconds: 180
```

### CI/CD Override

```yaml
extends: file://./team-policy.yaml

limits:
  max_execution_seconds: 600  # Longer for CI

on_violation: cancel  # Fail fast
```

## Next Steps

- [Policy Schema](../reference/policy-schema.md) - Full schema reference
- [Rulesets](../reference/rulesets/README.md) - Built-in policy details
- [Audit Logging](./audit-logging.md) - Log policy decisions
