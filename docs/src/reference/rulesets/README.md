# Rulesets

Built-in security policy presets.

## Overview

Hushclaw includes several pre-configured rulesets:

| Ruleset | Security Level | Use Case |
|---------|---------------|----------|
| [Default](./default.md) | Medium | General development |
| [Strict](./strict.md) | High | Production, sensitive work |
| [AI Agent](./ai-agent.md) | Medium | AI coding agents |

## Using Rulesets

### Directly

```bash
hush run --policy hushclaw:default -- command
```

### As Base

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:default

# Your customizations
egress:
  allowed_domains:
    - "api.mycompany.com"
```

## Comparison

| Feature | Default | Strict | AI Agent |
|---------|---------|--------|----------|
| **Egress Mode** | Allowlist | Allowlist | Allowlist |
| **AI APIs** | Yes | Yes | Yes |
| **Package Registries** | Yes | No | Yes |
| **Write Restrictions** | Workspace + tmp | Workspace only | Workspace + tmp |
| **Git Operations** | Allowed | Restricted | Confirmation |
| **Secrets Protection** | Yes | Yes | Yes |
| **Max Execution** | 300s | 120s | 600s |

## Custom Rulesets

Create your own:

```yaml
# company-ruleset.yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "*.company.com"
    - "api.github.com"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env*"

on_violation: cancel
```

Use it:

```yaml
extends: file://./company-ruleset.yaml
```

## Sharing Rulesets

### Via URL

```yaml
extends: https://policies.company.com/standard.yaml
```

### Via Git

```yaml
extends: git://github.com/company/policies.git#main:security/base.yaml
```

## Next Steps

- [Default Ruleset](./default.md) - Balanced security
- [Strict Ruleset](./strict.md) - Maximum security
- [AI Agent Ruleset](./ai-agent.md) - AI agent optimized
