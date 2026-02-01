# EgressAllowlistGuard

Controls network egress via domain allowlisting.

## Overview

The EgressAllowlistGuard blocks network connections to domains not in the allowlist, preventing data exfiltration and C2 connections.

## Modes

| Mode | Behavior |
|------|----------|
| `allowlist` | Only allow listed domains (recommended) |
| `denylist` | Block listed domains, allow others |
| `open` | Allow all (not recommended) |

## Configuration

```yaml
egress:
  mode: allowlist

  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "*.github.com"
    - "registry.npmjs.org"

  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
    - "10.*"
    - "192.168.*"
```

## Domain Matching

### Exact match
```yaml
allowed_domains:
  - "api.github.com"  # Only api.github.com
```

### Wildcard subdomain
```yaml
allowed_domains:
  - "*.github.com"  # Matches any subdomain
```

Matches: `api.github.com`, `raw.github.com`, `gist.github.com`
Does not match: `github.com` (no subdomain)

### IP patterns
```yaml
denied_domains:
  - "127.*"        # Localhost range
  - "10.*"         # Private network
  - "192.168.*"    # Private network
```

## Default Denied

These are always denied regardless of policy:

- `*.onion` (Tor hidden services)
- Private IP ranges (RFC 1918)
- Localhost variants

## Example Violations

```
Event: NetworkEgress { host: "evil.com", port: 443 }
Decision: Deny
Guard: EgressAllowlistGuard
Severity: High
Reason: Domain not in allowlist: evil.com
```

```
Event: NetworkEgress { host: "192.168.1.1", port: 22 }
Decision: Deny
Guard: EgressAllowlistGuard
Severity: Medium
Reason: Private IP addresses are denied
```

## Common Allowlists

### AI Development
```yaml
egress:
  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "generativelanguage.googleapis.com"
```

### Package Registries
```yaml
egress:
  allowed_domains:
    - "pypi.org"
    - "files.pythonhosted.org"
    - "registry.npmjs.org"
    - "crates.io"
```

### Git Hosting
```yaml
egress:
  allowed_domains:
    - "*.github.com"
    - "*.githubusercontent.com"
    - "gitlab.com"
```

## Testing

```bash
# Test domain access
echo '{"event_type":"network_egress","data":{"host":"evil.com","port":443}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [Policies](../../concepts/policies.md) - Configure egress rules
- [Rulesets](../rulesets/README.md) - Pre-built allowlists
