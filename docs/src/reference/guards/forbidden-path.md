# ForbiddenPathGuard

Blocks access to sensitive filesystem paths.

## Overview

The ForbiddenPathGuard prevents agents from reading or writing files that could expose credentials or compromise security.

## Default Protected Paths

| Path | Reason |
|------|--------|
| `~/.ssh/*` | SSH private keys |
| `~/.aws/*` | AWS credentials |
| `~/.gnupg/*` | GPG keys |
| `~/.config/gcloud/*` | Google Cloud credentials |
| `~/.kube/*` | Kubernetes config |
| `/etc/shadow` | System passwords |
| `/etc/passwd` | User information |
| `.env`, `.env.*` | Environment secrets |
| `*.pem`, `*.key` | Private keys |

## Configuration

```yaml
filesystem:
  forbidden_paths:
    # Add your own patterns
    - "~/.myapp/secrets"
    - "*.secret"
    - "./credentials/*"

  allowed_write_roots:
    - "/workspace"
    - "/tmp"
```

## Glob Patterns

Supports glob patterns for flexible matching:

| Pattern | Matches |
|---------|---------|
| `~/.ssh/*` | All files in .ssh directory |
| `*.pem` | Any file ending in .pem |
| `.env*` | .env, .env.local, .env.production |
| `/etc/shadow` | Exact path only |
| `**/*.key` | .key files in any subdirectory |

## Symlink Defense

The guard canonicalizes paths to prevent symlink attacks:

```
/tmp/innocent → ~/.ssh/id_rsa (symlink)

Request: FileRead("/tmp/innocent")
Resolved: ~/.ssh/id_rsa
Result: DENIED (forbidden path)
```

## Example Violations

```
Event: FileRead { path: "~/.ssh/id_rsa" }
Decision: Deny
Guard: ForbiddenPathGuard
Severity: Critical
Reason: Path matches forbidden pattern: ~/.ssh/*
```

```
Event: FileWrite { path: ".env.production" }
Decision: Deny
Guard: ForbiddenPathGuard
Severity: High
Reason: Path matches forbidden pattern: .env*
```

## Customization

### Add forbidden paths

```yaml
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./credentials.json"
```

### Restrict write locations

```yaml
filesystem:
  allowed_write_roots:
    - "./src"
    - "./tests"
    - "/tmp"
```

Writes outside these roots are denied.

### Path precedence

Forbidden paths always take precedence over allowed roots:

```yaml
filesystem:
  allowed_write_roots:
    - "./"  # Allow writing to project
  forbidden_paths:
    - "./.env"  # But not .env (takes precedence)
```

## Testing

```bash
# Test a path
echo '{"event_type":"file_read","data":{"path":"~/.ssh/id_rsa"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Related

- [Policies](../../concepts/policies.md) - Configure forbidden paths
- [Decisions](../../concepts/decisions.md) - Understanding denials
