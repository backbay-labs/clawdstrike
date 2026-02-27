# SecretLeakGuard

Scans file writes and patches for secret-like patterns (regex) and blocks or warns depending on severity.

## Actions

- `GuardAction::FileWrite(path, bytes)`
- `GuardAction::Patch(path, diff)`

## Configuration

```yaml
guards:
  secret_leak:
    enabled: true
    redact: true                    # redact matched values in audit details
    severity_threshold: error       # block when max severity >= this level
    patterns:
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
        description: "GitHub personal access token"
        luhn_check: false
        masking:                    # optional custom masking
          first: 4
          last: 4
    additional_patterns:            # additive patterns (merged by name)
      - name: custom_api_key
        pattern: "myapp_[A-Za-z0-9]{32}"
        severity: error
    remove_patterns:                # pattern names to remove from effective set
      - generic_secret
    skip_paths:
      - "**/tests/**"
      - "**/fixtures/**"
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. |
| `redact` | bool | `true` | Redact matched secret values in logs/audit details. |
| `severity_threshold` | Severity | `error` | Block when the highest matched severity is at-or-above this level. |
| `patterns` | SecretPattern[] | (18 built-in patterns) | Secret patterns to detect. |
| `additional_patterns` | SecretPattern[] | `[]` | Patterns to add (merged by name, additive with base). |
| `remove_patterns` | string[] | `[]` | Pattern names to remove from the effective set. |
| `skip_paths` | string[] | `["**/test/**", "**/tests/**", "**/*_test.*", "**/*.test.*"]` | File glob patterns to skip. |

### SecretPattern fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | (required) | Pattern identifier. |
| `pattern` | string | (required) | Regex pattern to match. |
| `severity` | Severity | `critical` | Severity level assigned to matches. |
| `description` | string or null | `null` | Optional description (useful for compliance evidence). |
| `luhn_check` | bool | `false` | Require Luhn validation (for card numbers). |
| `masking` | object or null | `null` | Custom masking with `first` and `last` visible character counts. |

## Behavior

- Content is scanned only if it is valid UTF-8 (binary content is skipped).
- Matches are redacted in results (only a prefix/suffix is preserved) when `redact: true`.
- If the highest matched severity >= `severity_threshold` → blocked result.
- Otherwise → warning result (allowed).
