# SecretLeakGuard

Scans file writes and patches for secret-like patterns (regex) and blocks or warns depending on severity.

## Actions

- `GuardAction::FileWrite(path, bytes)`
- `GuardAction::Patch(path, diff)`

## Configuration

```yaml
guards:
  secret_leak:
    patterns:
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical # info|warning|error|critical
    skip_paths:
      - "**/tests/**"
      - "**/fixtures/**"
```

## Behavior

- Content is scanned only if it is valid UTF-8 (binary content is skipped).
- Matches are redacted in results (only a prefix/suffix is preserved).
- `severity: critical|error` → blocked result
- `severity: warning|info` → warning result (allowed)
