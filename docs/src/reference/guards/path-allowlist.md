# PathAllowlistGuard

Deny-by-default path allowlisting. When enabled, only paths matching the configured glob patterns are permitted.

## Actions

- `GuardAction::FileAccess(path)`
- `GuardAction::FileWrite(path, bytes)`
- `GuardAction::Patch(path, diff)`

## Configuration

```yaml
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/workspace/**"
      - "**/tmp/**"
    file_write_allow:
      - "**/workspace/**"
    patch_allow: []          # falls back to file_write_allow when empty
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. When disabled (or `enabled: false`), all paths are allowed. |
| `file_access_allow` | string[] | `[]` | Glob patterns for allowed `FileAccess` paths. |
| `file_write_allow` | string[] | `[]` | Glob patterns for allowed `FileWrite` paths. |
| `patch_allow` | string[] | `[]` | Glob patterns for allowed `Patch` paths. Falls back to `file_write_allow` when empty. |

## How it differs from ForbiddenPathGuard

| | ForbiddenPathGuard | PathAllowlistGuard |
|-|--------------------|--------------------|
| Default posture | Allow-by-default (block listed paths) | Deny-by-default (allow listed paths) |
| Config approach | Blocklist of forbidden patterns | Allowlist of permitted patterns |
| Use case | Block known-sensitive paths | Restrict agent to a specific working directory |

Both guards can be used together. `ForbiddenPathGuard` runs first; if it blocks, `PathAllowlistGuard` is never reached. If it allows, the path must then also pass `PathAllowlistGuard`.

## Symlink handling

Paths are resolved through the filesystem before matching. If a symlink resolves to a target outside the allowlist, the access is denied even if the symlink's lexical path matches an allowlist entry. This prevents symlink-based allowlist bypasses.

## Notes

- Glob syntax is provided by the Rust `glob` crate.
- This guard is available in schema version `1.2.0` and later.
- The default `PathAllowlistGuard` is disabled (`enabled: false`) when no config is provided.
