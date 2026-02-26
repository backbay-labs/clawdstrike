# ForbiddenPathGuard

Blocks filesystem actions when a path matches a forbidden glob pattern.

## Actions

- `GuardAction::FileAccess(path)`
- `GuardAction::FileWrite(path, bytes)`
- `GuardAction::Patch(path, diff)`

## Configuration

```yaml
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "/etc/shadow"
    exceptions:
      - "**/.env.example"
    additional_patterns: []
    remove_patterns: []
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. |
| `patterns` | string[] or null | `null` (uses built-in defaults) | Glob patterns to block. When `null`, the full set of default patterns is used. |
| `exceptions` | string[] | `[]` | Glob patterns that override blocks (checked first). |
| `additional_patterns` | string[] | `[]` | Patterns to add when merging via `extends`. |
| `remove_patterns` | string[] | `[]` | Patterns to remove when merging via `extends`. |

## Default Windows patterns

The default forbidden patterns include Windows-specific paths (included unconditionally; they never match on Unix):

- `**/AppData/Roaming/Microsoft/Credentials/**` -- Windows credential stores
- `**/AppData/Local/Microsoft/Credentials/**`
- `**/AppData/Roaming/Microsoft/Vault/**` -- Credential Manager vault
- `**/NTUSER.DAT` / `**/NTUSER.DAT.*` -- Registry hives
- `**/Windows/System32/config/SAM` -- SAM database
- `**/Windows/System32/config/SECURITY` -- SECURITY hive
- `**/Windows/System32/config/SYSTEM` -- SYSTEM hive
- `**/*.reg` -- Registry export files
- `**/AppData/Roaming/Microsoft/SystemCertificates/**` -- Certificate stores
- `**/WindowsPowerShell/profile.ps1` / `**/PowerShell/profile.ps1` -- PowerShell profiles

## Notes

- Glob syntax is provided by the Rust `glob` crate.
- Paths are matched against a normalized string (backslashes become `/`). `~` is not expanded.
- Symlink targets are resolved before matching. A symlink into a forbidden directory is blocked even if the symlink's lexical path looks safe.
