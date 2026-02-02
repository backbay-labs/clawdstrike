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

- `patterns`: glob patterns to block
- `exceptions`: glob patterns that override blocks (checked first)
- `additional_patterns`: patterns to add when merging via `extends`
- `remove_patterns`: patterns to remove when merging via `extends`

## Notes

- Glob syntax is provided by the Rust `glob` crate.
- Paths are matched against a normalized string (backslashes become `/`). `~` is not expanded.
