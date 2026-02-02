# PatchIntegrityGuard

Validates unified diffs for obviously dangerous changes and unusually large patches.

## Actions

- `GuardAction::Patch(path, diff)`

## Configuration

```yaml
guards:
  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "(?i)chmod\\s+777"
    require_balance: false
    max_imbalance_ratio: 10.0
```

## Behavior

- Counts additions/deletions by diff line prefix (`+`/`-`, excluding `+++`/`---` headers).
- Blocks if:
  - a forbidden regex matches an added line, or
  - size limits are exceeded, or
  - `require_balance` is enabled and imbalance exceeds `max_imbalance_ratio`.
