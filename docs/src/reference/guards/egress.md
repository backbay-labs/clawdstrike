# EgressAllowlistGuard

Controls network egress via a simple allow/block list of domain patterns.

## Actions

- `GuardAction::NetworkEgress(host, port)`

## Configuration

```yaml
guards:
  egress_allowlist:
    allow:
      - "api.github.com"
      - "*.openai.com"
    block:
      - "bad.example.com"
    default_action: block # allow|block|log
    additional_allow: []
    remove_allow: []
    additional_block: []
    remove_block: []
```

## Matching semantics

Domain patterns use `globset` (shell-style glob patterns) and are matched **case-insensitively** against the full `host` string.

Supported syntax includes:

- `*` (match any sequence)
- `?` (match any single character)
- character classes like `[a-z]`

Examples:

- `api.github.com` (exact)
- `*.github.com` (any subdomain of `github.com`)
- `api-?.example.com` (single-character slot)
- `api-[0-9].example.com` (character class)

Note: `*.example.com` does **not** match `example.com`. If you want both, list both `example.com` and `*.example.com`.

## Default action

- `allow`: allow if no allow/block pattern matches
- `block`: block if no allow/block pattern matches
- `log`: allow, but return a warning result (useful for audit-only runs)
