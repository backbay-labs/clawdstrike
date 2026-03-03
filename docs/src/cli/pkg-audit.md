# clawdstrike pkg audit

Show package publish/yank history from the registry audit log.

## Usage

```bash
clawdstrike pkg audit <NAME> [--limit <N>] [--registry <URL>]
```

## Output

- Version
- Action (`publish` / `yank`)
- Timestamp
- Publisher key (truncated display)

## Endpoint

Uses `GET /api/v1/audit/{name}?limit=<N>`.
