# clawdstrike pkg search

Search package metadata in a registry.

## Usage

```bash
clawdstrike pkg search <QUERY> [--limit <N>] [--page <N>] [--registry <URL>]
```

## Output

- Package name
- Latest version
- Description
- Pagination summary (`showing X-Y of Z`)

## Endpoint

Uses `GET /api/v1/search?q=<query>&limit=<limit>&offset=<offset>`.
