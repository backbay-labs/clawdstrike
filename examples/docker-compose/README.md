# Docker Compose Example

Run hushd locally with Docker Compose for development and testing.

## Quick Start

```bash
# Generate a secure API key
export CLAWDSTRIKE_API_KEY=$(openssl rand -hex 32)

# Start hushd
docker compose up -d

# Check health
curl http://localhost:8080/health

# View logs
docker compose logs -f hushd
```

## Test Policy Check

```bash
# Check file access (should pass)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Authorization: Bearer $CLAWDSTRIKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": "file_access", "path": "/tmp/test.txt"}'

# Check forbidden path (should fail)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Authorization: Bearer $CLAWDSTRIKE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action": "file_access", "path": "/etc/shadow"}'
```

## Configuration

| File | Purpose |
|------|---------|
| `config.yaml` | Daemon configuration (ports, auth) |
| `policy.yaml` | Security policy (guards, allowlists) |

## Volumes

- `hushd-data` - Persists audit database between restarts

## Stop

```bash
docker compose down
```

## Clean Up

```bash
docker compose down -v  # Also removes volumes
```
