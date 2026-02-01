# Docker Examples

This directory contains Docker configurations for running hushclaw in containerized environments.

## Contents

- `Dockerfile.hushd` - Multi-stage Dockerfile for the hushd daemon
- `docker-compose.yaml` - Full stack with hushd + sample agent
- `policy.yaml` - Example policy for containerized deployment

## Quick Start

```bash
# Build and start all services
docker compose up -d

# View logs
docker compose logs -f hushd

# Stop services
docker compose down
```

## Services

### hushd

The hushclaw daemon that enforces policies and generates audit receipts.

- **Port 9090**: gRPC API
- **Port 9091**: HTTP health check
- **Volume**: `/var/lib/hushd` for receipts and state

### sample-agent

A demonstration agent that runs through hushclaw's security layer.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HUSH_POLICY_PATH` | `/etc/hushd/policy.yaml` | Path to policy file |
| `HUSH_RECEIPT_DIR` | `/var/lib/hushd/receipts` | Receipt storage directory |
| `HUSH_LOG_LEVEL` | `info` | Logging verbosity |
| `HUSH_MODE` | `deterministic` | Enforcement mode |

### Custom Policy

Mount your own policy file:

```yaml
volumes:
  - ./my-policy.yaml:/etc/hushd/policy.yaml:ro
```

## Production Considerations

1. **Persistence**: Mount `/var/lib/hushd` to retain receipts across restarts
2. **Secrets**: Use Docker secrets or external secret management
3. **Networking**: Consider using a private network for agent-daemon communication
4. **Resources**: Set appropriate CPU/memory limits

## Health Checks

The hushd container includes a health check on port 9091:

```bash
curl http://localhost:9091/health
```

Response:
```json
{"status": "healthy", "version": "0.1.0"}
```
