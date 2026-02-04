# Hushd Deployment

This directory contains deployment configurations for running the hushd security daemon in production.

## Platform Support

| Platform | Init System | Directory | Documentation |
|----------|-------------|-----------|---------------|
| Linux | systemd | `systemd/` | [README](systemd/README.md) |
| macOS | launchd | `launchd/` | [README](launchd/README.md) |
| Container | Docker/Podman | `../Dockerfile.hushd` | See below |

## Quick Start

### Linux (systemd)

```bash
# Install service
sudo cp deploy/systemd/hushd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hushd

# Check status
systemctl status hushd
journalctl -u hushd -f
```

See [systemd/README.md](systemd/README.md) for full installation instructions.

### macOS (launchd)

```bash
# Install as system daemon
sudo cp deploy/launchd/dev.clawdstrike.hushd.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/dev.clawdstrike.hushd.plist

# Check status
sudo launchctl list | grep hushd
```

See [launchd/README.md](launchd/README.md) for full installation instructions including user-level setup.

### Docker

```bash
# Build image
docker build -f Dockerfile.hushd -t clawdstrike/hushd .

# Run container
docker run -d \
  --name hushd \
  -p 9876:9876 \
  -v /path/to/config.yaml:/etc/hushd/config.yaml:ro \
  -v hushd-data:/var/lib/hushd \
  clawdstrike/hushd
```

### Docker Compose

```yaml
version: '3.8'
services:
  hushd:
    build:
      context: .
      dockerfile: Dockerfile.hushd
    ports:
      - "9876:9876"
    volumes:
      - ./config.yaml:/etc/hushd/config.yaml:ro
      - hushd-data:/var/lib/hushd
    environment:
      - RUST_LOG=info
      - HUSHD_API_KEY=${HUSHD_API_KEY}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9876/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  hushd-data:
```

## Configuration

All deployment methods use the same configuration file format. See `config.yaml` for an example.

### Required directories

| Directory | Purpose |
|-----------|---------|
| `/etc/hushd/` (or `/usr/local/etc/hushd/`) | Configuration files |
| `/var/lib/hushd/` (or `/usr/local/var/lib/hushd/`) | Persistent data (audit DB) |
| `/var/log/hushd/` (or `/usr/local/var/log/hushd/`) | Log files |

### Environment variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Log level (trace, debug, info, warn, error) |
| `HUSHD_API_KEY` | Default API key for authenticated endpoints |
| `HUSHD_ADMIN_KEY` | Admin API key with full permissions |

## Security

### Network

By default, hushd listens on `127.0.0.1:9876`. For production:

1. Use a firewall to restrict access
2. Terminate TLS at a reverse proxy (native TLS is not implemented in hushd yet)
3. Use API keys for authentication

### File permissions

```bash
# Config should be readable by daemon only
chmod 640 /etc/hushd/config.yaml
chown root:hushd /etc/hushd/config.yaml

# Data directory should be writable
chmod 750 /var/lib/hushd
chown hushd:hushd /var/lib/hushd
```

## Monitoring

### Health endpoint

```bash
curl http://localhost:9876/health
```

### Prometheus metrics

Prometheus `/metrics` is not implemented in v0.1.0.

### Log analysis

```bash
# Linux
journalctl -u hushd --since "1 hour ago" | grep -i error

# macOS
grep -i error /usr/local/var/log/hushd/hushd.log

# Docker
docker logs hushd 2>&1 | grep -i error
```
