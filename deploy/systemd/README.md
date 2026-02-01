# Hushd systemd Service

This directory contains systemd service files for running hushd on Linux systems.

## Files

| File | Description |
|------|-------------|
| `hushd.service` | Single instance service file |
| `hushd@.service` | Template for multiple instances |

## Installation

### 1. Create system user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hushd
```

### 2. Create directories

```bash
sudo mkdir -p /etc/hushd /var/lib/hushd /var/log/hushd
sudo chown hushd:hushd /var/lib/hushd /var/log/hushd
```

### 3. Install binary

```bash
# From release tarball
sudo install -m 755 hushd /usr/local/bin/

# Or build from source
cargo build --release -p hushd
sudo install -m 755 target/release/hushd /usr/local/bin/
```

### 4. Install configuration

```bash
sudo cp deploy/config.yaml /etc/hushd/config.yaml
sudo chmod 640 /etc/hushd/config.yaml
sudo chown root:hushd /etc/hushd/config.yaml
```

### 5. Set up API keys (optional)

```bash
# Create environment file for secrets
sudo tee /etc/hushd/environment << 'EOF'
HUSHD_API_KEY=your-api-key-here
HUSHD_ADMIN_KEY=your-admin-key-here
EOF
sudo chmod 600 /etc/hushd/environment
sudo chown hushd:hushd /etc/hushd/environment
```

### 6. Install and enable service

```bash
sudo cp deploy/systemd/hushd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hushd
sudo systemctl start hushd
```

## Commands

| Command | Description |
|---------|-------------|
| `systemctl status hushd` | Check service status |
| `systemctl start hushd` | Start the service |
| `systemctl stop hushd` | Stop the service |
| `systemctl restart hushd` | Restart the service |
| `systemctl reload hushd` | Reload configuration (SIGHUP) |
| `journalctl -u hushd -f` | Follow logs |
| `journalctl -u hushd --since today` | Today's logs |

## Multiple Instances

Use the template service to run multiple instances (e.g., prod and staging):

### 1. Create instance directories

```bash
# For 'prod' instance
sudo mkdir -p /etc/hushd/prod /var/lib/hushd/prod /var/log/hushd/prod
sudo chown hushd:hushd /var/lib/hushd/prod /var/log/hushd/prod

# For 'staging' instance
sudo mkdir -p /etc/hushd/staging /var/lib/hushd/staging /var/log/hushd/staging
sudo chown hushd:hushd /var/lib/hushd/staging /var/log/hushd/staging
```

### 2. Create instance configurations

```bash
# Copy and customize for each instance
sudo cp deploy/config.yaml /etc/hushd/prod/config.yaml
sudo cp deploy/config.yaml /etc/hushd/staging/config.yaml

# Edit to use different ports
sudo sed -i 's/listen: .*/listen: "0.0.0.0:9876"/' /etc/hushd/prod/config.yaml
sudo sed -i 's/listen: .*/listen: "0.0.0.0:9877"/' /etc/hushd/staging/config.yaml
```

### 3. Install template and start instances

```bash
sudo cp deploy/systemd/hushd@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hushd@prod hushd@staging
sudo systemctl start hushd@prod hushd@staging
```

### 4. Manage instances

```bash
systemctl status hushd@prod
systemctl status hushd@staging
journalctl -u hushd@prod -f
journalctl -u hushd@staging -f
```

## Security Notes

The service files include extensive security hardening:

- **NoNewPrivileges** - Prevents privilege escalation
- **ProtectSystem=strict** - Read-only filesystem except explicit paths
- **ProtectHome** - No access to /home directories
- **PrivateTmp** - Isolated /tmp directory
- **PrivateDevices** - No access to physical devices
- **ProtectKernel*** - Kernel protection options
- **RestrictNamespaces** - Prevents namespace creation
- **MemoryDenyWriteExecute** - Prevents memory exploits
- **SystemCallFilter** - Limits available syscalls
- **PrivateUsers** - User namespace isolation
- **CapabilityBoundingSet=** - No special capabilities

### Customizing Security

If hushd needs additional capabilities (e.g., binding to privileged ports):

```bash
# Allow binding to ports < 1024
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/hushd
```

Or modify the service file:

```ini
# Add to [Service] section
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Troubleshooting

### Service won't start

1. Check logs: `journalctl -u hushd -n 50 --no-pager`
2. Verify config syntax: `hushd show-config --config /etc/hushd/config.yaml`
3. Check file permissions: `ls -la /etc/hushd/ /var/lib/hushd/ /var/log/hushd/`

### Permission denied errors

Ensure the hushd user owns its directories:

```bash
sudo chown -R hushd:hushd /var/lib/hushd /var/log/hushd
```

### Configuration changes not taking effect

The daemon supports hot reload via SIGHUP:

```bash
sudo systemctl reload hushd
```

For major changes, restart:

```bash
sudo systemctl restart hushd
```
