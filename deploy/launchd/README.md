# Hushd launchd Service

This directory contains launchd configuration for running hushd on macOS.

## Files

| File | Description |
|------|-------------|
| `dev.hushclaw.hushd.plist` | Launch daemon/agent configuration |

## Installation Options

### Option A: System-level daemon (runs as root, starts at boot)

For production servers where hushd should start automatically:

```bash
# Create directories
sudo mkdir -p /usr/local/etc/hushd /usr/local/var/lib/hushd /usr/local/var/log/hushd

# Install configuration
sudo cp deploy/config.yaml /usr/local/etc/hushd/config.yaml

# Install plist
sudo cp deploy/launchd/dev.hushclaw.hushd.plist /Library/LaunchDaemons/

# Load and start
sudo launchctl load /Library/LaunchDaemons/dev.hushclaw.hushd.plist
```

### Option B: User-level agent (runs as current user)

For development or per-user installations:

```bash
# Create directories
mkdir -p ~/Library/Logs/hushd ~/.config/hushd ~/.local/share/hushd

# Modify plist paths for user directories
# (edit the plist or use the Homebrew formula which handles this)

# Install plist
cp deploy/launchd/dev.hushclaw.hushd.plist ~/Library/LaunchAgents/

# Load and start
launchctl load ~/Library/LaunchAgents/dev.hushclaw.hushd.plist
```

### Option C: Homebrew (recommended for development)

If installed via Homebrew:

```bash
brew install hushclaw/tap/hush

# For system-level (requires sudo)
sudo brew services start hush

# For user-level
brew services start hush
```

## Commands

| Command | Description |
|---------|-------------|
| `launchctl list \| grep hushd` | Check if running |
| `launchctl load <plist>` | Load and start service |
| `launchctl unload <plist>` | Stop and unload service |
| `launchctl start dev.hushclaw.hushd` | Start loaded service |
| `launchctl stop dev.hushclaw.hushd` | Stop loaded service |
| `tail -f /usr/local/var/log/hushd/hushd.log` | Follow logs |

### System-level commands (with sudo)

```bash
# Load
sudo launchctl load /Library/LaunchDaemons/dev.hushclaw.hushd.plist

# Unload
sudo launchctl unload /Library/LaunchDaemons/dev.hushclaw.hushd.plist

# Check status
sudo launchctl list | grep hushd
```

### User-level commands

```bash
# Load
launchctl load ~/Library/LaunchAgents/dev.hushclaw.hushd.plist

# Unload
launchctl unload ~/Library/LaunchAgents/dev.hushclaw.hushd.plist

# Check status
launchctl list | grep hushd
```

## Configuration

### Environment Variables

To set API keys or other secrets, create an environment file and source it in the plist, or set them before loading:

```bash
# Set via launchctl
launchctl setenv HUSHD_API_KEY "your-api-key"
launchctl setenv HUSHD_ADMIN_KEY "your-admin-key"

# Then restart
launchctl stop dev.hushclaw.hushd
launchctl start dev.hushclaw.hushd
```

### Log Locations

| Level | Log Path |
|-------|----------|
| System | `/usr/local/var/log/hushd/hushd.log` |
| User | `~/Library/Logs/hushd/hushd.log` |
| Stderr | Same directory with `.error.log` suffix |

### Resource Limits

The plist includes resource limits:
- 65536 open file descriptors
- 4096 processes

To modify, edit the `SoftResourceLimits` and `HardResourceLimits` sections.

## Troubleshooting

### Service won't start

1. Check launchd logs:
   ```bash
   log show --predicate 'subsystem == "com.apple.launchd"' --last 5m | grep hushd
   ```

2. Check hushd logs:
   ```bash
   cat /usr/local/var/log/hushd/hushd.error.log
   ```

3. Verify binary exists:
   ```bash
   ls -la /usr/local/bin/hushd
   ```

4. Test manual start:
   ```bash
   /usr/local/bin/hushd --config /usr/local/etc/hushd/config.yaml
   ```

### Permission issues

Ensure directories are writable:

```bash
# For system-level
sudo chown -R root:wheel /usr/local/etc/hushd
sudo chmod 755 /usr/local/var/lib/hushd /usr/local/var/log/hushd

# For user-level
chmod 755 ~/.config/hushd ~/.local/share/hushd ~/Library/Logs/hushd
```

### Plist validation

Validate plist syntax:

```bash
plutil -lint deploy/launchd/dev.hushclaw.hushd.plist
```

### Reload after plist changes

```bash
# System-level
sudo launchctl unload /Library/LaunchDaemons/dev.hushclaw.hushd.plist
sudo launchctl load /Library/LaunchDaemons/dev.hushclaw.hushd.plist

# User-level
launchctl unload ~/Library/LaunchAgents/dev.hushclaw.hushd.plist
launchctl load ~/Library/LaunchAgents/dev.hushclaw.hushd.plist
```
