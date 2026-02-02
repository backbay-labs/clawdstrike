# Hushd launchd Service

This directory contains launchd configuration for running hushd on macOS.

## Files

| File | Description |
|------|-------------|
| `dev.clawdstrike.hushd.plist` | Launch daemon/agent configuration |

## Installation Options

### Option A: System-level daemon (runs as root, starts at boot)

For production servers where hushd should start automatically:

```bash
# Create directories
sudo mkdir -p /usr/local/etc/hushd /usr/local/var/lib/hushd /usr/local/var/log/hushd

# Install configuration
sudo cp deploy/config.yaml /usr/local/etc/hushd/config.yaml

# Install plist
sudo cp deploy/launchd/dev.clawdstrike.hushd.plist /Library/LaunchDaemons/

# Load and start
sudo launchctl load /Library/LaunchDaemons/dev.clawdstrike.hushd.plist
```

### Option B: User-level agent (runs as current user)

For development or per-user installations:

```bash
# Create directories
mkdir -p ~/Library/Logs/hushd ~/.config/hushd ~/.local/share/hushd

# Modify plist paths for user directories
# (edit the plist or use the Homebrew formula which handles this)

# Install plist
cp deploy/launchd/dev.clawdstrike.hushd.plist ~/Library/LaunchAgents/

# Load and start
launchctl load ~/Library/LaunchAgents/dev.clawdstrike.hushd.plist
```

### Option C: Homebrew (recommended for development)

If installed via Homebrew:

```bash
brew install clawdstrike/tap/hush

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
| `launchctl start dev.clawdstrike.hushd` | Start loaded service |
| `launchctl stop dev.clawdstrike.hushd` | Stop loaded service |
| `tail -f /usr/local/var/log/hushd/hushd.log` | Follow logs |

### System-level commands (with sudo)

```bash
# Load
sudo launchctl load /Library/LaunchDaemons/dev.clawdstrike.hushd.plist

# Unload
sudo launchctl unload /Library/LaunchDaemons/dev.clawdstrike.hushd.plist

# Check status
sudo launchctl list | grep hushd
```

### User-level commands

```bash
# Load
launchctl load ~/Library/LaunchAgents/dev.clawdstrike.hushd.plist

# Unload
launchctl unload ~/Library/LaunchAgents/dev.clawdstrike.hushd.plist

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
launchctl stop dev.clawdstrike.hushd
launchctl start dev.clawdstrike.hushd
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
plutil -lint deploy/launchd/dev.clawdstrike.hushd.plist
```

### Reload after plist changes

```bash
# System-level
sudo launchctl unload /Library/LaunchDaemons/dev.clawdstrike.hushd.plist
sudo launchctl load /Library/LaunchDaemons/dev.clawdstrike.hushd.plist

# User-level
launchctl unload ~/Library/LaunchAgents/dev.clawdstrike.hushd.plist
launchctl load ~/Library/LaunchAgents/dev.clawdstrike.hushd.plist
```

## Security Hardening

### Sandboxing (Optional)

Unlike systemd which has built-in sandboxing options, launchd relies on macOS
sandboxing via `sandbox-exec`. For enhanced security in production, you can
run hushd under a sandbox profile.

Create `/usr/local/etc/hushd/sandbox.sb`:

```lisp
(version 1)
(deny default)
(allow process-exec (literal "/usr/local/bin/hushd"))
(allow file-read* (subpath "/usr/local/etc/hushd"))
(allow file-read-data (subpath "/usr/local/lib"))
(allow file-write* (subpath "/usr/local/var/lib/hushd"))
(allow file-write* (subpath "/usr/local/var/log/hushd"))
(allow network-bind (local tcp "*:9876"))
(allow network-outbound)
(allow sysctl-read)
(allow mach-lookup)
```

Then modify the plist ProgramArguments:

```xml
<key>ProgramArguments</key>
<array>
    <string>/usr/bin/sandbox-exec</string>
    <string>-f</string>
    <string>/usr/local/etc/hushd/sandbox.sb</string>
    <string>/usr/local/bin/hushd</string>
    <string>--config</string>
    <string>/usr/local/etc/hushd/config.yaml</string>
</array>
```

**Note:** Sandbox profiles require testing on your specific macOS version.
The systemd service file includes more comprehensive hardening by default.
