# Clawdstrike Agent

A lightweight system tray application that provides security policy enforcement for AI coding tools like Claude Code, Cursor, and Cline.

## Features

- **Daemon Management**: Automatically spawns and manages the hushd daemon
- **System Tray**: Shows status (running/stopped) and recent events
- **Desktop Notifications**: Alerts when actions are blocked
- **Claude Code Integration**: Auto-installs hooks for policy checking
- **MCP Server**: Exposes policy_check tool for Cursor/Cline
- **OpenClaw Session Manager**: Agent-owned gateway transport with reconnect logic
- **Local Authenticated API**: Loopback API used by desktop OpenClaw client
- **Policy Management**: Quick access to policy reload and settings

## Prerequisites

- macOS 10.15+ (Linux support planned)
- [hushd](../../crates/services/hushd) daemon binary installed
- For Claude Code: Claude Code CLI installed

## Installation

### Build from source

```bash
cd apps/agent
cargo tauri build
```

The built app will be in `src-tauri/target/release/bundle/`.

### Development

```bash
cargo tauri dev
```

## Usage

1. Launch the Clawdstrike Agent app
2. The agent will automatically start the hushd daemon on port 9876
3. A tray icon will appear showing the current status

### Tray Menu

- **Status**: Shows daemon state and blocks count
- **Enable/Disable**: Toggle policy enforcement
- **Recent Events**: Last 10 policy checks
- **Install Claude Code Hooks**: Auto-configure Claude Code
- **Reload Policy**: Reload policy without restart
- **Open SDR Desktop**: Launch the full debugging UI
- **Quit**: Stop the agent and daemon

### Claude Code Integration

Click "Install Claude Code Hooks" to automatically configure Claude Code with policy checking. This creates:

- `~/.claude/hooks/clawdstrike-check.sh` - Pre-tool hook script
- Updates `~/.claude/hooks.json` - Hook configuration

### MCP Server

The agent runs an MCP server on port 9877 that exposes the `policy_check` tool. To use with Cursor or other MCP-compatible tools, add to your MCP config:

```json
{
  "mcpServers": {
    "clawdstrike": {
      "url": "http://127.0.0.1:9877"
    }
  }
}
```

### Local Agent API (Desktop + Hooks)

The agent also runs a local authenticated API (default `127.0.0.1:9878`) for:

- hook policy checks (`/api/v1/agent/policy-check`)
- desktop OpenClaw operations (`/api/v1/openclaw/*`)
- health/settings control (`/api/v1/agent/*`)

Auth token file:

- `~/.config/clawdstrike/agent-local-token`

## Configuration

Settings are stored in `~/.config/clawdstrike/agent.json`:

```json
{
  "policy_path": "~/.config/clawdstrike/policy.yaml",
  "daemon_port": 9876,
  "mcp_port": 9877,
  "agent_api_port": 9878,
  "enabled": true,
  "auto_start": true,
  "notifications_enabled": true,
  "notification_severity": "block",
  "openclaw": {
    "gateways": [],
    "active_gateway_id": null
  }
}
```

### Default Policy

The agent bundles a default policy at `resources/default-policy.yaml` that will be copied to `~/.config/clawdstrike/policy.yaml` on first run.

## Architecture

```
┌─────────────────┐     ┌─────────────────────────────────┐
│   System Tray   │     │         Daemon (hushd)          │
│   ┌─────────┐   │     │  ┌─────────────────────────┐    │
│   │ 🛡️ SDR  │◄──┼─────┼──┤ Policy Engine           │    │
│   └─────────┘   │     │  ├─────────────────────────┤    │
│   Menu:         │     │  │ HTTP API (:9876)        │    │
│   • Status      │     │  ├─────────────────────────┤    │
│   • Events      │     │  │ Audit Ledger (SQLite)   │    │
│   • Settings    │     │  └─────────────────────────┘    │
└─────────────────┘     └─────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────┐     ┌─────────────────────────────────┐
│  Notifications  │     │      AI Tool Integrations       │
│  • Block alerts │     │  ┌───────────┐  ┌───────────┐   │
│  • Warnings     │     │  │Claude Code│  │  Cursor   │   │
└─────────────────┘     │  │  (hooks)  │  │  (MCP)    │   │
                        │  └───────────┘  └───────────┘   │
                        └─────────────────────────────────┘
```

## Verification

1. **Check daemon health**: `curl http://localhost:9876/health`
2. **Test policy check**:
   ```bash
   curl -X POST http://localhost:9876/api/v1/check \
     -H "Content-Type: application/json" \
     -d '{"action_type":"file_access","target":"/etc/passwd"}'
   ```
3. **Verify Claude Code hook**: Test with Claude Code, should see policy checks in events
4. **Run OpenClaw smoke harness**:
   ```bash
   scripts/openclaw-agent-smoke.sh --gateway-url ws://127.0.0.1:18789 --gateway-token dev-token
   ```

## Operations Runbook

- Full runbook: `docs/src/guides/agent-openclaw-operations.md`
- Desktop scenario reference: `apps/desktop/docs/openclaw-gateway-testing.md`

## Troubleshooting

### Daemon won't start
- Check if hushd binary is in PATH or set `hushd_binary_path` in settings
- Check if port 9876 is available: `lsof -i :9876`
- View logs: `Console.app` > search "clawdstrike"

### Claude Code hooks not working
- Ensure `~/.claude/` directory exists
- Check hook is executable: `ls -la ~/.claude/hooks/`
- Test hook manually: `echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | ~/.claude/hooks/clawdstrike-check.sh`

### No notifications
- Check macOS notification permissions for the app
- Verify `notifications_enabled: true` in settings

### Desktop cannot call local API
- Confirm `~/.config/clawdstrike/agent-local-token` exists and is non-empty
- Confirm API port in `~/.config/clawdstrike/agent.json` matches desktop expectation
- Confirm health endpoint:
  ```bash
  curl -fsS "http://127.0.0.1:9878/api/v1/agent/health" | jq .
  ```

## License

MIT
