# Clawdstrike Agent

A lightweight system tray application that provides security policy enforcement for AI coding tools like Claude Code, Cursor, and Cline.

## Features

- **Daemon Management**: Automatically spawns and manages the hushd daemon
- **Broker Sidecar**: Optionally bundles and supervises `clawdstrike-brokerd` for local secret-broker execution
- **System Tray**: Shows status (running/stopped) and recent events
- **Desktop Notifications**: Alerts when actions are blocked
- **Claude Code Integration**: Auto-installs hooks for policy checking
- **MCP Server**: Exposes policy_check tool for Cursor/Cline
- **OpenClaw Session Manager**: Agent-owned gateway transport with reconnect logic
- **Local Authenticated API**: Loopback API used by desktop OpenClaw client
- **Policy Management**: Quick access to policy reload and settings

## Prerequisites

- macOS 10.15+ (Linux support planned)
- For Claude Code: Claude Code CLI installed

The packaged app bundles `hushd` and can also bundle `clawdstrike-brokerd`.
Separate installs are only needed for advanced external-daemon or remote-broker setups.

## Installation

### Build from source

```bash
cd apps/agent
cargo tauri build
```

The build step compiles and bundles `hushd` and `clawdstrike-brokerd` into the app automatically.
The built app will be in `src-tauri/target/release/bundle/`.

### Development

```bash
cargo tauri dev
```

## Usage

1. Launch the Clawdstrike Agent app
2. The agent will automatically start the hushd daemon on port 9876
3. If `brokerd.enabled` is set in agent settings, the agent will also start `clawdstrike-brokerd` on port 9889 after hushd is healthy
4. A tray icon will appear showing the current status

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

`POST /api/v1/openclaw/request` is policy-gated (fail-closed) before gateway relay when enforcement is enabled.

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
  "dashboard_url": "http://127.0.0.1:9878/ui",
  "ota_enabled": true,
  "ota_mode": "auto",
  "ota_channel": "stable",
  "ota_manifest_url": null,
  "ota_allow_fallback_to_default": false,
  "ota_check_interval_minutes": 360,
  "ota_pinned_public_keys": [],
  "ota_last_check_at": null,
  "ota_last_result": null,
  "ota_current_hushd_version": null,
  "brokerd": {
    "enabled": false,
    "port": 9889,
    "binary_path": null,
    "allow_http_loopback": false,
    "allow_private_upstream_hosts": false,
    "allow_invalid_upstream_tls": false,
    "secret_backend": {
      "kind": "file",
      "file_path": "~/.config/clawdstrike/broker-secrets.json",
      "env_prefix": "CLAWDSTRIKE_SECRET_",
      "http_base_url": null,
      "http_bearer_token": null,
      "http_path_prefix": "/v1/secrets"
    }
  },
  "openclaw": {
    "gateways": [],
    "active_gateway_id": null
  }
}
```

### Default Policy

The agent bundles a default policy at `resources/default-policy.yaml` that will be copied to `~/.config/clawdstrike/policy.yaml` on first run.

### Local broker mode

When `brokerd.enabled` is `true`, the agent:

- copies the bundled `clawdstrike-brokerd` binary into `~/.config/clawdstrike/bin/`
- keeps a persistent local hushd signing key under `~/.config/clawdstrike/runtime/`
- fetches hushd's broker signing public key and injects it into brokerd on startup
- starts brokerd with the configured `file`, `env`, or managed `http` secret backend

### Signed hushd OTA updates

The agent can verify and apply signed `hushd` updates from release manifests:

- Status: `GET /api/v1/agent/ota/status`
- Check now: `POST /api/v1/agent/ota/check`
- Apply now: `POST /api/v1/agent/ota/apply`

Release automation:

- `scripts/generate-hushd-ota-manifest.sh` creates per-channel manifests from `hushd-*` release artifacts.
- `scripts/sign-hushd-ota-manifest.sh` signs manifests with Ed25519.
- `.github/workflows/release.yml` publishes `hushd-ota-manifest-stable.json` and `hushd-ota-manifest-beta.json`.

Release workflow secret:

- `HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM` (required)
- `HUSHD_OTA_SIGNING_PUBLIC_KEY_HEX` (optional override; otherwise derived from the private key)

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
- Verification and smoke checks: `#verification` section in this README

## Troubleshooting

### Daemon won't start
- Check agent logs for bundled `hushd` copy/start errors
- For external daemon mode, set `hushd_binary_path` in settings
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
