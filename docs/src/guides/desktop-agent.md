# Desktop Agent Deployment Guide

The Clawdstrike Desktop Agent is a Tauri-based application that provides local runtime security enforcement for AI coding assistants. It runs as a native desktop process, connecting to `hushd` for policy evaluation and optionally to OpenClaw gateways for fleet-wide coordination.

## Prerequisites

- Rust 1.93+ (for building from source)
- `clawdstrike` CLI installed ([Installation](../getting-started/installation.md))
- `hushd` daemon available (optional but recommended)
- OS keyring support (optional; falls back to in-memory secret storage)

## Installation

### Build from source

```bash
cd apps/desktop

# Install Tauri dependencies (macOS)
cargo install tauri-cli

# Build the desktop app
cargo tauri build
```

The built application is written to `apps/desktop/src-tauri/target/release/`.

### Development mode

```bash
cargo tauri dev
```

This starts the desktop agent with hot-reload for the frontend and Rust backend.

## Configuration

The agent stores its configuration in the platform config directory:

| File | Purpose |
|---|---|
| `~/.config/clawdstrike/agent.json` | Agent settings (port, enforcement toggle) |
| `~/.config/clawdstrike/agent-local-token` | Bearer token for local API authentication |
| `.hush/policy.yaml` | Project-level policy (loaded per workspace) |

### Agent settings

```json
{
  "agent_api_port": 9878,
  "enabled": true,
  "hushd_url": "http://127.0.0.1:8080"
}
```

## Policy Management

### Choose a baseline ruleset

```bash
clawdstrike policy list
clawdstrike policy show ai-agent
```

Built-in rulesets: `permissive`, `default`, `strict`, `ai-agent`, `ai-agent-posture`, `cicd`.

### Create a project policy

Create `.hush/policy.yaml` in your project root:

```yaml
version: "1.2.0"
name: My Project Policy
extends: clawdstrike:ai-agent

guards:
  forbidden_path:
    exceptions:
      - "**/.env.example"
```

### Validate the policy

```bash
clawdstrike policy validate .hush/policy.yaml
clawdstrike policy validate --resolve .hush/policy.yaml
```

### Use posture states (v1.2.0)

For finer-grained control, extend the posture-aware ruleset:

```yaml
version: "1.2.0"
name: Posture-Aware Project
extends: clawdstrike:ai-agent-posture
```

This gives three states (restricted, standard, elevated) with automatic transitions on user approval, critical violations, budget exhaustion, and timeouts. See [Posture Policies](posture-policy.md) for details.

## Claude Code Integration

The desktop agent enforces policy at the **tool boundary** -- the layer that performs file, network, and tool operations on behalf of the model. See [Enforcement Tiers](../concepts/enforcement-tiers.md) for the full integration contract.

### Preflight checks

Use the agent's local API to check actions before execution:

```bash
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike"
AGENT_TOKEN="$(tr -d '[:space:]' < "${CONFIG_DIR}/agent-local-token")"
API_BASE="http://127.0.0.1:9878"

curl -fsS -X POST \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"action_type":"file_access","target":"~/.ssh/id_rsa"}' \
  "${API_BASE}/api/v1/agent/policy-check" | jq .
```

### OpenClaw plugin integration

If using OpenClaw as your agent runtime, install the Clawdstrike plugin:

```bash
openclaw plugins install --link /path/to/clawdstrike/packages/adapters/clawdstrike-openclaw
openclaw plugins enable clawdstrike-security
```

The plugin registers a `policy_check` tool that agents call before risky operations. See [OpenClaw Integration](openclaw-integration.md) for full setup.

## Approval Flow

The desktop agent supports per-action approval for non-critical operations that are denied by policy. The flow is:

1. A pre-flight guard denies a non-critical action.
2. If the adapter has `CLAWDSTRIKE_APPROVAL_URL` configured, it submits an approval request to the agent's ApprovalQueue API.

> **Required:** The adapter also needs `CLAWDSTRIKE_AGENT_TOKEN` set to the same bearer token used by the agent's local API (found in `${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent-local-token`). Without this token, approval requests will be rejected with 401 Unauthorized.

3. The agent surfaces the request via OS notification and tray badge.
4. The user resolves the request (allow-once, allow-session, allow-always, or deny).
5. If the user approves, the action proceeds. If denied, expired, or no approval system is configured, the action is blocked.

> **Note:** `allow-session` and `allow-always` are currently stored in adapter memory only. `allow-always` does not persist across adapter restarts.

List pending approvals via the local API:

```bash
curl -fsS \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  "${API_BASE}/api/v1/approval/pending" | jq '.[].id'
```

Check a specific approval status:

```bash
curl -fsS \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  "${API_BASE}/api/v1/approval/${APPROVAL_ID}/status" | jq '{id, status, resolution, tool, resource, guard, reason, severity}'
```

> **Note:** The OpenClaw gateway has a separate `exec_approval_queue` for gateway-specific approval flows. These are distinct systems -- the desktop agent's ApprovalQueue is for local per-action approval.

## Behavior When hushd Is Unreachable

When `hushd` is unreachable or returns an error, policy checks return **deny** (fail-closed):

- **Transport error** (connection refused, timeout): guard `hushd_unreachable`, severity `critical`.
- **Auth failure** (401/403): guard `hushd_auth_error`, severity `critical`. Check API key configuration.
- **Rate limited** (429): guard `hushd_rate_limited`, severity `high`. The daemon is overloaded.
- **Request error** (400): guard `hushd_request_error`, severity `high`. Check request format.
- **Other errors**: guard `hushd_error` with the HTTP status code.

All error classes return `allowed: false` with `provenance.mode: "offline_deny"`. No actions are allowed without a successful policy evaluation.

- A policy cache is maintained on disk (`~/.config/clawdstrike/policy-cache.yaml`) for quick warm-start when the agent restarts, but it is **not** used for inline evaluation fallback.
- The agent logs a warning when secure storage (OS keyring) is unavailable and falls back to memory-only secrets.

## OpenClaw Gateway Connection

### Connect to a gateway

```bash
# Register a gateway
curl -fsS -X POST \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"label":"dev","gateway_url":"ws://127.0.0.1:18789","token":"dev-token"}' \
  "${API_BASE}/api/v1/openclaw/gateways" | jq .

# Connect
GATEWAY_ID="<id from above>"
curl -fsS -X POST \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  "${API_BASE}/api/v1/openclaw/gateways/${GATEWAY_ID}/connect" | jq .
```

### Subscribe to events (SSE)

```bash
curl -N -H "Authorization: Bearer ${AGENT_TOKEN}" \
  "${API_BASE}/api/v1/openclaw/events"
```

### Import gateways from desktop

If gateways were previously configured in the desktop app:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  "${API_BASE}/api/v1/openclaw/import-desktop-gateways" | jq .
```

## Session Lifecycle

The agent manages sessions with the following lifecycle:

1. **Start**: Agent process launches, loads policy, starts local API server.
2. **Connect**: Optionally connects to OpenClaw gateways and `hushd`.
3. **Enforce**: Evaluates guard checks against the active policy for every tool action.
4. **Transition**: Posture state changes based on events (user approval, violations, budget exhaustion).
5. **Shutdown**: Graceful disconnect from gateways, flush pending receipts.

Session timeout is configurable in the policy:

```yaml
settings:
  session_timeout_secs: 7200  # 2 hours
```

## Troubleshooting

### Agent health check

```bash
curl -fsS "http://127.0.0.1:9878/api/v1/agent/health" | jq .
```

Expected: `daemon.state` is `running`.

### 401 Unauthorized on local API

- Verify token file exists: `~/.config/clawdstrike/agent-local-token`
- Ensure no trailing whitespace in the token.
- Confirm the port in `~/.config/clawdstrike/agent.json` matches your request.

### Gateway stuck in "connecting"

- Verify gateway URL and token with `openclaw gateway probe --json`.
- Check agent logs for connect/reconnect errors.
- Ensure no firewall rules blocking WebSocket connections.

### Desktop shows no OpenClaw updates

- Confirm desktop is in agent-backed mode (production default).
- In development, unset `VITE_OPENCLAW_DIRECT_MODE` and `SDR_OPENCLAW_DIRECT_MODE`.
- Check SSE stream health by monitoring `/api/v1/openclaw/events` reconnects in logs.

### Enforcement disabled unexpectedly

Verify and restore enforcement:

```bash
# Check current settings
curl -fsS -H "Authorization: Bearer ${AGENT_TOKEN}" \
  "${API_BASE}/api/v1/agent/settings" | jq .

# Re-enable enforcement
curl -fsS -X PUT \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}' \
  "${API_BASE}/api/v1/agent/settings"
```

### Secure storage unavailable

- The agent falls back to memory-only secrets and logs a warning.
- Restart will lose stored gateway secrets in this mode.
- Enable OS keyring backend support to resolve.

## Related

- [Agent OpenClaw Operations Runbook](agent-openclaw-operations.md) -- Day-2 operations and incident triage
- [OpenClaw Integration](openclaw-integration.md) -- Plugin setup and configuration
- [Claude Integration](../recipes/claude.md) -- CLI-based Claude Code workflow
- [Posture Policies](posture-policy.md) -- Writing posture-aware policies
- [Policy Inheritance](policy-inheritance.md) -- Using `extends` for policy composition
