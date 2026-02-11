# Agent OpenClaw Operations Runbook

This runbook documents day-2 operations for the **agent-owned OpenClaw architecture**:

- Agent owns OpenClaw WebSocket sessions and reconnect/backoff behavior.
- Desktop talks to the local agent API (loopback + bearer token), not directly to gateway WS in production mode.
- OpenClaw secrets are stored by the agent in secure storage (keyring where available, memory-only fallback when unavailable).

## Components

- Agent runtime: `apps/agent/src-tauri/`
- Agent local API:
  - `GET /api/v1/agent/health`
  - `GET|PUT /api/v1/agent/settings`
  - `POST /api/v1/agent/policy-check`
  - `GET|POST|PATCH|DELETE /api/v1/openclaw/gateways`
  - `POST /api/v1/openclaw/gateways/:id/connect`
  - `POST /api/v1/openclaw/gateways/:id/disconnect`
  - `POST /api/v1/openclaw/discover`
  - `POST /api/v1/openclaw/probe`
  - `POST /api/v1/openclaw/request`
  - `GET /api/v1/openclaw/events` (SSE)
  - `POST /api/v1/openclaw/import-desktop-gateways`
- Desktop client bridge:
  - `apps/desktop/src/services/agentOpenClawClient.ts`
  - `apps/desktop/src/context/OpenClawAgentProvider.tsx`
- Local auth token file: `~/.config/clawdstrike/agent-local-token`

## Prerequisites

1. Start Clawdstrike Agent.
2. Ensure `hushd` is available and healthy.
3. Ensure `openclaw` CLI is installed if using discovery/probe or local gateway smoke scenarios.
4. Install `jq` and `curl` for runbook commands and smoke automation.

## Quick Health Checks

```bash
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike"
AGENT_PORT="$(jq -r '.agent_api_port // 9878' "${CONFIG_DIR}/agent.json" 2>/dev/null || echo 9878)"
AGENT_TOKEN="$(tr -d '[:space:]' < "${CONFIG_DIR}/agent-local-token")"
API_BASE="http://127.0.0.1:${AGENT_PORT}"

curl -fsS "${API_BASE}/api/v1/agent/health" | jq .
curl -fsS -H "Authorization: Bearer ${AGENT_TOKEN}" "${API_BASE}/api/v1/openclaw/gateways" | jq .
```

Expected:

- `daemon.state` is `running` or `starting`.
- Gateway runtime statuses eventually settle to `connected` or `disconnected`, not stuck in `connecting` indefinitely.

## Enforcement Toggle Verification

When enforcement is disabled, policy checks should return deterministic bypass metadata.

```bash
curl -fsS -X PUT \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}' \
  "${API_BASE}/api/v1/agent/settings" >/dev/null

curl -fsS -X POST \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"action_type":"exec","target":"echo smoke"}' \
  "${API_BASE}/api/v1/agent/policy-check" | jq .
```

Expected response:

- `allowed: true`
- `guard: "enforcement_disabled"`

Restore enforcement:

```bash
curl -fsS -X PUT \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}' \
  "${API_BASE}/api/v1/agent/settings" >/dev/null
```

## Production Smoke Harness

Use the repository smoke script for consistent validation:

```bash
scripts/openclaw-agent-smoke.sh --gateway-url ws://127.0.0.1:18789 --gateway-token dev-token
```

To include gateway restart/reconnect validation managed by the script:

```bash
scripts/openclaw-agent-smoke.sh \
  --start-local-gateway \
  --gateway-url ws://127.0.0.1:18789 \
  --gateway-token dev-token
```

The script validates:

1. Agent health endpoint reachability.
2. Enforcement-disabled policy bypass semantics.
3. Gateway config import/connect via agent API.
4. Request relay (`node.list`) through agent-owned session.
5. Optional reconnect-after-restart check when local gateway is started by the script.

## Common Failures and Remediation

### `401 unauthorized` on local API

- Confirm token file exists: `~/.config/clawdstrike/agent-local-token`
- Ensure token has no trailing whitespace in client code.
- Confirm API bound port from `~/.config/clawdstrike/agent.json`.

### Gateway never reaches `connected`

- Verify gateway URL and token using OpenClaw CLI:
  ```bash
  openclaw gateway probe --json
  ```
- Inspect agent logs for connect/reconnect errors.
- Confirm origin/auth/connect payload compatibility if using non-default gateway builds.

### Desktop shows no OpenClaw updates

- Confirm desktop is in agent-backed mode (production default).
- In dev, disable direct fallback unless intentionally testing:
  - unset `VITE_OPENCLAW_DIRECT_MODE`
  - unset `SDR_OPENCLAW_DIRECT_MODE`
- Confirm SSE stream health by checking repeated `openclaw/events` reconnects in logs.

### Secure storage unavailable

- Agent falls back to memory-only secrets and logs a warning.
- In that mode, restart loses stored gateway secrets by design.
- Remediate by enabling OS keyring backend support for the runtime environment.

## Incident Triage Data to Capture

1. Agent version and OS version.
2. `GET /api/v1/agent/health` output.
3. Gateway list snapshot from `GET /api/v1/openclaw/gateways`.
4. Relevant logs covering:
  - daemon lifecycle transitions
  - OpenClaw connect/disconnect/reconnect events
  - local API auth failures
5. Whether keyring or memory fallback secret mode is active.
