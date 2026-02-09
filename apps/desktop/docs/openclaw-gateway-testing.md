# OpenClaw Gateway ↔ SDR Desktop testing

This doc captures end-to-end scenarios for the SDR Desktop “agent” (operator UI) and its bridge to the OpenClaw Gateway:

- WebSocket control plane client: `apps/desktop/src/services/openclaw/gatewayClient.ts`
- UI state + multi-gateway wiring: `apps/desktop/src/context/OpenClawContext.tsx`
- Operator UI: `apps/desktop/src/features/openclaw/OpenClawFleetView.tsx`
- Native (Tauri) discovery/probe helpers: `apps/desktop/src-tauri/src/commands/openclaw.rs` + `apps/desktop/src/services/tauri.ts`

## Architecture snapshot

- The UI talks to the gateway **directly over WebSocket** (no proxy).
- `OpenClawGatewayClient` implements:
  - `connect` handshake (including optional `connect.challenge`)
  - request/response RPC (`type: "req"` / `type: "res"`)
  - event fan-out (`type: "event"`)
- `OpenClawContext` owns:
  - local gateway config storage (multi-gateway)
  - per-gateway runtime state (status/error/presence/nodes/devices/approvals)
  - high-level actions used by views (`connect`, `request`, `resolveExecApproval`, pairing)
- Discovery/probe uses the local `openclaw` CLI via Tauri IPC so the webview can remain a native WS client.

## Manual scenarios (back-and-forth)

### Quick start (local loopback)

This is the shortest path to “desktop ↔ gateway ↔ node” back-and-forth testing.

#### 1) Start the gateway

```bash
# Token auth is recommended (set OPENCLAW_GATEWAY_TOKEN instead if you prefer)
openclaw gateway run --force --token "dev-token"
```

Notes:
- SDR Desktop defaults to `ws://127.0.0.1:18789`. If your gateway uses a different port, update the URL in **OpenClaw Fleet**.
- If you run OpenClaw with the global `--dev` profile, the default gateway port is `19001` (set the URL accordingly).

#### 2) Allow the SDR Desktop origin (if needed)

If the gateway rejects the webview origin, allow both the Vite dev server and the Tauri origin:

```bash
openclaw config set --json gateway.controlUi.allowedOrigins \
  '["http://localhost:1420","tauri://localhost"]'
openclaw gateway restart
```

#### 3) Start SDR Desktop (Tauri)

```bash
npm --prefix apps/desktop run tauri:dev
```

Then open **OpenClaw Fleet**:
- set the gateway URL + token
- click **Connect**

#### 4) Start a node host (optional but recommended)

Install and start the local node host so `node.list` populates and `system.run` is available:

```bash
openclaw node install
openclaw node restart
```

If the node needs pairing, approve it in **OpenClaw Fleet → Device Pairing**. After approval:
- the node should appear in **Nodes**
- `system.run` should be available under **Node Invoke**

Alternative (ephemeral node host):

```bash
openclaw node run --host 127.0.0.1 --port 18789 --display-name "SDR Node"
```

### Scenarios

#### Scenario 1: Handshake + auth + presence

Goal: verify the WS connect handshake and a simple RPC works end-to-end.

1. Start an OpenClaw Gateway locally.
2. In SDR Desktop, open **OpenClaw Fleet** and set the Gateway URL (e.g. `ws://127.0.0.1:18789`) and token (if required).
3. Click **Connect**.
4. Expected:
   - status goes `connecting → connected`
   - `presence` list populates after refresh (or immediately if the gateway emits events)

Failure modes to validate:
- invalid token → connect fails and the UI surfaces the error
- gateway closes due to origin policy → UI shows a remediation hint
- connect schema mismatch → UI surfaces `invalid connect params` (SDR Desktop uses `client.id=cli`, `client.mode=cli`)

#### Scenario 2: Reconnect after gateway restart

Goal: make sure the UI reliably recovers when the gateway restarts mid-session.

1. Connect successfully in **OpenClaw Fleet**.
2. Restart the gateway while the UI is connected.
3. Expected:
   - connection status transitions to `connecting` and returns to `connected` after the gateway is back
   - the UI recovers to `connected` without requiring a full app restart
   - node/pairing snapshots refresh after reconnect (not just presence)

#### Scenario 3: Exec approvals: ordering, dedupe, expiry

Goal: validate the approvals inbox behaves under load.

1. Trigger multiple `exec.approval.requested` events from the gateway (including duplicates).
2. Expected:
   - duplicate approval IDs are deduped
   - newest approvals appear first
   - expired approvals are clearly surfaced/removed (implementation-dependent)

#### Scenario 4: Command invocation (`system.run`)

Goal: validate request/response, timeouts, and error reporting.

1. With a paired/connected node that supports `system.run`, select it in **OpenClaw Fleet**.
2. Run a command:
   - simple: `echo test`
   - structured argv: `["bash","-lc","echo test"]`
3. Expected:
   - `node.invoke` request returns a structured result (or a gateway error)
   - long-running commands respect `timeoutMs` and surface a timeout when exceeded

#### Scenario 5: Device pairing flows

Goal: ensure pairing requests and approvals are round-trippable.

1. Trigger a new pairing request.
2. Approve/reject from the UI.
3. Expected:
   - pending list updates promptly
   - paired devices list refreshes and includes token metadata

#### Scenario 6: Tailnet probe + discovery (Tauri IPC)

Goal: validate the UI ↔ Tauri IPC ↔ `openclaw` CLI bridge.

1. Ensure the `openclaw` CLI is installed and on your PATH (`command -v openclaw`).
2. Run SDR Desktop via Tauri.
3. In **OpenClaw Fleet**, click **Probe Tailnet** and **Discover**.
4. Expected:
   - new gateways are added when `openclaw gateway probe/discover --json` returns beacons
   - errors show up as **Discovery error** with actionable messages (missing CLI, non-zero exit, invalid JSON)

## Automated coverage (Vitest)

These unit tests mirror key back-and-forth flows without requiring a live gateway:

- `apps/desktop/src/services/openclaw/gatewayProtocol.test.ts`:
  - frame parsing and request ID generation
- `apps/desktop/src/services/openclaw/gatewayClient.test.ts`:
  - connect + `connect.challenge`
  - connect idempotency + cancel on manual disconnect
  - RPC request/response success/error
  - pending request rejection on disconnect
  - request timeouts
- `apps/desktop/src/services/tauri.openclaw.test.ts`:
  - discover/probe IPC wiring (Tauri-only)
- `apps/desktop/src/context/OpenClawContext.test.ts`:
  - pure event application logic (presence + approvals)
- `apps/desktop/src/features/openclaw/openclawFleetUtils.test.ts`:
  - command parsing for `system.run` + gateway URL normalization

Run with:

```bash
npm --prefix apps/desktop test -- --run
npm --prefix apps/desktop run lint
npm --prefix apps/desktop run typecheck
```

Rust (Tauri backend) unit tests cover best-effort JSON extraction from `openclaw --json` output:

```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

# Optional: run offline if deps are already cached
CARGO_NET_OFFLINE=true cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
```

## Troubleshooting

### `origin not allowed` / `Origin is not allowed`

- Symptom: connect fails and the gateway logs mention origin policy.
- Fix:
  ```bash
  openclaw config set --json gateway.controlUi.allowedOrigins \
    '["http://localhost:1420","tauri://localhost"]'
  openclaw gateway restart
  ```

### `Failed to execute openclaw` (Probe/Discover)

- Symptom: **Probe Tailnet** / **Discover** fails with a spawn error.
- Fixes:
  - verify the CLI exists: `command -v openclaw`
  - run the full Tauri app (`npm --prefix apps/desktop run tauri:dev`); web-only Vite (`npm run dev`) disables discovery/probe

### Port/profile mismatch

- Symptom: gateway is running but `ws://127.0.0.1:18789` won’t connect.
- Fixes:
  - confirm the listening URL with: `openclaw gateway probe --json`
  - if you started the gateway with `openclaw --dev ...`, the default gateway port is `19001`

### `connect timeout` / `websocket closed (1006)`

- Symptom: SDR Desktop shows a connect timeout or an abnormal close.
- Fixes:
  - confirm the gateway is listening: `openclaw gateway probe --json`
  - verify the URL is `ws://...` / `wss://...` (the UI normalizes `http(s)://...` to `ws(s)://...` on save) and the port matches your profile
  - if running through a tailnet/reverse proxy, confirm WS upgrades are permitted

## Next steps

- Add a small “fake gateway” test harness to exercise real WS framing (connect, reconnect, event flood) without a live OpenClaw process.
- Expand `applyGatewayEventFrame` to handle pairing + node state events when the gateway emits them.
- Add an E2E smoke script that starts `openclaw gateway` + `openclaw node` and validates “Connect → node.list → system.run → approval resolve”.
