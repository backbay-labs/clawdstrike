# Desktop Application OpenClaw Integration Analysis

> Exploratory analysis of the desktop app's OpenClaw fleet management UI, gateway client,
> and state management layer. Covers UI correctness, error handling, real-time event gaps,
> and hardcoded configuration.

**Status**: Research
**Date**: 2026-02-25
**Audience**: Desktop team, OpenClaw gateway team, QA

---

## Table of Contents

1. [Scope](#1-scope)
2. [UI Issues](#2-ui-issues)
3. [Gateway Client Issues](#3-gateway-client-issues)
4. [State Management Issues](#4-state-management-issues)
5. [Hardcoded Configuration](#5-hardcoded-configuration)
6. [Test Coverage Gaps](#6-test-coverage-gaps)
7. [Recommendations](#7-recommendations)

---

## 1. Scope

This analysis covers the desktop app's OpenClaw integration surface:

| Path | Role |
| --- | --- |
| `apps/desktop/src/features/openclaw/OpenClawFleetView.tsx` | Fleet view UI (gateways, nodes, presence, approvals, device pairing) |
| `apps/desktop/src/features/openclaw/openclawFleetUtils.ts` | Utility functions (command parsing, URL normalization, status helpers) |
| `apps/desktop/src/features/openclaw/openclawFleetUtils.test.ts` | Unit tests for utilities |
| `apps/desktop/src/services/openclaw/gatewayClient.ts` | WebSocket gateway client (`OpenClawGatewayClient`) |
| `apps/desktop/src/services/openclaw/gatewayProtocol.ts` | Frame types and parsing |
| `apps/desktop/src/context/OpenClawDirectFallback.tsx` | React context provider, event routing, multi-gateway state |

All line references are as of the current `feat/clawdstrike-sdks-launch` branch.

---

## 2. UI Issues

### D1: Approval Countdown Does Not Auto-Update [MEDIUM]

**Location**: `OpenClawFleetView.tsx:99-100`

```tsx
const expiresIn = approval.expiresAtMs - Date.now();
const expiresLabel = expiresIn > 0
  ? `expires in ${Math.max(0, Math.floor(expiresIn / 1000))}s`
  : "expired";
```

`expiresIn` is computed once during the render that creates `ExecApprovalCard`. No timer or effect triggers a re-render, so the "expires in Xs" label becomes stale immediately and never counts down.

**Fix**: Use a `useEffect` with `setInterval` to tick down the countdown, or adopt a relative-time component that self-updates. A 1-second interval is sufficient for the displayed granularity.

---

### D2: Expired Approvals Remain Actionable [MEDIUM]

**Location**: `OpenClawFleetView.tsx:120-128`

```tsx
<GlowButton onClick={() => onResolve("allow-once")} disabled={busy} variant="default">
  Allow once
</GlowButton>
<GlowButton onClick={() => onResolve("allow-always")} disabled={busy} variant="secondary">
  Always allow
</GlowButton>
<GlowButton onClick={() => onResolve("deny")} disabled={busy} variant="secondary">
  Deny
</GlowButton>
```

The buttons are only gated on the `busy` flag. When `expiresIn <= 0`, the label says "expired" but the user can still click Approve or Deny. Submitting a resolution for an expired approval will either silently fail or produce a confusing gateway error.

**Fix**: Disable all three buttons when `expiresIn <= 0`. Consider also visually dimming the entire card.

---

### D3: Silent Failure on Approval Resolution Errors [MEDIUM]

**Location**: `OpenClawFleetView.tsx:295-302`

```tsx
async function handleResolveApproval(approvalId: string, decision: ExecApprovalDecision) {
  setResolveBusyId(approvalId);
  try {
    await oc.resolveExecApproval(approvalId, decision);
  } finally {
    setResolveBusyId(null);
  }
}
```

There is no `catch` block. If `resolveExecApproval` rejects (network error, expired approval, auth failure, gateway error), the error is silently swallowed and the approval card returns to its idle state with no user feedback.

**Fix**: Add a `catch` block that surfaces the error via a toast notification or inline error message on the card. Consider removing the resolved approval from the queue only on confirmed success rather than optimistically.

---

### D4: Silent Failure on Device Pairing Actions [LOW]

**Location**: `OpenClawFleetView.tsx:687-690`

```tsx
<GlowButton onClick={() => oc.approveDevicePairing(d.requestId)} variant="default">
  Approve
</GlowButton>
<GlowButton onClick={() => oc.rejectDevicePairing(d.requestId)} variant="secondary">
  Reject
</GlowButton>
```

Both `approveDevicePairing` and `rejectDevicePairing` are called fire-and-forget with no loading state, no error display, and no success confirmation. The user has no indication whether the action succeeded.

**Fix**: Add a busy state per pending request (similar to `resolveBusyId` for approvals). Catch and display errors. Optionally show a brief success indicator.

---

### D5: Presence Rendered as Raw JSON [LOW]

**Location**: `OpenClawFleetView.tsx:501-508`

```tsx
{(runtime?.presence ?? []).slice(0, 12).map((p, idx) => (
  <pre key={idx} className="...">
    {JSON.stringify(p, null, 2)}
  </pre>
))}
```

Presence entries are dumped as pretty-printed JSON. This is useful during development but not suitable for a production fleet view. Users see raw objects with internal field names rather than structured client identity information.

**Fix**: Parse and render meaningful presence fields (client display name, version, mode, platform, connected duration). Fall back to JSON dump for unexpected shapes.

---

### D6: Presence and Nodes Capped at 12 Without Indication [LOW]

**Location**: `OpenClawFleetView.tsx:501, 524`

```tsx
(runtime?.presence ?? []).slice(0, 12).map(...)
(runtime?.nodes ?? []).slice(0, 12).map(...)
```

Both lists are silently truncated to 12 items. If a gateway has 30 connected nodes, only the first 12 are shown with no indication that more exist.

**Fix**: Add a "and N more" indicator below the truncated list, or add pagination / "Show all" toggle.

---

### D7: Approval Queue Capped at 20 But Badge Shows Full Count [LOW]

**Location**: `OpenClawFleetView.tsx:564-569`

```tsx
<Badge variant={...}>
  {runtime?.execApprovalQueue?.length ?? 0} pending
</Badge>
...
{(runtime?.execApprovalQueue ?? []).slice(0, 20).map((a) => (
```

The badge accurately displays the full queue length (e.g. "47 pending") but only 20 cards are rendered. There is no way for the user to access the remaining approvals.

**Fix**: Add pagination, virtual scrolling, or a "Load more" button. Alternatively, display a note like "showing 20 of 47".

---

## 3. Gateway Client Issues

### D8: Reconnect Killed on Initial Connect Failure [MEDIUM]

**Location**: `OpenClawDirectFallback.tsx:400-405`

```tsx
try {
  await client.connect();
} catch (err) {
  disconnectGatewayInternal(id, clientsRef, setRuntimeByGatewayId);
  throw err;
}
```

When the initial `connect()` call fails, `disconnectGatewayInternal` is called, which invokes `client.disconnect()`. This sets `manualDisconnect = true` on the client, permanently disabling auto-reconnect even though the client was configured with `autoReconnect: true`.

The gateway client's own `scheduleReconnect` logic checks `if (this.manualDisconnect) return;` and bails out. By calling `disconnect()` on the initial failure, the provider destroys the client's ability to self-heal.

**Fix**: On initial connect failure, either (a) let the client's internal reconnect logic handle recovery without calling `disconnect()`, or (b) provide an explicit "Retry" button in the UI that creates a fresh client.

---

### D9: Clean Close (Code 1000) Does Not Trigger Reconnect [LOW]

**Location**: `gatewayClient.ts:432-433`

```tsx
if (this.manualDisconnect) return;
if (ev.code === 1000) return;
this.scheduleReconnect("socket closed");
```

A clean WebSocket close (code 1000) is treated as intentional and reconnect is not attempted. However, planned gateway restarts send code 1000. After a rolling restart, the desktop client remains permanently disconnected until the user manually clicks Connect.

**Fix**: This may be intentional behavior, but consider making it configurable. A `reconnectOnCleanClose` option would let the provider opt in to reconnecting after code 1000.

---

### D10: Default Jitter Ratio is 0 [LOW]

**Location**: `gatewayClient.ts:208`

```tsx
const jitterRatio = Math.max(0, Math.min(1, config?.jitterRatio ?? 0));
```

The default jitter ratio is `0`, meaning no jitter is applied to reconnect backoff unless explicitly configured. The `OpenClawDirectFallback.tsx` provider correctly sets `jitterRatio: 0.15` at line 374, but any other consumer of `OpenClawGatewayClient` that omits the option gets deterministic backoff. This creates thundering-herd risk if multiple desktop clients reconnect simultaneously.

**Fix**: Change the default from `0` to a small positive value (e.g. `0.15`) so jitter is always present unless explicitly disabled.

---

### D11: RPC `retryable` and `retryAfterMs` Fields Not Acted Upon [LOW]

**Location**: `gatewayClient.ts:46-49`

```tsx
export class GatewayRpcError extends Error {
  readonly code?: string;
  readonly details?: unknown;
  readonly retryable?: boolean;
  readonly retryAfterMs?: number;
  ...
}
```

`GatewayRpcError` carries `retryable` and `retryAfterMs` hints from the gateway, and these fields are correctly parsed from the wire protocol. However, no consumer of the client inspects these fields or implements automatic retry.

**Fix**: Consider adding an optional auto-retry layer in `request()` that honors `retryable` and `retryAfterMs` for idempotent methods. Alternatively, document that consumers are expected to handle retries themselves.

---

## 4. State Management Issues

### D12: No `exec.approval.resolved` Event Handling [HIGH]

**Location**: `OpenClawDirectFallback.tsx:184-207`

```tsx
export function applyGatewayEventFrame(
  current: OpenClawGatewayRuntime,
  frame: GatewayEventFrame
): OpenClawGatewayRuntime {
  if (frame.event === "presence") {
    const payload = frame.payload;
    const list = Array.isArray(payload) ? payload : [];
    return { ...current, presence: list };
  }

  if (frame.event === "exec.approval.requested") {
    ...
    return { ...current, execApprovalQueue: [...] };
  }

  return current;
}
```

The event handler only processes `presence` and `exec.approval.requested`. There is no handler for `exec.approval.resolved` or `exec.approval.rejected`. When another operator resolves an approval (or the approval expires server-side), the local queue retains the stale entry. The only way it gets removed is if the same desktop instance resolved it via `resolveExecApproval`, which optimistically removes the item from state.

In a multi-operator scenario, approvals resolved by another operator remain visible indefinitely.

**Fix**: Handle `exec.approval.resolved` and `exec.approval.rejected` events by removing the corresponding item from `execApprovalQueue`. Also handle `exec.approval.expired` if the gateway emits it.

---

### D13: No Real-Time Node Event Handling [MEDIUM]

**Location**: `OpenClawDirectFallback.tsx:184-207`

The `applyGatewayEventFrame` function has no handlers for node lifecycle events (`node.connected`, `node.disconnected`, `node.updated`). The node list is only refreshed on:

1. Initial connection (line 393-394, triggered by status transition to `connected`)
2. Manual click of the "Refresh" button (line 341)

If a node connects or disconnects between refreshes, the fleet view shows stale data.

**Fix**: Handle `node.connected` (add/update node in list), `node.disconnected` (update connected status), and `node.updated` (merge updated fields) events in `applyGatewayEventFrame`.

---

## 5. Hardcoded Configuration

### D14: Gateway URL Hardcoded in 3 Places [LOW]

The default gateway URL `ws://127.0.0.1:18789` appears in three locations:

| File | Line | Context |
| --- | --- | --- |
| `OpenClawDirectFallback.tsx` | 117 | `defaultGateway()` function |
| `OpenClawDirectFallback.tsx` | 134 | `loadGateways()` fallback in parse loop |
| `OpenClawFleetView.tsx` | 328 | "Add" button `onClick` handler |

**Fix**: Extract to a shared constant (e.g. `DEFAULT_GATEWAY_URL`) in `openclawFleetUtils.ts` or a config module. Reference the constant from all three locations.

---

### D15: `tauri://localhost` and Port 1420 Hardcoded in Origin Fix Hint [LOW]

**Location**: `openclawFleetUtils.ts:57-62`

```tsx
return [
  "OpenClaw rejected this app origin.",
  "Fix: allow SDR Desktop origins then restart the gateway:",
  `openclaw config set --json gateway.controlUi.allowedOrigins '["http://localhost:1420","tauri://localhost"]'`,
  "openclaw gateway restart",
].join("\n");
```

The remediation message assumes the app runs on port 1420 and uses the `tauri://localhost` scheme. If the dev server port changes or the app runs in a browser context, the hint is wrong.

**Fix**: Use `window.location.origin` to construct the actual origin dynamically. Keep `tauri://localhost` as a secondary suggestion since it applies only in production Tauri builds.

---

## 6. Test Coverage Gaps

### 6.1 Utility Functions (`openclawFleetUtils.test.ts`)

The existing test file covers `parseCommand`, `normalizeGatewayUrl`, `originFixHint`, and `selectSystemRunNodes`. Missing:

- **`timeAgo`**: No tests at all. Edge case: `timeAgo(0)` returns `"n/a"` because `!0` is `true`, which may be surprising since `0` is a valid timestamp (Unix epoch).
- **`statusDotClass`**: No tests. Trivial function but worth covering for regression.

### 6.2 Gateway Client (`gatewayClient.test.ts`)

Existing tests cover connect/disconnect, RPC request/response, timeout, reconnect, and manual disconnect cancellation. Missing:

- No test for reconnect behavior when a `GatewayRpcError` with `retryable: true` is returned.
- No test for `connect()` when the socket opens but the connect response never arrives (tests connect timeout for socket-never-opens but not for auth-response-never-arrives; though the general connect timeout covers both paths implicitly).
- No test for the `connectDelayMs` option taking effect.

### 6.3 State Management (`OpenClawDirectFallback.tsx`)

- **`applyGatewayEventFrame`**: No dedicated test file. The function is exported and pure, making it straightforward to unit test. Missing cases:
  - Unrecognized event names (should return `current` unchanged)
  - Malformed `exec.approval.requested` payloads (missing `id`, missing `command`, non-number `expiresAtMs`)
  - Queue deduplication (same approval ID received twice)
  - Queue cap at 100 items
- No integration test exercising the desktop client against fixture event shapes end-to-end.

---

## 7. Recommendations

### Before Launch

| ID | Issue | Priority |
| --- | --- | --- |
| D12 | Handle `exec.approval.resolved` / `exec.approval.rejected` events | HIGH |
| D3 | Add error handling to approval resolution | MEDIUM |

Without D12, multi-operator deployments accumulate stale approval entries. Without D3, users have no feedback when approval resolution fails.

### Fast-Follow

| ID | Issue | Priority |
| --- | --- | --- |
| D1 | Auto-update approval countdown | MEDIUM |
| D2 | Disable buttons on expired approvals | MEDIUM |
| D8 | Do not destroy reconnect on initial failure | MEDIUM |
| D13 | Handle node lifecycle events in real time | MEDIUM |

These affect perceived reliability of the fleet view. D8 is particularly important for environments where the gateway may not be running when the desktop app first launches.

### Post-Launch

| ID | Issue | Priority |
| --- | --- | --- |
| D4 | Add loading/error state to device pairing buttons | LOW |
| D5 | Render presence as structured data instead of JSON | LOW |
| D6 | Indicate truncated presence/node lists | LOW |
| D7 | Add pagination for approval queue | LOW |
| D9 | Configurable reconnect on clean close | LOW |
| D10 | Default jitter ratio to 0.15 | LOW |
| D11 | Auto-retry for retryable RPC errors | LOW |
| D14 | Extract hardcoded gateway URL to constant | LOW |
| D15 | Dynamically construct origin in fix hint | LOW |
