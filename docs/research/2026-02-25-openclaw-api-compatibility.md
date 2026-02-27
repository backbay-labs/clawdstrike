# OpenClaw API Compatibility Analysis

> Compatibility analysis of the `@clawdstrike/openclaw` plugin against the OpenClaw
> framework plugin API as of v2026.2.24 (CalVer). Covers every API surface we touch,
> identifies high-risk integration points, and recommends concrete fixes.

**Status**: Research
**Date**: 2026-02-25
**Audience**: Adapter maintainers, plugin QA, security architecture

> Update (2026-02-26): Section 3.1/3.2 risks were revalidated and mitigated in code.  
> See [`../audits/2026-02-26-openclaw-launch-revalidation.md`](../audits/2026-02-26-openclaw-launch-revalidation.md) and [`../reports/2026-02-26-openclaw-runtime-compatibility-validation.md`](../reports/2026-02-26-openclaw-runtime-compatibility-validation.md).

---

## Table of Contents

1. [Overview](#1-overview)
2. [Verified Compatible API Surfaces](#2-verified-compatible-api-surfaces)
3. [Requires Verification](#3-requires-verification)
4. [Not Used (Opportunities)](#4-not-used-opportunities)
5. [Peer Dependency Version](#5-peer-dependency-version)
6. [Plugin Manifest](#6-plugin-manifest)
7. [OpenClaw Issues and Discussions to Track](#7-openclaw-issues-and-discussions-to-track)
8. [Breaking Changes in Recent Releases](#8-breaking-changes-in-recent-releases)
9. [Compatibility Risk Matrix](#9-compatibility-risk-matrix)
10. [Recommendations](#10-recommendations)

---

## 1. Overview

The `@clawdstrike/openclaw` package (`packages/adapters/clawdstrike-openclaw`) is a plugin
for the OpenClaw agent framework. It registers:

- One tool (`policy_check`) for pre-execution policy queries.
- Four hook handlers across three event types (`tool_call`, `tool_result_persist`, `agent:bootstrap`).
- A CLI namespace (`clawdstrike`) with `status` and `check` subcommands.
- An `openclaw.plugin.json` manifest describing the above.

The plugin entry point is `src/plugin.ts`, exported as the default function. It receives an
`OpenClawPluginAPI` object and wires everything together.

This document audits each API surface for compatibility with the documented OpenClaw plugin
API, identifies risk areas, and proposes mitigations.

---

## 2. Verified Compatible API Surfaces

### 2.1. `api.registerTool(config)` -- COMPATIBLE

**Our usage** (`src/plugin.ts:56-121`):

```ts
api.registerTool({
  name: "policy_check",
  description: "Check if an action is allowed...",
  parameters: { type: "object", properties: { ... }, required: [...] },
  async execute(_id: string, params: Record<string, unknown>) {
    // ...
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  },
});
```

**OpenClaw spec**: `registerTool(config, options?)` where `config` has `name`, `description`,
`parameters` (JSON Schema), and `execute(id, params)`. Return format is
`{ content: [{ type: "text", text }] }`.

**Assessment**: Fully compatible. Our `execute(_id, params)` signature matches. The return
format with `content` array of `{ type, text }` objects is the documented MCP-style response.

**Note**: We register as a required tool (no `{ optional: true }` second argument). This means
OpenClaw will surface the tool to the model on every conversation. Consider whether
`policy_check` should be optional when the enforcement mode is `audit` (log-only), since in
that mode the tool adds noise without enforcement value.

### 2.2. `api.registerCli(callback, opts)` -- COMPATIBLE

**Our usage** (`src/plugin.ts:124-164`):

```ts
api.registerCli(
  ({ program }) => {
    const clawdstrike = program.command("clawdstrike").description("...");
    clawdstrike.command("status").description("...").action(() => { ... });
    clawdstrike.command("check <action> <resource>").description("...").action(async (...args) => { ... });
  },
  { commands: ["clawdstrike"] }
);
```

**OpenClaw spec**: `registerCli(callback, opts)` where `callback` receives
`{ program: Commander.Command }` and `opts` has `commands: string[]` for discovery.

**Assessment**: Fully compatible. The Commander.js chain pattern (`program.command().description().action()`)
matches the documented API. The `{ commands: ["clawdstrike"] }` option is the documented
discovery mechanism for plugin-contributed CLI commands.

### 2.3. `api.logger` -- COMPATIBLE

**Our usage** (`src/plugin.ts:36`):

```ts
const logger = api.logger ?? console;
```

Called at registration end (`src/plugin.ts:185`):

```ts
logger.info?.("[clawdstrike] Plugin registered");
```

**OpenClaw spec**: `api.logger` is an object with `.info()`, `.warn()`, `.error()` methods.
May be `undefined` if the host does not provide one.

**Assessment**: Compatible. Our `?? console` fallback handles the `undefined` case. The
optional-chain call `logger.info?.()` is doubly safe.

### 2.4. `api.config` -- COMPATIBLE

**Our usage** (`src/plugin.ts:40`):

```ts
const pluginConfig = api.config?.plugins?.entries?.["clawdstrike-security"]?.config ?? {};
```

**OpenClaw spec**: Plugin configuration is accessed via
`api.config.plugins.entries[pluginId].config`, where `pluginId` matches the manifest `id`.

**Assessment**: Compatible. Our manifest (`openclaw.plugin.json`) declares `"id": "clawdstrike-security"`,
and we look up that exact key. The full optional-chain guards against partial configuration.

### 2.5. `api.registerHook('agent:bootstrap', handler)` -- COMPATIBLE

**Our usage** (`src/plugin.ts:177`):

```ts
api.registerHook('agent:bootstrap', agentBootstrapHandler);
```

The handler (`src/hooks/agent-bootstrap/handler.ts`) checks `event.type !== 'agent:bootstrap'`
and pushes to `bootstrap.context.bootstrapFiles`:

```ts
bootstrap.context.bootstrapFiles.push({
  path: 'SECURITY.md',
  content: securityPrompt,
});
```

**OpenClaw spec**: `agent:bootstrap` is a documented hook event. The `context.bootstrapFiles`
array mutation is the documented mechanism for injecting files into the agent workspace.

**Assessment**: Fully compatible. The handler signature matches, and `bootstrapFiles` mutation
is the sanctioned approach. The HOOK.md metadata (`events: ["agent:bootstrap"]`) also aligns
with the manifest declaration.

---

## 3. Requires Verification

### 3.1. `api.registerHook('tool_call', handler)` -- UNCERTAIN

**Risk**: **HIGH**

**Our usage** (`src/plugin.ts:173-178`):

```ts
if (typeof api.registerHook === 'function') {
  api.registerHook('tool_call', cuaBridgeHandler);
  api.registerHook('tool_call', toolPreflightHandler);
  // ...
} else if (typeof api.on === 'function') {
  api.on('tool_call', cuaBridgeHandler);
  api.on('tool_call', toolPreflightHandler);
  // ...
}
```

We register two handlers for the `'tool_call'` event: the CUA bridge handler (routes CUA
actions to the computer-use policy engine) and the tool preflight handler (blocks destructive
operations before execution).

**Concern**: OpenClaw documentation (v2026.2.1 onward) documents `'before_tool_call'` as the
canonical pre-execution hook event name, not `'tool_call'`. Issue #6535 revealed that several
hook events were declared in the type system but not actually wired into the runtime execution
flow. PRs #6570 and #6660 wired `'before_tool_call'` into the tool execution pipeline.

It is unclear whether `'tool_call'` is an alias for `'before_tool_call'`, a distinct event
that fires at a different lifecycle point, or an event that is not wired at all.

**Fallback concern**: Our `api.on()` fallback is not documented in the official OpenClaw
plugin API. The `on()` method may exist on the underlying EventEmitter but plugin authors
are expected to use `registerHook()`.

**Action required**:
1. Test against the OpenClaw runtime to confirm whether `'tool_call'` fires.
2. If it does not fire, switch to `'before_tool_call'`.
3. Verify ordering guarantees when two handlers register for the same event (CUA bridge
   must run before general preflight).

### 3.2. `event.preventDefault = true` -- UNCERTAIN

**Risk**: **HIGH**

**Our usage** (in `src/hooks/tool-preflight/handler.ts:512` and `src/hooks/cua-bridge/handler.ts:299`):

```ts
toolEvent.preventDefault = true;
toolEvent.messages.push(
  `[clawdstrike] Pre-flight check: blocked ${toolName} on ${resource}...`
);
```

When policy evaluation returns `deny`, we set `event.preventDefault = true` to signal to the
OpenClaw runtime that the tool should not execute. We also push human-readable messages into
`event.messages` for the agent to see.

**Concern**: The `preventDefault` mutation pattern is not documented in the official OpenClaw
plugin API. Community proposals (including discussions around #10502 and #1733) suggest a
return-value-based blocking mechanism:

```ts
// Proposed community pattern
return { action: 'block', reason: '...' };
// or
return { action: 'allow' };
// or
return { action: 'modify', params: { ... } };
```

The Tool Guard plugin (`openclawdir.com`) reportedly uses a `preventDefault`-like mechanism,
which suggests the runtime does support it, but it may be an undocumented internal API that
could change without notice.

Similarly, `event.messages` as a `string[]` that the runtime relays to the agent is not
formally specified. It may be dropped or restructured in future releases.

**Action required**:
1. Verify against the OpenClaw runtime that setting `event.preventDefault = true` actually
   blocks tool execution.
2. Track the return-value-based blocking proposal (issues #10502, #1733).
3. Consider dual-path: try return-value first, fall back to mutation.

### 3.3. `api.registerHook('tool_result_persist', handler)` -- LIKELY COMPATIBLE

**Our usage** (`src/plugin.ts:176`):

```ts
api.registerHook('tool_result_persist', toolGuardHandler);
```

The handler (`src/hooks/tool-guard/handler.ts`) is declared `async`:

```ts
const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'tool_result_persist') return;
  // ... await policyEngine.evaluate(policyEvent) ...
};
```

**OpenClaw spec**: `tool_result_persist` is confirmed as a working, integrated hook event in
the execution flow. It fires after a tool produces output but before the result is persisted
to the conversation transcript.

**Concern**: OpenClaw documentation states that `tool_result_persist` handlers "must be
synchronous" for deterministic ordering. Our handler is `async` because it awaits
`policyEngine.evaluate()`. If the runtime calls the handler but does not `await` the returned
Promise, then:
- Policy evaluation may complete after the result is already persisted.
- Mutations to `toolEvent.context.toolResult.error` may be silently ignored.
- The output sanitization (secret redaction) path would not run before persistence.

This is a subtle but potentially critical issue: the hook would appear to work in testing
(where the event loop runs to completion) but fail in production (where the runtime may
`fire-and-forget` synchronous-declared hooks).

**Action required**:
1. Verify whether the OpenClaw runtime awaits async hook handlers for `tool_result_persist`.
2. If it does not, refactor the handler to use synchronous evaluation or a blocking pattern.
3. The `openclaw.plugin.json` manifest declares this hook correctly:
   ```json
   { "event": "tool_result_persist", "handler": "./dist/hooks/tool-guard/handler.js" }
   ```

### 3.4. Hook Registration Order and Priority

**Risk**: MEDIUM

We register four hooks in `src/plugin.ts:173-178`:

```ts
api.registerHook('tool_call', cuaBridgeHandler);       // CUA routing (must run first)
api.registerHook('tool_call', toolPreflightHandler);    // general preflight
api.registerHook('tool_result_persist', toolGuardHandler);  // post-exec enforcement
api.registerHook('agent:bootstrap', agentBootstrapHandler); // workspace injection
```

**Concern**: The CUA bridge handler must run before the general preflight handler on
`tool_call` events, because CUA bridge detects CUA tool calls and applies specialized policy;
if general preflight runs first, it may misclassify a CUA tool as a generic destructive tool
and block it with a wrong guard.

OpenClaw does not document ordering guarantees for multiple handlers registered on the same
event from the same plugin. Some plugin frameworks use registration order; others provide a
`priority` field. The proposal in #5178 (`api.on("after_tool_result", { priority, tools }, handler)`)
suggests priority-based ordering is being considered but is not yet shipped.

**Mitigation**: Our current registration order (CUA bridge first, then preflight) likely
works if the runtime preserves insertion order. However, this is fragile. Both handlers
already include early-return guards (`isCuaToolCall` returns early in CUA bridge for non-CUA
tools, and the preflight handler checks classification). A more robust design would combine
them into a single dispatcher with explicit ordering.

---

## 4. Not Used (Opportunities)

These OpenClaw API surfaces are documented but not used by our plugin. Each represents a
potential enhancement.

### 4.1. `api.registerGatewayMethod(name, handler)`

Could expose security status, audit summaries, and real-time policy decisions via the OpenClaw
Gateway RPC interface. This would allow external dashboards and the ClawdStrike desktop
console to query live security state without going through the CLI.

### 4.2. `api.registerCommand(config)`

Could add security-related slash commands (e.g., `/security-status`, `/policy-explain`) that
appear in the agent's command palette. Currently our CLI commands are only accessible via the
terminal.

### 4.3. `api.registerService(config)`

Could run background services for:
- Policy file hot-reload (watch `policy.yaml` for changes, re-initialize engine).
- Audit log rotation and export.
- Periodic approval queue polling (replacing the synchronous poll in `requestApproval()`).
- Decision cache warming on startup.

### 4.4. `api.registerMiddleware(config)`

If available in future releases, could provide a cleaner interception model than hook
mutation, particularly for the tool-blocking use case currently handled via `preventDefault`.

---

## 5. Peer Dependency Version

**Current state** (`package.json:46-47`):

```json
"peerDependencies": {
  "openclaw": ">=0.1.0"
},
"peerDependenciesMeta": {
  "openclaw": { "optional": true }
}
```

**Problem**: OpenClaw uses CalVer (`2025.x.x`, `2026.x.x`), not semver. The package was
never published as `0.1.0`. The `>=0.1.0` range technically matches all CalVer versions in
npm's semver comparison (since `2025.0.0 > 0.1.0` is true), but this is misleading:

- It suggests we tested against a semver `0.x` release that does not exist.
- It provides no useful lower-bound signal about which OpenClaw version we actually support.
- Tooling that renders peer dependency ranges (npm, yarn, pnpm) will display it as-is,
  confusing users.

**Recommendation**: Change to one of:

```json
"openclaw": ">=2025.0.0"
```

This communicates that we target the CalVer era and provides a meaningful lower bound. If we
want to be more precise about the minimum version that wired `before_tool_call` hooks:

```json
"openclaw": ">=2026.2.1"
```

---

## 6. Plugin Manifest

**Current state**: We ship `openclaw.plugin.json` at the package root.

```json
{
  "id": "clawdstrike-security",
  "version": "0.1.0",
  "name": "Clawdstrike Security Plugin",
  "description": "...",
  "main": "./dist/plugin.js",
  "configSchema": { ... },
  "hooks": [
    { "event": "tool_result_persist", "handler": "./dist/hooks/tool-guard/handler.js" },
    { "event": "agent:bootstrap", "handler": "./dist/hooks/agent-bootstrap/handler.js" }
  ],
  "tools": [
    { "name": "policy_check", "handler": "./dist/tools/policy-check.js" }
  ],
  "commands": [
    { "name": "clawdstrike", "description": "Clawdstrike security management" }
  ]
}
```

**Findings**:

1. **Missing `tool_call` hook declaration**: The manifest declares hooks for
   `tool_result_persist` and `agent:bootstrap`, but not for `tool_call`. The `tool_call`
   hooks (CUA bridge and preflight) are registered programmatically in `src/plugin.ts` via
   `api.registerHook()`. If the OpenClaw runtime uses the manifest for hook discovery or
   validation, the programmatic hooks may be rejected or ignored.

   **Recommendation**: Add `tool_call` hook entries to the manifest:
   ```json
   { "event": "tool_call", "handler": "./dist/hooks/cua-bridge/handler.js" },
   { "event": "tool_call", "handler": "./dist/hooks/tool-preflight/handler.js" }
   ```

2. **Manifest version drift**: The manifest declares `"version": "0.1.0"` while `package.json`
   declares `"version": "0.1.1"`. These should be kept in sync.

3. **configSchema completeness**: The manifest `configSchema` does not include
   `computer_use`, `remote_desktop_side_channel`, or `input_injection_capability` guard
   toggles that are defined in `src/types.ts` (`PolicyGuards`). If the CUA bridge guards
   ship to users, the schema should reflect them.

4. **Package `openclaw` field** (`package.json:81-85`):
   ```json
   "openclaw": {
     "extensions": ["./dist/plugin.js"]
   }
   ```
   This matches the documented convention for plugin discovery. Compatible.

---

## 7. OpenClaw Issues and Discussions to Track

| Issue | Description | Impact on Us |
|-------|-------------|-------------|
| #10502 | `tool:call` and `tool:result` hook events | Would provide official tool lifecycle hooks with well-defined semantics. May replace or formalize our `tool_call` registration. |
| #1733 | `tool:pre` event for PreToolUse validation | Introduces the allow/block/modify return-value pattern for pre-tool hooks. Would replace our `preventDefault` mutation approach. |
| #19072 | First-class tool execution approvals | Would enable native human-in-the-loop workflows. We currently implement our own approval flow via `CLAWDSTRIKE_APPROVAL_URL` + polling (`src/hooks/tool-preflight/handler.ts:366-443`). |
| #20575 | Bridge plugin hook system to internal hooks | Would expose `after_tool_call` to plugins. Currently only `tool_result_persist` is available for post-execution. |
| #5178 | `after_tool_result` with priority + tool filter | `api.on("after_tool_result", { priority, tools }, handler)`. Would solve our hook ordering problem (CUA bridge before preflight) and allow tool-specific handler filtering. |
| #6535 | Hook events declared but not wired | Revealed that several hook events existed in the type system but were never connected to runtime execution. Direct precedent for our `tool_call` concern. |
| #6570 | Wire `before_tool_call` hook | The PR that actually connected `before_tool_call` to the tool execution pipeline. Confirms `before_tool_call` (not `tool_call`) is the wired event. |
| #6660 | `before_tool_call` execution ordering | Follow-up PR establishing handler execution order for `before_tool_call`. |

---

## 8. Breaking Changes in Recent Releases

### 8.1. v2026.2.1 (February 2026)

- `before_tool_call` plugin hook wired into tool execution flow (PRs #6570, #6660).
- File path validation against sandbox root -- plugins can no longer traverse outside the
  workspace via `../` in file operations.
- Plugin and hook install path validation: names containing path traversal sequences are
  rejected at load time.

**Impact**: The `before_tool_call` wiring confirms this is the correct event name for
pre-execution hooks. Our use of `tool_call` may need updating. File path validation does not
affect us (we do not perform filesystem operations from the plugin loader context).

### 8.2. v2026.2.x (February 2026, rolling)

- Docker sandbox network namespace joining blocked by default -- sandbox containers can no
  longer join the host network namespace.
- Browser SSRF policy defaults changed -- same-origin restrictions tightened for browser-based
  tool outputs.
- Security: runtime and package path containment with `realpath` checks. Symlink attacks on
  plugin paths are mitigated.
- Hook metadata now includes `guildId` and `channelName` in the event context. These are
  additive (non-breaking) but may be useful for multi-tenant audit logging.

**Impact**: No breaking changes to our core integration. The `guildId` and `channelName`
metadata could be captured in our audit logger (`src/hooks/audit-logger/handler.ts`) for
multi-tenant deployments.

### 8.3. No Breaking Changes to Core Plugin API Surface

The `registerTool`, `registerCli`, and `registerHook` method signatures are stable across
v2025.x and v2026.x. The `agent:bootstrap` and `tool_result_persist` event contracts are
unchanged.

---

## 9. Compatibility Risk Matrix

| API Surface | Risk | Status | Mitigation |
|------------|------|--------|-----------|
| `registerTool` (tool registration) | Low | Verified compatible | Fully documented and stable across versions. |
| `registerCli` (CLI registration) | Low | Verified compatible | Standard Commander.js pattern, documented `opts.commands` discovery. |
| `api.logger` | Low | Verified compatible | Nullable with `?? console` fallback. |
| `api.config` (plugin config access) | Low | Verified compatible | Optional-chained access matches documented structure. |
| `registerHook('agent:bootstrap')` | Low | Verified compatible | Documented event, documented mutation pattern. |
| `registerHook('tool_call')` (event name) | **High** | Uncertain | Must verify against runtime. May need `'before_tool_call'`. |
| `event.preventDefault` (tool blocking) | **High** | Uncertain | Undocumented mutation. May break without notice. Track #1733, #10502. |
| `event.messages` (agent messaging) | Medium | Uncertain | Not formally specified. May be restructured. |
| `registerHook('tool_result_persist')` | Medium | Likely compatible | Confirmed working; async handler may not be awaited (see 3.3). |
| Hook execution ordering | Medium | No guarantee | Registration order likely preserved but not documented. |
| `openclaw.plugin.json` manifest | Low | Mostly compatible | Missing `tool_call` hook declarations and version drift. |
| `package.json` `openclaw` field | Low | Compatible | Matches documented convention. |
| Peer dependency range (`>=0.1.0`) | Low | Misleading | Functional but confusing; should be CalVer-aligned. |

---

## 10. Recommendations

### 10.1. Critical (must fix before GA)

1. **Verify `tool_call` vs `before_tool_call` event name**: Run the E2E test suite
   (`npm run e2e`) against a live OpenClaw runtime to confirm which event name fires for
   pre-execution hooks. If `tool_call` does not fire, update all registrations to
   `before_tool_call` and update the `ToolCallEvent` type accordingly.

2. **Verify `preventDefault` blocking mechanism**: Confirm that setting
   `event.preventDefault = true` actually prevents tool execution. If it does not, implement
   the return-value blocking pattern proposed in the community.

3. **Test async handler behavior for `tool_result_persist`**: Confirm that the runtime awaits
   the returned Promise. If not, refactor `toolGuardHandler` to use synchronous policy
   evaluation or a blocking wrapper.

### 10.2. High Priority (should fix before GA)

4. **Add `tool_call` hooks to `openclaw.plugin.json`**: Declare the CUA bridge and preflight
   handlers in the manifest alongside the programmatic registration.

5. **Fix peer dependency range**: Change from `"openclaw": ">=0.1.0"` to
   `"openclaw": ">=2026.2.1"` (or `">=2025.0.0"` if backward compatibility with the 2025
   CalVer series is desired).

6. **Sync manifest version**: Align `openclaw.plugin.json` version (`0.1.0`) with
   `package.json` version (`0.1.1`).

### 10.3. Medium Priority (improve before v1.0)

7. **Consolidate `tool_call` handlers**: Merge the CUA bridge and preflight handlers into
   a single dispatcher with explicit ordering logic, rather than relying on registration
   order for prioritization.

8. **Extend audit logger with hook metadata**: Capture `guildId` and `channelName` from
   event context (when available) for multi-tenant audit trails.

9. **Extend configSchema for CUA guards**: Add `computer_use`, `remote_desktop_side_channel`,
   and `input_injection_capability` to the manifest `configSchema.properties.guards`.

### 10.4. Low Priority (track for future)

10. **Adopt `registerService` for background tasks**: Move approval polling, policy reload,
    and audit rotation into registered services.

11. **Adopt `registerGatewayMethod` for RPC**: Expose security status and audit queries via
    the Gateway for external consumption by the ClawdStrike desktop console.

12. **Consider `{ optional: true }` for `policy_check` tool**: When `mode` is `audit`,
    registering the tool as optional avoids polluting the model's tool list.
