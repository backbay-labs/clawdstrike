# ADR 0003: Canonical `PolicyEvent` + severity vocabulary (cross-SDK)

Status: **ACCEPTED**  
Date: 2026-02-03

## Context

Docs/plans and the runtimes currently disagree on:

- The shape/name of the event being evaluated (`PolicyEvent` vs guard-specific actions).
- The severity vocabulary (`low/medium/high/critical` vs `info/warning/error/critical`).

This blocks “same inputs, same decisions” parity tests across Rust + TypeScript.

## Decision

### Canonical `PolicyEvent` (portable JSON)

The M0 canonical event envelope is **camelCase JSON**:

- `eventId: string` (stable ID for correlation)
- `eventType: string` (see below)
- `timestamp: string` (RFC 3339 / ISO 8601)
- `sessionId?: string` (run/session correlation)
- `data: object` (event-specific payload; must include a `type` discriminator)
- `metadata?: object` (freeform; recommend `source`, `agentId`, `traceId`)

Canonical event types (initial set):

- `file_read`, `file_write`
- `network_egress`
- `command_exec`
- `patch_apply`
- `tool_call` (includes MCP tool calls; see `metadata.toolKind`)
- `custom` (escape hatch; requires `data.customType`)

**Input compatibility:** runtimes MAY accept snake_case aliases (`event_id`, `event_type`, …) but MUST normalize to the canonical camelCase shape internally/when emitting fixtures.

### Canonical severity vocabulary

For violations, standardize on:

`severity ∈ {"low","medium","high","critical"}`

Severity is distinct from the **decision/action** (`allow` / `warn` / `deny`).

### Mapping tables (current implementations)

**Severity mapping**

| Canonical | TS/OpenClaw (`@clawdstrike/openclaw`) | Rust (`crates/clawdstrike`) |
|---|---|---|
| low | low | info |
| medium | medium | warning |
| high | high | error |
| critical | critical | critical |

**Event mapping (by intent)**

| Canonical `eventType` | Canonical `data.type` | TS/OpenClaw shape today | Rust shape today |
|---|---|---|---|
| file_read | file | `PolicyEvent` + `data.path`, `operation:"read"` | `GuardAction::FileAccess(path)` |
| file_write | file | `PolicyEvent` + `data.path`, `operation:"write"` | `GuardAction::FileWrite(path, bytes)` |
| network_egress | network | `host`, `port`, optional `url` | `GuardAction::NetworkEgress(host, port)` |
| command_exec | command | `command`, `args[]` | `GuardAction::ShellCommand(commandline)` |
| patch_apply | patch | `filePath`, `patchContent` | `GuardAction::Patch(file, diff)` |
| tool_call | tool | `toolName`, `parameters` | `GuardAction::McpTool(tool, args)` *(for MCP)* / otherwise `GuardAction::Custom(type, data)` *(TBD)* |
| custom | custom | *(not yet supported)* | `GuardAction::Custom(customType, data)` |

**MCP encoding (canonical):**

- Use `eventType: "tool_call"`, `data.type: "tool"`.
- Distinguish MCP tools via metadata (recommended): `metadata.toolKind: "mcp"`, `metadata.toolProvider: "blender-mcp"`, etc.

## Consequences

- Enables a shared JSONL fixture corpus (see `fixtures/policy-events/v1/`) for parity testing.
- Forces an explicit answer on “what is a warning” vs “what is low severity”.

## Confirmed by Connor (2026-02-03)

- Canonical JSON casing: camelCase (`eventId`, …); snake_case accepted as input aliases
- Event taxonomy: keep `tool_call` unified; do not introduce `mcp_tool` eventType
- `custom` is allowed as a v1 escape hatch with required `data.customType`; recommend dot-separated namespaces (e.g. `hushclaw.untrusted_text`)
