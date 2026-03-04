# Agent Attribution Model

Clawdstrike tracks two agent layers for policy events:

- Endpoint agent: the desktop/host agent process running `clawdstrike-agent`.
- Runtime agent: the in-process AI runtime/tooling actor (for example Claude Code, OpenClaw gateway, MCP tools).

This split avoids the "all events look like one desktop agent" problem and lets the control console show both host-level ownership and runtime-level activity.

## Event Contract

`/api/v1/check` accepts:

- `agent_id`: endpoint agent ID
- `runtime_agent_id` (optional): runtime actor ID within the endpoint
- `runtime_agent_kind` (optional): runtime type (`claude_code`, `openclaw`, `mcp`, etc.)

Code:

- `crates/services/hushd/src/api/check.rs` (`CheckRequest`)
- `apps/agent/src-tauri/src/policy.rs` (`PolicyCheckInput`)

## Attribution Sources (Agent App)

Runtime attribution is attached where events originate:

- OpenClaw gateway checks:
  - `apps/agent/src-tauri/src/api_server.rs`
  - sets `runtime_agent_id = gateway:<gateway_id>`, `runtime_agent_kind = openclaw`
- MCP tool checks:
  - `apps/agent/src-tauri/src/integrations/mcp_server.rs`
  - supports explicit runtime fields and defaults to `runtime_agent_kind = mcp`, `runtime_agent_id = mcp-local`
- Claude Code hooks:
  - `apps/agent/src-tauri/src/integrations/claude_code.rs`
  - derives runtime identity from tool/session/conversation payload and sends `runtime_agent_kind = claude_code`

Endpoint attribution is normalized in:

- `apps/agent/src-tauri/src/policy.rs`
  - `resolve_effective_endpoint_agent_id`
  - precedence: NATS `agent_id` -> enrollment UUID -> persisted local agent ID -> generated local ID

## Backend Propagation (hushd)

`hushd` forwards runtime attribution through all policy telemetry channels:

- SSE event broadcast (`/api/v1/events`)
  - payload includes `agent_id`, `runtime_agent_id`, `runtime_agent_kind`
- Certification webhook payloads for violations
  - includes `agentId`, `runtimeAgentId`, `runtimeAgentKind`
- Audit metadata + audit_v2 extensions
  - persists runtime fields for later query/export

Code:

- `crates/services/hushd/src/api/check.rs`

## Control Console Aggregation

The console models attribution hierarchically:

- Group by endpoint agent (`agent_id`)
- Within each endpoint, group by runtime agent (`runtime_agent_id`)
- Keep desktop-only sessions separately

Code:

- Event types: `apps/control-console/src/hooks/useSSE.ts`
- Aggregation: `apps/control-console/src/hooks/useAgentSessions.ts`
- Rendering: `apps/control-console/src/pages/AgentExplorer.tsx`
- Cards/details: `apps/control-console/src/components/agents/AgentSessionCard.tsx`

## Test Coverage

- Runtime grouping logic:
  - `apps/control-console/src/hooks/useAgentSessions.test.ts`
- End-to-end Agent Explorer runtime hierarchy:
  - `apps/control-console/tests/agent-explorer-runtime.spec.ts`
- `/api/v1/check` SSE runtime attribution:
  - `crates/services/hushd/tests/integration.rs` (`test_check_sse_includes_runtime_agent_attribution`)
