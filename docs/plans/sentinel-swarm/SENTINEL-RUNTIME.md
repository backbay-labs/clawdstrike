# Sentinel Runtime Plan

> Concrete plan for Sentinel Drivers, Claude Code Sentinel, OpenClaw Hunt Pod,
> and execution-mode visibility.

**Status:** Phase 0 in execution
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Current State

The workbench already has strong sentinel UX, but runtime backing is still
implicit:

- `sentinel-store.tsx` persists sentinels locally.
- `sentinel-manager.ts` generates a compatible local identity.
- `sentinel-types.ts` only hints at runtime backing through `fleetAgentId`.
- `control-api` already supports agent runtime registration at
  `POST /agents/{id}/runtimes`.
- adapters already exist for Claude and OpenClaw.

The missing contract is a first-class runtime binding on each sentinel.

## Runtime Contract

Every sentinel gets a runtime binding with five operator-visible dimensions:

1. `driver`
   The execution backend: `claude_code`, `openclaw`, `hushd_agent`,
   `openai_agent`, or `mcp_worker`.
2. `executionMode`
   Product-facing operating posture: `observe`, `assist`, `enforce`.
3. `enforcementTier`
   Contract-facing tier from `docs/src/concepts/enforcement-tiers.md`.
4. `targetRef`
   The runtime target this sentinel is bound to: repo/workspace, gateway/node,
   fleet agent, remote endpoint, or MCP worker identifier.
5. `runtime/session refs`
   IDs that let UI findings and receipts point back to the actual runtime.

## Driver Matrix

| Driver | Primary use | Default target | Likely tier ceiling |
|--------|-------------|----------------|---------------------|
| `claude_code` | Repo-native code sentinel | local workspace | Tier 1 |
| `openclaw` | Browser/computer-use missions | gateway or node | Tier 2 |
| `hushd_agent` | Fleet-backed watcher/hunter | fleet runtime | Tier 1 |
| `openai_agent` | Remote model-backed agent | remote session | Tier 1 |
| `mcp_worker` | MCP tool worker or local orchestration lane | local or remote MCP endpoint | Tier 2 |

## Execution Mode Mapping

| Product mode | Meaning | Tier mapping |
|--------------|---------|--------------|
| `observe` | Capture evidence and receipts only | Tier 0 |
| `assist` | Advisory or operator-mediated execution | Tier 1 |
| `enforce` | Runtime actively mediates side effects | Tier 1-2 today, Tier 3 later when sandboxing exists |

`enforcementTier` remains explicit because `enforce` is a product promise while
the actual hard boundary depends on the driver and runtime.

## API and Storage Shape

Phase 0 adds a local-first binding object to the workbench sentinel model:

```ts
interface SentinelRuntimeBinding {
  driver: SentinelDriverKind;
  executionMode: SentinelExecutionMode;
  enforcementTier: 0 | 1 | 2 | 3;
  endpointType: "local" | "fleet" | "gateway" | "remote";
  targetRef: string | null;
  runtimeRef: string | null;
  sessionRef: string | null;
  health: "planned" | "ready" | "degraded" | "offline";
  receiptsEnabled: boolean;
  emitsSignals: boolean;
  lastHeartbeatAt: number | null;
  notes?: string;
}
```

### Control-plane binding plan

1. Create/update sentinel locally in the workbench store.
2. When a real runtime is attached, register or reconcile it with control-api.
3. Persist returned runtime principal/session identifiers back into the binding.
4. Route receipts, signals, and mission evidence through the sentinel ID.

## UI Plan

### Create Sentinel

- add driver selection to the create wizard
- add execution mode selection with tier preview
- capture optional runtime target metadata
- keep policy/schedule selection in the same step so the runtime and policy are
  configured together

### Sentinel Detail

- add runtime health and binding metadata in the config tab
- show execution mode and tier in the detail header/sidebar
- make the runtime target visible before full driver integrations land

### Sentinel List

- show which driver a sentinel is bound to
- show whether it is in `observe`, `assist`, or `enforce`

## Driver Pilot Follow-Ups

### Claude Code Sentinel

Phase 1 work:

1. bind a sentinel to a local workspace or repo
2. stream tool events from the Claude adapter into `Signal`
3. attach command/tool receipts to findings
4. let a mission hand the repo lane to this sentinel

### OpenClaw Hunt Pod

Phase 1 work:

1. bind a sentinel to an active OpenClaw gateway/node
2. capture browser/computer-use transcript summaries as evidence
3. surface approval and execution posture in the mission timeline
4. translate high-risk interactions into policy violations or findings

## Milestones

### M0

Model/UI/store support for runtime binding and execution modes.

### M1

Working Claude Code Sentinel binding with tool-event to signal conversion.

### M2

Working OpenClaw Hunt Pod binding with transcript to signal conversion.

### M3

Mission Control can assign and observe these runtime-backed sentinels.
