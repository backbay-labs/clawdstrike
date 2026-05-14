# Integration Specification: @clawdstrike/swarm-engine -> SwarmBoard

> **Canonical type source**: [TYPE-SYSTEM.md](./TYPE-SYSTEM.md) is the single
> authority for all shared types. This document describes how those types
> integrate with the SwarmBoard UI layer. Where types are referenced inline,
> TYPE-SYSTEM.md definitions take precedence.

## 1. New Provider: `SwarmEngineProvider`

### Provider Hierarchy (modified)

The current page hierarchy in `/apps/workbench/src/components/workbench/swarm-board/swarm-board-page.tsx` (lines 829-836) is:

```
SwarmBoardProvider (bundlePath)
  -> ReactFlowProvider
    -> SwarmBoardCanvas
```

The new hierarchy should be:

```
SwarmEngineProvider (NEW - outermost)
  -> SwarmBoardProvider (existing, receives engine dispatch bridge)
    -> ReactFlowProvider (existing, unchanged)
      -> SwarmBoardCanvas (existing, gains engine hooks)
```

### SwarmEngineProvider Design

The provider should be placed in a new file: `apps/workbench/src/features/swarm/stores/swarm-engine-provider.tsx`

It needs to:

1. Accept an `enabled?: boolean` prop (defaults to `true`) for backward compatibility. When `enabled` is false, the entire engine is a no-op and the SwarmBoard works in manual mode.

2. Initialize the `SwarmOrchestrator` from `@clawdstrike/swarm-engine` in a `useEffect` on mount. Store the instance in a `useRef` so it survives re-renders.

3. Expose a React context with the following shape:

```typescript
interface SwarmEngineContextValue {
  engine: SwarmOrchestrator | null;
  agentRegistry: AgentRegistry | null;
  taskGraph: TaskGraph | null;
  topology: TopologyManager | null;
  guardPipeline: GuardPipeline | null;
  isReady: boolean;
  /** "engine" = orchestrator running, "manual" = fallback, "error" = init failed */
  mode: "engine" | "manual" | "error";
  /** Non-null when mode === "error". Describes what went wrong. */
  error: string | null;
}
```

4. **Handle init failure gracefully.** The `engine.initialize()` call in the `useEffect` must be wrapped in a try/catch. If initialization fails (e.g., IndexedDB unavailable in incognito, structuredClone unsupported), the provider should:
   - Set `mode: "error"` and `error: <message>` in the context value
   - Fall back to manual mode (all hooks return null, existing SwarmBoard works as-is)
   - Log a warning via `console.warn` (not throw)
   - NOT retry automatically — the user can remount or refresh

5. Subscribe to engine events in a `useEffect` and dispatch into the existing Zustand `useSwarmBoardStore` (defined at `features/swarm/stores/swarm-board-store.tsx`) via `useSwarmBoardStore.getState().actions.*` calls -- exactly the same pattern used by the existing bridge hooks at `features/swarm/hooks/`: `useCoordinatorBoardBridge`, `usePolicyEvalBoardBridge`, `useReceiptFlowBridge`, and `useTrustGraphBridge`.

6. On unmount, call `engine.shutdown()` to clean up subscriptions. Guard against double-shutdown if init failed.

### Hooks exported

- `useSwarmEngine()` -- returns `SwarmEngineContextValue`
- `useAgentRegistry()` -- returns `agentRegistry` (convenience narrow hook)
- `useTaskGraph()` -- returns `taskGraph` (convenience narrow hook)
- `useTopology()` -- returns `topology` (convenience narrow hook)

These hooks should call `useContext(SwarmEngineContext)` and throw if used outside the provider (following the pattern in the existing `useSwarmBoard()` at line 963 of `features/swarm/stores/swarm-board-store.tsx` which returns noop stubs when session context is null).

### Where SwarmBoardPage changes

In `swarm-board-page.tsx` at lines 829-836, the `SwarmBoardPage` component changes from:

```tsx
<SwarmBoardProvider bundlePath={bundlePath}>
  <ReactFlowProvider>
    <SwarmBoardCanvas />
  </ReactFlowProvider>
</SwarmBoardProvider>
```

to:

```tsx
<SwarmEngineProvider>
  <SwarmBoardProvider bundlePath={bundlePath}>
    <ReactFlowProvider>
      <SwarmBoardCanvas />
    </ReactFlowProvider>
  </SwarmBoardProvider>
</SwarmEngineProvider>
```

## 2. Modified `spawnSession()` Flow

The current `spawnSession` in `features/swarm/stores/swarm-board-store.tsx` (lines 1106-1166) follows this flow:

```
1. Resolve cwd (terminalService.getCwd fallback)
2. terminalService.create(cwd, shell) -> SessionInfo
3. createBoardNode({ nodeType: "agentSession", ... })
4. actions.addNodeDirect(node)
5. monitorSessionExit(sessionInfo.id)
6. [optional] terminalService.write (launch claude or command)
```

The new engine-aware flow should be:

```
1. Resolve cwd (unchanged)
2. agentRegistry.register(agentType, capabilities, model) -> AgentDescriptor
3. guardPipeline.evaluate({ type: "agent_spawn", agent: descriptor }) -> Decision
4. receipt = signReceipt(guardResult) -> SignedReceipt
5. terminalService.create(cwd, shell, env) -> SessionInfo  (Tauri PTY, unchanged)
6. taskOrchestrator.assign(agent, task) -> TaskAssignment
7. createBoardNode for agentSession (+ sessionId, agentId from registry)
8. createBoardNode for receipt (from guard result)
9. actions.addNodeDirect(agentNode)
10. actions.addNodeDirect(receiptNode)
11. actions.addEdge(agent -> receipt, type: "receipt")
12. monitorSessionExit(sessionInfo.id) (unchanged)
```

### Implementation approach for swarm-board-store.tsx

The `spawnSession` callback (line 1106) should NOT be modified directly. Instead, create a new `spawnEngineSession` method in the `SwarmEngineProvider` that wraps the existing `spawnSession` from `SwarmBoardSessionContext`. This keeps the existing method as the "manual mode" path.

The new method would be:

```typescript
// In SwarmEngineProvider
const spawnEngineSession = useCallback(
  async (opts: SpawnSessionOptions & { agentType?: string; model?: string }) => {
    const engine = engineRef.current;
    if (!engine) {
      // Fallback to manual mode
      return sessionCtx.spawnSession(opts);
    }

    // Step 1: Register agent
    const descriptor = engine.agentRegistry.register({
      type: opts.agentType ?? "shell",
      model: opts.model ?? "shell",
      capabilities: [],
    });

    // Step 2: Guard pipeline evaluation
    const decision = await engine.guardPipeline.evaluate({
      type: "agent_spawn",
      agentId: descriptor.id,
      action: "spawn",
      params: { cwd: opts.cwd },
    });

    // Step 3: Sign receipt
    const receipt = engine.receiptSigner.sign(decision);

    // Step 4: Create PTY (existing path)
    const node = await sessionCtx.spawnSession(opts);

    // Step 5: Link agent ID to the session node
    const { actions } = useSwarmBoardStore.getState();
    actions.updateNode(node.id, {
      agentModel: descriptor.model,
    });

    // Step 6: Create receipt node + edge
    const receiptNode = actions.addNode({
      nodeType: "receipt",
      title: `Guard: ${decision.status.toUpperCase()}`,
      position: {
        x: node.position.x,
        y: node.position.y + 340,
      },
      data: {
        verdict: decision.status as "allow" | "deny" | "warn",
        guardResults: decision.guardResults ?? [],
        signature: receipt.signature,
        publicKey: receipt.publicKey,
        status: "completed",
      },
    });

    actions.addEdge({
      id: `edge-receipt-${receiptNode.id}-${node.id}`,
      source: node.id,
      target: receiptNode.id,
      type: "receipt",
      label: decision.status,
    });

    // Step 7: Assign task if provided
    if (opts.command) {
      engine.taskOrchestrator.assign(descriptor.id, {
        prompt: opts.command,
      });
    }

    return node;
  },
  [sessionCtx],
);
```

The `SwarmEngineProvider` should expose `spawnEngineSession` alongside the existing session methods via its own context, so `SwarmBoardCanvas` can opt into the engine path when the engine is ready.

## 3. Event Bridge Mapping

A new bridge hook should be created at: `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts`

This follows the identical pattern of the four existing bridge hooks (`useCoordinatorBoardBridge`, `usePolicyEvalBoardBridge`, `useTrustGraphBridge`, `useReceiptFlowBridge`).

The bridge subscribes to engine events in a `useEffect` and calls `useSwarmBoardStore.getState().actions.*`:

| Engine Event | Store Action(s) | Board Effect |
|---|---|---|
| `agent.spawn` | `actions.addNode({ nodeType: "agentSession" })` | New agentSession node appears with entry animation |
| `agent.status_change` | `actions.setSessionStatus(agentId, newStatus)` | Status dot color changes (green/amber/red/grey) |
| `agent.heartbeat` | `actions.setSessionMetadata(agentId, { toolBoundaryEvents, changedFilesCount, confidence })` | Metrics update on node footer and inspector |
| `agent.terminate` | `actions.updateNode(nodeId, { status: "completed" })` | Node fades to completed opacity (0.7) |
| `task.create` | `actions.addNode({ nodeType: "terminalTask" })` + `actions.addEdge({ type: "spawned" })` | New task node with animated spawned edge from parent agent |
| `task.complete` | `actions.updateNode(taskNodeId, { status: "completed" })` + `actions.addNode({ nodeType: "artifact" })` + `actions.addEdge({ type: "artifact" })` | Task turns green; artifact node appears with dotted green edge |
| `task.fail` | `actions.updateNode(taskNodeId, { status: "failed" })` | Task node turns red |
| `guard.evaluate` | `actions.addNode({ nodeType: "receipt" })` + `actions.addEdge({ type: "receipt" })` + `actions.updateNode(sessionNodeId, { status: "evaluating" })` | Receipt node + edge; 2-second gold glow on session node (matching `usePolicyEvalBoardBridge` pattern at line 87-95) |
| `topology.init` | `actions.setNodes(layoutComputed)` | All nodes repositioned according to layout algorithm |
| `topology.rebalance` | `actions.setNodes(layoutComputed)` | Animated reposition of all nodes |

**Deduplication:** Each bridge event handler should check for existing nodes by matching `agentId` or `taskId` in node data before creating duplicates, following the pattern in `useCoordinatorBoardBridge` (line 72: `if (nodes.some((n) => n.data.documentId === intel.id)) return;`).

**Position computation:** Reuse the `nextNodePosition()` helper already present in `use-coordinator-board-bridge.ts` (lines 36-44). For topology events, use the layout algorithms described in section 4.

## 4. Topology -> React Flow Layout

A new module should be created at: `apps/workbench/src/features/swarm/layout/topology-layout.ts`

**No new dependencies.** The codebase already has two custom layout implementations that should be reused:

1. **Force-directed:** `apps/control-console/src/utils/forceLayout.ts` (~90 lines, custom charge repulsion + spring attraction + center gravity + damping + bounds checking). Port this into the swarm layout module.
2. **Hierarchical (Sugiyama-style):** `clawdstrike-worktrees/huntronomer-workbench/apps/workbench/src/lib/workbench/force-graph-engine.ts` (back-edge detection, layer assignment, barycenter ordering). Port the layering logic for hierarchical/hybrid topologies.

Each topology type maps to a specific layout algorithm:

### `hierarchical` -- Sugiyama tree layout (queen/coordinator at top)

- Port the Sugiyama-style layering from `force-graph-engine.ts` (huntronomer worktree)
- Direction: top-to-bottom
- Queen node at layer 0; worker agents at layer 1; tasks at layer 2; artifacts/receipts at layer 3
- Node spacing: `rankSep: 120`, `nodeSep: 80`
- Back-edge detection prevents cycles from breaking the layout

### `mesh` -- Force-directed layout

- Port the custom force simulation from `control-console/src/utils/forceLayout.ts`
- All agents as equally weighted nodes
- Edges as spring forces (strength proportional to interaction frequency)
- Charge repulsion prevents overlap; center gravity keeps the graph centered
- Iterate simulation until velocity < threshold (damping-based convergence)

### `centralized` (star) -- Hub-spoke layout

- Coordinator node at center of canvas viewport
- Worker agents arranged in a circle at radius proportional to agent count
- Tasks positioned radially outward from their parent agent
- Receipt/artifact nodes stacked below their parent
- Pure math (no layout library needed)

### `hybrid` (hierarchical-mesh) -- Sugiyama backbone with force clusters

- Use Sugiyama layering for the overall rank structure (coordinator -> workers -> tasks)
- Within each rank, use force-directed positioning for peer clusters
- This matches ruflo's recommended `hierarchical-mesh` topology

### Layout interface

```typescript
interface LayoutResult {
  positions: Map<string, { x: number; y: number }>;
}

// TopologyType — see TYPE-SYSTEM.md section 5 (canonical definition)

function computeLayout(
  nodes: Node<SwarmBoardNodeData>[],
  edges: SwarmBoardEdge[],
  topology: TopologyType,
  viewport: { width: number; height: number },
): LayoutResult;
```

### How `topology.init` and `topology.rebalance` trigger layout

When the engine emits `topology.init` or `topology.rebalance`, the bridge hook calls:

```typescript
const layout = computeLayout(currentNodes, currentEdges, event.topology, viewport);
const repositioned = currentNodes.map(n => ({
  ...n,
  position: layout.positions.get(n.id) ?? n.position,
}));
actions.setNodes(repositioned);
```

For animated transitions, the bridge can set `node.data.__layoutAnimating = true` before updating positions, then clear it after 500ms. The node components can apply a CSS `transition: transform 0.5s ease-out` when this flag is set.

## 5. New SwarmBoard Actions

Three new action types need to be added to the `SwarmBoardAction` union type at line 51 of `features/swarm/stores/swarm-board-store.tsx`:

```typescript
| { type: "TOPOLOGY_LAYOUT"; topology: TopologyType; positions: Map<string, { x: number; y: number }> }
| { type: "ENGINE_SYNC"; nodes: Node<SwarmBoardNodeData>[]; edges: SwarmBoardEdge[] }
| { type: "GUARD_EVALUATE"; agentNodeId: string; decision: Decision; receipt: SignedReceipt }
```

And corresponding Zustand actions in the `actions` namespace (line 566):

```typescript
topologyLayout: (topology: TopologyType, positions: Map<string, { x: number; y: number }>) => void;
engineSync: (nodes: Node<SwarmBoardNodeData>[], edges: SwarmBoardEdge[]) => void;
guardEvaluate: (agentNodeId: string, decision: Decision, receipt: SignedReceipt) => void;
```

### `topologyLayout`

Applies computed positions to all nodes. Calls `set({ nodes: repositioned })` then `schedulePersist()`. Following the existing `setNodes` pattern at line 766.

### `engineSync`

Bulk sync engine state to board state. Merges engine nodes/edges with existing manual nodes (does not delete nodes that the engine does not know about). Uses a `Map` keyed on `agentId`/`taskId` for O(1) merge lookups.

### `guardEvaluate`

Creates a receipt node, creates a receipt edge from the agent node to the receipt node, and temporarily sets the agent node to `status: "evaluating"` with a 2-second reset timer (matching `usePolicyEvalBoardBridge` at lines 86-95).

### Dispatch shim update

The dispatch shim at line 909 should also be updated to handle these three new action types for backward compatibility.

## 6. Backward Compatibility

### Detection workflow integration

`use-swarm-launch.ts` (at `apps/workbench/src/lib/workbench/detection-workflow/use-swarm-launch.ts`) calls `useSwarmBoardStore.getState().actions.addNodeDirect()` and `actions.addEdge()` directly (lines 207-214). These Zustand actions are unchanged. The `_dispatchSwarmNodes` function, `buildPayload`, and all the node creation helpers (`createDetectionRuleNode`, `createEvidencePackNode`, etc.) remain untouched.

`swarm-session-templates.ts` is pure data (template definitions); it has no store interaction and is unaffected.

### Mock data seeder

`createMockBoard()` at line 227 of `features/swarm/stores/swarm-board-store.tsx` returns `{ nodes, edges }` and is called directly. It does not depend on the engine and will continue working.

### All existing tests (~745 cases across ~216 files)

The engine is gated behind the `SwarmEngineProvider`. When tests mount `SwarmBoardProvider` without `SwarmEngineProvider` (as all existing tests do), the engine hooks return `null` and no engine events are dispatched. The Zustand store actions remain identical.

### Key compatibility guarantees

- The `useSwarmBoard()` hook signature is unchanged (line 963). It still returns `state`, `dispatch`, `addNode`, `removeNode`, etc.
- The `SwarmBoardAction` type is extended (not modified). Existing action types are preserved exactly.
- The `SwarmBoardNodeData` interface does not need new required fields. Optional fields can be added for engine metadata (`agentId?: string`, `taskId?: string`, `engineManaged?: boolean`).
- The `SwarmBoardSessionContext` value shape is unchanged. `spawnEngineSession` is provided via the new `SwarmEngineContext`, not by modifying the existing context.

## 7. Test Plan

### New test files

| File | Cases | Description |
|---|---|---|
| `apps/workbench/src/features/swarm/stores/__tests__/swarm-engine-provider.test.tsx` | ~15 | Provider initialization, context value shape, cleanup on unmount, manual mode fallback when `enabled=false` |
| `apps/workbench/src/features/swarm/hooks/__tests__/use-engine-board-bridge.test.ts` | ~25 | All 9 event types mapped to correct store actions; deduplication; position computation; evaluating glow timer |
| `apps/workbench/src/features/swarm/layout/__tests__/topology-layout.test.ts` | ~20 | Each of 4 topology types produces valid positions; empty graph handling; single-node graph; position stability on re-layout |
| `apps/workbench/src/features/swarm/stores/__tests__/swarm-board-store-engine-actions.test.tsx` | ~12 | `topologyLayout`, `engineSync`, `guardEvaluate` actions; dispatch shim routing for new action types |
| `apps/workbench/src/features/swarm/hooks/__tests__/use-swarm-engine-hooks.test.tsx` | ~8 | `useSwarmEngine()`, `useAgentRegistry()`, `useTaskGraph()`, `useTopology()` return correct values; throw outside provider |

### Key test cases

1. **Engine init lifecycle** -- Engine creates on mount, destroys on unmount, handles double-mount.
2. **Manual mode** -- `<SwarmEngineProvider enabled={false}>` does not create engine; all hooks return null; existing functionality works.
3. **Event-to-action mapping** -- For each engine event type, verify the correct Zustand store actions are called with correct arguments.
4. **Deduplication** -- Emitting `agent.spawn` twice with the same `agentId` creates only one node.
5. **Guard evaluate glow cycle** -- Verify `status: "evaluating"` is set, then restored to previous status after 2000ms.
6. **Topology layout -- hierarchical** -- Queen at top, workers below, tasks below workers.
7. **Topology layout -- mesh** -- No node overlaps; all nodes within viewport bounds.
8. **Topology layout -- star** -- Hub centered; spokes equidistant.
9. **Engine sync merge** -- Manual nodes are preserved when engine sync runs; engine-managed nodes are updated.
10. **spawnEngineSession** -- Guard pipeline is called; receipt node is created; fallback to manual spawn on engine unavailability.
11. **Backward compatibility** -- Mount `SwarmBoardProvider` without `SwarmEngineProvider`; verify all ~745 existing test cases still pass (no regressions).
12. **Detection workflow unaffected** -- `_dispatchSwarmNodes` still creates nodes correctly when engine is present.

### Testing approach

All tests should use mock implementations of the `@clawdstrike/swarm-engine` module via `vi.mock()`. The engine tests should verify the bridge layer (events in -> store actions out), not the engine internals.

## Critical Files for Implementation

| File | Changes |
|---|---|
| `apps/workbench/src/features/swarm/stores/swarm-board-store.tsx` | Add 3 new actions (`topologyLayout`, `engineSync`, `guardEvaluate`), extend dispatch shim, add optional engine metadata fields to node data |
| `apps/workbench/src/components/workbench/swarm-board/swarm-board-page.tsx` | Wrap with `SwarmEngineProvider`, wire `useEngineBoardBridge` into `SwarmBoardCanvas` alongside the 4 existing bridge hooks |
| `apps/workbench/src/features/swarm/hooks/use-coordinator-board-bridge.ts` | Pattern to follow: event subscription in useEffect, deduplication, store action dispatch, cleanup on unmount |
| `apps/workbench/src/features/swarm/swarm-board-types.ts` | Add optional fields (`agentId`, `taskId`, `engineManaged`) to `SwarmBoardNodeData` interface. **Add `"topology"` to `SwarmBoardEdge.type`** union (currently `"handoff" \| "spawned" \| "artifact" \| "receipt"` — see line 96). This is needed for topology edges emitted by the engine bridge. |
| `packages/sdk/hush-ts/src/clawdstrike.ts` | Guard pipeline interface: `Clawdstrike.check()` returns `Decision` with `status`, `guard`, `severity` -- the contract the engine bridge must consume for receipt creation |
