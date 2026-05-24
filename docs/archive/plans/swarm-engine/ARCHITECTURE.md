# @clawdstrike/swarm-engine -- Architecture Plan

> Extracted from ruflo v3 `@claude-flow/swarm`, adapted for browser/Tauri WebView.
> Zero Node.js dependencies. Guard pipeline integration. SwarmBoard-native.

---

## 1. Package Structure

```
packages/swarm-engine/
├── src/
│   ├── index.ts                — Public API surface (re-exports)
│   ├── orchestrator.ts         — SwarmOrchestrator (main entry)
│   ├── agent-registry.ts       — Agent lifecycle management
│   ├── task-graph.ts           — Task DAG with dependency resolution
│   ├── topology.ts             — Network topology (mesh/hierarchical/hybrid)
│   ├── consensus/
│   │   ├── index.ts            — ConsensusEngine factory + algorithm selector
│   │   ├── raft.ts             — Raft leader election + log replication
│   │   ├── byzantine.ts        — PBFT consensus
│   │   └── gossip.ts           — Eventual-consistency gossip protocol
│   ├── agent-pool.ts           — Agent pooling, auto-scaling, health checks
│   ├── memory/
│   │   ├── hnsw.ts             — Pure-math HNSW vector index (no native deps)
│   │   ├── graph.ts            — In-memory knowledge graph
│   │   └── idb-backend.ts      — IndexedDB persistence backend
│   ├── protocol.ts             — SwarmEnvelope bridge (maps engine events to ClawdStrike protocol)
│   └── types.ts                — Merged type definitions
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

Location: `/Users/connor/Medica/backbay/standalone/clawdstrike-swarm-engine/packages/swarm-engine/`

### 1.1 package.json

```json
{
  "name": "@clawdstrike/swarm-engine",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": { "import": "./dist/index.js", "types": "./dist/index.d.ts" },
    "./consensus": { "import": "./dist/consensus/index.js", "types": "./dist/consensus/index.d.ts" },
    "./memory": { "import": "./dist/memory/hnsw.js", "types": "./dist/memory/hnsw.d.ts" }
  },
  "sideEffects": false,
  "files": ["dist"],
  "dependencies": {},
  "devDependencies": {
    "typescript": "^5.4",
    "vitest": "^2.0",
    "fake-indexeddb": "^6.0"
  },
  "peerDependencies": {}
}
```

Zero runtime dependencies. The package is pure TypeScript compiled to ESM.

### 1.2 tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM"],
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "dist",
    "strict": true,
    "isolatedModules": true,
    "esModuleInterop": false,
    "skipLibCheck": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

`"lib": ["DOM"]` gives us `performance.now()`, `crypto.subtle`, `EventTarget`, `CustomEvent`, `setInterval`/`setTimeout`, and `structuredClone` -- all available in both browsers and Tauri WebView.

---

## 2. Extraction Criteria

For each ruflo source file, the table below documents what to extract, what to leave behind, and what to adapt.

### 2.1 unified-coordinator.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/unified-coordinator.ts`

**Ruflo's UnifiedSwarmCoordinator** (1,844 lines) consolidates SwarmCoordinator, HiveMind, Maestro, and AgentManager. It extends `EventEmitter` from Node.js `events`, uses `NodeJS.Timeout` for background intervals, and composes TopologyManager, MessageBus, AgentPool, and ConsensusEngine.

| Category | Details |
|----------|---------|
| **Extract** | Full coordinator lifecycle (`initialize`, `shutdown`, `pause`, `resume`). Agent management (`registerAgent`, `unregisterAgent`, `getAgent`, `getAllAgents`, `getAgentsByType`, `getAvailableAgents`). Task management (`submitTask`, `cancelTask`, `getTask`, `getAllTasks`, `getTasksByStatus`). Consensus delegation (`proposeConsensus`). Monitoring (`getState`, `getMetrics`, `getPerformanceReport`). Domain-based routing (the `DOMAIN_CONFIGS` array, `AgentDomain` type, `DomainConfig`, `DomainStatus`, `TaskAssignment`, `ParallelExecutionResult`). Background heartbeat/health/metrics timers (the logic, not the timer type). Performance tracking (coordination latency recording, throughput calculation, utilization calculation). |
| **Leave behind** | `import { EventEmitter } from 'events'` (Node.js module). `NodeJS.Timeout` type annotations. The hardcoded 15-agent ruflo-specific domain assignments (agents 1-15 with ruflo-specific roles like `mcp-optimizer`, `neural-integrator`). |
| **Adapt** | Replace `EventEmitter` with a browser-safe `TypedEventEmitter` (see Section 2.8). Replace `NodeJS.Timeout` with `ReturnType<typeof setTimeout>`. Replace ruflo's `MessageBus.broadcast()` with a `ProtocolBridge` that emits `SwarmEnvelope` objects through ClawdStrike's `TransportAdapter` interface. The domain configs become user-configurable rather than hardcoded (ClawdStrike agents have different roles than ruflo's 15-agent hierarchy). The new class is named `SwarmOrchestrator` to avoid collision with ClawdStrike's existing `SwarmCoordinator` (the networking layer). |

**Resulting file: `orchestrator.ts`**

Key interface:

```typescript
export interface SwarmOrchestratorConfig {
  topology: TopologyConfig;
  consensus: ConsensusConfig;
  maxAgents: number;
  maxTasks: number;
  heartbeatIntervalMs: number;
  healthCheckIntervalMs: number;
  taskTimeoutMs: number;
  autoScaling: boolean;
  autoRecovery: boolean;
  // ClawdStrike-specific: guard pipeline hook
  guardEvaluator?: GuardEvaluator;
}

export interface SwarmOrchestrator {
  initialize(): Promise<void>;
  shutdown(): Promise<void>;
  pause(): Promise<void>;
  resume(): Promise<void>;

  // Agent management
  registerAgent(agent: AgentRegistration): Promise<string>;
  unregisterAgent(agentId: string): Promise<void>;
  getAgent(agentId: string): AgentState | undefined;
  getAllAgents(): AgentState[];

  // Task management (guard-aware)
  submitTask(task: TaskSubmission): Promise<string>;
  cancelTask(taskId: string): Promise<void>;
  getTask(taskId: string): TaskDefinition | undefined;

  // Consensus
  proposeConsensus(value: unknown): Promise<ConsensusResult>;

  // Monitoring
  getState(): OrchestratorState;
  getMetrics(): OrchestratorMetrics;

  // Event subscription
  on<E extends SwarmEventType>(event: E, handler: SwarmEventHandler<E>): () => void;
}
```

### 2.2 coordination/agent-registry.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/coordination/agent-registry.ts`

**Ruflo's AgentRegistry** (544 lines) manages agent definitions, lifecycle (spawn/terminate), state, health checks, and queries. It uses a custom `IEventBus` interface from `../shared/events`.

| Category | Details |
|----------|---------|
| **Extract** | The full `IAgentRegistry` interface (register, unregister, spawn, terminate, getState, updateStatus, assignTask, completeTask, getAllAgents, getActiveAgents, getAgentsByDomain, getAgentsByCapability, heartbeat, getHealthStatus, onAgentEvent). The `AgentRegistry` class implementation. The `HealthStatus` interface. Health check timer logic (startHealthChecks, stopHealthChecks, performHealthCheck). The `createInitialMetrics()` factory. |
| **Leave behind** | The `registerDefaultAgents()` method that hardcodes ruflo's 15 agents with ruflo-specific roles (`queen-coordinator`, `security-architect`, `security-implementer`, etc.) and ruflo-specific capability types (`security-audit`, `architecture-design`, `mcp-enhancement`, etc.). The import of ruflo's `IEventBus` from `../shared/events`. |
| **Adapt** | Replace ruflo's `IEventBus` with the swarm-engine's own `TypedEventEmitter`. Default agent registration becomes opt-in: consumers pass their own `AgentDefinition[]` instead of getting ruflo's 15-agent swarm. The `AgentDefinition` type gains an optional `guardPolicy` field so each agent can declare its ClawdStrike policy mode. `setInterval`/`clearInterval` are already browser-safe. |

**Resulting file: `agent-registry.ts`**

### 2.3 coordination/task-orchestrator.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/coordination/task-orchestrator.ts`

**Ruflo's TaskOrchestrator** (605 lines) manages a task DAG with dependency resolution, priority queuing, lifecycle state machine, and metrics. Pure data structures (Maps, Sets), no I/O.

| Category | Details |
|----------|---------|
| **Extract** | The full `ITaskOrchestrator` interface and `TaskOrchestrator` class. The dependency graph (adjacency-list representation via `dependencyGraph` and `dependentGraph` Maps of Sets). Cycle detection (`wouldCreateCycle` using iterative DFS). The priority queue (`getNextTask`, `getPriorityQueue` with priority ordering). Task lifecycle state machine (pending -> queued -> assigned -> in-progress -> completed/failed/cancelled). Blocked status tracking (`updateBlockedStatus`, `unblockDependentTasks`). Retry logic (`failTask` with `retryCount`/`maxRetries`). `TaskOrchestratorMetrics`. |
| **Leave behind** | ruflo's `AgentDomain` enum values (`security`, `core`, `integration`, `quality`, `performance`, `deployment`). ruflo's `PhaseId` type. |
| **Adapt** | The task DAG is the core of the new `task-graph.ts` file. Domain and phase concepts become generic string tags rather than ruflo-specific enums. Add a `guardRequired` field to `TaskSpec` to indicate tasks that must pass through ClawdStrike's guard pipeline before execution. Replace ruflo's event bus imports with the engine's own event system. |

**Resulting file: `task-graph.ts`**

### 2.4 topology-manager.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/topology-manager.ts`

**Ruflo's TopologyManager** (656 lines) extends Node.js `EventEmitter` and manages network topology with mesh, hierarchical, centralized, and hybrid modes. Uses adjacency lists, O(1) role indexes, BFS shortest path, leader election, and auto-rebalancing.

| Category | Details |
|----------|---------|
| **Extract** | The entire class logic: `addNode`, `removeNode`, `updateNode`, `electLeader`, `rebalance` (mesh/hierarchical/centralized/hybrid variants), `getNeighbors`, `findOptimalPath` (BFS), `getNodesByRole`, `getActiveNodes`, `isConnected`. O(1) role index (`roleIndex` Map, `queenNode`/`coordinatorNode` caches). Partition management. Edge creation with bidirectional support. The `shouldRebalance` heuristic. All topology types: `TopologyConfig`, `TopologyState`, `TopologyNode`, `TopologyEdge`, `TopologyPartition`, `TopologyType`. |
| **Leave behind** | `import { EventEmitter } from 'events'` (Node.js). |
| **Adapt** | Replace `EventEmitter` with `TypedEventEmitter`. The topology state becomes the primary data source for SwarmBoard auto-layout: when `addNode`/`removeNode`/`rebalance` fire, the engine emits events that the `SwarmEngineProvider` maps to React Flow node positions. Add a `toReactFlowLayout()` method that converts `TopologyState` into `{ nodes: Node[], edges: Edge[] }` using a force-directed or dagre layout algorithm. |

**Resulting file: `topology.ts`**

### 2.5 message-bus.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/message-bus.ts`

**Ruflo's MessageBus** (607 lines) extends Node.js `EventEmitter` and implements a high-performance priority message queue using a custom `Deque` (circular buffer) and 4-level priority lanes. Uses `setImmediate` for async delivery, `NodeJS.Timeout` for intervals, and `performance.now()` for latency.

| Category | Details |
|----------|---------|
| **Extract** | The `Deque<T>` circular buffer (O(1) push/pop). The `PriorityMessageQueue` (4-lane priority deque). Message lifecycle: `send`, `broadcast`, `subscribe`, `unsubscribe`, `acknowledge`. Queue processing with batch delivery. TTL-based expiration. Retry logic with re-enqueue. Stats collection (messages/sec, latency EMA, queue depth). The `MessageBusStats` type. |
| **Leave behind** | `import { EventEmitter } from 'events'`. `setImmediate` (not available in browsers). `NodeJS.Timeout` type. The entire `MessageBus` class as a standalone component -- it is **not extracted** as a separate module. |
| **Adapt** | The MessageBus is **replaced** rather than extracted. ClawdStrike already has `SwarmCoordinator` with `TransportAdapter` (see `swarm-coordinator.ts` line 211) and `SwarmEnvelope` (line 67). The swarm-engine's internal agent-to-agent messaging uses a thin `InternalBus` that wraps `EventTarget` (browser-native, same pattern as ClawdStrike's `InProcessEventBus`). External messaging goes through the `ProtocolBridge` (see `protocol.ts`). The `Deque` and `PriorityMessageQueue` data structures ARE extracted as utilities for the task graph's priority queue. `setImmediate` is replaced with `queueMicrotask` or `setTimeout(fn, 0)`. |

**Resulting file: protocol.ts (bridge) + internal Deque/PriorityQueue reused in task-graph.ts**

### 2.6 agent-pool.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/agent-pool.ts`

**Ruflo's AgentPool** (476 lines) extends Node.js `EventEmitter` and manages agent pooling with acquire/release semantics, auto-scaling with cooldown, LRU eviction on scale-down, and health checks.

| Category | Details |
|----------|---------|
| **Extract** | The full `AgentPool` class logic: `acquire`, `release`, `add`, `remove`, `scale` (up/down with cooldown), `getState`, `getUtilization`, `getPoolStats`. Auto-scaling logic (`checkScaling` with configurable `scaleUpThreshold`/`scaleDownThreshold`). Health checks (`performHealthChecks` with unhealthy agent replacement). LRU-based scale-down (sort available by `lastUsed`). The `AgentPoolConfig` and `AgentPoolState` types. |
| **Leave behind** | `import { EventEmitter } from 'events'`. `NodeJS.Timeout`. The `createDefaultCapabilities()` method that hardcodes ruflo-specific capabilities (languages: `['typescript', 'javascript', 'python']`, frameworks: `['node', 'deno', 'react']`, tools: `['git', 'npm', 'editor']`). |
| **Adapt** | Replace `EventEmitter` with `TypedEventEmitter`. Replace `NodeJS.Timeout` with `ReturnType<typeof setTimeout>`. Default capabilities become a config parameter so consumers define their own agent capabilities. In ClawdStrike context, an "agent" in the pool maps to a PTY session or a `claude -p` headless instance. The pool does not spawn OS processes (that is ClawdStrike's Tauri layer) -- it manages the logical agent state. |

**Resulting file: `agent-pool.ts`**

### 2.7 consensus/\*.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/consensus/index.ts`, `raft.ts`, `byzantine.ts`, `gossip.ts`

**Ruflo's ConsensusEngine** (267 lines) is a factory that delegates to Raft (leader election + log replication), Byzantine (PBFT-style with prepare/commit phases), or Gossip (eventual consistency with fanout). Each implementation extends Node.js `EventEmitter` and uses `NodeJS.Timeout`.

| Category | Details |
|----------|---------|
| **Extract** | The `ConsensusEngine` factory (`createConsensusEngine`, `selectOptimalAlgorithm`). Raft: `RaftConsensus` class (leader election via randomized timeout, proposal/vote, term management, `RaftState`, `RaftNode`, `RaftLogEntry`). Byzantine: `ByzantineConsensus` class (pre-prepare/prepare/commit phases, `ByzantineMessage`, `ByzantineNode`, view change timeout). Gossip: `GossipConsensus` class (fanout, hop-limited propagation, `GossipMessage`, `GossipNode`, convergence threshold). All consensus types: `ConsensusAlgorithm`, `ConsensusConfig`, `ConsensusProposal`, `ConsensusVote`, `ConsensusResult`. |
| **Leave behind** | `import { EventEmitter } from 'events'`. `NodeJS.Timeout`. |
| **Adapt** | Replace `EventEmitter` with `TypedEventEmitter`. Replace `NodeJS.Timeout` with `ReturnType<typeof setTimeout>`. The consensus algorithms are pure state machines at their core -- the timer-based election timeouts and heartbeat intervals use `setTimeout`/`setInterval` which are browser-safe. No other adaptation needed; these are already pure logic. |

**Resulting files: `consensus/index.ts`, `consensus/raft.ts`, `consensus/byzantine.ts`, `consensus/gossip.ts`**

### 2.8 types.ts

**Source:** `ruflo/v3/@claude-flow/swarm/src/types.ts`

**Ruflo's types file** (545 lines) defines all type definitions for the swarm system. The only Node.js dependency is `import { EventEmitter } from 'events'` (a dead/unused import -- `IEventBus` is actually defined in `shared/events.ts`, not here). Safe to remove during extraction.

| Category | Details |
|----------|---------|
| **Extract** | All core types: `SwarmId`, `AgentId`, `TaskId`, `TopologyType`, `TopologyConfig`, `TopologyState`, `TopologyNode`, `TopologyEdge`, `TopologyPartition`, `AgentType`, `AgentStatus`, `AgentCapabilities`, `AgentMetrics`, `AgentState`, `TaskType`, `TaskStatus`, `TaskPriority`, `TaskDefinition`, `ConsensusAlgorithm`, `ConsensusConfig`, `ConsensusProposal`, `ConsensusVote`, `ConsensusResult`, `MessageType`, `Message`, `MessageAck`, `MessageBusConfig`, `MessageBusStats`, `CoordinatorConfig`, `CoordinatorState`, `SwarmStatus`, `CoordinatorMetrics`, `SwarmEventType`, `SwarmEvent`, `AgentPoolConfig`, `AgentPoolState`, `HealthCheck`, `PerformanceReport`, `SWARM_CONSTANTS`. All interfaces: `ITopologyManager`, `IConsensusEngine`, `IMessageBus`, `IAgentPool`, `IUnifiedSwarmCoordinator`. All type guards: `isAgentId`, `isTaskId`, `isMessage`. |
| **Leave behind** | `import { EventEmitter } from 'events'`. The `IMessageBus` interface (replaced by ClawdStrike's `TransportAdapter`). |
| **Adapt** | Add ClawdStrike-specific type extensions: `GuardEvaluator` interface, `GuardReceipt` type, `SwarmBoardEvent` union type mapping engine events to board actions. Rename `IUnifiedSwarmCoordinator` to `ISwarmOrchestrator`. Add `AgentRegistration` (the `Omit<AgentState, 'id'>` input type with an optional `guardPolicy` field). Add `TaskSubmission` type with `guardRequired` boolean. |

**Resulting file: `types.ts`**

### 2.9 Browser-safe EventEmitter Replacement

All ruflo modules extend Node.js `EventEmitter`. The swarm-engine replaces this with a minimal typed emitter built on `EventTarget`:

```typescript
// Internal utility, not exported from index.ts
export class TypedEventEmitter<Events extends Record<string, unknown>> {
  private target = new EventTarget();
  private cleanups: Array<() => void> = [];

  on<K extends keyof Events & string>(
    event: K,
    handler: (data: Events[K]) => void,
  ): () => void {
    const listener = (e: Event) => handler((e as CustomEvent).detail);
    this.target.addEventListener(event, listener);
    const unsub = () => this.target.removeEventListener(event, listener);
    this.cleanups.push(unsub);
    return unsub;
  }

  emit<K extends keyof Events & string>(event: K, data: Events[K]): void {
    this.target.dispatchEvent(new CustomEvent(event, { detail: data }));
  }

  /** Remove all listeners. Called by orchestrator.shutdown() to prevent leaks. */
  dispose(): void {
    for (const fn of this.cleanups) fn();
    this.cleanups.length = 0;
  }
}
```

This provides type-safe event subscription with automatic cleanup (returns unsubscribe function) and bulk teardown via `dispose()`. `EventTarget` and `CustomEvent` are available in all browsers and Tauri WebView. Note: `CustomEvent` requires Node 18.7+ for Phase 2 ruflo CLI integration — document this as a minimum Node.js version constraint.

### 2.10 Memory: HNSW + IndexedDB

**Source:** `ruflo/v3/@claude-flow/memory/src/hnsw-lite.ts` and `ruflo/v3/@claude-flow/memory/src/hnsw-index.ts`

| Category | Details |
|----------|---------|
| **Extract from `hnsw-lite.ts`** | The `HnswLite` class: pure-math HNSW with `Float32Array` vectors, `Map<string, Set<string>>` neighbor graph, `add`/`remove`/`search`, cosine similarity, neighbor pruning, brute-force fallback for small datasets. This file has ZERO imports -- it is completely self-contained. |
| **Leave behind from `hnsw-index.ts`** | `import { EventEmitter } from 'node:events'` (explicitly Node.js). The `BinaryMinHeap`/`BinaryMaxHeap` implementations are extractable but `hnsw-lite.ts` already provides a complete standalone HNSW implementation. |
| **Adapt** | `hnsw-lite.ts` needs no adaptation -- it is already browser-safe. Add an `idb-backend.ts` that persists vectors to IndexedDB for session survival. The graph knowledge store uses in-memory `Map` structures with optional IndexedDB serialization. |

**Resulting files: `memory/hnsw.ts`, `memory/graph.ts`, `memory/idb-backend.ts`**

---

## 3. Integration with SwarmBoard

### 3.1 Provider Hierarchy

```
SwarmEngineProvider        (NEW — wraps @clawdstrike/swarm-engine)
  |
  +-- manages SwarmOrchestrator instance lifecycle
  |   - creates on mount, destroys on unmount
  |   - subscribes to engine events, dispatches board actions
  |   - provides engine ref via React context
  |
  └── SwarmBoardProvider   (EXISTING — Zustand store + session context)
        |
        +-- manages PTY session lifecycle (spawn/kill)
        +-- manages board persistence (localStorage + .swarm bundles)
        |
        └── ReactFlowProvider (EXISTING — React Flow canvas)
```

The `SwarmEngineProvider` lives **above** `SwarmBoardProvider` in the component tree. It:

1. Creates a `SwarmOrchestrator` instance on mount with the workbench's config.
2. Subscribes to all engine events and translates them into Zustand store actions.
3. Exposes the orchestrator via `useSwarmEngine()` context hook.
4. Calls `orchestrator.shutdown()` on unmount.

```typescript
// apps/workbench/src/features/swarm/SwarmEngineProvider.tsx

import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { createSwarmOrchestrator, type SwarmOrchestrator } from "@clawdstrike/swarm-engine";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";

// Context value shape matches INTEGRATION-SPEC section 1.
// See TYPE-SYSTEM.md section 7 for event naming conventions.
interface SwarmEngineContextValue {
  engine: SwarmOrchestrator | null;
  isReady: boolean;
  mode: "engine" | "manual" | "error";
  error: string | null;
}

const SwarmEngineContext = createContext<SwarmEngineContextValue>({
  engine: null,
  isReady: false,
  mode: "manual",
  error: null,
});

export function useSwarmEngine(): SwarmEngineContextValue {
  return useContext(SwarmEngineContext);
}

export function SwarmEngineProvider({
  children,
  enabled = true,
}: {
  children: ReactNode;
  enabled?: boolean;
}) {
  const engineRef = useRef<SwarmOrchestrator | null>(null);
  const [state, setState] = useState<SwarmEngineContextValue>({
    engine: null,
    isReady: false,
    mode: enabled ? "manual" : "manual",  // starts manual until init completes
    error: null,
  });

  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;
    const engine = createSwarmOrchestrator({ /* config */ });
    engineRef.current = engine;

    engine.initialize()
      .then(() => {
        if (cancelled) { engine.shutdown(); return; }
        // Subscribe to engine events -- see Section 3.2
        bridgeEngineToBoard(engine);
        setState({ engine, isReady: true, mode: "engine", error: null });
      })
      .catch((err: unknown) => {
        // Graceful degradation: fall back to manual mode
        const message = err instanceof Error ? err.message : String(err);
        console.warn("[SwarmEngineProvider] Init failed, falling back to manual mode:", message);
        setState({ engine: null, isReady: false, mode: "error", error: message });
      });

    return () => {
      cancelled = true;
      // Guard against double-shutdown if init failed
      if (engineRef.current) {
        engineRef.current.shutdown();
        engineRef.current = null;
      }
    };
  }, [enabled]);

  return (
    <SwarmEngineContext.Provider value={state}>
      {children}
    </SwarmEngineContext.Provider>
  );
}
```

### 3.2 Event-to-Action Mapping

The engine emits typed events. The bridge translates each into the existing `SwarmBoardAction` types that the Zustand store already handles (defined in `swarm-board-store.tsx` lines 51-65).

| Engine Event | Board Action(s) | Details |
|---|---|---|
| `agent.spawned` | `ADD_NODE` (agentSession) | Creates a new agentSession node. Position: auto-layout from topology. Data: `{ nodeType: 'agentSession', title: agent.name, status: 'idle', agentModel: agent.type }`. |
| `agent.terminated` | `REMOVE_NODE` | Removes the agent's node and all connected edges. |
| `agent.status_changed` | `UPDATE_NODE` or `SET_SESSION_STATUS` | Maps engine `AgentStatus` to board `SessionStatus`. `'idle'` -> `'idle'`, `'busy'` -> `'running'`, `'error'` -> `'failed'`, `'paused'` -> `'blocked'`. |
| `agent.heartbeat` | `SET_SESSION_METADATA` | Updates `confidence` field based on agent health score. |
| `task.created` | `ADD_NODE` (terminalTask) + `ADD_EDGE` (spawned) | Creates a terminalTask node. If `task.assignedTo` is set, adds a `spawned` edge from agent to task. |
| `task.assigned` | `ADD_EDGE` (spawned) | Adds edge from assigned agent node to task node. |
| `task.started` | `SET_SESSION_STATUS` on task node | Sets task node status to `'running'`. |
| `task.completed` | `UPDATE_NODE` on task + `ADD_NODE` (artifact) + `ADD_EDGE` (artifact) | Sets task status to `'completed'`. If `task.output` contains artifacts, creates artifact nodes linked to the task. |
| `task.failed` | `UPDATE_NODE` | Sets task status to `'failed'`. |
| `guard.evaluate` | `ADD_NODE` (receipt) + `ADD_EDGE` (receipt) | See Section 4. Creates a receipt node with guard results, linked to the action's source node. |
| `topology.updated` | `SET_NODES` + `SET_EDGES` | Full re-layout. Converts `TopologyState` into React Flow positions using force-directed layout. Preserves user-pinned node positions. |
| `topology.rebalanced` | `SET_NODES` + `SET_EDGES` | Same as topology.updated but animated (spring physics). |
| `consensus.resolved` | `ADD_NODE` (note) | Creates a note node documenting the consensus result. |

### 3.3 Engine Event -> SwarmEnvelope Bridge

The `protocol.ts` file bridges the engine's internal event system to ClawdStrike's existing `SwarmEnvelope` protocol. This allows the engine's events to flow through the same `TransportAdapter` that the existing `SwarmCoordinator` uses for intel/detection/signal distribution.

```typescript
// packages/swarm-engine/src/protocol.ts

import type { SwarmOrchestrator, SwarmEvent } from "./types";

/**
 * Maps engine events (past tense, see TYPE-SYSTEM.md section 7.2) to
 * SwarmEnvelope channel types for protocol bridging.
 */
export const EVENT_TO_ENVELOPE_TYPE: Record<string, SwarmEngineChannel | "status"> = {
  "agent.spawned": "agent_lifecycle",
  "agent.terminated": "agent_lifecycle",
  "agent.status_changed": "agent_lifecycle",
  "agent.heartbeat": "agent_lifecycle",
  "task.created": "task_orchestration",
  "task.assigned": "task_orchestration",
  "task.completed": "task_orchestration",
  "task.failed": "task_orchestration",
  "consensus.resolved": "consensus",
  "topology.updated": "topology",
  "topology.rebalanced": "topology",
};

export interface ProtocolBridgeConfig {
  /** A function that publishes a SwarmEnvelope to the transport layer. */
  publish: (type: string, payload: unknown, ttl: number) => Promise<void>;
}

/**
 * Connects a SwarmOrchestrator to ClawdStrike's SwarmEnvelope transport.
 * Returns an unsubscribe function.
 */
export function bridgeToProtocol(
  orchestrator: SwarmOrchestrator,
  config: ProtocolBridgeConfig,
): () => void {
  const unsubscribers: Array<() => void> = [];

  for (const [eventType, envelopeType] of Object.entries(EVENT_TO_ENVELOPE_TYPE)) {
    const unsub = orchestrator.on(eventType as any, (data: unknown) => {
      config.publish(envelopeType, { event: eventType, data }, 5);
    });
    unsubscribers.push(unsub);
  }

  return () => unsubscribers.forEach((fn) => fn());
}
```

### 3.4 Topology -> React Flow Layout

The topology manager maintains a graph of agent connections. When the topology changes, the engine emits a `topology.updated` event with the full `TopologyState`. The bridge converts this to React Flow positions:

```typescript
// Layout algorithm selection based on topology type
function layoutTopology(
  state: TopologyState,
  existingPositions: Map<string, { x: number; y: number }>,
): Map<string, { x: number; y: number }> {
  switch (state.type) {
    case "hierarchical":
      return treeLayout(state);     // Queen at top, workers fanned below
    case "mesh":
      return forceLayout(state);    // Force-directed spring simulation
    case "centralized":
      return radialLayout(state);   // Coordinator at center, workers in ring
    case "hybrid":
      return forceLayout(state);    // Force-directed with weighted edges
  }
}
```

ClawdStrike already has `forceLayout.ts` at `apps/control-console/src/utils/forceLayout.ts`. The swarm-engine package itself does NOT include layout algorithms (to stay DOM-free). The layout mapping lives in the `SwarmEngineProvider` bridge layer inside the workbench app.

---

## 4. Guard Integration Architecture

Every agent action flows through ClawdStrike's guard pipeline. The swarm-engine exposes a `GuardEvaluator` hook that the workbench injects at construction time.

### 4.1 Guard Evaluator Interface

```typescript
// packages/swarm-engine/src/types.ts

/** Result of a single guard check. */
export interface GuardResult {
  guard: string;
  allowed: boolean;
  duration_ms: number;
  reason?: string;
}

/** Signed receipt from the guard pipeline. */
export interface GuardReceipt {
  id: string;
  verdict: "allow" | "deny" | "warn";
  guardResults: GuardResult[];
  signature?: string;
  publicKey?: string;
  timestamp: number;
}

/**
 * Guard evaluator function injected by the host environment.
 * The swarm-engine calls this before executing any guarded action.
 * The host (workbench) implements this by calling the ClawdStrike
 * policy engine (HushEngine / clawdstrike-policy).
 */
export interface GuardEvaluator {
  evaluate(context: GuardEvaluationContext): Promise<GuardReceipt>;
}

export interface GuardEvaluationContext {
  agentId: string;
  taskId: string;
  actionType: string;    // "file_write" | "shell_exec" | "network" | ...
  actionPayload: unknown;
  policyMode: string;    // "strict" | "default" | "permissive"
}
```

### 4.2 Guard Pipeline Flow

```
Agent wants to act
  |
  v
SwarmOrchestrator.executeAction(agentId, action)
  |
  v
guardEvaluator.evaluate({
  agentId, taskId, actionType, actionPayload, policyMode
})
  |
  v
ClawdStrike policy engine runs guards:
  ForbiddenPathGuard, SecretLeakGuard, ShellCommandGuard, ...
  |
  v
GuardReceipt returned { verdict, guardResults[], signature }
  |
  +-- verdict === "allow"
  |     |
  |     v
  |   Action executes
  |   Engine emits "action.completed"
  |   SwarmBoard: UPDATE_NODE on task (progress)
  |
  +-- verdict === "deny"
  |     |
  |     v
  |   Action blocked
  |   Engine emits "action.denied"
  |   Agent status -> "blocked"
  |   SwarmBoard: SET_SESSION_STATUS("blocked")
  |
  +-- verdict === "warn"
        |
        v
      Action executes with warning
      Engine emits "action.warned"
      SwarmBoard: UPDATE_NODE (risk -> "medium" or "high")
  |
  v
In all cases:
  Engine emits "guard.evaluate" with GuardReceipt
  SwarmBoard bridge creates:
    - ADD_NODE (receipt) with { verdict, guardResults, signature, publicKey }
    - ADD_EDGE (receipt) from source agent/task node to receipt node
    - SET_SESSION_METADATA on agent: receiptCount++
    - Brief "evaluating" status pulse (gold glow, 2s)
```

### 4.3 Board Visualization

The guard evaluation produces linked node clusters on the SwarmBoard:

```
  [agentSession: "Fix auth"]
        |
        |  (spawned)
        v
  [terminalTask: "Write auth.rs"]
        |
        |  (receipt)
        v
  [receipt: ALLOW]
    guard: ForbiddenPathGuard  -> allowed
    guard: SecretLeakGuard     -> allowed
    guard: PatchIntegrityGuard -> allowed
    signature: 0xab12...
```

This matches the existing SwarmBoard node types (line 12-18 of `swarm-board-types.ts`) and edge types (line 96 of `swarm-board-types.ts`).

### 4.4 Integration with Existing Bridges

The swarm-engine's guard events integrate with the three existing bridge hooks:

| Existing Hook | Integration |
|---|---|
| `useCoordinatorBoardBridge` (`use-coordinator-board-bridge.ts`) | Extended to also handle `action.completed` events that produce artifacts. Currently handles `intel` and `detection` messages from `SwarmCoordinator`. The engine's task completion events supplement this with orchestration-level artifacts. |
| `useReceiptFlowBridge` (`use-receipt-flow-bridge.ts`) | No change needed. The engine's `guard.evaluate` events are mapped to receipt nodes through the same `SwarmBoardStore.actions.addNode({ nodeType: 'receipt', ... })` path that this hook uses for finding-envelope receipts. The engine bridge and the receipt bridge operate on different event sources but produce the same receipt node type. |
| `usePolicyEvalBoardBridge` (`use-policy-eval-board-bridge.ts`) | Extended to trigger on the engine's `guard.evaluate` events in addition to the existing `SwarmCoordinator.onPolicyEvaluated()` events. Same "evaluating" gold glow behavior (2s pulse). |

---

## 5. Dependencies and Constraints

### 5.1 Zero Node.js APIs

The package must run in:
- Modern browsers (Chrome 100+, Firefox 100+, Safari 16+)
- Tauri WebView (WebKitGTK on Linux, WebView2 on Windows, WKWebView on macOS)

**Banned APIs:**
- `import ... from 'events'` -- use `EventTarget`/`CustomEvent`
- `import ... from 'node:events'` -- same
- `import ... from 'fs'` / `'node:fs'` -- use IndexedDB
- `import ... from 'path'` / `'node:path'` -- string manipulation only
- `process.*` -- use `globalThis`
- `Buffer` -- use `Uint8Array`/`TextEncoder`
- `setImmediate` -- use `queueMicrotask` or `setTimeout(fn, 0)`
- `require()` -- ESM only
- Any npm package with native bindings (better-sqlite3, etc.)

**Allowed browser APIs:**
- `performance.now()` -- high-resolution timing
- `crypto.subtle` -- SHA-256 hashing (for consensus digest verification)
- `crypto.randomUUID()` -- ID generation
- `EventTarget` / `CustomEvent` -- event system
- `setTimeout` / `setInterval` / `clearTimeout` / `clearInterval` -- timers
- `queueMicrotask` -- async scheduling
- `structuredClone` -- deep copy
- `indexedDB` -- persistence (via idb-backend.ts)
- `Float32Array` -- HNSW vectors
- `TextEncoder` / `TextDecoder` -- string encoding
- `Map` / `Set` / `WeakMap` / `WeakRef` -- data structures

### 5.2 IndexedDB Persistence

The `idb-backend.ts` module provides persistence for:

| Data | IndexedDB Store | Key | Value |
|---|---|---|---|
| Agent states | `swarm-agents` | `agentId` | `AgentState` (JSON) |
| Task graph | `swarm-tasks` | `taskId` | `TaskDefinition` (JSON) |
| HNSW vectors | `swarm-vectors` | `vectorId` | `Float32Array` (binary) |
| Knowledge graph | `swarm-graph` | `nodeId` | `{ edges: string[], metadata: object }` |
| Consensus log | `swarm-consensus` | `proposalId` | `ConsensusProposal` (JSON) |

The persistence layer is optional. The orchestrator works entirely in-memory and optionally snapshots to IndexedDB on `pause()`, `shutdown()`, or at a configurable interval.

### 5.3 TransportAdapter Pattern

ClawdStrike's existing `TransportAdapter` interface (from `swarm-coordinator.ts` line 211-224) is the contract for external messaging:

```typescript
export interface TransportAdapter {
  subscribe(topic: string): void;
  unsubscribe(topic: string): void;
  publish(topic: string, envelope: SwarmEnvelope): Promise<void>;
  onMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void;
  offMessage(handler: (topic: string, envelope: SwarmEnvelope) => void): void;
  isConnected(): boolean;
}
```

The swarm-engine does NOT depend on this interface directly. Instead, the `protocol.ts` bridge accepts a `publish` function. The workbench's `SwarmEngineProvider` wires the bridge to the existing `SwarmCoordinator`'s transport.

### 5.4 Guard/Receipt System

ClawdStrike's guard system is defined in Rust (`crates/clawdstrike/`) and exposed via:
- `hush-wasm` (WebAssembly bindings)
- `@clawdstrike/sdk` (TypeScript SDK at `packages/sdk/hush-ts`)
- `clawdstrike-policy` (canonical TS policy engine at `packages/policy`)

The swarm-engine accepts a `GuardEvaluator` interface (Section 4.1) and is agnostic to which implementation backs it. In the workbench, the provider wires in the WASM engine or the TS policy engine.

### 5.5 Tree-Shakeability

- ESM-only (`"type": "module"`)
- `"sideEffects": false` in package.json
- No top-level side effects in any module
- Each module can be imported independently via subpath exports
- Target bundle: **<50KB gzipped** for core orchestration (orchestrator + agent-registry + task-graph + topology)
- Consensus algorithms are tree-shakeable: import only the algorithms you need

### 5.6 Estimated Bundle Sizes

| Module | Estimated gzip | Notes |
|---|---|---|
| `orchestrator.ts` | ~6KB | Extracted from 1,844-line coordinator; composes other modules. Much left behind (Node MessageBus, EventEmitter wiring). |
| `agent-registry.ts` | ~2KB | Maps + event wiring |
| `task-graph.ts` | ~3KB | DAG + Deque + priority queue |
| `topology.ts` | ~4KB | Adjacency lists + BFS + rebalance |
| `agent-pool.ts` | ~2KB | Pool state + auto-scaling |
| `consensus/raft.ts` | ~4KB | 443-line state machine + timers |
| `consensus/byzantine.ts` | ~4KB | 431-line PBFT phases |
| `consensus/gossip.ts` | ~4KB | 513-line fanout + convergence |
| `consensus/index.ts` | ~1KB | Factory |
| `memory/hnsw.ts` | ~3KB | Pure math |
| `memory/graph.ts` | ~1KB | Map-based graph |
| `memory/idb-backend.ts` | ~2KB | IndexedDB wrapper |
| `protocol.ts` | ~1KB | Event-to-envelope mapping |
| `types.ts` | ~0KB | Types-only, erased at build |
| **Total (all modules)** | **~37KB** | Well under 50KB target |
| **Core only** | **~18KB** | orchestrator + registry + task + topology |

---

## 6. Migration Path

### 6.1 Phase 1: Extract (current plan)

Create `@clawdstrike/swarm-engine` as described. The package is self-contained. ClawdStrike's workbench imports it and wires it into the existing SwarmBoard.

Ruflo continues to use its existing `v3/@claude-flow/swarm/src/` code unchanged.

### 6.2 Phase 2: Ruflo CLI Imports Swarm-Engine

After the package is stable, ruflo CLI becomes a thin wrapper:

```
ruflo CLI (Node.js)
  |
  +-- imports @clawdstrike/swarm-engine    (pure orchestration logic)
  +-- imports @claude-flow/cli              (CLI commands, daemon, claude -p spawning)
  +-- adds Node.js adapters:
        - SQLite memory backend (instead of IndexedDB)
        - process.spawn for agent execution (instead of PTY)
        - MCP server delegation
```

**Ruflo keeps:**
- CLI commands (26 commands, 140+ subcommands) -- these are Node.js-specific
- Daemon management (`daemon start/stop/status`) -- uses `child_process`
- `claude -p` spawning -- uses `child_process.spawn`
- MCP server management -- uses stdio transport
- SQLite memory backend (via better-sqlite3) -- Node.js native module
- Hook system (17 hooks, 12 background workers) -- file I/O heavy

**Ruflo loses (replaced by swarm-engine import):**
- `v3/@claude-flow/swarm/src/unified-coordinator.ts` -> `@clawdstrike/swarm-engine` orchestrator
- `v3/@claude-flow/swarm/src/coordination/agent-registry.ts` -> swarm-engine agent-registry
- `v3/@claude-flow/swarm/src/coordination/task-orchestrator.ts` -> swarm-engine task-graph
- `v3/@claude-flow/swarm/src/topology-manager.ts` -> swarm-engine topology
- `v3/@claude-flow/swarm/src/message-bus.ts` -> swarm-engine internal bus
- `v3/@claude-flow/swarm/src/agent-pool.ts` -> swarm-engine agent-pool
- `v3/@claude-flow/swarm/src/consensus/*.ts` -> swarm-engine consensus/*
- `v3/@claude-flow/memory/src/hnsw-lite.ts` -> swarm-engine memory/hnsw

### 6.3 Phase 3: Shared Types Package

Extract `@clawdstrike/swarm-types` as a separate types-only package that both `@clawdstrike/swarm-engine` and ruflo import. This ensures type compatibility when ruflo's CLI and ClawdStrike's workbench interoperate (e.g., ruflo spawns agents that appear on the SwarmBoard via the `TransportAdapter`).

### 6.4 Compatibility Matrix

| Consumer | Runtime | Memory Backend | Transport | Guard Pipeline |
|---|---|---|---|---|
| ClawdStrike Workbench | Browser / Tauri WebView | IndexedDB | InProcessEventBus or Gossipsub | WASM or TS policy engine |
| ClawdStrike Desktop (swarm map) | Tauri WebView | IndexedDB | InProcessEventBus | WASM engine |
| Ruflo CLI | Node.js 20+ | SQLite (via adapter) | stdio / MCP | None (optional) |
| Ruflo MCP Server | Node.js 20+ | SQLite (via adapter) | MCP protocol | None (optional) |
| Unit Tests | Vitest (Node.js) | In-memory (no IDB) | Mock | Mock evaluator |

---

## Appendix A: Key Source File References

### Ruflo (source of extraction)

| File | Lines | Role |
|---|---|---|
| `v3/@claude-flow/swarm/src/unified-coordinator.ts` | 1,844 | Main coordinator (extract to `orchestrator.ts`) |
| `v3/@claude-flow/swarm/src/coordination/agent-registry.ts` | 544 | Agent lifecycle (extract to `agent-registry.ts`) |
| `v3/@claude-flow/swarm/src/coordination/task-orchestrator.ts` | 605 | Task DAG (extract to `task-graph.ts`) |
| `v3/@claude-flow/swarm/src/topology-manager.ts` | 656 | Topology (extract to `topology.ts`) |
| `v3/@claude-flow/swarm/src/message-bus.ts` | 607 | Message bus (Deque/PriorityQueue extracted; bus replaced) |
| `v3/@claude-flow/swarm/src/agent-pool.ts` | 476 | Agent pool (extract to `agent-pool.ts`) |
| `v3/@claude-flow/swarm/src/consensus/index.ts` | 267 | Consensus factory (extract to `consensus/index.ts`) |
| `v3/@claude-flow/swarm/src/consensus/raft.ts` | 443 | Raft (extract to `consensus/raft.ts`) |
| `v3/@claude-flow/swarm/src/consensus/byzantine.ts` | 431 | PBFT (extract to `consensus/byzantine.ts`) |
| `v3/@claude-flow/swarm/src/consensus/gossip.ts` | 513 | Gossip (extract to `consensus/gossip.ts`) |
| `v3/@claude-flow/swarm/src/types.ts` | 545 | Types (extract + extend to `types.ts`) |
| `v3/@claude-flow/memory/src/hnsw-lite.ts` | 190 | HNSW (extract to `memory/hnsw.ts`) |

### ClawdStrike (integration targets)

| File | Role |
|---|---|
| `apps/workbench/src/features/swarm/swarm-board-types.ts` | Board node/edge/state types (6 node types, 4 edge types) |
| `apps/workbench/src/features/swarm/swarm-protocol.ts` | FindingEnvelope, hashing helpers (note: SwarmEnvelope is in `swarm-coordinator.ts`, not here) |
| `apps/workbench/src/features/swarm/swarm-coordinator.ts` | TransportAdapter, SwarmCoordinator, InProcessEventBus, SwarmEnvelope |
| `apps/workbench/src/features/swarm/coordinator-instance.ts` | Singleton coordinator factory |
| `apps/workbench/src/features/swarm/stores/swarm-board-store.tsx` | Zustand board store (SwarmBoardAction, node factory, persistence) |
| `apps/workbench/src/features/swarm/hooks/use-coordinator-board-bridge.ts` | Intel/detection -> board nodes |
| `apps/workbench/src/features/swarm/hooks/use-receipt-flow-bridge.ts` | FindingEnvelope -> receipt nodes |
| `apps/workbench/src/features/swarm/hooks/use-policy-eval-board-bridge.ts` | PolicyEvaluated -> "evaluating" glow |

## Appendix B: Type Mapping Cheatsheet

| Ruflo Type | Swarm-Engine Type | ClawdStrike Board Type |
|---|---|---|
| `AgentState` | `AgentState` | Node with `nodeType: 'agentSession'` |
| `AgentStatus` (`idle`/`busy`/`error`) | `AgentStatus` | `SessionStatus` (`idle`/`running`/`failed`) |
| `TaskDefinition` | `TaskDefinition` | Node with `nodeType: 'terminalTask'` |
| `TaskStatus` | `TaskStatus` | `SessionStatus` on task node |
| `TopologyNode` | `TopologyNode` | Node position + edges in React Flow |
| `TopologyEdge` | `TopologyEdge` | `SwarmBoardEdge` with type `'handoff'` |
| `ConsensusResult` | `ConsensusResult` | Node with `nodeType: 'note'` |
| `Message` | (internal) | `SwarmEnvelope` via protocol bridge |
| -- | `GuardReceipt` | Node with `nodeType: 'receipt'` |
| -- | `GuardResult` | `SwarmBoardNodeData.guardResults[]` |
