# `packages/swarm-engine/` Viability Audit

**Audit date:** 2026-05-23
**Auditor:** wave-3 deep-dive (Claude Opus 4.7 1M)
**Subject:** `packages/swarm-engine/` (`@clawdstrike/swarm-engine`, v0.1.0)
**Source tree examined:** `/Users/connor/Medica/backbay/standalone/clawdstrike/` on branch `fix/macos-es-ne-hardening`
**Prior reference:** `.audit/05-typescript-packages.md` (wave-1, called it "sketchy")

---

## Summary

**What it is.** A 24k-LOC pure-TypeScript package (12,000 LOC source + 12,000 LOC vitest tests, ESM only, zero runtime deps) that implements an in-process multi-agent **orchestration engine** with agent registry, task DAG, topology manager, agent pool, three consensus algorithms (Raft / PBFT / Gossip), an HNSW vector index + IndexedDB-backed shared memory, and a NATS-style topic/protocol bridge. It is a near-verbatim TypeScript port of `ruflo`'s (a sibling repo) `@claude-flow/swarm` Node.js coordinator, rewritten to run in the browser / Tauri WebView with no Node-only APIs.

**Who uses it.** Exactly one consumer in the main tree: `apps/workbench` (the Tauri/web "SwarmBoard" IDE). Linked via `file:../../packages/swarm-engine` in `apps/workbench/package.json`. No other app in the repo (`apps/agent`, `apps/desktop`, `apps/cloud-dashboard`, `apps/control-console`, `apps/academy`, `apps/terminal`) imports it. No Rust crate consumes or interoperates with it. It is **not published to npm** (registry returns 404 for `@clawdstrike/swarm-engine`).

**Status.** Real, functioning code with extensive tests (583 `describe`/`it` blocks across 12 test files). But: no README, no LICENSE, no `description`/`repository`/`author` fields, version stuck at `0.1.0`, and the workbench's integration is gated through a `useOptionalSwarmEngine()` provider that **falls back to "manual mode" on engine init failure** — meaning the workbench works without it. There is also an in-tree security audit (`docs/plans/swarm-engine/SECURITY-AUDIT.md`) authored 2026-03-24 flagging **3 critical + 4 high** unresolved findings, including "guard pipeline bypass — multiple mutable operations skip guard evaluation," which is fatal for a fail-closed security product. Active feature work stopped on 2026-03-28 ("restore fail-closed guard handling"); every subsequent commit touching the package has been Dependabot bumps.

**Verdict (preview, justified below): KEEP, INTERNAL.** Fold it into `apps/workbench` as a private submodule. It is not a library — it is workbench infrastructure that was scaffolded as a package and never earned its independence.

---

## Package Metadata

| Field | Value |
|---|---|
| `name` | `@clawdstrike/swarm-engine` |
| `version` | `0.1.0` |
| `description` | *(absent)* |
| `license` | *(absent — `apps/workbench` itself doesn't carry one either)* |
| `repository` | *(absent)* |
| `author` / `keywords` / `homepage` / `bugs` | *(all absent)* |
| `type` | `module` (ESM only) |
| `sideEffects` | `false` |
| `files` | `["dist"]` |
| `dependencies` | `{}` (zero) |
| `peerDependencies` | `{}` |
| `devDependencies` | `typescript ^5.7`, `vitest ^4.0` |
| `publishConfig` | *(absent — would default to public registry)* |

### Exports

```jsonc
{
  ".":          { "types": "./dist/index.d.ts",                "import": "./dist/index.js" },
  "./consensus":{ "types": "./dist/consensus/index.d.ts",      "import": "./dist/consensus/index.js" },
  "./memory":   { "types": "./dist/memory/shared-memory.d.ts", "import": "./dist/memory/shared-memory.js" }
}
```

### File / LOC inventory

23 TS files in `src/` (12 source + 11 test). LOC totals (production source only):

| File | LOC | Role |
|---|---:|---|
| `src/topology.ts` | 801 | Topology manager (mesh / hierarchical / hybrid) |
| `src/task-graph.ts` | 642 | Task DAG + dependency resolution |
| `src/types.ts` | 638 | Unified type system + `SWARM_ENGINE_CONSTANTS` |
| `src/consensus/gossip.ts` | 598 | Gossip eventual-consistency |
| `src/orchestrator.ts` | 565 | `SwarmOrchestrator` facade |
| `src/consensus/raft.ts` | 533 | Raft leader election + log replication |
| `src/consensus/byzantine.ts` | 512 | PBFT 3-phase consensus |
| `src/agent-registry.ts` | 469 | Agent lifecycle |
| `src/agent-pool.ts` | 390 | Pool + auto-scaling + health checks |
| `src/events.ts` | 366 | `TypedEventEmitter` + event union |
| `src/memory/shared-memory.ts` | 265 | Memory facade (guard-gated writes) |
| `src/memory/hnsw.ts`, `memory/graph.ts`, `memory/idb-backend.ts` | ~600 (combined) | HNSW vector index + KG + IDB persistence |
| `src/protocol.ts`, `collections.ts`, `ids.ts`, `index.ts` | ~700 (combined) | Topic builders, Deque/PQ, ULID, public API |
| **Total source** | **~7,200** | |
| **Total tests** | **~6,700** | 583 `describe`/`it` |
| **Total (incl. lockfile/configs)** | **~24,000** | wave-1's "13,931 LOC" was source-only undercount |

Test:source ratio ≈ 0.93, which is healthy on paper.

---

## Consumer Map

### In-tree imports of `@clawdstrike/swarm-engine` (main checkout only; excludes `.worktrees/` and `.claude/worktrees/`)

| File | Symbols imported |
|---|---|
| `apps/workbench/package.json:83` | `"file:../../packages/swarm-engine"` dep declaration |
| `apps/workbench/src/features/swarm/stores/swarm-engine-provider.tsx:6-26` | `SwarmOrchestrator`, `TypedEventEmitter`, `AgentRegistry`, `TaskGraph`, `TopologyManager`, type `GuardedAction`, type `SwarmEngineEventMap`, type `SwarmOrchestratorConfig` |
| `apps/workbench/src/features/swarm/stores/workbench-guard-evaluator.ts:1-8` | `generateSwarmId`, types `GuardEvaluationResult`, `GuardEvaluator`, `GuardSimResult`, `GuardedAction`, `Receipt` |
| `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts:4` | type `SwarmOrchestrator` |
| `apps/workbench/src/features/swarm/stores/__tests__/swarm-engine-provider.test.tsx:9` | `vi.mock("@clawdstrike/swarm-engine", …)` |
| `apps/workbench/src/features/swarm/stores/__tests__/workbench-guard-evaluator.test.ts:2` | type `GuardedAction` |
| `apps/workbench/src/features/swarm/hooks/__tests__/use-engine-board-bridge.test.ts:3-7` | `TypedEventEmitter`, types `SwarmEngineEventMap`, `SwarmEngineState` |

**Total: 1 app, 2 production modules + 1 type-only hook, ~3 test files.** Every consumer is inside `apps/workbench/src/features/swarm/`.

Indirect users (`useOptionalSwarmEngine` hook, not the package directly):
- `apps/workbench/src/components/workbench/swarm-board/swarm-board-page.tsx` (line 103-104, 779-787)
- `apps/workbench/src/lib/workbench/use-terminal-sessions.ts` (line 21, 52-81) — wraps terminal session spawning

### Build coupling

`apps/workbench/package.json` declares **eleven** `pre*` script hooks that all run `build:swarm-engine`:

```
predev, prebuild, prepreview, pretauri:dev, pretauri:build,
pretest, pretest:e2e, pretest:e2e:headed, pretest:e2e:ui, pretypecheck
```

The workbench cannot do *anything* without first compiling swarm-engine via `npm --prefix ../../packages/swarm-engine run build`. This is not "loose coupling between two libraries"; it is "workbench has a private build dependency on a sibling directory."

### npm publication

```
$ npm view @clawdstrike/swarm-engine
npm error 404 Not Found
```

Not published. The `clawdstrike` scope on npm contains other adapters but not this one.

### Other "swarm" symbols (different concept — do not confuse)

The Rust side has a completely separate "swarm hub" — `crates/services/hushd/tests/swarm_hub.rs` (1,405 LOC), `crates/services/control-api/{models/console.rs,routes/agents.rs,services/policy_distribution.rs}`. Those operate on `clawdstrike.swarm.finding_envelope.v1` / `head_announcement.v1` / `revocation_envelope.v1` schemas — a federation/intel-sharing protocol between hushd nodes. **No code path connects the TS `@clawdstrike/swarm-engine` orchestrator to the Rust swarm hub.** They share a word.

---

## Code Tour

The package's intended shape is described well in its own `docs/plans/swarm-engine/ARCHITECTURE.md` (847 lines, dated 2026-03-24): "Extracted from ruflo v3 `@claude-flow/swarm`, adapted for browser/Tauri WebView. Zero Node.js dependencies. Guard pipeline integration. SwarmBoard-native." The actual code matches the plan closely.

**The facade.** `SwarmOrchestrator` (`src/orchestrator.ts`, 565 LOC) composes five subsystems — `AgentRegistry`, `TaskGraph`, `TopologyManager`, `AgentPool`, and a `TypedEventEmitter<SwarmEngineEventMap>` — under one lifecycle (`initialize` → `running` → `pause`/`resume` → `shutdown` → `dispose`). It exposes `evaluateGuard(action: GuardedAction): Promise<GuardEvaluationResult>` which delegates to an injected `GuardEvaluator` (deny-by-default if absent), records the result, emits `guard.evaluated` + either `action.denied` or `action.completed`, and signs a `Receipt`. `getState()` returns a `structuredClone`'d snapshot; `getMetrics()` is computed on-demand. A `heartbeatTimer` runs at `heartbeatIntervalMs` to update agent liveness.

**The subsystems.** `AgentRegistry` (469 LOC) tracks `AgentSession` records keyed by ID, runs background health checks, and emits lifecycle events. `TaskGraph` (642 LOC) is a topologically-sorted DAG with dependency resolution, assignment, completion, and failure paths. `TopologyManager` (801 LOC) maintains the mesh/hierarchical/hybrid graph of agent nodes and handles role promotion, partition assignment, rebalancing, and adaptive thresholds. `AgentPool` (390 LOC) implements auto-scaling with cooldowns. `consensus/` ships three full algorithm implementations (Raft 533 LOC, PBFT 512 LOC, Gossip 598 LOC) behind a `ConsensusEngine` factory. `memory/` provides a pure-math HNSW vector index, an in-memory `KnowledgeGraph`, and an `IndexedDB` persistence backend, all coordinated by `SharedMemory` which gates `store()` writes through the same `GuardEvaluator` (but, per the in-tree security audit, **not** `delete()`).

**The protocol bridge.** `src/protocol.ts` defines a `/baychat/v1/swarm/{swarmId}/{channel}` topic scheme and an `EVENT_TO_CHANNEL` map that routes 20+ engine events to nine channels (`intel`, `signals`, `detections`, `coordination`, `agents`, `tasks`, `topology`, `consensus`, `memory`, `hooks`). The `ProtocolBridge` class converts internal events to `SwarmEngineEnvelope` records for downstream transport. Yet nothing in the package — or in the workbench consumer — actually wires this bridge to a transport. There is no NATS client, no libp2p stack, no WebSocket transport, no `TauriIpcTransport` implementation in the package. The bridge dead-ends.

**What's missing from a working orchestrator.** The agents the orchestrator manages are records, not processes. There is no executor: nothing in the package calls `claude -p`, no `child_process.spawn`, no Tauri command invocation, no WebWorker. Agent "lifecycle" means "object in a Map." The workbench provider `swarm-engine-provider.tsx` wires `spawnEngineSession`/`spawnEngineClaudeSession`/`spawnEngineWorktreeSession` callbacks that *accept* a real `spawnFn` from the caller (`use-terminal-sessions.ts`), evaluate a guard via `workbenchGuardEvaluator`, and only then run the caller's actual spawn function. So the engine is functioning as a **guard-evaluation + bookkeeping layer** wrapped around the workbench's own session machinery. Without the workbench, the package has no executor.

---

## Documentation Search

| Source | swarm-engine mentions |
|---|---|
| `packages/swarm-engine/README.md` | **Does not exist.** |
| `packages/swarm-engine/CHANGELOG.md` | Does not exist. |
| `packages/swarm-engine/LICENSE` | Does not exist. |
| Inline JSDoc | Present at the file-header level (`/** Facade composing all swarm engine subsystems… */`) on every source file. Most public methods have `/** … */` blocks. Quality is uneven — many are one-liners. |
| `docs/book/` (the mdBook) | Zero mentions. The published documentation does not acknowledge this package. |
| `docs/src/` | Zero mentions. |
| `docs/README.md`, `docs/REPO_MAP.md`, `docs/DOCS_MAP.md`, `docs/HANDOFF.md` | Zero mentions. |
| `docs/plans/swarm-engine/` | **5 plan docs, 4,699 LOC total**, all dated 2026-03-24: `ARCHITECTURE.md` (847), `TYPE-SYSTEM.md` (1,526), `PROTOCOL-SPEC.md` (1,386), `INTEGRATION-SPEC.md` (406), `SECURITY-AUDIT.md` (534). These are *plans*, not user docs. |
| Root `README.md` | Zero mentions. |
| `.audit/05-typescript-packages.md` (wave-1) | One paragraph, classified "sketchy — no README, no description, no license, `0.1.0`." |

So: extensive *internal* planning docs from one week in March, no *external* (user-facing or package-distributed) documentation.

---

## Git Activity

**Timeline.**
- **First commit:** `352e12a17 feat(01-01): scaffold @clawdstrike/swarm-engine package with unified type system` (2026-03-24, ~17:00 UTC).
- **Build-out:** 47 commits between 2026-03-24 and 2026-03-28, all tagged with phase numbers (`feat(01-02)…`, `feat(04-03)…`, `feat(07-01)…`). The commit prefixes correspond directly to the phases in `INTEGRATION-SPEC.md`.
- **Cleanup tail:** 5 commits 2026-03-25 → 2026-03-28 with messages like `fix(swarm-engine): resolve PR review comments`, `fix(swarm-engine): harden bridge and runtime edges`, `fix(swarm-engine): enforce guarded spawns and mirror pool state`, `refactor: remove 2,769 lines of AI-generated comment slop`, and the final substantive one — `3dfac24b6 fix(swarm): restore fail-closed guard handling` on 2026-03-28.
- **Since then:** 8 commits in `packages/swarm-engine/`, **all Dependabot** ("chore(deps): bump the npm_and_yarn group across 19 directories…"). Most recent: 2026-05-18.

**Pattern.** The package was scaffolded, integrated, code-reviewed, and shipped to the `feat(workbench)` branch in a single 5-day burst (2026-03-24 → 2026-03-28). Nothing has happened since except security/dep bumps. The "phases" in the integration spec are listed through Phase 7; the codebase reached Phase 7-01 (the `getEvents()` accessor commit) but Phase 4 ("consensus integration") and Phase 5 ("protocol bridge transport") are visibly incomplete — `activeProposals: {}, // Phase 4` and `messagesPerSecond: 0, // Populated by protocol bridge in Phase 5` are TODOs still in production code at `orchestrator.ts:228,265`.

**Hot files (by recent commit churn):** orchestrator, agent-registry, topology, consensus/* — but only Dependabot has touched them in seven weeks.

---

## Overlap Analysis

| Capability swarm-engine provides | Other repo location | Overlap? |
|---|---|---|
| Agent registry / lifecycle | Workbench's `swarm-board-store.tsx` (Zustand) already tracks "session" nodes with status. Engine mirrors these into its own Map and back via the bridge. | **Yes — bidirectional mirroring.** `useEngineBoardBridge` exists specifically to reconcile two parallel sources of truth. The `agentRegistry`, `taskGraph`, `topology` fields in `SwarmEngineContextValue` are already marked `@deprecated` in favor of `engine.getState()` (see `swarm-engine-provider.tsx:38-43`) — a smell that the abstraction is wrong. |
| Task DAG / orchestration | Workbench's `swarm-board-store.tsx` has its own `terminalTask` node type. `apps/workbench/src/lib/workbench/use-terminal-sessions.ts` is the real session orchestrator. | **Partial overlap.** Engine provides a richer DAG; workbench has the actual execution. |
| Consensus (Raft/PBFT/Gossip) | Nothing in the rest of the repo uses or needs distributed consensus. The Rust "swarm hub" uses Ed25519-signed finding envelopes and a different model (`head_announcement.v1`). The workbench has a single in-process orchestrator instance — there is no quorum to reach. | **Pure dead weight in current usage.** 1,643 LOC of Raft/PBFT/Gossip for a single-process React app. |
| HNSW vector memory | The workbench does not call `SharedMemory` anywhere. `packages/sdk/hush-ts` has its own crypto/memory primitives. | **Unused.** The 600 LOC of memory/* and the IndexedDB backend are imported by nothing outside their own tests. |
| Protocol bridge / topics | Workbench has its own `swarm-coordinator.ts` with `SwarmEnvelope`, `TransportAdapter`, `InProcessEventBus` (see `ARCHITECTURE.md` Appendix A). Rust hushd serves the actual federation protocol with different envelope schemas. | **Yes — competing envelope formats.** Engine's `swarmIntelTopic("/baychat/v1/swarm/{id}/intel")` is not wired to anything the Rust side serves. |
| Guard evaluation | This is the *only* capability that actively earns its keep: `workbenchGuardEvaluator` (in workbench) bridges `GuardedAction` → workbench's `simulatePolicy` → `GuardEvaluationResult`. The orchestrator runs the policy simulator before each spawn. | **No overlap, but tiny.** The wrapper is ~140 LOC and could live in workbench directly without the engine package. |

**Net.** Of the seven major subsystems, **one** (guard-gated spawn) is exercised end-to-end. The other six (consensus, HNSW memory, protocol bridge, pool auto-scaling, topology rebalancing, task DAG) are unused, mocked, or duplicated by workbench's existing infrastructure.

---

## Verdict

# **KEEP, INTERNAL.**

**Receipts:**

1. **Only one consumer.** `apps/workbench` is the sole user. The 11 `pre*` build hooks tying workbench's build to swarm-engine's build prove this is treated as a private build artifact already.

2. **Not published, not advertised.** `npm view` returns 404. The mdBook documentation does not mention it. The root README does not mention it. No external user has ever installed it.

3. **Workbench works without it.** `useOptionalSwarmEngine()` and the `mode: "manual" | "engine" | "error"` machinery exist *specifically* to let the workbench operate when the engine fails to initialize (`swarm-engine-provider.tsx:235-240` logs "Engine init failed, falling back to manual mode"). The engine is enhancement, not infrastructure.

4. **Six of seven subsystems are dead weight in the current usage.** Consensus (1,643 LOC + 762 LOC of tests), HNSW memory (~600 LOC + 478 LOC of tests), protocol bridge transport, pool auto-scaling at scale, topology rebalancing, and task DAG are all unreferenced by `apps/workbench`. Only the guard-gated spawn path is exercised — and it could be implemented in ~200 LOC inside the workbench.

5. **Unresolved CRITICAL security findings.** `docs/plans/swarm-engine/SECURITY-AUDIT.md` (in-tree, authored 2026-03-24) lists **3 CRITICAL + 4 HIGH** unresolved findings, including "Guard Pipeline Bypass — Multiple Mutable Operations Skip Guard Evaluation" — fatal for a security product. The last substantive commit (`3dfac24b6 fix(swarm): restore fail-closed guard handling`) was an attempt at one of these; the rest are still open. Shipping this to npm as `@clawdstrike/swarm-engine` would publish known critical security defects under a security-product brand. That alone disqualifies **KEEP, PUBLISH**.

6. **Phase 4 + Phase 5 are TODOs in production code.** `orchestrator.ts:228` (`activeProposals: {}, // Phase 4`) and `orchestrator.ts:265` (`messagesPerSecond: 0, // Populated by protocol bridge in Phase 5`). The package's own integration spec ships Phase 4 + Phase 5 as required for the documented behavior.

7. **Active development stopped seven weeks ago.** Every commit since 2026-03-28 has been Dependabot. The phase-numbered burst (`feat(01-01)` through `feat(07-01)`) ran for five days, hit the workbench integration, then stopped. The author moved on.

8. **The deprecation markers are already in place.** `SwarmEngineContextValue.agentRegistry`, `.taskGraph`, `.topology` are all `@deprecated` in favor of `engine.getState()` (`swarm-engine-provider.tsx:38-43`). The author was already in the middle of collapsing the abstraction before they stopped working on it.

**Why not WIPE.** The guard-gated spawn pipeline + `TypedEventEmitter` + `GuardedAction` type contract are genuinely useful for the workbench's SwarmBoard. Deleting outright loses real (if narrow) value and would break workbench's session spawning flow.

**Why not PARK.** It is not a paused design exploration — it is checked-in production code that the workbench currently depends on at runtime. Parking the directory orphans the workbench.

**Why not KEEP, PUBLISH.** See receipts 5 and 6. Also: missing README/LICENSE/description/repository/keywords/publishConfig; v0.1.0 with no semver story; depends on workbench-specific contracts (`SwarmBoardNodeData`, `SpawnSessionOptions`) that are not actually portable. The wave-1 audit reached the same conclusion ("wipe the convenience packages") for the same reasons.

---

## If KEEP, INTERNAL: Migration plan

The goal: collapse `packages/swarm-engine/` into `apps/workbench/src/features/swarm/engine/`, drop the consensus / memory / protocol-transport subsystems that nothing uses, and remove the 11-script build coupling.

### Phase 1 — Decide the scope cut (1 day)

Audit which engine symbols are *actually imported* by the workbench. Current set (verified from `grep`):

```
SwarmOrchestrator, AgentRegistry, TaskGraph, TopologyManager, AgentPool,
TypedEventEmitter, generateSwarmId,
GuardedAction, GuardEvaluator, GuardEvaluationResult, GuardSimResult, Receipt,
SwarmEngineEventMap, SwarmEngineState, SwarmOrchestratorConfig
```

The following are imported by **nobody** in the main tree:
- All of `src/consensus/` (Raft, PBFT, Gossip, factory) — 1,643 LOC
- All of `src/memory/` (HNSW, KG, IDB, SharedMemory) — ~865 LOC
- `ProtocolBridge`, all topic builders, `EVENT_TO_CHANNEL`, `parseSwarmTopic`, `getSwarmTopics` from `src/protocol.ts` — ~150 LOC
- `Deque`, `PriorityQueue` from `src/collections.ts` — 209 LOC

Decision: keep `orchestrator + registry + task-graph + topology + agent-pool + events + types + ids` (the "core 8"). Drop the rest along with their ~3,500 LOC of tests.

### Phase 2 — Move the core into workbench (1 day)

```
mv packages/swarm-engine/src/{orchestrator,agent-registry,agent-pool,task-graph,topology,events,types,ids,index}.ts \
   apps/workbench/src/features/swarm/engine/
mv packages/swarm-engine/src/{orchestrator,agent-registry,agent-pool,task-graph,topology,events,types,guard-types,collections}.test.ts \
   apps/workbench/src/features/swarm/engine/__tests__/
```

Rewrite imports in the moved files (`./events.js` → `./events.ts` once the bundler isn't enforcing the `.js` extension). Drop the `verbatimModuleSyntax` requirement — workbench's tsconfig is more lenient.

### Phase 3 — Rewire workbench (0.5 days)

In every file that does `from "@clawdstrike/swarm-engine"`, change to `from "@/features/swarm/engine"`:

```
apps/workbench/src/features/swarm/stores/swarm-engine-provider.tsx
apps/workbench/src/features/swarm/stores/workbench-guard-evaluator.ts
apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts
apps/workbench/src/features/swarm/hooks/__tests__/use-engine-board-bridge.test.ts
apps/workbench/src/features/swarm/stores/__tests__/swarm-engine-provider.test.tsx
apps/workbench/src/features/swarm/stores/__tests__/workbench-guard-evaluator.test.ts
```

Remove the `vi.mock("@clawdstrike/swarm-engine", …)` and replace with `vi.mock("@/features/swarm/engine", …)`.

### Phase 4 — Strip the build coupling (0.25 days)

`apps/workbench/package.json`:
- Remove the dep: `"@clawdstrike/swarm-engine": "file:../../packages/swarm-engine"`.
- Delete all 11 `pre*` hooks that run `build:swarm-engine`.
- Delete the `build:swarm-engine` script itself.

Root `package.json`:
- Remove `"packages/swarm-engine"` from `workspaces`.

### Phase 5 — Delete the package (0.1 days)

```
rm -rf packages/swarm-engine
```

Verify no `.worktrees/` or `.claude/worktrees/` are tracked by main branch (they shouldn't be — they're untracked dirs).

### Phase 6 — Address the open SECURITY-AUDIT.md findings (separate work item, NOT pre-req)

The 3 critical / 4 high findings predate this move and remain regardless. File as a follow-up:
- **C-01:** Make `AgentRegistry`, `TaskGraph`, `TopologyManager`, `Consensus*`, `SharedMemory` subsystems package-private (no longer possible after collapse — instead make them only constructible via the orchestrator facade).
- **C-02:** Remove the no-evaluator code path entirely once this is workbench-internal; the workbench always provides `workbenchGuardEvaluator`.
- **C-03:** Reject `topology.updateNode` calls that change `role`.

### Total estimated effort: ~3 engineer-days for the move; security hardening separate.

### Downstream impact

- **Workbench:** No user-visible change. Build becomes simpler (one tsc invocation instead of two).
- **Other apps:** None — they don't import it.
- **Rust crates:** None — they don't reference it.
- **External users:** None — package isn't published.
- **Documentation:** Move `docs/plans/swarm-engine/` to `docs/plans/decisions/archive/swarm-engine-2026-03-port/` to preserve the design history without implying it's a current project.

### Commit sequence

```
1. chore(swarm-engine): drop unused consensus/memory/protocol subsystems
2. refactor(workbench): move swarm-engine source into features/swarm/engine
3. refactor(workbench): rewire imports from @clawdstrike/swarm-engine to relative paths
4. chore(workbench): drop swarm-engine build coupling and root workspace entry
5. chore(repo): delete packages/swarm-engine
6. docs: archive swarm-engine plans under docs/plans/decisions/archive
```

Each step is independently reviewable. Steps 1-3 leave the package in a working dual-tree state; step 4-5 cut the package over atomically.

---

## Appendix: Evidence summary

- **Source LOC:** `packages/swarm-engine/src/*.ts` (production) = ~7,200; tests = ~6,700.
- **Wave-1 reference:** `.audit/05-typescript-packages.md:16` ("wipe the convenience packages (`@clawdstrike/swarm-engine`, …)").
- **Plan docs (in-tree):** `docs/plans/swarm-engine/{ARCHITECTURE,INTEGRATION-SPEC,PROTOCOL-SPEC,TYPE-SYSTEM,SECURITY-AUDIT}.md`, dated 2026-03-24, 4,699 LOC total.
- **Last substantive commit:** `3dfac24b6 fix(swarm): restore fail-closed guard handling` on 2026-03-28; all 8 subsequent commits are Dependabot.
- **Sole consumer:** `apps/workbench` (declared in `apps/workbench/package.json:83`, 6 source files import it).
- **Tauri/desktop, agent, control-console, academy, cloud-dashboard, terminal apps:** none import it.
- **Rust crates:** none import it; the "swarm" naming collision is with hushd's federation hub (`crates/services/hushd/tests/swarm_hub.rs`), a different concept on different schemas.
- **npm registry:** 404 for `@clawdstrike/swarm-engine` as of 2026-05-23.
- **TODOs in production code:** `orchestrator.ts:228` (Phase 4), `orchestrator.ts:265` (Phase 5).
- **Author-marked deprecations on the public consumer surface:** `swarm-engine-provider.tsx:38-43` (`agentRegistry`, `taskGraph`, `topology` all `@deprecated`).
