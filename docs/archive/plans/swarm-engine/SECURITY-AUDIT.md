# Security Audit: @clawdstrike/swarm-engine

**Date:** 2026-03-24
**Auditor:** Claude Opus 4.6 (automated static analysis)
**Scope:** packages/swarm-engine/src/*, apps/workbench/src/features/swarm/
**Version:** 0.1.0 (pre-release)

---

## Executive Summary

The swarm-engine package implements a browser-based AI agent orchestration system with a guard pipeline intended to gate every mutable action. The architecture is fundamentally sound: the `evaluateGuard()` flow is fail-closed by default, events are frozen before dispatch, and ULIDs use `crypto.getRandomValues` when available. However, the audit identified **3 critical**, **4 high**, **6 medium**, **5 low**, and **4 informational** findings across the nine focus areas.

The most severe issues relate to (1) guard pipeline bypass paths where mutable operations occur without guard evaluation, (2) unrestricted topology role promotion allowing privilege escalation, and (3) absence of rate limiting enabling denial-of-service via event flooding.

---

## Findings

### CRITICAL

#### C-01: Guard Pipeline Bypass -- Multiple Mutable Operations Skip Guard Evaluation
**CWE-284** (Improper Access Control)
**Files:** `agent-registry.ts`, `task-graph.ts`, `topology.ts`, `consensus/`
**Severity:** Critical

The PROTOCOL-SPEC.md (section 4.4) defines a guard classification where mutable actions like `agent.spawn`, `task.assign`, `topology.node_join`, `topology.role_change`, and `consensus.propose` must pass through the guard pipeline. However, the implementation provides **no enforcement** at these boundaries:

- `AgentRegistry.spawn()` (line 158) creates a full agent session and emits `agent.spawned` with no guard check. The guard evaluation only occurs in the workbench's `spawnEngineSession` wrapper, which is an optional convenience function -- direct callers of the registry bypass it entirely.
- `TaskGraph.assignTask()` (line 288) assigns tasks to agents without guard evaluation.
- `TaskGraph.completeTask()` (line 339) writes output data without guard evaluation.
- `TopologyManager.addNode()` (line 110) adds topology nodes without guard evaluation.
- `TopologyManager.updateNode()` (line 226) changes roles without guard evaluation (see C-03).
- All three consensus implementations (`RaftConsensus.propose()`, `ByzantineConsensus.propose()`, `GossipConsensus.propose()`) create proposals and commit state changes without guard evaluation.
- `SharedMemory.delete()` (line 257) removes entries without guard evaluation, even though `store()` is guarded.

**Impact:** Any code with a reference to the registry, task graph, topology, or consensus engine can perform mutable operations that the guard pipeline was designed to prevent. The guard pipeline is only invoked through `SwarmOrchestrator.evaluateGuard()`, which is a voluntary call -- not an interceptor.

**Remediation:**
1. Wrap all mutable subsystem methods (spawn, terminate, assignTask, addNode, updateNode, propose) with mandatory guard evaluation at the subsystem level.
2. Alternatively, make subsystem classes package-private and expose only guarded operations through the orchestrator facade.
3. At minimum, add a `requireGuardReceipt` parameter to mutable methods that throws if no receipt is provided.

---

#### C-02: SharedMemory Guard Bypass When No Evaluator Configured
**CWE-862** (Missing Authorization)
**File:** `memory/shared-memory.ts` lines 98-116
**Severity:** Critical

The `store()` method only invokes the guard evaluator when `this.guardEvaluator` is defined (line 98). When no evaluator is configured, writes proceed unconditionally. This contradicts the fail-closed design stated in the orchestrator comment (line 8): "If absent, all guarded actions are denied (fail-closed)."

```typescript
// shared-memory.ts line 98
if (this.guardEvaluator) {
  // ... evaluate
} else {
  // PROCEEDS WITHOUT CHECK -- should deny
}
```

Compare with `orchestrator.ts` line 234 which correctly denies when no evaluator exists.

**Impact:** Any SharedMemory instance created without a guard evaluator allows unrestricted writes, defeating the purpose of guard-gated memory. This is especially dangerous since memory writes can contain arbitrary `unknown` values.

**Remediation:** Change the fallback to deny when no evaluator is present, matching the orchestrator pattern:
```typescript
if (!this.guardEvaluator) {
  return false; // fail-closed
}
```

---

#### C-03: Privilege Escalation via Unrestricted Topology Role Changes
**CWE-269** (Improper Privilege Management)
**File:** `topology.ts` lines 226-241
**Severity:** Critical

`TopologyManager.updateNode()` accepts arbitrary `Partial<TopologyNode>` updates including `role`. Any caller can promote a worker node to `queen` or `coordinator` without:
1. Guard pipeline evaluation
2. Authorization check on the caller
3. Validation that the promotion is legitimate

```typescript
updateNode(agentId: string, updates: Partial<TopologyNode>): void {
  // ...
  if (updates.role !== undefined) node.role = updates.role;  // line 232
```

Additionally, the `addToRoleIndex` helper (line 808) automatically caches the node as `this.queenNode` or `this.coordinatorNode` if the role is set to `queen`/`coordinator`. However, `updateNode` does not call `addToRoleIndex`, so while the role field is mutated, the cached queen/coordinator references may become stale -- creating an inconsistent security state where two nodes may both believe they are queen.

The PROTOCOL-SPEC explicitly lists `topology.role_change` as requiring guard evaluation (section 4.4 table). This is not enforced.

**Impact:** A compromised or malicious agent can escalate its privileges to queen/coordinator, gaining preferential treatment in leader election, task routing, and topology decisions.

**Remediation:**
1. Remove `role` from the accepted updates in `updateNode()`, or gate it behind guard evaluation.
2. If role changes are allowed, update the role index and cached queen/coordinator references atomically.
3. Add a `changeRole()` method that requires a guard receipt.

---

### HIGH

#### H-01: No Rate Limiting on Heartbeats, Events, or Consensus Votes
**CWE-770** (Allocation of Resources Without Limits or Throttling)
**Files:** `agent-registry.ts`, `consensus/*.ts`, `events.ts`
**Severity:** High

There are no rate limits on:
- **Heartbeats**: `AgentRegistry.heartbeat()` can be called at arbitrary frequency. Each call emits an `agent.heartbeat` event that propagates through the protocol bridge to all subscribers.
- **Consensus votes**: `RaftConsensus.vote()`, `ByzantineConsensus.vote()`, and `GossipConsensus.vote()` accept votes from any `voterId` parameter. While vote deduplication exists (Map keyed by voterId), a caller can submit votes with different fabricated voterIds.
- **Event emission**: `TypedEventEmitter.emit()` has no throttle. A busy agent can flood the EventTarget with thousands of events per second.
- **Memory writes**: No per-agent or per-namespace quota on `SharedMemory.store()`.
- **Gossip queue**: `GossipConsensus.messageQueue` has no size limit (only processes 10 per round, but accepts unlimited queuing).

**Impact:** A single malfunctioning or malicious agent can saturate the event bus, fill consensus vote maps, exhaust the gossip message queue, or overwhelm IndexedDB with writes, causing performance degradation or browser tab crashes.

**Remediation:**
1. Add per-agent heartbeat throttling (e.g., minimum 1-second interval between heartbeat calls).
2. Cap the gossip message queue at `MAX_QUEUE_SIZE` (10,000).
3. Add per-namespace memory write quotas.
4. Consider a global event rate limiter in `TypedEventEmitter.emit()`.

---

#### H-02: Consensus Vote Spoofing via Arbitrary voterId Parameter
**CWE-290** (Authentication Bypass by Spoofing)
**Files:** `consensus/raft.ts` line 188, `consensus/byzantine.ts` line 237, `consensus/gossip.ts` line 227
**Severity:** High

All three consensus implementations accept an optional `voterId` parameter in `vote()`:

```typescript
vote(proposalId: string, approve: boolean, confidence?: number, voterId?: string): void {
  const vote: ConsensusVote = {
    voterId: voterId ?? this.node.id,  // caller can impersonate any node
```

There is no validation that the caller is authorized to vote on behalf of `voterId`. The deduplication key is `voterId`, so a single caller can cast votes impersonating every node in the cluster, achieving arbitrary consensus outcomes.

The `ConsensusEngine.vote()` facade (index.ts line 169) passes through to the implementation without adding any authentication.

**Impact:** A single malicious agent can unilaterally accept or reject any consensus proposal by submitting votes with fabricated voter IDs equal to every peer in the cluster.

**Remediation:**
1. Remove the `voterId` parameter from the public `vote()` API. Each node should only be able to vote as itself.
2. If cross-node voting is needed (e.g., relaying votes in gossip), validate the vote against a signed message from the claimed voter.

---

#### H-03: No Envelope Signature Verification
**CWE-347** (Improper Verification of Cryptographic Signature)
**Files:** `types.ts` (EnvelopeReceipt), `orchestrator.ts`, `protocol.ts`
**Severity:** High

`EnvelopeReceipt` declares `signature` and `publicKey` fields (types.ts lines 1211-1213), and the Receipt type includes Ed25519 signature fields. However, there is **no verification** anywhere in the codebase:

- `orchestrator.ts` `createDenyReceipt()` (line 465) sets `signature: ""` and `publicKey: ""` -- empty strings.
- `envelopeReceiptFromReceipt()` (line 483) copies the signature and publicKey from the receipt but never verifies them.
- `ProtocolBridge.connect()` (protocol.ts line 167) wraps events into envelopes and publishes them without any signature generation or verification.
- No incoming envelope validation exists -- `parseSwarmTopic()` only validates the topic string format, not the payload or its signature.

The `Receipt.valid` field (types.ts line 55) is a boolean that is always set to the value provided by the guard evaluator, but the engine never independently validates it.

**Impact:** Any participant can forge envelopes with fabricated receipts, claimed verdicts, or spoofed sourceAgentIds. The receipt audit trail provides no cryptographic integrity guarantee.

**Remediation:**
1. Implement Ed25519 signature generation on envelope creation (in the ProtocolBridge).
2. Implement signature verification on envelope receipt (incoming path).
3. Reject envelopes with invalid or missing signatures.
4. Generate actual key pairs during engine initialization (leverage the existing `hush-core` crate via WASM or the TypeScript SDK).

---

#### H-04: Denied Envelopes Leak Full Action Payload
**CWE-209** (Generation of Error Message Containing Sensitive Information)
**Files:** `orchestrator.ts` lines 269-299, `events.ts` (GuardEvaluatedEvent, ActionDeniedEvent)
**Severity:** High

When `evaluateGuard()` denies an action, three events are emitted that include the **full** `GuardedAction` object:

1. `guard.evaluated` (line 269): Contains the complete `action` and `result` including all guard details.
2. `action.denied` (line 278): Contains the complete `action` object.
3. The `GuardedActionRecord` stored in `recentGuardActions` (line 257) retains the full action and evaluation.

The `GuardedAction.context` field is `Record<string, unknown>`, which may contain sensitive information (file contents, API keys in command strings, credentials in network targets). This data is:
- Broadcast to all event listeners
- Published via ProtocolBridge to transport topics
- Stored in the state snapshot accessible via `getState()`
- Rendered in the workbench bridge hook (use-engine-board-bridge.ts)

**Impact:** Sensitive data from denied operations is exposed through event channels, state snapshots, and UI rendering, potentially to agents and UI components that should not see it.

**Remediation:**
1. Redact `action.context` and `action.target` in denied event payloads -- emit only the action type and agent ID.
2. Store full details only in the local receipt ledger, not in broadcast events.
3. Add a `DenyNotification` envelope (already specified in PROTOCOL-SPEC section 4.5) that contains only the receipt ID and verdict, not the full action.

---

### MEDIUM

#### M-01: No Input Validation on Agent IDs, Task IDs, or Namespace Strings
**CWE-20** (Improper Input Validation)
**Files:** `agent-registry.ts`, `task-graph.ts`, `memory/shared-memory.ts`, `topology.ts`
**Severity:** Medium

While the `generateSwarmId()` function produces well-formed `{prefix}_{ulid}` IDs, the subsystems accept arbitrary strings as IDs from external callers:

- `AgentRegistry.heartbeat(agentId: string)` -- no validation that agentId matches `agt_*` format.
- `TaskGraph.addDependency(taskId, dependsOn)` -- no format validation.
- `TopologyManager.addNode(agentId, role)` -- no format validation.
- `SharedMemory.store(namespace, key, value)` -- no validation on namespace or key. A namespace containing `/` or `..` could cause path confusion in the `memory://{namespace}/{key}` target string passed to the guard evaluator.
- `ConsensusEngine.vote(proposalId, ...)` -- no validation that proposalId exists or matches `csn_*` format.

The type guards (`isAgentSession`, `isTask`) validate ID prefixes but are only used by callers for runtime checks -- the subsystems do not invoke them.

**Impact:** Malformed IDs could cause unexpected Map key collisions, confuse audit trails, or exploit guard rules that match on target patterns (e.g., a namespace of `../../etc/passwd` in the memory target string).

**Remediation:**
1. Add ID format validation at subsystem entry points using regex: `/^(agt|tsk|swe|top|csn|msg)_[0-9A-Z]{26}$/`.
2. Validate namespace and key strings against an allowlist pattern (e.g., `[a-zA-Z0-9._-]+`).

---

#### M-02: Race Conditions in Async Guard Evaluation
**CWE-362** (Concurrent Execution Using Shared Resource with Improper Synchronization)
**Files:** `orchestrator.ts` lines 230-302, `memory/shared-memory.ts` lines 91-153
**Severity:** Medium

`evaluateGuard()` and `SharedMemory.store()` are `async` methods, but the underlying state (sessions, tasks, topology) is mutated synchronously without any locking or optimistic concurrency control:

1. Two concurrent `evaluateGuard()` calls for the same agent could both pass the check, then both execute, even if the guard pipeline intended to allow only one.
2. `SharedMemory.store()` performs TOCTOU: the guard evaluates the action at time T1, but the actual write happens at time T2. Between T1 and T2, another write could have changed the state that the guard evaluated against.
3. The `recentGuardActions` array (orchestrator.ts line 263) is mutated without synchronization. Concurrent pushes could interleave.

In a single-threaded JavaScript runtime this is partially mitigated because the synchronous portions are not interrupted. However, the `await this.config.guardEvaluator.evaluate(action)` at line 245 yields the event loop, creating a window for concurrent mutations.

**Impact:** Time-of-check-to-time-of-use (TOCTOU) vulnerabilities where the guard decision is made against stale state.

**Remediation:**
1. Implement per-agent or per-resource mutex for guarded operations (e.g., using a simple promise-based lock).
2. Attach a monotonic sequence number to guard evaluations and reject stale evaluations.

---

#### M-03: Unbounded Growth in Consensus Data Structures
**CWE-400** (Uncontrolled Resource Consumption)
**Files:** `consensus/raft.ts`, `consensus/byzantine.ts`, `consensus/gossip.ts`
**Severity:** Medium

Several consensus data structures grow without bounds:

- `RaftConsensus.proposals` (Map): Never cleaned up after resolution. Resolved proposals remain forever.
- `ByzantineConsensus.messageLog` (Map): Accumulates all prepare/commit messages. Never pruned.
- `GossipConsensus.node.seenMessages` (Set): Every seen message ID is retained permanently for dedup. In a long-running system this grows linearly with messages.
- `RaftConsensus.node.log` (Array): Raft log entries are never compacted.
- `ByzantineConsensus.node.preparedMessages` and `committedMessages`: Never cleaned.

**Impact:** In a long-running engine, these structures cause monotonically increasing memory consumption, eventually crashing the browser tab.

**Remediation:**
1. Implement TTL-based eviction for resolved proposals.
2. Compact the Raft log after commit.
3. Use a bounded LRU set for `seenMessages` (e.g., max 10,000 entries).
4. Prune Byzantine message logs after commit phase completes.

---

#### M-04: Object.freeze Only Shallow-Freezes Event Payloads
**CWE-471** (Modification of Assumed-Immutable Data)
**File:** `events.ts` line 82
**Severity:** Medium

The TypedEventEmitter calls `Object.freeze(data)` before dispatch. However, `Object.freeze()` is shallow -- it only freezes the top-level properties. Nested objects (such as `AgentSession.capabilities`, `AgentSession.metrics`, `Task.input`, `GuardedAction.context`) remain mutable.

```typescript
emit<K extends keyof Events & string>(event: K, data: Events[K]): void {
  const frozen = Object.freeze(data);  // Shallow freeze only
  this.target.dispatchEvent(new CustomEvent(event, { detail: frozen }));
}
```

For example, a listener receiving an `agent.spawned` event can mutate `event.agent.metrics.tasksCompleted` because `metrics` is a nested object that is not frozen.

**Impact:** Cross-listener mutation of nested event data can cause subtle bugs and security-relevant state corruption (e.g., one listener inflating another agent's success rate).

**Remediation:**
1. Implement deep freeze (recursive `Object.freeze` on all nested objects).
2. Alternatively, use `structuredClone()` to create a defensive copy for each listener.

---

#### M-05: Workbench Provider Exposes Raw Engine References
**CWE-668** (Exposure of Resource to Wrong Sphere)
**File:** `apps/workbench/src/features/swarm/stores/swarm-engine-provider.tsx` lines 179-188
**Severity:** Medium

The `SwarmEngineProvider` exposes raw references to `AgentRegistry`, `TaskGraph`, and `TopologyManager` through the context hooks:

```typescript
setContextValue({
  engine: orchestrator,
  agentRegistry: registry,     // Direct reference
  taskGraph,                   // Direct reference
  topology: topologyMgr,       // Direct reference
  // ...
});
```

Any React component that calls `useAgentRegistry()` gets the raw registry object and can call `spawn()`, `terminate()`, `updateStatus()`, or any other method without guard evaluation. This undermines the guard pipeline that the orchestrator is supposed to enforce.

**Impact:** UI components or third-party code with access to the React context can bypass all guard controls.

**Remediation:**
1. Expose only read-only query methods through the context (e.g., `getState()`, `getAgentSession()`).
2. All mutations should go through the orchestrator's guarded interface.
3. Consider wrapping subsystems in Proxy objects that intercept mutable methods.

---

#### M-06: Transport Layer Has No Replay Protection
**CWE-294** (Authentication Bypass by Capture-replay)
**Files:** `protocol.ts`, `types.ts` (SwarmEngineEnvelope)
**Severity:** Medium

`SwarmEngineEnvelope` has a `created` timestamp and `ttl` hop counter, but:

1. **TTL is hop-based, not time-based**: The `ttl` field (types.ts line 480) counts Gossipsub hops, not elapsed time. An envelope from 24 hours ago with `ttl: 5` can still be forwarded.
2. **No nonce or sequence number**: There is no mechanism to detect replayed envelopes. A captured envelope can be re-injected indefinitely.
3. **No seen-message dedup at the protocol layer**: While GossipConsensus has `seenMessages`, the ProtocolBridge has no dedup mechanism. Every envelope received is processed.
4. **No envelope expiration**: The `created` timestamp is present but never checked against a maximum age.

**Impact:** A malicious peer can capture and replay envelopes to re-trigger actions, duplicate votes, or cause state confusion.

**Remediation:**
1. Add a time-based TTL (e.g., envelopes expire after 60 seconds).
2. Add a unique envelope ID and maintain a seen-envelope set at the protocol bridge level.
3. Reject envelopes with `created` timestamps more than `MAX_ENVELOPE_AGE_MS` in the past.

---

### LOW

#### L-01: ULID Math.random Fallback Weakens ID Unpredictability
**CWE-330** (Use of Insufficiently Random Values)
**File:** `ids.ts` lines 60-63
**Severity:** Low

When `crypto.getRandomValues` is unavailable, the ULID generator falls back to `Math.random()`:

```typescript
} else {
  for (let i = 0; i < 16; i++) {
    chars[i] = CROCKFORD_BASE32[Math.floor(Math.random() * 32)]!;
  }
}
```

`Math.random()` is not cryptographically secure. In environments without Web Crypto API, generated IDs become predictable.

**Impact:** Low in practice since all modern browsers provide `crypto.getRandomValues`. However, in edge cases (older WebViews, certain Node.js test environments), IDs could be predicted, enabling targeted attacks on specific agent/task/proposal IDs.

**Remediation:** Throw an error if `crypto.getRandomValues` is unavailable, rather than silently degrading.

---

#### L-02: Topology Rebalance Uses Math.random for Node Selection
**CWE-330** (Use of Insufficiently Random Values)
**File:** `topology.ts` lines 688, 779
**Severity:** Low

The mesh rebalance function uses `Math.random() - 0.5` for shuffling (line 688), and hybrid rebalance uses `Math.floor(Math.random() * candidates.length)` for coordinator selection (line 779). These are not cryptographically secure.

**Impact:** A sophisticated attacker could predict rebalance outcomes and position agents favorably. Low severity since topology is an internal optimization concern.

**Remediation:** Use `crypto.getRandomValues` for topology randomization if deterministic-resistance matters.

---

#### L-03: Error Messages Leak Internal State
**CWE-209** (Generation of Error Message Containing Sensitive Information)
**Files:** `agent-registry.ts`, `task-graph.ts`, `topology.ts`
**Severity:** Low

Error messages include internal IDs and state:

- `"Cannot terminate agent ${agentId} with active task ${session.currentTaskId}"` -- leaks task ID.
- `"Agent ${agentId} current task is ${session.currentTaskId}, not ${taskId}"` -- leaks current task assignment.
- `"Task ${taskId} is not queued (status: ${task.status})"` -- leaks task status.
- `"Cannot initialize from status \"${this.status}\""` -- leaks engine status.

**Impact:** In a multi-tenant or adversarial context, error messages could reveal information about other agents' task assignments and states.

**Remediation:** Use generic error codes instead of interpolating internal state into error messages returned to callers.

---

#### L-04: AgentSession.filesTouched Array Is Unbounded
**CWE-770** (Allocation of Resources Without Limits or Throttling)
**File:** `types.ts` line 365
**Severity:** Low

`AgentSession.filesTouched: string[]` has no maximum length. A long-running agent that touches many files accumulates an ever-growing array that is included in every `getState()` snapshot and `agent.spawned`/`agent.heartbeat` event payload.

**Impact:** Memory bloat in long-running sessions; large state snapshots slow down serialization and transport.

**Remediation:** Implement a max size (e.g., 1000) with FIFO eviction, or track only a count and recent window.

---

#### L-05: Workbench Bridge Hook Uses `any` Types Extensively
**CWE-704** (Incorrect Type Conversion or Cast)
**File:** `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts`
**Severity:** Low

Every event handler in the bridge hook casts event data as `any`:

```typescript
events.on("agent.spawned", (event: any) => {
events.on("agent.status_changed", (event: any) => {
events.on("guard.evaluated", (event: any) => {
```

This bypasses TypeScript's type safety and means any property access (e.g., `event.result?.receipt?.signature`) will not be caught at compile time if the event shape changes.

**Impact:** Runtime type errors in production; missed refactoring when event shapes evolve.

**Remediation:** Use the properly typed event interfaces from the swarm-engine package instead of `any`.

---

### INFORMATIONAL

#### I-01: guardExempt Classification Exists in Spec But Not in Code
**File:** `docs/plans/swarm-engine/PROTOCOL-SPEC.md` section 4.4
**Severity:** Informational

The PROTOCOL-SPEC defines a `guardExempt` flag on certain payload types (heartbeat, progress, search_result, vote, status_change). This flag is documented but not implemented anywhere in the TypeScript code. The actual guard exemption is implicit -- these operations simply never call `evaluateGuard()`.

**Recommendation:** Either implement the `guardExempt` flag as a runtime property on payload schemas (enabling runtime verification that guard-exempt operations are truly read-only), or document the current implicit approach as intentional.

---

#### I-02: Byzantine Consensus Uses Non-Cryptographic Digest
**File:** `consensus/byzantine.ts` lines 506-516
**Severity:** Informational

The `computeDigest()` function uses a simple hash-code algorithm (Java-style `hashCode`):

```typescript
private computeDigest(value: Record<string, unknown>): string {
  const str = JSON.stringify(value);
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}
```

This is a 32-bit non-cryptographic hash with trivial collision potential. In a real PBFT deployment, digest collisions would allow an equivocating primary to propose different values with the same digest.

**Recommendation:** Since the consensus implementations are labeled as in-process simulations, this is informational. If consensus is ever used for real distributed coordination, replace with SHA-256 via Web Crypto API.

---

#### I-03: Gossip Auto-Vote Defeats Purpose of Consensus
**File:** `consensus/gossip.ts` lines 510-513
**Severity:** Informational

When a gossip node receives a proposal message, it automatically votes to approve:

```typescript
if (node.id === this.node.id) {
  this.vote(proposalId, true, 0.9);
}
```

This means every reachable node will auto-approve every proposal, making the gossip consensus a rubber-stamp mechanism rather than an actual decision gate.

**Recommendation:** Document this as intentional for the current simulation phase, or implement actual decision logic.

---

#### I-04: KnowledgeGraph Entity Properties Use Record<string, unknown>
**File:** `memory/graph.ts`
**Severity:** Informational

Entity and Relation `properties` fields are `Record<string, unknown>`. When these objects are round-tripped through `JSON.parse(JSON.stringify(...))`, any non-JSON-serializable values (functions, Symbols, BigInts) will be silently dropped. The `query()` method uses strict equality (`!==`) for property matching, which means `NaN !== NaN` would fail to match.

**Recommendation:** Document the serialization constraints. Consider validating that property values are JSON-safe on write.

---

## Summary Table

| ID | Severity | Category | CWE | Title |
|----|----------|----------|-----|-------|
| C-01 | Critical | Guard Pipeline Bypass | CWE-284 | Multiple mutable operations skip guard evaluation |
| C-02 | Critical | Guard Pipeline Bypass | CWE-862 | SharedMemory allows writes without evaluator (should fail-closed) |
| C-03 | Critical | Privilege Escalation | CWE-269 | Unrestricted topology role changes via updateNode() |
| H-01 | High | Denial of Service | CWE-770 | No rate limiting on heartbeats, events, votes, or memory writes |
| H-02 | High | Consensus Integrity | CWE-290 | Arbitrary voterId parameter enables vote spoofing |
| H-03 | High | Cryptographic | CWE-347 | No envelope signature verification implemented |
| H-04 | High | Information Leakage | CWE-209 | Denied envelopes broadcast full action payload including context |
| M-01 | Medium | Input Validation | CWE-20 | No format validation on IDs, namespaces, or keys |
| M-02 | Medium | State Corruption | CWE-362 | TOCTOU race in async guard evaluation |
| M-03 | Medium | Denial of Service | CWE-400 | Unbounded growth in consensus data structures |
| M-04 | Medium | State Corruption | CWE-471 | Object.freeze only shallow-freezes event payloads |
| M-05 | Medium | Privilege Escalation | CWE-668 | Provider exposes raw subsystem references |
| M-06 | Medium | Transport Security | CWE-294 | No replay protection on envelopes |
| L-01 | Low | Cryptographic | CWE-330 | Math.random fallback for ULID generation |
| L-02 | Low | Cryptographic | CWE-330 | Math.random used in topology rebalance |
| L-03 | Low | Information Leakage | CWE-209 | Error messages leak internal state |
| L-04 | Low | Denial of Service | CWE-770 | AgentSession.filesTouched array unbounded |
| L-05 | Low | Code Quality | CWE-704 | Bridge hook uses `any` types throughout |
| I-01 | Info | Design Gap | -- | guardExempt flag specified but not implemented |
| I-02 | Info | Cryptographic | -- | Byzantine consensus uses non-cryptographic digest |
| I-03 | Info | Consensus | -- | Gossip auto-vote defeats consensus purpose |
| I-04 | Info | Data Integrity | -- | KnowledgeGraph properties lack serialization validation |

---

## Recommended Priority

1. **Immediate (before any production use):** C-01, C-02, C-03, H-02
2. **Before networked/multi-tenant deployment:** H-01, H-03, H-04, M-06
3. **Before GA release:** M-01 through M-05, L-01 through L-05
4. **Track for future phases:** I-01 through I-04
