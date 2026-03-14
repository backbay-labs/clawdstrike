# Signal Pipeline — Technical Design

> Detailed architecture for the signal-to-finding-to-intel pipeline that forms the
> backbone of the Sentinel Swarm data flow.

**Status:** Design
**Date:** 2026-03-12
**Parent:** [INDEX.md](./INDEX.md) -- sections 3, 4, and 7

---

## Table of Contents

1. [Signal Ingestion](#1-signal-ingestion)
2. [Signal Scoring](#2-signal-scoring)
3. [Signal Correlation](#3-signal-correlation)
4. [Finding Lifecycle](#4-finding-lifecycle)
5. [Enrichment Pipeline](#5-enrichment-pipeline)
6. [Intel Promotion](#6-intel-promotion)
7. [Feedback Loop](#7-feedback-loop)
8. [Performance Budget](#8-performance-budget)
9. [Client vs. Server Split](#9-client-vs-server-split)

---

## 1. Signal Ingestion

Signals originate from four distinct source families. Each source emits raw
events in its own schema; the ingestion layer normalizes them into the canonical
`Signal` type before any downstream processing.

### 1.1 Source Families

| Source Family | Origin | Current Precursor | Volume Profile |
|---------------|--------|-------------------|----------------|
| **Guard results** | `HushEngine` guard pipeline (BuiltIn -> Custom -> Extra -> Async) | `GuardSimResult` in `hunt-types.ts`; `GuardResult` in `clawdstrike/src/guards/mod.rs` | 1 per tool invocation -- proportional to agent activity |
| **Anomaly detector** | Workbench client-side scoring | `scoreAnomaly()` and `enrichEvents()` in `hunt-engine.ts`; `Baseline.scoreDetailed()` in `anomaly.ts` | 1 per enriched event above anomaly threshold |
| **External feeds** | IOC databases (STIX 2.1, CSV, plain-text), Sigma rules, YARA | `IocDatabase` in `correlate/ioc.ts` and `ioc.rs`; `compile_rule_source()` in `detection.rs` | Batch on load; match events produce signals continuously |
| **Swarm intel** | Gossipsub topics `/baychat/v1/swarm/{id}/signals` and `/baychat/v1/swarm/{id}/intel` | Not yet implemented; Speakeasy `MessageEnvelope` is the transport primitive | Burst on peer discovery; steady-state proportional to swarm size |

### 1.2 Normalization

Every source must produce a `Signal` (defined in INDEX.md section 3). The
normalization step maps source-specific fields into the canonical shape.

**Guard result -> Signal:**

```
auditEventToAgentEvent()          // hunt-engine.ts L50-77 — existing conversion
  |
  v
guardResultToSignal(event, guardResult) -> Signal
  type       = "detection" | "policy_violation"  // deny -> policy_violation; warn -> detection
  source     = { guardId: guardResult.guardId, provenance: "guard_evaluation" }
  severity   = deriveSeverity(guardResult, event)  // see section 2
  confidence = 1.0 for deny, 0.7 for warn         // guard pipeline is authoritative
  context    = { agentId: event.agentId, sessionId: event.sessionId }
```

**Anomaly score -> Signal:**

```
scoreAnomaly(event, baseline)     // hunt-engine.ts L115-180 — existing
  |
  v
anomalyToSignal(event, anomalyResult) -> Signal
  type       = "anomaly" | "behavioral"
  source     = { sentinelId, provenance: "anomaly_detection" }
  severity   = anomalyResult.score > 0.9 ? "high" : anomalyResult.score > 0.7 ? "medium" : "low"
  confidence = anomalyResult.score        // direct mapping -- anomaly score IS confidence
  data       = { factors: anomalyResult.factors, baselineId }
```

**IOC match -> Signal:**

```
IocDatabase.matchEvent(event)     // correlate/ioc.ts L386-442 — existing
  |
  v
iocMatchToSignal(iocMatch) -> Signal
  type       = "indicator"
  source     = { externalFeed: iocMatch.matchedIocs[0].source, provenance: "external_feed" }
  severity   = iocTypeSeverity(iocMatch)  // sha256 match -> high; domain -> medium; IP -> medium
  confidence = 0.8                        // IOC feeds carry uncertainty from staleness
  data       = { matchedIocs, matchField }
```

**Swarm intel -> Signal:**

```
MessageEnvelope (type: "message", payload.type: "intel_share") from Gossipsub
  |
  v
swarmIntelToSignal(envelope) -> Signal
  type       = "detection" | "indicator"  // inherited from the Intel artifact type
  source     = { externalFeed: "swarm:" + swarmId, provenance: "swarm_intel" }
  severity   = envelope.payload.severity
  confidence = envelope.payload.confidence * peerReputation  // attenuated by trust
  data       = { intelId, authorFingerprint, signature }
```

### 1.3 Deduplication

Signals are deduplicated before entering the scoring pipeline to prevent double-
counting when multiple source families observe the same underlying event.

**Deduplication key:** `SHA-256(signal.type + signal.context.agentId + signal.context.sessionId + signal.timestamp_truncated_to_1s + signal.data_hash)`

**Window:** 5 seconds (same underlying event reported by multiple guards or
arriving via both local detection and swarm intel).

**Implementation:** A `SignalDeduplicator` maintains a `Set<string>` of recent
signal hashes, evicting entries older than the dedup window. This mirrors the
existing `deduplicateAlerts()` function in `playbook.ts` (L191-202) but operates
on signal-level granularity.

```typescript
class SignalDeduplicator {
  private seen: Map<string, number> = new Map();  // hash -> timestamp_ms
  private windowMs = 5_000;

  isDuplicate(signal: Signal): boolean {
    const hash = computeSignalHash(signal);
    const now = Date.now();
    // Evict stale entries
    for (const [k, ts] of this.seen) {
      if (now - ts > this.windowMs) this.seen.delete(k);
    }
    if (this.seen.has(hash)) return true;
    this.seen.set(hash, now);
    return false;
  }
}
```

---

## 2. Signal Scoring

### 2.1 Confidence Scoring Algorithm

The confidence score represents the probability that the signal indicates a real
threat. It builds on the existing multi-factor anomaly scoring in `scoreAnomaly()`
(`hunt-engine.ts` L115-180) in the workbench and `Baseline.scoreDetailed()`
(`packages/sdk/clawdstrike-hunt/src/anomaly.ts` L57-88) in the hunt SDK.
Note: these are parallel implementations — the workbench operates on
`AgentEvent` + `AgentBaseline` while the SDK operates on `TimelineEvent`.
The signal pipeline generalizes across all signal sources.

**Composite confidence formula:**

```
confidence_final = clamp(0, 1,
    w_source   * confidence_source   +   // inherent source reliability
    w_anomaly  * anomaly_score       +   // deviation from baseline
    w_pattern  * pattern_match_score +   // Spider-Sense or n-gram match
    w_corr     * correlation_boost   +   // co-occurrence with other signals
    w_rep      * reputation_factor       // swarm peer reputation (swarm signals only)
)
```

**Default weights:**

| Factor | Weight | Rationale |
|--------|--------|-----------|
| `w_source` | 0.35 | Guard verdicts are authoritative (confidence=1.0 for deny) |
| `w_anomaly` | 0.25 | Continuous behavioral baseline from `computeBaseline()` (`hunt-engine.ts` L213-289) |
| `w_pattern` | 0.20 | Spider-Sense cosine similarity (`SpiderSenseDetector::screen()` in `spider_sense.rs` L270-310) |
| `w_corr` | 0.15 | Correlation boost when 2+ signals share time window or agent |
| `w_rep` | 0.05 | Peer reputation attenuation for swarm-sourced signals |

These weights sum to 1.0. The `correlation_boost` factor is computed
retroactively: when a new signal clusters with existing signals (section 3),
confidence is recalculated for all signals in the cluster.

### 2.2 Severity Derivation

Severity is a discrete classification derived from confidence and impact:

```typescript
function deriveSeverity(confidence: number, impact: SignalImpact): Severity {
  // Impact categories: "data_access", "code_execution", "network_egress",
  //   "privilege_escalation", "persistence", "credential_access"
  const impactMultiplier = IMPACT_WEIGHTS[impact] ?? 1.0;
  const adjustedScore = confidence * impactMultiplier;

  if (adjustedScore >= 0.9) return "critical";
  if (adjustedScore >= 0.7) return "high";
  if (adjustedScore >= 0.4) return "medium";
  if (adjustedScore >= 0.2) return "low";
  return "info";
}
```

This aligns with the existing `Severity` type in `hunt-types.ts` (L99):
`"critical" | "high" | "medium" | "low" | "info"`, and with `RuleSeverity` in
the Rust `hunt-correlate` crate (`rules.rs` L113-120).

### 2.3 False-Positive Suppression

Suppression operates at three levels:

1. **Hash-based suppression:** `SentinelMemory.falsePositiveHashes` stores SHA-256
   hashes of previously dismissed signals. Before scoring, the pipeline checks
   the FP set and drops matches with zero cost.

2. **Baseline adaptation:** When an analyst marks a Finding as `false_positive`,
   the contributing signal patterns are folded back into `AgentBaseline` via
   `computeBaseline()` so that future occurrences score lower.

3. **Pattern exclusion:** Confirmed FP patterns generate negative pattern
   entries in the sentinel's `SentinelMemory.knownPatterns` (`MemoryPattern[]`) with a
   `suppress: true` flag, preventing them from contributing to `w_pattern`.

---

## 3. Signal Correlation

Correlation groups individual signals into clusters that together represent a
coherent threat narrative. The pipeline uses four correlation strategies in
parallel, then merges results.

### 3.1 Correlation Strategies

#### 3.1.1 Time-Window Correlation

Mirrors the sliding-window state machine in `CorrelationEngine` (both the Rust
implementation in `hunt-correlate/src/engine.rs` and the TS mirror in
`correlate/engine.ts`).

- **Window size:** Configurable per sentinel; default 5 minutes.
- **Mechanism:** Signals from the same agent or session arriving within the
  window are grouped into a candidate cluster.
- **Implementation:** Reuses the existing `WindowState` tracking from
  `CorrelationEngine`, but with `Signal` as the event type rather than
  `TimelineEvent`.

```typescript
// Adapter: convert Signal to the TimelineEvent shape expected by CorrelationEngine
function signalToTimelineEvent(signal: Signal): TimelineEvent {
  return {
    timestamp: new Date(signal.timestamp),
    source: signal.source.guardId ?? signal.source.externalFeed ?? "sentinel",
    kind: TimelineEventKind.GuardDecision,
    verdict: signalTypeToVerdict(signal),
    summary: signal.data.summary ?? signal.id,
    actionType: signal.data.actionType,
    // ...remaining fields mapped from signal.context
  };
}
```

#### 3.1.2 Agent-Affinity Correlation

Signals from the same `agentId` or `sessionId` receive a correlation bonus even
outside the time window, because agent compromise typically manifests as a
sequence of events across multiple sessions.

- **Affinity score:** `0.3` for same agent different session; `0.6` for same
  session.
- **Decay:** Affinity decays linearly over 24 hours: `affinity * max(0, 1 - elapsed_hours / 24)`.
- **Builds on:** `detectAnomalyClusters()` in `hunt-engine.ts` (L554-580) which
  already groups anomalous events by `agentId:sessionId`.

#### 3.1.3 Pattern-Match Correlation

Signals that match the same `HuntPattern` sequence are automatically clustered.

- **Existing:** `matchPatternInSession()` (`hunt-engine.ts` L362-398) checks if
  session events match a known `PatternStep[]` sequence.
- **Extension:** When a signal matches step N of a pattern, the correlation
  engine searches open clusters for signals matching steps 1..N-1 in the same
  session.
- **N-gram discovery:** `discoverPatterns()` (`hunt-engine.ts` L404-490)
  periodically mines new sequences. Discovered patterns with `matchCount >= 3`
  create new correlation templates.

#### 3.1.4 MITRE Technique Grouping

Signals that map to the same MITRE ATT&CK technique or tactic chain are
correlated.

- **Existing:** `mapEventToMitre()` in `mitre.ts` (L45-65) provides the
  technique mapping. `coverageMatrix()` (L90-105) groups by tactic.
- **Extension:** When two signals map to techniques in the same kill-chain
  progression (e.g., T1003.008 credential-access followed by T1021.004
  lateral-movement), they receive a `0.4` correlation boost.

### 3.2 Cluster Merging

When a signal matches multiple strategies, the resulting clusters are merged:

```
Strategy outputs:  [cluster_A, cluster_B, cluster_C, cluster_D]
                        |           |
                        └── overlap on signal S3
                              |
                        merged → cluster_AB

Final clusters:    [cluster_AB, cluster_C, cluster_D]
```

**Merge rule:** Two clusters merge if they share at least one signal ID. The
merged cluster inherits the union of all signal IDs and the maximum confidence
of any constituent signal.

### 3.3 Integration with Existing CorrelationEngine

The new `SignalCorrelator` wraps rather than replaces the existing
`CorrelationEngine`. The flow:

```
Signal[] ──adapt──> TimelineEvent[] ──feed──> CorrelationEngine.processEvent()
                                                    │
                                              Alert[] (from rules)
                                                    │
                                    ┌───────────────┤
                                    ▼               ▼
                              rule-based      heuristic-based
                              clusters        clusters (time, affinity, pattern, MITRE)
                                    │               │
                                    └───────┬───────┘
                                            ▼
                                    merged clusters
                                            │
                                            ▼
                                    Finding candidates
```

The rule-based path reuses `CorrelationRule` YAML (schema
`clawdstrike.hunt.correlation.v1`) as-is. The heuristic path adds the four
strategies above. Both paths output clusters that flow into the Finding Engine.

---

## 4. Finding Lifecycle

### 4.1 State Machine

```
             ┌──────────────────────────────────┐
             │                                  │
   ┌─────────▼────────┐    confirm    ┌────────┴────────┐
   │     emerging      │─────────────>│    confirmed     │
   └─────┬───────┬─────┘              └──────┬───────┬───┘
         │       │                           │       │
    dismiss   auto-expire              promote   dismiss
         │       │                           │       │
         ▼       ▼                           ▼       ▼
   ┌─────────┐ ┌───────────┐         ┌──────────┐ ┌──────────────┐
   │dismissed│ │  archived  │         │ promoted │ │false_positive│
   └─────────┘ └───────────┘         └──────────┘ └──────────────┘
                                           │
                                           │ Intel artifact created
                                           ▼
                                     (Intel pipeline)
```

**States:**

| State | Entry Condition | Exit Conditions |
|-------|----------------|-----------------|
| `emerging` | First signal cluster exceeds minimum threshold (>= 2 signals, confidence > 0.3) | Confirm, dismiss, auto-expire (TTL) |
| `confirmed` | Human analyst or sentinel curator confirms the finding | Promote, dismiss as FP |
| `promoted` | Finding is packaged as an Intel artifact (section 6) | Terminal (immutable) |
| `dismissed` | Human or sentinel rejects the finding | Terminal; signals remain for pattern analysis |
| `false_positive` | Finding is confirmed as FP | Terminal; triggers FP suppression feedback (section 7) |
| `archived` | Emerging finding's TTL expires without confirmation | Terminal; retained for historical analysis |

### 4.2 Auto-Promotion Rules

Findings can advance without human intervention when conditions are met. These
rules are configurable per sentinel via `SentinelGoal.escalation`.

```typescript
interface AutoPromotionRules {
  // emerging -> confirmed
  autoConfirmThresholds: {
    minSignals: number;        // default: 5
    minConfidence: number;     // default: 0.8
    minSeverity: Severity;     // default: "high"
    requireMitreMapping: boolean; // default: true
  };

  // confirmed -> promoted
  autoPromoteThresholds: {
    minConfidence: number;     // default: 0.9
    minSeverity: Severity;     // default: "critical"
    requireCorroboration: boolean; // default: true -- needs 2+ independent sources
  };
}
```

**Corroboration requirement:** A finding is "corroborated" when its constituent
signals originate from at least two distinct source families (e.g., guard result
+ IOC match, or anomaly + swarm intel). Single-source findings require human
confirmation before promotion.

### 4.3 Human-in-the-Loop Gates

Certain transitions always require human approval:

1. **Promotion of `high`/`critical` findings to swarm intel** -- because
   shared intel affects peer sentinels' detection behavior.
2. **FP dismissal of findings with `critical` severity** -- because false
   negatives at this level are unacceptable.
3. **Any finding attached to a Speakeasy room** -- because it may contain
   sensitive context from the coordination session.

These gates surface in the approval queue (existing `/approvals` route),
extended with a new `approval_type: "finding_promotion"` category.

### 4.4 Relationship to Existing Investigation Type

The `Finding` type evolves from the existing `Investigation` in `hunt-types.ts`
(L101-122). Migration path:

| Investigation field | Finding field | Change |
|--------------------|---------------|--------|
| `id` | `id` | No change |
| `title` | `title` | No change |
| `status: InvestigationStatus` | `status: FindingStatus` | Values change: `open` -> `emerging`, `in-progress` -> `confirmed`, `resolved` -> `promoted` |
| `severity` | `severity` | No change (same `Severity` type) |
| `eventIds[]` | `signalIds[]` | Renamed; points to Signal IDs instead of AgentEvent IDs |
| `agentIds[], sessionIds[]` | Derived from `signals[].context` | No longer stored directly; computed from signal contexts |
| `annotations[]` | `annotations[]` | No change (same `Annotation` type) |
| `verdict?` | `verdict?` | Renamed type from `InvestigationVerdict` to `FindingVerdict` |
| `actions?` | `actions` | Extended with `"intel_promoted"` action type; uses snake_case convention |
| -- | `signalCount` | New: count of contributing signals |
| -- | `confidence` | New: aggregate confidence |
| -- | `enrichment[]` | New: MITRE mapping, IOC data, Spider-Sense results |
| -- | `promotedToIntel?` | New: reference to Intel artifact if promoted |
| -- | `receipt?` | New: `SignedReceipt` for provenance attestation |

---

## 5. Enrichment Pipeline

Enrichment runs on every Finding at creation and again on each state transition.
Each enrichment stage is idempotent and appends to `Finding.enrichments[]`.

### 5.1 MITRE ATT&CK Mapping

**Existing code:** `mapEventToMitre()` in `mitre.ts` matches event summaries
against 24 regex-to-technique mappings. `mapAlertToMitre()` deduplicates across
alert evidence.

**Extension for Findings:**

```typescript
function enrichFindingWithMitre(finding: Finding, signals: Signal[]): Enrichment {
  const techniques: MitreTechnique[] = [];
  const seen = new Set<string>();

  for (const signal of signals) {
    // Convert signal to TimelineEvent for MITRE matching
    const event = signalToTimelineEvent(signal);
    for (const tech of mapEventToMitre(event)) {
      if (!seen.has(tech.id)) {
        seen.add(tech.id);
        techniques.push(tech);
      }
    }
  }

  // Build kill-chain progression
  const tactics = new Set(techniques.map(t => t.tactic));
  const killChainDepth = tactics.size;

  return {
    type: "mitre_attack",
    data: { techniques, killChainDepth, tactics: [...tactics] },
    addedAt: Date.now(),
    source: "enrichment_pipeline",
  };
}
```

The existing `coverageMatrix()` function is reused to produce the tactic-grouped
view for the Findings UI.

### 5.2 IOC Extraction

Scans signal payloads for indicators of compromise using the existing `IocDatabase`
matching infrastructure.

**Existing code:** `IocDatabase.matchEvent()` (`correlate/ioc.ts` L386-442) and
the Rust `match_event()` in `hunt-correlate/src/ioc.rs`.

**Extension:** The enrichment stage also runs `detectIocType()` on all string
fields in `signal.data` to discover embedded indicators that were not part of an
IOC feed match:

```typescript
function extractIocs(signal: Signal): IocEntry[] {
  const extracted: IocEntry[] = [];
  walkStringFields(signal.data, (value) => {
    const iocType = detectIocType(value);  // correlate/ioc.ts L12-43
    if (iocType) {
      extracted.push({ indicator: value, iocType });
    }
  });
  return extracted;
}
```

### 5.3 Spider-Sense Screening

Applies the two-tier threat screening from `SpiderSenseDetector::screen()` in
`spider_sense.rs` (L270-310) to Finding narratives.

**Fast path (client-side WASM):** Embedding cosine similarity against the
`PatternDb`. Uses the existing `builtin:s2bench-v1` pattern database (36
entries, 3-dimensional demo embeddings).

**Deep path (server-side via hushd, optional):** When the fast path returns
`ScreeningVerdict::Ambiguous`, the deep-path LLM judge is invoked for signals
with severity >= `high`.

```typescript
async function enrichFindingWithSpiderSense(
  finding: Finding,
  signals: Signal[],
  detector: WasmSpiderSenseDetector,
): Promise<Enrichment> {
  // Build a composite embedding from signal summaries
  const narrative = signals.map(s => s.data.summary ?? "").join(" ");
  const embedding = await computeEmbedding(narrative);
  const result = detector.screen(embedding);

  return {
    type: "spider_sense",
    data: {
      verdict: result.verdict,        // "deny" | "ambiguous" | "allow"
      topScore: result.topScore,
      threshold: result.threshold,
      topMatches: result.topMatches.map(m => ({
        category: m.entry.category,
        label: m.entry.label,
        score: m.score,
      })),
    },
    addedAt: Date.now(),
    source: "spider_sense",
  };
}
```

The ambiguity band (`DEFAULT_AMBIGUITY_BAND = 0.10` from `spider_sense.rs` L15)
determines which signals need deep-path review.

### 5.4 External Feed Correlation

Cross-references Finding indicators against external threat intelligence
databases loaded via `IocDatabase`:

- **STIX 2.1 bundles:** `IocDatabase.loadStixBundle()` (`correlate/ioc.ts` L341-379)
- **CSV feeds:** `IocDatabase.loadCsvFile()` (`correlate/ioc.ts` L312-336)
- **Plain-text IOC lists:** `IocDatabase.loadTextFile()` (`correlate/ioc.ts` L294-306)

The Rust equivalents (`IocDatabase::load_stix_bundle_value()`,
`IocDatabase::load_csv_file()`, `IocDatabase::load_text_file()`) in
`hunt-correlate/src/ioc.rs` are used server-side via hushd.

### 5.5 Enrichment Data Model

```typescript
interface Enrichment {
  type: "mitre_attack" | "ioc_extraction" | "spider_sense" | "external_feed"
      | "swarm_corroboration" | "reputation" | "geolocation" | "whois" | "custom";
  data: Record<string, unknown>;  // Type-specific payload
  addedAt: number;
  source: string;  // Which enrichment stage produced this
}
```

---

## 6. Intel Promotion

When a Finding reaches the `promoted` state, it is packaged as an Intel
artifact -- a portable, signed, verifiable knowledge unit suitable for swarm
distribution.

### 6.1 What Gets Signed

The Intel artifact includes:

| Field | Signed | Rationale |
|-------|--------|-----------|
| `id` | Yes | Unique identifier for deduplication across swarm |
| `type` | Yes | Classification of the intel (`detection_rule`, `pattern`, `ioc`, `campaign`, `advisory`, `policy_patch`) |
| `title` | Yes | Human-readable summary |
| `description` | Yes | Narrative explanation |
| `content` | Yes | The shareable payload (pattern, rule, indicators, policy delta) |
| `derivedFrom` | Yes | Finding IDs -- provenance chain |
| `confidence` | Yes | Aggregate confidence from the Finding |
| `tags` | Yes | Categorical tags |
| `mitre` | Yes | MITRE ATT&CK mapping |
| `shareability` | Yes | Distribution scope (`private`, `swarm`, `public`) |
| `createdAt` | Yes | Timestamp |
| `author` | Yes | Sentinel or human fingerprint |

**Not signed (excluded from canonical form):**

- Raw signal data (redacted for privacy; summaries only)
- Session-specific identifiers (agent IDs, session IDs)
- Internal enrichment metadata

### 6.2 Receipt Chain

Intel artifacts carry a two-level provenance chain:

```
Intel.receipt: SignedReceipt
  ├── signs: canonical(Intel minus receipt/signature fields)
  ├── policy_hash: hash of the sentinel's active policy at time of promotion
  ├── decision: "promote"
  ├── metadata:
  │   ├── finding_ids: string[]
  │   ├── signal_count: number
  │   ├── enrichment_summary: string
  │   └── swarm_id?: string
  └── parent_receipt?: Finding.receipt  // links back to the Finding's receipt
```

This reuses the existing `SignedReceipt` infrastructure from
`hush-core/src/receipt.rs` and the TS `signReport()` in `report.ts` (L65-80).
The `merge_metadata()` pattern (noted in INDEX.md section 3) extends receipts
without structural changes.

### 6.3 Canonical Serialization (RFC 8785)

All signed Intel payloads are serialized using RFC 8785 (JSON Canonicalization
Scheme) before signing, ensuring cross-language deterministic hashing.

**Existing code:**

- Rust: `hush_core::canonicalize_json()` (used in `report.rs` L81)
- TS: `canonicalize()` from `@clawdstrike/sdk` (used in `report.ts` L37)

**Intel signing flow:**

```typescript
async function signIntel(intel: Intel, keypair: SentinelKeypair): Promise<Intel> {
  // 1. Extract signable fields (exclude receipt and signature)
  const { receipt, signature, ...signable } = intel;

  // 2. Canonicalize using RFC 8785
  const canonical = canonicalize(signable);

  // 3. Sign with sentinel's Ed25519 key
  const sig = await signMessage(
    new TextEncoder().encode(canonical),
    keypair.privateKey,
  );

  // 4. Build receipt
  const evidenceItems = buildIntelEvidence(intel);
  const report = buildReport(`Intel: ${intel.title}`, evidenceItems);
  const signedReport = await signReport(report, keypair.privateKeyHex);

  return {
    ...intel,
    signature: toHex(sig),
    receipt: signedReport,
  };
}
```

### 6.4 Packaging for Swarm Distribution

Intel artifacts are wrapped in a Speakeasy `MessageEnvelope` for Gossipsub
distribution:

```typescript
// Wrap intel in an IntelShareMessage (extends BaseMessage per SPEAKEASY-INTEGRATION.md)
const message: IntelShareMessage = await createSignedMessage(
  {
    type: "intel_share",
    intel,                          // full signed Intel artifact
    summary: intel.description,     // human-readable preview
    shareability: intel.shareability,
  },
  sentinelIdentity,
);

const envelope: MessageEnvelope = createEnvelope(
  "message",                       // envelope type (must be valid MessageEnvelope.type)
  message,                         // payload is AnyMessage (BaseMessage-extending)
  10,                              // TTL: max 10 hops in Gossipsub
);
```

**Topic routing:**

| Shareability | Gossipsub Topic |
|-------------|----------------|
| `private` | Not published (local only) |
| `swarm` | `/baychat/v1/swarm/{swarmId}/intel` |
| `public` | `/baychat/v1/discovery` (global topic) |

**Verification on receipt:** Peers verify the Intel signature and receipt chain
before ingesting. Invalid signatures are dropped silently (fail-closed). This
reuses `verifyReport()` from `report.ts` (L85-153) and the Rust
`verify_report()` from `hunt-correlate/src/report.rs` (L133-178).

---

## 7. Feedback Loop

The swarm's value compounds over time because intel feeds back into sentinel
memory, improving future detection.

### 7.1 Swarm Intel -> Sentinel Memory

When a sentinel receives Intel from a swarm peer:

```
Incoming Intel artifact (verified)
  │
  ├── type: "pattern" ──> append to SentinelMemory.knownPatterns[]
  │                        (used by matchPatternInSession() for w_pattern scoring)
  │
  ├── type: "ioc" ──────> merge into active IocDatabase
  │                        (IocDatabase.merge() in correlate/ioc.ts L282-286)
  │
  ├── type: "detection_rule" ──> load as new CorrelationRule
  │                               (parsed via parseRule() in correlate/rules.ts)
  │
  └── type: "policy_patch" ──> queue for human review in approval queue
                                (origin_type: "swarm_intel")
```

### 7.2 Pattern DB Updates

Spider-Sense `PatternDb` entries can be extended at runtime with swarm-sourced
patterns:

```typescript
function ingestSwarmPattern(
  patternDb: PatternDb,
  intelPattern: PatternEntry,
  peerReputation: number,
): void {
  // Only ingest patterns from peers above minimum reputation threshold
  if (peerReputation < MIN_PATTERN_REPUTATION) return;

  // Validate embedding dimensions match
  if (patternDb.expectedDim() !== intelPattern.embedding.length) return;

  // Add to runtime pattern DB (not persisted to builtin s2bench-v1)
  patternDb.addEntry(intelPattern);
}
```

This extends the existing `PatternDb` (which currently only loads from JSON via
`PatternDb::parse_json()` in `spider_sense.rs` L102-133) with a runtime
insertion path.

### 7.3 Baseline Adjustments

Swarm intel about new threat patterns causes baseline recalculation:

1. **New IOCs** trigger re-scoring of recent events against the updated IOC
   database. Events that now match are retroactively flagged, potentially
   creating new signals.

2. **New patterns** from swarm peers are checked against the historical event
   window. Matches that exceed the anomaly threshold generate new signals and
   may create new Findings.

3. **FP reports from peers** (shared as Intel type `advisory`) are added to
   `SentinelMemory.falsePositives` with a peer-reputation-weighted confidence
   discount, preventing over-suppression from low-reputation peers.

### 7.4 Reputation Updates

When a sentinel's Intel is consumed by peers and independently corroborated
(or contradicted), reputation scores are updated:

```typescript
function updateReputation(
  member: SwarmMember,
  intelId: string,
  outcome: "corroborated" | "contradicted" | "inconclusive",
): void {
  const delta = {
    corroborated: +0.02,
    contradicted: -0.05,   // asymmetric: bad intel is penalized more
    inconclusive: 0,
  }[outcome];

  member.reputation = clamp(0, 1,
    member.reputation + delta
  );
}
```

---

## 8. Performance Budget

### 8.1 Signal Volume Estimates

| Scenario | Agents | Events/Agent/Hour | Signals/Hour | Findings/Hour |
|----------|--------|-------------------|--------------|---------------|
| Solo developer | 1-3 | 50-200 | 10-60 | 0-5 |
| Small team | 5-20 | 100-500 | 50-500 | 5-20 |
| Enterprise fleet | 50-500 | 200-2000 | 500-10,000 | 20-200 |
| Federated swarm (aggregate) | 1000+ | Varies | 10,000-100,000 | 200-2000 |

**Key constraint:** The workbench runs client-side (React 19 + Tauri). The solo
and small-team scenarios must be handled entirely in-browser with no server
dependency.

### 8.2 Retention Strategy (TTL Tiers)

| Data Type | Hot (in-memory) | Warm (localStorage/IndexedDB) | Cold (server/archive) |
|-----------|----------------|-------------------------------|----------------------|
| **Signals** (info/low severity) | 1 hour | 24 hours | 7 days |
| **Signals** (medium+) | 6 hours | 7 days | 30 days |
| **Findings** (emerging) | 24 hours | 30 days | 90 days |
| **Findings** (confirmed/promoted) | Always | Always | Forever |
| **Intel** | Always | Always | Forever |
| **Baselines** | Current + 1 prior | 7 rolling | 30 rolling |

**Eviction policy:** Signals are evicted in priority order:
1. Expired TTL (wall-clock)
2. `info` severity with confidence < 0.3 (noise)
3. Signals already rolled into a Finding (summarized; raw data unnecessary)

### 8.3 Memory Management for Client-Side Processing

**Target:** The signal pipeline should consume < 50MB of heap for the solo/team
scenario (< 500 signals in-memory at steady state).

**Signal size estimate:** ~1 KB per Signal (JSON). 500 signals = ~500 KB.

**Budget breakdown:**

| Component | Estimated Heap | Notes |
|-----------|---------------|-------|
| Signal buffer (hot) | 500 KB | 500 signals at 1 KB each |
| Baseline profiles | 200 KB | 20 agents, 10 KB each |
| Pattern DB | 100 KB | s2bench-v1 (36 entries) + runtime additions |
| IOC database indices | 500 KB | 5,000 indicators with hash/domain/IP indices |
| Correlation engine windows | 200 KB | ~50 active windows at 4 KB each |
| Finding state | 500 KB | 50 active Findings with enrichment |
| **Total** | **~2 MB** | Well within 50 MB budget |

**Pressure valve:** When memory exceeds 80% of budget, the pipeline reduces the
hot retention window by 50% and drops `info`-severity signals immediately.

### 8.4 Throughput Targets

| Operation | Target Latency | Implementation |
|-----------|---------------|----------------|
| Signal normalization | < 1 ms | Pure TS, no I/O |
| Deduplication check | < 0.1 ms | Hash set lookup |
| Confidence scoring | < 2 ms | Weighted sum with baseline lookup |
| Correlation (per signal) | < 5 ms | `CorrelationEngine.processEvent()` |
| Spider-Sense screening | < 10 ms | WASM cosine similarity |
| MITRE mapping | < 1 ms | 24 regex matches via `mapEventToMitre()` |
| IOC matching | < 5 ms | Indexed hash/domain/IP lookups via `IocDatabase.matchEvent()` |
| Finding creation | < 10 ms | Signal aggregation + enrichment |

**Total per-signal pipeline latency:** < 35 ms (acceptable for real-time
display in the workbench activity stream).

---

## 9. Client vs. Server Split

### 9.1 Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    WORKBENCH (Client)                         │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Signal       │  │ Finding      │  │ Intel            │  │
│  │ Pipeline     │  │ Engine       │  │ Forge            │  │
│  │              │  │              │  │                  │  │
│  │ - normalize  │  │ - cluster    │  │ - canonicalize   │  │
│  │ - dedup      │  │ - lifecycle  │  │ - sign (Ed25519) │  │
│  │ - score      │  │ - enrich     │  │ - package        │  │
│  │ - correlate  │  │ - triage UI  │  │ - publish        │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────┘  │
│         │                 │                      │          │
│  ┌──────┴─────────────────┴──────────────────────┴───────┐  │
│  │                   Sentinel Manager                     │  │
│  │  - sentinel CRUD, scheduling, memory, identity         │  │
│  └────────────────────────────┬──────────────────────────┘  │
│                               │                              │
│  ┌────────────────────────────┴──────────────────────────┐  │
│  │                 Swarm Coordinator                      │  │
│  │  - Gossipsub pub/sub (via @backbay/speakeasy)          │  │
│  │  - peer trust graph, reputation tracking               │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────┬───────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │   hushd (Server)     │
                    │                     │
                    │  - bulk correlation  │
                    │  - IOC feed sync    │
                    │  - deep-path LLM    │
                    │  - long-term store  │
                    │  - fleet heartbeat  │
                    │  - NATS transport   │
                    └─────────────────────┘
```

### 9.2 What Runs in the Workbench (Client-Side)

| Component | Existing Code | New Code |
|-----------|--------------|----------|
| Signal normalization | `auditEventToAgentEvent()` in `hunt-engine.ts` | `guardResultToSignal()`, `anomalyToSignal()`, `iocMatchToSignal()`, `swarmIntelToSignal()` |
| Signal deduplication | `deduplicateAlerts()` in `playbook.ts` | `SignalDeduplicator` class |
| Anomaly scoring | `scoreAnomaly()`, `enrichEvents()` in `hunt-engine.ts`; `Baseline.scoreDetailed()` in `anomaly.ts` | Confidence composite scoring (`computeSignalConfidence()`) |
| Baseline computation | `computeBaseline()`, `computeDrift()` in `hunt-engine.ts` | Per-sentinel scoping of baselines |
| Pattern matching | `matchPatternInSession()`, `discoverPatterns()` in `hunt-engine.ts` | Pattern-match correlation strategy |
| Correlation (rule-based) | `CorrelationEngine` in `correlate/engine.ts` | Signal-to-TimelineEvent adapter |
| MITRE mapping | `mapEventToMitre()`, `mapAlertToMitre()` in `mitre.ts` | `enrichFindingWithMitre()` |
| IOC matching (small DBs) | `IocDatabase.matchEvent()` in `correlate/ioc.ts` | IOC extraction from signal payloads |
| Spider-Sense (fast path) | `WasmSpiderSenseDetector` in `hush-wasm` | Finding-level screening |
| Finding lifecycle | `Investigation` state in `hunt-types.ts` | `FindingEngine` with state machine |
| Intel signing | `signReport()` in `report.ts` | `signIntel()` with RFC 8785 canonicalization |
| Swarm pub/sub | -- | `SwarmCoordinator` using `@backbay/speakeasy` `useTransport()` |

### 9.3 What Runs in hushd (Server-Side)

| Component | Existing Code | New Code |
|-----------|--------------|----------|
| Bulk correlation at scale | `CorrelationEngine` in `hunt-correlate/src/engine.rs` | Streaming signal ingestion endpoint |
| IOC feed synchronization | `IocDatabase` in `hunt-correlate/src/ioc.rs` | Scheduled STIX/CSV feed polling |
| Spider-Sense deep path | `SpiderSenseGuard` async guard (LLM judge) | Finding-level deep-path endpoint |
| Long-term signal/finding storage | -- | PostgreSQL persistence layer |
| Fleet heartbeat + sentinel status | `fleet-client.ts` polling | `/sentinel/heartbeat` endpoint |
| NATS transport for spine envelopes | `spine/src/transport.rs` | `swarm.*`, `intel.*`, `sentinel.*` subject families |
| Report generation + signing | `build_report()`, `sign_report()` in `report.rs` | Server-signed Intel artifacts for high-assurance |
| Detection rule compilation | `compile_rule_source()` in `detection.rs` | Sigma/YARA compilation for swarm-distributed rules |

### 9.4 What Could Run as WASM

| Component | Current State | WASM Feasibility |
|-----------|--------------|-----------------|
| Spider-Sense fast path | Already WASM-exported (`WasmSpiderSenseDetector` in `hush-wasm`) | Ready -- ~1.6 MB binary |
| Correlation engine | Rust `CorrelationEngine` in `hunt-correlate` | High feasibility -- pure computation, no I/O. Would allow client-side Rust-speed correlation. Depends on regex crate WASM compat (already solved in `hush-wasm`) |
| IOC matching | Rust `IocDatabase` in `hunt-correlate` | High feasibility -- in-memory hash/trie lookups, no filesystem. Would accelerate large IOC databases client-side |
| Canonical JSON | Already WASM-exported (`canonicalize_json` in `hush-wasm`) | Ready |
| Report building + verification | Rust `build_report()`, `verify_report()` in `report.rs` | Medium feasibility -- requires `hush_core::merkle::MerkleTree` and Ed25519 signing in WASM. `hush_core` already compiles for WASM |
| Signal scoring (Rust-native) | Not yet implemented | Medium-term -- would allow server-identical scoring in-browser |

**Recommended WASM compilation priority:**
1. `hunt-correlate::engine::CorrelationEngine` -- largest throughput gain for
   client-side correlation
2. `hunt-correlate::ioc::IocDatabase` -- enables large IOC databases in-browser
3. Report building/verification -- already near-ready via `hush-wasm`

### 9.5 Offline/Local-Only Mode

When no server is available (personal swarm, day-one experience):

- All pipeline stages run client-side in the workbench.
- Signals and Findings are persisted to IndexedDB (primary store, < 50 MB)
  with the TTL tiers from section 8.2. localStorage is reserved for small
  config values only (see DATA-MODEL.md storage strategy).
- Sentinel-to-sentinel coordination within a personal swarm uses an
  in-process event emitter (e.g., `EventTarget` or lightweight pub/sub bus)
  matching the Gossipsub message interface. This ensures sentinel code has
  a single coordination path regardless of swarm type (personal vs. networked).
- Spider-Sense deep path is unavailable (requires LLM); fast path via WASM
  provides degraded-but-functional screening.
- IOC feeds are loaded from local files only (no scheduled sync).

This ensures the product is fully functional for a solo user with zero network
dependency -- the "make the solo product undeniable" principle from INDEX.md
Phase 1.
