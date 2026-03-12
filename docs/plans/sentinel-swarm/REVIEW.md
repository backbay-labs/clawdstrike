# Sentinel Swarm Design Docs — Technical Review

**Reviewer:** Claude (automated review agent)
**Date:** 2026-03-12
**Scope:** INDEX.md, DATA-MODEL.md, SPEAKEASY-INTEGRATION.md, UI-PAGE-MAP.md, SIGNAL-PIPELINE.md
**Method:** Cross-referenced all five docs against actual source files in the working tree

---

## 1. Factual Errors

### 1.1 Route Count (INDEX.md, line 68)

**Claim:** "Current navigation (16 routes)"
**Actual:** App.tsx defines 15 page routes (home, editor, simulator, hunt, compare, compliance, receipts, delegation, approvals, hierarchy, fleet, audit, guards, library, settings). The INDEX itself lists only 15 paths in its route table. The number 16 does not match either counting method.
**File:** `apps/workbench/src/App.tsx` lines 287-304
**Fix:** Change to "(15 routes)".

### 1.2 MessageEnvelope.type Mismatch (INDEX.md, line 193; SIGNAL-PIPELINE.md, line 675)

**Claim (INDEX.md):** `MessageEnvelope` has fields `version, type, payload, TTL (default 10 hops), created timestamp`. The INDEX and SIGNAL-PIPELINE use `type: "SentinelResponse"` as the envelope type value for Intel distribution.
**Actual:** `MessageEnvelope.type` is defined as `'message' | 'presence' | 'typing' | 'sync_request' | 'sync_response'` in `@backbay/speakeasy/src/transport/types.ts` line 84. There is no `"SentinelResponse"` value in the envelope type union. `SentinelResponse` is a *message-level* type (inside `BaseMessage.type`), not an envelope type.
**Impact:** The SIGNAL-PIPELINE section 6.4 shows `type: "SentinelResponse"` on the envelope, which would be rejected by any type-checked code.
**Credit:** SPEAKEASY-INTEGRATION.md section 2 (line 452-466) correctly identifies this problem and proposes extending the envelope type union. But INDEX.md and SIGNAL-PIPELINE.md still use the wrong value.
**Fix:** INDEX.md section 5 and SIGNAL-PIPELINE section 6.4 should use the proposed envelope types from SPEAKEASY-INTEGRATION (e.g., `type: "intel"` for intel distribution).

### 1.3 MessageEnvelope.payload Type (SIGNAL-PIPELINE.md, line 673-684)

**Claim:** The SIGNAL-PIPELINE shows `payload: { intel, summary, shareability }` inside the `MessageEnvelope`.
**Actual:** `MessageEnvelope.payload` is typed as `AnyMessage` (the union of all Speakeasy message types extending `BaseMessage`). It is not an arbitrary object. You cannot stuff a raw `{ intel, summary, shareability }` object into it.
**Fix:** Intel artifacts must be wrapped in a proper `BaseMessage`-extending type (e.g., `IntelShareMessage` as defined in SPEAKEASY-INTEGRATION.md) before being placed in the envelope payload.

### 1.4 Anomaly.ts Location (SIGNAL-PIPELINE.md, lines 37, 144)

**Claim:** References `Baseline.scoreDetailed()` in `anomaly.ts` at "(L57-88)".
**Actual:** The `Baseline` class and `scoreDetailed()` method live in `packages/sdk/clawdstrike-hunt/src/anomaly.ts`, not in the workbench. The actual line numbers are L57-88, which is correct. However, the doc conflates two different codebases: the workbench `hunt-engine.ts` `scoreAnomaly()` (which operates on `AgentEvent` + `AgentBaseline`) and the SDK `anomaly.ts` `Baseline.scoreDetailed()` (which operates on `TimelineEvent`). These are parallel implementations with different input types.
**Fix:** Clarify which `anomaly.ts` is being referenced (SDK vs. workbench) and note that the two scoring systems operate on different event types.

### 1.5 Investigation.actions Type (INDEX.md, line 119; SIGNAL-PIPELINE.md, line 425)

**Claim (INDEX.md):** `Investigation` has `actions?` field typed as an array.
**Actual:** `Investigation.actions` is typed as `InvestigationAction[]` (optional) in `hunt-types.ts` line 121. The INDEX snippet shows it as `actions?` but the SIGNAL-PIPELINE migration table (line 425) claims the type is extended with `"promoted-to-intel"`.
**Issue:** The existing `InvestigationAction` uses kebab-case values (`"policy-updated"`, `"pattern-added"`, `"agent-revoked"`, `"escalated"`), but the new `FindingAction` type in DATA-MODEL.md uses snake_case (`"policy_updated"`, `"pattern_added"`, `"agent_revoked"`, `"escalated"`, `"intel_promoted"`, `"speakeasy_opened"`). This is a silent naming convention change that the migration section does not flag.
**Fix:** Either keep kebab-case for backward compatibility or explicitly document the convention change and ensure the migration function handles the translation.

### 1.6 InvestigationVerdict Naming Convention (DATA-MODEL.md, lines 105-109)

**Claim:** `FindingVerdict` extends `InvestigationVerdict` with values `"threat_confirmed"`, `"false_positive"`, `"policy_gap"`, `"inconclusive"`.
**Actual:** `InvestigationVerdict` in `hunt-types.ts` line 97 uses kebab-case: `"threat-confirmed"`, `"false-positive"`, `"policy-gap"`, `"inconclusive"`. The proposed `FindingVerdict` silently switches to snake_case.
**Fix:** Document this as an intentional convention change in the migration section, or keep kebab-case.

### 1.7 File Line Counts (INDEX.md, Section 9)

| File | Claimed Lines | Actual Lines | Correct? |
|------|--------------|-------------|----------|
| `hunt-types.ts` | 180 | 179 | Close (off by 1) |
| `types.ts` | 529 | 528 | Close (off by 1) |
| `delegation-types.ts` | 77 | 76 | Close (off by 1) |
| `approval-types.ts` | 47 | 46 | Close (off by 1) |
| `hunt-engine.ts` | 596 | 595 | Close (off by 1) |

All line counts are consistently off by exactly 1, suggesting they were counted with trailing newline or a different method. Minor but worth correcting.

### 1.8 Severity Type Source (SIGNAL-PIPELINE.md, line 192)

**Claim:** "This aligns with the existing `Severity` type in `hunt-types.ts` (L99)."
**Actual:** The line number is correct (line 99). However, the Severity order in hunt-types.ts is `"critical" | "high" | "medium" | "low" | "info"` while DATA-MODEL.md defines it as `"info" | "low" | "medium" | "high" | "critical"`. While the sets are identical, the reversed order is worth noting for consistency if the type ordering carries semantic meaning (e.g., iteration or comparison).

---

## 2. Internal Inconsistencies

### 2.1 Signal.relatedSignals Optionality

| Document | Definition |
|----------|-----------|
| INDEX.md (line 257) | `relatedSignals?: string[]` — optional |
| DATA-MODEL.md (line 488) | `relatedSignals: string[]` — required (empty array default) |

**Recommendation:** Use the DATA-MODEL.md approach (required, default `[]`). Optional arrays create unnecessary null-checking overhead.

### 2.2 Signal.ttl Optionality

| Document | Definition |
|----------|-----------|
| INDEX.md (line 257) | `ttl?: number` — optional |
| DATA-MODEL.md (line 495) | `ttl: number | null` — required, nullable |

**Recommendation:** Use `number | null` from DATA-MODEL.md for consistency with the fail-closed principle (explicit null vs. missing field).

### 2.3 Signal.findingId — Exists Only in DATA-MODEL.md

The `Signal` type in INDEX.md (Section 3) has no `findingId` field. DATA-MODEL.md adds `findingId: string | null` (line 500). This back-reference is architecturally important but is not mentioned in the INDEX overview.

### 2.4 Sentinel.schedule Type Inconsistency

| Document | Definition |
|----------|-----------|
| INDEX.md (line 223) | `schedule?: CronExpression` — optional, typed alias |
| DATA-MODEL.md (line 258) | `schedule: string | null` — required, nullable |

The INDEX uses a `CronExpression` type alias that is never defined. DATA-MODEL.md simplifies to `string | null`.
**Recommendation:** Use DATA-MODEL.md's definition; define `CronExpression` as a branded string alias if validation is desired.

### 2.5 SentinelMemory.falsePositives vs. falsePositiveHashes

| Document | Field Name |
|----------|-----------|
| INDEX.md (line 242) | `falsePositives: string[]` |
| DATA-MODEL.md (line 375) | `falsePositiveHashes: string[]` |

**Recommendation:** Use `falsePositiveHashes` from DATA-MODEL.md -- it's more descriptive.

### 2.6 SentinelMemory.knownPatterns Type

| Document | Element Type |
|----------|-------------|
| INDEX.md (line 239) | `PatternEntry[]` (from spider_sense.rs) |
| DATA-MODEL.md (line 365) | `MemoryPattern[]` (new dedicated type) |

DATA-MODEL.md introduces a separate `MemoryPattern` type distinct from Spider-Sense's `PatternEntry`. The INDEX conflates them. This needs reconciliation: are sentinel memory patterns the same as Spider-Sense pattern DB entries, or not?

### 2.7 Finding.enrichment vs. enrichments

| Document | Field Name |
|----------|-----------|
| INDEX.md (line 278) | `enrichment: Enrichment[]` |
| DATA-MODEL.md (line 690) | `enrichments: Enrichment[]` |
| SIGNAL-PIPELINE.md (line 437) | `Finding.enrichment[]` |

Two out of three docs use singular. DATA-MODEL.md uses plural.
**Recommendation:** Use `enrichments` (plural) per DATA-MODEL.md since it is a collection.

### 2.8 Enrichment Type Definition Conflict

| Document | Enrichment.type Values |
|----------|----------------------|
| SIGNAL-PIPELINE.md (line 566) | `"mitre_mapping" | "ioc_extraction" | "spider_sense" | "external_feed" | "swarm_corroboration"` |
| DATA-MODEL.md (line 767) | `"mitre_attack" | "ioc_lookup" | "reputation" | "geolocation" | "whois" | "threat_intel" | "custom"` |

These are completely different enumerations for the same field on the same type. SIGNAL-PIPELINE describes pipeline stages; DATA-MODEL describes enrichment categories.
**Recommendation:** Reconcile into a single union. The SIGNAL-PIPELINE values should be a subset of the DATA-MODEL values. Suggested unified set: `"mitre_attack" | "ioc_extraction" | "spider_sense" | "external_feed" | "swarm_corroboration" | "reputation" | "geolocation" | "whois" | "custom"`.

### 2.9 Finding.createdBy Present in DATA-MODEL, Absent in INDEX

DATA-MODEL.md has `createdBy: string` and `updatedBy: string` on Finding (lines 717-719). The INDEX.md only shows `updatedBy: string` (line 285). The `createdBy` field is essential for provenance.

### 2.10 Intel.signature vs. Intel.signerPublicKey

INDEX.md (line 302) defines `signature: Ed25519Signature` (an opaque type alias). DATA-MODEL.md (lines 871-877) splits this into two fields: `signature: string` (hex) and `signerPublicKey: string` (hex). The DATA-MODEL approach is better because it includes the public key needed for verification without a separate lookup.

### 2.11 AUTO_FINDING_CONFIDENCE_THRESHOLD vs. Auto-Promotion Thresholds

DATA-MODEL.md defines `AUTO_FINDING_CONFIDENCE_THRESHOLD = 0.75` (line 176). SIGNAL-PIPELINE.md section 4.1 says findings are created when cluster confidence exceeds 0.3 with >= 2 signals (line 360). Section 4.2 says `autoConfirmThresholds.minConfidence = 0.8` (line 377). These three thresholds interact but their relationship is not clearly documented.

**Recommendation:** Add a threshold glossary that explains:
- 0.3 = minimum to create an `emerging` finding from a signal cluster
- 0.75 = general-purpose constant (what is this actually for?)
- 0.8 = auto-confirm threshold for emerging -> confirmed transition
- 0.9 = auto-promote threshold for confirmed -> promoted transition

---

## 3. Missing Connections

### 3.1 Dual OriginContext Definitions

The workbench has two `OriginContext` interfaces:
- `types.ts` line 283: full version (provider, tenant_id, space_id, space_type, thread_id, actor_id, actor_type, actor_role, visibility, external_participants, tags, sensitivity, provenance_confidence)
- `approval-types.ts` line 7: simplified version (provider, tenant_id, space_id, space_type, actor_id, actor_name, visibility)

Additionally, the `OriginProvider` unions differ:
- `types.ts`: `"slack" | "teams" | "github" | "jira" | "email" | "discord" | "webhook"`
- `approval-types.ts`: `"slack" | "teams" | "github" | "jira" | "cli" | "api"`

The docs reference `OriginContext` from `types.ts` but the approval integration (which the DATA-MODEL's Speakeasy section references) uses the one from `approval-types.ts`. This existing duplication should be resolved as part of the sentinel-swarm work, and the docs should note it.

### 3.2 Existing Receipt Type Mismatch

The workbench `Receipt` type in `types.ts` (lines 471-486) has fields like `guard: string`, `policyName: string`, `action: { type, target }` that are specific to per-guard evaluations. The sentinel-swarm docs propose using `Receipt` for Finding attestation and Intel provenance, which are not guard evaluations. The docs should address how to repurpose or extend the Receipt type for non-guard-evaluation attestations.

### 3.3 HuntPattern.promotedToTrustprint Field

`hunt-types.ts` line 154 defines `promotedToTrustprint?: string` on `HuntPattern`. DATA-MODEL.md (line 825) correctly references this as `HuntPattern.promotedToTrustprint maps to Intel.id`. However, the field name "trustprint" is a legacy Speakeasy concept. When patterns are promoted to Intel (not trustprints), this field name becomes confusing. The migration should either rename it or add a parallel `promotedToIntel` field.

### 3.4 AgentEvent.timestamp is string, not number

The entire signal pipeline assumes `timestamp: number` (Unix ms), but `AgentEvent.timestamp` in `hunt-types.ts` line 10 is `string` (ISO-8601). The migration function `agentEventToSignal()` in DATA-MODEL.md (line 1476) correctly calls `new Date(event.timestamp).getTime()`, but the SIGNAL-PIPELINE normalization pseudocode at line 49 (`auditEventToAgentEvent()`) does not highlight this type conversion.

### 3.5 Missing Reference to multi-policy-store.tsx State Architecture

The docs propose new stores (`sentinel-store.tsx`, `swarm-store.tsx`) but do not reference the existing `MultiPolicyProvider` / `MultiPolicyState` architecture in `multi-policy-store.tsx`. Since all new stores will need to coexist within the same React context hierarchy (visible in App.tsx lines 275-318), the docs should specify where new providers slot into the provider stack and whether they depend on existing providers.

### 3.6 fleet-client.ts AuditEvent Type

The `hunt-engine.ts` imports `AuditEvent` from `./fleet-client` (line 8), and the `auditEventToAgentEvent()` function converts it to `AgentEvent`. The docs should reference `AuditEvent` as the original source type (it is the fleet API response shape), not just `AgentEvent`.

### 3.7 TSX File Count Claim

INDEX.md line 65 claims "237 TSX files, ~47K lines of component code" but this is not verifiable without a full count. Consider removing exact counts or marking them as approximate snapshots.

---

## 4. Naming Inconsistencies

### 4.1 "Intel" as Both Noun and Prefix

- Type name: `Intel` (DATA-MODEL.md)
- ID prefix: `int_` (DATA-MODEL.md line 64)
- But `int` is a reserved word in many languages. While not a problem in TypeScript, this could cause issues if the types are ever generated into other languages (Rust, Go, Python).
- **Recommendation:** Consider `intel_` or `ntl_` as the prefix.

### 4.2 SpeakeasyMember.role vs. SwarmMember.role

- `SpeakeasyMember.role`: `"moderator" | "participant" | "observer"` (DATA-MODEL.md line 1324)
- `SwarmMember.role`: `"admin" | "contributor" | "observer"` (DATA-MODEL.md line 1085)

These are parallel role systems with different values for what could be the same concept. Only `"observer"` overlaps. The admin/moderator distinction is understandable but should be explicitly documented.

### 4.3 "Speakeasy" vs. "ClawdstrikeSpeakeasy"

The docs use three different names for the same concept:
- `Speakeasy` (INDEX.md Section 1 ontology)
- `ClawdstrikeSpeakeasy` (INDEX.md Section 3 type definition, DATA-MODEL.md Section 4.6)
- `SpeakeasyPanel` (INDEX.md Section 4 component list)

**Recommendation:** Settle on `ClawdstrikeSpeakeasy` for the type and `Speakeasy` as the product term.

### 4.4 Signal Source Provenance Values

SIGNAL-PIPELINE.md uses values like `"guard_pipeline"`, `"anomaly_detector"`, `"ioc_feed"`, `"swarm_intel"` in normalization pseudocode (lines 54-99).
DATA-MODEL.md defines `SignalProvenance` with different values: `"guard_evaluation"`, `"anomaly_detection"`, `"pattern_match"`, `"correlation_rule"`, `"spider_sense"`, `"external_feed"`, `"manual"` (lines 150-157).

These don't align. `"guard_pipeline"` vs `"guard_evaluation"`, `"anomaly_detector"` vs `"anomaly_detection"`, `"ioc_feed"` vs `"external_feed"`, `"swarm_intel"` is missing from the DATA-MODEL enum entirely.
**Recommendation:** Add `"swarm_intel"` to the `SignalProvenance` enum in DATA-MODEL.md and reconcile the naming with SIGNAL-PIPELINE.md.

---

## 5. Type Mismatches with Existing Code

### 5.1 SignalDataPolicyViolation.verdict Uses Existing Verdict Type

DATA-MODEL.md (line 590) imports `Verdict` from `./types` for the policy violation signal. The existing `Verdict = "allow" | "deny" | "warn"` includes `"allow"`, but a policy *violation* signal should only carry `"deny"` or `"warn"`. Using the full `Verdict` type allows semantically invalid data.
**Recommendation:** Use a narrower type: `verdict: "deny" | "warn"`.

### 5.2 SignalContext.agentName Missing from AgentEvent

DATA-MODEL.md defines `SignalContext.agentName: string` (line 616). The existing `AgentEvent` has `agentName: string` (hunt-types.ts line 12), so this is fine for fleet-sourced signals. However, for external-feed signals or swarm-sourced signals, there is no agent name. The field should be optional (`agentName?: string`) or the context should distinguish between agent-attributed and non-agent-attributed signals.

### 5.3 IntelContentPolicyPatch References GuardConfigMap

DATA-MODEL.md (line 998) defines `guardsPatch: Partial<import("./types").GuardConfigMap>`. This is a strong coupling to the workbench's local `GuardConfigMap` type. If Intel artifacts are shared across swarms (potentially across different versions of the workbench), the receiver may have a different `GuardConfigMap` schema. The patch should be a plain `Record<string, unknown>` with a separate `schemaVersion` field for compatibility.

### 5.4 Dual Import Style for Existing Types

DATA-MODEL.md uses inline `import("./hunt-types")` syntax extensively (e.g., line 370, 390, 537, etc.). While this is valid TypeScript, it creates a dependency on the relative path structure. If the sentinel-swarm types are defined in a separate file (e.g., `sentinel-types.ts`), the import paths must match the actual file layout. The docs should specify the intended file location for these types.

---

## 6. Architectural Concerns

### 6.1 Gossipsub for High-Volume Signal Sharing

INDEX.md proposes using Gossipsub (via `@backbay/speakeasy`) for both intel exchange and signal streaming. The open question in Section 10 asks about Gossipsub vs. NATS. The SIGNAL-PIPELINE performance budget (Section 8) estimates 10,000-100,000 signals/hour for enterprise/federated scenarios.

**Concern:** Gossipsub is a pub/sub protocol designed for moderate-throughput, high-fan-out messaging (chat, announcements). At 100K signals/hour (~28 messages/second) across a federated mesh, Gossipsub's message overhead (signed envelopes + hop-based TTL) becomes significant. The existing Speakeasy transport was designed for human-scale messaging rates.

**Recommendation:** Signal streaming should use NATS (via Spine transport) for enterprise/federated scenarios, with Gossipsub reserved for intel/coordination messages (lower volume, higher value). The SPEAKEASY-INTEGRATION.md's signal topic should be marked as "small swarms only" with a clear throughput ceiling.

### 6.2 Client-Side State Management Explosion

The existing workbench uses `MultiPolicyState` (a single `useReducer`-based store) for all state. The proposal adds:
- `sentinel-store.tsx` for sentinel CRUD
- `swarm-store.tsx` for swarm membership

Plus the existing stores that are already separate: `FleetConnectionProvider`, `GeneralSettingsProvider`, `HintSettingsProvider`, `MultiPolicyProvider`.

**Concern:** Six nested React context providers (visible in App.tsx lines 278-317) will become eight or more. Deep provider nesting causes unnecessary re-renders and makes state dependencies opaque.

**Recommendation:** Consider a unified store approach (e.g., Zustand, Jotai, or a single `WorkbenchStore` reducer) rather than proliferating providers. At minimum, document the provider dependency graph and render boundaries.

### 6.3 localStorage + IndexedDB Storage Limits

SIGNAL-PIPELINE Section 8.2 proposes localStorage for warm storage and IndexedDB for larger datasets. The Tauri desktop target and web browser have different storage limits:
- localStorage: 5-10 MB (varies by browser)
- IndexedDB: effectively unlimited on desktop, 50-100MB on some mobile browsers

With 10,000 signals at ~1KB each = ~10MB, plus findings, intel, baselines, and patterns, the localStorage limit could be exceeded quickly.

**Recommendation:** Default to IndexedDB for all data storage, with localStorage only for small configuration values. The SIGNAL-PIPELINE should revise its storage strategy table accordingly.

### 6.4 Offline Personal Swarm as Direct Function Calls

SIGNAL-PIPELINE Section 9.5 states: "Sentinel-to-sentinel coordination within a personal swarm uses direct function calls (no message bus needed when all sentinels run in the same process)."

**Concern:** This means the personal swarm has a fundamentally different coordination mechanism than trusted/federated swarms (which use Gossipsub). Code that works locally may behave differently when connected to a network swarm. This also means sentinel code must have two coordination paths.

**Recommendation:** Use an in-process event emitter (e.g., `EventTarget` or a lightweight pub/sub bus) for personal swarms, matching the Gossipsub message interface. This way sentinel code has a single coordination path regardless of swarm type.

### 6.5 Identity Unification: Seed Phrase Exposure

SPEAKEASY-INTEGRATION.md Section 1 proposes sharing a single Ed25519 keypair between Speakeasy and Clawdstrike. The Speakeasy identity includes a BIP39 seed phrase shown once at creation. If this same keypair is used for receipt signing, the seed phrase recovery path becomes a high-value target (recovering the seed phrase = signing arbitrary receipts and intel).

**Concern:** The UI-PAGE-MAP.md (Section 3c, Config tab) mentions "seed phrase reveal behind confirmation". Displaying the seed phrase in the workbench UI for a signing key that attests to security findings is a security design tension.

**Recommendation:** Document the threat model for seed phrase exposure. Consider whether sentinel keypairs (which sign authoritative security artifacts) should have a different key management path than speakeasy social identities.

---

## 7. Gap Analysis

### 7.1 No Conflict Resolution for Concurrent Edits

Multiple sentinels may update the same Finding concurrently (e.g., adding signals, changing status). None of the docs specify a conflict resolution strategy. Since Findings are mutable state shared between sentinels:
- What happens if two sentinels try to confirm the same emerging finding simultaneously?
- What if one sentinel marks a finding as FP while another promotes it?

**Recommendation:** Define a last-writer-wins or CRDT-based conflict resolution strategy for Finding state transitions. At minimum, add optimistic locking via `updatedAt` timestamps.

### 7.2 No Rate Limiting for Swarm Intel

None of the docs specify rate limiting for Gossipsub messages. A compromised or misbehaving sentinel could flood a swarm with bogus intel or signals.

**Recommendation:** Define per-member rate limits for each message type (e.g., max 10 intel shares per hour, max 100 signals per minute). Rate-exceeded messages should be dropped by receivers.

### 7.3 No Versioning Strategy for Wire Types

The new message types (SPEAKEASY-INTEGRATION.md Section 2) do not include a schema version field. When message formats evolve, receivers have no way to detect or handle version mismatches.

**Recommendation:** Add a `schemaVersion: string` field to `ClawdstrikeAnyMessage` or to each new message type.

### 7.4 No Testing Strategy

None of the five docs describe how to test the sentinel-swarm features. Key gaps:
- How to simulate a multi-sentinel environment locally
- How to test Gossipsub message flow without a real P2P network
- How to test the signal pipeline with realistic volume (performance benchmarks)
- How to test the Finding state machine transitions

**Recommendation:** Add a TESTING.md companion doc or a testing section to each doc.

### 7.5 No Error Handling / Failure Modes

The docs describe the happy path thoroughly but do not address:
- What happens when a sentinel crashes mid-hunt?
- What happens when a swarm peer sends malformed intel?
- What happens when IndexedDB storage is full?
- What happens when the Gossipsub mesh partitions?

The Clawdstrike project's core principle is "fail-closed," but none of the docs specify what fail-closed means for each new component.

**Recommendation:** Add a failure modes section to SIGNAL-PIPELINE.md and SPEAKEASY-INTEGRATION.md.

### 7.6 No Accessibility Considerations in UI-PAGE-MAP

UI-PAGE-MAP.md specifies detailed visual layouts but does not mention:
- Keyboard navigation for sentinel creation wizard
- Screen reader support for sigil icons and sparkline charts
- Color contrast requirements for severity dots and status indicators

**Recommendation:** Add an accessibility section or note that the existing workbench accessibility patterns apply.

### 7.7 Swarm Membership Revocation

The docs describe swarm joining but not leaving or revocation:
- How is a member removed from a swarm?
- What happens to their shared intel when they leave?
- Can a revoked member still read historical messages on Gossipsub topics?

**Recommendation:** Add membership revocation to the Swarm section of DATA-MODEL.md and SPEAKEASY-INTEGRATION.md.

### 7.8 No Migration for Existing Hunt Lab Users

The UI-PAGE-MAP.md shows `/hunt` being absorbed into `/findings` and `/intel` routes. But there is no discussion of:
- What happens to bookmarked `/hunt` URLs?
- Is there a redirect from `/hunt` to the appropriate new route?
- What happens to in-progress investigations when the UI switches to the Finding model?

**Recommendation:** Add redirect rules to UI-PAGE-MAP.md and migration notes to DATA-MODEL.md's Section 6 (which only covers data migration, not URL migration).

---

## 8. Recommendations Summary

### Resolution Status (updated 2026-03-12)

#### Critical — RESOLVED

1. ~~**Reconcile Enrichment.type enums**~~ — FIXED: Both DATA-MODEL.md and SIGNAL-PIPELINE.md now use unified superset: `"mitre_attack" | "ioc_extraction" | "spider_sense" | "external_feed" | "swarm_corroboration" | "reputation" | "geolocation" | "whois" | "custom"`
2. ~~**Fix MessageEnvelope.type usage**~~ — FIXED: SIGNAL-PIPELINE.md now uses `"message"` envelope type with `IntelShareMessage` payload
3. ~~**Fix MessageEnvelope.payload**~~ — FIXED: Uses `createSignedMessage()` + `createEnvelope()` pattern per SPEAKEASY-INTEGRATION.md
4. ~~**Add `"swarm_intel"` to SignalProvenance**~~ — FIXED: Added to DATA-MODEL.md enum
5. **Resolve dual OriginContext** definitions before adding more code that depends on them (Section 3.1) — **OPEN: requires implementation decision**

#### High — MOSTLY RESOLVED

6. ~~**Reconcile naming conventions**~~ — FIXED: SIGNAL-PIPELINE migration table now uses snake_case (`"intel_promoted"`) matching DATA-MODEL.md convention. Note: existing `InvestigationAction` uses kebab-case; migration function must translate.
7. ~~**Standardize Signal field optionality**~~ — FIXED: INDEX.md now matches DATA-MODEL.md (`relatedSignals: string[]`, `ttl: number | null`, added `findingId`)
8. ~~**Reconcile SentinelMemory.knownPatterns**~~ — FIXED: INDEX.md now uses `MemoryPattern[]` matching DATA-MODEL.md; SIGNAL-PIPELINE references clarified
9. **Specify where new React providers** slot into the App.tsx provider hierarchy (Section 3.5) — **OPEN: address during implementation**
10. **Define conflict resolution** for concurrent Finding updates (Section 7.1) — **OPEN: needs design decision**

#### Medium — PARTIALLY RESOLVED

11. **Add threshold glossary** (Section 2.11) — **OPEN**
12. **Add failure modes** to SIGNAL-PIPELINE.md and SPEAKEASY-INTEGRATION.md (Section 7.5) — **OPEN**
13. ~~**Revise storage strategy**~~ — FIXED: SIGNAL-PIPELINE now defaults to IndexedDB for signals/findings
14. ~~**Use in-process event bus**~~ — FIXED: SIGNAL-PIPELINE offline section now specifies EventTarget/pub-sub matching Gossipsub interface
15. **Add URL redirect plan** for `/hunt` -> `/findings` + `/intel` migration (Section 7.8) — **OPEN**

#### Low — PARTIALLY RESOLVED

16. ~~Fix route count from 16 to 15~~ — FIXED
17. Fix file line counts (off by 1 consistently) (Section 1.7) — **OPEN** (cosmetic)
18. Consider `intel_` prefix instead of `int_` (Section 4.1) — **OPEN** (naming decision)
19. ~~Standardize enrichment field name as `enrichments` (plural)~~ — FIXED across INDEX.md and SIGNAL-PIPELINE.md
20. Add schema version to new Speakeasy message types (Section 7.3) — **OPEN**

#### Additional fixes applied

21. ~~INDEX.md: Added `createdBy` field to Finding~~ — FIXED (matching DATA-MODEL.md)
22. ~~INDEX.md: Intel.signature split into `signature` + `signerPublicKey`~~ — FIXED (matching DATA-MODEL.md)
23. ~~INDEX.md: Sentinel.schedule changed to `string | null`~~ — FIXED (matching DATA-MODEL.md)
24. ~~INDEX.md: SentinelMemory.falsePositives renamed to `falsePositiveHashes`~~ — FIXED
25. ~~INDEX.md: Added SignalProvenance enum values as comment~~ — FIXED
26. ~~DATA-MODEL.md: SignalDataPolicyViolation.verdict narrowed to `"deny" | "warn"`~~ — FIXED
27. ~~SIGNAL-PIPELINE.md: Clarified SDK vs workbench anomaly.ts reference~~ — FIXED

### Remaining Open Items

| # | Issue | Priority | Action Needed |
|---|-------|----------|---------------|
| 5 | Dual OriginContext definitions | Critical | Unify during implementation; document canonical source |
| 9 | React provider hierarchy | High | Specify in UI-PAGE-MAP.md during implementation |
| 10 | Finding conflict resolution | High | Design last-writer-wins or CRDT strategy |
| 11 | Threshold glossary | Medium | Add to SIGNAL-PIPELINE.md or DATA-MODEL.md |
| 12 | Failure modes | Medium | Add sections to SIGNAL-PIPELINE.md and SPEAKEASY-INTEGRATION.md |
| 15 | URL redirect plan | Medium | Add to UI-PAGE-MAP.md |
| 18 | `int_` vs `intel_` prefix | Low | Naming decision |
| 20 | Wire type schema version | Low | Add `schemaVersion` field to new message types |
