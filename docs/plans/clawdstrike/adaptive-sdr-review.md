# Adaptive SDR -- Review

> **Date:** 2026-02-26
> **Reviewer:** critic agent (T5)
> **Status:** Complete
> **Deliverables reviewed:** D1 (Research Brief), D2 (Spec 15), D3 (Implementation Plan)

## Executive Summary

The adaptive SDR deliverables form a coherent, well-researched architecture. Spec 15 successfully addresses all 12 gaps identified in the research brief, the implementation plan provides a realistic five-phase delivery strategy, and the design preserves the frozen `PolicyEngineLike` contract throughout. The primary concerns are: (1) the enrollment protocol uses NATS for its initial request, but an unenrolled agent has no NATS credentials yet -- creating a chicken-and-egg problem; (2) the `details` field on `Decision` is typed as `unknown`, and shallow-merging provenance into it may silently overwrite adapter-supplied details; (3) several error paths in the approval escalation flow lack explicit fail-closed handling; and (4) the implementation plan and spec diverge on the `AdaptiveEngineOptions` interface design.

---

## 1. Completeness Review

### 1.1 Gaps Addressed

| Gap ID | Title | Addressed? | Where (Spec 15 Section) | Notes |
|--------|-------|------------|--------------------------|-------|
| G1 | No Mode Negotiation Protocol | Yes | S2 (Deployment Modes), S14 (engine-adaptive), S6.6 | Probing via health endpoint; mode state machine with transitions |
| G2 | No Graceful Promotion/Demotion | Yes | S14.2 (Mode Transition State Machine) | Full state machine: standalone <-> connected <-> degraded |
| G3 | No Unified Adaptive Configuration | Yes | S2.2 (Connected config), S14.1 (AdaptiveEngineOptions) | Unified YAML config surface with local + enterprise + agent sections |
| G4 | Missing hushd Session API in TS | Partially | S19 (Open Question #2) | Acknowledged but deferred: "extend eval request with optional session_id." No concrete wire format defined. |
| G5 | No Policy Sync / Cache-Ahead | Yes | S9 (Policy Sync) | NATS KV watch with checksum validation and local cache |
| G6 | Degraded Provenance Is Shallow | Yes | S14.3 (Enriched Provenance) | Provenance includes mode, reason, policy ref/version/age, capabilities lost |
| G7 | No Audit Bridge for Offline | Yes | S10.4 (Store-and-Forward) | File-based queue with drain-on-reconnect and JetStream dedup |
| G8 | Desktop Agent Port Hardcoded | Partially | S19 (Open Question #5) | Acknowledged but deferred to "recommendation: yes, add port config." Not in the spec body or file changes. |
| G9 | Session Posture Extraction Fragile | No | Not addressed | The deeply-nested `state["posture"]["current_state"]` extraction is not fixed or mentioned in the spec. |
| G10 | IAM Plans Unimplemented | Acknowledged | S1.2, S6.2, S18 | Explicitly deferred: "enrollment token validation can use simple HMAC initially; full IAM integration deferred" |
| G11 | No Fleet Discovery / Registration | Yes | S7 (Enrollment Protocol) | One-time enrollment with HMAC token, credential provisioning, NATS binding |
| G12 | hushd Dockerfile Missing | No | Not addressed | Spec 15 does not mention the missing Dockerfile; this remains a Spec 09 deliverable |

### 1.2 Missing Coverage

1. **G9 not addressed.** The fragile posture extraction via deeply-nested JSON path is a reliability risk during connected-mode heartbeat reporting. Spec 15 Section 8.1 defines a heartbeat message with `posture` field but does not address how posture is extracted from the hushd session response.

2. **G4 partially addressed.** Open Question #2 recommends adding `session_id` to eval requests but this is left as an open question rather than specified. The implementation plan (Phase 1) does not include session binding either.

3. **G8 partially addressed.** Open Question #5 recommends port configurability but this is not reflected in the file changes table (Section 15) or the implementation plan.

4. **Receipts replay endpoint.** The implementation plan (Phase 5) defines `POST /api/v1/receipts/replay` for the store-and-forward drain, but Spec 15 does not specify this endpoint at all. The spec only says "publishes each envelope to the JetStream stream" on reconnect (Section 10.4), implying direct NATS publish rather than HTTP replay.

5. **Capabilities probe endpoint.** The research brief (R1) recommends `GET /api/v1/capabilities`, and the implementation plan Phase 1 mentions probing `/api/v1/health` or `/api/v1/capabilities`. Spec 15 Section 14 does not define a capabilities endpoint; the probe just uses health checks.

---

## 2. Consistency Review

### 2.1 PolicyEngineLike Contract Preservation

**Verdict: Preserved correctly.**

The `PolicyEngineLike` interface (`engine.ts:3-6`) has two members: `evaluate(event: PolicyEvent): Promise<Decision> | Decision` and `redactSecrets?(value: string): string`. Both Spec 15 (Section 14.1) and the implementation plan (Phase 1) correctly wrap existing engines without modifying the interface. The `createAdaptiveEngine()` returns a `PolicyEngineLike`.

### 2.2 Spec 15 vs. Implementation Plan: AdaptiveEngineOptions Divergence

**Finding: The interface designs differ significantly between Spec 15 and the implementation plan.**

Spec 15 Section 14.1 defines:
```typescript
interface AdaptiveEngineOptions {
  local: PolicyEngineLike;       // pre-constructed engine
  remote: PolicyEngineLike;      // pre-constructed engine
  initialMode?: string;
  probeIntervalMs?: number;
  onModeChange?: (...) => void;
}
```

Implementation plan Phase 1 defines:
```typescript
interface AdaptiveEngineOptions {
  local: { hushPath?, policyRef, ... };    // raw config
  desktopAgent?: { enabled?, baseUrl?, ... };  // desktop agent probe
  enterprise?: { baseUrl, token?, ... };       // enterprise config
  receiptQueue?: { maxSize?, persistPath? };
  onModeChange?: (...) => void;
}
```

The spec takes pre-constructed `PolicyEngineLike` instances; the implementation plan takes raw configuration and constructs engines internally. The spec has no `desktopAgent` concept (only standalone/connected/headless); the implementation plan adds a fourth mode (`desktop-agent`). The spec has three modes; the plan has four (`standalone | desktop-agent | enterprise | degraded`).

**Severity: High.** These must be reconciled before implementation begins.

### 2.3 StrikeCellOptions Compatibility

**Verdict: Compatible.** The remote engine's `StrikeCellOptions` (`strike-cell.ts:4-16`) accepts `baseUrl`, `token`, `timeoutMs`, `fallback`, and `offlineFallback`. Spec 15 wraps this engine rather than modifying it; the adaptive engine constructs a `hushd-engine` StrikeCell with `offlineFallback: false` (since the adaptive layer handles fallback itself). This is correct.

### 2.4 failClosed() Usage

**File:** `engine-response.ts:87-95`

The `failClosed()` function returns `{ status: 'deny', reason_code: 'ADC_GUARD_ERROR', reason: 'engine_error', message }`. Both Spec 15 (Section 6.6) and the implementation plan reference fail-closed behavior. However, neither document specifies whether the adaptive engine should use the existing `failClosed()` utility or create its own. The implementation plan's Phase 1 acceptance criteria says "All error paths produce fail-closed deny decisions" but does not explicitly import or reference `failClosed` from `adapter-core`.

**Severity: Low.** The intent is correct; implementation should use the existing `failClosed()` utility.

### 2.5 NATS Auth Alignment

**Verdict: Consistent.** The `NatsAuthConfig` from `nats_transport.rs` has `creds_file`, `token`, `nkey_seed` with priority order creds_file > token > nkey_seed. Spec 15 Section 6.2 and the implementation plan Phase 2 (`NatsSettings`) both align with this priority order.

### 2.6 `details` Field Type

**File:** `types.ts:146` -- `details?: unknown`

The `Decision` type defines `details` as `unknown`. The existing remote engine (`strike-cell.ts:47-55`) spreads decision details and adds `provenance: DEGRADED_PROVENANCE`. Spec 15 Section 14.3 defines enriched provenance in the same location. This works, but:

- If the upstream engine returns `details` that already contains a `provenance` key, it will be overwritten.
- The type is `unknown`, so there is no compile-time guarantee that the merge is safe.

**Severity: Medium.** The spec should define the merge semantics explicitly (e.g., `details.provenance` is reserved for the adaptive engine; upstream engines must not use this key).

---

## 3. Security Review

### 3.1 Enrollment Token Replay

**Severity: Medium**
**Location:** Spec 15 Section 7.4

The enrollment token format is `cset_<base64url(tenant_id + random + expiry + hmac)>`. It is single-use and time-limited (24h). The HMAC prevents forgery. However:

- **Token-in-transit risk:** The token is delivered out-of-band (email, CLI output, dashboard copy). If intercepted, an attacker can enroll a rogue agent before the legitimate agent does.
- **No binding to agent identity:** The enrollment token is not bound to a specific machine or agent ID. Any device with the token can enroll.

**Suggested fix:** Consider binding the enrollment token to a device fingerprint or requiring a secondary verification step (e.g., the admin confirms the enrollment on the dashboard before credentials are issued).

### 3.2 Enrollment via NATS -- Chicken-and-Egg Problem

**Severity: Critical**
**Location:** Spec 15 Section 7.3, Section 5.6

The enrollment protocol (Section 7.3) shows the enrollment request sent via NATS subject `clawdstrike.<tenant>.agent.enroll`. But per Section 6.5, NATS access requires tenant-scoped credentials. An unenrolled agent does not have NATS credentials yet -- that is precisely what enrollment is supposed to provision.

The spec heading says "via NATS or HTTP" but the protocol diagram only shows the NATS path. The implementation plan (Phase 3) correctly uses HTTP (`POST /api/v1/agents/enroll` to cloud-api), which avoids this problem.

**Suggested fix:** Spec 15 should explicitly define enrollment as an HTTP-only operation against the Cloud API, not a NATS request. The NATS `agent.enroll` subject should be removed from the subject inventory or marked as an internal enterprise-side event.

### 3.3 NATS Tenant Isolation

**Severity: Low**
**Location:** Spec 15 Section 6.5

Tenant isolation relies on NATS account configuration. The spec correctly states that cross-account access is denied by NATS server configuration. However, the spec does not define the NATS server configuration itself (that is Spec 09/14 territory). Assuming proper NATS account isolation, this is secure.

**Note:** Spec 14 Section 4.2 shows NATS account config with an `exports` section that exports `clawdstrike.spine.envelope.>` from tenant accounts. This could inadvertently expose tenant envelopes to the system account. Verify that the export is consumed only by authorized internal services.

### 3.4 Kill Switch Spoofing

**Severity: Low**
**Location:** Spec 15 Section 11.5

Posture commands are delivered via NATS request/reply to `clawdstrike.<tenant>.posture.command.<agent-id>`. Within a tenant's NATS account, any entity with publish permission to this subject can issue a kill switch. The spec does not define per-subject ACLs within the tenant account.

**Suggested fix:** Define NATS subject ACLs so that only the enterprise Cloud API (or a specific service identity) can publish to `posture.command.*` subjects. Agent credentials should have subscribe-only permission on their command subject.

### 3.5 Approval Response Forgery

**Severity: Medium**
**Location:** Spec 15 Section 12.4

Approval responses are published to `clawdstrike.<tenant>.approval.response.<request-id>`. The response format includes `responded_by` and `status: "approved"`. However:

- The response is not cryptographically signed.
- Any entity within the tenant's NATS account that can publish to the approval response subject can forge an approval.
- The `request_id` may be guessable (UUID format, but UUIDs are predictable if the generation method is known).

**Suggested fix:** Approval responses should be wrapped in a Spine signed envelope, signed by the enterprise service's keypair. The agent should verify the envelope signature before accepting the response.

### 3.6 Store-and-Forward Queue Tampering

**Severity: Low**
**Location:** Spec 15 Section 10.4, Implementation Plan Phase 1

Offline receipts are stored as individual JSON files at `~/.clawdstrike/offline_queue/`. These files contain signed Spine envelopes. Since the envelopes are Ed25519-signed with the agent's keypair, tampering with the file contents would invalidate the signature. Enterprise-side verification (`verify_envelope`) would catch this.

However, an attacker with local filesystem access could:
- Delete queued receipts (denial of audit).
- Inject forged envelopes (but these would fail signature verification).

**Verdict: Acceptable risk.** Local filesystem access already implies full agent compromise.

### 3.7 NATS Credentials Storage

**Severity: Medium**
**Location:** Spec 15 Section 7.5, Implementation Plan Phase 3

NATS credentials are stored at `~/.clawdstrike/nats.creds` with chmod 600. The agent private key is at `~/.clawdstrike/agent.key`. Neither document specifies:

- Whether these files should be encrypted at rest.
- What happens if the file permissions are loosened (the agent should verify permissions at startup).
- Whether the credential file path is validated to prevent path traversal.

**Suggested fix:** Add a startup check that verifies file permissions are 600 or stricter. Document that at-rest encryption is recommended for enterprise deployments. Validate that the configured credential paths are within `~/.clawdstrike/`.

---

## 4. Fail-Closed Audit

| Scenario | Current Handling (Spec 15) | Recommendation |
|----------|---------------------------|----------------|
| Enterprise hushd returns HTTP 4xx/5xx | Fail closed (deny). Section 6.6. | Correct. Already handled by existing `hushd-engine` (non-connectivity errors are not treated as fallback triggers). |
| Enterprise hushd unreachable (ECONNREFUSED) | Degrade to local engine. Section 6.6. | Correct. Local engine itself fails closed on error. |
| NATS unreachable during policy sync | "Queue receipts locally; continue local evaluation." Section 6.6. | **Incomplete.** What if NATS disconnect happens during initial policy fetch on first connect? The agent has no cached policy. The spec should specify: if no cached policy exists and NATS is unreachable, the agent uses the local `policy_ref` from config (standalone behavior). |
| Enrollment fails mid-way (e.g., NATS creds written but agent crashes before mode transition) | Not specified. | **Missing.** The enrollment flow (Section 7.3, steps 7-9) has no atomicity guarantee. If the agent crashes after writing creds but before transitioning mode, the next startup should detect orphaned credentials and either retry enrollment or clean up. |
| Heartbeat endpoint unreachable | Heartbeats are fire-and-forget. Section 8.5. | **Acceptable but underspecified.** Missed heartbeats cause the enterprise to mark the agent as stale/dead. The agent should also track consecutive heartbeat failures and emit a local warning. |
| Posture command times out (no ACK in 10s) | Enterprise marks agent unresponsive, retries 3x. Section 11.6. | Correct from enterprise side. Agent-side behavior not specified: if the agent receives a command during a period of high load and cannot process it in time, it should still apply the command on eventual processing (not silently drop it). |
| Approval response corrupted/malformed | Not specified. | **Missing.** If the approval response JSON is malformed, the agent should treat it as a timeout (deny). This is implied by fail-closed philosophy but not stated. |
| Approval response arrives after timeout | Not specified. | **Missing.** If the agent already generated a local timeout-deny, and a late approval arrives, the agent should discard the late response. The implementation plan Phase 4 does not address this race. |
| Policy sync receives corrupt YAML | Reject; keep last known good policy. Section 9.5. | Correct. Explicit checksum + schema validation. |
| Local hush CLI engine crashes | `failClosed(error)`. Existing behavior in `engine-response.ts:87-95`. | Correct. |
| Receipt queue overflow | Oldest first eviction. Section 10.4. | **Acceptable but lossy.** Evicted receipts are permanently lost. Consider logging an alert when eviction occurs. |

---

## 5. Over-Engineering Concerns

### 5.1 Four-Mode State Machine in Implementation Plan

**Location:** Implementation Plan Phase 1, Mode State Machine

The implementation plan introduces a `desktop-agent` mode that is absent from Spec 15. Spec 15 has three deployment modes: standalone, connected, headless. The plan adds a fourth mode (`desktop-agent`) for the case where the desktop agent is running but enterprise is not configured.

This additional mode adds complexity to the state machine without clear user value. The desktop agent's API server is functionally equivalent to a local hushd -- both provide HTTP-based policy evaluation. The probe logic for desktop agent (`GET http://127.0.0.1:9878/api/v1/health`) is an optimization for the specific case where the desktop agent mediates access to a local hushd.

**Suggestion:** Consider whether the `desktop-agent` mode can be folded into the existing `standalone` mode with an optional HTTP endpoint preference. If the desktop agent is running, the engine uses it; if not, it falls back to CLI. This is a simpler two-tier preference within standalone mode rather than a separate state.

### 5.2 File-Based Offline Queue Persistence

**Location:** Spec 15 Section 10.4, Implementation Plan Phase 1

The store-and-forward queue stores each envelope as an individual file (`<seq>-<envelope_hash>.json`). With a default max of 10,000 entries, this means up to 10,000 individual files in a directory.

- On macOS HFS+/APFS, directory listing performance degrades significantly above ~10,000 entries.
- File-per-envelope creates high I/O overhead for drain operations.

**Suggestion:** Use a single append-only file (JSONL format) or an embedded database (e.g., SQLite) for the offline queue. This is simpler and more performant than individual files.

### 5.3 Dual Publication (Section 13.5)

**Location:** Spec 15 Section 13.5

Both the agent and hushd publish envelopes for the same decision. This provides dual-attestation, which is valuable for high-security environments. However, it doubles the telemetry volume and adds complexity to the audit consumer (which must correlate agent and server envelopes for the same event).

**Verdict:** Not over-engineering -- dual attestation is a legitimate security feature. But the spec should clarify whether dual publication is always-on or configurable. For most deployments, server-side publication alone is sufficient.

---

## 6. Phase Ordering Review

### Phase 1 (engine-adaptive, TypeScript)

- **Dependencies:** None beyond existing packages.
- **LOC estimate:** ~1,400. Reasonable for a new package with state machine, probing, queue, and tests.
- **Test strategy:** Adequate. Mocked fetch and engine delegation.
- **Assessment:** Well-scoped. Can start immediately.

### Phase 2 (NATS sync, Rust/Desktop Agent)

- **Dependencies:** Phase 1 (listed), but actually independent. The plan itself notes "Phases 1 and 2 can run in parallel."
- **LOC estimate:** ~1,150. Reasonable for NATS client, KV watcher, telemetry publisher.
- **Test strategy:** Good. Includes embedded NATS server for integration tests.
- **Assessment:** Should explicitly state it does NOT depend on Phase 1. The dependency listed ("Phase 1 complete") is incorrect -- the plan's own summary says they can run in parallel.

### Phase 3 (Enrollment + Heartbeat)

- **Dependencies:** Phase 2 (NATS client exists).
- **LOC estimate:** ~1,250. Reasonable.
- **Test strategy:** Good. Includes embedded PostgreSQL.
- **Finding:** The stale agent detector (Phase 3) uses a 5-minute threshold, but Spec 15 Section 8.4 defines 120s (stale) and 300s (dead). These should be reconciled. The implementation plan should use the spec's thresholds.

### Phase 4 (Posture Commands + Approval)

- **Dependencies:** Phase 3 (enrollment + NATS).
- **LOC estimate:** ~1,400. Reasonable.
- **Test strategy:** Includes security tests for tenant isolation.
- **Assessment:** Well-scoped. Correctly depends on Phase 3.

### Phase 5 (hushd -> Spine Integration)

- **Dependencies:** Phase 2 (NATS infrastructure). The plan lists Phase 2 as the dependency, not Phase 4.
- **Finding:** Phase 5 could potentially run in parallel with Phases 3-4, since it operates on hushd (Rust service) and cloud-api (audit consumer), which are independent of the desktop agent enrollment/command work.
- **LOC estimate:** ~1,250. Reasonable.
- **Optimization:** Consider running Phase 5 in parallel with Phase 3. The only shared dependency is Phase 2 (NATS client). The hushd Spine publisher and the cloud-api audit consumer are independent of enrollment and posture commands.

### Parallelization Opportunity

```
Phase 1 (TS)  ──────────────────────►
Phase 2 (Rust NATS)  ──────────────────────►
                          Phase 3 (enrollment)  ──────────►
                          Phase 5 (spine)  ──────────────────►  (can parallel with 3)
                                                Phase 4 (commands)  ──────────►
```

This could save ~2-3 engineer-days by parallelizing Phase 5 with Phase 3.

---

## 7. Spec Conflicts

### 7.1 Spec 15 vs. Spec 09 (Helm Chart)

**No direct conflicts.** Spec 15 defines agent-side protocols; Spec 09 defines enterprise-side Kubernetes deployment. They are complementary.

**Note:** Spec 15 introduces new NATS streams and KV buckets (Section 5) that are not referenced in Spec 09's Helm chart values. The Helm chart's `nats` section should eventually support pre-provisioning of the adaptive SDR subjects.

### 7.2 Spec 15 vs. Spec 14 (ClawdStrike Cloud)

**Minor conflict: NATS subject naming.**

Spec 14 Section 4.2 uses subject prefix `clawdstrike.spine.envelope.>` for tenant exports. Spec 15 Section 5 uses `clawdstrike.<tenant>.telemetry.receipts`. These are different naming patterns:

- Spec 14: `clawdstrike.spine.envelope.>`  (no tenant prefix in subject; isolation via NATS accounts)
- Spec 15: `clawdstrike.<tenant>.telemetry.receipts`  (tenant ID embedded in subject name)

These approaches are redundant when NATS account isolation is in place. Embedding tenant ID in the subject name AND using per-tenant accounts means the subject path duplicates the isolation boundary.

**Suggested fix:** Since NATS accounts provide isolation, the subject pattern should omit the tenant prefix: `clawdstrike.telemetry.receipts` (within the tenant's account). This aligns with Spec 14's approach and simplifies subject management.

**Minor conflict: Agent registration endpoint.**

Spec 14 defines `POST /agents` (Section 4.3, `register_agent`). The implementation plan Phase 3 uses `POST /api/v1/agents/enroll`. These are different endpoints for related but distinct operations:

- `POST /agents` (Spec 14): Register an agent with known public key.
- `POST /api/v1/agents/enroll` (Impl Plan): One-time enrollment with token.

This is not a true conflict -- enrollment is a higher-level operation that includes registration. But the routing patterns should be consistent. Spec 14 uses `register_agent` at the route level; the implementation plan introduces a new `/enroll` route.

**Suggested fix:** Document that enrollment (`POST /api/v1/agents/enroll`) is the client-facing API, and it internally calls the registration logic from Spec 14. This avoids two separate entry points for agent creation.

### 7.3 Spec 15 vs. IAM Plans

**No conflicts.** Spec 15 explicitly defers full IAM to a separate workstream. The enrollment protocol uses HMAC tokens as a minimal auth contract that can be replaced by IAM later. The RBAC roles from the IAM plan (`rbac.md`) are not referenced in Spec 15, which is appropriate since Spec 15 focuses on agent-to-enterprise protocols rather than user access control.

### 7.4 Naming Convention Consistency

- **Envelope schema:** Spec 15 Section 10.2 uses `"aegis.spine.envelope.v1"` and `"aegis:ed25519:"` issuer prefix. This is consistent with the current code but inconsistent with the project's "clawdstrike" branding. Research brief contradiction C6 identified this. Spec 15 Open Question #1 correctly defers this to a separate spec.

- **Fact type:** Spec 15 Section 13.3 uses `"clawdstrike.decision.v1"` as the fact type within the envelope, while the envelope schema itself uses the `aegis` prefix. This mixed naming (aegis envelope + clawdstrike fact) is confusing but pragmatic.

---

## 8. Missing Items

### Priority 1 (Must address before implementation)

1. **Enrollment bootstrap path.** Resolve the NATS vs. HTTP chicken-and-egg problem (Finding 3.2). Define enrollment as HTTP-only.

2. **AdaptiveEngineOptions reconciliation.** The spec and implementation plan define different interfaces (Finding 2.2). Choose one.

3. **Enrollment atomicity.** Define recovery behavior for partial enrollment (Fail-Closed Audit, enrollment mid-way failure).

### Priority 2 (Should address)

4. **Approval response authentication.** Approval responses should be signed (Finding 3.5).

5. **NATS subject ACLs for posture commands.** Define intra-tenant publish/subscribe permissions (Finding 3.4).

6. **Late approval response handling.** Define behavior when approval arrives after timeout (Fail-Closed Audit).

7. **Stale threshold reconciliation.** Align implementation plan Phase 3 (5 min) with Spec 15 Section 8.4 (120s stale, 300s dead).

8. **NATS subject naming consistency.** Reconcile Spec 14 and Spec 15 naming patterns (Finding 7.2).

### Priority 3 (Nice to have)

9. **G9 fix (fragile posture extraction).** Add schema validation for hushd session response posture field.

10. **Port configurability.** Promote from open question to spec requirement (address G8).

11. **Offline queue format.** Consider JSONL or SQLite instead of file-per-envelope (Finding 5.2).

12. **Dual publication configurability.** Make agent-side telemetry publication configurable (Finding 5.3).

13. **Migration strategy.** Document how existing standalone deployments upgrade to connected mode (no current migration path defined).

14. **Monitoring and observability.** Neither the spec nor the plan defines metrics, dashboards, or alerting for the adaptive SDR components themselves (e.g., mode transition rate, queue depth, probe latency).

15. **Performance/latency impact.** The adaptive engine adds a probe check and mode selection to every evaluation path. While this is likely <1ms, neither document quantifies the expected overhead.

---

## 9. Actionable Items Summary

| # | Target | Severity | Action Required |
|---|--------|----------|-----------------|
| 1 | D2 (Spec 15 S7.3, S5.6) | Critical | Change enrollment protocol from NATS to HTTP-only. Remove or relabel `clawdstrike.<tenant>.agent.enroll` NATS subject. The agent cannot use NATS before it has NATS credentials. |
| 2 | D2 + D3 | High | Reconcile `AdaptiveEngineOptions` between Spec 15 (takes `PolicyEngineLike` instances) and Implementation Plan (takes raw config). Decide whether the adaptive engine constructs sub-engines internally or receives them pre-constructed. |
| 3 | D2 (Spec 15 S7) | High | Add enrollment atomicity guarantee. Define behavior when enrollment fails between credential write (step 7) and mode transition (step 8). Recommend: on startup, detect orphaned credentials and retry enrollment or roll back. |
| 4 | D2 (Spec 15 S12) | Medium | Require approval responses to be wrapped in Spine signed envelopes. Agent must verify the envelope signature before accepting an approval. |
| 5 | D2 (Spec 15 S11, S6) | Medium | Define NATS subject ACLs within tenant accounts. Posture command subjects should be publish-restricted to enterprise services; agents should have subscribe-only permission. |
| 6 | D2 (Spec 15 S12) | Medium | Define behavior for late approval responses that arrive after the timeout deny has already been issued. Recommend: discard the late response and log a warning. |
| 7 | D3 (Phase 3) | Medium | Align stale agent threshold with Spec 15: use 120s for stale, 300s for dead, not 5 minutes. |
| 8 | D2 (Spec 15 S5) + Spec 14 | Medium | Reconcile NATS subject naming. Either embed tenant ID in subjects (Spec 15) or rely solely on NATS account isolation (Spec 14). Do not mix both approaches. |
| 9 | D2 (Spec 15 S14) | Medium | Define merge semantics for `decision.details.provenance`. Document that the `provenance` key within `details` is reserved for the adaptive engine. |
| 10 | D2 (Spec 15) | Low | Address G9: add schema validation for hushd session response posture field to prevent silent breakage. |
| 11 | D2 (Spec 15 S2, S15) | Low | Promote port configurability from open question to spec requirement. Add config.yaml `agent.port` field and startup conflict detection. |
| 12 | D3 (Phase 2) | Low | Remove incorrect dependency on Phase 1. Phase 2 is Rust-only and does not depend on the TypeScript engine-adaptive package. The plan's own summary acknowledges they can run in parallel. |
| 13 | D3 (Phase 5) | Low | Consider parallelizing Phase 5 with Phase 3. The hushd Spine publisher is independent of desktop agent enrollment. Only shared dependency is Phase 2 (NATS). |
| 14 | D2 (Spec 15) | Low | Add a section on monitoring/observability: mode transition metrics, queue depth metrics, probe latency metrics, and recommended alerting thresholds. |
| 15 | D3 (Phase 1) | Low | Consider JSONL or SQLite for offline queue instead of file-per-envelope. Directory listing with 10K files has performance implications on macOS. |
