# `edr/receipt/` Family Extraction Plan

Target crate: `crates/libs/clawdstrike-policy-event`
Module under audit: `crates/libs/clawdstrike-policy-event/src/edr/receipt/`

---

## Summary

| Metric | Value |
|---|---|
| `mod.rs` lines | 6,402 |
| `evidence.rs` lines | 173 |
| `families.rs` lines | 26 |
| `inputs/` lines (15 files) | 351 |
| **Total directory LOC** | **6,952** |
| Public `for_*` constructors on `EndpointDecisionReceipt` | **19** |
| Family enum variants (`EndpointDecisionReceiptFamily`) | 17 (`SensorState`, `ProviderDegradation`, `Observation`, `PolicyDecision`, `PolicyDelta`, `GraphSlice`, `Detection`, `Simulation`, `ResponseRequest`, `ResponseExecution`, `ResponseRollback`, `ResponseAcknowledgement`, `DeceptionMaterialization`, `DeceptionCleanup`, `DeceptionRotation`, `EvidenceBundleManifest`, `PrivacyReport`) |
| Constructor LOC (line 99–1624 of `mod.rs`) | ~1,526 lines |
| Validator LOC (line 1626–6402 of `mod.rs`) | ~4,776 lines |
| Free helper / validator functions | **94** (lines 2149–6402) |
| One God-method (`validate()`) | 1,626 → 2,067 = **442 lines**, dispatches on `receipt_family` for every family |
| **Recommended target file count after split** | **~14 files** (1 `mod.rs` shell + 1 `trait.rs` + 1 `common.rs` + 11 family modules) |

The taxonomy is not "file_*, network_*, process_*" as the prompt hypothesized. This module is the **EDR endpoint-decision receipt builder** keyed to `EndpointDecisionReceiptFamily`. The 19 `for_*` constructors map 1:1 to the 17 family variants (Response has 4 sub-constructors that share a family group). Bloat is dominated by **per-family validator/ID-derivation free functions**, not by constructor bodies.

---

## Family Inventory

Counts: constructor LOC measured by distance to next `pub fn for_*`. Validator LOC is sum of `require_*`, `*_id_from_*`, and helper free functions grouped by family prefix from `grep -n` of `mod.rs`. "Sample fns" abbreviates names.

| Family | `for_*` count | Constructor LOC | Validator/helper LOC | sample fns | proposed file path |
|---|---:|---:|---:|---|---|
| **sensor_state** | 1 | 86 | ~115 | `for_sensor_state`, `require_sensor_state_evidence` | `families/sensor_state.rs` |
| **telemetry_privacy** (a.k.a. PrivacyReport) | 1 | 83 | ~195 | `for_telemetry_privacy`, `telemetry_privacy_report_id_from_*` (×3), `require_privacy_report_evidence` | `families/telemetry_privacy.rs` |
| **provider_degradation** | 1 | 58 | ~215 | `for_provider_degradation`, `provider_degradation_id_from_*` (×3), `require_provider_degradation_*` (×2), `endpoint_provider_full_disk_access_evidence_value` | `families/provider_degradation.rs` |
| **observation** | 1 | 70 | ~190 | `for_observation`, `observation_receipt_id_from_*` (×3), `require_observation_evidence` | `families/observation.rs` |
| **policy_decision** | 1 | 70 | ~125 | `for_policy_decision`, `policy_decision_id_from_*` (×3), `require_policy_decision_evidence` | `families/policy_decision.rs` |
| **graph_slice** | 1 | 55 | ~60 | `for_graph_slice`, `require_graph_slice_evidence`, `require_graph_slice_content_hash_evidence`, `require_subgraph_reference` | `families/graph_slice.rs` |
| **detection** | 1 | 69 | ~135 | `for_detection`, `require_detection_evidence`, `require_detection_graph_reference`, `detection_severity_label`, `detection_finding_id_from_signed_fields` | `families/detection.rs` |
| **evidence_bundle_manifest** | 1 | 43 | ~50 | `for_evidence_bundle_manifest`, `require_evidence_bundle_manifest_evidence` | `families/evidence_bundle.rs` |
| **simulation** | 1 | 64 | ~115 | `for_simulation`, `require_simulation_evidence`, `require_graph_policy_simulation_evidence`, `graph_policy_simulation_id_from_signed_fields`, `simulation_breakage_score_from_confidence` | `families/simulation.rs` |
| **deception** (materialization + cleanup + rotation) | 3 | 315 (87+95+133) | ~795 | `for_deception_materialization`, `for_deception_cleanup`, `for_deception_rotation`, `deception_{materialization,cleanup,rotation}_id_from_*` (×9), `require_deception_*_evidence` (×3), `deception_cleanup_dry_run_from_decision`, `deception_rotation_dry_run_from_decision` | `families/deception.rs` |
| **response** (request + execution + rollback + acknowledgement) | 4 | 377 (55+112+72+138) | ~1,485 | `for_response_request`, `for_response_execution`, `for_response_rollback`, `for_response_acknowledgement`; `require_response_*_evidence` (×20+), `response_action_id_from_*` (×2), `response_execution_id_from_*` (×4), `response_acknowledgement_id_from_*` (×3), `response_rollback_id_from_*` (×3), `response_effect_evidence_value`, `response_*_effect_binding_digest_*` (×6), `response_execution_status_from_decision`, `response_acknowledgement_status_from_decision`, `response_execution_transition_id_*` (×2), `response_execution_bundle_id_from_signed_fields`, `expected_response_rollback_ref`, `expected_live_response_rollback_ref`, `require_control_*` (×3) | `families/response.rs` |
| **policy_event_replay** | 1 | 62 | ~95 | `for_policy_event_replay`, `policy_event_replay_id_from_evidence`, `require_policy_event_replay_evidence` | `families/policy_event_replay.rs` |
| **policy_event_impact** | 1 | 74 | ~100 | `for_policy_event_impact`, `policy_event_impact_id_from_evidence`, `require_policy_event_impact_evidence`, `require_policy_event_stream_graph_reference` | `families/policy_event_impact.rs` |
| **policy_delta** | 1 | 100 | ~250 | `for_policy_delta`, `policy_delta_id_from_evidence`, `require_policy_delta_*_evidence` (×4), `policy_delta_stage_from_hash`, `policy_delta_receipt_enforcement_action_supported`, `policy_delta_operation_from_title`, `require_policy_delta_graph_reference` | `families/policy_delta.rs` |
| _(shared)_ | — | — | ~360 | `require_field_eq`, `require_nonempty`, `require_optional_nonempty`, `require_nonzero`, `require_confidence`, `require_receipt_evidence`, `require_evidence_value_hash`, `require_boolean_hashed_evidence`, `require_nonempty_hashed_evidence`, `evidence_value_hash`, `require_evidence_hash_not_empty`, `hex_strings_match`, `trim_hex_prefix`, `camel_debug_to_snake`, `reconstruct_path` | `common.rs` |
| _(struct + impl shell)_ | — | 50 (struct) + ~120 (validate dispatch + `to_receipt`/`sign_with`/`receipt_id`/`to_verdict`) | — | `EndpointDecisionRecord`, `EndpointDecisionReceipt`, `validate()`, `to_receipt()`, `sign_with()`, `receipt_id()`, `to_verdict()` | `mod.rs` |
| **TOTAL** | **19** | **~1,576** | **~4,285** | | |

Notes:
- "Family" in the trait sense groups by `EndpointDecisionReceiptFamily` variant. Response and Deception families contain multiple `for_*` because the family covers a lifecycle of related receipts that share validators (the existing `validate()` dispatch uses `matches!(family, Request|Execution|Rollback|Ack)` blocks).
- `for_policy_delta` is the largest constructor (100 lines) because of optional-evidence push branches; `for_response_acknowledgement` is the second-largest at 138 lines.
- `validate()` itself contains 17 `if self.receipt_family == X` branches plus one `matches!()` group — this is the natural seam for extraction.

---

## Common Patterns

Every `for_*` follows the same five-step shape. Sample, condensed from `for_response_execution` (mod.rs:645–754):

```rust
pub fn for_response_execution(input: EndpointResponseExecutionReceiptInput<'_>) -> Self {
    // 1. Derive graph slice / subgraph reference from input.
    let graph_ref =
        EndpointGraphReference::for_subgraph(&input.execution.root_node_id, input.graph);

    // 2. Derive actor + actor content hash (used as evidence).
    let actor = input.actor.with_endpoint_id_if_missing(input.endpoint_id);
    let actor_hash = endpoint_decision_actor_content_hash(&actor);

    // 3. Build the receipt envelope (schema version, family tag, clock,
    //    signer stub, policy/sensor_state passthrough, decision record).
    Self {
        schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_family: EndpointDecisionReceiptFamily::ResponseExecution,
        local_sequence: input.local_sequence,
        clock: EndpointClockState::default(),
        signer: EndpointReceiptSigner {
            signer_identity: input.signer_identity.to_string(),
            signer_public_key: None,
        },
        actor,
        policy: input.policy,
        sensor_state: input.sensor_state,
        decision: EndpointDecisionRecord { /* family-specific finding_id, rule_id, action, passed, ttl */ },
        graph: graph_ref,

        // 4. Push family-specific evidence keys (always
        //    `EndpointReceiptEvidence::hashed("camelCaseKey", value)`).
        evidence: {
            let mut evidence = vec![
                EndpointReceiptEvidence::hashed("responseActionId", &input.execution.action_id),
                EndpointReceiptEvidence::hashed("executionId",      &input.execution.execution_id),
                /* … many family-specific keys … */
            ];
            // 5. Optionally push per-effect / per-control / per-stage repeated evidence.
            for effect in &input.execution.effects {
                evidence.push(EndpointReceiptEvidence::hashed(
                    format!("executionEffect:{}", effect.effect_id),
                    response_effect_evidence_value(effect),
                ));
            }
            evidence
        },
    }
}
```

The matching validator branch in `EndpointDecisionReceipt::validate()` (mod.rs:1973–2001) is symmetric:

```rust
if self.receipt_family == EndpointDecisionReceiptFamily::ResponseExecution {
    require_response_execution_id_evidence(&self.evidence, &self.decision, …)?;
    require_response_execution_status_evidence(&self.decision, &self.evidence)?;
    require_response_reason_evidence(&self.evidence)?;
    require_response_execution_evidence_bundle_evidence(&self.evidence, &self.decision, …)?;
    require_response_execution_dry_run_evidence(&self.evidence)?;
    require_response_execution_actor_evidence(&self.evidence)?;
    require_response_effect_count_evidence(&self.evidence, "executionEffect:", …)?;
    require_response_effect_evidence_hashes(&self.evidence, "executionEffect:", …)?;
    require_response_execution_effect_type_evidence(&self.decision, &self.evidence)?;
}
```

Every family thus has the pair *(builder constructor, family-scoped validator block)*. The pair currently lives in two different parts of one 6.4kLOC file, with all helper IDs/validators jumbled together in lines 2149–6402.

---

## Proposed `ReceiptFamily` Trait

The trait formalises the (builder, validator, family-tag) triple and lets the dispatch in `validate()` become an O(1) trait call. It lives in a new `crates/libs/clawdstrike-policy-event/src/edr/receipt/family_trait.rs`.

```rust
// crates/libs/clawdstrike-policy-event/src/edr/receipt/family_trait.rs
use anyhow::Result;

use super::{
    EndpointDecisionReceipt, EndpointDecisionReceiptFamily,
    EndpointReceiptEvidence,
};

/// Every endpoint decision receipt family implements this trait.
///
/// `Input<'a>` is the strongly-typed reference bundle in `receipt/inputs/*.rs`
/// (e.g. `EndpointResponseExecutionReceiptInput<'a>`). The constructor lives
/// on the implementor and produces a fully-formed `EndpointDecisionReceipt`.
/// The validator runs in `EndpointDecisionReceipt::validate()` after the
/// common envelope checks pass.
pub trait ReceiptFamily {
    /// Reference bundle consumed by the constructor.
    type Input<'a>;

    /// The `EndpointDecisionReceiptFamily` enum variant this impl owns.
    const FAMILY: EndpointDecisionReceiptFamily;

    /// Build a fully-populated, unsigned `EndpointDecisionReceipt` for this
    /// family. Constructors are pure: no I/O, no time except `Utc::now()` in
    /// downstream signers, no validation. Validation is `validate_family`.
    #[must_use]
    fn build(input: Self::Input<'_>) -> EndpointDecisionReceipt;

    /// Family-specific validation. Called by
    /// `EndpointDecisionReceipt::validate()` after the shared envelope
    /// checks (schema version, signer, policy hash, sensor providers,
    /// `require_receipt_evidence`) succeed.
    ///
    /// Must NOT re-check things that `validate()`'s envelope block
    /// already enforces.
    fn validate_family(receipt: &EndpointDecisionReceipt) -> Result<()>;

    /// Optional hook: families with sub-variants (Response{Request,
    /// Execution, Rollback, Ack}) can override to share envelope checks
    /// before sub-variant dispatch. Default = no-op.
    fn validate_family_group(_receipt: &EndpointDecisionReceipt) -> Result<()> {
        Ok(())
    }

    /// Evidence keys this family is REQUIRED to emit. Used for cross-checks
    /// and (future) policy-driven evidence-schema linting. Default = empty
    /// (families can opt in incrementally).
    fn required_evidence_keys() -> &'static [&'static str] {
        &[]
    }
}

/// Marker for families that own multiple `for_*` constructors that share
/// validators (Response family today). Used by `validate()` to call
/// `validate_family_group` once per group before sub-variant dispatch.
pub trait ReceiptFamilyGroup {
    fn family_group(family: &EndpointDecisionReceiptFamily) -> bool;
    fn validate_group(receipt: &EndpointDecisionReceipt) -> Result<()>;
}
```

### Sample impl: `ResponseExecutionReceipt`

The Response family is the biggest (~1.86kLOC) and exercises every trait method. It would live in `families/response.rs`:

```rust
// crates/libs/clawdstrike-policy-event/src/edr/receipt/families/response.rs
use super::super::common::*;
use super::super::family_trait::{ReceiptFamily, ReceiptFamilyGroup};
use super::super::{
    EndpointDecisionReceipt, EndpointDecisionReceiptFamily, EndpointDecisionRecord,
    EndpointGraphReference, EndpointReceiptEvidence, EndpointReceiptSigner,
    EndpointResponseExecutionReceiptInput, ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION,
};

pub struct ResponseRequestReceipt;
pub struct ResponseExecutionReceipt;
pub struct ResponseRollbackReceipt;
pub struct ResponseAcknowledgementReceipt;

impl ReceiptFamily for ResponseExecutionReceipt {
    type Input<'a> = EndpointResponseExecutionReceiptInput<'a>;
    const FAMILY: EndpointDecisionReceiptFamily =
        EndpointDecisionReceiptFamily::ResponseExecution;

    fn build(input: Self::Input<'_>) -> EndpointDecisionReceipt {
        // Body verbatim from current `EndpointDecisionReceipt::for_response_execution`
        // (mod.rs:645–754). No semantic change.
        let graph_ref =
            EndpointGraphReference::for_subgraph(&input.execution.root_node_id, input.graph);
        // … 100+ lines copied unchanged …
    }

    fn validate_family(receipt: &EndpointDecisionReceipt) -> Result<()> {
        require_response_execution_id_evidence(
            &receipt.evidence, &receipt.decision,
            receipt.graph.graph_slice_id.as_deref().unwrap_or_default(),
            receipt.graph.content_hash.as_deref(),
        )?;
        require_response_execution_status_evidence(&receipt.decision, &receipt.evidence)?;
        require_response_reason_evidence(&receipt.evidence)?;
        require_response_execution_evidence_bundle_evidence(
            &receipt.evidence, &receipt.decision,
            receipt.graph.graph_slice_id.as_deref().unwrap_or_default(),
            receipt.graph.content_hash.as_deref(),
        )?;
        require_response_execution_dry_run_evidence(&receipt.evidence)?;
        require_response_execution_actor_evidence(&receipt.evidence)?;
        require_response_effect_count_evidence(
            &receipt.evidence, "executionEffect:", "execution effect count evidence",
        )?;
        require_response_effect_evidence_hashes(
            &receipt.evidence, "executionEffect:", "execution effect evidence",
        )?;
        require_response_execution_effect_type_evidence(&receipt.decision, &receipt.evidence)?;
        Ok(())
    }

    fn required_evidence_keys() -> &'static [&'static str] {
        &["responseActionId", "executionId", "rootNodeId", "graphSliceId",
          "ttlSeconds", "rollbackRef", "executionStatus", "dryRun",
          "evidenceBundleId", "evidenceBundleContentHash", "reason",
          "effectCount", "actorHash", "executionActorHash"]
    }
}

// Group impl: lets `validate()` run the shared response envelope once.
pub struct ResponseFamilyGroup;

impl ReceiptFamilyGroup for ResponseFamilyGroup {
    fn family_group(family: &EndpointDecisionReceiptFamily) -> bool {
        matches!(
            family,
            EndpointDecisionReceiptFamily::ResponseRequest
                | EndpointDecisionReceiptFamily::ResponseExecution
                | EndpointDecisionReceiptFamily::ResponseRollback
                | EndpointDecisionReceiptFamily::ResponseAcknowledgement,
        )
    }

    fn validate_group(receipt: &EndpointDecisionReceipt) -> Result<()> {
        // Body verbatim from current `validate()` lines 1924–1968
        // (shared response envelope: actor context, ttl, rollback ref,
        // subgraph reference, dispatch to request vs live evidence checks).
        Ok(())
    }
}
```

### Backwards-compat shim on `EndpointDecisionReceipt`

To avoid breaking the ~40 internal callers in `edr/mod.rs`, the inherent `for_*` methods become thin delegations:

```rust
impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_response_execution(input: EndpointResponseExecutionReceiptInput<'_>) -> Self {
        <families::response::ResponseExecutionReceipt as ReceiptFamily>::build(input)
    }
    // … 18 more one-line delegations …
}
```

The slimmed-down `validate()` (mod.rs:1626–2067 → ~80 lines) becomes:

```rust
pub fn validate(&self) -> Result<()> {
    // Shared envelope (schema version, signer, policy hash, sensor
    // providers, `require_receipt_evidence`, confidence). Kept here in
    // mod.rs because every family needs it.
    self.validate_envelope()?;

    // Group dispatch.
    if families::response::ResponseFamilyGroup::family_group(&self.receipt_family) {
        families::response::ResponseFamilyGroup::validate_group(self)?;
    }

    // Family dispatch (one match arm per `EndpointDecisionReceiptFamily`).
    use families::*;
    match self.receipt_family {
        EndpointDecisionReceiptFamily::SensorState =>
            sensor_state::SensorStateReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::ProviderDegradation =>
            provider_degradation::ProviderDegradationReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::Observation =>
            observation::ObservationReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::PolicyDecision =>
            policy_decision::PolicyDecisionReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::PolicyDelta =>
            policy_delta::PolicyDeltaReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::GraphSlice =>
            graph_slice::GraphSliceReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::Detection =>
            detection::DetectionReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::EvidenceBundleManifest =>
            evidence_bundle::EvidenceBundleManifestReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::Simulation =>
            simulation::SimulationReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::DeceptionMaterialization =>
            deception::DeceptionMaterializationReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::DeceptionCleanup =>
            deception::DeceptionCleanupReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::DeceptionRotation =>
            deception::DeceptionRotationReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::PrivacyReport =>
            telemetry_privacy::TelemetryPrivacyReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::ResponseRequest =>
            response::ResponseRequestReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::ResponseExecution =>
            response::ResponseExecutionReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::ResponseRollback =>
            response::ResponseRollbackReceipt::validate_family(self),
        EndpointDecisionReceiptFamily::ResponseAcknowledgement =>
            response::ResponseAcknowledgementReceipt::validate_family(self),
    }
}
```

---

## Per-Family File Designs

All new files live under `crates/libs/clawdstrike-policy-event/src/edr/receipt/families/`. The existing `inputs/` directory is unchanged.

### `mod.rs` (slimmed shell)

- Path: `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs`
- Contents: module wiring, `EndpointDecisionRecord` (51–79), `EndpointDecisionReceipt` struct (81–95), `validate()` dispatch (~80 lines), `validate_envelope()` (~50 lines extracted from the top of current `validate()`), `to_receipt()`, `sign_with()`, `receipt_id()`, `to_verdict()`, and 19 backwards-compat `for_*` delegating methods (~40 lines total).
- Estimated LOC after split: **~350**.
- Public surface: unchanged. Re-exports `pub use families::*;` so external code keeps seeing the receipt types.

### `family_trait.rs`

- Path: `…/receipt/family_trait.rs`
- Contents: `ReceiptFamily` and `ReceiptFamilyGroup` traits as shown above.
- Estimated LOC: **~70**.
- Public: `ReceiptFamily`, `ReceiptFamilyGroup`.

### `common.rs`

- Path: `…/receipt/common.rs`
- Contents: cross-family helpers from mod.rs lines 2149–2243 plus the trailing utility block (6206–6402): `require_field_eq`, `require_nonempty`, `require_optional_nonempty`, `require_nonzero`, `require_confidence`, `require_receipt_evidence`, `require_evidence_value_hash`, `require_boolean_hashed_evidence`, `require_nonempty_hashed_evidence`, `require_evidence_hash_not_empty`, `evidence_value_hash`, `hex_strings_match`, `trim_hex_prefix`, `camel_debug_to_snake`, `reconstruct_path`, `require_subgraph_reference`, `require_response_actor_context`, `require_response_actor_evidence`, `require_response_action`, `require_response_action_for_family`, `require_provider_last_seen_consistency`, `require_provider_degradation_consistency`.
- Estimated LOC: **~360**.
- Public: `pub(super) fn` for everything; nothing leaves the crate.

### `families/mod.rs`

- Path: `…/receipt/families/mod.rs`
- Contents: `pub mod sensor_state; pub mod telemetry_privacy; …` plus `pub use sensor_state::*; …` so the parent `mod.rs` keeps its glob re-exports working.
- Estimated LOC: **~30**.

### `families/sensor_state.rs`

- Constructor body from mod.rs:99–182 + `require_sensor_state_evidence` (4326–4437).
- Estimated LOC: **~210**.
- Public: `SensorStateReceipt` (impl `ReceiptFamily`).

### `families/telemetry_privacy.rs`

- `for_telemetry_privacy` (185–267) + `telemetry_privacy_report_id_from_values` (2480–2527), `telemetry_privacy_report_id_from_evidence` (2528–2592), `telemetry_privacy_report_id_from_evidence_hashes` (2593–2598) + `require_privacy_report_evidence` (5815–5894).
- Estimated LOC: **~290**.
- Public: `TelemetryPrivacyReceipt`.

### `families/provider_degradation.rs`

- `for_provider_degradation` (268–325) + `provider_degradation_id_from_*` ×3 (2599–2716) + `endpoint_provider_full_disk_access_evidence_value` (2717–2724) + `require_provider_degradation_evidence` (5895–5991).
- Estimated LOC: **~290**.
- Public: `ProviderDegradationReceipt`.

### `families/observation.rs`

- `for_observation` (326–395) + `observation_receipt_id_from_*` ×3 (4692–4794) + `require_observation_evidence` (4532–4629).
- Estimated LOC: **~280**.
- Public: `ObservationReceipt`.

### `families/policy_decision.rs`

- `for_policy_decision` (396–465) + `policy_decision_id_from_*` ×3 (2725–2787) + `require_policy_decision_evidence` (4815–4874).
- Estimated LOC: **~220**.
- Public: `PolicyDecisionReceipt`.

### `families/graph_slice.rs`

- `for_graph_slice` (466–520) + `require_graph_slice_evidence` (4281–4325) + `require_graph_slice_content_hash_evidence` (4267–4280).
- Estimated LOC: **~135**.
- Public: `GraphSliceReceipt`.

### `families/detection.rs`

- `for_detection` (521–589) + `require_detection_evidence` (4438–4531) + `require_detection_graph_reference` (4630–4664) + `detection_severity_label` (4665–4674) + `detection_finding_id_from_signed_fields` (4675–4691).
- Estimated LOC: **~230**.
- Public: `DetectionReceipt`.

### `families/evidence_bundle.rs`

- `for_evidence_bundle_manifest` (967–1009) + `require_evidence_bundle_manifest_evidence` (4221–4266).
- Estimated LOC: **~110**.
- Public: `EvidenceBundleManifestReceipt`.

### `families/simulation.rs`

- `for_simulation` (1325–1388) + `require_simulation_evidence` (4875–4901) + `require_graph_policy_simulation_evidence` (4902–5006) + `graph_policy_simulation_id_from_signed_fields` (4795–4814) + `simulation_breakage_score_from_confidence` (5007–5018).
- Estimated LOC: **~245**.
- Public: `SimulationReceipt`.

### `families/deception.rs`

- All three `for_deception_*` constructors (1010–1324, 315 lines) + the 9 ID helpers `deception_{materialization,cleanup,rotation}_id_from_{hashes,evidence,evidence_hashes}` (3079–3584) + `require_deception_materialization_evidence` (5276–5340) + `require_deception_cleanup_evidence` (5341–5433) + `deception_cleanup_dry_run_from_decision` (5434–5445) + `require_deception_rotation_evidence` (5446–5561) + `deception_rotation_dry_run_from_decision` (5562–5573).
- Estimated LOC: **~1,120**.
- Public: `DeceptionMaterializationReceipt`, `DeceptionCleanupReceipt`, `DeceptionRotationReceipt`. Consider further splitting into `deception/{materialization,cleanup,rotation}.rs` if file exceeds 800 lines (each sub-family is ~370 LOC then).
- **Recommendation:** split into `families/deception/mod.rs`, `materialization.rs`, `cleanup.rs`, `rotation.rs` to keep each file <500 lines.

### `families/response.rs`

- All four `for_response_*` constructors (590–965, 377 lines) + every `response_*` and `require_response_*` helper, including: `response_action_id_from_*` (2375–2391, 2425–2459), `expected_*_rollback_ref` (2461–2479), `require_response_*_receipt_evidence_*` (2245–2374), `response_execution_id_from_*` and effect-binding digests (2928–3077, 3585–3711), `response_acknowledgement_id_*` and effect digests (3713–3957), `response_execution_bundle_id_from_signed_fields` (3959–3990), all `require_response_{request,execution,rollback,acknowledgement}_*` (3991–4220, 5992–6203).
- Estimated LOC: **~1,860**.
- **Recommendation:** split into `families/response/{mod.rs, request.rs, execution.rs, rollback.rs, acknowledgement.rs, ids.rs, evidence.rs}` so no sub-file exceeds 600 lines. `ids.rs` holds the ~12 `response_*_id_from_*` derivations shared by ≥2 sub-families; `evidence.rs` holds the shared `require_response_receipt_evidence_fields` and effect helpers.
- Public: `ResponseRequestReceipt`, `ResponseExecutionReceipt`, `ResponseRollbackReceipt`, `ResponseAcknowledgementReceipt`, `ResponseFamilyGroup`.

### `families/policy_event_replay.rs`

- `for_policy_event_replay` (1389–1450) + `policy_event_replay_id_from_evidence` (5140–5184) + `require_policy_event_replay_evidence` (5019–5073).
- Estimated LOC: **~170**.
- Public: `PolicyEventReplayReceipt`.

### `families/policy_event_impact.rs`

- `for_policy_event_impact` (1451–1524) + `policy_event_impact_id_from_evidence` (5185–5240) + `require_policy_event_impact_evidence` (5074–5139) + `require_policy_event_stream_graph_reference` (5241–5275).
- Estimated LOC: **~230**.
- Public: `PolicyEventImpactReceipt`.

### `families/policy_delta.rs`

- `for_policy_delta` (1525–1624) + `require_policy_delta_evidence` (5574–5661) + `require_policy_delta_stage_action_evidence` (5662–5681) + `policy_delta_stage_from_hash` (5682–5690) + `policy_delta_receipt_enforcement_action_supported` (5691–5702) + `policy_delta_operation_from_title` (5703–5716) + `require_policy_delta_operation_evidence` (5717–5757) + `policy_delta_id_from_evidence` (5758–5801) + `require_policy_delta_graph_reference` (5802–5814).
- Estimated LOC: **~350**.
- Public: `PolicyDeltaReceipt`.

### Resulting file map

```
crates/libs/clawdstrike-policy-event/src/edr/receipt/
├── mod.rs                        ~350   (struct, validate dispatch, signing)
├── family_trait.rs               ~70    (ReceiptFamily, ReceiptFamilyGroup)
├── common.rs                     ~360   (require_* primitives, hex helpers)
├── evidence.rs                   173    (unchanged)
├── families.rs                   26     (unchanged enum)
├── inputs/                       351    (unchanged, 15 files)
└── families/
    ├── mod.rs                    ~30
    ├── sensor_state.rs           ~210
    ├── telemetry_privacy.rs      ~290
    ├── provider_degradation.rs   ~290
    ├── observation.rs            ~280
    ├── policy_decision.rs        ~220
    ├── graph_slice.rs            ~135
    ├── detection.rs              ~230
    ├── evidence_bundle.rs        ~110
    ├── simulation.rs             ~245
    ├── deception/
    │   ├── mod.rs                ~40
    │   ├── materialization.rs    ~370
    │   ├── cleanup.rs            ~360
    │   └── rotation.rs           ~370
    ├── response/
    │   ├── mod.rs                ~40
    │   ├── ids.rs                ~420
    │   ├── evidence.rs           ~360
    │   ├── request.rs            ~180
    │   ├── execution.rs          ~330
    │   ├── rollback.rs           ~220
    │   └── acknowledgement.rs    ~360
    ├── policy_event_replay.rs    ~170
    ├── policy_event_impact.rs    ~230
    └── policy_delta.rs           ~350
```

No file exceeds ~420 lines after the split (vs. today's 6,402). Total LOC across the tree stays within ~5% of today (some glue, no logic change).

---

## Migration Plan

Each step is a self-contained commit that compiles, runs `cargo test -p clawdstrike-policy-event`, and passes `cargo clippy --workspace -- -D warnings` (a project gate per `CLAUDE.md`).

1. **`refactor(edr-receipt): extract envelope helpers into receipt/common.rs`**
   - Move the 21 functions listed under `common.rs` above out of `mod.rs` into the new `pub(super)` module.
   - No public-surface change. Net: `mod.rs` shrinks by ~360 lines.

2. **`refactor(edr-receipt): introduce ReceiptFamily trait`**
   - Add `family_trait.rs` with both traits, no impls yet.
   - Add `families/mod.rs` shell.
   - Zero behavioural change.

3. **`refactor(edr-receipt): extract SensorState family`** — pilot, smallest non-trivial family.
   - Create `families/sensor_state.rs` containing `pub struct SensorStateReceipt;` + `impl ReceiptFamily`.
   - Replace the body of `EndpointDecisionReceipt::for_sensor_state` with a one-line delegate to `SensorStateReceipt::build`.
   - Replace the `if self.receipt_family == EndpointDecisionReceiptFamily::SensorState { … }` block in `validate()` with `SensorStateReceipt::validate_family(self)?;`.
   - Verify: run the existing test suite (the file currently has zero unit tests inside the module but is exercised by edr/mod.rs tests, lines 5806+).

4. **`refactor(edr-receipt): extract simple families`** (one commit per family, in this order to grow muscle memory before tackling the giants):
   - PrivacyReport / `telemetry_privacy.rs`
   - ProviderDegradation
   - PolicyDecision
   - GraphSlice
   - Detection
   - EvidenceBundleManifest
   - Observation
   - Simulation
   - PolicyEventReplay
   - PolicyEventImpact
   - PolicyDelta

5. **`refactor(edr-receipt): extract Deception family`** (or three commits for materialization/cleanup/rotation).
   - Decide whether `families/deception/` becomes a sub-tree or one file. Recommend sub-tree given the 1.1kLOC.

6. **`refactor(edr-receipt): extract Response family`** — final and largest.
   - Create `families/response/` sub-tree.
   - Implement `ResponseFamilyGroup` first so the shared `matches!()` block in `validate()` collapses cleanly.
   - Then port each of the four sub-family validators.
   - This is the highest-risk commit; budget extra review.

7. **`refactor(edr-receipt): slim mod.rs`** (cleanup).
   - Replace `validate()` body with the `match` shown in the trait section.
   - Extract `validate_envelope()` (mod.rs:1627–1677 of today) as a private method on `EndpointDecisionReceipt`.
   - Add module-level doc comment summarising the trait.

8. **`refactor(edr-receipt): mark for_* methods as deprecated wrappers (optional)`**
   - Decision point: do we want callers to migrate to `<X as ReceiptFamily>::build` directly?
   - If yes: add `#[deprecated(note = "use ReceiptFamily::build")]` to the `EndpointDecisionReceipt::for_*` methods and migrate the ~40 internal call sites in `edr/mod.rs` and tests.
   - If no: keep the `for_*` delegations as the stable surface and remove this commit.
   - **Recommendation:** *keep* the `for_*` delegations. They are a small, stable, discoverable surface and the trait is an internal-organisation refactor, not an API redesign.

After step 7, `mod.rs` is ~350 lines, the largest sibling is `families/response/ids.rs` at ~420, and the total tree is still in the same workspace crate with no new dependencies.

---

## Risk Notes

### Public-API impact

- `EndpointDecisionReceipt`, `EndpointDecisionRecord`, `EndpointDecisionReceiptFamily`, `EndpointReceiptEvidence`, `EndpointGraphReference`, `EndpointEvidenceBundleReference`, all 15 `Endpoint*ReceiptInput<'a>` structs, and all 19 `EndpointDecisionReceipt::for_*` methods stay in their current paths via `pub use families::*;` glob re-export. **Zero breaking changes** are intended.
- Inherent methods (`validate`, `to_receipt`, `sign_with`, `receipt_id`) keep their signatures.
- All 40+ internal callers in `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` (and the duplicate `.claude/worktrees/agent-…/crates/libs/clawdstrike-policy-event/src/edr.rs` worktree copy — not modified, separate concern) continue to compile unchanged.

### Serde / wire compatibility

- The on-wire JSON for `EndpointDecisionReceipt` is determined by the struct definition + `#[serde(rename_all = "camelCase", deny_unknown_fields)]`. The struct stays in `mod.rs` — no field reordering, no rename, no serde attribute change. **Wire format is invariant.**
- `ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION = "clawdstrike.endpoint_decision.v1"` is unchanged.
- Evidence key strings (`"responseActionId"`, `"executionEffect:{id}"`, etc.) are the canonicalisation surface for `evidence_value_hash`; they must be byte-identical post-refactor. **Risk: typo during the move.** Mitigation: `required_evidence_keys()` returns a `&'static [&'static str]` list per family; a single new unit test can assert every key in `required_evidence_keys()` actually appears in `build()`'s output for a canonical fixture.

### `validate()` ordering risk

- Today's `validate()` runs envelope checks first, then family-specific blocks in a fixed `if … if … if …` cascade. The proposed `match` runs exactly one arm per receipt — semantically equivalent because every `if self.receipt_family == X` block is mutually exclusive (`receipt_family` is an enum).
- **Exception:** the `matches!(self.receipt_family, ResponseRequest | ResponseExecution | ResponseRollback | ResponseAcknowledgement)` block at lines 1924–1968 runs *before* the per-sub-family blocks. This is what `ReceiptFamilyGroup::validate_group` captures — keep the calling order `validate_envelope → group → family` exactly as today.

### Test coverage

- The receipt module has no `#[cfg(test)] mod tests` inside `mod.rs`; coverage lives in `edr/mod.rs` (lines 5806+, ~3.5kLOC of integration tests building receipts and asserting validation). These exercise every family and will catch regressions if the existing test suite is run after every commit.
- One legitimate test-only helper exists: `pub(crate) fn response_action_id_from_signed_response_fields` at line 2426 — must remain `pub(crate)` after the move into `families/response/ids.rs`.
- Recommend adding a per-family "round-trip" test in each new file: build a canonical fixture, sign with a deterministic signer, validate, assert evidence-key set. This pins the wire format per family.

### Cyclic-dependency risk

- `families/*.rs` import from `super::common::*`, `super::family_trait::*`, `super::{EndpointDecisionReceipt, …}`, and `super::inputs::*`. No cross-family imports are required (Response's `ids.rs` is internal to the `response/` sub-tree). **No new cycles.**
- The Response and Deception families currently call `endpoint_decision_actor_content_hash` from the parent `edr/mod.rs`; that import path is unchanged.

### Visibility

- All current `fn require_*`, `fn *_id_from_*`, etc. are crate-private (no `pub`). After moving into `common.rs` they need `pub(super)` to stay reachable from `families/*`. After moving family-specific helpers into their family module, they become module-private (`fn`, no qualifier needed) — a strict net improvement in encapsulation.
- The three currently `pub(crate)` helpers (`response_acknowledgement_id_from_report_fields`, `response_acknowledgement_id_from_report_fields_with_control`, `response_acknowledgement_id_from_signed_evidence`, `response_action_id_from_signed_response_fields`, `response_execution_effect_binding_digest_from_effects`, `response_rollback_id_from_effects`, `response_rollback_id_from_signed_evidence`, `response_effect_evidence_value`) must keep `pub(crate)` because they're called from `edr/mod.rs` outside this directory.

### Downstream consumers

- `grep -rn "EndpointDecisionReceipt::for_" --include="*.rs"` outside `edr/receipt/` returns **40 matches, all in the same crate** (`edr/mod.rs`). There are zero external (other-crate) consumers of any `for_*` constructor. Cross-crate consumers only touch the struct types, which don't move.
- `.claude/worktrees/agent-a28ba40d43bfae230/` contains a stale copy — out of scope.

### Build-time / clippy

- `clippy::unwrap_used = "deny"` and `clippy::expect_used = "deny"` (per `CLAUDE.md`) apply. The trait surface uses `Result<()>` everywhere, matching today.
- The proposed `match` dispatch is exhaustive on `EndpointDecisionReceiptFamily`; if a new variant is added later, the compiler will force the implementer to add the corresponding `families/foo.rs` and match arm — strictly safer than today's silent `if` chain.
- `serde(rename_all = "snake_case")` on `EndpointDecisionReceiptFamily` means new variants need a `families/<snake_case_name>.rs` to keep the file naming consistent.

### Formal / diff-test impact

- The Lean 4 spec under `formal/lean4/ClawdStrike/` and `crates/tests/formal-diff-tests` do not import from `edr/receipt/`; this refactor does not affect the verification pipeline.

---

*End of plan.*
