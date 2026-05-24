# `edr/mod.rs` Dead-Code Audit

## Summary

`crates/libs/clawdstrike-policy-event/src/edr/mod.rs` is a 9,836-line file with **zero `pub` items of its own** — every public symbol exported under `clawdstrike_policy_event::edr::*` lives in one of 18 sibling files that `mod.rs` re-exports via blanket `pub use foo::*`. Of those 9,836 lines, **7,453 lines (lines 2384-9836) are a single `#[cfg(test)] mod tests` block** containing roughly 88 test functions; only ~2,382 lines of production code (utility helpers, projection functions, hashing helpers, plus `pub(crate)` shared between siblings) actually live in `mod.rs`. The `#![allow(dead_code, unused_imports)]` attribute at line 8 conceals warnings on this code.

Across the 18 sibling files plus `mod.rs`, I inventoried **60 distinct public items** (types, enums, free functions, plus inherent methods on those types). Of those, **3 public symbols are completely dead** (no callers anywhere except the file that defines them or worktree copies), **6 are test-only or near-dead** (only used by `#[cfg(test)]` blocks in `mod.rs` itself), and **another ~12 inherent methods are dead or test-only**. The remaining 39 types are USED, but a meaningful subset are TYPE_ECHO (referenced only as fields of a parent type, or only by the sibling `edr/receipt/` tree which is a separate audit).

**Removable LOC estimate: ~7,800-8,200 lines, dominated by the 7,453-line in-file test mega-block in `mod.rs`** (which should be split per-file or moved to `crates/libs/clawdstrike-policy-event/tests/` so the `#![allow(dead_code)]` blanket can be removed). The truly orphan-code wipe (`EndpointFlightRecorderSnapshot`, `EndpointFlightRecorder::snapshot()`, `EndpointFlightRecorder::read_observations()`, `EndpointFlightRecorder::read_observation_window()`, `CausalGraphRecorder::causal_path()`, `EndpointTelemetryPrivacyReport::from_observations()`, `EndpointSensorState::single_active_agent()`, plus the test-only `pub` constructors on `EndpointResponseExecutionReport::terminate_process_tree` and `EndpointResponsePlan::dry_run` test-only paths) is small (~80-120 LOC) but the symbolic clean-up unlocks removing the `#![allow]` shield.

**Recommended action:** (1) delete the small confirmed-dead methods, (2) split tests out of `mod.rs` (~7,400 LOC migration, line-count-equal but file-shrinking), (3) drop `#![allow(dead_code, unused_imports)]`, (4) flatten the `pub use foo::*` blanket re-exports to explicit lists to make future drift visible.

## Inventory by Module

### `edr/mod.rs` (9,836 lines)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| _(no `pub` items)_ | — | — | — | — |
| `pub(crate) FNV_OFFSET`, `FNV_PRIME` | const | 2 | none | USED (inside file by `stable_id`) |
| `pub(crate) ENDPOINT_FLIGHT_RECORDER_*_SCHEMA_VERSION` (3) | const | 3 | `flight_recorder/index.rs`, `flight_recorder/mod.rs` | USED |
| `pub(crate) endpoint_*_content_hash` (3 funcs) | fn | ~24 | `edr/receipt/` | TYPE_ECHO (in-edr) |
| `pub(crate) observation_age_seconds`, `tool_name_field`, `credential_kind_field`, `event_target_field`, `event_target_hash_field`, `process_image_hash_field`, `process_command_line_hash_field`, `package_registry_cli_name`, `cloud_cli_name`, `insert_json` | fn | ~200 | `flight_recorder/mod.rs`, `causal/recorder.rs`, etc. | USED (cross-sibling helpers) |
| `pub(crate) FindingRule<'a>` | struct | ~12 | `detection/supply_chain.rs` | USED |
| ~88 `#[test] fn …` | tests | **7,453** | — | TEST_ONLY (inflate file 4×) |

### `edr/action.rs` (39 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointDecisionAction` | enum | 15 | `apps/agent/src-tauri/src/api_server.rs`, `apps/agent/src-tauri/src/edr/dto.rs`, etc. (5 files) | USED |
| `EndpointDecisionAction::as_str()` | fn | 17 | `simulation.rs`, `ids.rs` and consumers via JSON | USED |

### `edr/actor.rs` (91 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointClockState` | struct | 8 | **none** in main tree; only `edr/receipt/mod.rs` | TYPE_ECHO (in-edr only) |
| `impl Default for EndpointClockState` | impl | 10 | only `edr/receipt/` consumers | TYPE_ECHO |
| `EndpointDecisionActor` | struct | 10 | `apps/agent/src-tauri/src/edr/dto.rs`, `api_server.rs` | USED |
| `EndpointDecisionActor::from_observation()` | fn | 18 | only `edr/receipt/mod.rs` | TYPE_ECHO (in-edr only) |
| `EndpointDecisionActor::with_endpoint_id()` | fn | 7 | only `edr/receipt/mod.rs` | TYPE_ECHO (in-edr only) |
| `EndpointDecisionActor::with_endpoint_id_if_missing()` | fn | 7 | only `edr/receipt/mod.rs` | TYPE_ECHO (in-edr only) |
| `EndpointPolicySnapshot` | struct | 6 | `api_server.rs`, `edr/dto.rs` (5 files) | USED |
| `EndpointReceiptSigner` | struct | 5 | **none** in main tree; only `edr/receipt/mod.rs` | TYPE_ECHO (in-edr only) |

### `edr/deception.rs` (254 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `HoneyArtifactKind` | enum | 10 | `apps/agent/src-tauri/src/edr/dto.rs` | USED |
| `HoneyArtifactKind::as_str()` | fn | 12 | (JSON shape) | USED |
| `HoneyArtifact` | struct | 10 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` | USED |
| `HoneyArtifact::absolute_path()` | fn | 4 | `api_server.rs:18440,27608,…` | USED |
| `HoneyArtifact::matches_path()` | fn | 6 | only `edr/mod.rs` line 2017 | INTERNAL (in-edr only) |
| `HoneyArtifact::internal_hostname()` | fn | 9 | `api_server.rs:27539,27709` | USED |
| `HoneyArtifact::matches_network_destination()` | fn | 15 | only `edr/mod.rs` line 2025-2042 | INTERNAL (in-edr only) |
| `HoneyArtifact::browser_cookie_indicators()` | fn | 40 | only `edr/deception.rs` (self) | INTERNAL (self-only) |
| `HoneyArtifact::matches_browser_cookie_access()` | fn | 13 | only `edr/mod.rs` line 2058 | INTERNAL (in-edr only) |
| `DeceptionPlan` | struct | 6 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` (5 files) | USED |
| `DeceptionPlan::standard()` | fn | 32 | `api_server.rs` | USED |
| `DeceptionPlan::materialize()` | fn | 30 | `api_server.rs` | USED |
| `DeceptionMaterializationReport` | struct | 5 | `edr/dto.rs`, `edr/receipt/inputs/deception.rs` | USED |
| `DeceptionCleanupReport` | struct | 8 | `edr/dto.rs`, `edr/receipt/inputs/deception.rs` | USED |
| `DeceptionRotationReport` | struct | 10 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` | USED |

### `edr/event.rs` (556 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointEvent` | enum (13 variants) | ~110 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` | USED |
| `EndpointEvent::kind_name()` | fn | 20 | only `edr/causal/recorder.rs` and `edr/event.rs` (self) | INTERNAL (in-edr only) |
| `FileOperation` | enum | 13 | `api_server.rs`, `edr/dto.rs` | USED |
| `PackageManager` | enum (19 variants + Other) | 22 | `api_server.rs`, `edr/dto.rs`, `edr/causal/recorder.rs` (4 files) | USED |
| `PackageManager::as_str()` | fn | 27 | `edr/causal/recorder.rs` | USED |
| `CredentialKind` | enum | 10 | `api_server.rs`, `edr/dto.rs` | USED |
| `CredentialKind::as_str()` | fn | 13 | `edr/causal/recorder.rs`, `edr/mod.rs` | USED |
| `EndpointObservation` | struct | 10 | `api_server.rs`, `edr/dto.rs`, many others (6 files) | USED |
| `EndpointObservation::event_name()` | fn | 3 | `facade.rs:453` | USED |
| `EndpointObservation::from_policy_event()` | fn | 38 | `api_server.rs` | USED |
| `EndpointObservation::to_policy_event_projection()` | fn | 135 | `api_server.rs:10701` | USED |

### `edr/ids.rs` (90 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `endpoint_policy_event_replay_id()` | fn | 24 | `apps/agent/src-tauri/src/edr/…`, `api_server.rs` | USED |
| `endpoint_policy_event_impact_id()` | fn | 30 | (same) | USED |
| `endpoint_policy_delta_id()` | fn | 28 | (same) | USED |

### `edr/privacy.rs` (183 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointTelemetryPrivacyMode` | enum | 8 | `apps/agent/src-tauri/src/edr/dto.rs` + TS | USED |
| `EndpointTelemetryPrivacyMode::as_str()` | fn | 9 | (in-edr + JSON) | USED |
| `EndpointTelemetryPrivacyMode::permits_raw_artifacts()` | fn | 3 | only `privacy.rs` self | INTERNAL (self-only) |
| `EndpointTelemetryFieldProjection` | struct | 9 | mirrored in TS `apps/control-console/src/api/client.ts`; no Rust caller outside edr/ | TYPE_ECHO (field of parent + JSON wire) |
| `impl Default for EndpointTelemetryFieldProjection` | impl | 12 | none | TYPE_ECHO |
| `EndpointTelemetryObservationProjection` | struct | 9 | TS only | TYPE_ECHO (field of parent + JSON wire) |
| `EndpointTelemetryPrivacyReport` | struct | 19 | `api_server.rs`, `apps/agent/src-tauri/src/edr/handlers/privacy.rs` | USED |
| `EndpointTelemetryPrivacyReport::from_observations()` | fn | 6 | only `#[cfg(test)]` blocks in `edr/mod.rs` | **TEST_ONLY** |
| `EndpointTelemetryPrivacyReport::from_observations_with_raw_artifact_approval()` | fn | 82 | `apps/agent/src-tauri/src/edr/handlers/privacy.rs:45` | USED |

### `edr/process.rs` (96 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `SignatureTrust` | enum | 13 | `api_server.rs`, `edr/dto.rs` | USED |
| `CodeSignatureStatus` | struct | 10 | `api_server.rs`, `edr/dto.rs` | USED |
| `CodeSignatureStatus::has_drift()` | fn | 17 | `apps/agent/src-tauri/src/edr/…` | USED |
| `CodeSignatureStatus::is_untrusted_runtime_binary()` | fn | 7 | `apps/agent/src-tauri/src/edr/…` | USED |
| `EndpointProcess` | struct | 10 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` (4 files) | USED |
| `EndpointProcess::stable_key()` | fn | 19 | `edr/causal/recorder.rs` | USED |
| `EndpointProcess::stable_node_id()` | fn | 5 | only self / `edr/causal/recorder.rs` | INTERNAL |

### `edr/response.rs` (1,741 total — **256 prod + 1,485 tests**)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointResponsePlan` | struct | 15 | `api_server.rs`, `edr/handlers/response.rs`, `edr/dto.rs` (5 files) | USED |
| `EndpointResponsePlan::dry_run()` | fn | 11 | `edr/handlers/response.rs:92` (also tests) | USED |
| `EndpointResponsePlan::collect_evidence_execution()` | fn | 17 | `api_server.rs`, `edr/handlers/response.rs` | USED |
| `EndpointResponsePlan::restrict_egress_execution()` | fn | 17 | `api_server.rs:19776` | USED |
| `EndpointResponsePlan::quarantine_file_execution()` | fn | 17 | `edr/handlers/response.rs:118` | USED |
| `EndpointResponsePlan::disable_persistence_execution()` | fn | 17 | `edr/handlers/response.rs:126` | USED |
| `EndpointResponsePlan::revoke_grant_execution()` | fn | 17 | `api_server.rs` (4 sites) | USED |
| `EndpointResponsePlan::suspend_process_tree_execution()` | fn | 20 | `edr/response/targets.rs:219`, `edr/handlers/response.rs:140` | USED |
| `EndpointResponsePlan::terminate_process_tree_execution()` | fn | ~110 (incl. body) | only `edr/mod.rs` tests + `edr/response.rs` carries a `deprecated` note pointing to alternatives | **TEST_ONLY** |
| `EndpointResponseExecutionStatus` | enum + `as_str` | 26 | `api_server.rs`, `edr/dto.rs` | USED |
| `EndpointResponseExecutionEffect` | struct | 9 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` | USED |
| `EndpointResponseExecutionEffect::quarantine_file()` | fn | 24 | only `edr/response.rs:850` (self) | INTERNAL (self-only) |
| `EndpointResponseExecutionEffect::restore_quarantine_file()` | fn | 24 | `edr/handlers/response.rs` rollback | USED |
| `EndpointResponseExecutionEffect::disable_persistence()` | fn | 24 | only `edr/response.rs:930` (self) | INTERNAL (self-only) |
| `EndpointResponseExecutionEffect::restore_persistence_file()` | fn | 24 | rollback handler | USED |
| `EndpointResponseExecutionEffect::revoke_grant()` | fn | 15 | rollback handler | USED |
| `EndpointResponseExecutionEffect::restrict_egress()` | fn | 23 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionEffect::restore_egress()` | fn | 23 | rollback handler | USED |
| `EndpointResponseExecutionEffect::suspend_process_tree()` | fn | 26 | `edr/response/targets.rs`, handler | USED |
| `EndpointResponseExecutionEffect::resume_process_tree()` | fn | 26 | rollback handler | USED |
| `EndpointResponseExecutionEffect::terminate_process_tree()` | fn | 26 | rollback handler | USED |
| `EndpointResponseExecutionReport` | struct | 21 | `api_server.rs`, `edr/handlers/response.rs`, `edr/receipt/` (6 files) | USED |
| `EndpointResponseExecutionReport::collect_evidence()` | fn | 67 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionReport::failed()` | fn | 70 | `api_server.rs:6104` | USED |
| `EndpointResponseExecutionReport::restrict_egress()` | fn | 73 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionReport::quarantine_file()` | fn | 80 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionReport::disable_persistence()` | fn | 80 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionReport::revoke_grant()` | fn | 74 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionReport::suspend_process_tree()` | fn | 74 | `edr/handlers/response.rs` | USED |
| `EndpointResponseExecutionReport::terminate_process_tree()` | fn | 12 | only `edr/mod.rs` tests (line 8216) | **TEST_ONLY** |
| `EndpointResponseExecutionReport::expires_at()` | fn | 5 | `api_server.rs` (12 sites) | USED |
| `EndpointResponseExecutionReport::expired_from()` | fn | 34 | `api_server.rs` rollback flow | USED |
| `EndpointResponseExecutionReport::cancelled_from()` | fn | 38 | `api_server.rs` rollback flow | USED |
| `EndpointResponseExecutionReport::rolled_back_from()` | fn | 40 | `api_server.rs` rollback flow | USED |
| `EndpointResponseRollbackReport` | struct | 18 | `api_server.rs`, `edr/handlers/response.rs`, `edr/receipt/` | USED |
| `EndpointResponseRollbackReport::restrict_egress()` | fn | 73 | handler | USED |
| `EndpointResponseRollbackReport::quarantine_file()` | fn | 64 | handler | USED |
| `EndpointResponseRollbackReport::disable_persistence()` | fn | 66 | handler | USED |
| `EndpointResponseRollbackReport::suspend_process_tree()` | fn | 118 | handler | USED |
| `EndpointResponseControlCorrelation` | struct | 28 | `api_server.rs:62,13036+,13989,14232` | USED |
| `EndpointResponseAcknowledgementReport` | struct | 20 | `api_server.rs`, `edr/handlers/response.rs`, `edr/receipt/` | USED |
| `EndpointResponseAcknowledgementReport::from_execution()` | fn | 39 | `edr/handlers/response.rs` (×4) | USED |
| `EndpointResponseAcknowledgementReport::with_control_correlation()` | fn | 12 | `edr/handlers/response.rs:859` | USED |

### `edr/sensor_state.rs` (58 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointProviderKind` | enum | 13 | `api_server.rs`, `edr/dto.rs`, `edr/receipt/` | USED |
| `EndpointProviderState` | struct | 15 | `api_server.rs`, `edr/receipt/inputs/provider_degradation.rs` | USED |
| `EndpointSensorState` | struct | 5 | `api_server.rs`, `edr/handlers/policy.rs`, `edr/handlers/privacy.rs` (4 files) | USED |
| `EndpointSensorState::single_active_agent()` | fn | 20 | only `edr/mod.rs` tests (10+ call sites) | **TEST_ONLY** |

### `edr/simulation.rs` (559 LOC, 0 tests; internal helpers only)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointPolicySimulationRule` | struct | 7 | `api_server.rs`, `edr/dto.rs` | USED |
| `EndpointSimulationImpactLevel` | enum + as_str | 22 | `api_server.rs`, `edr/dto.rs` | USED |
| `EndpointPolicySimulationAffectedNode` | struct | 9 | **none** named externally; only constructed as field of `EndpointPolicySimulationReport` | TYPE_ECHO |
| `EndpointPolicySimulationIdentityContext` | struct | 9 | `api_server.rs`, `edr/dto.rs` | USED |
| `EndpointPolicySimulationToolContext` | struct | 8 | `api_server.rs`, `edr/dto.rs` | USED |
| `EndpointPolicySimulationReport` | struct | 25 | `api_server.rs`, `edr/dto.rs`, `edr/handlers/…` (4 files) | USED |
| `EndpointPolicySimulationReport::for_rule()` | fn | 108 | `api_server.rs` | USED |
| `pub(crate) simulation_action_would_block()` | fn | 11 | `edr/mod.rs` | USED |
| `pub(crate) impact_level_for_score()` | fn | 8 | `edr/mod.rs` | USED |
| `pub(crate) simulation_context_evidence_value()` | fn | 5 | `edr/mod.rs` | USED |

### `edr/causal/graph.rs` (111 LOC)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `CausalGraph` | struct | 5 | `api_server.rs`, `edr/dto.rs`, many handlers (10 files) | USED |
| `CausalGraph::causal_subgraph_from()` | fn | 38 | `api_server.rs` (9+ sites) | USED |
| `CausalGraph::causal_context_around()` | fn | 56 | `api_server.rs` (5+ sites) | USED |

### `edr/causal/node.rs` (79 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `CausalNodeKind` | enum (18 variants) | 21 | `api_server.rs`, `edr/dto.rs`, `flight_recorder/index.rs` (7 files) | USED |
| `CausalNode` | struct | 11 | `api_server.rs`, `edr/dto.rs`, `flight_recorder/index.rs` (7 files) | USED |
| `CausalEdgeKind` | enum (21 variants) | 24 | `flight_recorder/index.rs`, `edr/dto.rs` | USED |
| `CausalEdge` | struct | 12 | `flight_recorder/index.rs`, `edr/dto.rs` | USED |

### `edr/causal/recorder.rs` (717 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `CausalGraphRecorder` | struct | 6 | `api_server.rs` (only as field/`record_observation` consumer) | USED |
| `CausalGraphRecorder::new()` | fn | 3 | `flight_recorder/mod.rs` (in-edr) | INTERNAL (in-edr only) |
| `CausalGraphRecorder::graph()` | fn | 3 | `flight_recorder/mod.rs` self chain | INTERNAL (in-edr only) |
| `CausalGraphRecorder::into_graph()` | fn | 3 | `api_server.rs:14604,21565` | USED |
| `CausalGraphRecorder::record_observation()` | fn | 45 | `api_server.rs` (10+ sites), `flight_recorder/mod.rs` | USED |
| `CausalGraphRecorder::causal_path()` | fn | 25 | **none** | **DEAD** |
| private helpers (`process_node`, `event_node`, `add_edge`, `add_temporal_edge`, `ensure_node`, `touch_node`, `identity_context_nodes`) | fn | ~590 | self-only | INTERNAL |

### `edr/detection/finding.rs` (36 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `DetectionSeverity` | enum | 8 | `api_server.rs:46`, `edr/dto.rs` | USED |
| `DetectionEvidence` | struct | 5 | **none** named externally; only field of `DetectionFinding` | TYPE_ECHO |
| `DetectionFinding` | struct | 16 | `api_server.rs` (5 sites, including `edr_recent_findings: Arc<Mutex<VecDeque<DetectionFinding>>>`), `apps/control-console/src/api/client.ts` (as `DetectionFindingJson`) | USED |

### `edr/detection/supply_chain.rs` (382 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `SupplyChainRuntimeGuard` | struct | 4 | `api_server.rs` (constructed + evaluated) | USED |
| `SupplyChainRuntimeGuard::new()` | fn | 4 | `api_server.rs` | USED |
| `SupplyChainRuntimeGuard::with_honey_artifacts()` | fn | 4 | `api_server.rs` | USED |
| `SupplyChainRuntimeGuard::evaluate()` | fn | ~370 | `api_server.rs` | USED |

### `edr/flight_recorder/compaction.rs` (23 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointFlightRecorderCompactionRecord` | struct | 12 | `api_server.rs:51`, `edr/dto.rs:22+2716` | USED |
| `EndpointFlightRecorderCompactionReport` | struct | 6 | **none** named externally; only `compact()`'s return type, fields accessed in `edr/handlers/causal.rs:438+` | USED (return-only) |

### `edr/flight_recorder/index.rs` (80 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointFlightRecorderHistoryIndexEntry` | struct | 39 | `api_server.rs`, used by `read_indexed_observation_window` predicate | USED |
| `EndpointFlightRecorderGraphNodeIndexEntry` | struct | 13 | `edr/handlers/causal.rs:280` | USED |
| `EndpointFlightRecorderGraphEdgeIndexEntry` | struct | 12 | `edr/handlers/causal.rs:193,281` | USED |

### `edr/flight_recorder/mod.rs` (1,449 LOC, 0 tests)

| Symbol | Kind | LOC | Callers (outside edr/) | Status |
|---|---|---|---|---|
| `EndpointFlightRecorder` | struct | 5 | `api_server.rs` (state field) | USED |
| `EndpointFlightRecorderSnapshot` | struct | 8 | **none** — only `.snapshot()` produces it | **DEAD** |
| `EndpointFlightRecorderHistoryWindow` | struct | 8 | accessed via `.read_indexed_observation_window()` return: `api_server.rs:10648+` | USED (return-only) |
| `EndpointFlightRecorder::open()` | fn | 21 | `api_server.rs:18069,23162,23224` | USED |
| `EndpointFlightRecorder::transient()` | fn | 8 | `api_server.rs:18077,21061` | USED |
| `EndpointFlightRecorder::path()` | fn | 3 | `api_server.rs:10641`, `edr/handlers/causal.rs:430` | USED |
| `EndpointFlightRecorder::observation_count()` | fn | 3 | `api_server.rs:2011` | USED |
| `EndpointFlightRecorder::graph()` | fn | 3 | `api_server.rs` (5+ sites) | USED |
| `EndpointFlightRecorder::snapshot()` | fn | 7 | **none** | **DEAD** |
| `EndpointFlightRecorder::read_observations()` | fn | 3 | **none** | **DEAD** |
| `EndpointFlightRecorder::read_observation_window()` | fn | 15 | **none** (only the `_indexed_` variant is used) | **DEAD** |
| `EndpointFlightRecorder::read_indexed_observation_window()` | fn | 15 | `api_server.rs:10648` | USED |
| `EndpointFlightRecorder::read_graph_node_index()` | fn | 13 | `edr/handlers/causal.rs:280` | USED |
| `EndpointFlightRecorder::read_graph_edge_index()` | fn | 13 | `edr/handlers/causal.rs:193,281` | USED |
| `EndpointFlightRecorder::append_observations()` | fn | ~73 | `api_server.rs:12019` | USED |
| `EndpointFlightRecorder::compact()` | fn | ~67 | `edr/handlers/causal.rs:438` | USED |
| `EndpointFlightRecorder::rebuild_from_disk()` | fn | ~30 | called by `open()` (in-file) | INTERNAL (self-only) |
| private `read_observations_from_disk`, `rewrite_observations`, `read_endpoint_observation_window`, `read_indexed_endpoint_observation_window`, `read_or_rebuild_endpoint_graph_node_index`, `read_or_rebuild_endpoint_graph_edge_index`, … | fn | ~1,000 | self-only | INTERNAL |

## Confirmed Dead Symbols (the wipe list)

These have **zero callers** anywhere outside the file that defines them (and outside `.claude/worktrees/`, `.worktrees/`, `infra/vendor/` which we deliberately ignore):

1. **`edr::flight_recorder::EndpointFlightRecorderSnapshot`** — struct, 8 LOC at `flight_recorder/mod.rs:50-56`. Constructed only by `EndpointFlightRecorder::snapshot()` (also dead). No consumer.

2. **`EndpointFlightRecorder::snapshot(&self) -> EndpointFlightRecorderSnapshot`** — fn, 7 LOC at `flight_recorder/mod.rs:119-125`. No caller.

3. **`EndpointFlightRecorder::read_observations(&self) -> Result<Vec<EndpointObservation>>`** — fn, 3 LOC at `flight_recorder/mod.rs:130-132`. Thin wrapper around the private `read_observations_from_disk`. No caller — every consumer uses the windowed/indexed variant instead.

4. **`EndpointFlightRecorder::read_observation_window<F>(&self, limit, predicate)`** — fn, 15 LOC at `flight_recorder/mod.rs:138-152`. No caller — `api_server.rs` only uses `read_indexed_observation_window`. The non-indexed version is genuinely orphaned. Also drag the helper `read_endpoint_observation_window` it delegates to (~50 LOC) if no other caller remains after deletion. _(Verify nothing else calls the helper directly before deleting it.)_

5. **`CausalGraphRecorder::causal_path(&self, from, to) -> Option<Vec<String>>`** — fn, 25 LOC at `causal/recorder.rs:249-273`. BFS shortest-path query. No caller. Tests in `edr/mod.rs` do not exercise it.

6. **`EndpointTelemetryPrivacyReport::from_observations(observations, privacy_mode)`** — fn, 6 LOC at `privacy.rs:92-98`. Convenience wrapper around `from_observations_with_raw_artifact_approval` with `None, None`. Only `edr/mod.rs` test functions (7 call sites) reach it; **TEST_ONLY**, eligible for deletion once the tests inline `from_observations_with_raw_artifact_approval(..., None, None)`.

7. **`EndpointSensorState::single_active_agent(provider_id)`** — fn, 20 LOC at `sensor_state.rs:39-57`. Only called by `edr/mod.rs` test functions (10+ sites). **TEST_ONLY**; eligible for deletion once tests inline the literal `EndpointSensorState { providers: vec![…] }`.

8. **`EndpointResponsePlan::terminate_process_tree_execution(...)`** — fn, ~110 LOC at `response.rs:179-256`. The file already carries a `#[deprecated]`-style comment (line 177) noting "terminate_process_tree is dry-run/modeling only; use EndpointResponsePlan::dry_run or suspend_process_tree_execution for live response plans". No production caller in `apps/agent/src-tauri/`. Only `edr/mod.rs` tests reach it. **TEST_ONLY**; eligible for deletion as a dry-run-only path that is never exercised in production.

9. **`EndpointResponseExecutionReport::terminate_process_tree(...)`** — fn, 12 LOC at `response.rs:1123-1133`. Only called by `edr/mod.rs:8216` test, expected to be rejected. **TEST_ONLY**.

10. **`EndpointResponsePlan::dry_run(...)`** — _(SUSPECT)_ fn, 11 LOC at `response.rs:63-72`. Externally called from `apps/agent/src-tauri/src/api_server.rs:19426` and `apps/agent/src-tauri/src/edr/handlers/response.rs:92`. **NOT dead in production.** Listed here only to flag that all _other_ callers in `edr/mod.rs` are tests; keep as USED.

11. **`HoneyArtifact::matches_path()`, `HoneyArtifact::matches_network_destination()`, `HoneyArtifact::matches_browser_cookie_access()`, `HoneyArtifact::browser_cookie_indicators()`** — ~74 LOC combined in `deception.rs:60-149`. Callers exist but **only inside `edr/mod.rs`** (lines 2017, 2025-2042, 2058). They are essentially private helpers exposed as `pub` for the sole reason that `mod.rs` lives in a sibling file. Convert to `pub(crate)` (zero LOC removal) or push the call sites into `deception.rs` and delete the helpers entirely once unused.

12. **`EndpointEvent::kind_name()`** — fn, 20 LOC at `event.rs:128-147`. Callers: only `edr/causal/recorder.rs`, `edr/event.rs` (self), and tests. No external consumer. Convert to `pub(crate)`.

## Suspect Dead Symbols (probably dead, verify)

These warrant a manual verification pass before deletion:

- **`EndpointTelemetryFieldProjection`, `EndpointTelemetryObservationProjection`** — no Rust caller outside `edr/`, but mirrored verbatim in `apps/control-console/src/api/client.ts` and `apps/control-console/src/pages/PrivacyReport.tsx` (consumed as TypeScript types over the JSON wire). They _are_ structurally required by the parent `EndpointTelemetryPrivacyReport` field (`projections: Vec<EndpointTelemetryFieldProjection>`). **Verify**: nothing in TS/Python SDKs imports either name as a runtime guard before considering removal. Verdict: TYPE_ECHO, keep, but consider making them `pub` only within the `privacy` submodule once the API freezes.

- **`EndpointPolicySimulationAffectedNode`** — only ever constructed inside `simulation.rs::classify_simulated_affected_node` and assigned to `EndpointPolicySimulationReport::affected_nodes`. The only external "construction" is `affected_nodes: Vec::new()` (zero items) at `api_server.rs:36619`. Verdict: TYPE_ECHO required by JSON shape, **keep**.

- **`DetectionEvidence`** — never named outside `edr/`. Only a field of `DetectionFinding::evidence`. TYPE_ECHO required by JSON shape, **keep**.

- **`EndpointReceiptSigner`, `EndpointClockState`** — only consumed by `edr/receipt/mod.rs` (a separate audit per the brief). If that audit also decides those receipt structs are dead, these come down with them. **Keep for now**, but mark as eligible for relocation into `edr/receipt/` directly so the public API surface shrinks.

- **`EndpointResponseExecutionEffect::quarantine_file()` and `…::disable_persistence()`** — currently `pub`, but only called once each from inside `response.rs` itself. Either delete and inline, or downgrade to `pub(crate)`. Low risk.

- **`EndpointResponsePlan::terminate_process_tree_execution` (item 8 above)** — the `note = "…dry-run/modeling only…"` string in the source proves the author already knows this is vestigial; the only call site is a test that asserts "report is rejected". Safe to delete.

- **`CausalGraphRecorder::new()` and `CausalGraphRecorder::graph()`** — only called from `flight_recorder/mod.rs` (inside `edr/`). The `Default` impl gives equivalent behaviour. Convert to `pub(crate)`.

## Removable LOC Estimate

| File | Total LOC | Removable LOC | % shrink |
|---|---:|---:|---:|
| `edr/mod.rs` | 9,836 | ~7,500 (move tests out + drop `#![allow]`) | ~76 % |
| `edr/flight_recorder/mod.rs` | 1,449 | ~80 (snapshot + read_observations + read_observation_window + private helper they delegate to) | ~5 % |
| `edr/causal/recorder.rs` | 717 | ~25 (causal_path) | ~3 % |
| `edr/response.rs` | 1,741 | ~125 (terminate_process_tree_execution + report ctor; ExecEffect::quarantine_file/disable_persistence converted to pub(crate) = 0 LOC) | ~7 % |
| `edr/sensor_state.rs` | 58 | ~20 (single_active_agent → inline in tests) | ~34 % |
| `edr/privacy.rs` | 183 | ~6 (from_observations wrapper) | ~3 % |
| `edr/deception.rs` | 254 | 0 LOC (visibility-only changes to pub(crate)) | 0 % |
| `edr/event.rs` | 556 | 0 LOC (`kind_name` to pub(crate)) | 0 % |
| **Total (production)** | **~14,800** | **~7,756** | **~52 %** |

Of the ~7,756 removable LOC, **~7,500 are the in-file test mega-block** that should be split out of `edr/mod.rs` (not deleted, but relocated). The genuine dead-code wipe is only ~256 LOC. The big win is structural.

## Refactor Notes

After this clean-up:

1. **Drop `#![allow(dead_code, unused_imports)]` at `edr/mod.rs:8`.** Once test code is relocated and the listed `pub` items become `pub(crate)` or are deleted, the allow becomes unnecessary. Removing it lets `cargo clippy` and `cargo fix --lib` surface the next wave of rot automatically.

2. **Replace blanket `pub use foo::*` re-exports (lines 25-45 of `edr/mod.rs`) with explicit lists.** With the existing globs, every new `pub fn` in a sibling becomes a `clawdstrike_policy_event::edr::*` re-export by accident. Explicit lists make the API surface a deliberate decision.

3. **Collapse `edr/flight_recorder/` into a single file or move the index/compaction types up a level.** The directory currently has `compaction.rs` (23 LOC), `index.rs` (80 LOC), `mod.rs` (1,449 LOC) — the split costs more navigation than it saves. Both `compaction.rs` and `index.rs` are pure type definitions consumed only by `flight_recorder/mod.rs` and `api_server.rs`. Either inline them into `flight_recorder/mod.rs` or move them under `edr/` as `flight_recorder_compaction.rs` / `flight_recorder_index.rs` siblings.

4. **Split `edr/mod.rs` tests into per-feature files** under `crates/libs/clawdstrike-policy-event/tests/edr_*.rs` (integration tests) or sibling `tests` submodules. The 88-test, 7,453-line block is unscannable and is the single biggest reason `mod.rs` is 9,836 lines.

5. **Move `edr/receipt/` consumers' usage of `EndpointClockState` / `EndpointReceiptSigner` / `EndpointDecisionActor::with_endpoint_id*` into `edr/receipt/` directly** — these helpers have no caller _outside_ that submodule. Pulling them in lets `edr/actor.rs` shrink to just `EndpointDecisionActor` + `EndpointPolicySnapshot` (the two types actually exported through the public API).

6. **`HoneyArtifact::matches_*` helpers and `EndpointEvent::kind_name()` should be `pub(crate)`.** They're called only from `edr/mod.rs` and `edr/causal/recorder.rs`. Demoting visibility makes future `pub` audits cheaper.

7. **The `#[deprecated]`-style comment on `EndpointResponsePlan::terminate_process_tree_execution`** (response.rs:177) should be promoted to an actual `#[deprecated(note = "…")]` attribute or deleted outright — the current free-form comment provides no compile-time pressure.

## Recommended Sequence

A safe commit-by-commit plan. Each step compiles and tests pass on its own.

**Commit 1 — Delete the orphan flight-recorder API.**
- Remove `EndpointFlightRecorderSnapshot` struct, `EndpointFlightRecorder::snapshot()`, `EndpointFlightRecorder::read_observations()`, `EndpointFlightRecorder::read_observation_window()` (and the private `read_endpoint_observation_window` helper it wraps, once verified no other caller).
- Net: ~80 LOC, zero callers, zero behaviour change.

**Commit 2 — Delete `CausalGraphRecorder::causal_path`.**
- Net: ~25 LOC. Single fn, no caller.

**Commit 3 — Delete the dry-run-only `terminate_process_tree` paths.**
- Remove `EndpointResponsePlan::terminate_process_tree_execution`, `EndpointResponseExecutionReport::terminate_process_tree` and the one `edr/mod.rs` test that exercises them (`endpoint_terminate_process_tree_execution_report_is_rejected` at line 8186).
- Net: ~130 LOC. The note in `response.rs:177` confirms author intent.

**Commit 4 — Demote internal-only `pub` to `pub(crate)`.**
- `HoneyArtifact::matches_path / matches_network_destination / matches_browser_cookie_access / browser_cookie_indicators`
- `EndpointEvent::kind_name`
- `EndpointTelemetryPrivacyMode::permits_raw_artifacts`
- `EndpointResponseExecutionEffect::quarantine_file`, `EndpointResponseExecutionEffect::disable_persistence`
- `CausalGraphRecorder::new`, `CausalGraphRecorder::graph`
- `EndpointProcess::stable_node_id`
- Net: 0 LOC removed, but the public API shrinks meaningfully.

**Commit 5 — Inline single-use test fixtures.**
- Delete `EndpointSensorState::single_active_agent` (20 LOC); replace the ~10 test call sites with a `fn single_active_agent_for_test()` defined inside the `tests` mod, or an explicit literal.
- Delete `EndpointTelemetryPrivacyReport::from_observations` (6 LOC); update tests to call `from_observations_with_raw_artifact_approval(obs, mode, None, None)`.

**Commit 6 — Split the 7,453-line test mega-block.**
- Move `edr/mod.rs` lines 2384-9836 into per-area files under `crates/libs/clawdstrike-policy-event/tests/` (or a new `crates/libs/clawdstrike-policy-event/src/edr/tests/` subdir). Suggested grouping:
  - `tests_response_execution.rs` (~3,000 LOC)
  - `tests_response_rollback.rs` (~1,500 LOC)
  - `tests_privacy.rs` (~400 LOC)
  - `tests_supply_chain.rs` (~800 LOC)
  - `tests_flight_recorder.rs` (~800 LOC)
  - `tests_simulation.rs` (~400 LOC)
  - `tests_deception.rs` (~400 LOC)
  - residual `tests_misc.rs`
- After: `edr/mod.rs` shrinks from 9,836 to ~2,380 LOC.

**Commit 7 — Drop `#![allow(dead_code, unused_imports)]` from `edr/mod.rs:8`.**
- Replace blanket `pub use foo::*` (lines 25-45) with explicit re-exports. Anything that was relying on the glob is now visible.
- Run `cargo clippy -p clawdstrike-policy-event --all-features` and fix remaining warnings.

**Commit 8 (optional) — Relocate `EndpointClockState`, `EndpointReceiptSigner` and the actor helpers into `edr/receipt/`.**
- These types live in `edr/actor.rs` but have zero non-receipt consumers. Moving them shrinks the public API surface of `edr::actor` to the two types it actually owns.
- Coordinate with the `edr/receipt/` audit (the separate Wave 3 line item).

**Final state:** `edr/mod.rs` becomes a ~2,300-LOC file of pure projection helpers and re-export wiring, no in-file tests, no dead-code allow, and the `pub` surface accurately reflects what callers actually use.

---

*Audit date: 2026-05-23. Repo state: branch `fix/macos-es-ne-hardening`, commit `2eff91532`. Scope: `crates/libs/clawdstrike-policy-event/src/edr/{*.rs, causal/*.rs, detection/*.rs, flight_recorder/*.rs}` excluding `edr/receipt/` (separate audit) and `infra/vendor/`, `.claude/worktrees/`, `.worktrees/`.*
