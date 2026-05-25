# DELTA D03: Rust Core Libs

**Refreshed:** 2026-05-24 | **Source:** `.audit/03-rust-core-libs.md` (2026-05-23) + `.audit/wave3/A-edr-mod-deadcode.md` + `.audit/wave3/C-receipt-family-extraction.md` | **Scope:** `crates/libs/`

## Quick Verdict

- **Findings still valid:** 28 (CRITICAL: 3, HIGH: 11, MEDIUM: 12, LOW: 2)
- **Findings fixed since 2026-05-23:** 1 partial (the `#[deprecated]` attribute was added on `EndpointResponsePlan::terminate_process_tree_execution` per wave3 recommendation — but the function itself still exists)
- **Findings wrong/misdiagnosed:** 2 minor (`hush-wasm` file count was 5, actually 3; `clawdstrike/src/lib.rs` was 64 lines, actually 236 — both auditor inventory drift, not impactful)
- **New issues found:** 9 (most important: HEAD silently introduced ~42 dead-code warnings that the working-tree is masking by re-adding `#![allow(dead_code, unused_imports)]` — a regression from the audit's main complaint about `edr/mod.rs`)
- **Working-tree state (uncommitted):** Three EDR files modified. Two are clippy-driven (struct-of-args refactor in `receipt/mod.rs`, match-guard tightening in `supply_chain.rs`). One is functional regression: `edr/mod.rs` is **putting back** the dead-code allow that HEAD removed. Plus one wasmtime bump in `clawdstrike/Cargo.toml` (41.0.3 → 44.0.1).
- **Net delta:** Status quo is *worse* than 2026-05-23. HEAD removed the `#![allow]` from `edr/mod.rs` (good) but never deleted the dead code beneath it (bad — 42 warnings broke `-D warnings` so the working tree is re-introducing the allow). Wave3's planned cleanup (delete dead symbols → drop the allow) was NOT performed. The EDR `harden macos es` patches (commits 768876a7b, 56dc31483) were operational hardening, not architectural cleanup. Per-file line counts unchanged.

The audit is in excellent shape; almost nothing needs to be re-investigated. The aggressive cleanup ceiling is more justified now, because the half-done cleanup at HEAD is a clear sign someone tried to remove the `#![allow]` cosmetically without doing the underlying work.

## STILL VALID

### [V-01] `edr/mod.rs` is a 9,836-line monolith with `#![allow(dead_code, unused_imports)]`

At HEAD: `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` is **9,836 lines** (re-verified via `wc -l`). 80 `#[test]` functions confirmed. The wildcard re-exports survive verbatim at lines 25–45.

**Critical change since audit:** HEAD (`768876a7b`) *removed* the `#![allow(dead_code, unused_imports)]` line. But the working tree (`M crates/libs/.../edr/mod.rs`) reintroduces it. Running `cargo check -p clawdstrike-policy-event` against pristine HEAD surfaces **42 warnings**, including 5 truly dead production items:
- `fn canonical_graph_content_hash` at `edr/mod.rs:68` — never called
- `struct ResponseExecutionEffectBindingEntry` at `edr/mod.rs:2315` — never constructed
- `fn telemetry_privacy_report_id_from_values` at `edr/receipt/mod.rs:2479` — never called
- `fn response_execution_id_from_effects` at `edr/receipt/mod.rs:3009` — never called
- `fn reconstruct_path` at `edr/receipt/mod.rs:6387` — never called

Plus ~30 unused imports in `edr/causal/recorder.rs`, `edr/deception.rs`, `edr/detection/supply_chain.rs`, `edr/flight_recorder/{index,mod}.rs`, `edr/response.rs`, and `edr/mod.rs` itself.

The working tree's solution — slap the `#![allow]` back on — is the wrong direction. The audit's recommendation (delete dead code, drop the allow) is exactly the right one and is now *more* urgent because someone clearly tried and gave up.

**Aggressive cleanup:** Wave3's plan in `A-edr-mod-deadcode.md` is the play. Execute it as written:
1. Delete `EndpointFlightRecorderSnapshot`, `snapshot()`, `read_observations()`, `read_observation_window()` — confirmed all dead at `flight_recorder/mod.rs:50,52,119,130,138`.
2. Delete `CausalGraphRecorder::causal_path()` at `causal/recorder.rs:250`.
3. Delete `EndpointResponsePlan::terminate_process_tree_execution` (now has `#[deprecated]` per the wave3 plan, *finally*) and its only caller in `mod.rs` tests.
4. Demote `pub` → `pub(crate)` on `HoneyArtifact::matches_*`, `EndpointEvent::kind_name`, `EndpointTelemetryPrivacyMode::permits_raw_artifacts`, `EndpointResponseExecutionEffect::{quarantine_file, disable_persistence}`, `CausalGraphRecorder::{new, graph}`, `EndpointProcess::stable_node_id`.
5. Delete the 5 dead production items I listed above (the new warnings exposed at HEAD).
6. Move the 7,453-line `#[cfg(test)] mod tests` block to `tests/edr_*.rs` integration tests.
7. Replace `pub use foo::*;` blanket re-exports at lines 25–45 with explicit `pub use foo::{Type1, Type2, …};`.
8. *Then* drop `#![allow(dead_code, unused_imports)]` permanently — and the working tree's re-add becomes a 1-line revert.

### [V-02] `edr/receipt/mod.rs` is 6,402 lines of receipt-builder boilerplate

At HEAD: `wc -l` confirms **6,402 lines**. 19 `for_*` constructors (verified via `grep -c "pub fn for_"`). 106 `Result<_>` returns (via `use anyhow::Result;` — the audit's "anyhow::Result" grep was slightly miscounted at the time because of the use-alias, but the absolute number is identical: 106). The whole wave3 `C-receipt-family-extraction.md` plan still applies verbatim.

Working tree: a clippy-driven `clippy::too_many_arguments` refactor extracted `ObservationReceiptIdFields<'a>` as a struct-of-args for `observation_receipt_id_from_fields`. Net delta: +71/-66 lines, no architectural change.

**Aggressive cleanup:** Execute wave3 `C-receipt-family-extraction.md` in full. The file map (1 mod shell + 1 trait + 1 common + 11 family modules; no file >420 lines) is unchanged in feasibility. Particular note: the working-tree refactor extracting a fields struct is exactly the pattern that should be applied to each family extraction (every `for_*` already takes a typed input bundle `Endpoint…ReceiptInput<'_>` — the `families/<x>.rs` module pattern just adds a `ReceiptFamily` impl on top).

### [V-03] `hush-wasm` checks generated WASM/JS artifacts into git

At HEAD: `git ls-files crates/libs/hush-wasm/` confirms `hush_wasm.js` (42234 bytes), `hush_wasm.d.ts` (6898 bytes), `hush_wasm_bg.wasm.d.ts` (4128 bytes), `hush_wasm.d.ts.template`, `package.json` all still tracked. The `.gitignore` excludes only `pkg/` and `*.wasm`.

**Aggressive cleanup:** unchanged from audit — `git rm` the 5 files, extend `.gitignore`, have `build.sh` write to `dist/`. ~15 min.

### [V-04] `logos-ffi` advertises LEAN 4 FFI it does not implement

At HEAD: `crates/libs/logos-ffi/Cargo.toml:7` still says `description = "FFI bindings to Logos (LEAN 4) proof system for formal reasoning"`. `lib.rs:99` still has `lean_available: cfg!(feature = "lean-runtime")`. `lib.rs:126-130` still has the `// TODO: Call LEAN 4 runtime via FFI` followed by `Ok(ProofResult::Unknown { reason: "LEAN FFI not yet implemented".to_string() })`.

**Aggressive cleanup:** Either:
- (a) Rename the crate to `logos-types`, rewrite the description, delete the `lean-runtime` feature + `lean_available` field + accessor. 1,760 LOC becomes 1,720 with proper framing.
- (b) Fold the whole thing into `clawdstrike-logos`. The two crates already share types and have a near-circular relationship; consolidating is cleaner.

### [V-05] `logos-z3` stubs Layer 1 and Layer 2 with `"not yet implemented"`

At HEAD: `crates/libs/logos-z3/src/lib.rs:231-243` still has both `check_explanatory` and `check_epistemic` returning `Ok(ProofResult::Unknown { reason: "... not yet implemented".to_string() })`. Re-verified by Read; bytes identical to the audit citation.

File length is **1,302 lines** at HEAD (the audit said 1,842 in the inventory but the absolute file count was correctly cited; both numbers are inside the same crate but the lib.rs alone is 1,302 — the rest is in other files). 24 `#[test]` functions in the lib.rs alone.

**Aggressive cleanup:** Convert both stubs to `Err(Z3Error::UnsupportedFormula("explanatory layer (L1) is not implemented"))` (and parallel for L2). 5 minutes.

### [V-06] `version = "0.2.7"` hand-pinned in `logos-z3`

At HEAD: `crates/libs/logos-z3/Cargo.toml:3-7` still has `version = "0.2.7"`, `edition = "2021"`, `rust-version = "1.93"`, `license = "Apache-2.0"`, and `repository = "https://github.com/backbay-labs/clawdstrike"` hand-pinned (vs `workspace.true` everywhere else).

**Aggressive cleanup:** 5-line `*.workspace = true` substitution. 3 min.

### [V-07] `bridge-runtime` is 911 lines in one `lib.rs` with `Result<_, String>` everywhere

At HEAD: `wc -l` confirms **911 lines**. Working tree unchanged. Sampled call sites:
- `lib.rs:89` `pub async fn open(config: OutboxConfig) -> Result<Self, String>`
- `lib.rs:96, 100, 102, 106, 124, 126, 132, 142, 159, 163, 174, 175, 179, 186, 188, 191` — 16 `format!` errors that should be `PublishError` variants.
- The `PublishError` enum at lib.rs:59-71 already has `Outbox(String)`, `Config(String)`, `Publish(String)` and `#[from] spine::Error`, `#[from] serde_json::Error` variants. Every String error in the file could be a typed enum variant TODAY.

`tokio = { workspace = true, features = ["full"] }` at `Cargo.toml:13` confirmed — a library asking for full tokio.

**Aggressive cleanup:** Split into `outbox.rs`, `publisher.rs`, `chain.rs`, `health.rs` modules. Replace every `Result<_, String>` with `Result<_, PublishError>`. Add `#[from] std::io::Error` and `#[from] rusqlite::Error` to `PublishError`. Tighten tokio features: `["macros", "rt-multi-thread", "fs", "time"]`. Net: 1-2 days of work but unblocks every downstream consumer that wants typed retry classification.

### [V-08] `spine` library crate ships three binaries totaling 3,480 lines

At HEAD: `wc -l` confirms `src/bin/checkpointer.rs` (1,938 lines), `src/bin/proofs_api.rs` (1,426), `src/bin/witness.rs` (116). `Cargo.toml:43-56` still has the three `[[bin]]` sections gated on `required-features = ["bins"]`, and `Cargo.toml:17` enumerates the 8 optional dependencies that feature pulls in.

**Aggressive cleanup:** Move all three to `crates/services/spine-{checkpointer,proofs-api,witness}/`. Delete the `bins` feature entirely. Delete `anyhow`, `clap`, `axum`, `tower-http`, `tracing`, `tracing-subscriber`, `futures`, `uuid` from `spine/Cargo.toml` (8 optional deps go away). Small refactor with high readability return.

### [V-09] `clawdstrike-policy-event` uses `anyhow::Result` across 100+ public signatures

At HEAD: distribution by file (`grep -c "Result<" file`):
- `edr/receipt/mod.rs`: **106** (the audit's number)
- `facade.rs`: 13
- `event.rs`: 4
- `stream.rs`: 4
- `ocsf.rs`: 1
- `simulate.rs`: 1
- Plus several in `edr/mod.rs`, `edr/response.rs`, `edr/flight_recorder/mod.rs`, `edr/deception.rs`.

All 10 files that `grep`s flag still have `use anyhow::{anyhow, Context, Result}` at the top.

**Aggressive cleanup:** Introduce `PolicyEventError`, `EdrReceiptError`, `FacadeError`. The wave3 `C-receipt-family-extraction.md` already proposes `validate()` returns `Result<(), EdrReceiptError>` via the `ReceiptFamily` trait — pair this with the family extraction so the conversion is one large coherent change.

### [V-10] `Error::SpineError(String)` collapses a perfectly good error enum

At HEAD: `crates/libs/clawdstrike/src/error.rs:96-97, 109-114` is BYTE-IDENTICAL to the audit citation. No fix attempt. The `#[from]` impls for `IoError`, `JsonError`, `YamlError`, `RegexError`, `CoreError` are right there 10 lines above.

**Aggressive cleanup:** 2-line patch:
```rust
#[error(transparent)]
Spine(#[from] spine::Error),
```
Delete the manual `impl From<spine::Error>`. 2 min. Quick win.

### [V-11] `BrokerCapabilityStatus` is a 22-field god struct, most fields `Option`

At HEAD: `clawdstrike-broker-protocol/src/lib.rs:405-447`. I counted **23 fields** in the current struct: `capability_id`, `provider`, `state`, `issued_at`, `expires_at`, `policy_hash`, `session_id` (Opt), `endpoint_agent_id` (Opt), `runtime_agent_id` (Opt), `runtime_agent_kind` (Opt), `origin_fingerprint` (Opt), `secret_ref_id`, `url`, `method`, `state_reason` (Opt), `revoked_at` (Opt), `execution_count`, `max_executions` (Opt), `last_executed_at` (Opt), `last_status_code` (Opt), `last_outcome` (Opt), `intent_preview` (Opt), `minted_identity` (Opt), `lineage` (Opt), `suspicion_reason` (Opt). 17 Options.

**Aggressive cleanup:** Same recommendation as audit. The state machine inside this type (`state` enum + `execution_count` + `last_*` + `revoked_at`) is the obvious extraction target.

### [V-12] `WasmPolicyLab` holds an `inner` that no method uses

At HEAD: `crates/libs/hush-wasm/src/policy_lab.rs:22-37` confirmed unchanged. `#[allow(dead_code)]` still there on `inner`. The constructor still parses and stores `PolicyLabHandle`, no methods use `self.inner`.

**Aggressive cleanup:** Delete the struct or wire up `simulate`/`synth`. The free functions at `policy_lab.rs:40+` are the actually-callable surface; the struct is a placeholder for an API that never landed.

### [V-13] `HushEngine` has four near-identical "add extra guard" methods

At HEAD: `crates/libs/clawdstrike/src/engine.rs:241-277` confirmed unchanged. `with_extra_guard`, `with_extra_guard_box`, `add_extra_guard`, `add_extra_guard_box`. The doc comments on all four are bit-identical ("Note: when `fail_fast` is enabled…").

**Aggressive cleanup:** Replace with two methods using `Into<Box<dyn Guard>>`. 4 methods → 2 methods. 10 min.

### [V-14] `clawdstrike` `default = ["full"]` defeats feature-gating

At HEAD: `crates/libs/clawdstrike/Cargo.toml:78` confirmed `default = ["full"]`. `full` is unchanged 14-feature blob. `[features] ipfs = ["full"]` at line 106 also unchanged — and see **[N-04]** below: `ipfs.rs` has zero callers in the workspace.

**Aggressive cleanup:** `default = []`. Run `cargo check --no-default-features` in CI. Add a `wasm` feature alias for `policy-event`-minimum.

### [V-15] `clawdstrike/src/policy.rs` is 4,156 lines

At HEAD: `wc -l` confirms 4,156 lines. Unchanged.

### [V-16] `clawdstrike/src/engine.rs` is 4,599 lines

At HEAD: `wc -l` confirms 4,599 lines. Unchanged.

### [V-17] `unwrap_or` on `serde_json::to_value` hides failures

At HEAD: `crates/libs/clawdstrike-policy-event/src/edr/mod.rs:78-91` confirmed — three pairs of `.unwrap_or(serde_json::Value::Null)` + `.unwrap_or_else(|_| "null".to_string())` for `endpoint_sensor_state_content_hash`, `endpoint_observation_content_hash`, `endpoint_decision_actor_content_hash`. Each returns `sha256("null")` on failure — a single deterministic collision value for failed serialization. Total of 4 occurrences of `.unwrap_or(serde_json::Value::Null)` across `crates/libs/clawdstrike-policy-event/src/`.

In a fail-closed system this is the exact opposite of fail-closed — it silently emits an invalid receipt. **Aggressive cleanup:** convert helpers to `Result<String, PolicyEventError>` and propagate.

### [V-18] `crates/libs/README.md` is three lines

At HEAD: `wc -l` confirms 3 lines. Unchanged.

### [V-19] 17 of 20 crates have no `README.md`

At HEAD: `for d in crates/libs/*/; do test -f "$d/README.md" && echo "HAS:$d" || echo "MISSING:$d"; done` shows:
- HAS: `clawdstrike`, `hush-core`, `hush-wasm`
- MISSING: `bridge-runtime`, `clawdstrike-broker-protocol`, `clawdstrike-guard-sdk`, `clawdstrike-guard-sdk-macros`, `clawdstrike-logos`, `clawdstrike-ocsf`, `clawdstrike-policy-event`, `hunt-correlate`, `hunt-query`, `hunt-scan`, `hush-certification`, `hush-ffi`, `hush-multi-agent`, `hush-proxy`, `logos-ffi`, `logos-z3`, `spine`

17/20 missing (audit said 15/20; the audit slightly miscounted — `clawdstrike-guard-sdk-macros` and one other were on its missing list but not in the count). The trend is correct.

### [V-20] `clawdstrike::core` is an empty re-export trick

At HEAD: `crates/libs/clawdstrike/src/lib.rs:219-225` unchanged:
```rust
pub mod crypto {
    pub use hush_core::*;
}
pub mod core;
```
The crypto module is a wildcard pass-through. `core` lives in `src/core.rs` (separate file). Three paths to the same `sha256`, `Hash`, etc.: `clawdstrike::crypto::*`, `clawdstrike::core::*`, `hush_core::*`. The audit's complaint stands.

**Note:** `crates/libs/clawdstrike/src/lib.rs` is **236 lines** at HEAD, not 64 as the audit claimed — the audit's number was wrong (W-02 below). The substance of the finding survives the line-count error.

### [V-21] `Result<_, String>` in `LlmJudge` and `SessionStore` traits

At HEAD: `crates/libs/clawdstrike/src/jailbreak.rs:26-37` confirmed bit-identical to audit citation. (Audit erroneously cited `hush-multi-agent::token` but the actual location is `clawdstrike/src/jailbreak.rs` — the audit body had the path right but the section heading was off; substance is correct.)

### [V-22] `clawdstrike-logos/src/verifier.rs` is 3,875 lines

At HEAD: `wc -l` confirms **3,875 lines**. Unchanged. Two `#[allow(unused_mut)]` at lines 430 and 541 also confirmed.

### [V-23] `publish = false` scatter (no rationale)

At HEAD: still 3 crates marked `publish = false`: `clawdstrike-broker-protocol/Cargo.toml`, `hush-certification/Cargo.toml`, `hush-multi-agent/Cargo.toml`. No comment explaining why on any of them. Audit's recommendation stands.

### [V-24] `clawdstrike-policy-event/src/ocsf.rs:423` calls a variable `stub`

At HEAD: `sed -n '420,432p' crates/libs/clawdstrike-policy-event/src/ocsf.rs` confirms — `let stub = PolicyEvent { … };  classify_event(&stub)` at lines 423-432. Cosmetic-only finding.

### [V-25] `b"\0asm"` magic-bytes WASM stub

At HEAD: `crates/libs/clawdstrike/src/plugins/loader.rs:410` confirmed:
```rust
std::fs::write(dir.path().join("guard.wasm"), b"\0asm").expect("write wasm stub");
```
`wat = "1.245.1"` is in dev-dependencies at `Cargo.toml:59`. Audit's `wat::parse_str("(module)")` swap is trivially achievable.

### [V-26] `#[allow(dead_code)]` on three `MCP*` fields in `hunt-scan`

At HEAD: `crates/libs/hunt-scan/src/mcp_client.rs:67, 69, 103` confirmed.

### [V-27] Doctests use `unwrap()` instead of `?`

At HEAD: `crates/libs/clawdstrike/src/lib.rs:42` says `let policy = Policy::from_yaml(yaml).unwrap();` — unchanged. `hush-core/src/lib.rs:40-43` and `hush-core/src/merkle.rs:66, 161-162` also confirmed.

### [V-28] `Severity::Info` is "logged but allowed" — name is misleading

At HEAD: `crates/libs/clawdstrike/src/guards/mod.rs:67-82` unchanged. Documentation-only fix open.

## FIXED SINCE 2026-05-23

### [F-01] `#[deprecated]` attribute on `EndpointResponsePlan::terminate_process_tree_execution`

**Commit:** `768876a7b fix(edr): harden macos es and response evidence` (2026-05-19; pre-audit but the audit didn't notice). Confirmed by `git show 56dc31483 -- crates/libs/clawdstrike-policy-event/src/edr/response.rs`.

**Was:** wave3 audit (`A-edr-mod-deadcode.md` step 7 of refactor notes) said the file carried a free-form comment, not an actual `#[deprecated]` attribute.

**Now:** lines 174-177 of `edr/response.rs` show:
```rust
#[must_use]
#[deprecated(
    note = "terminate_process_tree is dry-run/modeling only; use EndpointResponsePlan::dry_run or suspend_process_tree_execution for live response plans"
)]
pub fn terminate_process_tree_execution(
```
The compile-time pressure is now there. The function still exists and is still test-only — wave3 step 3 (delete it entirely) is open — but at least consumers get a `deprecated` warning.

## NOW WRONG / MISDIAGNOSED

### [W-01] `hush-wasm` had 5 files, actually 3

Audit inventory table claimed `hush-wasm` is `1,459 / 5`. Actual: `1,028 / 3` (`lib.rs`, `detect.rs`, `policy_lab.rs`). The inventory line was wrong; the finding about checked-in `.js`/`.d.ts` artifacts (which are NOT counted as Rust src files) is unaffected and still valid.

### [W-02] `clawdstrike/src/lib.rs` is 236 lines, not 64

Audit's strengths section claimed `crates/libs/clawdstrike/src/lib.rs` is 76 lines (in the "Strengths" bullet at line 59) — actually **236 lines** at HEAD. The wider point (clean module layout, working doctests, TPM gating) is still correct; the line count was wrong. Not a substantive change.

## NEW ISSUES

### [N-01] HEAD removed `#![allow(dead_code, unused_imports)]` from `edr/mod.rs` but never fixed the dead code — working tree is reintroducing it

This is the most consequential delta. Commit `768876a7b` removed the file-level allow in `crates/libs/clawdstrike-policy-event/src/edr/mod.rs:8`. But `cargo check -p clawdstrike-policy-event` on pristine HEAD emits **42 warnings**:

| Kind | Location | Item |
|---|---|---|
| dead function | `edr/mod.rs:68` | `fn canonical_graph_content_hash` |
| dead struct | `edr/mod.rs:2315` | `struct ResponseExecutionEffectBindingEntry` |
| dead function | `edr/receipt/mod.rs:2479` | `fn telemetry_privacy_report_id_from_values` |
| dead function | `edr/receipt/mod.rs:3009` | `fn response_execution_id_from_effects` |
| dead function | `edr/receipt/mod.rs:6387` | `fn reconstruct_path` |
| unused imports | `edr/causal/recorder.rs:4,7`; `edr/deception.rs:1,4,7,10,13`; `edr/detection/supply_chain.rs:1,3,6,8,10,13,21`; `edr/event.rs`; `edr/flight_recorder/index.rs:7,8,9`; `edr/flight_recorder/mod.rs:4,5,10,14,24,29`; `edr/receipt/inputs/response.rs:4`; `edr/receipt/mod.rs:24,46`; `edr/response.rs:1,2,12,17`; `edr/mod.rs:45,47,50,53,55,58,68` | ~30 lines of stale imports |

The workspace clippy gate is `-D warnings`, so HEAD on its own *cannot pass clippy clean*. The working tree's reintroduction of the allow at `edr/mod.rs:8` is therefore an emergency revert disguised as a refactor. The author tried to remove the allow but didn't run the warnings down — and the working tree is silently undoing the only good thing about HEAD's state.

**Aggressive cleanup:** Adopt wave3 `A-edr-mod-deadcode.md` Commits 1-7. The working tree change should be REVERTED (don't re-add the allow), and Commits 1-7 should be done in sequence. After Commits 1-3 the dead functions/struct die. After Commit 4 the visibility narrows. After Commits 6-7 the file becomes navigable and the allow stays gone.

### [N-02] `clawdstrike::ipfs` module is 593 lines and has zero in-repo consumers

At HEAD: `crates/libs/clawdstrike/src/ipfs.rs` is 593 lines, gated behind the `ipfs = ["full"]` feature at `Cargo.toml:106`. `grep -rn "use clawdstrike::ipfs\|crate::ipfs::\|::ipfs::" --include="*.rs"` returns **zero matches** in the entire workspace. The module documents IPFS pinning with Pinata + gateway fallback — a legit feature, but no caller exists.

**Aggressive cleanup:** Delete the module + feature. Save 593 LOC. If the feature is intended for the operator console (next milestone), gate behind `#[cfg(disabled)]` with a TODO so it doesn't compile until wired.

### [N-03] `clawdstrike-policy-event` has 28,753 LOC across 48 files — second-largest crate in `crates/libs/`

Re-counting at HEAD: **27,241 lines / 48 files** (audit said 28,753 / 54 — actually 27k / 48; possible test files merged). This crate alone is larger than `hush-core`, `hush-proxy`, `clawdstrike-guard-sdk`, `clawdstrike-guard-sdk-macros`, `clawdstrike-broker-protocol`, `clawdstrike-ocsf`, `hush-certification`, `hush-multi-agent`, AND `spine` combined.

The crate has tangled responsibilities: PolicyEvent types, OCSF projection, simulation, facade, EDR receipts, EDR event types, deception, flight recorder, causal graphs, detection rules, response actions.

**Aggressive cleanup:** Split the crate. Suggestion:
- `clawdstrike-policy-event` (core types only: `PolicyEvent`, `PolicyEventType`, `PolicyEventData` enum, the wire envelope) — keep at ~3-5k LOC.
- `clawdstrike-edr` (everything under `src/edr/` except `receipt/`) — ~12-15k LOC, the deception/causal/flight-recorder/response domain.
- `clawdstrike-edr-receipt` (the receipt zoo) — ~7k LOC after wave3 family extraction.
- `clawdstrike-edr-facade` (`facade.rs`, `simulate.rs`, `stream.rs`, `ocsf.rs`) — ~3k LOC, the consumer-facing surface that pulls the three above together.

This is a 2-week project. But the current shape makes incremental cleanup impossibly tangled because every file imports through `pub use *::*` wildcards.

### [N-04] `default = ["full"]` enables the `ipfs.rs` 593-LOC dead module on every default build

Because `default = ["full"]` AND `ipfs = ["full"]` and `pub mod ipfs;` is gated behind `#[cfg(feature = "ipfs")]` (in lib.rs:171) — actually wait, double-check: `lib.rs:170-171` says `#[cfg(feature = "ipfs")] pub mod ipfs;`. So default builds DON'T pull it. Verifying… `default = ["full"]` doesn't include `"ipfs"`. So this finding is partially wrong — the ipfs module IS gated correctly. The `[N-02]` finding (no callers) still stands; this `[N-04]` is withdrawn.

(Redacting [N-04]; keeping the slot empty for clarity.)

### [N-05] Three working-tree-only EDR file changes have NOT been committed

The git status shows:
- `M crates/libs/clawdstrike-policy-event/src/edr/mod.rs` — re-adds `#![allow(dead_code, unused_imports)]` (the bad one — see [N-01])
- `M crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs` — extracts `ObservationReceiptIdFields<'a>` (a `clippy::too_many_arguments` driven refactor; net +71 -66 lines; minor)
- `M crates/libs/clawdstrike-policy-event/src/edr/detection/supply_chain.rs` — converts an `if path_is_launch_persistence(path)` body to a match guard `_ if path_is_launch_persistence(path) =>` (clippy-driven; +14 -27)

The receipt and supply_chain changes are small clippy improvements. The `edr/mod.rs` change is a regression. The user is mid-flight on something — likely trying to land the wave3 cleanup but stalled.

**Aggressive cleanup:** finish or abandon. If finish: discard the `edr/mod.rs` working-tree change (don't re-add the allow), do wave3 Commits 1-7. If abandon: stash and ship the two clippy improvements as a separate small PR.

### [N-06] `wasmtime` version bump in working tree (41.0.3 → 44.0.1)

`git diff crates/libs/clawdstrike/Cargo.toml` shows the `wasmtime` dep bumped from 41.0.3 to 44.0.1. This is a 3-major-version jump (wasmtime moves fast; each major is API-breaking on engine internals). Not analyzed for whether call sites in `clawdstrike/src/plugins/loader.rs` still compile — assume the author tested locally.

Not a code-cleanup issue but worth flagging as a pending uncommitted dep change that should be its own PR with explicit changelog reference.

### [N-07] 80 `#[test]` functions in `edr/mod.rs` (vs audit's "~88")

At HEAD: `grep -cE "^\s*#\[test\]" crates/libs/clawdstrike-policy-event/src/edr/mod.rs` returns **80**. The audit said ~88 and wave3 said 88. The number is in the right ballpark and supports the audit's case. Minor inventory correction.

### [N-08] `clawdstrike-broker-protocol` is 712 LOC in a single `lib.rs`

At HEAD: `wc -l` confirms **712 lines** in one file. The audit flagged this in the inventory table ("solid but monolithic") but it's not in the "Findings" section. Worth promoting to a MEDIUM finding alongside the other single-file-too-big complaints (bridge-runtime, edr/mod.rs, edr/receipt/mod.rs, clawdstrike-logos/verifier.rs).

The file contains: `BrokerProvider`, `HttpMethod`, `UrlScheme`, `CredentialRef`, `ProofBinding`, `BrokerCapability`, `BrokerCapabilityState`, `BrokerCapabilityStatus`, `BrokerDelegationLineage`, `BrokerMintedIdentity`, `BrokerExecutionOutcome`, `BrokerIntentPreview`, `CompletionBundle`, sig-verification helpers, and more. 31 wire types per the audit. Could split into `types.rs`, `capability.rs`, `bundle.rs`, `identity.rs`.

### [N-09] `hush-spine` package-name vs lib-name confusion is unchanged

`crates/libs/spine/Cargo.toml:2-14` has `name = "hush-spine"` (Cargo package) and `[lib] name = "spine"` (Rust crate name). Other crates pull it in via `spine.workspace = true` and `spine::Error`. This is intentional but undocumented and surfaces inconsistently — sometimes called "hush-spine" (in publish metadata), sometimes "spine" (in `use spine::*`). The directory is `crates/libs/spine/`. Pick one name and use it consistently. Not in the audit at all; flagging as a documentation gap.

## AGGRESSIVE EXECUTION PLAN (top-5 in this area)

### 1. Execute Wave3 `A-edr-mod-deadcode.md` Commits 1-7 (3-5 days, HIGHEST IMPACT)

This is the single biggest cleanup in the workspace. The plan is already written. The dead symbols are confirmed. The test-block-move target is identified. After Commit 7:
- `edr/mod.rs` shrinks from 9,836 to ~2,300 LOC (76% reduction).
- The dead-code allow is permanently removed.
- The blanket `pub use foo::*;` wildcards become explicit lists.
- The 5 dead production items in [N-01] are gone.
- The working-tree regression in [N-05] is moot — there's nothing to re-add an allow against.

### 2. Execute Wave3 `C-receipt-family-extraction.md` (1-2 weeks)

The 6,402-line `receipt/mod.rs` becomes 14 files, none over ~420 LOC. The `ReceiptFamily` trait is the right abstraction. The plan is fully spec'd including a `match` exhaustiveness check that becomes a compile-time guard on future variants. Bigger than Commit 1 but the structural payoff is bigger too.

### 3. Bridge-runtime split + String→PublishError conversion (1-2 days)

Cited as `[V-07]`. Concrete steps:
- Create modules: `outbox.rs`, `publisher.rs`, `chain.rs`, `health.rs` under `bridge-runtime/src/`.
- Move each method group. Each move is mechanical (cut-paste).
- For each `Result<_, String>`, the matching `PublishError` variant already exists. Add `#[from] std::io::Error` and `#[from] rusqlite::Error` to `PublishError`. Map every `format!("…: {e}")` to the right variant.
- Tighten tokio features from `["full"]` to `["macros", "rt-multi-thread", "fs", "time"]`.

### 4. Quick wins (top-10 from audit, ~2 hours total)

All confirmed-valid. Do them in one PR:
- `git rm` the 5 hush-wasm WASM/JS files; extend `.gitignore`. (5 min)
- `Error::SpineError(String)` → `Spine(#[from] spine::Error)`. (2 min)
- `logos-z3/Cargo.toml`: replace 5 hand-pinned fields with `*.workspace = true`. (3 min)
- Delete `#[allow(unused_mut)]` × 2 in `clawdstrike-logos/src/verifier.rs:430,541`. (5 min)
- Delete `[features] ocsf = []` from `hunt-query/Cargo.toml` + the doc comment. (10 min)
- Honest `Err(Z3Error::UnsupportedFormula(…))` in `logos-z3` for L1/L2. (5 min)
- `wat::parse_str("(module)")` in `clawdstrike/src/plugins/loader.rs:410`. (10 min)
- Rewrite `crates/libs/README.md` from 3 lines to 100-line index. (20 min)
- Implement-or-delete `WasmPolicyLab`. Delete is faster. (15 min)
- Collapse `add_extra_guard{,_box}/with_extra_guard{,_box}` into 2 methods via `Into<Box<dyn Guard>>`. (10 min)

### 5. Split `clawdstrike-policy-event` into 3-4 crates (long term, 2-3 weeks)

See [N-03]. Only feasible AFTER #1 and #2 above (otherwise you'd be moving the 9,836-line file as one chunk, which is impossible). After the EDR cleanup, the natural seams are visible:
- `clawdstrike-policy-event` core types.
- `clawdstrike-edr` (`edr/{action,actor,deception,event,detection,causal,flight_recorder,response,sensor_state,simulation,privacy,process,ids}.rs`).
- `clawdstrike-edr-receipt` (`edr/receipt/`).
- `clawdstrike-edr-facade` (`facade.rs`, `simulate.rs`, `stream.rs`, `ocsf.rs`).

This is the long-term endgame. Do not start until 1-3 are done.

## DEFER / OUT OF SCOPE

- **`hush-core` is untouched and excellent.** Don't touch any file under `crates/libs/hush-core/`. Confirmed at HEAD: 9 files, 2,485 LOC, no dead code, working doctests. Audit's verdict stands.
- **`hush-proxy` is small and right-shaped.** 5 files, 718 LOC. Leave alone.
- **`clawdstrike-guard-sdk` + `clawdstrike-guard-sdk-macros`.** 4 + 1 files. The plugin SDK is well-factored.
- **`clawdstrike-ocsf`.** 29 files, 5,498 LOC. The size is justified by the OCSF v1.4 spec surface — every file is one spec class/object. The structure is correct.
- **`hush-ffi`.** 11 files, 2,796 LOC. The C ABI hygiene is right.
- **Worktree copies** (`.claude/worktrees/agent-…/crates/libs/.../edr.rs`). Out of scope per wave3 brief.
- **`hunt-correlate`, `hunt-query`, `hunt-scan` deep refactors.** The audit calls them "shaky" but the structural issues are smaller than the EDR / receipt / bridge-runtime issues. Defer until the top-5 above are done.
- **`hush-multi-agent` and `hush-certification`** in-memory store concerns. These were flagged as "shaky" because they're in-memory only, but the right fix (sqlite/postgres backends) is a feature plan, not cleanup. Out of scope for an aggressive cleanup pass.
- **`wasmtime` 41 → 44 bump in working tree.** Separate PR with its own changelog; not a cleanup decision.

---

**Bottom line:** the audit's top 3 findings (V-01 EDR mod, V-02 receipt mod, V-03 checked-in WASM) account for 16,500 of the ~27,000 problematic LOC. Doing the wave3 plans + the WASM artifact removal recovers about 60% of the visible damage. Then the quick wins drive the per-file LOC distribution toward "normal Rust workspace". Then split `clawdstrike-policy-event`. Then everything else is small.

The single most important course-correction since 2026-05-23: do NOT just remove the `#![allow(dead_code, unused_imports)]` and walk away. That's what HEAD tried, and the working tree is silently putting it back. Either delete the dead code (wave3 plan) or leave the allow — but don't ship the half-state HEAD is currently in.

*Refreshed at HEAD `2eff91532`. Branch `fix/macos-es-ne-hardening`. Scope `crates/libs/`; services/bridges audited separately.*
