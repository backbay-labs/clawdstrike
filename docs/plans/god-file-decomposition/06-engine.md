# Step 6 — `clawdstrike/src/engine.rs`

`crates/libs/clawdstrike/src/engine.rs` — 4,614 lines (~1,796 code / ~2,818 test,
70 test fns). Effort: **M (4–6h)**. **The crown jewel** — core policy-enforcement engine,
formally verified. Do after [Step 5 `policy.rs`](./05-policy.md). Most sensitive refactor;
lean on `formal-diff-tests`.

## What it does / why it's big

The `HushEngine` facade: instantiates guards from a policy, runs an action through the
full decision flow (origin/enclave/budget prechecks → built-in fast/std guards → custom →
extra → async deep-path), aggregates a verdict, signs receipts. Big because a single
~1,250-line `impl HushEngine` carries the entire orchestration, plus a 2,819-line test
module.

## Current structure (line ranges)

- Public report types (L32–73): `GuardReport`, `GuardEvaluationMetadata`,
  `GuardResolvedEnclave`, `PostureAwareReport`.
- Private prep types (L75–119); `HushEngine` struct + `EngineState` (L121–160).
- **`impl HushEngine`** (L162–1513): constructors/builders incl. `with_policy`
  (**guard-pipeline assembly**, L177–216); public check entrypoints (L303–453);
  `prepare_origin_context` (L455–622); **`check_action_report_prepared`** (L623–755,
  **the decision flow + pipeline ordering invariant**); prechecks (L757–977); stage runner
  (L978–1041); posture-aware/runtime entrypoints (L1042–1257); posture state machine
  (L1258–1414); receipt glue (L1415–1497); stats (L1499–1512).
- `HushEngineBuilder` (L1515–1570); free helpers (L1572–1794): `tool_matches`,
  `origin_budget_limit`, `OutputSendPayload`, `build_custom_guards_from_policy`,
  `severity_to_core`, `check_bridge_policy` (cross-origin), **`aggregate_overall`**
  (delegates to formally-verified `crate::core::aggregate::aggregate_index`).

## Test situation

`#[cfg(test)] mod tests` @ L1796–4614 (2,819 LOC, 70 fns + 14 helpers). Calls private
methods/helpers (`check_action_report_with_runtime`, `tool_matches`, `aggregate_overall`,
`check_bridge_policy`) → **sibling child module**. Already banner-delimited into 4 sections
that map to 4 test files: core (L1796–2711, ~916), origin enclave (L2712–3550, ~839),
posture integration (L3551–3841, ~291), cross-origin isolation (L3842–4614, ~773).

## Proposed module tree

`HushEngine` + `EngineState` defined in `mod.rs`; submodules add `impl HushEngine` blocks.
**No item's visibility changes — pure relocation.**

```
engine/
├── mod.rs        ~120  imports, HushEngine + EngineState defs, module decls,
│                       explicit re-export block, #[cfg(test)] mod tests;
├── types.rs      ~90   GuardReport, GuardEvaluationMetadata, GuardResolvedEnclave,
│                       PostureAwareReport, PreparedContext, PreparedEvaluation,
│                       PosturePrecheck(+impl), EngineStats
├── construct.rs  ~210  impl: new/builder/with_policy/from_ruleset/with_*_guard/...;
│                       HushEngineBuilder; Default; build_custom_guards_from_policy
├── check_api.rs  ~165  impl: public check_* entrypoints + report metadata helpers
├── evaluate.rs   ~330  impl: prepare_origin_context, check_action_report_prepared (THE
│                       pipeline), evaluate_guard_stage, observe_guard_result ← touch LAST
├── prechecks.rs  ~225  impl: enclave/origin/budget prechecks + free origin helpers + OutputSend*
├── posture.rs    ~360  impl: posture-aware + runtime entrypoints + state machine
├── bridge.rs     ~110  BridgeCheckResult + check_bridge_policy + format_origin_brief + tool_matches
├── receipts.rs   ~130  impl: create_receipt(_for_report) + signed variants + stats + reset
│                       + merge_report_metadata_into_receipt
├── aggregate.rs  ~30   severity_to_core + aggregate_overall (thin wrapper — keep tiny/isolated)
└── tests/        mod.rs + part_1_core + part_2_origin + part_3_posture + part_4_cross_origin
```

**Re-export block:** `pub use types::{GuardReport, GuardEvaluationMetadata,
GuardResolvedEnclave, PostureAwareReport, EngineStats}; pub use construct::HushEngineBuilder;`
— keeps `lib.rs`'s `pub use engine::{GuardReport, HushEngine, PostureAwareReport}` and the
3 external importers (`benches/engine.rs`, `sandbox/supervisor.rs`,
`hunt-scan/src/policy_eval.rs`) resolving. `HushEngine`/`EngineState` live in `mod.rs` so
every submodule's `impl HushEngine` + the test module's `use super::*` resolve.

## Risks & coupling

- **HIGHEST: pipeline ordering invariant.** The "BuiltIn → Custom → Extra → Async" order
  is the assembly in `check_action_report_prepared` (L661–671: builtins partitioned by
  `builtin_stage_for_guard_name`, then `std_guards.extend(custom)` then `.extend(extra)`)
  + the instantiation order in `with_policy` (L177–216). Move together; diff line-for-line.
- **Shared `Arc<RwLock<EngineState>>`** mutated across many methods — safe because
  `EngineState` stays crate-private in `mod.rs`; do not change field visibility.
- **Fail-closed sticky errors** (`config_error`/`async_guard_init_error`) set in
  `construct.rs`, checked in `evaluate.rs` — keep semantics identical (a dropped
  early-return changes deny behavior).
- **`aggregate_overall` is verdict semantics** — keep it a thin passthrough to the
  formally-verified `core::aggregate::aggregate_index`; do NOT inline-simplify.
- `prepare_origin_context` + `check_action_report_with_runtime` are deeply entangled with
  enclave/origin/posture/bridge — all helpers stay crate-visible via `mod.rs`.
- Step 5 owns the shared `policy` types; this step only imports them — no conflict as long
  as `policy/mod.rs` re-export paths stay stable.

## Sequencing (compile + `cargo test -p clawdstrike` after each)

1. Extract tests first (removes 2,819 lines of noise): `git mv` → `engine/mod.rs`, split
   the test body into `tests/part_{1..4}.rs` on the existing banners, `tests/mod.rs` with
   shared imports + `TestExtraGuard` + the 4 `#[allow]` lints. Must pass byte-identically
   before touching code.
2. Carve least-coupled leaves: `aggregate.rs`, `bridge.rs`, `types.rs`.
3. `receipts.rs`, `construct.rs` (diff `with_policy` instantiation order).
4. `prechecks.rs`, `check_api.rs` (verify 3 external importers + crate-root re-exports
   build via `cargo build --workspace`).
5. `posture.rs`, then **`evaluate.rs` LAST** (decision core). Then run full
   `cargo test -p clawdstrike` + **`cargo test -p formal-diff-tests`** to confirm decision
   semantics unchanged, then `cargo clippy --workspace -- -D warnings`.
6. Confirm `mod.rs` re-export list compiles with no `unused_imports` (targeted
   `#[allow(unused_imports)]` on any helper used only by tests after the split).
