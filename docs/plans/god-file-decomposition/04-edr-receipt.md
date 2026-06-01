# Step 4 — `clawdstrike-policy-event/src/edr/receipt/mod.rs`

`crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs` — 6,668 lines
(**6,668 production / 0 test**). Effort: **L (6–9h)**. Pairs with
[Step 3](./03-edr-mod.md) — do Step 3 first.

## What it does / why it's big

Defines `EndpointDecisionReceipt` (the signed EDR attestation) + `EndpointDecisionRecord`.
Huge because it carries (a) a single ~2,100-line `impl EndpointDecisionReceipt` with **22
per-family `for_*` constructors** + a ~440-line `validate()` dispatcher + serialization
methods, and (b) ~190 free helper functions — `require_*` evidence validators and
`*_id_from_*` deterministic stable-ID derivations, one cluster per receipt family. The
directory is already partly decomposed: `families.rs`, `evidence.rs`, `inputs/` are
siblings; `mod.rs` is the leftover god file.

## Anomaly resolved — ZERO tests

`grep -c '#[test]'` = 0. The lone `#[cfg(test)]` @ L2482 gates a single
`pub(crate) fn response_action_id_from_signed_response_fields` — a 3-arg test-only shim
delegating to the always-compiled `..._with_mode`. Its only caller is `edr/mod.rs:9189`
(inside that file's test block). The naive heuristic swept L2482–6668 (shim + ~4,180
lines of **production** free fns) and mislabeled it "tests." **True split: ~6,668
production LOC, 0 test LOC.** No `tests/` subtree needed; the shim moves into the new
`families/response.rs`, keeping its `#[cfg(test)] pub(crate)` attrs verbatim.

## Current structure (line ranges)

- Header + glob re-exports (L1–48): `pub mod evidence/families/inputs;` + `pub use *::*`;
  two `use super::{…}` blocks pulling ~30 sibling-`edr` types + ~10 free fns from
  `edr/mod.rs` (`stable_id`, `endpoint_*_content_hash`, `endpoint_policy_delta_id`, …).
- `EndpointDecisionRecord` (L49–79) + `EndpointDecisionReceipt` struct (L81–95).
- **`impl EndpointDecisionReceipt`** (L97–2204, ~2,108): 22 `pub fn for_*` constructors
  (L99–~1585); `validate()` (L~1683–2029, ~440, the family-dispatch chain);
  `to_receipt`/`sign_with`/`receipt_id`/`to_verdict` (L~2030–2092).
- **~190 free functions** (L2206–6668, ~4,460): generic validators + hex/path tail
  (L2206–2480, L6451–6668, ~470 shared); response family (L2483–2535, 2891–3160,
  3689–4324, 6235–6450, ~1,300 — largest); deception (L3161–3688, 5514–5811, ~840);
  policy-decision/simulation (~300); policy-delta (~240); policy-event replay/impact
  (~240); privacy/provider-degradation (~430); observation/detection/graph-slice/
  sensor-state/evidence-bundle (L4325–4934, ~610).

## Proposed module tree

`impl EndpointDecisionReceipt` may be split across files via multiple inherent `impl`
blocks. Keep `evidence.rs`/`families.rs`/`inputs/` as-is.

```
edr/receipt/
├── mod.rs                  ~140  struct defs + Default; mod decls + the public re-export list
├── construct.rs            ~1,800 the 22 for_* constructors (one impl block)
│                                 — OR fold each for_* into its families/<family>.rs to stay <600
├── serialize.rs            ~70   impl block: to_receipt/sign_with/receipt_id/to_verdict
├── validate.rs             ~450  impl block: validate() — the family-dispatch chain
├── common.rs               ~480  generic require_* (field_eq/nonempty/nonzero/confidence/
│                                 receipt_evidence/hashed-evidence/value_hash) + hex/path helpers
└── families/               one file per family: its for_* body, require_* validators, *_id_from_*
    ├── mod.rs              ~30   mod decls + `pub(crate) use` of externally-used helpers
    ├── response.rs         ~1,300 (consider sub-split request/execution/rollback/ack)
    │                              — includes the #[cfg(test)] pub(crate) shim (old L2482)
    ├── deception.rs        ~840  (optionally materialization/cleanup/rotation files)
    ├── observation.rs      ~250
    ├── detection.rs        ~180
    ├── graph_slice.rs      ~120
    ├── sensor_state.rs     ~150
    ├── evidence_bundle.rs  ~60
    ├── policy_decision.rs  ~300
    ├── policy_delta.rs     ~240
    ├── policy_event.rs     ~240  (replay + impact)
    ├── simulation.rs       ~140
    ├── privacy_report.rs   ~220
    └── provider_degradation.rs ~250
```

**Re-export list:** `pub struct EndpointDecisionReceipt/Record` defined in `mod.rs`;
`pub use evidence::*; pub use families::*; pub use inputs::*;` (unchanged). Methods on the
type are public regardless of which file holds the `impl` — no re-export needed.
**`pub(crate)` free fns with within-crate callers MUST be re-exported from `mod.rs`** (so
`edr/mod.rs`'s `pub use receipt::*` + `edr/response.rs` keep resolving):
`response_acknowledgement_id_from_report_fields`, `..._with_control`,
`..._id_from_signed_evidence`, `response_execution_effect_binding_digest_from_effects`,
`response_rollback_id_from_effects`, `response_rollback_id_from_signed_evidence`,
`response_effect_evidence_value`, and the `#[cfg(test)]` shim — via
`pub(crate) use families::response::{…};`.

## Risks & coupling

- **`pub(crate)` helpers leak to `edr/mod.rs` + `edr/response.rs`** (8 of them) — the
  `pub use receipt::*` glob means any visibility regression silently breaks those two
  files. Keep `pub(crate)` + explicit re-export; don't demote.
- **`validate()` ↔ ~50 `require_*` fan-out** — each dispatched validator's visibility
  bumps private→`pub(crate)`. Wide but mechanical diff.
- **Shared `common.rs`** called from nearly every family; keep flat + broadly
  `pub(crate)`; family files gain `use super::common::*`.
- **`use super::{…}` depth** — from `families/`, parent `edr` is `super::super::`. Most
  error-prone manual step.
- Multiple inherent `impl EndpointDecisionReceipt` blocks across files is legal; document
  it. serde structs move byte-identical (no attr/field-order changes).
- **Coordinate with Step 3:** the `#[cfg(test)]` shim's caller is `edr/mod.rs:9189`; the
  8 `pub(crate)` response helpers form a bidirectional dep with `edr/response.rs`. Land
  the `pub(crate) use util::stable_id` (Step 3) before/with this.

## Sequencing (compile + `cargo test -p clawdstrike-policy-event` after each)

1. Extract `common.rs` (generic validators + hex/path). Build.
2. Extract `serialize.rs` (second `impl` block). Build.
3. Create `families/`; move one family at a time, smallest first (`evidence_bundle`,
   `graph_slice`), bumping dispatched validators to `pub(crate)` + adding re-exports.
   Build + test after **each** family. Do `response.rs` + `deception.rs` last
   (helper-leaking) and coordinate the re-exports with Step 3 then.
4. Extract `validate.rs` once families exist.
5. Extract `construct.rs` (22 `for_*`), optionally folding into `families/<family>.rs`.
6. Final `mod.rs` = type defs + mod decls + re-export list. `cargo clippy --workspace
   -- -D warnings`, `cargo test -p clawdstrike-policy-event`, build `control-api`
   (external consumer of `EndpointDecisionReceipt`).
