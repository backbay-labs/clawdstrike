# Step 1 — `clawdstrike-logos/src/verifier.rs`

`crates/libs/clawdstrike-logos/src/verifier.rs` — 3,875 lines (~2,640 impl / ~1,234 test).
Effort: **M (5–7h)**. Independent — no coordination with other steps. Good lead-off to
prove the pattern (no external coupling; public surface is tiny and fully enumerable).

## What it does / why it's big

The policy **verifier**: turns compiled Logos formulas and full ClawdStrike policies
into verification reports (consistency, completeness, inheritance soundness), with an
optional Z3 backend and a load-time verification hook
(`install_clawdstrike_policy_load_verifier`) called by the CLI, daemon, workbench, and
Python native module. Big because it fuses three heavy concerns: the report/attestation
type model + `PolicyVerifier`, a large **semantic inheritance** engine that synthesizes
witness strings from glob/regex/domain patterns, and load-time orchestration + an LRU
cache.

**Correction:** NOT test-dominated. Real split ~2,640 impl / ~1,234 test. The "711"
figure was just the line of the *first* `#[cfg(test)]` marker; a second large impl
region (L718–2640) sits between that marker and the test module. So an implementation
split is the main event, with test extraction secondary.

## Current structure

- **Impl region A — type model + verifier core (L1–710):** `VerificationBackend`,
  `AttestationLevel` (+as_u8/name/from_u8/Display), `CheckOutcome`, report DTOs
  (`Conflict`, `ConsistencyResult`, `CompletenessResult`, `WeakenedProhibition`,
  `InheritanceResult`, `VerificationReport` +all_pass/to_receipt_metadata),
  `DEFAULT_EXPECTED_ACTION_TYPES`, `PolicyVerifier` + the big `impl` (L228–567), and
  free report helpers (`compute_attestation_level`, `build_policy_report`,
  `report_backend`, `expected_action_types_for_policy`).
- **Test-only helper (L711–717):** `#[cfg(test)] fn expected_action_types_for_policy_set`
  — a lone fn in the parent namespace (this is the second `#[cfg(test)]` marker grep
  found). Must NOT be dropped; keep it in the slimmed root file.
- **Impl region B — inheritance engine + witness generation + load-time/cache
  (L718–2640):** atom/formula classification (L718–943); inheritance dispatch + per-guard
  checks (L944–1453); pattern→witness sample generation (L1454–2213, the most
  self-contained cluster); load-time verification + `VerificationCache` LRU
  (L2215–2640).

## Test situation

- **Block 1 @ L711:** the lone test-only helper fn (~7 LOC). Keep in root file.
- **Block 2 @ L2642–3875 (`mod tests`, ~1,234 LOC):** 55 `#[test]` fns (2 are
  `#[cfg(feature = "z3")]`), 3 fixtures. Calls crate-private free fns directly
  (`shortest_common_supersequence`, `regex_hir_samples_from_pattern`,
  `default_mcp_probe`, …) → **must stay a sibling child `mod tests`**, not a crate-root
  integration test.

## Proposed module tree

Use the sibling-root-file form (`lib.rs` already says `pub mod verifier;`, which resolves
to `verifier.rs` OR `verifier/mod.rs` — keep `verifier.rs` as the root to match the
`api_server.rs` precedent literally; a `verifier/mod.rs` is equivalent if preferred).

```
src/verifier.rs                       (~120) root: doc, shared `use`, the L711 cfg(test) helper,
                                              `mod report/verifier_core/inheritance/witness/load_time;`
                                              + explicit re-export list, `#[cfg(test)] mod tests;`
src/verifier/report.rs                (~210) region-A types (L34–220) + DEFAULT_EXPECTED_ACTION_TYPES
                                              + compute_attestation_level, report_backend, build_policy_report
src/verifier/verifier_core.rs         (~360) PolicyVerifier struct/Default/impl (L228–567)
                                              + expected_action_types_for_policy, collect_atoms*,
                                                classify_formula, atom_action_type, z3 counterexample helpers
src/verifier/inheritance.rs           (~510) inspect_policy_inheritance_against_parent + all
                                              check_*_inheritance, disabled_*_config builders, probes (L944–1453)
src/verifier/witness.rs               (~760) regex HIR sampling, path/domain/token witness synthesis,
                                              shortest_common_supersequence (L1454–2213) — largest impl module
src/verifier/load_time.rs             (~430) enrich_receipt, LoadTimeVerificationResult, load-time fns,
                                              VerificationCache(+State), registered_policy_load_cache,
                                              install_clawdstrike_policy_load_verifier (L2215–2640)
src/verifier/tests/mod.rs             (~40)  #![allow(...)] + 3 fixtures + theme module decls
src/verifier/tests/core.rs            (~520, ~25 fns) consistency/completeness/conflict/attestation/metadata
src/verifier/tests/inheritance.rs     (~380, ~16 fns) semantic weakening detection
src/verifier/tests/witness_synthesis.rs (~120, ~10 fns) regex/path/domain internals
src/verifier/tests/load_time.rs       (~290, ~12 fns) load-time + caching
src/verifier/tests/z3.rs              (~50, 2 fns, #[cfg(feature = "z3")])
```

**Re-export list** (`verifier.rs` must keep these reachable — 7 are externally consumed,
17 total pub): `VerificationBackend, AttestationLevel, CheckOutcome, VerificationReport,
PolicyVerifier, enrich_receipt, install_clawdstrike_policy_load_verifier` + `Conflict,
ConsistencyResult, CompletenessResult, WeakenedProhibition, InheritanceResult,
DEFAULT_EXPECTED_ACTION_TYPES, LoadTimeVerificationResult, VerificationCache,
verify_policy_at_load_time, verify_policy_at_load_time_with_resolver`. `report` +
`verifier_core` + `load_time` public fns → `pub use`; `inheritance` + `witness` →
`pub(crate) use`. No crate-root re-exports of verifier symbols exist → `lib.rs` unchanged.

## Risks & coupling

- The lone `#[cfg(test)]` helper @ L711 must stay in root or it only fails under
  `cargo test`.
- z3 gating appears in impl (16 `#[cfg(feature = "z3")]` sites) and tests (2). Preserve
  every attribute; **compile with and without `--features z3`** (clippy `-D warnings`
  will reject a `use` that becomes unused under one config — mirror the precedent's
  `#[allow(unused_imports)]` trick on the root re-export if needed).
- Cross-module private fns resolve via the root's `pub(crate) use <mod>::*` + each
  submodule's `use super::*`. No `pub` widening required.

## Sequencing (compile after each)

1. Create `verifier/`; move `report.rs` first (fewest deps). Build.
2. Move `witness.rs` (most self-contained). Build.
3. Move `inheritance.rs` (depends on witness). Build.
4. Move `verifier_core.rs` (depends on report + inheritance). Build.
5. Move `load_time.rs` (depends on verifier_core + report). Root now ~120 LOC. Build.
6. Extract tests into `verifier/tests/` (5 theme files). Build with **and without**
   `--features z3`.
7. Gate: `cargo test -p clawdstrike-logos` (and `--features z3`), `cargo clippy
   -p clawdstrike-logos --all-features -- -D warnings`, `cargo build --workspace`.
