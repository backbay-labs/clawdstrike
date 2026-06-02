# God-File Decomposition Initiative — Documentation Index

Last updated: 2026-06-01.

## Vision

Break up the eight largest source "god files" into well-organized module trees,
following the precedent set by the `api_server.rs` → `api_server/` refactor
(PRs #355–#358). These are **behavior-preserving** refactors: pure relocation of
code into submodules, public API preserved byte-for-byte, with a green build +
passing tests at every commit.

The original worst offender — `apps/agent/src-tauri/src/api_server.rs` — is already
resolved: it is now a directory of ~37 implementation files (largest ~595 lines)
with inline tests extracted into an `api_server/tests/` subtree. This initiative
applies the same treatment to the next eight.

## Why

As of 2026-06-01, tracked source over thresholds (excluding vendor + test dirs):
**16 files ≥ 3,000 lines, 41 ≥ 2,000, 140 ≥ 1,000.** The eight files below are the
top of that distribution. Two were initially mis-measured by a naive "lines after
first `#[cfg(test)]`" heuristic; the **true** code/test split (verified per-file) is
in the table.

| # | File | Lines | code / test | → becomes | Effort | Top risk |
|---|------|------:|------------:|-----------|--------|----------|
| 1 | [`clawdstrike-logos/src/verifier.rs`](./01-verifier.md) | 3,875 | 2,640 / 1,234 | 5 impl + 5 test | M · 5–7h | z3 feature gating; lone `cfg(test)` helper @ L711 |
| 2 | [`hush-cli/src/pkg_cli.rs`](./02-pkg-cli.md) | 5,199 | 4,227 / 972 | ~18 impl + 4 test | M · 6–9h | `cmd_pkg_test` cfg-feature pair must move verbatim |
| 3 | [`clawdstrike-policy-event/src/edr/mod.rs`](./03-edr-mod.md) | 10,164 | 2,437 / 7,727 | 6 impl + 6 test | M · 6–9h | shared `stable_id` re-export; `finding` name clash |
| 4 | [`clawdstrike-policy-event/src/edr/receipt/mod.rs`](./04-edr-receipt.md) | 6,668 | **6,668 / 0** | ~16 (`families/`) | L · 6–9h | wide `pub(crate)` bumps; `validate`↔`require_*` fan-out |
| 5 | [`clawdstrike/src/policy.rs`](./05-policy.md) | 4,156 | 2,381 / 1,775 | ~14 impl + 5 test | M · 6–9h | serde `deny_unknown_fields`; `include_str!` path depth |
| 6 | [`clawdstrike/src/engine.rs`](./06-engine.md) | 4,614 | 1,796 / 2,818 | 10 impl + 4 test | M · 4–6h | **guard-pipeline ordering invariant**; verdict semantics |
| 7 | [`control-api/src/routes/response_actions.rs`](./07-response-actions.md) | 3,909 | 2,952 / 957 | ~14 (`ack/`) + 4 test | M · 3–4.5h | shared symbols w/ `policies.rs` |
| 8 | [`control-api/src/routes/policies.rs`](./08-policies.md) | 3,596 | 3,334 / 262 | ~9, tests co-located | M · 4–6h | shared symbols w/ `response_actions.rs` |

**Net:** ~42K lines across 8 god files → ~95 files, none over ~600 lines.

### Measurement corrections

- **`edr/receipt/mod.rs` has ZERO tests.** Its single `#[cfg(test)]` gates a
  one-function test-only shim. The file is 6,668 lines of *production* code. This is
  a pure implementation split, not a test extraction.
- **`verifier.rs` is impl-heavy, not test-heavy.** True split ~2,640 impl / ~1,234
  test (not 711 / 3,164). The "711" was the line of a stray `#[cfg(test)]` helper. It
  needs a real implementation split, with test extraction as a secondary win.

## Cross-cutting principles

1. **Explicit re-exports, not globs.** The `api_server` precedent used
   `pub use child::*`, but PRs #357 ("narrow re-export surface") and #358 ("replace
   glob re-exports") deliberately moved *away* from that. Every new `mod.rs` uses
   **explicit** `pub use child::{Specific, Items}` matching today's exact visibility.
   Do not reintroduce globs.

2. **Tests stay as sibling child modules.** The inline `#[cfg(test)] mod tests { use
   super::* }` blocks call private items, so they cannot become crate-root `tests/`
   integration tests (which see only the public API). Extract them into a `tests/`
   subdir declared `#[cfg(test)] mod tests;` from the new `mod.rs` — same privacy
   access, out of the implementation file. (Exception: `policies.rs`, where touched
   items span child modules, so tests co-locate inside each owning module.)

3. **Mechanical, verifiable steps.** Each refactor starts with
   `git mv bigfile.rs bigdir/mod.rs` (proves the directory-module switch is inert),
   then carves the least-coupled leaves first, compiling + running the crate's tests
   between every cut. No logic edits.

4. **Preserve the public surface.** Identify every `pub`/`pub(crate)` item and grep
   the workspace for external importers; the new `mod.rs` re-exports exactly those.
   `#[cfg(...)]` attributes and serde derives move verbatim with their items.

## Coordination pairs

Three pairs share a crate; sequence them, do not parallelize blindly:

- **#7 `response_actions.rs` → #8 `policies.rs`** (control-api). `policies.rs` imports
  `create_and_publish_internal_action`, `CreateResponseActionRequest`,
  `ResponseTargetInput` from `response_actions`. One-directional. Land #7 first
  (keep those 3 re-exported at the module root), then rebase #8.
- **#3 `edr/mod.rs` → #4 `edr/receipt/mod.rs`** (clawdstrike-policy-event). Share
  `stable_id` + telemetry-id helpers; `receipt/evidence.rs` reaches `super::super::
  stable_id`. Do #3 first (carve `util.rs`, add `pub(crate) use util::stable_id`).
- **#5 `policy.rs` / #6 `engine.rs`** (clawdstrike). Loosely coupled — `policy.rs`
  *owns* the shared types, `engine.rs` only imports them. Do #5 first; as long as
  `policy/mod.rs` keeps its re-export paths stable, #6 is unaffected.

## Execution order & status

Order chosen by independence → risk: prove the pattern on independent crates, then
the coupled pairs, with the formally-verified engine last.

| Step | File | Status | Commit |
|------|------|--------|--------|
| 1 | `verifier.rs` | ☑ done (verified) | `b4002a48f..f10adf75c` |
| 2 | `pkg_cli.rs` | ☑ done (verified) | `c9bcf1ff3..7d144cd50` |
| 3 | `edr/mod.rs` | ☑ done (verified) | `15c63e245..1b777a474` |
| 4 | `edr/receipt/mod.rs` | ☑ done (verified) | `edfc3d464..fe1b9d692` |
| 5 | `policy.rs` | ☑ done (verified) | `b31020693..6a51b4dc0` |
| 6 | `engine.rs` | ☑ done (verified) | `5adfd170d..d5587014d` |
| 7 | `response_actions.rs` | ☐ pending | — |
| 8 | `policies.rs` | ☐ pending | — |

**Steps 1–6 are complete and verified; step 7 has landed its tests extraction
(the response_actions impl split is in progress); step 8 is not started.** The steps
land **incrementally**: each step is an independent, behavior-preserving relocation
gated and committed on its own, so a PR may carry a contiguous prefix of the table
rather than all eight at once. Step 6 (`engine.rs`) additionally passes the
`formal-diff-tests` gate after every cut. Remaining follow-on: finish the
`response_actions/` impl modules (dto/handlers/access/create/ack/publish/delivery/
execute/fetch per the tree below) and then step 8 (`policies.rs`).

Per-file gate (must hold before marking a step done and committing):
`cargo fmt --all -- --check` + `cargo build -p <crate>` + `cargo test -p <crate>` +
`cargo clippy -p <crate> -- -D warnings`, plus `cargo build --workspace` for files with
external importers. For #6, additionally `cargo test -p formal-diff-tests`.

> **Gate notes (learned on step 1):**
> - **`cargo fmt --all -- --check` is part of the gate** (CI runs it). Newly-split files
>   and de-indented `include!` test files must be fmt-clean. rustfmt does not follow
>   `include!`, so de-indent those theme files by hand.
> - **Default features only.** The `z3` feature (and thus `--all-features`) cannot compile
>   in this environment (no system `z3.h`). z3-gated code is moved by careful inspection
>   and its `#[cfg(feature = "z3")]` attributes preserved verbatim, not compile-verified.
> - **Enforce the ~600-line target.** Split dense clusters proactively rather than leaving
>   a file 50+ lines over (a non-sanctioned >600 file is a P2).

## Definition of done

**Per step (what makes a single step landable):**

- The step's file is decomposed; no resulting file > ~600 lines (a couple of dense
  validator clusters may land ~800 and are flagged for an optional further split).
- Workspace builds; all tests pass; clippy clean with `-D warnings` (per-file gate above).
- Review agents report **no P0/P1/P2** findings across that step's diff.
- Bot/review comments resolved to a thumbs-up / "no more issues".

**Initiative (the full eight-file goal — reached only once steps 5–8 also land):**

- All 8 files decomposed under the per-step bar above.
- A PR carrying the full set (or the final contiguous steps) is **not** titled or
  evaluated as "all 8 done" until the status table shows steps 1–8 complete. Until
  then, PRs land a contiguous prefix and are scoped to the steps they actually carry.
