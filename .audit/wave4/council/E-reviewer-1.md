# Wave E Council — Reviewer 1 (Rust refactors: E1 + E2)

**HEAD:** `0730ccd2e` (cleanup/waves-abce)
**Baseline:** `7f97033ca` (pre-Wave E)
**Verdict:** **CONCUR**

## Check 1: Workspace compile + lint

**cargo check --workspace --all-targets:** PASS (exit 0)
```
    Checking hush-cli v0.2.7 ...
    Checking hush-native v0.2.7 ...
    Checking hush-ffi v0.2.7 ...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 32.33s
```
Zero errors. Zero unexpected warnings on the main workspace check (warnings appeared only on the dedicated clippy run).

**cargo clippy --workspace:** PASS (exit 0); 2 warnings total, both pre-existing:
- `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs:4606` — `too_many_arguments (10/7)` on `observation_receipt_id_from_fields` (spec said acceptable)
- `crates/services/control-api/src/routes/policies.rs:2380` — `too_many_arguments (9/7)` on `observe` (pre-existing; not touched by Wave E — last touched by `ce7a85ba5` long before baseline)

Neither warning is new from Wave E.

**clawdstrike-policy-event clippy warnings now vs. 42 before:** **1** (down from 42). The lone remaining warning is the pre-existing `too_many_arguments` in `receipt/mod.rs:4606` — exactly the one the spec authorized as acceptable.

## Check 2: E1 api_server.rs split

**Commits present:** Y (all 6)
- `c4eedeec4` refactor(agent): extract daemon proxy handlers into api_server submodule — Y
- `ca83a427f` refactor(agent): extract UI bootstrap flow into api_server::ui_bootstrap — Y
- `f783d1b08` refactor(agent): extract auth, token rotation, cookie helpers — Y
- `8c3a4b813` refactor(agent): extract default_edr_*_path/ledger factories — Y
- `976db189d` refactor(agent): extract route_rate_limit and rate limiters — Y
- `0730ccd2e` refactor(agent): extract module-level constants — Y (also HEAD)

**Submodule files exist:** Y (all 6)
- `apps/agent/src-tauri/src/api_server/auth.rs` (373 LOC)
- `apps/agent/src-tauri/src/api_server/constants.rs` (70 LOC)
- `apps/agent/src-tauri/src/api_server/daemon_proxy.rs` (183 LOC)
- `apps/agent/src-tauri/src/api_server/edr_paths.rs` (298 LOC)
- `apps/agent/src-tauri/src/api_server/rate_limit.rs` (185 LOC)
- `apps/agent/src-tauri/src/api_server/ui_bootstrap.rs` (546 LOC)
- Total extracted: ~1,655 LOC

**api_server.rs LOC:** **46,644** (was 48,111 in working-tree-restored pre-Wave-E state per audit DELTA-SUMMARY; the spec's exact-match expectation hits). Net change: -1,467 LOC (refactor cost: the extracted code is mostly verbatim + new module declarations, so the small delta is consistent with declared moves rather than rewrites).

**cargo check -p apps-agent:** PASS via workspace + via manifest-path (the `-p apps-agent` package name doesn't exist; the actual package name is `clawdstrike-agent` and it's in a separate workspace at `apps/agent/src-tauri/`). Building via `--manifest-path apps/agent/src-tauri/Cargo.toml` succeeds.

**cargo test -p apps-agent (via --manifest-path):** **PASS** — `459 passed; 2 failed; 1 ignored`. The 2 failures are exactly the pre-existing flakes the spec named acceptable:
- `api_server::tests::agent_edr_sensor_routes_match_registered_honey_artifacts_without_resubmission`
- `api_server::tests::provider_policy_decision_receipts_auto_upload_to_control_api`

Pass count matches the spec's baseline of "~459 pass, 2 pre-existing flakes" exactly.

## Check 3: E2 edr/receipt splits

**Commits present:** Y (all 5)
- `b0ffb906c` chore(policy-event): remove dead code and stale imports from edr module
- `8280bdda5` chore(policy-event): delete orphan flight-recorder snapshot/read API
- `a7a2beab0` chore(policy-event): delete dry-run-only terminate_process_tree paths
- `761e18904` refactor(policy-event): relocate edr/mod.rs test mega-block to sibling tests.rs
- `3fc76b1b1` refactor(policy-event): demote in-edr-only helpers to pub(crate)

**allow(dead_code, unused_imports) removed from edr/mod.rs:** Y (verified at line 1-30; the file now starts cleanly with `//!` doc comment and `pub mod` declarations — no `#![allow(...)]` attribute present)

**edr/mod.rs LOC:** **2,367** (spec expected ~2,367 vs. 9,842 baseline) — matches exactly

**edr/tests.rs LOC:** **7,351** (spec expected ~7,000) — matches (the mega-block relocation is the big delta)

**5 dead items absent:** Mixed (spec's grep test was slightly misleading; the actual cleanup matches the commit message of `b0ffb906c`):

Commit `b0ffb906c` removed the DUPLICATES of these helpers in `receipt/mod.rs` and the unused `pub` exports. The canonical definitions remain in `edr/mod.rs` because production code DOES call them (e.g., `response.rs` uses `response_execution_id_from_effects` 5 times, `causal/recorder.rs` uses `reconstruct_path`, `privacy.rs` uses `telemetry_privacy_report_id_from_values`). The commit message explicitly says "the last three were duplicates in receipt/mod.rs" — and `git diff 7f97033ca..b0ffb906c -- receipt/mod.rs` confirms the duplicate `fn` definitions were deleted from receipt/mod.rs.

So the spec's literal interpretation ("should return nothing or only references in tests") is wrong — the deliverable was duplicate removal, not deletion. The actual code state matches commit messages and removes the 42-warning-storm. Verdict: behavior correct, spec wording slightly inaccurate.

**cargo test -p clawdstrike-policy-event:** 144 pass, 1 fail (`endpoint_response_rollback_receipt_binds_restore_effect`). **Verified pre-existing**: running the same test against baseline `7f97033ca` (fresh clone in `/tmp/clawdstrike-baseline`) produces the identical failure (`assertion failed: empty_rollback_effect.validate().unwrap_err().to_string().contains("rollback effect evidence")`). Not a Wave E regression.

## Check 4: Cargo.lock

**Changed paths:** 0 lines changed in root `Cargo.lock`, 0 lines in `apps/agent/src-tauri/Cargo.lock`.

**Scope reasonable:** Y. Spec expected possible changes due to E3 hushspec move; actual change is zero, which is even better (the hushspec promotion was apparently neutral to the lockfile, or already reflected at baseline).

## Check 5: 8280bdda5 process issue

**Commit subject mismatch:** Y. Subject says "delete orphan flight-recorder snapshot/read API" (which the spec describes as ~112 lines), but `git show --stat` reveals 45,891 files / 16,989,252 deletions — the bulk of which is the `infra/vendor/` deletion that belongs to E3.

**Workspace builds despite mismatch:** Y. `cargo check --workspace --all-targets` exits 0; tests run; clippy is clean.

**Functional impact:** **None**. The vendor deletion (E3's actual deliverable) and the flight-recorder snapshot deletion both happened — they just landed in one commit with a misleading subject due to an index race during parallel agent execution. The final tree state is correct; only the git archaeology is muddled.

## DISSENT log

- (Process, not code) Commit `8280bdda5` has a misleading subject line — squashed flight-recorder removal with E3's vendor deletion in a single commit. Recommend a `git notes` annotation or a follow-up commit clarifying the audit trail. Does NOT affect functional correctness.
- (Spec, not code) The spec's Check 3 expected `grep -rn 'fn canonical_graph_content_hash...'` to return nothing — but the actual deliverable in commit `b0ffb906c` was duplicate removal from `receipt/mod.rs` while keeping the canonical definitions in `edr/mod.rs` (because production code uses them). The deliverable matches the commit message; the spec wording was slightly off. The 42→1 warning reduction confirms the underlying cleanup happened.
- (Minor) Spec used `-p apps-agent` for cargo commands; the actual package name is `clawdstrike-agent` in a separate workspace at `apps/agent/src-tauri/`. Workaround: `cargo test --manifest-path apps/agent/src-tauri/Cargo.toml`. This is documentation, not a code issue.

## Final verdict

**CONCUR**

E1 (api_server.rs split): 6/6 commits present, 6/6 submodule files exist, LOC reduction matches spec (-1,467), agent compiles and tests match baseline (459 pass, 2 pre-existing flakes).

E2 (edr/receipt splits): 5/5 commits present, dead-code allow attribute removed, edr/mod.rs and tests.rs LOC match spec, policy-event clippy warnings 42→1 (the remaining one is the pre-existing acceptable `too_many_arguments`), all production callers of "the 5 dead items" continue to compile because the actual deliverable was duplicate removal + visibility demotion.

Workspace builds cleanly. Cargo.lock unchanged. Only known test failure (`endpoint_response_rollback_receipt_binds_restore_effect`) is verified pre-existing on baseline `7f97033ca`. The 8280bdda5 contamination is purely a git-history aesthetic issue with no functional impact.

The Rust refactor side of Wave E meets every load-bearing acceptance criterion in the spec.
