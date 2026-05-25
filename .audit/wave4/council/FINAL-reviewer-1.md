# Final Council — Reviewer 1 (Waves A + B end-to-end)

**HEAD:** 0730ccd2e5776a900bd5cf106aa534a7b50a7202
**Verdict:** CONCUR — every Wave A + Wave B acceptance criterion verified end-to-end against HEAD. Pre-existing `too_many_arguments` clippy warnings in `policy-event/receipt/mod.rs` and `control-api/routes/policies.rs::observe` are explicitly carve-outs per the brief; no new errors/warnings introduced by Wave B itself.

## Wave A verification
1. **.env**: PASS — `ls .env` returns `No such file or directory`. Removal recorded in commit `555f2f33b` body (working-tree deletion only; revoke at provider noted separately).
2. **Cruft dirs**: PASS — `tmp/`, `output/`, `coverage/`, `.tmp-release-venv/`, `.playwright-cli/`, `.cleanup-audit/`, `apps/cloud-dashboard/` all absent from disk.
3. **.DS_Store**: PASS — the only matches are inside `.worktrees/` and `.claude/worktrees/`, which the audit explicitly excludes.
4. **Committed Vite bundles**: PASS — `git ls-files apps/agent/src-tauri/resources/control-console/assets/*.js` returns empty. Deletion recorded in `555f2f33b` (-152 lines across 22 files; bundles regenerated at build).
5. **test-mdx**: PASS — `git ls-files apps/academy/src/app/test-mdx/` returns empty.
6. **Shell injection**: PASS — `scripts/codex-swarm/common.sh:451-463` now contains a `case "$bootstrap_preset"` with named arms (`cargo-fetch-locked`, `cargo-fetch-agent-locked`) and a default branch that prints `"unknown preset"` and `return 1`. No `bash -lc "$bootstrap_preset"` anywhere. Quote: `printf 'bootstrap %s: unknown preset %q (allowed: cargo-fetch-locked, cargo-fetch-agent-locked, none)\n' "$lane" "$bootstrap_preset" >&2; return 1`.
7. **.gitignore**: PASS — `tmp/`, `output/`, `coverage/`, `.playwright-cli/`, `.tmp-release-venv/`, `.worktrees/` all explicitly listed (plus `.env`, `.DS_Store`, the `infra/vendor/*` allow-list pattern).

## Wave B verification
1. **hushd auth**: PASS — `crates/services/hushd/src/config.rs:109-120` shows `default_auth_enabled() -> bool { true }` and `AuthConfig::default()` uses it. Test `auth::middleware::tests::default_auth_config_rejects_request_with_no_bearer_token` passes (`cargo test -p hushd --lib`: `1 passed; 0 failed; 257 filtered out`).
2. **control-api defaults + clippy**: PASS — `crates/services/control-api/src/config.rs:48-91` uses `SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)` and `Vec::new()` for CORS; **no `.expect()` in the Default impl** (entire body is plain struct construction). `cargo clippy -p clawdstrike-control-api` emits one `too_many_arguments` warning on `routes/policies.rs:2380` (`fn observe`) — same file/line existed at base `2eff91532` (`git show 2eff91532:.../policies.rs | grep "fn observe"` → line 2380), so it is pre-existing, not a Wave B regression.
3. **registry config**: PASS — `clawdstrike-registry/src/config.rs:27-31` defaults `host: "127.0.0.1"`, `api_key: String::new()`, `allow_insecure_no_auth: false`. `validate()` at `:40-49` rejects empty `api_key` unless `allow_insecure_no_auth` is set. `cargo test -p clawdstrike-registry`: **182 passed; 0 failed**.
4. **brokerd admin auth**: PASS — `clawdstrike-brokerd/src/api.rs:193-223` `require_admin_auth` returns `Err(ApiError::unauthorized("BROKER_AUTH_REQUIRED", ...))` when `admin_token` is None, unless `allow_insecure_no_admin_token` is true (and then logs a warn). Used by mutating routes at lines 261, 632, 725, 855. `cargo test -p clawdstrike-brokerd`: **117 + 19 + 0 + 0 passed; 0 failed** across lib/integration suites.
5. **workbench stronghold**: PASS — `apps/workbench/src-tauri/src/commands/stronghold.rs:102-108` `generate_and_write_machine_secret` uses `getrandom::getrandom(out).map_err(|e| ... refusing to open vault with a weak key)` — error propagates upward, no hostname-only fallback. The hostname is still mixed in at line 91 (binding only, not fallback), per the doc comment at lines 55-64. Comment at :98-101 explicitly notes the prior bug: "a getrandom failure used to be swallowed with `unwrap_or_else`, leaving `out` zeroed and effectively deriving the vault key from hostname alone."

## Cross-cutting
**cargo check workspace:** clean — `cargo check --workspace` finishes with `Finished dev profile`, no errors or warnings.
**cargo clippy -D warnings:** two errors, both pre-existing-style and explicitly permitted by the brief:
  - `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs:4606` — `observation_receipt_id_from_fields` (10/7 args) — receipt/mod.rs is the wave-1 known-pre-existing carve-out.
  - `crates/services/control-api/src/routes/policies.rs:2380` — `fn observe` (9/7 args) — verified to exist at the same line in base commit `2eff91532` (pre-cleanup). Not touched by Wave B's `config.rs` work.
  Neither error is in code Wave B modified.
**commit count:** 38 commits (`git log 2eff91532..HEAD --oneline | wc -l` → 38). Matches the brief expectation.

## Process
**Atomicity spot-check:** PASS — 5/5 random commits hold up:
  - `cae9aca70` (shell-injection): touches only `scripts/codex-swarm/common.sh` + a related test/doc — single concern.
  - `b6a7d3be6` (hushd auth default): 4 files in `crates/services/hushd/` (config + middleware + presence + test common).
  - `9f668a7c6` (stronghold getrandom): focused on `apps/workbench/src-tauri/src/commands/stronghold.rs` security path.
  - `555f2f33b` (cruft removal): 22 files / -152 lines — Vite bundles + .DS_Store, coherent single-concern.
  - `e893defcd` (registry empty-key): single file `clawdstrike-registry/src/config.rs`, +57/-2.
  Subjects accurately match `git show --stat` for each — no drift between subject and content.

**8280bdda5 process issue:** verified workspace state OK Y — the commit subject ("delete orphan flight-recorder snapshot/read API") describes ~112 LOC of intended dead-code removal, but `git show --stat` ends with `45891 files changed, 16989252 deletions(-)` because the parallel agent index race squashed Wave E3's `infra/vendor/*` deletion into the same commit. **The workspace state is correct**: `ls infra/vendor/` returns only `async-nats`, `nono`, `rustls-webpki` (matching the `.gitignore` allow-list); `git ls-files infra/vendor | wc -l` → 138 tracked files (just the three preserved sub-trees). The history is messy but the tree is right.

## Critical gaps (if any)
- None blocking. The 8280bdda5 commit-message vs. diff-stat mismatch is documented in the brief and the resulting tree is correct. Pre-existing clippy `too_many_arguments` warnings are pre-cleanup and outside Wave B's scope. Default control-api config carries no `.expect()`.

## Final verdict
**CONCUR.** Wave A (cruft + secrets + shell-injection + .gitignore) and Wave B (4 insecure defaults flipped + stronghold fail-loud) are both done end-to-end at HEAD `0730ccd2e`. Tests pass. No new clippy errors introduced. Commit history is atomic (with one documented exception that doesn't affect workspace state). Workspace tree matches what the spec describes. Nothing blocks shipping these two waves.
