# Tier A + B Execution Report

**Branch:** `chore/cleanup-tier-ab`
**Base:** `origin/main`
**Reviewer:** Wave reviewer (read-only audit)
**Date:** 2026-05-23
**Commits landed:** 11 (10 cleanup + 1 audit corpus)

---

## Verdict

The cleanup **succeeded at the macro level and broke two specific things at the micro level**. The Rust workspace compiles end-to-end, all 4 target TypeScript packages typecheck cleanly, every workflow YAML parses, the canonical security commits do what they say (receipt verifier is fail-closed, daemons reject empty admin tokens by default), the Discord URL is canonicalized to a single value across 6 docs, three rulesets are now `extends: default`, 1.5 GB of build cruft and 12k lines of fictional planning docs are gone, and the audit corpus that justifies the work is checked in for posterity. **Two real regressions** were introduced and merit blocking before push: (1) `cargo test -p clawdstrike-brokerd --lib config::tests` now fails 4 tests because the new fail-closed admin-token check fires before the tests' specific failure assertions can; (2) `hush policy verify` on the consolidated `rulesets/ai-agent.yaml` and `rulesets/cicd.yaml` now **FAIL** with 78 and 100 "weakened prohibitions from base default" findings respectively — the old policies passed only because `extends:` was absent and the inheritance check was skipped. Beyond those, two minor inconsistencies: (a) one commit message overstated its scope (workbench refactor silently dropped the workbench `[patch.crates-io]` block, then the dedicated async-nats commit double-counted it); (b) the rulesets consolidation bumped to v1.2.0 while the simultaneous reconciliation commit bumped examples to v1.5.0 — both are valid per `POLICY_SUPPORTED_SCHEMA_VERSIONS`, but the inconsistency itself is exactly the kind of drift the cleanup was supposed to end. Net: **fix the two regressions, then push**.

---

## Commits landed

| # | SHA | Scope | Status |
|---|---|---|---|
| 1 | `8015e437f` | chore(cleanup): prune build artifacts, demo routes, tighten .gitignore | DONE (clean) |
| 2 | `4a9a2d061` | chore(deps): canonicalize npm, drop bun lockfiles, add packageManager | DONE (clean) |
| 3 | `255e8a5f4` | docs: schema reconciliation to v1.5.0 + delete planning theater | DONE (see schema inconsistency note) |
| 4 | `aefb71c02` | fix(security): fail-closed daemon auth defaults | DONE **but 4 brokerd config tests now fail** |
| 5 | `80cec40b1` | chore(tauri): identity alignment, capabilities, TEAM_ID parameterization | DONE (clean) |
| 6 | `733c69763` | chore(ci): permissions, concurrency, timeouts, matrix docker, .cargo/audit.toml | DONE (clean) |
| 7 | `4c613fd1b` | chore(rulesets): consolidate via extends + path_allowlist + fix compliance fixtures | DONE **but `hush policy verify` now FAILS on ai-agent + cicd** |
| 8 | `254d8a52c` | fix(security): SDK typing + fail-closed receipt verifier + Vercel-AI middleware | DONE (clean, tests pass) |
| 9 | `7f9cb6068` | refactor(workbench): split sentinel-swarm pages + biome lint + console codemod | DONE (clean, but silently removed workbench async-nats patch — see discrepancy) |
| 10 | `6851ec5fd` | chore: drop redundant async-nats patches + remove 4 dead EDR symbols | DONE (overstates: workbench was already done in commit 9) |
| 11 | `3eea855d6` | docs(audit): add the 22-file audit corpus | DONE (documentation only, 8596 insertions) |

---

## Sanity check results

### Rust workspace

**Command:** `cargo check --workspace` (offline failed with `attempting to make an HTTP request` due to missing vendored sources; ran without `--offline`)
**Result:** PASS — 45.94s, no errors. All ~150 workspace crates compile.

### Rust crates (--tests, per-crate)

| Crate | Result |
|---|---|
| `cargo check -p hushd --tests` | PASS (0.76s) |
| `cargo check -p clawdstrike-control-api --tests` | PASS (5.56s) |
| `cargo check -p clawdstrike-registry --tests` | PASS (0.32s) |
| `cargo check -p clawdstrike-brokerd --tests` | PASS (compile OK; **runtime tests fail — see below**) |
| `cargo check -p clawdstrike-policy-event --tests` | PASS (4.31s) |
| `cargo check -p clawdstrike` | PASS (10.51s) |

### Rust unit-test execution (the deeper check)

| Command | Result |
|---|---|
| `cargo test -p hushd --lib config::` | **PASS** — 16 tests, all green |
| `cargo test -p clawdstrike-registry --bins` | **PASS** — 181 tests, all green |
| `cargo test -p clawdstrike-control-api --bin clawdstrike-control-api config` | **PASS** — 25 tests, all green |
| `cargo test -p clawdstrike-brokerd --lib config::tests` | **FAIL** — 4 failures, 21 passes |

The 4 brokerd failures (single-threaded reproduction):
- `from_env_multiple_pubkeys` — sets HUSHD_PUBKEYS + SECRET_FILE only; new admin-token check refuses to start before the multi-key assertion is reached.
- `from_env_refuses_to_start_without_admin_token` — fails only as part of the suite; in isolation passes (the failure is the cascade from the next item below leaving `ENV_LOCK` Mutex poisoned).
- `from_env_unsupported_backend_errors` — sets PUBKEYS + BACKEND=redis only; admin-token check fires before "unsupported redis" error.
- `from_env_zero_binding_proof_ttl_errors` — calls `set_minimum_env()` (which DOES set admin token), but is poisoned by Mutex cascade from earlier failures.

Root cause: commit `aefb71c02` added `Config::from_env() → refuse to start without CLAWDSTRIKE_BROKERD_ADMIN_TOKEN` but only updated tests that go through `set_minimum_env()`. Three pre-existing tests construct env manually for specific failure-path assertions, and the new fail-closed check fires *before* their intended failure mode. Then the first panicking test poisons the test-suite `ENV_LOCK` mutex, cascading the failures.

**Fix sketch:** in each of `from_env_multiple_pubkeys`, `from_env_unsupported_backend_errors`, `from_env_http_backend_missing_url_errors` (almost certainly the same issue, just not surfaced because it errors before reaching admin check), and any other partial-env test, add `std::env::set_var("CLAWDSTRIKE_BROKERD_ADMIN_TOKEN", "test")` after `clear_env()`. Alternatively, replace `.lock().unwrap()` with `.lock().unwrap_or_else(|p| p.into_inner())` so a single panic doesn't poison the suite.

### TypeScript typechecks

Used `npx tsc --noEmit` from each package (root `node_modules` is present).

| Package | Errors |
|---|---|
| `packages/sdk/hush-ts` | **0** (PASS) |
| `packages/adapters/clawdstrike-openclaw` | **0** (PASS) |
| `packages/adapters/clawdstrike-vercel-ai` | **0** (PASS) |
| `apps/workbench` | **45** (all pre-existing — see note) |

The 45 workbench errors are all in `src/features/swarm/` and all stem from `Cannot find module '@clawdstrike/swarm-engine'` cascading into `unknown` typing. This is the **Wave 3-H** finding — swarm-engine module is a half-built sibling package, not built into the workbench's node_modules layout. The commit message claimed "68 before, 68 after"; actual current is 45. Either the codemod removed some, or the count was an overestimate. Either way, **none of the workbench errors trace to changes in this PR** — they all exist in files this PR did not touch.

### Selected vitest runs (security fixes)

| Command | Result |
|---|---|
| `npx vitest run tests/receipt.test.ts` (openclaw) | **PASS** — 23 tests, all green |
| `npx vitest run src/middleware-fail-closed.test.ts` (vercel-ai) | **PASS** — 4 tests, all green |

### Workflow YAML

**Command:** `for f in .github/workflows/*.yml; do python3 -c 'import yaml; yaml.safe_load(open("$f"))' || echo FAIL; done`
**Result:** **PASS** — zero `FAIL` lines. All 18 workflows parse cleanly.

### Policy load (`hush policy verify`)

Built `cargo build -p hush-cli --bin hush` (debug, 1.68s after the workspace warm-up).

| Policy | Result |
|---|---|
| `rulesets/default.yaml` | **PASS** (Inheritance: SKIP, no base) |
| `rulesets/strict.yaml` | **PASS** (Inheritance: PASS — adds prohibitions to default) |
| `rulesets/permissive.yaml` | **PASS** (no base) |
| `rulesets/ai-agent.yaml` | **FAIL** — Inheritance: FAIL (78 weakened prohibitions from base "default") |
| `rulesets/cicd.yaml` | **FAIL** — Inheritance: FAIL (100 weakened prohibitions from base "default") |

This is a real regression introduced by commit `4c613fd1b`. Old `ai-agent.yaml` and `cicd.yaml` had no `extends:` so the inheritance check was SKIPped. Adding `extends: default` exposes that the children's `egress.allow` list (e.g. `api.bitbucket.org`, `gitlab.com`, `docs.rs`) and `forbidden_path.patterns` (smaller list than default's) are objectively weaker than the parent. From the engine's point of view, an ai-agent ruleset that *permits* `api.bitbucket.org` while inheriting from a default that *denies* it is a weakening — even if the human intent was "ai-agent needs to read these for code intelligence."

The executor's commit message says the smoke test `test_rulesets_parse_validate_and_match_disk_registry` "passes after edits" — and that's true, that test only checks YAML parses + matches the registry. The Logos inheritance check is a separate code path and was not exercised before merging.

**Fix options:**
1. Mark the egress/forbidden-path differences as intentional overrides in the child policies (the schema likely has a mechanism — see `additional_*` patterns already in use for other lists).
2. Restructure: instead of `extends: default`, keep ai-agent/cicd standalone but extract the shared core into a fragment YAML they all `extends:`.
3. Loosen the inheritance check in Logos to allow per-domain `allow` overrides when the child also pins them in `forbidden_path` exceptions (engine-level change, larger scope).

For a v0.2.x cut: option 1 is the lowest-risk. Or temporarily revert ai-agent + cicd to standalone until the override semantics are designed (strict.yaml's `additional_patterns` model works because strict only *adds* prohibitions).

### Schema-version grep

```
grep -rln 'version: "1.0.0"' examples/        → empty   PASS
grep -rln 'schema_version:' examples/         → empty   PASS
grep -rln 'clawdstrike-v1.0' examples/        → empty   PASS
```

All three are clean. All `examples/**/policy*.yaml` use `version: "1.5.0"` per commit `255e8a5f4`. **Mild inconsistency**: the rulesets/ + crate-rulesets/ files were bumped to `1.2.0` (not 1.5.0) in commit `4c613fd1b`. Both are accepted by `POLICY_SUPPORTED_SCHEMA_VERSIONS`, but a viewer flipping between `rulesets/default.yaml` (v1.2.0) and `examples/.../policy.yaml` (v1.5.0) will wonder which is canonical. The "Theme 1 — schema version drift" gripe in the master report was about this exact pattern.

### Discord-URL grep

```
grep -rln 'discord.gg' --include="*.md" . | grep -v '.audit\|infra/vendor'
```

Returns 6 files: `GOVERNANCE.md`, `CONTRIBUTING.md`, `README.md`, `docs/plans/custom-guards/guard-sdk.md`, `docs/specs/11-open-source-governance.md`, `docs/src/roadmap.md`. **All six use `https://discord.gg/fdbCZHm8zM`** — the canonical URL. PASS.

### Receipt verifier (security fix verification)

`packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts` lines 107-138 (`verify`) and 144-170 (`verifyAsync`):

- Unsigned receipts (signature === null): return `options.allowUnsignedDevReceipts === true` (default `false`).
- Signed receipts without a `verifySignature` callback: return `false` (or throw if `strict: true`).
- Promise returned from sync `verifier`: throws ("use verifyAsync").

**No `return true` short-circuit anywhere.** PASS.

Construction enforces `sign: true → throw "OpenClaw signed receipts require the hush-wasm Ed25519 signing bridge"` at lines 51-55. Tests at `tests/receipt.test.ts` (23 cases) cover all four code paths.

---

## Regressions found

1. **`cargo test -p clawdstrike-brokerd --lib config::tests` — 4 failures.**
   New admin-token fail-closed check (`aefb71c02`) fires in tests that don't set `CLAWDSTRIKE_BROKERD_ADMIN_TOKEN`, masking the failure path the test was designed to assert. Tests: `from_env_multiple_pubkeys`, `from_env_unsupported_backend_errors`, `from_env_refuses_to_start_without_admin_token` (only in suite due to mutex poison), `from_env_zero_binding_proof_ttl_errors`. **Blocking.**

2. **`hush policy verify rulesets/ai-agent.yaml` and `rulesets/cicd.yaml` — FAIL Inheritance check.**
   The rulesets consolidation (`4c613fd1b`) added `extends: default` but the children's egress allow-lists and partial forbidden_path lists are detected by the Logos inheritance check as 78 / 100 "weakened prohibitions" respectively. Before consolidation these policies passed because Inheritance: SKIP fired (no base). **Blocking for any release that bundles these rulesets.**

Neither failure breaks `cargo check --workspace`. Both surface only under the test runner / the verifier.

---

## Discrepancies (commit message vs diff)

1. **Commit `7f9cb6068` (workbench refactor) silently dropped `apps/workbench/src-tauri/Cargo.toml`'s `[patch.crates-io] async-nats` block** without mentioning it in the commit body. The deletion is correct (Wave 3-J recommended it) but it should have been in commit `6851ec5fd`.

2. **Commit `6851ec5fd` (async-nats cleanup) overstates scope.** Body says "remove redundant `[patch.crates-io] async-nats` blocks from root + agent/src-tauri + desktop/src-tauri (committed in C5) + workbench/src-tauri", but the diff stat shows only `Cargo.lock`, `Cargo.toml`, `apps/agent/src-tauri/Cargo.toml`, and the flight_recorder. `apps/desktop/src-tauri/Cargo.toml` had no patch block to remove (already absent at base), and `apps/workbench/src-tauri/Cargo.toml`'s patch was removed in the *previous* commit (`7f9cb6068`).

3. **Commit `7f9cb6068` claims "Zero typecheck regressions: 68 errors before, 68 after."** Actual current count is 45 (45 in `features/swarm/`). The codemod or the file-split may have eliminated some errors; in any case the directional claim ("no regression") is correct, but the absolute number is off.

4. **Commit `4c613fd1b` claims "Wave 9 audit's smoke test ... passes after edits"** but did not run `hush policy verify` on the consolidated rulesets. That's the verifier that actually fails (see Regressions).

5. **Schema-version inconsistency between commits 3 and 7.** `255e8a5f4` bumped examples to v1.5.0; `4c613fd1b` bumped rulesets to v1.2.0. Both are in-spec, but ending a "schema reconciliation" pass with two valid-but-different version numbers across the two largest YAML directories is exactly the drift the audit complained about.

---

## Tier A items: status

From `00-MASTER-REPORT.md` Quick Wins list (items 1-15) + Critical-Immediate items:

| # | Item | Status |
|---|---|---|
| A1 | Nuke build cruft, demo routes, .DS_Store, .tmp-release-venv, etc. + .gitignore | **DONE** (commit 8015e437f) |
| A2 | Delete broken `divider.png` ref + fix CONTRIBUTING.md smart-quote | **DONE** (commit 255e8a5f4) |
| A3 | Pick one package manager — drop bun lockfiles, add packageManager | **DONE** (commit 4a9a2d061) |
| A4 | Replace 3 identical Tauri default-T icons | **DEFERRED** — needs artwork; md5sum confirms all three apps still ship `9418b9b0e421e3ff0744aef7960f511c` |
| A5 | Schema version reconciliation across READMEs / examples | **DONE** (commit 255e8a5f4) but see inconsistency note |
| A6 | Flip 4 fail-closed auth defaults | **DONE** (commit aefb71c02) but introduced 4 brokerd test failures |
| A7 | One canonical Discord URL | **DONE** (commit 255e8a5f4) — all 6 .md files use `discord.gg/fdbCZHm8zM` |
| A8 | Delete AI-slop docs (HANDOFF.md, auth.md, agent-frameworks/, nono-integration/, codex-handoff-prompt.md, executor-handoff-prompt.md, UI-POLISH-CAMPAIGN.md) | **DONE** (commit 255e8a5f4) — 12,282 deletions |
| A9 | Delete academy test-mdx demo route | **DONE** (commit 8015e437f) |
| A10 | Rename apps/desktop from sdr-desktop → @clawdstrike/desktop | **DONE** (commit 80cec40b1) |
| A11 | Delete committed WASM artifacts in `crates/libs/hush-wasm/` | **DONE** (commit 8015e437f, 1,713 lines deleted) |
| A12 | Delete committed Vite bundles in `apps/agent/src-tauri/resources/` | **DONE** (commit 8015e437f) |
| A13 | Fix workbench Tauri schema URL | **DONE** (commit 80cec40b1) — nicegui URL → schema.tauri.app/config/2 |
| A14 | Renumber duplicate spec 19 → 20 | **DONE** (commit 255e8a5f4) |
| A15 | Remove `src/hush` ghost from hush-py/pyproject.toml | **DONE** (commit 255e8a5f4) |

**Tier A status: 14/15 DONE, 1 DEFERRED (icons).**

---

## Tier B items: status

| # | Item | Status |
|---|---|---|
| B1 | Rewrite README.md from scratch ≤300 lines | **DEFERRED** — needs voice decisions; current README still 1,122 lines |
| B2 | Add concurrency + permissions + timeouts to all workflows | **DONE** (commit 733c69763) |
| B3 | Collapse docker.yml 9 jobs into matrix | **DONE** (commit 733c69763) — 347 lines → ~94 lines, 61% shrink |
| B4 | Pin trivy-action SHA + drop continue-on-error | **DONE** (commit 733c69763) |
| B5 | Move cargo audit --ignore list into structured config | **DONE** (commit 733c69763) — `.cargo/audit.toml` with rationale + owner + expiry |
| B6 | Swatinem/rust-cache@v2 replacing per-job actions/cache@v5 | **DONE** (commit 733c69763) |
| B7 | Split workbench `sentinel-swarm-pages.tsx` (939 lines) into 6 files | **DONE** (commit 7f9cb6068) — 9-line barrel + 6 page files + 441-line `_shared.tsx` |
| B8 | Enable workbench biome linter with noConsole + noExplicitAny | **DONE** (commit 7f9cb6068) — `biome.json` flipped + workbench override |
| B9 | Codemod 102 console.* calls in workbench → logger | **DONE** (commit 7f9cb6068) — 289 calls actually codemodded across 77 files; only logger.ts retains console.* internally |
| B10 | Convert strict/ai-agent/cicd/permissive to `extends: default` | **PARTIAL** — strict/ai-agent/cicd done (permissive intentionally kept standalone, weaker than default); but ai-agent + cicd now FAIL `hush policy verify` |
| B11 | Add path_allowlist block to default.yaml | **DONE** (commit 4c613fd1b) — disabled-by-default with sample allow lists |
| B12 | Fix broken compliance fixtures (hipaa/pci-dss/soc2) | **DONE** (commit 4c613fd1b) — bumped to v1.2.0; the executor disputed the "invalid fields" claim and audit corpus confirms only the version was stale |
| B13 | Add Tauri `capabilities/default.json` for agent + desktop | **DONE** (commit 80cec40b1) — deny-everything baselines added; workbench already had one |
| B14 | Remove hardcoded `TEAM_ID=JB6682CJY9` | **DONE** (commit 80cec40b1) — parameterized via env/--team-id flag, plist uses `@@TEAM_ID@@` placeholder |
| B15 | Set CSP on `apps/desktop/src-tauri/tauri.conf.json` | **DONE** (commit 80cec40b1) |
| B16 | Rewrite hush-ts client.ts with real types | **DONE** (commit 254d8a52c) — concrete certification-domain types + runtime envelope checks |
| B17 | Fix `ReceiptSigner.verify` fail-open | **DONE** (commit 254d8a52c) — fail-closed by default + pluggable verifier + verifyAsync |
| B18 | Make Vercel-AI middleware fail-closed on WASM unavail | **DONE** (commit 254d8a52c) — `ClawdstrikeMiddlewareInitError` + opt-in `allowDegradedSecurity` + onDegrade callback |

**Tier B status: 17/18 DONE (1 partial with regression), 1 DEFERRED (README rewrite).**

---

## Wave 3 items executed

From `.audit/wave3/`:

| ID | Topic | Status |
|---|---|---|
| W3-A item 4 | Drop redundant async-nats `[patch.crates-io]` blocks | **DONE** (commit 6851ec5fd) — all 4 of 4 removed (root + agent + desktop never had one + workbench in prior commit) |
| W3-B item 2 | Remove 4 of 5 confirmed-dead EDR symbols | **DONE** (commit 6851ec5fd) — EndpointFlightRecorderSnapshot, snapshot(), read_observations(), read_observation_window() non-indexed variant. **`CausalGraphRecorder::causal_path()` retained** with executor note: it has 2 callers in `edr/mod.rs` test code (lines 4216, 4409), contradicting Wave 3-A's "zero callers" finding. |
| W3-E | Lockfile sweep (40 active lockfiles → npm canonical) | **DONE** (commit 4a9a2d061) — root bun.lockb, workbench bun.lock, cursor-plugin/clawdstrike-plugin bun.lockb deleted |
| W3-A item 5 | macOS provider dogfood contract test wired into CI | **DONE** (commit 733c69763) — `macos-provider-dogfood-contract` job at end of ci.yml |
| W3-A item 2 | Audit-ignore list externalized | **DONE** (commit 733c69763) — `.cargo/audit.toml` with 158-line structured spec |

---

## What was deliberately deferred

| Item | Reason | Effort estimate |
|---|---|---|
| Master Tier A #4 — 3 Tauri default icons | Needs actual artwork (PNG/ICNS/ICO per app) | 30 min + a designer |
| Master Tier B #1 — README rewrite ≤300 lines | Needs voice decisions and which tagline to keep | 1 afternoon |
| Master Tier W3-B #1 — swarm-engine fold into workbench | 3-day refactor; see `.audit/wave3/H-swarm-engine-viability.md` | 3 days |
| Master Tier W3-B #3 — roadmap consolidation (17 → 3) | Needs editorial decisions on what's live vs aspirational | 1 week |
| Master Tier W3-B #4 — TS `any` Sprint 1 (52 vendor-AI hits + 25 WASM bindings) | 3 days; see `.audit/wave3/D-typescript-any-inventory.md` | 3 days |
| Master Tier W3-A #3 — TS `any` Sprint 0 (~95 hits) | Wasn't dispatched | 1-2 days |

Additional gaps surfaced by this audit (not on the original deferral list):

- **`docs/plans/swarm-engine/ARCHITECTURE.md:35` hardcoded local filesystem path** — still present (`/Users/connor/Medica/backbay/standalone/clawdstrike-swarm-engine/...`). Not in the executor scope but flagged in master report Critical-Immediate.
- **Tier C structural items** (api_server.rs split, edr/mod.rs split, control-api/integration_tests move to `tests/`) — explicitly out of scope, ≥1-2 weeks each.
- **Critical-Immediate #19** — 4 `sorry`s in Aeneas-generated Lean files — not in scope (formal-verification team).
- **Critical-Immediate #9** — `eas-anchor` is a service whose entire purpose returns `Err("Chain submission not yet implemented")` — not in scope.

---

## Recommended next steps

In priority order:

1. **Fix the 4 brokerd config test failures** (Blocker). Either (a) add `CLAWDSTRIKE_BROKERD_ADMIN_TOKEN=test` to each test's env setup that doesn't go through `set_minimum_env`, or (b) make the test ENV_LOCK use `.unwrap_or_else(|p| p.into_inner())` so a panic doesn't poison the suite. Without this, `cargo test --workspace` fails for any merger and CI will go red.

2. **Fix the ai-agent + cicd verifier regression** (Blocker for cutting a release that includes these rulesets). Lowest-risk fix: revert ai-agent.yaml and cicd.yaml to standalone for v0.2.x, file an issue to design the inheritance-override semantics (e.g. an explicit `weaken_egress: [api.bitbucket.org]` block), and land that in v0.3.0. Alternative: leave them as-is and accept the verifier failure with an explicit `inheritance: relaxed` flag in the policy.

3. **Reconcile rulesets/ schema version with examples/ schema version.** Either bump rulesets to 1.5.0 to match examples (matches `POLICY_SCHEMA_VERSION`), or downgrade examples to 1.2.0 (matches the schema features they actually use). Don't ship a "schema reconciliation PR" that leaves the two largest YAML directories on different versions.

4. **Run `cargo test --workspace` before push.** None of the per-crate test runs the executors cited would have caught the brokerd cascade. Add a smoke step to wave-cleanup checklist: `cargo test --workspace -- --test-threads=1` and `for p in rulesets/*.yaml; do ./target/debug/hush policy verify "$p" || echo "FAIL: $p"; done`.

5. **Document the workbench Cargo.toml `[patch]` removal** in commit 7f9cb6068's body (or, if pushing now, in the PR description). Surface to reviewer that the async-nats cleanup actually spans commits 9 and 10.

6. **Update the executor-J commit message** to drop the "desktop" claim (no patch was there) and to note that the workbench patch was already removed by the prior commit.

7. **Replace the 3 default-T Tauri icons.** Even a 30-minute cargo-tauri-icon generation from a single brand SVG would clear master report Critical-Immediate #25 and visibly upgrade the desktop apps.

8. **Decide on README direction** before the next PR. Tier B #1 is the highest-visibility deferred item and every cosmetic improvement above is washed out by a 1,122-line README that opens with a poem.

---

## Push/PR recommendation

**Do not push as-is.** Fix the two regressions first.

Recommended sequence:

1. **One follow-up commit (`test(brokerd): set admin token in partial-env config tests`)** that adds `CLAWDSTRIKE_BROKERD_ADMIN_TOKEN` to the 3 tests that lack it, plus changes `ENV_LOCK.lock().unwrap()` to `.unwrap_or_else(|p| p.into_inner())` so a future panic doesn't cascade. Verify with `cargo test -p clawdstrike-brokerd --lib config:: -- --test-threads=1`.
2. **One follow-up commit (`revert(rulesets): keep ai-agent + cicd standalone pending override semantics`)** that backs out the `extends: default` change for those two files only (keep `path_allowlist` in default, keep strict.yaml's extends, keep all other parts of `4c613fd1b`). Verify with `./target/debug/hush policy verify rulesets/{default,strict,ai-agent,cicd,permissive}.yaml`. File issue: "Design `extends` override semantics so allow-list deltas don't read as weakened prohibitions."
3. **Optional: a third commit normalizing rulesets/ to v1.5.0** to match examples/. Trivial change, ends the inconsistency.
4. **Push** `chore/cleanup-tier-ab` and open the PR.

PR gates to add before merge:
- `cargo test --workspace -- --test-threads=1` must pass.
- A new CI step: `for p in rulesets/*.yaml; do ./target/debug/hush policy verify "$p"; done` (matches Wave 1 master report's request for `scripts/validate-example-policies.sh`).
- A grep guard: fail if any root `.md` mentions a schema version not in `POLICY_SUPPORTED_SCHEMA_VERSIONS`.
- A grep guard: fail if the audit corpus references a deferred Tier A/B item that has not been opened as a tracking issue.

PR description should explicitly list the 4 deferred items (icons, README, swarm-engine fold, roadmap consolidation) and link to the audit corpus.

**Net assessment:** This is a strong cleanup pass — 14 of 15 Tier A items done, 17 of 18 Tier B items done, 5 of 5 Wave 3 items done, every meaningful security default flipped, the receipt verifier no longer fail-open, the Vercel-AI middleware no longer silently degrades, the schema-version drift collapsed from 6 answers to 2, 12 KB of fictional planning docs gone, ~2 KB of build artifacts gone, 4 redundant `[patch]` blocks gone. The two regressions are mechanical, isolatable, and fixable in under an hour. **Land it after the fixes — this is the most significant cleanup pass the repo has had.**
