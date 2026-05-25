# Wave 4 — Delta Synthesis

**Refreshed:** 2026-05-24
**Branch:** `fix/macos-es-ne-hardening` @ `2eff91532`
**Source audits:** `.audit/01..09-*.md` (2026-05-23) + `.audit/wave3/*`
**Method:** 9 parallel agents validated every concrete finding against current HEAD + working tree.
**Tone:** Direct, file:line, no theatrics.

---

## TL;DR (one minute)

**Net state vs. 2026-05-23: essentially unchanged.** Of ~230 concrete findings across nine areas, **0 are fixed on `fix/macos-es-ne-hardening` HEAD**. A handful drift by 1–2 lines (refactors moved code, didn't fix issues). The "tough love" critique from yesterday is still the critique today.

**The real story is in the branches list.** Nine `chore/cleanup-*` branches exist locally (`chore/cleanup-tier-ab`, `chore/cleanup-purge-and-vendor`, `chore/cleanup-refs-and-formatting`, `chore/fix-security-deps`, `chore/misc-cleanup`, `chore/resolve-dependabot-alerts`, `chore/remove-production-readiness-test-plan`, `chore/restore-long-readme`, `chore/ts-sprints-23-deps-latest`). Several remediate concrete audit findings (CI hardening, biome linting, sentinel-swarm split, dep updates). **They didn't merge.** Step zero of any cleanup is deciding which of these to land before doing fresh work.

**What did change is small and partially bad.** The EDR refactor (commits `a97fda5d9` → `bd3ea7e63`) extracted ~3.2K of ~21K planned LOC out of `api_server.rs` into `edr/` submodules — but the file itself is still 48,111 lines. Worse: someone removed `#![allow(dead_code, unused_imports)]` from `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` *without deleting the dead code*, which broke `cargo check` under `-D warnings`, and the uncommitted working tree silently re-adds the allow to compile. Half-cleanup that left the repo in a worse spot than before. The CI signing setup (`1ade43894`) introduced a new shell-injection sink in `scripts/codex-swarm/common.sh:462`. The macOS Swift hardening (`768876a7b`, `56dc31483`) is real cleanup that landed cleanly.

**5 new criticals the wave-1 audit missed (or that materialized after):**
1. **Live OpenAI API key in `.env`** — `sk-proj-Xg1k2XaPA5BuBjy...` is a real, unrevoked credential on a security tool's working tree. (D01 N-01)
2. **Shell-injection regression** at `scripts/codex-swarm/common.sh:462` introduced by `1ade43894` — `bash -lc "$bootstrap_preset"` against untrusted lane TSV input. (D02 N-01)
3. **`infra/vendor/` is 1.0 GB / 841 directories** with 96 multi-version duplicates; every clone pays 1 GB. (D02 N-03)
4. **swarm-engine ships with 3 CRITICAL + 4 HIGH security findings** documented in-tree at `docs/plans/swarm-engine/SECURITY-AUDIT.md` since 2026-03-24. (D05 N-01)
5. **Workbench `stronghold.rs:96-105` silently derives vault keys from hostname+time** when `getrandom` fails — vault security regression hiding behind a fallback. (D07 N-07)

Plus: workbench `biome.json` has `linter.enabled: false` (D06 N-09), schema-version drift is 19/27 unloadable example policies (not the audited ~11; D08 corrects this upward), and the working tree is *actively making three audit god-files bigger* (+568/+223/+231 LOC to `routes/policies.rs`, `routes/response_actions.rs`, `integration_tests.rs`; D04 N-03).

**The four insecure defaults — still all insecure**, verified line-by-line at HEAD (D04 V-01..V-04). For a fail-closed security product, this remains the most damning single line in the report.

---

## Aggregate delta scorecard

| Area | Wave-1 score | Wave-4 score | Direction | Why |
|---|---|---|---|---|
| 01 Top-Level Meta | 5 | 4 | ▼ | new critical (`.env` key); README, schema-drift, lockfile sprawl all still live |
| 02 CI/CD & Infra | 5 | 5 | → | shell-injection regression cancels macOS-signing CI win |
| 03 Rust Core Libs | mixed | mixed− | ▼ | dead-code allow removed *without* deleting dead code; working tree re-adds allow to compile |
| 04 Rust Services/Bridges | 5–6 (security 3) | 5–6 (security 3) | → | 0 findings fixed; +1022 LOC of new code in dirty tree to three god-files |
| 05 TypeScript Packages | 4–6 | 4–6 | → | 0 commits to `packages/` since audit; 272 `any` survey unchanged |
| 06 Frontend Apps | 5–6 | 5−–6 | → | 26 workbench files >1k LOC (audit cataloged 6); 6 new EDR-page god-files in control-console |
| 07 Tauri Desktop | 3 (build/sign 2) | 4 (build/sign 3) | ▲ small | macOS signing fixed *in CI*; Swift hardening landed; api_server.rs still 48k LOC |
| 08 Docs/Formal/Examples | 6 (planning 2) | 6− | ▼ small | corrected: 19 unloadable examples (not 11), 11 doc paths cite schema (not 4) |
| 09 Tests/Rulesets/Misc | 6–7 | 6–7 | → | exact reproduction; one diagnosis sharpened (`vendor/hushspec` is first-party misfiled) |

**Glaring outliers (unchanged):**
- **Security defaults: 3/10** — hushd auth-disabled-by-default, control-api `0.0.0.0:8080` with permissive CORS, registry permits empty API key, brokerd skips admin auth when token is None.
- **Planning hygiene: 2/10** — 18 `docs/plans/<topic>/` dirs, 7 fictional agent-framework specs (~256 KB), 11+ overlapping roadmaps.
- **Tauri config: 3/10** — three byte-identical default-T icons, empty `capabilities.json` × 2, null signing identities.
- **TS type safety: 4/10** — 272 `any`/`as any` in `packages/` alone.

---

## Critical issues (must-fix; minutes-to-hours each)

These are the things that turn this from "needs cleanup" to "actively dangerous or embarrassing."

### C-1. Revoke the OpenAI API key in `.env`, then delete the file. (D01 N-01)
- `.env` at repo root contains `OPENAI_API_KEY=sk-proj-Xg1k2XaPA5BuBjy...` + `OPENAI_MODEL=gpt-5`.
- Gitignored, but the credential is exfiltratable by anyone with FS read.
- **Action:** revoke in OpenAI console *first*, then `rm .env`. Add `.env.example` documenting expected vars.
- **Time:** 5 min.

### C-2. Revert the shell-injection regression in `scripts/codex-swarm/common.sh:462`. (D02 N-01)
- Commit `1ade43894` regressed `exit 1` → `bash -lc "$bootstrap_preset"` against untrusted lane TSV input.
- **Action:** revert that line; `$bootstrap_preset` must be sanitized or use an enum dispatch.
- **Time:** 5 min.

### C-3. Flip all four insecure defaults in one PR. (D04 V-01..V-04)
- `hushd/src/config.rs:97-107` — `AuthConfig::enabled = true`.
- `control-api/src/config.rs:59-61` + `main.rs:310` — listen `127.0.0.1` by default + named CORS allowlist.
- `clawdstrike-registry/src/config.rs:26,41-42` — refuse empty API key unless explicit `allow_insecure_no_auth: true`.
- `clawdstrike-brokerd/src/api.rs:193-210` — admin token required unless explicit opt-out.
- **Action:** four small commits in one PR; each finding has the exact diff site.
- **Time:** 1–3 hrs total.

### C-4. Resolve the half-finished dead-code cleanup in `edr/mod.rs`. (D03 V-01 + the working-tree re-add)
- HEAD removed `#![allow(dead_code, unused_imports)]` from `crates/libs/clawdstrike-policy-event/src/edr/mod.rs:8` without removing the dead code, so `cargo check` is now warning-storming. Working tree silently re-adds the allow.
- **Action:** either land wave3/A-edr-mod-deadcode.md (the 7-commit deletion plan) or revert the allow removal. Don't ship the dirty re-add.
- **Time:** 1–3 days (deletion plan) or 5 min (revert).

### C-5. Decide what to do with `chore/cleanup-tier-ab` and `chore/ts-sprints-23-deps-latest`. (Wave-4 meta)
- Each contains real remediation for audit findings (CI hardening, biome linting, sentinel-swarm split, deps).
- Sitting unmerged, they will conflict harder every day.
- **Action:** rebase, review, merge — or close with an explicit "won't land" decision.
- **Time:** 2–4 hrs review.

---

## High-leverage execution plan (sequenced, with cost)

Five waves, ordered for max professionalism gain per hour. Each wave is independently shippable.

### Wave A — Cruft & secrets (today, ~1 hr)
Goal: stop leaking, stop embarrassing.
1. **C-1** revoke + delete `.env`. **C-2** revert shell-injection.
2. Delete from working tree: `.DS_Store` (all instances), `tmp/` (55 MB / 3863 files), `output/`, `coverage/`, `.tmp-release-venv/` (13 MB), `.playwright-cli/`, `apps/cloud-dashboard/dist/`, `docs/book/` if present, `apps/agent/src-tauri/resources/control-console/assets/*.js` (committed Vite bundles), `apps/academy/src/app/test-mdx/`.
3. Add the four corresponding `.gitignore` entries; verify `git status` is clean.

### Wave B — Security defaults (this week, ~half a day)
Goal: the product can no longer ship insecure-by-default.
1. **C-3** flip all four defaults; add integration test that a fresh hushd/control-api/registry/brokerd rejects unauthenticated calls by default.
2. Restore wave3 dep-bump intent from `chore/fix-security-deps` and `chore/resolve-dependabot-alerts` if those still apply cleanly.
3. Fix the workbench `stronghold.rs:96-105` getrandom fallback — fail loud, do not derive from hostname+time.

### Wave C — Surface professionalism (this week, ~2 days)
Goal: anyone clicking through GitHub thinks "elite OSS."
1. Rewrite `README.md` from scratch (target ≤300 lines; one tagline; kill the 5-line poem and broken `divider.png`). Reject `chore/restore-long-readme` if it conflicts with this goal.
2. Unify schema version: `1.5.0` everywhere. Patch the 11+ doc paths + 19 example YAMLs the agents enumerated. Add `scripts/validate-example-policies.sh` to CI.
3. Replace 3 byte-identical Tauri-default "T" icons. One mark per shipping app.
4. Pick a package manager. Delete every other lockfile family. Root + 15 nested locks today.
5. Land C-5 — merge `chore/cleanup-tier-ab` (CI hardening + biome lint) and `chore/ts-sprints-23-deps-latest`.

### Wave D — Subtraction (next week, ~3–5 days)
Goal: cut anything that doesn't serve the core product.
1. **Delete `apps/cloud-dashboard/`** — verified empty in git, only `dist/` artifacts. (5 min after Wave A.)
2. **Delete `crates/services/eas-anchor/`** — entire service body returns `Err("Chain submission not yet implemented")`. ~1124 LOC removed. If EAS anchoring matters, file an issue; don't ship a stub.
3. **Delete `packages/swarm-engine/`** — 21 K LOC of half-built product carrying 3 CRITICAL + 4 HIGH unresolved security findings. Workbench's `useOptionalSwarmEngine()` already falls back.
4. **Delete `packages/sdk/clawdstrike/`** — 5-LOC vanity re-export, zero consumers.
5. **Decide: workbench 3D / Spirit / Observatory / Nexus layer.** 44,967 LOC across 228 files. `MOTION_PLAN.md:7` says "Delight = precision engineering, NOT playfulness" — the layer contradicts it. Either: (a) extract to its own product/repo, (b) delete entirely, (c) make a defensible product case in `apps/workbench/README.md`. **No third audit should find this open.**
6. **Decide: `apps/desktop/` future.** Audit says vestigial; D06 confirms ~33 K LOC + new findings (`ForensicsRiverView.tsx` 1,728 LOC). If `apps/agent` covers the use case, delete `desktop`.
7. **Delete `chore/restore-long-readme` branch** if Wave C lands a short README.

### Wave E — Restructure (week after, ~1–2 weeks)
Goal: actually fix the architectural smells.
1. Execute `.audit/wave3/B-api-server-routes.md` — split `api_server.rs` (48 K LOC) into the planned router + handlers + DTO modules. Move the 229 inline tests out. Convert `signedReceipt` payload addition into a documented wire-format change.
2. Execute `.audit/wave3/A-edr-mod-deadcode.md` and `C-receipt-family-extraction.md` — split `edr/mod.rs` (9836) and `receipt/mod.rs` (6402), delete dead modules, restore the `-D warnings` gate.
3. Promote `vendor/hushspec/` to `crates/libs/hushspec/`. Delete its duplicate in `fixtures/hushspec/rulesets/`.
4. Replace `infra/vendor/` (1 GB on disk) with CI-time `cargo vendor`. -1 GB from clone.
5. Decompose god-files in front-end land: 26 workbench files >1k LOC + 6 new control-console EDR pages.
6. Plan-doc purge: 18 plans dirs → keep what's shipped, archive the rest. 7 fictional agent-framework specs → delete.

---

## Things to NOT do yet

- **Don't rewrite `apps/workbench`** before deciding the 3D-layer question. Refactoring before deletion is wasted work.
- **Don't ship a v0.3.0 release** before C-3 + the README + schema unification. The current version+README will get screen-shotted on Hacker News and you don't want that screenshot.
- **Don't merge `chore/restore-long-readme`** if Wave C lands a 300-line README. Names like this exist because someone tried the short README and got pushback; that pushback was wrong.
- **Don't touch `formal/lean4/`** as a cleanup target. The Lean spec is one of the few unambiguously elite artifacts in the repo. Audit-overclaim in *docs* is a docs problem, not a Lean problem.
- **Don't refactor `bridge_runtime`** before deciding the 4-bridge consolidation in D04 AGG-4.

---

## Cross-cutting themes (refreshed)

The five wave-1 themes still hold; severity unchanged except where noted.

| Theme | Wave-1 | Wave-4 |
|---|---|---|
| Schema-version drift | 1.0/1.1/1.2/1.3/1.4/1.5 across 4 docs + 11 YAML | Same versions; **11+ doc paths** (was 4); **19/27 YAML unloadable** (was 11) — worse on inspection |
| God files (2k–48k LOC) | 13 worst offenders | Same 13 + **26 workbench files >1k LOC** + 6 new control-console EDR pages + `fleet-client.ts` 2,387 + `EventDetailDrawer.tsx` 1,332 |
| Two lockfile families | 15 sites | Same; CI never references the root locks |
| Marketing-tone READMEs | README poem, three taglines | Same; `chore/restore-long-readme` branch exists, ominous |
| Security defaults | hushd off, control-api 0.0.0.0, registry empty-key OK, brokerd skip-on-None | All four still hold; verified at HEAD |

Two themes surfaced in Wave-4 that weren't in the original cross-cutting list:

- **"Cleanup attempted, not merged."** 9 `chore/cleanup-*` branches exist; the audit findings aren't because someone hasn't *thought* about them — they've been worked, just not landed.
- **"Half-cleanup worse than no-cleanup."** Two examples: `edr/mod.rs` `#![allow(dead_code)]` removal without deletion (D03), and `api_server.rs` EDR extraction at 15% completion (D07). Both leave the repo less coherent than before the work started.

---

## Per-area pointer to detailed delta

- `.audit/wave4/D01-top-level-meta.md` — root meta/config; new `.env` critical
- `.audit/wave4/D02-ci-cd-infra.md` — CI bloat persists; shell-injection regression; `infra/vendor` 1 GB
- `.audit/wave4/D03-rust-core-libs.md` — half-finished dead-code cleanup; god files unchanged
- `.audit/wave4/D04-rust-services-bridges.md` — all 4 insecure defaults verified; god files growing in dirty tree
- `.audit/wave4/D05-typescript-packages.md` — zero TS commits; 21K LOC subtraction available
- `.audit/wave4/D06-frontend-apps.md` — 80K LOC subtraction available; biome linter disabled
- `.audit/wave4/D07-tauri-desktop-apps.md` — api_server.rs effectively unchanged; signing fixed in CI
- `.audit/wave4/D08-docs-formal-examples.md` — 19 unloadable example policies; 5 Lean `sorry`, 141 axioms
- `.audit/wave4/D09-tests-rulesets-misc.md` — `vendor/hushspec` is first-party misfiled; 5 of 11 rulesets use `extends`

---

## What "professional open-source elite principal" looks like for this repo

For each of the five worst impressions today, the elite-version of the artifact:

| Today | After cleanup |
|---|---|
| `README.md` 1,126 lines, opens with a 5-line poem, three competing taglines, broken `divider.png` | ~280 lines, single tagline, one diagram, install + minimal example + link to mdBook |
| `apps/agent/src-tauri/src/api_server.rs` 48,111 lines / 884 functions / 229 inline tests | `api_server.rs` < 200 lines (Axum builder); handlers in `api_server/handlers/{domain}.rs`; tests in `tests/`; one error enum |
| `hushd` defaults: auth off, no admin token requirement | Defaults: auth on; admin token mandatory unless `--insecure` flag; startup log refuses to bind 0.0.0.0 without `--bind` flag |
| 3 byte-identical default Tauri "T" icons across agent/desktop/workbench | One product = one mark; three brand-coherent icons + macOS `.icns` + Linux `.png` variants generated from one source SVG |
| `docs/plans/` has 18 subdirs, 7 fictional agent specs, 11+ overlapping roadmaps | One `docs/plans/ROADMAP.md` + per-shipped-feature ADR under `docs/plans/decisions/`. Everything else moved to `docs/archive/` or deleted |

---

## Recommended next step

**Ask:** "Should we execute Wave A (cruft + secrets) right now?" It's <1 hr, blast-radius is zero, and the trust upgrade is immediate. Wave B (security defaults) is the harder ask — it touches public API. Wave D (subtraction) needs a product call on the workbench 3D layer.

If you say "go," I dispatch an execution swarm that does Wave A in one commit, opens a PR for Wave B, and drafts deletion PRs for Wave D items individually so you can approve/reject each.
