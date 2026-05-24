# Wave 3 — Deep-Dive Synthesis

**Date:** 2026-05-23
**Inputs:** 11 narrow deep-dive audits in `.audit/wave3/A–K-*.md`
**Companion to:** `.audit/00-MASTER-REPORT.md`

The 11 deep-dives produced 4,100 lines of receipts. Where they contradict or refine Wave 2's numbers, the deep-dive numbers win — they're sourced from line-level reads.

---

## Bottom-line per dive

| # | Topic | Headline | LOC | Effort to act | File |
|---|---|---|---|---|---|
| A | `edr/mod.rs` dead-code | 7,453 of 9,836 lines are in-file tests; only ~256 LOC truly dead; ~52% shrink possible by relocating tests + dropping orphans | 405 | 8 commits, 1 day | `A-edr-mod-deadcode.md` |
| B | `api_server.rs` route audit | 720 fns (not 884), 109 routes, 19k production + 29k inline tests. Split already half-done — handlers extracted but still glob-import helpers. 33 of 109 routes untested. | 669 | 5–8 commits, 1 week | `B-api-server-routes.md` |
| C | `edr/receipt/` family extraction | 19 `for_*` constructors + 94 helpers + 442-line `validate()` god-method. 14 families collapse to ~14 modules; zero breaking changes. `mod.rs` 6,402 → ~350 lines. | 625 | 7 commits, 3 days | `C-receipt-family-extraction.md` |
| D | TypeScript `any` inventory | Actual count: **347 hits (122 `any` + 225 `as any`)**, not 503/189. 90% lives in three categories: hand-rolled YAML validators (~125), Vercel-AI vendor gap (~52), WASM bindings (~25). | 420 | 11-day plan in 4 sprints | `D-typescript-any-inventory.md` |
| E | Lockfile sweep | **40 active lockfiles.** Root is package-manager schizophrenic (npm workspaces declaration is decorative, CI uses neither root lockfile). 14 redundant `package-lock.json` in workspace members. Cargo is clean. | 278 | 6 commits, 1 day | `E-lockfile-sweep.md` |
| F | `release.yml` walkthrough | Publish reach: **5 of 14 crates**, 3 of those already at `0.2.7` on crates.io. `clawdstrike` dry-run failure root-caused: `hushspec=0.1.1` is `publish=false`; `nono=0.11.0` is 46 minor versions behind upstream. 27 of 36 `cargo audit` ignores have zero rationale. | 346 | 9-step plan to v0.3.0 cut | `F-release-walkthrough.md` |
| G | Roadmap reconciliation | **17 roadmaps, 10,912 LOC**, contradicting each other on every shared topic (schema version v1.2/1.4/1.5 — code is v1.5). Multiple Phase-3 plans that already shipped still listed as "planned." | 268 | 7-commit migration | `G-roadmap-reconciliation.md` |
| H | `swarm-engine/` viability | **Verdict: KEEP, INTERNAL.** Only consumer is `apps/workbench`; not on npm; 11 `pre*` scripts already treat it as private build artifact. **6 of 7 subsystems unused.** 3 CRITICAL + 4 HIGH unresolved security findings in `docs/plans/swarm-engine/SECURITY-AUDIT.md`. Development stopped 2026-03-28. | 326 | 6 commits, 3 days | `H-swarm-engine-viability.md` |
| I | `scripts/*.py` triage | Wave-1 narrative was wrong: 15 (not 18) files, ALL reachable via dogfood/contract scripts. **None dead, none dangerous.** Real gap: the contract test that exercises them is never invoked from CI. Disposition: 15 STILL-USEFUL-MOVE → `tools/`. | 195 | 7 commits | `I-scripts-py-triage.md` |
| J | `infra/vendor/` audit | **Actually 1.0 GB / 841-crate `cargo vendor` mirror** for offline CI, not a curated fork list. Only 2 crates have local mods (`nono`, `rustls-webpki`). The 4× `[patch.crates-io] async-nats` blocks are **UNJUSTIFIED** (vendored copy is stock). `docs/specs/04-apache-2-license.md:57` falsely claims vendored crates are "NOT modified." | 372 | 6-step cleanup | `J-infra-vendor-audit.md` |
| K | Plugin surface gap | Wave-1 framing was incomplete. TS plugin SDK actually ships ~23k LOC including iframe sandbox + postMessage bridge + playground. Real problem: **two parallel "plugin" worlds** (TS + Rust/WASM) that share only branding; docs describe only TS world; the actually-shippable end-to-end story (sign → install → load → execute) is the **undocumented** WASM world. Policy validation hardcodes 4 acceptable plugin packages. | 196 | Option B = trim docs, 3-5 days | `K-plugin-surface-gap.md` |

---

## Corrections to the master report

Wave 2 leaned on Wave 1's grep-level counts; the deep dives caught several overstatements. Where they disagree, trust Wave 3.

| Master report claimed | Wave 3 verified | Delta |
|---|---|---|
| `api_server.rs` is 884 functions | 720 functions, 109 routes, 162 of those are duplicate `Router::new()` rebuilds in inline tests | -164 fns |
| `edr/mod.rs` is 9,836 lines of "production code with `#![allow(dead_code)]`" | 9,836 lines, but **7,453 are `#[cfg(test)] mod tests`**. The `allow(dead_code)` exists because the test mod references private symbols | Production code is ~2,382 LOC |
| TS `any` audit: 503 + 189 = 692 | Actually 122 + 225 = 347 in production TS (the wave-1 number counted tests + `.d.ts` + `infra/vendor/`) | -345 hits |
| 14 publishable Rust crates | Workflow only attempts 5 (hardcoded allow-list); 9 others stuck at `0.2.5` | Publish reach much smaller than implied |
| 18 Python scripts, "none referenced by CI" | 15 Python scripts; all are reachable via dogfood scripts + a self-test covenant; the CI gap is the contract test, not the scripts | Disposition flips from "delete most" → "promote a CI job + relocate" |
| `swarm-engine` is "vestigial 13,931 LOC, no consumers" | Has exactly 1 consumer (workbench), tightly wired in via 11 `pre*` build hooks; **6 of 7 subsystems unused**; 3 CRITICAL security findings open; stopped dev 2026-03-28 | Refines verdict from WIPE → KEEP-INTERNAL with subsystem-level subtraction |
| `infra/vendor/` is curated forks | It's a 1.0 GB `cargo vendor` mirror for offline CI; only 2 of 841 crates have local mods | Different cleanup story entirely |
| Plugin docs vs "1 partial implementation" | TS plugin runtime exists at scale (iframe sandbox, ~23k LOC, 47 test files). Real problem is two non-interoperating worlds (TS vs Rust/WASM), only one documented | Docs problem more than implementation problem |

---

## Cross-cutting Wave-3 themes

### 1. "Vibe-coded 884-line claim" syndrome — file-level greps overcount

Three of the most damning numbers in the master report (`884 fns`, `503 any`, `9836 lines of production code`) were inflated by counting tests + dead-code-guarded modules + transitive bins. The pattern: a single `grep -c '^fn '` in a god-file looks alarming but conceals that half the count lives in `#[cfg(test)]`. **Lesson: when an audit cites a count, the deep-dive should always split production vs test.**

### 2. Most of the rot is structural, not buggy

None of the deep dives surfaced unsafe code, race conditions, or security bypasses beyond what was already in the master. Every dive instead found **architectural debt**: god-file with extracted-but-not-decoupled handlers (B), trait that wants to exist but doesn't (C), single-file with 17 categories of constructors (C), 4× duplicate `[patch.crates-io]` block (J), single feature shipped through 17 roadmap docs (G), policy validation hardcoded to a closed enum (K policy.rs:2079).

This is **good news**: structural debt is mechanical to fix. There's no hidden landmine — just a lot of patient refactoring.

### 3. "Already half-done" pattern

Several refactors were started but never finished:
- **B**: `api_server.rs` handlers were extracted to `src/edr/handlers/*.rs` — but they reach back via `crate::api_server::*` glob import.
- **H**: `swarm-engine` provider already marks `agentRegistry`, `taskGraph`, `topology` as `@deprecated` — collapse was in progress, then dev stopped.
- **G**: Three planned crate splits never happened (`clawdstrike-spider-sense` got merged into `clawdstrike` instead).

Finishing what was started is faster than starting fresh.

### 4. CI gap is one specific thing

Across audits I, F, and J, the same root cause appears: **`scripts/ci-changed.sh` is the entry point for several real test surfaces but is never called from GitHub Actions.** It would unify:
- macOS provider dogfood contract test (I)
- The advisory-expiry checker (`tools/scripts/check-advisory-expiry.sh`) (F)
- Vendor-mod hash checks (J recommendation)

One workflow job calling `scripts/ci-changed.sh --on-pr` closes three independent gaps.

### 5. "Documentation lies about reality" repeats at every level

Every dive surfaced a doc that contradicts the code:
- Policy schema version (G + master)
- Vendored crates "NOT modified" claim (J)
- Plugin CLI commands documented vs actual (K)
- 5 of 13 plugin docs say `clawdstrike pkg sign`; the binary is `hush` (K)
- Roadmaps list shipped features as planned (G)
- Formal-verification claims (master)

The pattern: **docs are written aspirationally, never reconciled when the code lands.** Single highest-leverage fix in the whole audit: add `mise run docs:reconcile` that fails CI when README/CLAUDE.md/policy-schema.md/etc. claim a schema version, package name, CLI binary, or guard count that doesn't appear in the code.

---

## Wave 3 quick wins (additive to master report quick wins)

Things you could do in ≤30 min each that the deep-dives surfaced:

- [ ] **F**: Drop the 4× redundant `[patch.crates-io] async-nats` blocks (root + 3 Tauri apps). 5-line PR, no functional change.
- [ ] **F**: Add `"publishConfig": {"access": "public"}` to `@clawdstrike/swarm-engine` package.json (or per the H verdict, mark `"private": true` instead).
- [ ] **F**: Migrate PyPI auth from static `PYPI_TOKEN` to trusted publishing (`id-token: write` is already enabled).
- [ ] **J**: Move `infra/vendor/nono/` to a sibling `vendor/` location — it's first-party, not third-party.
- [ ] **J**: Verify and delete `infra/vendor/crossterm-0.28.1/` (a 0.29.0 lives next to it).
- [ ] **E**: Delete root `bun.lockb` OR `package-lock.json` (whichever isn't canonical). Add `packageManager` field to root `package.json` to lock the choice.
- [ ] **E**: Delete `apps/workbench/bun.lock` (CI uses npm).
- [ ] **E**: Delete `cursor-plugin/bun.lockb` and `clawdstrike-plugin/bun.lockb` (byte-identical copy-paste leftovers).
- [ ] **K**: Fix `clawdstrike pkg sign` → `hush pkg publish` in `docs/src/plugins/*.md`.
- [ ] **K**: Fix `npm create @clawdstrike/plugin` → `npm init @clawdstrike/plugin` (or use the actual package name).
- [ ] **G**: Move `.planning/ROADMAP.md` (Academy product roadmap) out of the engine repo entirely.
- [ ] **A**: Delete 5 confirmed-dead symbols from `edr/`: `EndpointFlightRecorderSnapshot`, `EndpointFlightRecorder::snapshot()`, `read_observations()`, `read_observation_window()`, `CausalGraphRecorder::causal_path()`.
- [ ] **B**: Add `RequireAuth` axum extractor — deletes 88 lines of boilerplate `require_auth(&headers, &state)?;` across 44 handlers.
- [ ] **D**: Fix `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts` event-bus typing — single fix kills 13 `any` hits.
- [ ] **H**: Mark `packages/swarm-engine/package.json` as `"private": true` until the H migration completes.

---

## Tiered Wave-3 action plan (additive to master)

### Tier W3-A — This week
1. **(E + F + J quick wins above)** — ~2 hours total.
2. **Promote `scripts/test-macos-provider-dogfood-contract.sh` to a CI job** (I) — 1 hour. Closes the real I/F/J gap simultaneously.
3. **Sprint 0 of the TS `any` plan** (D) — 1 day. Eliminates ~95 hits in workbench + adapter glue.
4. **Drop the `[patch.crates-io] async-nats` blocks** (J) — 30 minutes.
5. **Consolidate the `cargo audit --ignore` lists** into `.cargo/audit.toml` with `id/reason/expiry/owner` (F) — 2 hours. Eliminates the 27 unjustified ignores or schedules their removal.

### Tier W3-B — This sprint (~1 week)
1. **`swarm-engine` fold into `apps/workbench/src/features/swarm/engine/`** (H) — 3 days. Resolves 3 CRITICAL security findings + drops 6 unused subsystems.
2. **`edr/mod.rs` test relocation + 5 dead-symbol deletion** (A) — 1 day. Drops file from 9,836 → ~2,100 lines.
3. **Roadmap consolidation: archive 9, delete 4, keep 3** (G) — 1 day. Run as a single PR.
4. **Sprint 1 of the TS `any` plan**: WASM + HTTP-client typing (D) — 3 days. Eliminates ~80 hits.

### Tier W3-C — This month
1. **`api_server.rs` 5-8 commit split** (B) — 1-2 weeks. Introduces `RequireAuth`, typed error enums, file-per-route-group.
2. **`edr/receipt/` family extraction** (C) — 3 days. 7 commits.
3. **`release.yml` "actually releasable v0.3.0" cut** (F) — 1 week. Fix `clawdstrike` dry-run, drop `hushspec`/`nono` blockers, add 9 more crates to publish list.
4. **Plugin docs trim (Option B)** (K) — 3-5 days. Removes the cliff plugin authors fall off.
5. **TS `any` Sprints 2 + 3**: zod migration of policy validators + Vercel-AI types (D) — 7 days. Final ~155 hits.

---

## Things Wave 3 didn't audit (consider for a Wave 4 if appetite remains)

- The TS plugin iframe sandbox (`apps/workbench/src/lib/plugins/`) — 23k LOC, 47 test files; surfaced as substantial but uncharted.
- The 442-line `validate()` god-method in `edr/receipt/mod.rs` (Wave 3C noted it but didn't audit each branch).
- The 162 `Router::new()` rebuilds in `api_server.rs` test mod (Wave 3B surfaced but didn't propose the consolidation).
- The 4 macOS system-extension Swift packages (Wave 1 audit 07 covered shape; line-level deep-dive on `Monitor.swift` AUTH_OPEN paths still open).
- The `clawdstrike-guard-sdk` Rust API surface — does it match what plugin examples use?

---

## Reading order

If you read only one wave-3 deliverable: **B** (`api_server.rs` route inventory) — it has the most surprising structural insight (the split is already half-done) and the clearest path to action.

If you read two: add **G** (roadmap reconciliation) — the easiest big visible win, and the only way to fix the docs-lie-about-reality theme at the source.

If you read three: add **H** (swarm-engine) — the verdict matters because the wrong call here ripples into apps/workbench cleanup, the release matrix (F), and the master report's Tier B plan.
