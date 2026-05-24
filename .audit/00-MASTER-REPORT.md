# Clawdstrike Cleanup — Master Report

**Date:** 2026-05-23
**Branch:** `fix/macos-es-ne-hardening`
**Synthesizes:** 9 area audits in `.audit/01–09-*.md`
**Tone:** Tough love, as requested.

---

## TL;DR

**As a senior engineer, would I be embarrassed to share this repo today? Yes, in specific places. No, in others.** The bones are stronger than the surface suggests: `hush-core` (RFC 8785 canonical JSON with a hand-written float canonicalizer, proptest, clean `thiserror`), `clawdstrike-brokerd` (constant-time auth, structured `ApiError`, 17-line `main.rs`), the bridge family (`tetragon`/`hubble`/`auditd`/`k8s-audit`/`darwin-telemetry` sharing a real `bridge_runtime` crate), `apps/academy` (Next.js, restrained, on-brand), `apps/control-console` design language ("Forged Gold on Black Glass"), the macOS Swift `Monitor.swift` AUTH_OPEN handling, the `clawdstrike-brokerd` admin-token constant-time path, the workbench's backend-held capability-grant model, `formal/lean4/.../Spec/Properties.lean` (707 lines, fully proved P1–P5), the `formal-diff-tests` proptest harness, and the `docs/plans/decisions/0001..0008` ADRs are all elite work. Meta files (`LICENSE`, `NOTICE`, `SECURITY.md`, `GOVERNANCE.md`, `THREAT_MODEL.md`, `NON_GOALS.md`, `deny.toml`) are unusually mature for an OSS project at 0.2.x.

**The worst rot, in order, is:** (1) `apps/workbench` is two products glued together — a detection IDE plus a 3D "Spirit/Observatory/Nexus" gamification layer with character avatars, ghost-memory systems, GLSL star-nest shaders, and a 4,868-line `ObservatoryWorldCanvas.tsx`. The workbench's own `MOTION_PLAN.md` literally says "Delight = precision engineering, NOT playfulness" — and the codebase contradicts it. (2) `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` is **9,836 lines** with `#![allow(dead_code, unused_imports)]` at the top and `pub use causal::*; pub use deception::*; ...` re-exports; `edr/receipt/mod.rs` is **6,402 lines**; `apps/agent/src-tauri/src/api_server.rs` is **48,118 lines** in one file (884 functions, ~19k production + ~29k inline tests). (3) `hushd` ships with **auth disabled by default** (`AuthConfig.enabled` defaults to `false`), `control-api` defaults to `0.0.0.0:8080` with `CorsLayer::permissive()`, `clawdstrike-registry` permits an empty API key, and `clawdstrike-brokerd` skips admin auth when the token is `None`. (4) Documentation lies about formal verification — public docs claim P1–P13 "proved by Lean's kernel" while 4 `sorry` admissions sit inside the Aeneas-generated `Impl/Merkle/Funs.lean` serde bodies and 13 hand-written iterator axioms underlie the bridge proofs. (5) `eas-anchor` is a service whose entire purpose returns `Err("Chain submission not yet implemented")`. (6) `apps/agent`, `apps/desktop`, `apps/workbench` all ship the **byte-identical default Tauri "T" icon** (MD5 `9418b9b0e421e3ff0744aef7960f511c`). (7) Across the repo, schema versions drift across `1.0.0` / `1.1.0` / `1.2.0` / `1.3.0` / `1.4.0` / `1.5.0` — six README/CLAUDE/CONTRIBUTING/policy-schema.md files give different answers and nine example policies will not load against the current engine.

**5 things to do TODAY that would lift perceived professionalism the most:**

1. **Delete the cruft from the working tree.** `.env`, `.DS_Store` (≥6 instances), `.tmp-release-venv/`, `.playwright-cli/`, `tmp/`, `output/`, `coverage/`, `.worktrees/`, `apps/cloud-dashboard/dist/`, `docs/book/`, `apps/agent/src-tauri/resources/control-console/assets/*.js` (committed Vite bundles), `apps/academy/src/app/test-mdx/`. **One commit, instant trust upgrade.**
2. **Rewrite `README.md` from scratch.** Kill the 5-line poem (`"The claw strikes back. / At the boundary..."`), kill the broken `divider.png` reference, pick one tagline (the third one is the only one a procurement reviewer can use), target ≤300 lines. The current 1,126-line README opens with a poem and three competing taglines, and the actual one-line definition of the project appears at line 84.
3. **Flip the four security defaults.** `hushd::AuthConfig::enabled = true` by default; `control-api` listens on `127.0.0.1:8080` with an explicit CORS allowlist; `clawdstrike-registry` refuses empty API key unless `allow_insecure_no_auth = true`; `clawdstrike-brokerd` requires admin token unless explicitly opted out. Four small commits. A fail-closed security product cannot ship insecure-by-default daemons.
4. **Replace the three identical Tauri-default "T" icons.** One real brand mark per shipping app. Immediate visual credibility boost; the duplicate stock icons are the single most "vibe-coded" tell in the entire repo.
5. **Pick one package manager.** Delete every other lockfile family. Root has both `bun.lockb` and `package-lock.json`; workbench has both `bun.lock` and `package-lock.json` (320 KB); 14 per-package `package-lock.json` files exist under `packages/adapters/*` despite the root declaring npm workspaces. One decision, one delete pass. The "two lockfiles" pattern is in every audit.

**Aggregate verdict per area:** Top-Level Meta = polish, not rewrite. CI/CD = "two days of focused work and this is a portfolio piece" (auditor's words). Rust Core Libs = beautiful nucleus, cancerous edges (split the giants, delete the WASM commits). Rust Services/Bridges = bridges are 8/10, hushd/control-api are 5/10, `eas-anchor` is 1/10 (a stub). TS Packages = wipe convenience packages (`clawdstrike` re-export, half-built `swarm-engine`), kill `any` usage, fix the fail-open receipt verifier. Frontend Apps = `academy` ships, `control-console` is defensibly opinionated, `workbench` needs an existential product decision, `desktop` and `cloud-dashboard` are subtraction wins. Tauri = collapse to 2 apps max, fix signing/notarization, extract `api_server.rs` to a library. Docs = mdBook is good, planning surface is a disaster, formal-verification claims are overstated. Tests/Rulesets = strong primitives (formal-diff-tests, policy-torture), broken compliance fixtures, rulesets don't use `extends`.

---

## Aggregate Scorecard

Scores rolled up from each report. Scale: 1–10. Bold = headline number when the report gave one; otherwise an average of the dimensions.

| Area | Professionalism / 1st Impression | Code Quality | Architecture | Docs | Tests | Notes |
|---|---|---|---|---|---|---|
| 01 Top-Level Meta | **5** | 5 (config hygiene) | n/a | 3 (doc consistency) | n/a | Strong meta files (`LICENSE`, `SECURITY.md`, `deny.toml`); fatal README; 4 schema versions across 4 docs |
| 02 CI/CD & Infra | **5** (CI quality) | 6 (build hygiene) | 6 (IaC) | n/a | n/a | OIDC done right; `ci.yml` is 1497L w/ no concurrency; `docker.yml` is 9 copy-paste jobs |
| 03 Rust Core Libs | n/a | 6 (idiomatic) / 5 (API) / 5 (errors) | 4 | 5 | 7 | `hush-core` 9/10; `clawdstrike-policy-event` 1/10; 9,836-line single file |
| 04 Rust Services/Bridges | n/a | 6 (service quality) | 6 (API design) | n/a | 6 | Brokerd + bridges 8/10; hushd 5/10; `eas-anchor` 1/10; **security defaults 3/10** |
| 05 TS Packages | n/a | 4 (type safety) / 6 (API) | 5 (consistency) | 5 (npm-readiness) | 6 | 503 `any` + 189 `as any`; fail-open receipt verifier; 14 lockfiles in workspace |
| 06 Frontend Apps | **6** (visual) | 5 (components) | 4 (state) / 3 (consistency) | n/a | 6 | `academy` ships; `workbench` is two products; `desktop` is vestigial |
| 07 Tauri Desktop | n/a | **3** (Tauri config) / 6 (native) / 5 (IPC) | 2 (build/sign/notarize) | n/a | 5 | 48k-line `api_server.rs`; 4 Tauri apps; default-T icons; empty `capabilities.json` |
| 08 Docs/Formal/Examples | n/a | n/a | 5 (structure) | 6 (accuracy) / 8 (onboarding) | n/a | mdBook builds; formal-verification rigor 6/10 (overclaim); planning hygiene **2/10** |
| 09 Tests/Rulesets/Misc | n/a | 7 (test discipline) / 6 (depth) | 4 (rulesets) | n/a | 6 (CI integration) | `formal-diff-tests` exemplary; compliance fixtures broken; 6/13 guards missing from default |

**Glaring outliers:**
- **Security defaults: 3/10** (audit 04) — for a "fail-closed" security product, this is the most damning single number in the entire scorecard.
- **Planning doc hygiene: 2/10** (audit 08) — 18 `docs/plans/<topic>/` directories, 7 fictional agent-framework specs, 8+ overlapping roadmaps.
- **Tauri config: 3/10** (audit 07) — empty `capabilities.json`, null signing identity, default icons.
- **TS type safety: 4/10** (audit 05) — `strict: true` everywhere is cosmetic with 503 `any` sites.

---

## Cross-Cutting Themes

Five themes appear in 3+ reports. Each is a real pattern, with receipts.

### 1. Schema version drift (1.0 / 1.1 / 1.2 / 1.3 / 1.4 / 1.5)

**Appears in:** 01 (Top-Level Meta), 08 (Docs), 09 (Tests/Rulesets), plus alluded to in 05.

**Receipts:**
- `crates/libs/clawdstrike/src/policy.rs:29` says `POLICY_SCHEMA_VERSION = "1.5.0"`.
- `CLAUDE.md:81` says v1.5.0 backward-compat with v1.1.0.
- `CONTRIBUTING.md:128` says schema v1.1.0.
- `README.md:628` quick-start YAML uses `version: "1.3.0"`.
- `README.md:701` says "Explicit 1.1.0 / 1.2.0 policy versions".
- `docs/src/reference/policy-schema.md:13-20` lists 1.1.0–1.4.0 (omits 1.5.0).
- `docs/src/concepts/policies.md:10` uses `1.2.0`.
- Nine `examples/**/policy.yaml` files use `version: "1.0.0"` (unsupported by the engine), plus two use the legacy `clawdstrike-v1.0` string.
- `examples/hybrid-swarm/*.yaml` and `examples/red-blue-swarm/policy.yaml` use a `schema_version:` key that does not exist (field is `version:`); these will fail `deny_unknown_fields`.

**Why it matters:** The single most important versioned interface in the product has at least four different "current" answers across canonical docs, and headline example policies will not load. A user's first attempt at a Spider-Sense policy gets rejected and they conclude the README is hallucinated. (It is.)

**Highest-leverage fix:** Pick one (1.5.0). Update README × 2 + CLAUDE.md + CONTRIBUTING.md + `policy-schema.md` + every `examples/**/policy.yaml`. Add `scripts/validate-example-policies.sh` to CI that runs `hush policy verify` on every example YAML. Add a grep-check that fails if any root-level `.md` mentions a schema version that doesn't appear in `policy.rs`.

### 2. God files (single source files in the 2k–48k LOC range)

**Appears in:** 03, 04, 05, 06, 07 (every code-bearing area).

**Receipts:**
- `apps/agent/src-tauri/src/api_server.rs` — **48,118 lines, 884 functions** (one file).
- `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` — **9,836 lines**, `#![allow(dead_code, unused_imports)]` at the top.
- `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs` — **6,402 lines**.
- `crates/services/control-api/src/integration_tests.rs` — **11,377 lines** (in `src/`, not `tests/`).
- `crates/services/control-api/src/routes/policies.rs` — **3,153 lines**.
- `crates/services/hush-cli/src/main.rs` — **3,238 lines** (god-binary).
- `crates/services/clawdstrike-brokerd` — wait, that one is clean (17 lines). It's the model.
- `crates/libs/clawdstrike-logos/src/verifier.rs` — **3,875 lines**.
- `crates/libs/clawdstrike/src/policy.rs` — **4,156 lines** (2,380 prod + 1,700 tests).
- `crates/libs/clawdstrike/src/engine.rs` — **4,599 lines** (1,796 prod + 2,800 tests).
- `crates/libs/bridge-runtime/src/lib.rs` — **911 lines** in one `lib.rs`.
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — **4,868 lines** (single React component).
- `apps/workbench/src/features/spirit/components/spirit-ritual/canvas/model.ts` — 1,449 lines.
- `apps/desktop/src/shell/dock/SessionRail.tsx` — 1,544 lines.
- `apps/control-console/src/pages/ExecutionProof.tsx` — 1,434 lines.
- `apps/workbench/src/components/workbench/sentinel-swarm-pages.tsx` — 939 lines (six pages in one file, defeats lazy code-splitting).
- `packages/sdk/hush-ts/src/clawdstrike.ts` — 2,027 lines.
- `packages/sdk/hush-ts/src/guards/spider-sense.ts` — 2,365 lines.
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts` — 1,190 lines (~30 `as any`).

**Why it matters:** `rust-analyzer` chokes; PR review is impossible; merge conflicts are guaranteed; tests live in the same file as production code (so the file is 60% tests by line count); `#![allow(dead_code)]` permanently hides growth.

**Highest-leverage fix:** Adopt a soft cap (~800 lines per file, ~300 per React component) and a CI guardrail (`scripts/check-file-size.sh`). Split the worst offenders in priority order: `api_server.rs` (extract to `crates/services/agent-api/`), `edr/mod.rs` + `edr/receipt/mod.rs` (one file per family with a `ReceiptFamily` trait), `clawdstrike.ts` + `spider-sense.ts` (sub-modules), `ObservatoryWorldCanvas.tsx` (probably delete entirely — see theme 4), `control-api/integration_tests.rs` (move to `tests/integration/`).

### 3. AI-slop bloat (overclaimed features, fictional plans, vibe-coded experiments)

**Appears in:** 01, 03, 04, 05, 06, 08 (six of nine reports).

**Receipts:**
- **Overclaimed:** `logos-ffi` crate description says "FFI bindings to Logos (LEAN 4) proof system" — actual impl is `// TODO: Call LEAN 4 runtime via FFI` returning `Ok(ProofResult::Unknown { reason: "LEAN FFI not yet implemented" })`. The `lean-runtime` feature flips a boolean and does nothing else (`crates/libs/logos-ffi/src/lib.rs:99-131`).
- **Overclaimed:** `logos-z3::check_explanatory` and `check_epistemic` both return `Ok(Unknown { reason: "not yet implemented" })` — two of three claimed verification layers are stubs that look like passing results (`crates/libs/logos-z3/src/lib.rs:231-243`).
- **Overclaimed:** `docs/src/formal-verification.md:62, 115-135` enumerates P1–P13 as proved; reality is 7+ `sorry` admissions (load-bearing) and 145 axioms including 4 `sorry`s in Aeneas-generated Merkle serde bodies and 13 hand-written `IteratorAxioms.lean`.
- **Stubs:** `eas-anchor::submit_batch` and `revoke_attestation` both end with `Err(Error::Client("Chain submission not yet implemented"))` — the entire service is a stub (`crates/services/eas-anchor/src/eas_client.rs:104-147`).
- **Stubs:** `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts:99-107` — `verify(receipt)` returns `true` for unsigned receipts (fail-open in a fail-closed product).
- **Stubs:** `WasmPolicyLab` (`crates/libs/hush-wasm/src/policy_lab.rs:22-37`) holds an `inner` field marked `#[allow(dead_code)]`. The constructor parses YAML and stores a handle. No method uses `self.inner`.
- **Fictional plans:** `docs/plans/agent-frameworks/{autogpt,crewai,langchain,vercel-ai,generic-adapter,comparison,overview}.md` — 7 multi-thousand-line "integration plans" for adapters where most don't exist in `packages/adapters/`. AutoGPT and CrewAI adapters do not exist.
- **Fictional plans:** `docs/plans/sentinel-swarm/` — 10 files, **6,800 lines**, no corresponding shipping product.
- **Fictional plans:** `docs/plans/swarm-engine/ARCHITECTURE.md:35` hardcodes the author's local filesystem path `/Users/connor/Medica/backbay/standalone/clawdstrike-swarm-engine/...` in committed docs.
- **Fictional plans:** `docs/plans/pact/PROTOCOL.md` is a "Pre-RFC" for a brand-new protocol that "replaces" MCP.
- **Vibe-coded:** `apps/workbench/src/features/{observatory,spirit,nexus,hunt}/` — a 3D space-station with character avatar (`OBSERVATORY_ASTRONAUT_OPERATOR_*`), GLTF model loading, weather system, ghost memory (`observatory-ghost-memory.ts`), NPC crew, "Spirit Ritual Manifestation Canvas", GLSL star-nest shader. Dependencies: `wawa-vfx`, `@react-three/rapier`, `ecctrl`, `r3f-forcegraph`, `postprocessing`, `leva`. In a detection IDE.
- **Vibe-coded:** Workbench's own `MOTION_PLAN.md` says "Delight = precision engineering, NOT playfulness." The Spirit/Observatory layer is precisely the playfulness the doc forbids.
- **Aspirational docs:** `docs/src/package-manager/` (6 chapters) and `docs/src/plugins/` (9 + 6 chapters) document features the CLI does not ship. Users will run `clawdstrike pkg install foo` and see "unknown command."
- **AI-prompt artifacts in canonical plans:** `docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md`, `docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md`, `docs/plans/multi-agent/codex-swarm-playbook.md`.
- **Marketing copy in roadmap:** `docs/src/roadmap.md:472-476` ("Guard Bounty Program", "Clawdstrike Champions", "Security Research Grants", "Attack Range", "Quarterly Security Report").
- **Three taglines, none of which says what it is** — `README.md:18-22, 38-39, 84`.
- **Fictional community programs:** Same `roadmap.md` block above.

**Why it matters:** This is the single biggest professionalism tell. An OSS evaluator who finds one stub-pretending-to-be-a-service or one fictional plan dir or one ghost-memory system in a detection IDE concludes the whole project is theater. Three of these in the first browse and they're gone.

**Highest-leverage fix:** Adopt a "ship or delete" rule. (a) Every CRITICAL-tier stub becomes either a real implementation, an explicit `Err(NotImplemented)`, or a deletion. (b) Move `apps/workbench/src/features/{spirit,observatory,nexus,hunt}/` to `apps/labs/` or delete it. (c) Wipe `docs/plans/agent-frameworks/`, `docs/nono-integration/`, `docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md` (R1), `docs/plans/sentinel-swarm/` (or demote to `docs/research/`). (d) Promote `docs/plans/pact/PROTOCOL.md` to `docs/src/rfcs/0002-*.md` or demote to `docs/research/`. (e) Delete all `*-handoff-prompt.md` and `codex-*-playbook.md` from canonical plans.

### 4. Insecure-by-default deployment configs

**Appears in:** 02, 04, 07.

**Receipts:**
- `crates/services/hushd/src/config.rs:97-107` — `AuthConfig { #[serde(default)] pub enabled: bool, .. }`. A config that omits the `auth` block boots hushd with all API key middleware bypassed.
- `crates/services/clawdstrike-brokerd/src/api.rs:193-210` — `require_admin_auth` returns `Ok` immediately when `state.config.admin_token` is `None`.
- `crates/services/control-api/src/config.rs:58-61` — `LISTEN_ADDR` default `"0.0.0.0:8080"`.
- `crates/services/control-api/src/main.rs:310` — `app.layer(CorsLayer::permissive())` unconditionally.
- `crates/services/clawdstrike-registry/src/config.rs:26, 41-42` — `host` defaults to `"0.0.0.0"`; `api_key` defaults to empty; loader does not enforce that empty key is rejected unless `allow_insecure_no_auth = true`.
- All five bridges: `--admin-listen-addr` defaults to `0.0.0.0:2112` with no auth on `/metrics` (which often leaks pod/namespace cardinality).
- All five bridges: outbox SQLite default path `/tmp/<bridge>-outbox.db` (`tmpfs` on Linux, wiped at reboot — defeats durability).
- `crates/services/hushd/src/certification_webhooks.rs:68-105` — webhook delivery is `tokio::spawn` fire-and-forget with no persistent outbox; SIGTERM drops every in-flight notification.
- `infra/docker/docker-compose.services.yaml:76-80, 113, 133-135` — `JWT_SECRET: ${... :-dev-jwt-secret-local}`, `STRIPE_SECRET_KEY: ${... :-sk_test_local}`, etc. (clearly labeled dev defaults, but the smell is shipped in the compose file).
- `apps/agent/src-tauri/macos/system-extension/.../main.swift:118` — fallback URL `http://127.0.0.1:9878` (plain HTTP loopback default in a system extension).
- Per-service `OperatorState` is **in-memory only** in `clawdstrike-brokerd` (capabilities, executions, revocations, freeze flag all lost on restart). Same in `hushd::InMemoryRevocationStore`.

**Why it matters:** A "fail-closed policy engine" that boots with auth disabled, permissive CORS, world-bind defaults, no persistence on its capability ledger, and fire-and-forget webhooks is the exact opposite of fail-closed. A senior security reviewer will catch this in 90 seconds.

**Highest-leverage fix:** Flip every default to secure. `hushd::AuthConfig.enabled = true` + refuse to start if `api_keys` empty AND no IdP. `clawdstrike-brokerd` admin token mandatory unless explicit env var disable. `control-api` bind `127.0.0.1` + explicit CORS allowlist. `clawdstrike-registry` refuse empty key unless `allow_insecure_no_auth = true`. Bridges admin to `127.0.0.1`. Bridge outboxes to `$XDG_STATE_HOME` or `/var/lib/`. Webhook delivery via `SqliteOutbox`. Brokerd `OperatorState` persisted to sqlite or NATS JetStream subject.

### 5. Multiple competing build/package tools without resolution

**Appears in:** 01, 02, 05, 06, 09.

**Receipts:**
- Root tracks both `bun.lockb` (439 KB) and `package-lock.json` (610 KB). `package.json` declares no `packageManager` field.
- `mise.toml` uses `npm` for `control-console` (line 54-57) and `bun` for `desktop` (line 57-60).
- `AGENTS.md:25` says "no root JS workspace" while `package.json:7-31` declares a 26-entry `workspaces:` array.
- `apps/workbench` has **both** `bun.lock` (104 KB) and `package-lock.json` (320 KB).
- 14 per-package `package-lock.json` files across `packages/adapters/*` despite root using npm workspaces.
- `packages/sdk/hush-py/pyproject.toml` (hatchling) AND `packages/sdk/hush-py/hush-native/pyproject.toml` (maturin) **both** declare `name = "clawdstrike"`, `version = "0.2.7"` — two competing build backends for one wheel.
- `pyproject.toml:48` declares `packages = ["src/clawdstrike", "src/hush"]` — `src/hush/` does not exist.
- `packages/sdk/hush-ts` builds with `tsup` + `bundler` module resolution; every other TS package builds with `tsc` + `NodeNext`.
- `Cargo.toml:188-189` patches `async-nats` via `[patch.crates-io] async-nats = { path = "infra/vendor/async-nats" }` — same patch declared again in `apps/agent/src-tauri/Cargo.toml:85-86`, `apps/desktop/src-tauri/Cargo.toml:65-66`, and `apps/workbench/src-tauri/Cargo.toml:52-53`. No comment in any of them.
- Two competing TS UI primitive systems for one product family (`control-console/ui` bespoke; `workbench/ui` Base UI + cva; `academy/ui` Radix; `desktop/ui` `@backbay/glia`).
- `apps/desktop/package.json:2` is named `"sdr-desktop"` (a previous product).
- `tools/scripts/` (5 files) and `scripts/` (61 files) both contain CI helpers with overlapping responsibilities.
- `vendor/hushspec/` is both vendored AND `version = "0.1.1"` declared (`crates/libs/clawdstrike/Cargo.toml:33`).
- `fixtures/hushspec/rulesets/` duplicates `vendor/hushspec/rulesets/` with diffs.

**Why it matters:** Every "two tools for one job" pair is a future bug. CI cache splits. Local dev picks whichever the dev's muscle memory picks. New contributors don't know which to use. Each instance is small; cumulatively this is the loudest "no one owns the toolchain" signal.

**Highest-leverage fix:** Make four decisions. (a) Bun OR npm — delete the other lockfile family everywhere. Add `"packageManager"` to root `package.json`. Delete all 14 per-package lockfiles. (b) Maturin OR hatchling for `hush-py` — delete the other. (c) `tsc + NodeNext` OR `tsup + bundler` for TS — pick one and migrate. (d) Vendored `async-nats` — document the patch reason and link upstream, or remove and use crates.io. Apply same rule to `vendor/hushspec/`.

### 6. Vendor / cruft / artifacts leaking through the working tree

**Appears in:** 01, 06, 07, 08, 09.

**Receipts:**
- Root: `.env` (199 bytes, untracked but present in working copy — in a project literally about secret hygiene); `.DS_Store`; `.tmp-release-venv/`; `.playwright-cli/`; `tmp/imagegen-venv`; `output/playwright`; `coverage/`; `.worktrees/pr180-clone/`; `.worktrees/pr180-followup/`.
- `apps/cloud-dashboard/dist/` and `apps/cloud-dashboard/tsconfig.tsbuildinfo` — `git ls-files apps/cloud-dashboard/` returns nothing; the source was deleted, the artifacts remain.
- `apps/control-console/test-results/` — Playwright output in working tree.
- `apps/desktop/dist/sdr-require-shim.js` and 40+ pre-built Vite bundles committed under `apps/agent/src-tauri/resources/control-console/assets/*.js`.
- `apps/agent/src-tauri/resources/cloud-dashboard/assets/index-8-O9U-nN.js` — a checked-in bundle for an app whose source was deleted.
- Workbench `dist/`, desktop `dist/` checked in via `build.rs` writing into source tree.
- `crates/libs/hush-wasm/hush_wasm.js`, `hush_wasm.d.ts`, `hush_wasm_bg.wasm.d.ts`, `hush_wasm.d.ts.template`, `package.json` — generated WASM/JS artifacts committed.
- `packages/sdk/hush-py/dist/clawdstrike-0.1.0*.whl` and `0.2.4*` — stale wheels (current is 0.2.7).
- `docs/book/` — 30+ HTML/CSS/JS files generated by `mdbook build`, committed.
- `.DS_Store` files at `apps/agent/.DS_Store`, `apps/agent/src-tauri/.DS_Store`, `apps/agent/src-tauri/src/.DS_Store`, `apps/desktop/.DS_Store`, etc.
- `.gitignore` lists `.planning/` four separate times (lines 45, 76, 77, 112).
- Despite `.gitignore` claiming to ignore `.planning/`, `git ls-files .planning/` returns `PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`.

**Why it matters:** Cruft on a security-tool root says "the maintainer's machine ≈ the repo." `.env` in a project about secret hygiene — even untracked — is a brutally bad look. Committed build artifacts destroy git blame and produce noisy commits.

**Highest-leverage fix:** One `git rm -r --cached` pass for every committed build artifact + `mise run clean` task that nukes the rest + bring `.gitignore` into shape (dedupe `.planning/`, add `.DS_Store`, add `docs/book/`, add `apps/*/dist/`, add `apps/agent/src-tauri/resources/{control-console,cloud-dashboard}/`).

### 7. Misleading metadata, branding, and "looks abandoned" signals

**Appears in:** 01, 06, 07, 08.

**Receipts:**
- Three Tauri apps (`agent`, `desktop`, `workbench`) ship the byte-identical default Tauri "T" PNG icon (MD5 `9418b9b0e421e3ff0744aef7960f511c`).
- `apps/desktop/package.json:2` named `"sdr-desktop"` — a prior product name.
- `apps/desktop` tauri title is `"Huntronomer"`, package is `sdr-desktop`, description references "autonomous threat hunting swarms" — three names for one app.
- `CHANGELOG.md` jumps from 0.2.6 → 0.1.2 with no 0.1.3/0.2.0/0.2.1/0.2.2/0.2.3/0.2.4/0.2.5 entries; `[Unreleased]` says "No unreleased changes yet" despite two months of commits.
- `GOVERNANCE.md` Maintainer Council table has 5 rows, all `(TBD)`.
- `CODEOWNERS` is `* @connor` with a comment "Replace @connor with org teams as they are formalized" — written months ago, never replaced.
- Three different Discord invite URLs across `README.md:11`, `CONTRIBUTING.md:6`, `GOVERNANCE.md:99`.
- `README.md:27` references `.github/assets/divider.png` — file does not exist; renders as broken-image icon on GitHub.
- `CONTRIBUTING.md:6` has a smart-quote AND a stray backtick in the second sentence of the file.
- `docs/HANDOFF.md` (241 lines) is a Feb-7 handoff still living in `docs/` root.
- `apps/academy/src/app/test-mdx/page.mdx` — a route literally named `test-mdx` at production URL.
- `apps/control-console/src/state/lightTheme.ts` — light theme applied via JS at runtime (FOUC vector).
- Workbench `App.tsx:294` comment says HashRouter is required for Tauri's `file://` — outdated, Tauri 2 supports custom protocols.
- `apps/workbench/src-tauri/tauri.conf.json:2` `$schema` URL points to `nicegui-org/nicegui` (wrong project).
- `docs/specs/19-origin-sdk-parity-api-contract.md` and `docs/specs/19-secret-broker-egress-tier.md` — two specs numbered 19.

**Why it matters:** Cumulative "this looks unmaintained" signal. Any one of these is a "first 30 seconds" tell. Three together convince an OSS evaluator the project is a hobby.

**Highest-leverage fix:** A "polish PR" that touches only the 30-second tells: real Tauri icons, real branding for desktop (or delete), one Discord URL, fix README image + opener, fix the smart-quote-and-backtick, delete `docs/HANDOFF.md`, delete `test-mdx`, fix the schema URL, renumber the duplicate spec, fix the workbench Tauri schema URL.

### 8. Overclaimed formal verification

**Appears in:** 03 (the Logos/Z3 entries), 08 (the public docs).

**Receipts:**
- Public `docs/src/formal-verification.md:62, 115-135` enumerates P1–P13 as proved.
- `formal/lean4/.../Proofs/MergeMonotonicity.lean:122` has `sorry`.
- `formal/lean4/.../Impl/Merkle/Funs.lean:589, 632, 768, 895` have **four `sorry`s** inside serde serializer bodies. File header says "Aeneas-generated, do not edit."
- 145 axiom declarations across the Lean project (35 in `Impl/FunsExternal.lean`, 13 in `IteratorAxioms.lean`, 10 in `Spec/MerkleProperties.lean`, 9 in `Core/Crypto.lean`, etc.).
- `formal/tlaplus/PostureStateMachine.tla` is orphan — never referenced in docs, not in CI.
- `logos-ffi` advertises "LEAN 4 FFI" and has zero `extern "C"` blocks.
- `logos-z3::check_explanatory` and `check_epistemic` stubbed.
- `INDEX.md` table claims "P4 partial, P7 partial" — a power user has to grep `sorry` to see this.

**Why it matters:** Formal verification is the project's strongest differentiator. A single academic-verification person walking through the `sorry`s on Twitter ends the credibility of the entire project. The Aeneas-generated file with hidden hand-injected `sorry`s is the worst configuration possible.

**Highest-leverage fix:** Rewrite `docs/src/formal-verification.md` with a "Limitations" section listing every `sorry`, every axiom class. Add `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md`. Either complete the Aeneas Merkle serde translation by hand (and document the divergence) or scope P7 to exclude the serde path. Either implement or delete `logos-ffi`. Promote `cargo test -p formal-diff-tests` (1M proptest cases vs spec) as the empirical complement so the absence of full proof doesn't read as absence of evidence.

### 9. Documentation drift between docs/, READMEs, code, and CHANGELOG

**Appears in:** 01, 03, 04, 07, 08, 09.

**Receipts (beyond the schema-version theme):**
- Guard count: README table says 10; CLAUDE.md says 13; CHANGELOG says "from 7 to 12 with CUA Gateway guards." Three docs, three numbers.
- CONTRIBUTING says `cd apps/desktop && npm install && npm run tauri dev`. Reality is `bun install --frozen-lockfile` per `mise.toml`, AND the recommended app per README is `apps/agent` not `apps/desktop`.
- `README.md:280` ("see apps/agent/README.md") vs `CONTRIBUTING.md:77` (`cd apps/desktop`) — four "the official UI is X" stories.
- `apps/agent/README.md:19` says "macOS 10.15+" but `tauri.conf.json:35` says `"minimumSystemVersion": "13.0"`.
- `docs/src/roadmap.md:15-31` marks `hush-core`/`clawdstrike` as "Stable" but `docs/REPO_MAP.md:31-46` and `docs/HANDOFF.md:70-78` mark them as "alpha".
- 15 of 20 crates in `crates/libs/` have no `README.md`.
- 6 of 20 TS packages ship no README despite declaring `"files": ["dist", "README.md"]`.
- `crates/libs/README.md` is three lines.
- `crates/tests/README.md` is one line.
- 4 hard-coded `version = "0.1.1"` strings in TS adapters despite the package being at 0.2.7 (`adapter-core/src/framework-adapter.ts:27`, etc.).

**Why it matters:** Each contradiction erodes trust independently. A reader hits one, doubts the next. The CONTRIBUTING-vs-mise lockfile contradiction is particularly bad because it actively breaks the first-contributor experience.

**Highest-leverage fix:** Adopt a "code is source of truth" rule. Add grep-based CI checks: schema version, guard count, app name, MSRV, Node version. Backfill the missing CHANGELOG entries (0.1.3, 0.2.0–0.2.5). Reconcile alpha/stable labels (alpha is honest at 0.1.x — say so everywhere). Stop describing guards in CHANGELOG narratives; reference the canonical doc.

### 10. Test theater (constructor-only tests, silent-skip integration tests, fail-open mocks)

**Appears in:** 02 (proof-bundle scripts), 05 (TS), 06 (FE), 09 (Python).

**Receipts:**
- `packages/sdk/hush-py/tests/_recording_backend.py:16-25` — always returns `{"allowed": True}`. Routing tests built on it never exercise deny verdicts.
- `packages/sdk/hush-py/tests/test_typed_actions.py:16-47` and `test_native_engine.py:29-51` — `assert a.path == "/test"; assert engine is not None` — constructor sanity dressed as unit tests.
- `crates/tests/sdr-integration-tests/tests/k8s_audit_bridge_reliability.rs:313, 337, 384` — silent `eprintln!("skipping integration test"); return;` when Docker/NATS unavailable. CI sees green; nothing ran.
- `apps/workbench/src/__tests__/App.test.tsx:17-50` — `vi.mock(...)` every page component with `<div data-testid="page-X">X</div>`. Tests routing typos only.
- 27 `toBeDefined()`-only assertions in `swarm-engine` tests.
- `packages/cli/create-plugin/tests/scaffold.integration.test.ts:177-185` — the meaningful end-to-end assertions are commented out.
- `rulesets/tests/policy-torture/run.sh:119-141` — `cat > "${REPORTS_DIR}/05-...json" <<EOF` writes canned PASS JSON regardless of actual outcome.
- `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts:99-107` — `verify()` returns `true` for unsigned receipts.
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:475-516` — three `try/catch` blocks silently disable jailbreak, output-sanitization, and instruction-hierarchy enforcement on WASM failure with a `console.warn`.
- 18 Python "proof bundle" scripts in `scripts/` (~14k LOC: `endpoint-decision-engine-readiness-audit.py` 3,814 lines, etc.) — never referenced from CI workflows.

**Why it matters:** Coverage % is misleading. A "test" that's a fail-open mock or a silent skip is worse than no test — it produces false confidence. The fail-open verifier and the silent guard-disabling middleware are not just test theater; they're security holes.

**Highest-leverage fix:** Rewrite the WASM-failure path in Vercel-AI middleware to throw unless `allowDegradedSecurity: true`. Delete or rewrite `ReceiptSigner.verify`. Add a `RecordingBackend.with_verdict(decision)` API or split into `AllowingRecordingBackend` and `DenyingRecordingBackend`. Convert k8s integration silent-skip to `#[ignore]` + a dedicated CI job that brings up NATS. Decide the fate of the 18 proof-bundle scripts (move to `docs/evidence/` or delete).

---

## Critical-Immediate Items

Every CRITICAL finding from the 9 reports, deduplicated, with path + one-line description + source report.

1. **`apps/agent/src-tauri/src/api_server.rs` is 48,118 lines in one file.** Extract to `crates/services/agent-api/`. [07-tauri-desktop-apps.md]
2. **`crates/libs/clawdstrike-policy-event/src/edr/mod.rs` is 9,836 lines with `#![allow(dead_code, unused_imports)]`** and wildcard re-exports. [03-rust-core-libs.md]
3. **`crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs` is 6,402 lines** of receipt-builder boilerplate. [03-rust-core-libs.md]
4. **`crates/services/control-api/src/integration_tests.rs` is 11,377 lines** in `src/` (not `tests/`). [04-rust-services-bridges.md]
5. **`crates/services/hushd/src/config.rs:97-107` — `AuthConfig.enabled` defaults to `false`.** Vanilla config boots hushd with all API auth bypassed. [04-rust-services-bridges.md]
6. **`crates/services/control-api/src/config.rs:58-61, main.rs:310` — defaults `0.0.0.0:8080` + `CorsLayer::permissive()`.** [04-rust-services-bridges.md]
7. **`crates/services/clawdstrike-brokerd/src/operator.rs:16-28` — capability/execution/revocation state is in-memory only.** Restart silently loses the entire ledger. [04-rust-services-bridges.md]
8. **`crates/services/clawdstrike-registry/src/bin/audit-monitor.rs:114-281` — transparency-log monitor uses `eprintln!` everywhere, no signal handling.** [04-rust-services-bridges.md]
9. **`crates/services/eas-anchor/src/eas_client.rs:104-147` — entire service is a stub returning `Err("Chain submission not yet implemented")`.** [04-rust-services-bridges.md]
10. **`packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts:99-107` — `verify(receipt)` returns `true` for unsigned receipts.** [05-typescript-packages.md]
11. **`packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:468-516` — silently disables three security guards on WASM failure with `console.warn`.** [05-typescript-packages.md]
12. **`packages/sdk/hush-ts/src/client.ts:90-140` — every public method returns `Promise<any>`.** [05-typescript-packages.md]
13. **`apps/workbench/src/features/{observatory,spirit,nexus,hunt}/` — 3D gamification layer (~5,840 LOC in `observatory/world/` alone, 4,868-line `ObservatoryWorldCanvas.tsx`) in a SOC detection IDE.** Workbench's own `MOTION_PLAN.md` forbids this. [06-frontend-apps.md]
14. **`apps/desktop` package name is `sdr-desktop` (vestigial product), duplicates 70% of `control-console`.** [06-frontend-apps.md]
15. **`apps/cloud-dashboard/dist/` — build artifacts only, no source.** Looks like an abandoned app in `apps/`. [06-frontend-apps.md]
16. **`apps/desktop/src-tauri/gen/schemas/capabilities.json` and `apps/agent/src-tauri/gen/schemas/capabilities.json` are both literally `{}`.** Tauri v2 will reject IPC at release-build time. [07-tauri-desktop-apps.md]
17. **`apps/agent` has zero `#[tauri::command]`s.** Exposes 884 functions over local HTTP via the 48k-line `api_server.rs`. The "frontend" is `resources/index.html` saying "Tray-only app". [07-tauri-desktop-apps.md]
18. **`docs/src/formal-verification.md:62, 115-135` oversells proofs.** ≥7 `sorry`s in load-bearing files; public doc lists P1–P13 as proved. [08-docs-formal-examples.md]
19. **`formal/lean4/.../Impl/Merkle/Funs.lean:589, 632, 768, 895` — four `sorry`s in Aeneas-generated serde bodies** that downstream P7 inclusion proofs depend on. [08-docs-formal-examples.md]
20. **`docs/HANDOFF.md` (241 lines) is a Feb-7 single-author handoff still in `docs/` root.** Makes the repo look like one engineer's WIP snapshot. [08-docs-formal-examples.md]
21. **`crates/libs/hush-wasm/{hush_wasm.js, hush_wasm.d.ts, hush_wasm_bg.wasm.d.ts, hush_wasm.d.ts.template, package.json}` — generated WASM/JS artifacts committed to git.** [03-rust-core-libs.md]
22. **`.github/workflows/ci.yml` is 1,497 lines, 33 jobs, no concurrency cancellation, 4/33 timeouts, no path filters.** [02-ci-cd-infra.md]
23. **`.github/workflows/docker.yml` is 414 lines of 9 byte-identical jobs.** Should be one matrix or reusable workflow. [02-ci-cd-infra.md]
24. **`README.md:1-83` — 5-line italic poem opener, three competing taglines, broken image reference, 1,126 lines total.** Actual project definition appears at line 84. [01-top-level-meta.md]
25. **Three Tauri apps ship the byte-identical default Tauri "T" icon (MD5 `9418b9b0e421e3ff0744aef7960f511c`).** [07-tauri-desktop-apps.md]

---

## Tiered Action Plan

### Tier A — Today (a few hours, high-visibility quick wins)

1. **Nuke the cruft.** `git rm -r --cached` and delete from working tree: `.env`, `.DS_Store` (≥6 instances), `.tmp-release-venv/`, `.playwright-cli/`, `tmp/`, `output/`, `coverage/`, `.worktrees/`, `apps/cloud-dashboard/`, `docs/book/`, `apps/control-console/test-results/`, `packages/sdk/hush-py/dist/clawdstrike-0.1.0*` and `0.2.4*`. Extend `.gitignore`. Add `mise run clean` task. [01, 06, 07, 08, 09] — 15 minutes.
2. **Delete the broken `divider.png` reference** in `README.md:26-28` and fix the smart-quote-and-backtick in `CONTRIBUTING.md:6`. [01] — 2 minutes.
3. **Pick one package manager.** Delete every other lockfile family. Delete `bun.lockb` OR `package-lock.json` at root; delete the matching one in `apps/workbench`; delete all 14 per-package `package-lock.json` files in `packages/adapters/`. Add `packageManager` to root `package.json`. [01, 05, 06] — 10 minutes once decided.
4. **Replace three identical Tauri-default icons.** One real brand mark per shipping app. `cargo tauri icon path/to/icon.png` for each. [07] — 30 minutes.
5. **Reconcile schema version.** Pick 1.5.0. Update README × 2, CLAUDE.md, CONTRIBUTING.md, `docs/src/reference/policy-schema.md`, `docs/src/concepts/policies.md`. Bulk-replace `version: "1.0.0"` → `version: "1.5.0"` in every `examples/**/policy*.yaml`. Rename `schema_version:` → `version:` in `examples/hybrid-swarm/` and `examples/red-blue-swarm/`. [01, 08, 09] — 1 hour.
6. **Flip auth defaults to fail-closed.** `hushd::AuthConfig.enabled = true`; `control-api` bind `127.0.0.1:8080` + explicit CORS allowlist; `clawdstrike-registry` refuse empty key unless `allow_insecure_no_auth = true`; `clawdstrike-brokerd` require admin token unless explicit env-var disable. [04] — 1 hour for code + a few hours of test cascade.
7. **One Discord URL.** Pick the live invite. Update `README.md:11`, `CONTRIBUTING.md:6`, `GOVERNANCE.md:99`. CONTRIBUTING/GOVERNANCE should link to README. [01] — 5 minutes.
8. **Delete obvious AI-slop docs.** `rm docs/HANDOFF.md docs/auth.md docs/plans/implementation-pad.md docs/plans/clawdstrike/formal-verification/codex-handoff-prompt.md docs/plans/clawdstrike/secret-broker/executor-handoff-prompt.md`; `rm -rf docs/plans/agent-frameworks/ docs/nono-integration/`; `rm docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md`. [08] — 5 minutes.
9. **Delete prod demo route.** `rm -rf apps/academy/src/app/test-mdx/`. [06, 08] — 1 minute.
10. **Rename or delete `apps/desktop`.** If keeping, rename `package.json` from `sdr-desktop` to `@clawdstrike/desktop`. If deleting, do it now. [06, 07] — 1 minute (rename) or 1 day (delete with downstream cleanup).
11. **Delete checked-in WASM artifacts.** `git rm crates/libs/hush-wasm/{hush_wasm.js,hush_wasm.d.ts,hush_wasm_bg.wasm.d.ts,hush_wasm.d.ts.template,package.json}`; extend `.gitignore`. [03] — 5 minutes.
12. **Delete committed Vite bundles.** `git rm -r apps/agent/src-tauri/resources/control-console/assets/*.js apps/agent/src-tauri/resources/cloud-dashboard/`; add to `.gitignore`. [07] — 5 minutes.
13. **Fix workbench Tauri schema URL.** `apps/workbench/src-tauri/tauri.conf.json:2` — replace nicegui URL with `https://schema.tauri.app/config/2`. [07] — 30 seconds.
14. **Renumber duplicate spec.** `docs/specs/19-secret-broker-egress-tier.md` → `20-*`. [08] — 1 minute.
15. **Remove `src/hush` ghost package** from `packages/sdk/hush-py/pyproject.toml:48`. [09] — 30 seconds.

### Tier B — This week (~2 days of focused work)

1. **Rewrite `README.md` from scratch.** Target ≤300 lines. Definition → install → 30-line quick start → capabilities → links. Delete poem, sigils, GIFs, enterprise content (move to `docs/enterprise/`). [01] — 1 afternoon.
2. **Add concurrency + permissions + timeouts to every workflow.** Top-level `concurrency: { group: ..., cancel-in-progress: PR-only }`; default `timeout-minutes: 30`; `permissions: { contents: read }` on the 7 workflows missing it. [02] — 1 hour.
3. **Collapse `.github/workflows/docker.yml` 9 jobs into a matrix.** Drops ~280 lines, immediate visible cleanup. [02] — 2 hours.
4. **Pin `aquasecurity/trivy-action@master` to a SHA and drop `continue-on-error: true`.** 9 call sites. [02] — 15 minutes.
5. **Move 32-entry `cargo audit --ignore` list from `ci.yml:488-533` into `deny.toml`** with structured id/reason/expiry/owner. [02] — 1 hour.
6. **Replace per-job `actions/cache@v5` with `Swatinem/rust-cache@v2`.** Drops ~80 lines, improves cache hit rate. [02] — 2 hours.
7. **Split `apps/workbench/src/components/workbench/sentinel-swarm-pages.tsx` into 6 files.** Restores code-splitting. [06] — 1 hour.
8. **Add `apps/workbench/` to root `biome.json` `files.includes`; enable linter** with `noExplicitAny`, `noConsole`. Run `biome check --write`. [05, 06] — 2 hours.
9. **Codemod 102 `console.log/warn/error` calls in `apps/workbench/`** to a `lib/logger.ts` module. [06] — 1 hour.
10. **Convert core rulesets to use `extends`.** `strict.yaml`, `ai-agent.yaml`, `cicd.yaml`, `permissive.yaml` all become `extends: default`. Add golden-compare CI test. [09] — 3 hours.
11. **Add a `path_allowlist:` block to `default.yaml`.** Six of thirteen guards never appear in core rulesets; this is the most visible. [09] — 30 minutes.
12. **Fix or delete the broken compliance fixtures.** `fixtures/certification/policies/{hipaa,pci-dss,soc2}-policy.yaml` use unrecognized fields (`default_action: deny`, `severity: medium`, `additional_patterns` without deep_merge). [09] — 3 hours.
13. **Add Tauri `capabilities/default.json`** for `apps/desktop` and `apps/agent`. Without these, Tauri v2 release builds break. [07] — 1 hour.
14. **Remove hardcoded `TEAM_ID=JB6682CJY9`** from `render-mdm-profiles.sh:16` and `developer-id-profile-template.plist:9,22`. Make it a build input. [07] — 30 minutes.
15. **Set CSP on `apps/desktop/src-tauri/tauri.conf.json`.** Currently `null`. Copy from workbench. [07] — 5 minutes.
16. **Rewrite `packages/sdk/hush-ts/src/client.ts`** with real types instead of `Promise<any>`. [05] — 4 hours.
17. **Delete or rewrite `ReceiptSigner.verify`** in `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts`. Wire `verifySignature` from `@clawdstrike/sdk`. [05] — 1 hour.
18. **Make Vercel-AI middleware fail-closed on WASM unavailability.** Accept `onDegrade` callback and `allowDegradedSecurity: true` opt-in. [05] — 2 hours.
19. **`Error::SpineError(String)` → `Spine(#[from] spine::Error)`** in `crates/libs/clawdstrike/src/error.rs:96-114`. [03] — 2 minutes.
20. **Stop logos-z3 lying.** `check_explanatory` and `check_epistemic` return `Err(Unsupported)` not `Ok(Unknown)`. Update crate docs. [03] — 30 minutes.
21. **Rename or absorb `logos-ffi`.** Either rename to `logos-types` or fold into `clawdstrike-logos`. Delete `lean-runtime` feature. [03] — 1 hour.
22. **Fix `logos-z3/Cargo.toml`** to use `version.workspace = true` etc. (5 lines). [03] — 3 minutes.
23. **Move `Dockerfile.hushd` and `Dockerfile.registry`** from repo root to `infra/docker/`. Update CI refs. [01, 02] — 30 minutes.
24. **Move `MOTION_PLAN.md`, `REALIZATION_ROADMAP.md`, `REVIEW.md`** from `apps/*/` to `docs/plans/`. [06] — 5 minutes.
25. **Move `crates/tests/e2e-posture-cmd/`** to `tools/` (it's a CLI, not a test). [09] — 15 minutes.
26. **Move top-level `tests/registry-smoke.sh`** to `scripts/smoke/registry.sh`. [09] — 5 minutes.
27. **Add `with_graceful_shutdown(shutdown_signal())` to `clawdstrike-brokerd::main`.** [04] — 15 minutes.
28. **Delete the `clawdstriked` vanity binary** from `hushd/Cargo.toml` (or document why both names exist). [04] — 2 minutes.
29. **Wire `tracing_subscriber` in `spine-cli::main`** so `--verbose` is not a lie. [04] — 30 minutes.
30. **Default outbox paths** in all five bridges away from `/tmp/`. [04] — 30 minutes.

### Tier C — This month (substantial structural work)

1. **Split `apps/agent/src-tauri/src/api_server.rs` (48,118 lines)** into a new library crate `crates/services/agent-api/` with one module per route group. Agent binary becomes ~200 lines. [07] — 1–2 weeks.
2. **Modularize `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` (9,836 lines)** and `edr/receipt/mod.rs` (6,402 lines). Introduce `ReceiptFamily` trait; one file per family. Replace wildcard re-exports. Drop the file-level `allow(dead_code)`. [03] — 1–2 weeks.
3. **Decompose `apps/workbench`** by deleting (or extracting to `apps/labs/`) `features/{spirit,observatory,nexus,hunt}/`. Drop `wawa-vfx`, `ecctrl`, `r3f-forcegraph`, `react-three-rapier`, `postprocessing`, `leva`. [06] — multi-day.
4. **Consolidate to ≤2 Tauri apps.** Keep `agent` + `workbench`. Delete `desktop` ("Huntronomer") and the vestigial `control-console` Tauri shell. Resolve the "is agent a Tauri app or a tray daemon?" question. [07] — 3–4 weeks.
5. **Rewrite `docs/src/formal-verification.md`** with a "Limitations" section listing every `sorry`, every axiom class. Add `formal/lean4/ClawdStrike/TRUSTED-AXIOMS.md`. Either complete the Aeneas Merkle serde translation or scope-down P7. [08] — 2–3 days.
6. **Split `crates/services/hush-cli/src/main.rs` (3,238 lines)** into per-command modules. [04] — 3–4 days.
7. **Split route god-files** (`policies.rs` 3,153L; `response_actions.rs` 2,740L; `broker.rs` 2,538L; `certification.rs` 2,109L; `swarm_hub.rs` 2,038L) by domain action. [04] — multi-day.
8. **Move `crates/services/control-api/src/integration_tests.rs` (11,377 lines)** to `tests/integration/` with a `testkit` feature for helper exports. [04] — 1 day.
9. **Refactor `control-api::main::run`** into a `ServiceSupervisor` over a `JoinSet` + single `watch<bool>` shutdown. `main` becomes ~50 lines instead of 336. [04] — 2 days.
10. **Persist `clawdstrike-brokerd::OperatorState`** to SQLite or NATS JetStream. Recover on boot. [04] — 2–3 days.
11. **Move `spine` library's three binaries** (`checkpointer` 1,938L, `proofs_api` 1,426L, `witness` 116L) to `crates/services/spine-{checkpointer,proofs-api,witness}/`. Drop the `bins` feature. [03] — 1 day.
12. **Replace `anyhow::Result` in `clawdstrike-policy-event` public API** with typed `thiserror` enums. ~100+ signatures. [03] — multi-day.
13. **Restructure `bridge-runtime`** — split 911-line `lib.rs` into `outbox.rs / publisher.rs / chain.rs / health.rs`; replace `Result<_, String>` with `Result<_, PublishError>` everywhere. [03] — 2 days.
14. **Decide eas-anchor's fate** — finish the alloy implementation against Base Sepolia OR hide from service docs OR refuse to start without `--allow-stub`. [04] — large if implementing.
15. **Webhook outbox in `hushd::certification_webhooks`** using `SqliteOutbox` pattern from `bridge_runtime`. [04] — 2 days.
16. **Consolidate the three `hushd` rate limiters** (`rate_limit.rs` 502L + `v1_rate_limit.rs` 246L + `identity_rate_limit.rs` 206L) into one `RateLimitRegistry`. [04] — 2 days.
17. **Reduce hushd crypto stacks.** Gate SAML/OpenSSL behind a feature; default build links only ring/rustls. [04] — large.
18. **Move `resvg` badge rendering** out of the hushd daemon. [04] — 2 days.
19. **Extract `bridge_runtime::run_bridge<B>`** to eliminate five duplicate 200-line bridge mains. [04] — 1 day.
20. **Wire Tauri signing + notarization.** Env-var signing identity; CI `xcrun notarytool submit`; document signer-host setup. Without this, the agent's system extension will not load on macOS 15+. [07] — 1 week.
21. **Adopt `utoipa` or `aide`** for OpenAPI generation across control-api + hushd. Stops manual SDK drift. [04] — large but high-leverage.
22. **Move `prepare-bundled-hushd.sh` out of Tauri's `beforeBuildCommand`** into a moon task or `xtask`. Tauri consumes pre-built artifacts only. [07] — 2 days.
23. **Split `packages/sdk/hush-ts/src/clawdstrike.ts` (2,027 lines)** and `guards/spider-sense.ts` (2,365 lines) into sub-modules. [05] — 1 day each.
24. **Consolidate Zustand stores in `apps/workbench`** from 29 to ~8 along boundaries: `editor`, `panes`, `project`, `fleet`, `findings`, `swarm`, `operator`, `ui`. [06] — multi-day.
25. **Create `packages/ui/`** shared design-system package. Migrate the four near-duplicate UI primitive systems. [06] — 1 week.
26. **Codemod inline `style={{}}` blocks** (929 in control-console + 941 in workbench) to Tailwind utilities + CSS modules. [06] — multi-day mechanical.
27. **Stand up React Compiler** on workbench (React 19 already); delete most of the 1,194 defensive `useMemo`/`useCallback` calls. [06] — 1 day.
28. **Pick one TS build path** — `tsc + NodeNext` or `tsup + bundler`. Migrate `hush-ts` to match the rest. Codemod `.js` extensions. [05] — 2 days.
29. **Create `tsconfig.base.json`** at root, enable `noUncheckedIndexedAccess`, fix surfaced errors. [05] — 1–2 days.
30. **Unify Python packaging** — pick maturin OR hatchling; delete the other pyproject. Document `maturin develop` as the test invocation. [09] — 2–3 days.
31. **Backfill CHANGELOG entries** for 0.1.3, 0.2.0–0.2.5; update `[Unreleased]` from recent git history. [01] — half a day.
32. **Restructure `docs/plans/`** — convert `monorepo-staff-organization-plan.md` to ADR; demote `sentinel-swarm/` to `docs/research/`; trim `swarm-engine/` and remove hardcoded `/Users/connor/` paths; decide `pact/` (RFC or research). Target: 6–8 plan directories instead of 18. [08] — 3–5 days.
33. **Tighten the formal-verification public messaging** + complete or scope-down the Aeneas Merkle `sorry`s. [08] — 1 week.
34. **Replace `PAT-based bot commit`** in `promote-dev-profile-images.yml` with a GitHub App. [02] — 4–6 hours.

---

## Aggregated Quick Wins

Combined and deduplicated from every "Top 5/10 Quick Wins" section. ~25 items. Each <30 min unless noted.

- [ ] Delete `.DS_Store`, `.env`, `.tmp-release-venv/`, `.playwright-cli/`, `tmp/`, `output/`, `coverage/`, `.worktrees/` from working tree. Add to `.gitignore`.
- [ ] Delete `apps/cloud-dashboard/` entirely.
- [ ] Delete `apps/academy/src/app/test-mdx/`.
- [ ] Delete `docs/HANDOFF.md`, `docs/auth.md`, `docs/plans/implementation-pad.md`, both `*-handoff-prompt.md`, `docs/plans/agent-frameworks/`, `docs/nono-integration/`, `docs/plans/editor-ide/UI-POLISH-CAMPAIGN.md`.
- [ ] `git rm -r docs/book/`; add to `.gitignore`.
- [ ] `git rm crates/libs/hush-wasm/{hush_wasm.js,hush_wasm.d.ts,hush_wasm_bg.wasm.d.ts,hush_wasm.d.ts.template,package.json}`.
- [ ] `git rm -r apps/agent/src-tauri/resources/{control-console,cloud-dashboard}/`.
- [ ] Delete `packages/sdk/hush-py/dist/clawdstrike-0.1.0*` and `0.2.4*`.
- [ ] Remove `divider.png` reference in `README.md:26-28`.
- [ ] Fix smart-quote + stray backtick in `CONTRIBUTING.md:6`.
- [ ] De-dupe `.planning/` (×4) in `.gitignore`.
- [ ] Delete 14 per-package `package-lock.json` files in `packages/adapters/*` and `packages/sdk/hush-ts`; add `packages/**/package-lock.json` to `.gitignore`.
- [ ] Delete root-level lockfile not picked (bun.lockb OR package-lock.json). Add `packageManager` to `package.json`.
- [ ] Replace three identical Tauri-default icons; run `cargo tauri icon` per surviving app.
- [ ] Rename `apps/desktop/package.json` from `sdr-desktop` to `@clawdstrike/desktop` (or delete the app).
- [ ] Move `MOTION_PLAN.md`, `REALIZATION_ROADMAP.md`, `REVIEW.md` from `apps/*/` to `docs/plans/`.
- [ ] Rename `rulesets/patterns/s2bench-v1.json` → `s2bench-v1-demo.json` with a header comment.
- [ ] Bulk-replace `version: "1.0.0"` → `version: "1.5.0"` and `clawdstrike-v1.0` → `1.5.0` across `examples/**/policy*.yaml`. Rename `schema_version:` → `version:`.
- [ ] Update `docs/src/reference/policy-schema.md:13-20` to list 1.5.0.
- [ ] Renumber `docs/specs/19-secret-broker-egress-tier.md` → `20-*`.
- [ ] Remove `"src/hush"` entry from `packages/sdk/hush-py/pyproject.toml:48`.
- [ ] Make `permissive.yaml` `extends: default`.
- [ ] Add `path_allowlist:` block to `default.yaml`.
- [ ] Move `crates/tests/e2e-posture-cmd/` to `tools/`.
- [ ] Move `tests/registry-smoke.sh` to `scripts/smoke/registry.sh`.
- [ ] Add `permissions: { contents: read }` to 7 workflows missing it.
- [ ] Add top-level `concurrency:` to `ci.yml`.
- [ ] Pin `aquasecurity/trivy-action@master` to a SHA; drop `continue-on-error: true`.
- [ ] Add `with_graceful_shutdown(shutdown_signal())` to `clawdstrike-brokerd::main`.
- [ ] Flip `hushd::AuthConfig::enabled` default to `true`.
- [ ] Default `control-api` `LISTEN_ADDR` to `127.0.0.1:8080` and replace `CorsLayer::permissive()`.
- [ ] `Error::SpineError(String)` → `Spine(#[from] spine::Error)` in `clawdstrike/src/error.rs:96-114`.
- [ ] Replace hand-pinned `version`/`edition`/`license`/`rust-version`/`repository` in `logos-z3/Cargo.toml` with `*.workspace = true`.
- [ ] Make `check_explanatory` and `check_epistemic` in `logos-z3` return `Err(Unsupported)`.
- [ ] Replace duplicate `eprintln!` warnings in five bridge `main`s with `tracing::warn!`.
- [ ] Initialize `tracing_subscriber` in `spine-cli::main`.
- [ ] Delete `clawdstriked` vanity binary from `hushd/Cargo.toml`.
- [ ] Fix workbench `tauri.conf.json:2` `$schema` URL (currently nicegui).
- [ ] Pick a single Discord URL; reduce duplication in CONTRIBUTING + GOVERNANCE.
- [ ] Add `.editorconfig`, `.nvmrc`, `rust-toolchain.toml` at root.

---

## What's Actually Good

Consolidating "Strengths" + "Things to Leave Alone" across all 9 reports. These exemplify what the rest of the codebase should look like.

**Crypto + canonical-data primitives:**
- `crates/libs/hush-core/src/canonical.rs` — 358-line hand-written shortest-repr float canonicalizer with five JCS conformance vectors. The kind of code to point at in an interview.
- `crates/libs/hush-core/src/{lib.rs, error.rs, signing.rs, hashing.rs, merkle.rs}` — clean modules, all under 500 lines, `#[non_exhaustive]` errors, `thiserror` `#[from]`, doctests that actually compile.
- `packages/sdk/hush-ts/src/{merkle.ts, canonical.ts, receipt.ts}` — clean, typed, security-sound.

**Plugin SDK and engine internals:**
- `crates/libs/clawdstrike-guard-sdk/` + `clawdstrike-guard-sdk-macros/` — five small files, one proc macro, a clear `prelude`. Model of a plugin SDK.
- `crates/libs/hush-proxy/src/lib.rs` — 13 lines. Four modules, four `pub use`. Crate description matches contents.
- `crates/libs/clawdstrike/src/guards/mod.rs:67-308` — `Severity`, `GuardResult`, `GuardContext`, `Guard` trait. Concise, `#[must_use]`, doctests.
- `crates/libs/clawdstrike/src/error.rs` — 118 lines, `#[non_exhaustive]`, proper `From` impls.
- `crates/libs/hush-ffi/src/{lib.rs, error.rs}` — `with_ffi_guard` + thread-local last-error is the right pattern.
- Workspace `[workspace.lints.clippy] unwrap_used = "deny" / expect_used = "deny"` — actually enforced; sampled production unwraps all live in `#[cfg(test)]`.

**Services and bridges done right:**
- `crates/services/clawdstrike-brokerd/src/main.rs` — 17 lines. Loads config, builds state, binds, serves. The model.
- `crates/services/clawdstrike-brokerd/src/api.rs:179-188` — constant-time admin auth via `constant_time_eq`.
- `crates/services/clawdstrike-brokerd/src/api.rs::ApiError` — discriminated `(status, code, message)` with `IntoResponse`. Mirror this pattern.
- `crates/services/clawdstrike-brokerd/src/config.rs:109-119` — fail-closed config validation (rejects empty trusted-key sets, zero TTL).
- `crates/bridges/{tetragon,hubble,auditd,k8s-audit,darwin-telemetry}-bridge/` sharing `bridge_runtime` — admin server, outbox worker, metrics. Right shape; extend rather than undo.
- `crates/bridges/tetragon-bridge/src/lib.rs:238-298` — supervised event loop with `consecutive_errors`, exponential backoff, metrics. Solid pattern.
- `crates/services/hushd/src/cli.rs::parse_listen_host_port` — IPv6 support with explicit unit tests.
- `crates/services/hushd/src/cli.rs:218-262` — systemd `sd_notify::Ready` + watchdog heartbeat at half `WATCHDOG_USEC`. Real daemon engineering.
- `crates/services/hushd/src/tls.rs::handle_accept_error` — correctly classifies transient client drops vs server issues.
- `crates/services/hush-cli/src/main.rs:78-99` — stable documented `ExitCode` enum (an external contract; don't change values).

**Native + Tauri done right:**
- `apps/agent/src-tauri/macos/system-extension/endpoint-security/.../Monitor.swift:962-1006, 1070-1093` — EndpointSecurity AUTH_OPEN with correct fail-open via `es_respond_flags_result` on deallocation.
- `apps/agent/src-tauri/macos/system-extension/profiles/render-mdm-profiles.sh:62-80` — regex-validates Team ID, bundle ID, org identifier; post-render `{{` token detection; `plutil -lint`.
- `apps/workbench/src-tauri/src/commands/capability.rs:1-356` — backend-held short-lived capability grants gated by native dialog. Renderer never holds reusable auth.
- `apps/workbench/src-tauri/capabilities/default.json:31-62` — explicitly denies `~/.ssh`, `~/.aws`, `~/.kube`, `~/.docker`, keychain dirs, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`. The right shape; copy to every new app.
- `apps/agent/src-tauri/src/security/auth.rs:1-12` — `subtle::ConstantTimeEq`. Correct primitive.
- `apps/agent/src-tauri/build.rs:1-179` — `CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING` rejects `__PLACEHOLDER__` strings at release. Model for other release gates.

**TS architecture done right:**
- `packages/adapters/clawdstrike-adapter-core/` — `FrameworkAdapter`, `BaseToolInterceptor`, `PolicyEngineLike`, `failClosed`, `ClawdstrikeBlockedError`. The load-bearing contract.
- `packages/sdk/clawdstrike-hunt/src/index.ts` — handwritten barrel, verb-led naming (`buildReport`, `signReport`, `verifyReport`, `correlate`, `replay`).

**Frontend strengths to preserve:**
- `apps/control-console/src/index.css:5-67` — "Forged Gold on Black Glass" CSS variable design system.
- `apps/control-console/src/state/processRegistry.tsx:70-543` — 24 hand-drawn SVG sigils using design tokens. Distinctive and on-brand. (Split out of registry; do not replace with lucide.)
- `apps/control-console/src/components/ui/Stamp.tsx` — `stamp-press` keyframe; perfect "decision recorded" micro-interaction.
- `apps/academy/` — Next.js 16 + Radix + Tailwind v4 tokens + MDX + Pagefind. Cleanest app in repo. Don't touch beyond `test-mdx` cleanup.
- `apps/workbench/src/features/panes/` (pane-tree, pane-store, pane-session) — clean binary-tree pane primitive.
- `apps/workbench/src/lib/command-registry.ts` — right pattern; ensure the rest of the app actually routes through it.
- `apps/workbench/build/workbench-chunking.test.ts` — 137-line Vite chunk-allocation guardrail. The kind of test other features should imitate.
- `apps/workbench/src/App.tsx:295-317` — Tauri Stronghold credential migration on boot. Real fail-closed hygiene.

**CI workflows worth copying:**
- `.github/workflows/docs.yml` — exemplary: path-scoped trigger, scoped permissions, `concurrency: { group: pages, cancel-in-progress: true }`, parallel linkcheck. If every workflow looked like this, audit 02 would not exist.
- `.github/workflows/argo-dev-verify.yml` — purpose-built, complete, well-instrumented.
- `.github/workflows/helm-cluster-smoke.yml` — gate-job pattern + `merge-candidate` label + fork-refusal. Copy elsewhere.
- `infra/deploy/helm/clawdstrike/` — 689-line `values.yaml`, profiles, CI values, NetworkPolicy, PDB, HPA, ServiceMonitor, ExternalSecrets, RBAC, ingresses, chart-tests. What a real chart looks like.
- OIDC-to-AWS pattern across `argo-dev-verify`, `helm-cluster-smoke`, `helm-nightly-resilience`, `promote-dev-profile-images`. Modern, correct.
- Dockerfile multi-stage + non-root + tini PID-1 + cache mounts. Just collapse the duplication.

**Tests + rulesets worth preserving:**
- `crates/tests/formal-diff-tests/` — proptest with env-driven `PROPTEST_CASES`, named algebraic properties P1–P11, independent spec reimplementation. The crown jewel of tests.
- `crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs` — self-contained bridge → envelope → checkpoint → witness → inclusion proof chain, with wrong-leaf and wrong-root tamper checks.
- `rulesets/tests/policy-torture/run.sh` — `--min-coverage 100` gauntlet exercising every built-in guard.
- `fixtures/canonical/jcs_vectors.json` and `fixtures/receipts/` — well-structured golden vectors under 17 KB.
- `fixtures/policy-events/<category>/v1/cases.json` versioning — disciplined; keep extending.

**Formal verification crown jewels:**
- `formal/lean4/ClawdStrike/ClawdStrike/Spec/Properties.lean` — 707 lines, **0 `sorry`s**, proves P1, P2, P3, P4 (forbidden-path), P5. Don't touch.
- `formal/lean4/ClawdStrike/ClawdStrike/Core/` — hand-written spec types, clean, well-organized.
- `docs/plans/decisions/0001..0008-*.md` — short, focused, dated ADRs. The pattern the rest of `docs/plans/` should converge on.

**Meta files (audit 01 said "leave alone"):**
- `LICENSE`, `NOTICE`, `SECURITY.md`, `THREAT_MODEL.md`, `NON_GOALS.md`, `CODE_OF_CONDUCT.md`, `deny.toml`, workspace `Cargo.toml` member list + lints + `profile.release`, `moon.yml`, `.gitattributes`.

**Docs that work:**
- `docs/src/` mdBook structure — builds cleanly, all chapters resolve.
- `docs/src/reference/guards/` — page per guard, consistent naming. Most polished docs area.
- `docs/src/hunt/report.md` openly states "planned command, not implemented". The pattern to apply to plugins/ and package-manager/.

**Examples that work:**
- `examples/hello-secure-agent-{ts,py,vercel}/` — three clean reference quickstarts with `--dry-run` mode. Idiomatic, faithful.
- `examples/spider-sense-threat-intel/` — TS/Py/Go cross-language parity demo.

---

## Recommendations for a "Wave 3"

If the owner wants to drill deeper after the Tier A/B/C cleanup lands, these narrow audits would each surface another batch of receipts.

1. **Dead-code sweep of `crates/libs/clawdstrike-policy-event/src/edr/mod.rs`** line-by-line — drop the `#![allow(dead_code, unused_imports)]` and follow the compiler errors. Will likely surface 1–3k lines of removable code.
2. **Lockfile consistency sweep** across every `package-lock.json`, `bun.lock`, `bun.lockb`, `pyproject.toml`, `uv.lock`, `Cargo.lock` in the tree. There are 14+ JS lockfiles alone.
3. **`apps/agent/src-tauri/src/api_server.rs` route audit** — enumerate all 884 functions, identify duplicates, identify unused routes, identify untyped error returns. Producible as a CSV.
4. **`infra/vendor/*` audit** — every vendored crate (`async-nats`, `addr2line`, `cranelift-*`, etc.) — what's patched, why, link to upstream issue, expiry. Will likely reveal multiple "no idea why this is here."
5. **`crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs` family extraction** — list every `for_*` constructor, group by family, design the `ReceiptFamily` trait, estimate per-family file size after split.
6. **TS `any` audit** — produce a categorized inventory (`WASM module access`, `Vercel AI shapes`, `LangChain generics`, `HTTP client`, `other`). Each category gets its own remediation plan.
7. **`.github/workflows/release.yml` (1,266 lines) walkthrough** — the in-line audit-ignore list, the hardcoded crate publish order, the comment about `clawdstrike` dry-run failing against crates.io. What's actually publishable?
8. **Tauri capabilities audit** — for `apps/desktop` and `apps/agent` once they have real `capabilities/default.json`. Enumerate each `#[tauri::command]` and the minimum capability needed.
9. **Plugin surface audit** — `docs/src/plugins/` documents 9 chapters of unshipped runtime. Compare to `clawdstrike-guard-sdk` actual surface. What's the gap to ship at least Tier-1?
10. **Stale roadmap reconciliation** — `docs/src/roadmap.md` (639L), `docs/plans/clawdstrike/formal-verification/ROADMAP.md`, `docs/plans/origin-enclaves/ROADMAP.md`, `docs/plans/sentinel-swarm/NEXT-WAVE-ROADMAP.md`, `docs/plans/clawdstrike/secret-broker/roadmap.md`, `docs/roadmaps/nextgen-policy-roadmap.md` (2,496L), `docs/roadmaps/spider-sense-integration.md` (963L). Merge into one canonical roadmap with the rest archived under `docs/plans/decisions/archive/`.
11. **`packages/swarm-engine/` audit** — 13,931 LOC of TS, no README, no description, no license. Is it real product code or vestigial?
12. **`scripts/*.py` proof-bundle triage** — 18 files, ~14k LOC, names like `endpoint-decision-engine-readiness-audit.py` (3,814 lines). Per file: kept / moved to `docs/evidence/` / deleted.
13. **`fixtures/hushspec/rulesets/` vs `vendor/hushspec/rulesets/` diff** — pick one, delete the other, document the pinning policy.
14. **`mise.toml` task graph** — current tasks duplicate work between `test:apps` and `ci`. Refactor into `depends = [...]`.
15. **Native code: EndpointSecurity authorization deadline fuzz** — wrap `es_client_t` in a protocol, add tests for the four AUTH_OPEN paths (allow, deny, decode-failure-fail-open, self-deallocated-fail-open).

---

## Reading Order

If the owner wants to dive into the underlying reports themselves:

**Read first (worst rot, biggest leverage):**

1. **`07-tauri-desktop-apps.md`** — the 48k-line `api_server.rs`, four Tauri apps with default icons, empty capability files, no signing or notarization. Most damning single area.
2. **`04-rust-services-bridges.md`** — security-default disasters (`hushd` auth off, control-api permissive CORS, registry empty key permitted, brokerd admin-token bypass), `eas-anchor` stub, in-memory persistence. The security posture chapter.
3. **`06-frontend-apps.md`** — Spirit/Observatory/Nexus 3D gamification in a detection IDE, two vestigial apps, 4,868-line single component. Biggest "vibe-coded" tell in the repo.
4. **`03-rust-core-libs.md`** — 9,836-line `edr/mod.rs`, `logos-ffi`/`logos-z3` half-built features, `bridge-runtime` String errors, checked-in WASM artifacts.
5. **`08-docs-formal-examples.md`** — overclaimed formal verification, planning-doc sprawl, schema-version drift in examples, `docs/HANDOFF.md` still in root.

**Read in the middle (substantial but more tractable):**

6. **`05-typescript-packages.md`** — 503 `any` sites, fail-open receipt verifier, 14 lockfiles, 2,027-line god module.
7. **`02-ci-cd-infra.md`** — 1,497-line `ci.yml`, 9 copy-paste `docker.yml` jobs, 18 unreferenced Python proof scripts. Mechanical to fix.
8. **`09-tests-rulesets-misc.md`** — broken compliance fixtures, rulesets don't use `extends`, two `pyproject.toml` for one wheel, silent-skip integration tests.

**Read last (the most tractable; lots of trivial fixes):**

9. **`01-top-level-meta.md`** — README theatricality, schema-version drift, lockfile war, three Discord URLs, `.DS_Store` everywhere. Almost entirely a one-afternoon edit.

---

*Master report generated 2026-05-23 from 9 area audits totaling ~3,800 lines. Underlying reports: `.audit/01..09-*.md`.*
