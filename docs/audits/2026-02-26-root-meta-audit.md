# Root & Meta Documentation Audit -- 2026-02-26

## Summary

- Files audited: 16
- Total findings: 19
- Critical (outdated/wrong): 7
- Missing (should exist but doesn't): 3
- Improvement (could be better): 9

## Findings

### Root Documents

#### 1. CHANGELOG.md has no v0.1.1 or v0.1.2 release entries
- **File:** CHANGELOG.md
- **Severity:** Critical
- **Issue:** CHANGELOG.md only contains an `[Unreleased]` section. Git tags `v0.1.1` and `v0.1.2` exist, and commit `0b14ef4e` explicitly bumps the version to 0.1.2. There are 37+ commits between v0.1.1 and v0.1.2 including significant features (CUA Gateway, Desktop Agent Overhaul, FFI crate, OpenClaw launch readiness) but none are reflected as versioned entries.
- **Evidence:** `git tag -l` returns `v0.1.1` and `v0.1.2`. CHANGELOG.md:8 shows only `## [Unreleased]`. The compare link at line 154 points to `compare/main...HEAD` with no versioned compare links.
- **Fix:** Add `## [0.1.2] - 2026-02-26` and `## [0.1.1]` sections summarizing the major changes from git log. Add versioned compare links at the bottom.

#### 2. CHANGELOG.md uses @backbay/ npm scope instead of @clawdstrike/
- **File:** CHANGELOG.md
- **Severity:** Critical
- **Issue:** CHANGELOG.md references adapter packages as `@backbay/adapter-core`, `@backbay/hush-cli-engine`, `@backbay/hushd-engine`, `@backbay/vercel-ai`, `@backbay/langchain`, `@backbay/sdk`, `@backbay/wasm`. The actual published npm package names use the `@clawdstrike/` scope (verified in `packages/sdk/hush-ts/package.json` name: `@clawdstrike/sdk`, `packages/adapters/clawdstrike-adapter-core/package.json` name: `@clawdstrike/adapter-core`).
- **Evidence:** CHANGELOG.md:81-97 uses `@backbay/sdk`, `@backbay/adapter-core`, etc. Actual package.json files use `@clawdstrike/sdk`, `@clawdstrike/adapter-core`.
- **Fix:** Replace all `@backbay/` references in CHANGELOG.md with the correct `@clawdstrike/` scope.

#### 3. CHANGELOG.md lists 7 built-in guards but repo now has 9+
- **File:** CHANGELOG.md
- **Severity:** Critical
- **Issue:** CHANGELOG.md:31-38 lists 7 guards (ForbiddenPath, Egress, SecretLeak, PatchIntegrity, McpTool, PromptInjection, Jailbreak). README.md:134-136 lists 9 guards including ComputerUseGuard and ShellCommandGuard added in the CUA Gateway work (commit `95973807`). CHANGELOG.md does not reflect these additions.
- **Evidence:** README.md:134 lists `ComputerUseGuard` and `ShellCommandGuard`. These were added in `feat(cua): CUA Gateway` (#88). CHANGELOG.md has no mention of either.
- **Fix:** Add ComputerUseGuard and ShellCommandGuard to the CHANGELOG Added section, and add CUA Gateway, Desktop Agent Overhaul, and FFI features to a v0.1.2 release section.

#### 4. CHANGELOG.md missing major features from v0.1.1-v0.1.2 cycle
- **File:** CHANGELOG.md
- **Severity:** Critical
- **Issue:** The following significant features merged between v0.1.1 and v0.1.2 are absent from CHANGELOG.md:
  - CUA Gateway with ComputerUseGuard, ShellCommandGuard, remote-desktop rulesets (#88)
  - Desktop Agent Overhaul with OTA updates, session/agent tracing (#86)
  - hush-ffi C ABI crate + C# SDK + Go SDK (#83)
  - Enterprise desktop agent hardening (#80)
  - Helm all-on profile with bridge/ingress contract fixes (#66)
  - Helm confidence pipeline and EKS smoke/resilience workflows (#65)
  - Policy Workbench in Forensics River desktop (#64)
  - OpenClaw launch readiness -- security fixes, adapter-core alignment (#101)
- **Evidence:** `git log v0.1.1..v0.1.2 --oneline` shows all these commits. CHANGELOG.md contains none of them.
- **Fix:** Create versioned changelog sections covering all these features.

#### 5. README.md Quick Start uses wrong package name for Rust CLI install
- **File:** README.md:234
- **Severity:** Improvement
- **Issue:** README.md:234 says `cargo install hush-cli`. The actual crate path is `crates/services/hush-cli` and CLAUDE.md:43 correctly says `cargo install --path crates/services/hush-cli`. The `hush-cli` crate may not be published on crates.io yet (alpha software), so `cargo install hush-cli` may fail for users.
- **Evidence:** README.md:234 `cargo install hush-cli` vs CLAUDE.md:43 `cargo install --path crates/services/hush-cli`.
- **Fix:** Either confirm crates.io publication or change to `cargo install --path crates/services/hush-cli` with a note about building from source.

#### 6. README.md TypeScript Quick Start uses @clawdstrike/sdk but import uses wrong class name
- **File:** README.md:243-251
- **Severity:** Improvement
- **Issue:** README.md:243 says `npm install @clawdstrike/sdk` and then imports `Clawdstrike` from `@clawdstrike/sdk`. The actual exported class/API should be verified against `packages/sdk/hush-ts/src/`. The example shows `Clawdstrike.withDefaults("strict")` and `cs.checkNetwork()` which are high-level convenience APIs that may not match the actual SDK surface.
- **Evidence:** README.md:247-251. The SDK source would need verification to confirm these exact APIs exist.
- **Fix:** Verify the Quick Start example compiles and runs against the current SDK, or add a caveat about API stability.

#### 7. README.md lists rulesets including "remote-desktop" variants not in CLAUDE.md
- **File:** README.md:326 and CLAUDE.md:90
- **Severity:** Improvement
- **Issue:** README.md:326 lists built-in rulesets as `permissive | default | strict | ai-agent | cicd | remote-desktop | remote-desktop-strict`. CLAUDE.md:90 lists only `permissive, default, strict, ai-agent, cicd`. The actual `rulesets/` directory contains 9 YAML files including `remote-desktop.yaml`, `remote-desktop-strict.yaml`, `remote-desktop-permissive.yaml`, and `ai-agent-posture.yaml`.
- **Evidence:** `rulesets/*.yaml` shows remote-desktop.yaml, remote-desktop-strict.yaml, remote-desktop-permissive.yaml, ai-agent-posture.yaml. CLAUDE.md:90 omits all remote-desktop variants and ai-agent-posture.
- **Fix:** Update CLAUDE.md to list all current rulesets, and update README.md to include `remote-desktop-permissive` and `ai-agent-posture`.

#### 8. README.md OpenAI adapter example references non-existent packages
- **File:** README.md:286-293
- **Severity:** Improvement
- **Issue:** The OpenAI adapter example imports from `@clawdstrike/engine-local` and uses `createStrikeCell`, `wrapOpenAIToolDispatcher`, and `OpenAIToolBoundary`. The package `@clawdstrike/engine-local` does not exist in the packages directory. The actual engine packages are `@clawdstrike/hush-cli-engine` and `@clawdstrike/hushd-engine`.
- **Evidence:** No `engine-local` package exists under `packages/`. Available engines: `clawdstrike-hush-cli-engine`, `clawdstrike-hushd-engine`.
- **Fix:** Update the example to use actual package names or note that this is a planned convenience wrapper.

#### 9. CONTRIBUTING.md references rulesets/community/ which does not exist
- **File:** CONTRIBUTING.md:147
- **Severity:** Missing
- **Issue:** CONTRIBUTING.md:147-158 instructs contributors to "Create a new security ruleset in `rulesets/community/`" with a YAML example. This directory does not exist in the repo.
- **Evidence:** Glob for `rulesets/community/**/*` returns no results.
- **Fix:** Either create the `rulesets/community/` directory with a `.gitkeep` or README, or update the contribution guide to use a different path.

#### 10. CONTRIBUTING.md Level 5 Guard trait example may be outdated
- **File:** CONTRIBUTING.md:177-184
- **Severity:** Improvement
- **Issue:** The Guard trait example shows `async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult` with `#[async_trait]`. This should be verified against the current Guard trait definition in `crates/libs/clawdstrike/`, as the trait signature may have evolved (e.g., different parameter types or return types).
- **Evidence:** CONTRIBUTING.md:177-184 shows a specific trait signature. Needs verification against actual code.
- **Fix:** Verify the example compiles against current code and update if needed.

### Meta Documents (DOCS_MAP, REPO_MAP, SUMMARY)

#### 11. DOCS_MAP.md last-updated date is stale
- **File:** docs/DOCS_MAP.md:3
- **Severity:** Improvement
- **Issue:** DOCS_MAP.md says "Last updated: 2026-02-09" but significant documentation changes have occurred since then (CUA roadmap docs, OpenClaw research docs, operational docs, audit reports). The `docs/ops/` directory is not mentioned as a domain in DOCS_MAP.md.
- **Evidence:** docs/DOCS_MAP.md:3 says 2026-02-09. `docs/ops/` directory exists with 3 files but is not listed in the Canonical Sources table or the "What Goes Where" section.
- **Fix:** Update the date and add `docs/ops/**` as a domain (e.g., "Operational runbooks and safe-defaults guidance").

#### 12. REPO_MAP.md last-updated date is stale and missing components
- **File:** docs/REPO_MAP.md:3
- **Severity:** Critical
- **Issue:** REPO_MAP.md says "Last updated: 2026-02-10". Since then, major components have been added:
  - `crates/libs/hush-ffi` (C ABI, commit `d2c06c07` #83) -- not in Component Maturity table
  - `crates/libs/spine` is in the table but `packages/sdk/clawdstrike` (re-export package) is not mentioned
  - The `docs/ops/` directory is not in the Top-Level Layout
  - The `docs/roadmaps/` directory is not in the Top-Level Layout
  - The `docs/audits/` directory is not in the Top-Level Layout
- **Evidence:** `crates/libs/hush-ffi/Cargo.toml` exists. REPO_MAP.md Component Maturity table (lines 27-43) has no `hush-ffi` entry. `docs/ops/`, `docs/roadmaps/`, `docs/audits/` all exist with content but are not in the top-level layout table.
- **Fix:** Add hush-ffi to Component Maturity. Add docs subdirectories to the layout description or reference docs/README.md for the docs layout.

#### 13. SUMMARY.md is complete but missing CUA-related docs
- **File:** docs/src/SUMMARY.md
- **Severity:** Improvement
- **Issue:** All links in SUMMARY.md resolve to actual files under `docs/src/`. However, there are no entries for CUA/Computer Use related content despite the CUA Gateway being a major feature. The only CUA coverage is in `docs/roadmaps/cua/INDEX.md` which is linked from README.md but not from SUMMARY.md.
- **Evidence:** SUMMARY.md has no entries containing "cua", "computer-use", or "remote-desktop". README.md:365 links to `docs/roadmaps/cua/INDEX.md`. The `rulesets/remote-desktop*.yaml` files exist but have no corresponding SUMMARY.md entry for documentation.
- **Fix:** Consider adding a CUA/Computer Use guide or reference page to the mdBook and linking it from SUMMARY.md.

#### 14. docs/README.md references docs/specs/ and docs/research/ correctly
- **File:** docs/README.md
- **Severity:** (No finding -- verified correct)
- **Issue:** No issue. docs/README.md lists 6 domains and all exist: `docs/src/`, `docs/plans/`, `docs/specs/`, `docs/research/`, `docs/roadmaps/`, `docs/audits/`. All directories contain files.
- **Evidence:** Glob results confirm all 6 directories exist and contain content.

### CLAUDE.md

#### 15. CLAUDE.md lists 7 guards; actual count is 9+
- **File:** CLAUDE.md:77-85
- **Severity:** Critical
- **Issue:** CLAUDE.md:77 says "Built-in Guards (7)" and lists 7 guards. README.md lists 9 guards including ComputerUseGuard and ShellCommandGuard. The actual guard count should reflect the CUA Gateway additions from commit `95973807`.
- **Evidence:** README.md:134-136 lists ComputerUseGuard and ShellCommandGuard. CLAUDE.md:77-85 omits them.
- **Fix:** Update to "Built-in Guards (9)" and add ComputerUseGuard and ShellCommandGuard to the list.

#### 16. CLAUDE.md omits several Rust crates from architecture section
- **File:** CLAUDE.md:49-68
- **Severity:** Critical
- **Issue:** CLAUDE.md's Monorepo Structure section omits several crates that exist in `Cargo.toml` workspace members:
  - `spine` (crates/libs/spine) -- transparency log protocol
  - `spine-cli` (crates/services/spine-cli) -- CLI for spine
  - `hush-ffi` (crates/libs/hush-ffi) -- C ABI/FFI crate
  - `cloud-api` (crates/services/cloud-api) -- cloud API service
  - `eas-anchor` (crates/services/eas-anchor) -- EAS anchoring service
  - Bridge crates: `tetragon-bridge`, `hubble-bridge`
  - `sdr-integration-tests` (crates/tests/)
  - `hush-native` (packages/sdk/hush-py/hush-native) -- Python native extension
- **Evidence:** Cargo.toml workspace members (lines 3-21) include all of these. CLAUDE.md:49-59 lists only 8 Rust crates.
- **Fix:** Add missing crates to the Monorepo Structure section, at least the non-test crates.

#### 17. CLAUDE.md lists rulesets incompletely
- **File:** CLAUDE.md:90
- **Severity:** Improvement
- **Issue:** Same as finding #7. CLAUDE.md:90 lists `permissive, default, strict, ai-agent, cicd` but actual rulesets include `remote-desktop`, `remote-desktop-strict`, `remote-desktop-permissive`, and `ai-agent-posture`.
- **Evidence:** `rulesets/*.yaml` directory listing.
- **Fix:** Add the missing rulesets to the list.

### Operational Docs

#### 18. docs/ops/ directory not referenced from DOCS_MAP.md or SUMMARY.md
- **File:** docs/ops/*.md
- **Severity:** Missing
- **Issue:** The `docs/ops/` directory contains 3 operational documents (operational-limits.md, policy-workbench-rollout.md, safe-defaults.md) but is not listed in `docs/DOCS_MAP.md` as a canonical source domain, and none of the files are linked from `docs/src/SUMMARY.md`. The only inbound references are from the ops docs themselves (cross-linking each other) and from `docs/README.md` which doesn't mention ops either.
- **Evidence:** docs/DOCS_MAP.md has no `docs/ops/**` entry. docs/README.md lists 6 domains but not ops. docs/src/SUMMARY.md has no ops links.
- **Fix:** Add `docs/ops/**` to DOCS_MAP.md (e.g., "Operational runbooks and safe-defaults guidance, canonical for deployment posture"). Consider adding ops docs to SUMMARY.md or creating an ops landing page in docs/src/.

#### 19. HANDOFF.md references stale crate status labels
- **File:** docs/HANDOFF.md:70-77
- **Severity:** Improvement
- **Issue:** HANDOFF.md:70-77 labels `hush-core`, `clawdstrike`, `hush-multi-agent`, and `hush-cli` as "Stable" while REPO_MAP.md:29-42 labels everything as "alpha". Since the project is alpha software (README.md:62), "Stable" labels in the HANDOFF doc may create a false impression. HANDOFF.md also does not mention crates added after its creation (hush-ffi, cloud-api, eas-anchor).
- **Evidence:** HANDOFF.md:70-77 vs REPO_MAP.md:29-42. README.md:62 says "Alpha software."
- **Fix:** Either align terminology or add a note that "Stable" in HANDOFF context means "code-complete for SDR scope" rather than "production stable".

## Cross-Reference Checks

### SUMMARY.md vs docs/src/ files

All 57 links in SUMMARY.md resolve to actual files under `docs/src/`. No orphaned links found. No docs/src/ pages found that are missing from SUMMARY.md (all files are referenced).

### REPO_MAP.md paths vs actual repo

All top-level paths listed in REPO_MAP.md exist (`apps/`, `crates/`, `packages/`, `integrations/`, `infra/`, `docs/`, `examples/`, `fixtures/`, `rulesets/`, `scripts/`, `tools/`, `fuzz/`). Component paths in the maturity table are valid. Missing entries documented in finding #12.

### CONTRIBUTING.md build commands vs actual build system

Build commands in CONTRIBUTING.md are correct for Rust, TypeScript, and Python. The `mise run ci` and `mise run guardrails` commands reference `mise.toml` which exists. Helm lint command references `infra/deploy/helm/clawdstrike/` which exists.

### README.md link verification

| Link | Target | Status |
|------|--------|--------|
| `docs/src/getting-started/quick-start.md` | docs/src/ | Exists |
| `docs/src/getting-started/quick-start-typescript.md` | docs/src/ | Exists |
| `docs/src/getting-started/quick-start-python.md` | docs/src/ | Exists |
| `packages/adapters/clawdstrike-openclaw/docs/getting-started.md` | packages/ | Exists |
| `examples` | examples/ | Exists |
| `packages/adapters/clawdstrike-openai/README.md` | packages/ | Exists |
| `packages/adapters/clawdstrike-claude/README.md` | packages/ | Exists |
| `docs/src/guides/vercel-ai-integration.md` | docs/src/ | Exists |
| `docs/src/guides/langchain-integration.md` | docs/src/ | Exists |
| `docs/src/guides/openclaw-integration.md` | docs/src/ | Exists |
| `docs/src/reference/guards/README.md` | docs/src/ | Exists |
| `docs/src/reference/policy-schema.md` | docs/src/ | Exists |
| `docs/REPO_MAP.md` | docs/ | Exists |
| `docs/src/guides/agent-openclaw-operations.md` | docs/src/ | Exists |
| `apps/desktop/docs/openclaw-gateway-testing.md` | apps/ | Exists |
| `docs/roadmaps/cua/INDEX.md` | docs/ | Exists |
| `docs/src/concepts/multi-language.md` | docs/src/ | Exists |
| `CONTRIBUTING.md` | root | Exists |
| `LICENSE` | root | Exists |
