# Documentation Audit Index — 2026-02-26

## Summary
- Total findings: 52 (deduplicated)
- Critical (outdated/wrong): 18
- Missing (should exist but doesn't): 14
- Improvement (could be better): 20
- Reports: 4
- Files audited: 144

## Checklist

### Critical Fixes

- [ ] [docs/src/concepts/guards.md:33-41] Guards concept doc lists 7 built-in guards; codebase has 12 — add ComputerUseGuard, ShellCommandGuard, PathAllowlistGuard, InputInjectionCapabilityGuard, RemoteDesktopSideChannelGuard → [Core](2026-02-26-core-docs-audit.md) #1, [Reference](2026-02-26-reference-docs-audit.md) #1, [Root](2026-02-26-root-meta-audit.md) #15
- [ ] [docs/src/reference/guards/README.md:3] Guards README claims "seven built-in guards" and has incomplete action coverage matrix and evaluation order — update to 12 guards, add ShellCommand column → [Reference](2026-02-26-reference-docs-audit.md) #1, #8, #9
- [ ] [docs/src/reference/guards/README.md:55] Guards README incorrectly claims "no `enabled: false` toggle" — every guard config has an `enabled` field → [Reference](2026-02-26-reference-docs-audit.md) #7
- [ ] [Schema version drift across 6+ files] Policy examples show `version: "1.1.0"` but current is `1.2.0` — bulk-update to `1.2.0` with backward-compat note. Affected files: `concepts/policies.md:10`, `getting-started/quick-start.md:54`, `guides/policy-inheritance.md:23`, `guides/openclaw-integration.md:57`, `recipes/claude.md:19`, `recipes/github-actions.md:37` → [Core](2026-02-26-core-docs-audit.md) #8, #11, #14, #15, #24, #25
- [ ] [docs/src/concepts/decisions.md:9-13] GuardResult fields omit the `guard` field present in code → [Core](2026-02-26-core-docs-audit.md) #4
- [ ] [docs/src/concepts/terminology.md:19] GuardAction types list omits `ShellCommand` variant → [Core](2026-02-26-core-docs-audit.md) #6
- [ ] [docs/src/concepts/terminology.md:72-78] Severity levels conflate guard Severity (info/warning/error/critical) with JailbreakSeverity (safe/suspicious/likely/confirmed) — split into two sections → [Core](2026-02-26-core-docs-audit.md) #7
- [ ] [docs/src/guides/openclaw-integration.md:88] References non-existent `clawdstrike:ai-agent-minimal` ruleset — replace with `clawdstrike:ai-agent` or `clawdstrike:permissive` → [Core](2026-02-26-core-docs-audit.md) #18
- [ ] [CHANGELOG.md] Has no v0.1.1 or v0.1.2 release entries despite 37+ commits; uses wrong `@backbay/` npm scope (should be `@clawdstrike/`); lists only 7 guards; omits CUA Gateway, Desktop Agent Overhaul, FFI, and other major features → [Root](2026-02-26-root-meta-audit.md) #1, #2, #3, #4
- [ ] [CLAUDE.md:77-85] Lists "Built-in Guards (7)" — should be 12; omits several Rust crates from architecture section (spine, hush-ffi, cloud-api, eas-anchor, bridges) → [Root](2026-02-26-root-meta-audit.md) #15, #16
- [ ] [docs/REPO_MAP.md:3] Last updated 2026-02-10; missing hush-ffi in Component Maturity table, missing docs/ops/, docs/roadmaps/, docs/audits/ directories → [Root](2026-02-26-root-meta-audit.md) #12
- [ ] [docs/src/reference/api/python.md:9] Claims Python SDK has 5 guards — actual count is 7 (includes PromptInjection, Jailbreak) → [Reference](2026-02-26-reference-docs-audit.md) #15
- [ ] [docs/src/reference/api/python.md:12] Claims prompt-security utilities are "not yet implemented" — jailbreak/prompt injection guards and prompt_security module exist in Python SDK → [Reference](2026-02-26-reference-docs-audit.md) #16
- [ ] [docs/src/reference/rulesets/README.md:9-15] Rulesets README missing remote-desktop (3 variants) and ai-agent-posture rulesets → [Reference](2026-02-26-reference-docs-audit.md) #12, #13
- [ ] [packages/sdk/hush-ts/README.md:18] Lists only 5 guards; source exports 7. Guards section only shows 3 of 7 → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #16, #17
- [ ] [packages/adapters/clawdstrike-adapter-core/README.md:35-36] Code example imports from `@clawdstrike/engine-local` which is not a declared dependency → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #1
- [ ] [packages/adapters/clawdstrike-openclaw/examples/hello-secure-agent/README.md:12,47] References `npm install` and `npm test` but no package.json or test files exist → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #6, #7
- [ ] [README.md:286-293] OpenAI adapter example imports from `@clawdstrike/engine-local` which does not exist as a package — actual engines are `@clawdstrike/hush-cli-engine` / `@clawdstrike/hushd-engine` → [Root](2026-02-26-root-meta-audit.md) #8

### Missing Documentation

- [ ] [ComputerUseGuard] No reference page — create `docs/src/reference/guards/computer-use.md` documenting config fields (enabled, allowed_actions, mode), three modes (observe, guardrail, fail_closed) → [Core](2026-02-26-core-docs-audit.md) #20, [Reference](2026-02-26-reference-docs-audit.md) #2
- [ ] [ShellCommandGuard] No reference page — create `docs/src/reference/guards/shell-command.md` documenting forbidden patterns and path extraction → [Core](2026-02-26-core-docs-audit.md) #21, [Reference](2026-02-26-reference-docs-audit.md) #3
- [ ] [PathAllowlistGuard] No reference page — create `docs/src/reference/guards/path-allowlist.md` documenting deny-by-default path allowlisting → [Core](2026-02-26-core-docs-audit.md) #22, [Reference](2026-02-26-reference-docs-audit.md) #5
- [ ] [RemoteDesktopSideChannelGuard] No reference page — create `docs/src/reference/guards/remote-desktop-side-channel.md` documenting clipboard/file-transfer/session channel controls → [Reference](2026-02-26-reference-docs-audit.md) #4
- [ ] [InputInjectionCapabilityGuard] No reference page — create `docs/src/reference/guards/input-injection-capability.md` documenting input type controls and postcondition probes → [Reference](2026-02-26-reference-docs-audit.md) #6
- [ ] [CUA/Computer Use guide] No concept or guide docs for the CUA Gateway feature — create guide for remote-desktop/CUA integration → [Core](2026-02-26-core-docs-audit.md) #20, [Root](2026-02-26-root-meta-audit.md) #13
- [ ] [Remote-desktop rulesets] Three remote-desktop rulesets and ai-agent-posture have no reference docs — create pages and add to rulesets README → [Reference](2026-02-26-reference-docs-audit.md) #12, #13
- [ ] [Built-in rulesets list incomplete] 4 rulesets missing from docs: `ai-agent-posture`, `remote-desktop`, `remote-desktop-strict`, `remote-desktop-permissive` — affects concepts, guides, CLAUDE.md → [Core](2026-02-26-core-docs-audit.md) #9, #16, [Root](2026-02-26-root-meta-audit.md) #7, #17
- [ ] [Custom guards YAML config] `guards.custom[]` policy-driven guards (`PolicyCustomGuardSpec` with id/enabled/config) are undocumented → [Core](2026-02-26-core-docs-audit.md) #17
- [ ] [CONTRIBUTING.md:147] References `rulesets/community/` directory which does not exist → [Root](2026-02-26-root-meta-audit.md) #9
- [ ] [docs/ops/] Operational docs directory not referenced from DOCS_MAP.md or SUMMARY.md → [Root](2026-02-26-root-meta-audit.md) #11, #18
- [ ] [Crate READMEs] No individual READMEs for 7 library crates (except hush-wasm) or 7 service/bridge crates — at minimum add READMEs for `clawdstrike` and `hush-core` crates → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #20, #21
- [ ] [apps/cloud-dashboard/] Has no README despite being listed in apps/README.md → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #23
- [ ] [packages/sdk/README.md:5-6] Omits the `clawdstrike` unscoped convenience package from the list → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #19

### Improvements

- [ ] [docs/src/concepts/architecture.md:18-20] OutputSanitizer and Watermarking not listed as separate components in the components table → [Core](2026-02-26-core-docs-audit.md) #3
- [ ] [docs/src/concepts/decisions.md:29] Posture-aware decisions heading says `1.2.0+` but surrounding examples still use `1.1.0` — add consistent version guidance → [Core](2026-02-26-core-docs-audit.md) #5
- [ ] [docs/src/guides/audit-logging.md:36] References `clawdstriked start` — CLI uses `clawdstrike daemon start` per other docs → [Core](2026-02-26-core-docs-audit.md) #19
- [ ] [docs/src/guides/observe-synth.md:39] References `examples/policies/synthesized-example.yaml` which may not exist → [Core](2026-02-26-core-docs-audit.md) #23
- [ ] [docs/src/reference/guards/secret-leak.md] Missing config fields: `redact`, `severity_threshold`, `additional_patterns`, `remove_patterns`, pattern sub-fields → [Reference](2026-02-26-reference-docs-audit.md) #10
- [ ] [docs/src/reference/guards/forbidden-path.md] Missing Windows-specific default patterns (11 patterns for credential stores, registry hives, etc.) → [Reference](2026-02-26-reference-docs-audit.md) #11
- [ ] [docs/src/reference/rulesets/cicd.md:15] Does not mention `fail_fast: true` which is a significant behavior difference vs default → [Reference](2026-02-26-reference-docs-audit.md) #14
- [ ] [docs/src/reference/policy-schema.md:46-76] Full schema example only shows 6 guard configs — missing 6 of 12 guards → [Reference](2026-02-26-reference-docs-audit.md) #17
- [ ] [CLI reference doc] Missing `policy impact`, `policy version`, and `run` subcommands that exist in CLI source → [Reference](2026-02-26-reference-docs-audit.md) (CLI section)
- [ ] [packages/adapters/clawdstrike-openclaw/README.md] Minimal (10 lines) — no install command, no API examples unlike other adapter READMEs → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #3
- [ ] [packages/adapters/clawdstrike-openclaw/docs/getting-started.md:41] Uses legacy schema `clawdstrike-v1.0` without noting canonical `1.2.0` is preferred → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #4
- [ ] [Adapter READMEs] langchain, claude, openai, opencode READMEs redundantly list `@clawdstrike/adapter-core` in install commands — it is already a transitive dependency → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #10, #12, #13, #14
- [ ] [packages/adapters/clawdstrike-vercel-ai/README.md] Does not document the `./react` subpath export → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #9
- [ ] [packages/adapters/clawdstrike-langchain/README.md] Does not document LangGraph-specific APIs (createSecurityCheckpoint, addSecurityRouting, etc.) → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #11
- [ ] [README.md:234] Quick Start `cargo install hush-cli` may fail if not on crates.io — CLAUDE.md uses `cargo install --path` → [Root](2026-02-26-root-meta-audit.md) #5
- [ ] [docs/DOCS_MAP.md:3] Last-updated date stale (2026-02-09); missing `docs/ops/` domain → [Root](2026-02-26-root-meta-audit.md) #11
- [ ] [docs/HANDOFF.md:70-77] Labels crates as "Stable" while REPO_MAP.md and README say "alpha" — terminology mismatch → [Root](2026-02-26-root-meta-audit.md) #19
- [ ] [CONTRIBUTING.md:177-184] Guard trait example may be outdated — verify `async fn check` signature against current code → [Root](2026-02-26-root-meta-audit.md) #10
- [ ] [Category READMEs] 7 category-level READMEs (packages/sdk, packages/adapters, packages/policy, crates/libs, crates/services, crates/bridges, crates/tests) are minimal 1-4 line stubs → [Ecosystem](2026-02-26-package-ecosystem-audit.md) #24
- [ ] [Package name mapping] Directory names differ from npm/crate names (hush-ts -> @clawdstrike/sdk, hush-cli-engine -> @clawdstrike/engine-local, etc.) — document mapping table → [Ecosystem](2026-02-26-package-ecosystem-audit.md) (Cross-Cutting)

## Cross-Cutting Themes

### 1. Schema version drift (affects 8+ files across all 4 audit domains)
The policy schema version `1.2.0` is current, with `1.1.0` supported for backward compatibility and `clawdstrike-v1.0` as a legacy OpenClaw alias. However, 6+ doc files in the mdBook, the CLAUDE.md, the OpenClaw getting-started guide, and the CHANGELOG all use `1.1.0` as the primary example. This is the single most widespread issue, touching concepts, getting-started, guides, recipes, adapter docs, and meta docs.

### 2. Undocumented guards (affects 12+ files across 3 audit domains)
5 guards added in the CUA Gateway and enterprise hardening work (ComputerUseGuard, ShellCommandGuard, PathAllowlistGuard, InputInjectionCapabilityGuard, RemoteDesktopSideChannelGuard) have no reference pages and are missing from guard lists in concept docs, the guards README, CLAUDE.md, CHANGELOG, and the action coverage matrix. This affects Core, Reference, and Root/Meta reports.

### 3. Incomplete ruleset listings (affects 6+ files across 3 audit domains)
4 rulesets (ai-agent-posture, remote-desktop, remote-desktop-strict, remote-desktop-permissive) are missing from most ruleset enumerations: CLAUDE.md, policy-inheritance guide, terminology doc, rulesets README, and the OpenClaw getting-started guide. One doc also references a non-existent `ai-agent-minimal` ruleset.

### 4. CHANGELOG staleness (affects 1 file but high visibility)
CHANGELOG.md has no versioned release entries despite two tagged releases (v0.1.1, v0.1.2) with 37+ commits including 5 major features. It also uses the wrong npm scope (`@backbay/` instead of `@clawdstrike/`). As the primary release communication artifact, this has outsized impact on users and contributors.

### 5. Python SDK documentation lag (affects 2+ files across 2 audit domains)
Python API docs undercount guards (5 vs 7) and claim prompt-security utilities are unimplemented when they exist. The Python quick-start also understates guard count. This creates a misleading impression of the Python SDK's capabilities.

### 6. Meta/navigation docs stale (affects 3+ files)
DOCS_MAP.md, REPO_MAP.md, and SUMMARY.md are all missing entries for recently added components (hush-ffi crate, docs/ops/ directory, CUA-related content). Their last-updated dates predate significant additions.

## Audit Reports
- [Core Docs Audit](2026-02-26-core-docs-audit.md) — 35 files, 25 findings
- [Reference Docs Audit](2026-02-26-reference-docs-audit.md) — 51 files, 17 findings
- [Package Ecosystem Audit](2026-02-26-package-ecosystem-audit.md) — 42 files, 24 findings
- [Root & Meta Audit](2026-02-26-root-meta-audit.md) — 16 files, 19 findings
