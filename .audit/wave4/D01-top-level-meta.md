# DELTA D01: Top-Level Meta
**Refreshed:** 2026-05-24 | **Source:** .audit/01-top-level-meta.md (2026-05-23) | **Scope:** root-level meta/config

## Quick Verdict
- Findings still valid: 26 (out of ~27 in the original — only the divider.png reference has any nuance)
- Findings fixed since 2026-05-23: 0
- Findings wrong/misdiagnosed: 0 substantive; 1 numerical drift on `.planning/` dedupe count
- New issues found: 4 (live OpenAI API key in `.env`; tracked `node_modules/` symptoms; empty `.cleanup-audit/`; cross-cluster `vendor/hushspec` + `packs/{hipaa,pci-dss,soc2}` orphan dirs)
- Net professionalism delta: **same — actually slightly worse**. Zero meta-cleanup commits landed in the last day (HEAD is `2eff91532` dated 2026-05-19, predating the audit). The audit recorded the working tree, nothing has been merged since. One new untracked dir (`.cleanup-audit/`, empty) appeared today.

---

## STILL VALID (cite file:line at HEAD)

### [V-01] README is 1,126 lines with a poem opener
**At HEAD:** `README.md:1-83` unchanged. `wc -l README.md` → 1126. Hero PNG, 8-badge wall, `<em>The claw strikes back...</em>` at L18-26, `<h1>` at L36, second tagline at L38-39, third (real) definition at L84.
**Aggressive cleanup:** REWRITE from scratch to ~250 lines. Move enterprise architecture, compliance tables, mermaid diagrams, observe-synth walkthrough, Spider-Sense quick-start, and reel GIF to `docs/`. Delete the divider+sigil chrome (`README.md:26-49`).

### [V-02] Three competing taglines
**At HEAD:** Confirmed at `README.md:18-22, 38-39, 84`. Lines 38-39 still say `EDR for the age of the swarm. / Fail closed. Sign the truth.`; L84 still opens `Clawdstrike is a fail-closed policy engine and cryptographic attestation runtime for AI agent systems.`
**Aggressive cleanup:** Keep only L84's sentence. Delete L17-39 outright (poem block, divider, sigils, h1's subtitle stanza).

### [V-03] Guard count drift across docs
**At HEAD:** `README.md:680-691` lists 10 guards (the table at L682-691 is intact). `CLAUDE.md:95-109` lists 13 guards. `CHANGELOG.md:62` still reads "Guard count expanded from 7 to 12 with CUA Gateway guards". `crates/libs/clawdstrike/src/guards/` still hosts the canonical 13 — `PathAllowlistGuard`, `RemoteDesktopSideChannelGuard`, `InputInjectionCapabilityGuard` are absent from the README table.
**Aggressive cleanup:** REWRITE `README.md:680-691` to mirror `CLAUDE.md:95-109` verbatim. Add a single-source-of-truth `docs/guards.md` and have both README and CLAUDE.md include it via grep-fenced markers so they cannot drift again.

### [V-04] Policy schema version: README says 1.1.0/1.2.0/1.3.0; CLAUDE says 1.5.0; CONTRIBUTING says 1.1.0
**At HEAD:** Canonical answer from `crates/libs/clawdstrike/src/policy.rs:29-31`:
- `POLICY_SCHEMA_VERSION = "1.5.0"`
- `POLICY_SUPPORTED_SCHEMA_VERSIONS = ["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"]`

Doc drift confirmed: `README.md:628` quick-start YAML hard-codes `version: "1.3.0"`; `README.md:701` still says `Explicit 1.1.0 / 1.2.0 policy versions`; `README.md:705` mentions `1.2.0+`; `CLAUDE.md:91,113` say `1.5.0`; `CONTRIBUTING.md:126` says `schema v1.1.0`; `CONTRIBUTING.md:153` quick-start YAML says `version: "1.2.0"`. Five docs, four numbers, none agree.
**Aggressive cleanup:** REWRITE all root docs to cite `1.5.0` as the current schema and `1.1.0–1.5.0` as supported. Add a CI test that greps every `*.md` for `version: *"1\.[0-9]+\.[0-9]+"` and diffs against the constants in `policy.rs`. Bonus: have `policy.rs` emit the supported-versions list to `target/policy-schema.json` at build time and have docs reference it.

### [V-05] Three Discord invite URLs across three docs
**At HEAD:**
- `README.md:11` → `discord.gg/fdbCZHm8zM`
- `CONTRIBUTING.md:6` → `discord.gg/tWKSGCvq`
- `GOVERNANCE.md:99` → `discord.gg/clawdstrike` (vanity URL, almost certainly placeholder)

**Aggressive cleanup:** Pick one. Replace the other two with a relative link to the README badge. Verify the chosen invite resolves (curl-test the redirect to `discord.com`).

### [V-06] Smart-quote + rogue backtick at `CONTRIBUTING.md:6`
**At HEAD:** Line 6 raw bytes: `If you’d like to discuss ideas, ask questions\`, or coordinate work, you are very welcome to join our Discord server: [clawdstrike Discord](https://discord.gg/tWKSGCvq).` The curly apostrophe (`’`, U+2019) and the rogue backtick after `questions` are both present. Hexdump confirms UTF-8 smart-quote bytes.
**Aggressive cleanup:** REWRITE the line to ASCII: `If you'd like to discuss ideas, ask questions, or coordinate work, join our Discord server: ...`. Add a CI grep for `[\x{2018}-\x{201F}]` across `*.md` to fail on smart quotes.

### [V-07] CONTRIBUTING tells contributors `cd apps/desktop && npm run tauri dev`
**At HEAD:** `CONTRIBUTING.md:77-81` still uses `npm`. `mise.toml:53-57` uses `bun install --frozen-lockfile && bun run tauri:dev` for the same directory. `AGENTS.md:27` uses `npm --prefix apps/desktop`. Three different invocation patterns for one app.
**Aggressive cleanup:** REWRITE `CONTRIBUTING.md:77-81` to a single sentence: `Desktop and agent Tauri apps: use 'mise run test:apps' (it knows bun vs npm per surface).` Delete the three bespoke snippets.

### [V-08] Confusion over which app is "the" app (agent vs desktop vs workbench)
**At HEAD:** `apps/` contains 8 entries: `academy/ agent/ cloud-dashboard/ control-console/ desktop/ README.md terminal/ workbench/`. `README.md:252,280,1107` push contributors at `apps/agent`. `CONTRIBUTING.md:78` walks them through `apps/desktop`. `AGENTS.md:27,32,50` reference `apps/desktop` and `apps/academy`. None of them mention `apps/cloud-dashboard/`, `apps/terminal/`, or `apps/workbench/`.
**Aggressive cleanup:** DOCUMENT once in README: which app is canonical for which audience (operator/SOC/contributor/researcher). RESTRUCTURE: collapse `apps/cloud-dashboard` and `apps/control-console` if they are the same thing under two names, or document the split.

### [V-09] Broken image `README.md:27` → `.github/assets/divider.png`
**At HEAD:** `ls .github/assets/divider.png` → no such file. The `.github/assets/` dir has `clawdstrike-helm-architecture.png`, `clawdstrike-hero-2.png`, `clawdstrike-hero.png`, `clawdstrike-icon.png`, `sigils/`. No `divider.png`. README still references it at L26-28 → renders as broken-image icon on GitHub.
**Aggressive cleanup:** WIPE `README.md:26-28`. Plain markdown `---` rule is sufficient.

### [V-10] Tracked junk at repo root: `.env`, `.DS_Store`, `.tmp-release-venv/`, `.playwright-cli/`, `coverage/`, `tmp/`, `output/`, `.worktrees/`
**At HEAD:** All present, all dated before the audit:
- `.env` (199 bytes, untracked — but see N-01, it contains a live API key)
- `.DS_Store` (6,148 bytes, untracked, plus `apps/.DS_Store` and `infra/.DS_Store` recursively)
- `.tmp-release-venv/` (untracked, last touched Mar 4)
- `.playwright-cli/` (untracked, 23 log files from Mar 7)
- `coverage/` (untracked, empty since Mar 20)
- `tmp/imagegen-venv/` (untracked, Feb 11)
- `output/playwright/` (untracked, Mar 7)
- `.worktrees/pr180-clone/`, `.worktrees/pr180-followup/` (untracked, May 20-21)

**Aggressive cleanup:** WIPE every one. `rm -rf .DS_Store .env .tmp-release-venv .playwright-cli coverage tmp output .worktrees` then `find . -name .DS_Store -not -path './.git/*' -delete`. Add an `mise run clean` task that does this on demand. Add the `apps/.DS_Store`-style nested DS_Stores to `.gitignore` even though `.DS_Store` is already there (the entry at `.gitignore:55` is naked, not `**/.DS_Store`).

### [V-11] Two competing lockfiles tracked
**At HEAD:** `bun.lockb` (439,144 bytes) and `package-lock.json` (610,622 bytes) both at root. `package.json:1-38` declares a 26-entry `workspaces:` array AND has no `packageManager` field. `mise.toml:53,57` uses `bun` for desktop, `npm` for control-console.
**Aggressive cleanup:** Pick one. Per the per-app split in mise.toml, the most honest answer is to delete the root `package.json`'s `workspaces:` entirely and have each app maintain its own lockfile. Then delete both root lockfiles. If you want a true monorepo, pick bun, delete `package-lock.json`, add `"packageManager": "bun@<sha>"`.

### [V-12] `Cargo.toml`: vendored `async-nats` via `[patch.crates-io]` with no rationale
**At HEAD:** `Cargo.toml:188-189`:
```
[patch.crates-io]
async-nats = { path = "infra/vendor/async-nats" }
```
No comment block. Memory says it's for offline builds, but a reader of `Cargo.toml` has no signal. `infra/vendor/async-nats/` is heavily edited per `git status` (the audit's lockfile-churn evidence).
**Aggressive cleanup:** DOCUMENT inline. Add a 3-line comment matching the `deny.toml` rationale-with-expiry pattern (owner, expiry date, upstream PR link, reason). Better: delete the patch and use the upstream `async-nats` since the project is supposedly OSS — if it cannot, the deviation deserves its own ADR in `docs/plans/decisions/`.

### [V-13] `Cargo.toml`: `nono` workspace dep with zero context
**At HEAD:** `Cargo.toml:182` `nono = { path = "infra/vendor/nono", version = "0.11.0", default-features = false }`. Path-only crate. No member entry, no comment, no doc cross-ref. Per memory it's "kernel-level sandboxing"; the manifest doesn't say.
**Aggressive cleanup:** DOCUMENT with an inline comment OR move the dep to the single crate that uses it (likely `crates/libs/clawdstrike`) instead of leaking it to workspace scope. Workspace scope is a "everyone reads this" surface.

### [V-14] Two Dockerfiles at repo root
**At HEAD:** `Dockerfile.hushd` (67 lines, tracked), `Dockerfile.registry` (51 lines, tracked). `infra/docker/` already contains 7 sibling Dockerfiles (`Dockerfile.auditd-bridge`, `Dockerfile.control-api`, `Dockerfile.eas-anchor`, `Dockerfile.hubble-bridge`, `Dockerfile.k8s-audit-bridge`, `Dockerfile.spine`, `Dockerfile.tetragon-bridge`). `CONTRIBUTING.md:115` says infra lives in `infra/docker/`. These two are orphans.
**Aggressive cleanup:** RESTRUCTURE. `git mv Dockerfile.hushd Dockerfile.registry infra/docker/`. Update CI workflows that reference them (must verify in scope D02).

### [V-15] `.rustfmt.toml`: dead nightly-only commented config
**At HEAD:** `.rustfmt.toml:5-8`:
```
# Note: imports_granularity and group_imports require nightly
# Uncomment when using nightly toolchain:
# imports_granularity = "Crate"
# group_imports = "StdExternalCrate"
```
Project pins stable Rust 1.93 via `mise.toml:2`. The comment has been there since 2026-02-09.
**Aggressive cleanup:** WIPE lines 5-8.

### [V-16] `clippy.toml`: one knob, no rationale
**At HEAD:** `clippy.toml` is exactly `cognitive-complexity-threshold = 30\n` (36 bytes). Default is 25. No comment.
**Aggressive cleanup:** Either DELETE the file and let clippy use default 25 (which would surface honest complexity hotspots — exactly what an aggressive cleanup wants), or DOCUMENT with one line: `# Raised from 25 because <crate-or-function-name> exceeds default after <PR>; revisit when <work> lands.`

### [V-17] `mise.toml`: `/tmp/hushpy-venv` and hard-coded `~/.elan/bin/lake`
**At HEAD:** `mise.toml:81` `VENV_DIR="${VENV_DIR:-/tmp/hushpy-venv}"`. `mise.toml:152` `cd formal/lean4/ClawdStrike && ~/.elan/bin/lake build`. Both confirmed.
**Aggressive cleanup:** REWRITE. `VENV_DIR="${VENV_DIR:-.tooling/hushpy-venv}"` (gitignored). Drop the elan prefix: just `lake build` and let PATH resolve.

### [V-18] `mise.toml`: `ci` task duplicates `test:apps` body
**At HEAD:** `mise.toml:50-63` (`test:apps`) shares the desktop install/typecheck/test/build/check block with `mise.toml:114-129` (`ci`). No `depends = [...]` reuse.
**Aggressive cleanup:** REWRITE `[tasks.ci]` to `depends = ["fmt-check", "lint", "test", "test:apps", "guardrails"]` and drop the inline `run = "..."` body.

### [V-19] CHANGELOG has 0.1.2 → 0.2.6 jump with no 0.1.3–0.2.5 entries
**At HEAD:** `CHANGELOG.md` ordering: `## [Unreleased]` (L8) → `## [0.2.7] - 2026-03-18` (L12) → `## [0.2.6] - 2026-03-16` (L27) → `## [0.1.2] - 2026-02-26` (L47) → `## [0.1.1] - 2026-02-10` (L80). The compare-link block at L94-98 confirms the same set: Unreleased, 0.2.7, 0.2.6, 0.1.2, 0.1.1. No 0.1.3, 0.2.0, 0.2.1, 0.2.2, 0.2.3, 0.2.4, 0.2.5. Compare link for 0.2.6 references `v0.2.5...v0.2.6` (L96), implying 0.2.5 existed as a tag but never landed a changelog entry.
**Aggressive cleanup:** DOCUMENT. Either backfill or add `## [0.2.0 - 0.2.5]` block stating "internal cuts; no public release notes". Add `git tag` validation in CI that fails the release pipeline if `CHANGELOG.md` doesn't contain the new tag.

### [V-20] `CHANGELOG.md` Unreleased: "No unreleased changes yet"
**At HEAD:** `CHANGELOG.md:10` literal text: `- No unreleased changes yet.` Last release entry is 2026-03-18 (`0.2.7`). Two-plus months of work (the commits validated in this delta range from 2026-03 through 2026-05) have not been changelogged.
**Aggressive cleanup:** DOCUMENT. Backfill from merged PRs since 0.2.7. Add a checklist item to `.github/PULL_REQUEST_TEMPLATE.md` (verify in D02 scope) requiring CHANGELOG entries for user-facing changes.

### [V-21] `.gitignore`: `.planning/` appears 4 times (audit said 3)
**At HEAD:** `grep -n "\.planning" .gitignore` returns lines 45, 76, 77, 112. The original said "three times" but listed four references at lines 45, 76, 77, 112. The "three" was a count error; the file paths cited were right.
**Aggressive cleanup:** WIPE duplicates. Single `.planning/` and `**/.planning/` block at one location, with a one-line comment explaining what `.planning/` is (GSD planning artifacts per CLAUDE.md memory).

### [V-22] `.planning/` is gitignored but `.planning/PROJECT.md` etc. are tracked
**At HEAD:** `git ls-files .planning/` returns `PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`. `.gitignore:45` says `.planning/` is ignored. The files predate the ignore but were never `git rm`d.
**Aggressive cleanup:** Choose one path: either `git rm` the four files (they look like GSD scratch artifacts that don't belong in the public OSS history), OR delete the `.planning/` lines from `.gitignore`. Don't have both.

### [V-23] `AGENTS.md:25` claims "no root JS workspace"
**At HEAD:** `AGENTS.md:25` literal: `TypeScript packages are built/tested per-package (no root JS workspace):`. But `package.json:7-31` has a 26-entry `workspaces:` array (verified). The claim is false.
**Aggressive cleanup:** REWRITE. Either delete the `workspaces:` array (consistent with the apparent per-package philosophy and aligns with V-11 cleanup) and keep the AGENTS line, or rewrite the AGENTS line to match reality.

### [V-24] `CLAUDE.md` as repo-root file
**At HEAD:** `CLAUDE.md` (8269 bytes, 163 lines) still at root. Adjacent AI-tool config: `.agents/skills/`, `.claude/`, `.claude-plugin/marketplace.json`, `.codex/agents/`, `.codex/config.toml`, `.codex/swarm/`. Plus `clawdstrike-plugin/` (Claude Code plugin package) and `cursor-plugin/` (Cursor plugin package) — both tracked as published artifacts. Root is an AI-tool zoo.
**Aggressive cleanup:** RESTRUCTURE. Move `CLAUDE.md` content to `docs/contributing/agents.md` or `.agents/CLAUDE.md`. Keep `AGENTS.md` as the canonical 10-line entrypoint that points to docs. The plugin packages can stay (they're products) but the proliferation of root-level AI configs (`.agents/`, `.claude/`, `.codex/`, `.claude-plugin/`) should consolidate under `.agents/`.

### [V-25] `CLAUDE.md` and `AGENTS.md` overlap and disagree
**At HEAD:** `CLAUDE.md:95` says 13 guards; `AGENTS.md` doesn't take a position. `CLAUDE.md:91,113` says schema 1.5.0; `AGENTS.md` doesn't. Both restate cargo fmt/clippy commands. Both list project structure with subtly different wording (e.g. `AGENTS.md:7` says `academy/, desktop/, agent/, control-console/, workbench/, …`; `CLAUDE.md:78-86` describes packages with different framing).
**Aggressive cleanup:** REWRITE `AGENTS.md` to ~10 lines: project name + 1-paragraph definition + pointer to `CLAUDE.md` (or the canonical doc). Delete the duplication.

### [V-26] `GOVERNANCE.md`: all 5 maintainer slots `(TBD)`
**At HEAD:** `GOVERNANCE.md:17-24` confirmed — 5 component-area rows, every "Maintainer" cell is `(TBD)` and every "GitHub" cell is empty. Combined with `CODEOWNERS` having `* @connor`, the "Maintainer Council" framing reads as aspirational.
**Aggressive cleanup:** REWRITE the section header to `## Roadmap to a Maintainer Council (no seats currently filled — see CODEOWNERS for active reviewers)` and either fill the table or delete it until you have at least one non-BDFL name.

### [V-27] `SECURITY.md` references three audit files dated 2026-02-10
**At HEAD:** `SECURITY.md:66-68` lists `docs/audits/2026-02-10-remediation.md`, `2026-02-10-wave2-remediation.md`, `2026-02-10-wave3-remediation.md`. Same naming pattern in `THREAT_MODEL.md:78-80`. Confirmed verbatim.
**Aggressive cleanup:** DOCUMENT. Add one sentence above the list: `These are pre-release internal security review remediations (not incident reports).` Fixes the misread risk.

### [V-28] No `.editorconfig`, no `.nvmrc`, no `rust-toolchain.toml`
**At HEAD:** All confirmed missing. The `find -maxdepth 1` confirms only `.rustfmt.toml` and `clippy.toml` exist as toolchain pins; everything else lives in `mise.toml`.
**Aggressive cleanup:** ADD all three (each 1-3 lines). `.editorconfig` solves V-06 at the editor layer. `rust-toolchain.toml = '1.93'` makes the project work with rustup users who don't run mise. `.nvmrc = '24'` does the same for Node. The cost is ~6 lines total.

### [V-29] `README.md` Yu et al arxiv link
**At HEAD:** `README.md:691,867` cite `[Yu et al. 2026](https://arxiv.org/abs/2602.05386)`. Verified the URL resolves (HTTP 200) and the paper title is "Spider-Sense: Intrinsic Risk Sensing for Efficient Agent Defense with Hierarchical Adaptive Screening". README never gives the title inline.
**Aggressive cleanup:** Add the title inline: `[Yu et al., "Spider-Sense: Intrinsic Risk Sensing for Efficient Agent Defense with Hierarchical Adaptive Screening" (2026)](...)`. Or move the citation to a `docs/research.md` bibliography and reference it once from README.

### [V-30] README enterprise section is 200+ lines
**At HEAD:** `README.md` lines 916-1080 confirmed — mermaid diagrams (L924-960), enrollment walkthrough, Spine envelope JSON example, kill-switch story (L1003-1027), control-console feature list, compliance mapping table (L1074-1078).
**Aggressive cleanup:** RESTRUCTURE. Move to `docs/enterprise/README.md`. Keep a 5-line block in README pointing at it.

### [V-31] `package.json` missing `name`, `description`, `repository`, `homepage`
**At HEAD:** `package.json:1-38` confirmed — `private: true`, `scripts`, `workspaces` only. No `name`, `description`, `repository`, `homepage`, `engines.npm`/`engines.bun`.
**Aggressive cleanup:** DOCUMENT four fields. Cost is 4 lines.

---

## FIXED SINCE 2026-05-23

None. The git log confirms HEAD has not advanced since 2026-05-19 (`2eff91532`), four days before the audit was written. Zero meta-cleanup commits have landed.

---

## NOW WRONG / MISDIAGNOSED

None substantive. The only wrinkle is the off-by-one on the `.planning/` duplicate count (audit said "three times", actual is four — see V-21). All other concrete file:line claims verified.

---

## NEW ISSUES (not in original)

### [N-01] LIVE OpenAI API key sitting in `.env` at repo root
**`.env:1`.** Untracked but on disk: a live `OPENAI_API_KEY=sk-proj-<REDACTED>` followed by `OPENAI_MODEL=gpt-5`. The full key bytes have been removed from this document; the user has been advised to rotate at the OpenAI API console. The original audit only flagged the `.env` file's existence at root as bad-look-but-harmless because it was gitignored. The actual key bytes are a real `sk-proj-*` token. This is in the working copy of the security-tool maintainer's machine and would appear in any `tar` of the repo, any backup, any IDE search across the workspace, and any subagent that runs `cat .env`.

**Recommendation:** REVOKE the key at OpenAI's API console **today** (rotate, don't just delete the file). Then `rm .env`. Then audit any historical revisions or tarballs that might have carried it. Add a pre-commit hook that scans for `sk-proj-`, `sk-ant-`, `ghp_`, `xoxb-`, AWS access-key prefixes. The project is literally a `SecretLeakGuard`-shipping security product — having an unrevoked OpenAI key in `.env` at root is the textbook embarrassing failure.

### [N-02] Empty `.cleanup-audit/` directory appeared today
**`.cleanup-audit/`.** Created today (2026-05-24, mtime matches `ls -la` output). Empty. Likely scaffold from this audit session. Should not stick around.
**Recommendation:** WIPE. `rmdir .cleanup-audit`.

### [N-03] Root `vendor/hushspec/`, `packs/{hipaa,pci-dss,soc2}/`, `clawdstrike-plugin/`, `cursor-plugin/` are unmentioned in any root meta doc
**Repo root.** Untracked-in-docs but present: `vendor/hushspec/` (one entry), `packs/{hipaa,pci-dss,soc2}/`, `clawdstrike-plugin/`, `cursor-plugin/`, plus `assets/` (containing `promo-reel.gif` and `capture-promo.mjs`), `examples/` (26 subdirs), `fixtures/` (15 subdirs), `tools/`, `integrations/`, `formal/`, `fuzz/`. Of those, `AGENTS.md:9-13` lists `infra/vendor/` but says nothing about a separate root-level `vendor/`. `.gitignore:109-111` literally says `vendor/` is ignored (`vendor/` then `!infra/vendor/` exclusions) — so the root `vendor/` directory exists in the working tree as gitignored content. `clawdstrike-plugin/` and `cursor-plugin/` are tracked plugin packages that no root doc explains.
**Recommendation:** DOCUMENT in one paragraph (likely in CONTRIBUTING.md's directory map) what `clawdstrike-plugin/`, `cursor-plugin/`, `packs/`, `assets/`, and `vendor/` (vs `infra/vendor/`) each contain. If `vendor/hushspec/` is actually consumed, move it under `infra/external/` (which was added in commit `d12066c32`, per `git log`).

### [N-04] `node_modules/` directly at repo root (483 entries)
**`./node_modules/`.** Present at the repo root, indicating that `npm install` (or similar) was run against the root `package.json` despite the per-package philosophy in AGENTS.md. `.gitignore:22` ignores `**/node_modules/`, so it's untracked, but its presence at root is a strong signal that the root workspace IS in use (contradicting AGENTS.md, V-23). The folder has 483 entries.
**Recommendation:** RESTRUCTURE first (decide root workspace yes/no per V-11), THEN add a `mise run clean` task that removes root `node_modules/` along with the other cruft.

---

## AGGRESSIVE EXECUTION PLAN (top-5 highest-leverage actions in THIS area)

1. **Revoke the OpenAI key and nuke the cruft.** Revoke `sk-proj-Xg1...` at the OpenAI API console (5 min). Then: `rm -rf .env .DS_Store .tmp-release-venv .playwright-cli coverage tmp output .worktrees .cleanup-audit && find . -name .DS_Store -not -path './.git/*' -delete && rm -rf node_modules`. Add a `[tasks.clean]` block to `mise.toml`. Risk: low. Effort: 15 min. Commit count: 1.

2. **Rewrite README from scratch to ~250 lines.** Target structure: 1-paragraph definition (rip from `README.md:84`) → install snippet (rip from `README.md:158-250`) → 30-line quickstart → guard table (mirror `CLAUDE.md:95-109` exactly) → links to deeper docs in `docs/`. Move the poem, sigils, divider, hero PNG, enterprise architecture (L916-1080), compliance tables, observe-synth walkthrough, Spider-Sense quick-start, and reel GIF to `docs/enterprise/`, `docs/getting-started/`, `docs/research.md`, etc. Delete `assets/promo-reel.gif` if unused. Risk: medium (some external blog posts deep-link to README anchors — verify before delete). Effort: 3-4 hours. Commit count: 2 (one for new README, one for docs/ relocation).

3. **Pick schema version + Discord URL + lockfile + app-canonical-story; rewrite all four root meta docs in lockstep.** Single big-cleanup PR: (a) schema 1.5.0 everywhere except where it explicitly enumerates the back-compat list, (b) one Discord URL (vote: keep `discord.gg/fdbCZHm8zM` from README; delete the other two), (c) bun-only — delete `package-lock.json` and add `"packageManager"` to `package.json`, (d) state "`apps/agent` is the canonical UI" at the top of README/CONTRIBUTING/AGENTS. Add a CI grep test in `scripts/path-lint.sh` (already wired into `mise.toml:97`) that fails on (i) schema version mismatch, (ii) more than one Discord URL across `*.md`, (iii) both lockfiles present, (iv) `’` U+2019 in any `*.md`. Risk: low (mechanical edits). Effort: 2 hours. Commit count: 1 (single sweep) or 4 (per concern).

4. **Move root Dockerfiles + add toolchain pins.** `git mv Dockerfile.hushd Dockerfile.registry infra/docker/`. Find and update any CI workflow that references the old path (likely 2-3 lines in `.github/workflows/*`; D02 scope). Then add `.editorconfig`, `.nvmrc` (=24), `rust-toolchain.toml` (=1.93) — three tiny files that match `mise.toml`. Risk: low. Effort: 30 min. Commit count: 1.

5. **Fix CHANGELOG + add release-checklist hook.** Backfill `[Unreleased]` with the merged-PR history since 0.2.7 (use `git log v0.2.7..HEAD --merges --pretty="- %s (%h)"`). Add `## [0.2.0 - 0.2.5]` placeholder block. Add `.github/PULL_REQUEST_TEMPLATE.md` checklist item: `- [ ] Updated CHANGELOG.md [Unreleased] section for user-facing changes`. Risk: low. Effort: 1 hour. Commit count: 1.

---

## DEFER / OUT OF SCOPE

- **`.github/` contents** (workflows, issue templates, CODEOWNERS, dependabot) — D02 (CI/CD & infra) territory.
- **`infra/vendor/` heavy uncommitted edits** — see `git status` showing M edits to addr2line, cranelift, etc. The original audit hand-waved this; the actual diff content is a D02 scope problem.
- **`apps/desktop` vs `apps/agent` vs `apps/workbench` Tauri ergonomics** — D07 (Tauri desktop apps) scope.
- **`docs/audits/2026-02-10-*-remediation.md`** content — D08 (docs/formal/examples) scope.
- **`crates/libs/clawdstrike/src/policy.rs:1842` validation logic** — D03 (Rust core libs) scope.
- **`rulesets/*.yaml` version-string drift** (1.1.0 / 1.2.0 / 1.4.0 across files) — surfaced here as evidence for V-04 but the rulesets themselves are D09 scope.
- **`scripts/path-lint.sh`, `scripts/move-validation.sh`, `scripts/architecture-guardrails.sh`** — referenced from `mise.toml:97-99` but their content is D02 / D09 scope.
