# Top-Level Meta Audit

**Repo**: `/Users/connor/Medica/backbay/standalone/clawdstrike/`
**Date**: 2026-05-23
**Scope**: Root-level meta, docs, and tooling config only.

---

## Executive Summary

A senior engineer who lands on this repo will see a polished hero image, a wall of badges, and a poem before they find out what the project does. The README is **1,126 lines** — roughly the size of a small book chapter — and it tries to be the landing page, the marketing site, the multi-language quick start, the architecture deck, the compliance brochure, and the enterprise sales sheet all at once. It opens with `<em>The claw strikes back. / At the boundary between intent and action, / it watches what leaves, what changes, what leaks.</em>` That is exactly the AI-marketing-poem energy this audit is meant to flag. The actual one-line definition ("a fail-closed policy engine and cryptographic attestation runtime for AI agent systems") doesn't appear until line 84, buried under sigils, vertical dividers, and prose like "EDR for the age of the swarm. Fail closed. Sign the truth."

The bones underneath are surprisingly solid for an OSS project — Apache-2.0 LICENSE present, NOTICE present, SECURITY.md present and well-structured, GOVERNANCE.md present (BDFL model declared honestly), CHANGELOG present and Keep-a-Changelog formatted, CODE_OF_CONDUCT pinned to Contributor Covenant 2.1, deny.toml with rationale and expiry on every ignore, cargo workspace cleanly organized, clippy `unwrap_used = "deny"`. Whoever set up the meta scaffolding did the right things. What's killing the first impression is **(a)** the README is theatrical instead of professional, **(b)** the docs do not agree with each other on basic facts (guard count, policy schema version, Discord URL, packaging layout), and **(c)** the working tree leaks a lot of operator-of-this-machine cruft (`.env`, `.DS_Store`, `.tmp-release-venv/`, `.playwright-cli/`, `.worktrees/`, `tmp/`, `output/`, `coverage/`) that should never have been there.

Net: the structure is 70% there, the prose is the problem. This is fixable in a focused day of editing, not a re-architecture. Three changes — rewrite the README from scratch as a real OSS README, reconcile the schema/guard/discord drift, and nuke the on-disk cruft — would move the first-impression score from "boutique-startup-trying-too-hard" to "I'd contribute to this."

---

## Scores

- **Professionalism / First impression: 5/10** — Strong meta files undermined by a theatrical README and stale, contradictory facts.
- **README quality: 3/10** — 1,126 lines, poem opener, three competing taglines, dead anchor refs, undefined guards in the table, missing image, schema version off.
- **Open-source readiness: 7/10** — LICENSE, NOTICE, CODE_OF_CONDUCT, GOVERNANCE, SECURITY, CONTRIBUTING, CODEOWNERS, dependabot, PR template, issue templates — all present. Governance is honest about being BDFL + TBD council.
- **Config/tooling hygiene: 5/10** — `Cargo.toml`, `deny.toml`, `mise.toml`, `biome.json`, `clippy.toml`, `.rustfmt.toml` all reasonable. But two competing JS lockfiles tracked, no root `tsconfig.json` despite TS packages, no `rust-toolchain.toml`, no `.editorconfig`, `Dockerfile.*` parked at repo root, vendored crate via `[patch.crates-io]`.
- **Doc consistency: 3/10** — Policy schema is `1.1.0`, `1.2.0`, `1.3.0`, and `1.5.0` depending on which doc you read. Guard count is 12 or 13. Discord has three different invite codes. CONTRIBUTING says `apps/desktop` exists; AGENTS.md says the desktop is in a different scaffold; both are right because they describe different things and never reconcile.

---

## Strengths

- **Apache-2.0 LICENSE** present and full, plus matching `NOTICE`. Copyright year `2026` is current.
- **SECURITY.md** is genuinely good: preferred channel is GitHub Security Advisories (correct), backup email, response SLOs, scope statement, threat-model cross-ref.
- **CHANGELOG.md** follows Keep-a-Changelog with `[Unreleased]`, semver tags, and footer compare links. Most projects don't bother.
- **GOVERNANCE.md** is honest: explicitly BDFL + "Maintainer Council (TBD)" instead of inventing a fake committee. Includes RFC process, security-review requirements, and a planned evolution path (Steering Committee → CNCF Sandbox).
- **deny.toml** documents each `RUSTSEC-*` ignore with owner, expiry, and rationale — that's mature supply-chain hygiene.
- **THREAT_MODEL.md** and **NON_GOALS.md** exist and are short, explicit, and credible. The deliberate "we do not claim..." framing in NON_GOALS is exactly what you want from a security tool.
- **`Cargo.toml`** workspace is clean: every member explicitly listed, `[workspace.package]` central, `[workspace.lints.clippy] unwrap_used = "deny" / expect_used = "deny"`, `[profile.release] lto = true, codegen-units = 1`.
- **`mise.toml`** centralizes toolchain pins (rust 1.93, node 24, python 3.12) and most tasks are functional and well-described.
- **`CODEOWNERS`** exists and is honest ("Replace @connor with org teams as they are formalized").

---

## Findings

### [CRITICAL] README: theatrical opening that hides what the project does
- **Where**: `README.md:1-83`
- **What**: The first 83 lines are: a hero PNG, 8 badges, a 5-line italic poem (`"The claw strikes back. / At the boundary between intent and action, / it watches what leaves, what changes, what leaks. / Not 'visibility.' Not 'telemetry.' Not 'vibes.' Logs are stories; proof is a signature. / If the tale diverges, the receipt won't sign."`), a divider image, two SVG sigils with light/dark variants, an `<h1>` 35 lines into the document, a second tagline (`"EDR for the age of the swarm. Fail closed. Sign the truth."`), five inline icon+text capability chips, a four-link nav row, a `---`, another GIF, and only THEN — at line 84 — does it say what Clawdstrike actually is. A senior engineer scrolls past this assuming it's a marketing site fork.
- **Why it matters**: First impression. This is the file 90% of evaluators will judge the project by. Every OSS project in the top tier (ripgrep, sqlx, axum, tokio, sled, polars) opens with a one-paragraph definition above the fold. Yours opens with a 5-line poem.
- **Recommended action**: REWRITE. Target 200-300 lines max. Structure: 1-paragraph definition → install → 30-line minimum quick start → core capabilities table → links to deeper docs. Move the brand identity, the architecture diagrams, the compliance mapping, the enterprise architecture, the adaptive engine prose, and the "Observe→Synth→Tighten" walkthrough into `docs/`.
- **Effort**: medium (1 focused afternoon).

### [CRITICAL] README: three taglines, none of them say what it is
- **Where**: `README.md:18-22, 38-39, 84`
- **What**: Reader gets bombarded with: (1) "The claw strikes back. / At the boundary between intent and action..." (2) "EDR for the age of the swarm. Fail closed. Sign the truth." (3) "Clawdstrike is a fail-closed policy engine and cryptographic attestation runtime for AI agent systems." Only #3 is a sentence a procurement reviewer can paste into a slack message.
- **Why it matters**: A project with three taglines has no tagline. "EDR for the age of the swarm" is genre-fiction-coded; competing analysts will not parse it as a product category.
- **Recommended action**: REWRITE. Keep #3. Delete #1 and #2. If you want a flavor line, put it under the H1 in one line, no italics.
- **Effort**: trivial.

### [HIGH] README: guard table contradicts the rest of the docs
- **Where**: `README.md:680-691`
- **What**: The "Guard Stack" table lists **10 guards** (ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool, PromptInjection, Jailbreak, ComputerUse, ShellCommand, SpiderSense). `CLAUDE.md:97-109` lists **13 guards** (adds PathAllowlist, RemoteDesktopSideChannel, InputInjectionCapability). `CHANGELOG.md:62` says "Guard count expanded from 7 to 12 with CUA Gateway guards" as of 0.1.2 (2026-02-26). Three docs, three numbers.
- **Why it matters**: The product positioning literally has a different surface area depending on which file you read. Anyone evaluating Clawdstrike against a competitor cannot tell what's shipping.
- **Recommended action**: DOCUMENT + REWRITE. Decide the canonical count (it appears to be 13), then have the table in README mirror it. Stop describing guards in CHANGELOG narratives.
- **Effort**: small.

### [HIGH] Docs: policy schema version is 1.1.0, 1.2.0, 1.3.0, and 1.5.0 depending on file
- **Where**: `CLAUDE.md:91` (`v1.5.0, backward-compatible with v1.1.0`), `CONTRIBUTING.md:128` (`schema v1.1.0`), `README.md:628` quick-start YAML (`version: "1.3.0"`), `README.md:701` ("Explicit `1.1.0` / `1.2.0` policy versions")
- **What**: Four different "current schema version" answers across four root-level docs. The quick-start YAML in README literally hands users a 1.3.0 policy template while the prose two sections away promises only 1.1.0/1.2.0 are supported.
- **Why it matters**: If a user's first attempt at a Spider-Sense policy gets rejected because the schema field is wrong, they will conclude the README is hallucinated. (It is.)
- **Recommended action**: DOCUMENT. Pick the true current version. Update README, CLAUDE.md, CONTRIBUTING.md, and the quick-start YAML in lockstep. Add a CI guardrail (grep test) that fails if any root-level .md file mentions a schema version that doesn't appear in `crates/libs/clawdstrike/src/policy.rs`.
- **Effort**: small.

### [HIGH] Docs: three different Discord invite URLs
- **Where**: `README.md:11` (`discord.gg/fdbCZHm8zM`), `CONTRIBUTING.md:6` (`discord.gg/tWKSGCvq`), `GOVERNANCE.md:99` (`discord.gg/clawdstrike`)
- **What**: Three docs, three different invite codes. At most one is real; two are dead links. The GOVERNANCE one looks like a placeholder vanity URL that doesn't resolve.
- **Why it matters**: A new contributor who clicks the wrong link and hits "this invite is invalid" loses trust in everything else they read.
- **Recommended action**: DOCUMENT. Pick one canonical invite, put it in README, link to README from CONTRIBUTING and GOVERNANCE instead of duplicating.
- **Effort**: trivial.

### [HIGH] CONTRIBUTING.md: smart-quote + stray backtick typo in the second line
- **Where**: `CONTRIBUTING.md:6`
- **What**: `"If you'd like to discuss ideas, ask questions\`, or coordinate work, you are very welcome to join our Discord server..."` — note the curly apostrophe AND the rogue backtick after "questions". Looks like someone hit `<kbd>`</kbd>` instead of `,` and never noticed. This is the second sentence of the file new contributors read first.
- **Why it matters**: Tiny but extremely telling. Anyone reading this assumes nobody proofreads.
- **Recommended action**: REWRITE this one line. Audit the rest of CONTRIBUTING for smart quotes (Rust ecosystem convention is ASCII).
- **Effort**: trivial.

### [HIGH] CONTRIBUTING.md: tells contributors to `cd apps/desktop` to run Tauri
- **Where**: `CONTRIBUTING.md:77-81`
- **What**: Says `cd apps/desktop && npm install && npm run tauri dev`. But the actual desktop scaffold uses `bun install --frozen-lockfile` and `bun run tauri:dev` per `mise.toml:54-57`. The agent app — which the README treats as the recommended path — is at `apps/agent` and isn't mentioned at all in CONTRIBUTING.
- **Why it matters**: First-time contributor follows the doc, gets a `bun: command not found` or worse a half-installed npm tree, opens a "docs are wrong" issue, walks away.
- **Recommended action**: REWRITE the Desktop/Agent sections of CONTRIBUTING to match `mise.toml`. Better: tell people to just run `mise run test:apps`.
- **Effort**: small.

### [HIGH] README claims `apps/desktop/README.md` and `apps/agent/README.md` are authoritative; CONTRIBUTING describes things differently
- **Where**: `README.md:280` (`see [apps/agent/README.md]`), `CONTRIBUTING.md:77` (cd apps/desktop)
- **What**: README pushes users at the **agent**. CONTRIBUTING walks them through **desktop**. AGENTS.md mentions both plus a `workbench` and a `terminal` app. The result is four "the official UI is X" stories.
- **Why it matters**: Reviewer can't tell which app to install or trust.
- **Recommended action**: DOCUMENT. State once, at the top of README and CONTRIBUTING: "The user-facing surface is `apps/agent` (recommended). `apps/desktop` is the SOC console. `apps/workbench` is the policy IDE. `apps/control-console` is the web dashboard."
- **Effort**: small.

### [HIGH] README: broken image reference
- **Where**: `README.md:27` references `.github/assets/divider.png`
- **What**: That file does not exist. `ls .github/assets/divider.png` returns "No such file or directory." Renders as a broken-image icon on GitHub.
- **Why it matters**: Visible broken image on the README is the most embarrassing class of bug for a security project.
- **Recommended action**: WIPE. Remove the entire divider element (lines 26-28). Plain `---` markdown rules are fine.
- **Effort**: trivial.

### [HIGH] Tracked junk: `.env`, `.DS_Store`, `.tmp-release-venv/`, `.playwright-cli/`, `coverage/`, `tmp/`, `output/`, `.worktrees/`
- **Where**: repo root
- **What**: Root contains `.env` (199 bytes, untracked but present in working tree — explicitly named in `.gitignore` so at least it stops at the porcelain), `.DS_Store` (untracked), `.tmp-release-venv/` (untracked Python venv from a release dry-run), `.playwright-cli/` (untracked, Playwright console logs from March), `coverage/` (untracked, empty), `tmp/imagegen-venv` (untracked), `output/playwright` (untracked), `.worktrees/pr180-clone/`, `.worktrees/pr180-followup/` (untracked git worktrees). None are tracked, but they all live in the developer's working copy and will appear in any tarball, IDE search, or contributor's `ls`.
- **Why it matters**: Visible cruft on a security-tool root says "the maintainer's machine ≈ the repo." Also `.env` at root in a project literally about secret hygiene is a brutally bad look even if untracked.
- **Recommended action**: WIPE every one of these from the working tree. Add an `mise run clean` task that nukes them. Move `.env` into a `dev/` subdir or to `$XDG_CONFIG_HOME`. Add `.DS_Store` exclusion to a global gitignore template the team uses.
- **Effort**: trivial.

### [HIGH] Two competing JS lockfiles tracked: `bun.lockb` AND `package-lock.json`
- **Where**: `bun.lockb` (439 KB, tracked), `package-lock.json` (610 KB, tracked), `package.json` declares no packageManager field
- **What**: Both lockfiles are committed. `mise.toml` uses `npm` for `control-console` and `bun` for `desktop` (lines 54-57 vs 57-60). `package.json` declares an `npm` workspace list. AGENTS.md states "no root JS workspace" — directly contradicting the `workspaces:` array in `package.json:7-31`.
- **Why it matters**: Doubles dependency resolution. New contributors don't know which to use. CI cache is split. Whichever is stale silently rots until someone runs a build that uses it.
- **Recommended action**: DOCUMENT a single tool. If it's bun, delete `package-lock.json` and add `"packageManager": "bun@..."`. If npm, delete `bun.lockb`. Pick. Don't ship both.
- **Effort**: small (decision is hard; execution is trivial).

### [MEDIUM] `Cargo.toml`: vendored `async-nats` via `[patch.crates-io]`
- **Where**: `Cargo.toml:188-189`
- **What**: `async-nats = { path = "infra/vendor/async-nats" }`. No comment, no link to the upstream PR being carried, no expiry. The hand-maintained `infra/vendor/addr2line/` and dozens of other vendored crates also show heavy uncommitted edits per `git status`.
- **Why it matters**: Workspace-wide `[patch.crates-io]` of a major networking crate is a giant supply-chain footnote with zero justification in the manifest.
- **Recommended action**: DOCUMENT. Add a comment block above the patch explaining why (offline builds? carried fix?), link the upstream issue, set an expiry/owner like the `deny.toml` ignores do.
- **Effort**: trivial.

### [MEDIUM] `Cargo.toml`: `nono` dependency, no comment
- **Where**: `Cargo.toml:182` `nono = { path = "infra/vendor/nono", version = "0.11.0", default-features = false }`
- **What**: A path-only internal crate called `nono` is declared at workspace scope. It is not a member, not documented anywhere at root. Per memory notes this is "kernel-level sandboxing" but that's invisible to a reader of `Cargo.toml`.
- **Why it matters**: Untracked feature surface; reviewer doesn't know what they're agreeing to.
- **Recommended action**: DOCUMENT with a comment, or move to a per-crate dep where it's actually used.
- **Effort**: trivial.

### [MEDIUM] Two Dockerfiles at repo root
- **Where**: `Dockerfile.hushd`, `Dockerfile.registry`
- **What**: Both Dockerfiles sit at the root. CONTRIBUTING.md:114-118 says infra lives in `infra/docker/`. So either the docs lie or these are stragglers.
- **Why it matters**: Repo root should be the "table of contents." Two random Dockerfiles muddy that signal.
- **Recommended action**: RESTRUCTURE. Move both to `infra/docker/` and update any references.
- **Effort**: small.

### [MEDIUM] `.rustfmt.toml`: dead config comments
- **Where**: `.rustfmt.toml:5-8`
- **What**: Includes commented-out nightly-only options (`imports_granularity`, `group_imports`) with a "Uncomment when using nightly" note. The project pins stable Rust 1.93. The comment is permanent dead weight.
- **Why it matters**: Tiny, but signals "this was tinkered with and abandoned."
- **Recommended action**: WIPE the commented lines. If you ever want them, git history has them.
- **Effort**: trivial.

### [MEDIUM] `clippy.toml`: one knob, no rationale
- **Where**: `clippy.toml:1`
- **What**: Contains only `cognitive-complexity-threshold = 30`. Default is 25. No comment on why the bump.
- **Why it matters**: Loosening a lint without a comment looks like a "shut clippy up" tactical retreat.
- **Recommended action**: DOCUMENT with a comment, or delete the override and let clippy warn at its default.
- **Effort**: trivial.

### [MEDIUM] `mise.toml`: `test:packages:py` creates a venv in `/tmp/hushpy-venv` and `verify-lean` hardcodes `~/.elan/bin/lake`
- **Where**: `mise.toml:81, 152`
- **What**: `test:packages:py` defaults `VENV_DIR=/tmp/hushpy-venv` — surviving across reboots is OS-specific (Linux clears /tmp on reboot, macOS doesn't). `verify-lean` invokes `~/.elan/bin/lake` directly, bypassing whatever `lake` the user has on PATH and assuming the elan layout.
- **Why it matters**: New contributor on macOS gets a stale `/tmp` venv. Contributor without elan can't run the verify-lean task at all even if they have `lake` installed via brew.
- **Recommended action**: REWRITE. Use a project-local `.tooling/venv/` (gitignored). Use `lake` from PATH or check it like a prerequisite.
- **Effort**: small.

### [MEDIUM] `mise.toml`: `ci` and `test:apps` repeat the same `bun install / typecheck / test / build / cargo check` blocks
- **Where**: `mise.toml:50-63` (`test:apps`), `mise.toml:114-129` (`ci`)
- **What**: Three of the four steps in `ci` are also in `test:apps`. No `depends = ["test:apps", ...]`. Drift risk.
- **Why it matters**: When someone adds a new typecheck step they'll add it to one place and forget the other.
- **Recommended action**: REWRITE `ci` to be `depends = [...]` over the smaller tasks.
- **Effort**: trivial.

### [MEDIUM] `CHANGELOG.md`: gap between 0.1.2 (Feb 26) and 0.2.6 (Mar 16). No 0.1.3 / 0.2.0 / 0.2.1 / ... entries
- **Where**: `CHANGELOG.md:46-47`
- **What**: Jumps `0.2.6 → 0.1.2`. No entries for 0.1.3, 0.2.0, 0.2.1, 0.2.2, 0.2.3, 0.2.4, 0.2.5. Either there were no releases (unusual for the volume of work in the 0.2.6 entry), or there were and the changelog is missing them. Compare links section also skips: `[0.2.6]: ...v0.2.5...v0.2.6`, implying 0.2.5 existed but has no entry.
- **Why it matters**: Changelog with holes is worse than no changelog — it makes downstream consumers think they're missing releases or that the project is opaque.
- **Recommended action**: DOCUMENT. Either backfill the missing release entries (preferred) or add an explicit `## [0.2.0 - 0.2.5]` block stating these were internal cuts not released to the public.
- **Effort**: small.

### [MEDIUM] `CHANGELOG.md`: `[Unreleased]` reads "No unreleased changes yet"
- **Where**: `CHANGELOG.md:8-10`
- **What**: Repo has clearly had work between 0.2.7 (Mar 18) and today (May 23). `git status` shows ~40+ modified files. The Unreleased section has zero entries.
- **Why it matters**: Either the project went quiet for two months (the commit log shows it didn't), or the changelog is not being maintained.
- **Recommended action**: DOCUMENT. Backfill `[Unreleased]` from the merged-PR history. Add a release-checklist item to `mise.toml` or `.github/PULL_REQUEST_TEMPLATE.md` reminding contributors to update CHANGELOG.
- **Effort**: small (with automation: medium).

### [MEDIUM] `.gitignore`: `.planning/` appears three times
- **Where**: `.gitignore:45, 76-77, 112`
- **What**: `.planning/` (line 45), `.planning/` again (line 76), `**/.planning/` (line 77), `.planning/` a fourth time (line 112). Plus comment redundancy. Suggests an automated tool kept appending.
- **Why it matters**: Lint hygiene. Looks careless.
- **Recommended action**: WIPE duplicates. One `.planning/` and one `**/.planning/` is sufficient.
- **Effort**: trivial.

### [MEDIUM] `.gitignore`: tracked `.planning/PROJECT.md` etc. exist despite `.planning/` being ignored
- **Where**: `.gitignore:45` says `.planning/` ignored, but `git ls-files .planning/` returns `PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`
- **What**: Files are committed in `.planning/` even though `.gitignore` claims to ignore that directory. Either the ignore is wrong or these files were `git add -f`ed and shouldn't have been.
- **Why it matters**: Contradictory state — repo-hygiene confusion.
- **Recommended action**: DOCUMENT. Either remove the gitignore entry (if `.planning/` IS meant to be tracked) or remove the tracked files. Don't have both.
- **Effort**: trivial.

### [MEDIUM] AGENTS.md says "no root JS workspace", `package.json` says yes
- **Where**: `AGENTS.md:25`, `package.json:7-31`
- **What**: `AGENTS.md:25` literally states `"TypeScript packages are built/tested per-package (no root JS workspace)"`. But `package.json` declares a 26-entry `workspaces:` array.
- **Why it matters**: Hot-and-cold guidance for any agent that reads this file. Also wrong.
- **Recommended action**: REWRITE the AGENTS.md line to match reality.
- **Effort**: trivial.

### [LOW] CLAUDE.md is a developer onboarding doc shipped in the repo root
- **Where**: `CLAUDE.md`
- **What**: Quality is fine, content is fine. But it's an `AI-tool-specific instructions file` (instructions for Claude Code) checked in at the repo root next to your README. Other agent tools have their own (`AGENTS.md`, `.codex/agents`, `.claude-plugin/`, `.agents/skills`). The root is now an AI-tool zoo.
- **Why it matters**: Cumulative, this AI-tooling clutter says "this repo is configured to be consumed by 5 different AI assistants" which is not an elite-OSS signal.
- **Recommended action**: RESTRUCTURE. Move all AI-tool config under a single `.agents/` (or `.ai/`) dir. Keep `CLAUDE.md` content but move it to `.agents/CLAUDE.md` and add a small `AGENTS.md` at root that points to the canonical CONTRIBUTING.
- **Effort**: small.

### [LOW] `CLAUDE.md` and `AGENTS.md` partially overlap and disagree
- **Where**: `CLAUDE.md`, `AGENTS.md`
- **What**: Both list project structure, commands, conventions. CLAUDE says 13 guards; AGENTS doesn't mention count. CLAUDE references schema `1.5.0`; AGENTS doesn't take a position. Both restate `cargo fmt` / `cargo clippy`.
- **Why it matters**: Two source-of-truth files for the same audience (agents).
- **Recommended action**: DOCUMENT. Make AGENTS.md a 10-line pointer at CLAUDE.md (or vice versa).
- **Effort**: trivial.

### [LOW] `GOVERNANCE.md`: every "Maintainer" entry is `(TBD)` with no GitHub handle
- **Where**: `GOVERNANCE.md:17-24`
- **What**: Maintainer Council table has 5 rows, all `(TBD)`. Honest, but visible. Combined with `CODEOWNERS` having `* @connor` it makes the "Council" framing feel aspirational rather than active.
- **Why it matters**: Reviewers see "Maintainer Council" + zero maintainers and conclude the governance is paper.
- **Recommended action**: REWRITE. Either remove the table until you have real names, or label it explicitly: `## Roadmap to a Maintainer Council (no seats currently filled)`.
- **Effort**: trivial.

### [LOW] `SECURITY.md` references THREE different audit files
- **Where**: `SECURITY.md:65-67`
- **What**: Lists `docs/audits/2026-02-10-remediation.md`, `...wave2-remediation.md`, `...wave3-remediation.md`. Same single date, "wave 2" and "wave 3". Reads like internal post-incident docs surfaced to public meta.
- **Why it matters**: Probably fine, but the naming makes a reader wonder if there was a series of breaches on 2026-02-10. A short one-sentence header in SECURITY explaining what these are would help.
- **Recommended action**: DOCUMENT with one sentence: "These are internal pre-release security review remediation reports."
- **Effort**: trivial.

### [LOW] No `.editorconfig`, no `.nvmrc`, no `rust-toolchain.toml`
- **Where**: repo root
- **What**: Project pins toolchains in `mise.toml`. But contributors who don't use mise (which is most of them — mise is niche compared to nvm/rustup) get no signal. `rust-toolchain.toml` is the cargo-native way to pin the rust version and would auto-honor across rustup users. `.nvmrc` is the universal node-pinning file. `.editorconfig` solves the smart-quote-in-CONTRIBUTING.md problem at the editor layer.
- **Why it matters**: Friction for non-mise contributors. Smart-quote drift.
- **Recommended action**: DOCUMENT (add the three files). They're 1-3 lines each.
- **Effort**: trivial.

### [LOW] README: arxiv reference looks fishy
- **Where**: `README.md:691, 867` — `[Yu et al. 2026](https://arxiv.org/abs/2602.05386)`
- **What**: arxiv IDs are `YYMM.NNNNN`. `2602.05386` would imply Feb 2026, which is plausible but worth verifying the link resolves. The paper title is never given inline; reader must click to find out what "S2Bench" is.
- **Why it matters**: Citation hygiene. If the link is dead the README looks like it's citing fake papers.
- **Recommended action**: DOCUMENT. Verify the link resolves; add the paper title inline: `[Yu et al., "Spider-Sense: ..." (2026)](https://arxiv.org/abs/2602.05386)`.
- **Effort**: trivial.

### [LOW] README spends 200+ lines on "Enterprise Architecture" before the contributor section
- **Where**: `README.md:916-1080`
- **What**: Two mermaid diagrams, enrollment walkthrough, Spine envelope JSON example, kill switch story, control console feature list, compliance mapping table — all in the README.
- **Why it matters**: This is sales-deck material in a contributor-facing doc.
- **Recommended action**: RESTRUCTURE. Move to `docs/enterprise/README.md`. Leave a single 5-line "For enterprise deployments see [docs/enterprise/]" block in the README.
- **Effort**: medium.

### [LOW] `package.json` is bare-bones (no `name`, no `description`, no `repository`)
- **Where**: `package.json:1-38`
- **What**: `{ "private": true, "scripts": {...}, "workspaces": [...] }` — no name, no description, no repository field, no homepage. Fine functionally for a private root, but `npm` tooling and many monorepo visualizers expect these.
- **Why it matters**: Minor polish.
- **Recommended action**: DOCUMENT. Add `name: "clawdstrike-monorepo"`, `description`, `repository`, `homepage`.
- **Effort**: trivial.

---

## Action Plan

In dependency order:

1. **Nuke the cruft.** Delete from working tree: `.DS_Store`, `.env`, `.tmp-release-venv/`, `.playwright-cli/`, `tmp/`, `output/`, `coverage/`, `.worktrees/`. Add an `mise run clean` task. (Trivial, do today.)
2. **Resolve the lockfile war.** Pick bun OR npm. Delete the other lockfile. Add `packageManager` to `package.json`. (Small, do today.)
3. **Fix the broken image and the smart-quote-backtick typo.** `README.md:27` and `CONTRIBUTING.md:6`. (Trivial.)
4. **Reconcile the schema version everywhere.** Pick the true value, update README × 2, CLAUDE.md, CONTRIBUTING.md, the quick-start YAML. Add a CI grep test. (Small.)
5. **Reconcile the guard count everywhere.** Update README table + CHANGELOG narrative + CLAUDE.md to one number. (Small.)
6. **One Discord URL.** Pick the live invite; update three files; in CONTRIBUTING and GOVERNANCE just link to README. (Trivial.)
7. **Rewrite README from scratch.** Target ≤300 lines. Structure: definition → install → minimum quick-start → capabilities → links. Move marketing/enterprise/compliance content to `docs/`. Delete the poem, the divider PNG, the 5 sigils, the 3 taglines, the GIF up top. Keep one badge row, one tagline, one paragraph definition. (Medium.)
8. **Sync CONTRIBUTING and AGENTS with reality.** Fix the `apps/desktop` vs `apps/agent` confusion. Fix `bun` vs `npm`. Fix the "no root JS workspace" lie in AGENTS.md. (Small.)
9. **Backfill CHANGELOG.** Add the missing 0.1.3–0.2.5 entries. Update `[Unreleased]` from recent git history. (Small to medium.)
10. **Restructure AI-tool config.** Move `CLAUDE.md`, `.agents/`, `.codex/`, `.claude-plugin/` content under one `.agents/` (or delete what isn't needed). Keep `AGENTS.md` as the canonical agent entrypoint. (Small.)
11. **Move Dockerfiles to `infra/docker/`.** (Small — needs CI ref updates.)
12. **Polish meta configs.** Add `.editorconfig`, `.nvmrc`, `rust-toolchain.toml`. Add comments to the `[patch.crates-io]` and `nono` entries in `Cargo.toml`. Add rationale to `clippy.toml`. (Trivial each.)
13. **Tighten GOVERNANCE.** Either fill the maintainer table with real names or rebrand it as "Maintainer Council (roadmap; no seats currently filled)". (Trivial.)
14. **Add a SECURITY one-liner** explaining the three `2026-02-10-*-remediation.md` audit refs. (Trivial.)

---

## Top 5 Quick Wins

Each < 30 minutes:

1. **Delete `.DS_Store`, `.env`, `.tmp-release-venv/`, `.playwright-cli/`, `tmp/`, `output/`, `coverage/`, `.worktrees/`** from the working tree. One shell command, immediate "this repo looks cared-for" upgrade.
2. **Remove the broken `divider.png` reference** at `README.md:26-28`. Three-line delete. Fixes a visible-on-GitHub broken image.
3. **Fix `CONTRIBUTING.md:6`** — replace smart quote, kill the rogue backtick, replace the Discord URL with the canonical one from README. Two-character edit + one-link edit.
4. **De-dupe `.gitignore`** — `.planning/` appears four times across the file. Five-line cleanup.
5. **Add comments to `Cargo.toml`'s `[patch.crates-io]`, `nono` dep, and `clippy.toml`'s threshold bump.** Each is one line; collectively they convert "weird, no idea why" into "intentional, with rationale" — exactly the senior-engineer signal you want.

---

## Things to Leave Alone

- **`LICENSE`.** Full Apache-2.0 text, correct. Don't touch.
- **`NOTICE`.** Correctly formatted, year-current, brief. Don't touch.
- **`SECURITY.md`** body. Disclosure channels, SLOs, scope are all right. Only add the one-sentence audit-file annotation suggested above.
- **`THREAT_MODEL.md`.** Tight, technical, no marketing-speak. Genuinely good.
- **`NON_GOALS.md`.** Excellent — explicitly enumerates what the project does NOT claim. Rare and valuable.
- **`deny.toml`.** Best file in the repo. The ignore rationale + owner + expiry pattern should be the template for any other config that ignores things.
- **`CODE_OF_CONDUCT.md`.** Contributor Covenant 2.1, real enforcement email, no fluff. Keep as is.
- **`.github/CODEOWNERS`.** Honest about being a bootstrap. The comment block explains why. Don't gild it.
- **Workspace `Cargo.toml` member list, lints, and profile.release.** Clean. Only add comments where flagged above.
- **`moon.yml`.** Functional, well-grouped with the `── Section ──` separators. Leave it.
- **`.gitattributes`.** One-liner, correct purpose (linguist-generated for vendored crates). Leave it.
