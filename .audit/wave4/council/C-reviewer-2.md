# Wave C Council — Reviewer 2 (lockfiles + docs)

**HEAD:** `7f97033caeb77cf0b123da9a4805fc73c58ab57f` (matches spec)
**Verdict:** CONCUR

## Check 1: Lockfile consolidation

**bun lockfiles found** (excluding `node_modules`, `target`, all worktree dirs, `infra/vendor`):
- `./clawdstrike-plugin/bun.lockb`
- `./cursor-plugin/bun.lockb`
- `./apps/terminal/bun.lockb`
- `./apps/desktop/bun.lockb`

All four are in directories that are **NOT** members of the root `workspaces` array
(verified in `package.json` lines 7-31 — neither `apps/desktop`, `apps/terminal`,
`clawdstrike-plugin`, nor `cursor-plugin` appears). These are independently
bun-managed sub-projects, which the executor explicitly flagged as intentional.

No `bun.lock` files exist outside `.claude/worktrees/` (which are sibling
worktrees from other branches and outside this branch's scope).

**Root state:** `ls -la` confirms exactly ONE root lockfile: `package-lock.json`
(610,622 bytes, dated 2026-05-14). `bun.lockb` and `bun.lock` are both absent.

**package-lock.json files found:** 19 (root + 18 workspace members):
- `./package-lock.json` (root)
- `./examples/{output-sanitization,prompt-watermarking,jailbreak-detection,spider-sense-threat-intel/typescript}/package-lock.json`
- `./packages/swarm-engine/package-lock.json`
- `./apps/{control-console,workbench}/package-lock.json`
- `./packages/adapters/clawdstrike-{openclaw,claude,langchain,broker-client,opencode,hushd-engine,openai,adapter-core,hush-cli-engine,engine-adaptive,vercel-ai}/package-lock.json`
- `./packages/sdk/hush-ts/package-lock.json`
- `./packages/dev/vite-plugin-clawdstrike/package-lock.json`
- `./packages/policy/clawdstrike-policy/package-lock.json`

`./formal/lean4/.../proofwidgets/widget/package-lock.json` exists but is inside
a vendored Lean dependency (`.lake/packages/proofwidgets`), not workspace-managed.

**Root `workspaces` declaration:** Present and well-formed (24 entries covering
`crates/libs/hush-wasm`, all SDK + adapter packages, `apps/control-console`,
`apps/workbench`, `apps/academy`, `packages/sdk/plugin-sdk`, etc.). Does NOT
include the four bun-managed directories — confirms the split is intentional.

**npm install --dry-run:** PASS. Output: `added 225 packages, and changed 16
packages in 2s`. No errors, no unmet peer-dep complaints in the tail. Resolves
cleanly.

## Check 2: CI usage

**bun in workflows** (`grep -rE 'bun (install|run|test|ci)' .github/workflows/`):
- `desktop-release.yml`: `bun install --frozen-lockfile`, `bun run typecheck`,
  `bun run tauri build` — all scoped to `apps/desktop` working dir.
- `ci.yml`: two distinct bun blocks. Lines 174-179 (`working-directory: apps/terminal`)
  run `bun install --frozen-lockfile`, `bun run typecheck`, `bun test`. Lines
  278-283 (`working-directory: apps/desktop`) run `bun install --frozen-lockfile`,
  `bun run typecheck`, `bun run test`, `bun run build`. There is also one
  `bun install --production --frozen-lockfile` inside a packaging stage that
  copies `apps/terminal/bun.lockb` into a `share/clawdstrike/tui/` payload
  (line 204) — that lockfile still exists on disk, so the reference is valid.

All bun usage is confined to the four non-workspace directories. Matches the
executor's note exactly.

**npm in workflows** (`grep -rE 'npm (ci|install|run|test)' .github/workflows/`):
- `release.yml`: `npm ci --ignore-scripts`, `npm run build -w "$pkg"`,
  `npm test -w "$pkg"`.
- `ci.yml`: 23 `npm ci` / `npm run typecheck` / `npm test` / `npm run build`
  invocations across multiple workspace stages. npm clearly dominates.

**workflows reference deleted bun.lockb:** 0. The only `bun.lockb` reference in
workflows is `apps/terminal/bun.lockb` (still present), copied during the
packaging stage. There are zero references to a root-level `bun.lockb` or to
`apps/workbench/bun.lock` (the two files the executor deleted).

## Check 3: Branch-rec doc accuracy

**Doc location:** `.audit/wave4/CLEANUP-BRANCHES-RECOMMENDATIONS.md` (203 lines,
created in commit `751ef593c`).

**Spot-check: `chore/cleanup-tier-ab`.** Doc claims HEAD `14aff0d5c` and lists
four cherry-pick candidates (`645c38501`, `ea6d5e9bd`, `ec8f79adc`, `733c69763`).
- `git log -1 chore/cleanup-tier-ab` confirms HEAD = `14aff0d5c Revert
  "docs(readme): rewrite from 1122 → 243 lines"` (matches).
- `git log -1 --format='%h %s' 645c38501 ea6d5e9bd ec8f79adc 733c69763` all
  resolve and have the subjects the doc cites:
  - `645c38501 chore(brand): replace default Tauri 'T' icons with ClawdStrike claw sigil`
  - `ea6d5e9bd refactor(ts): TS \`any\` Sprints 0+1 — 91 hits removed, zero typecheck regressions`
  - `ec8f79adc refactor(workbench): fold swarm-engine into workbench; drop dead subsystems`
  - `733c69763 chore(ci): harden permissions, concurrency, timeouts; matrix docker; pin trivy; consolidate audit`
  All four are factual.

**Spot-check: `chore/ts-sprints-23-deps-latest`.** Doc claims HEAD `ae564c1a2`
with rebase recommendation. `git log -1 chore/ts-sprints-23-deps-latest` confirms
HEAD = `ae564c1a2 fix(adapters): pick compat path for SDK version derivation
across Node 18.x` (matches).

**Spot-check: orphan branches.** Doc claims `chore/fix-security-deps`,
`chore/misc-cleanup`, and `chore/resolve-dependabot-alerts` have NO merge-base
with main. `git rev-parse` confirms the three HEAD hashes match the doc
(`e557e35ad`, `8aa59255d`, `c47584ae8`). `git merge-base
chore/fix-security-deps origin/main` returned empty output with exit 0,
confirming no common ancestor — the orphan-history claim is correct.

**`chore/cleanup-tier-ab` "PR #313 landed on main":** **Y — verified.**
`git log --oneline -50 origin/main` shows `c0ff91ed4 Tier A + B cleanup:
hygiene, security defaults, CI hardening, refactors (#313)`. PR #316
(`5689c70bb docs(readme): restore long-form README`) is also on main as the
doc states. Both citations are accurate.

**Recommendation specificity:** Each of the six branches has a labeled verdict
(CLOSE / REBASE FIRST / CHERRY-PICK), an effort estimate in hours, a scope
list with specific commit hashes, an explicit conflict analysis, and a
reasoning paragraph. The summary table at the end consolidates the verdicts.
This is specific, not vague.

## Check 4: Tauri icons doc

**Doc location:** `.audit/wave4/TAURI-ICONS-DECISION.md` (109 lines, commit `7f97033ca`).

**Names affected apps:** Y. Table on lines 12-15 names `apps/agent/src-tauri`
(productName `Clawdstrike Agent`, identifier `dev.clawdstrike.agent`),
`apps/desktop/src-tauri` (`Huntronomer`, `com.backbaylabs.clawdstrike.desktop`),
and `apps/workbench/src-tauri` (`ClawdStrike Workbench`, `com.clawdstrike.workbench`).

**Cites MD5 `9418b9b0e421e3ff0744aef7960f511c`:** Y, on line 20. **Independently
verified** — I ran `md5 -q apps/{agent,desktop,workbench}/src-tauri/icons/icon.png`
and got that exact hash three times. The other two cited hashes
(`65b5ef45ccb2efc1cd05fdf5d1e8b856` for icon.icns, `332a56695e4931ea0747be607be6014a`
for 32x32.png) are presented as the same byte-identical pattern, consistent
with the directory listing showing all seven file names in each of the three
icons/ directories.

**Lists icon variants per Tauri convention:** Y. Lines 48-59 enumerate
`icon.png`, `icon.icns`, `icon.ico`, `32x32.png`, `64x64.png`, `128x128.png`,
`128x128@2x.png` — exactly the 7-file Tauri scaffold layout. `ls
apps/*/src-tauri/icons/` confirms all three apps carry exactly these 7 files.

**Asks user clear questions:** Y. Lines 65-95 enumerate three explicit
decisions: (1) which shipping apps survive, (2) where brand assets live (with
a note that `chore/cleanup-tier-ab` carries commit `645c38501` as a candidate
cherry-pick), and (3) per-app vs unified mark with tradeoffs spelled out.

**Does not generate placeholders:** Y. `git show --stat 7f97033ca` shows the
commit touched ONE file: `.audit/wave4/TAURI-ICONS-DECISION.md` (+109 lines).
No icon files were created, modified, or replaced. No fake brand assets exist
anywhere on this branch (the doc explicitly flags the brand-asset search
returned no `.svg`/`.ai`/`.afdesign`/`.figma` results).

## Check 5: 5 atomic commits

**Commits in scope (`ed5e1b918..HEAD`):**
1. `779ac3554 docs: unify policy schema version to 1.5.0 across docs` — 16 files,
   all in `docs/src/`, `clawdstrike-plugin/`, `cursor-plugin/`, top-level
   README/CONTRIBUTING, and `crates/libs/clawdstrike/README.md`. Pure doc text
   updates.
2. `1b5cf512c fix(examples): align all example policies to supported schema versions` —
   22 files: 21 example `policy*.yaml` files in `examples/` + one new
   `scripts/validate-example-policies.sh`. Example-policy work only.
3. `9584a7e37 chore: consolidate to one package manager and remove duplicate lockfiles` —
   2 files deleted: `bun.lockb` (root, binary) and `apps/workbench/bun.lock`
   (981 lines). Nothing else.
4. `751ef593c docs: evaluate stale cleanup branches and recommend disposition` —
   1 file added: `.audit/wave4/CLEANUP-BRANCHES-RECOMMENDATIONS.md` (203 lines).
5. `7f97033ca docs: flag Tauri default-icon replacement decision for user` —
   1 file added: `.audit/wave4/TAURI-ICONS-DECISION.md` (109 lines).

**Atomicity:** Y. Each commit touches one logical concern. The schema-docs
commit (#1) does not also delete lockfiles. The lockfile commit (#3) touches
only the two stale lockfiles and nothing else — no schema text, no docs, no
config. The two doc commits (#4, #5) each add a single .md file. Subject lines
match the contents. Commit bodies provide adequate rationale.

## DISSENT log

None. All five checks pass cleanly. Findings:

- One minor observation: the lockfile commit body says CI uses
  `npm ci --ignore-scripts` against `package-lock.json` "everywhere else", which
  is accurate; the only npm command that scripts run is in `release.yml`. Not
  worth blocking on.

- The branch-rec doc estimates 2-3h for cherry-picking four commits off
  `chore/cleanup-tier-ab`. Those four commits include `ea6d5e9bd` (TS-`any`
  Sprints 0+1, 91 hits removed) which is plausibly multi-file and may take
  longer than 2-3h in practice. The estimate is plausible but optimistic; not
  a verdict-changer.

- I did not run `npm ci` (just `--dry-run`) because the spec said dry-run is
  sufficient and the resolver result is what matters for the consolidation
  claim. The dry-run output is clean.

## Final verdict

**CONCUR.** Wave C completes the stated scope: lockfile consolidation is real
(two files deleted, no remaining workspace duplicates, CI references match
reality, npm resolves cleanly), the branch-recommendations doc is accurate
and specific (every spot-checked claim verified against `git log`, PR #313's
landing on main is confirmed at `c0ff91ed4`), the Tauri icons doc names the
right apps with the correct MD5, enumerates the right 7-file variants, asks
the user the right questions, and creates zero placeholder assets. All five
commits are atomic and properly scoped.
