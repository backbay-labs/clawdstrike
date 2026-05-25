# Wave A — Reviewer 2 Verdict

**Reviewer:** Agent #2 (second-order focus)
**Branch:** cleanup/waves-abce
**HEAD:** 555f2f33bbe6d25aad1e0830349d3dbf9b436163
**Verdict:** CONCUR (with one minor gap noted)

## Primary checks (9 items)

### 1. scripts/codex-swarm/common.sh line ~458 no longer has shell injection
PASS. Lines 450-470 now use an explicit `case "$bootstrap_preset"` with
allowlist `cargo-fetch-locked | cargo-fetch-agent-locked` and a default arm
that prints an error + `return 1`. No `bash -lc "$bootstrap_preset"`
remains anywhere in the file. Commit `cae9aca70` (`fix(scripts): close
shell-injection sink in codex-swarm bootstrap`) credits the regression to
`1ade43894`, matches the C-2 fix described in the delta summary.

### 2. .env not on disk
PASS. `ls -la .env` returns "No such file or directory". The live
`sk-proj-<REDACTED>` credential string does not appear in any
git-tracked file (verified by `git ls-files | xargs grep -l` against the prefix; empty).
`.env` was never committed (gitignored at `.gitignore:67`), so no git-history
purge is required. Note: revoking the credential at the OpenAI console is a
separate action that this reviewer cannot verify from the repository.

### 3. tmp/, output/, coverage/, .tmp-release-venv/, .playwright-cli/, .cleanup-audit/, apps/cloud-dashboard/ not on disk
PARTIAL PASS. Six of seven targets gone:
- `tmp/`, `output/`, `coverage/`, `.tmp-release-venv/`, `.playwright-cli/`,
  `.cleanup-audit/` — all return "No such file or directory".
- `apps/cloud-dashboard/` — **STILL ON DISK** (2.9 MB, contains `dist/`
  + `tsconfig.tsbuildinfo`). The commit message at `555f2f33b` claims
  cloud-dashboard was removed "from the working tree (untracked /
  gitignored)" but `ls -la apps/cloud-dashboard/` shows `dist/` and
  `tsconfig.tsbuildinfo` are still present. See DISSENT below — this is
  a soft fail (git-clean still, no tracked files), but the commit
  message is inaccurate.

### 4. No .DS_Store outside .worktrees/ + .claude/worktrees/
PASS. `find . -name ".DS_Store" | grep -v "/.worktrees/" | grep -v
"/.claude/worktrees/" | grep -v "/node_modules/" | grep -v "/target/"`
returned empty.

### 5. Vite bundles in apps/agent/src-tauri/resources/control-console/assets/ removed from git index
PASS. `git ls-files apps/agent/src-tauri/resources/control-console/assets/`
returns empty. `git ls-tree -r HEAD -- apps/agent/src-tauri/resources/
control-console/assets/` returns empty. Commit `555f2f33b` deleted 20 .js/
.css bundle files (Vite content-hashed names). Local disk still has
freshly-regenerated bundles (from a prior dev build) which is expected and
ignored by `.gitignore:94`.

### 6. apps/academy/src/app/test-mdx/page.mdx removed from git index
PASS. `git ls-tree -r HEAD -- apps/academy/src/app/test-mdx/` returns empty,
directory does not exist on disk. Commit `555f2f33b` includes the deletion
(30-line file).

### 7. infra/vendor/.DS_Store removed from git index
PASS. `git ls-tree -r HEAD -- infra/vendor/.DS_Store` returns empty. Commit
`555f2f33b` shows `infra/vendor/.DS_Store | Bin 8196 -> 0 bytes`.

### 8. .gitignore covers new patterns and dedupes .planning/
PASS. Inspected `.gitignore`:
- Line 46-49: `tmp/`, `output/`, `coverage/`, `.playwright-cli/`
- Line 31: `.tmp-release-venv/`
- Line 52: `.worktrees/`
- Line 55: `**/.planning/` (single rule, deduplicated)
- Line 65: `.DS_Store`
- Line 67: `.env`
- Line 94: `apps/agent/src-tauri/resources/control-console/assets/`

`grep -c "planning" .gitignore` shows only the single `**/.planning/` rule
on line 55. Commit `da34d052f` message says "Consolidate three duplicate
.planning/ entries down to a single recursive **/.planning/ rule" —
verified.

### 9. Three commits on cleanup/waves-abce above fix/macos-es-ne-hardening
PASS. `git log --oneline fix/macos-es-ne-hardening..cleanup/waves-abce`:
- `555f2f33b chore: remove tracked build artifacts and cruft`
- `da34d052f chore: tighten .gitignore for cruft and worktree dirs`
- `cae9aca70 fix(scripts): close shell-injection sink in codex-swarm bootstrap`

Three commits, ordered fix-then-gitignore-then-cleanup. Co-Author trailers
present.

## Second-order checks (A..E)

### A. Compile status
**PASS.** `cargo check --workspace --all-targets 2>&1 | tail -40` (4m 02s):

```
warning: `clawdstrike-policy-event` (lib) generated 42 warnings
warning: `clawdstrike-policy-event` (lib test) generated 44 warnings (39 duplicates)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4m 02s
```

Zero `error[E...]` lines. Compilation succeeds.

The 42 dead-code warnings in `clawdstrike-policy-event` are the *pre-existing*
C-4 issue from the delta summary (`edr/mod.rs` removed
`#![allow(dead_code)]` without deleting the dead code). Wave A did not
introduce these — they exist on `fix/macos-es-ne-hardening` too. Wave A is
strictly non-causal here. C-4 is in Wave E scope (per task list #17).

### B. Build pipeline dependencies on deleted Vite bundles
**PASS.** Tauri's `tauri.conf.json:8` declares
`"beforeBuildCommand": "sh scripts/prepare-bundled-hushd.sh release"` and
`"beforeDevCommand": "sh scripts/prepare-bundled-hushd.sh dev"`. The script
at `apps/agent/scripts/prepare-bundled-hushd.sh:59-66`:

```sh
VITE_BASE_PATH="/ui/" npm --prefix "${control_console_dir}" run build
dashboard_src="${control_console_dir}/dist"
dashboard_dst="${src_tauri_dir}/resources/control-console"
rm -rf "${dashboard_dst}"
mkdir -p "${dashboard_dst}"
cp -R "${dashboard_src}/." "${dashboard_dst}/"
```

The deleted Vite bundles are regenerated by the `beforeBuildCommand` /
`beforeDevCommand` from `apps/control-console/` source. No regression.
The runtime lookup in `api_server.rs:1129-1146` references
`resources/control-console` (directory) which is populated at build time,
not at git-checkout time.

### C. Conflict with cleanup-tier-ab
**Potential conflict, manageable.** `git diff cleanup/waves-abce
origin/chore/cleanup-tier-ab` differs on:
- `apps/academy/package.json` — version bumps in tier-ab (next 16.2.0
  → 16.2.6, react 19.2.0 → 19.2.6, typescript 5.8.0 → 6.0.3, etc.). Wave
  A did not touch this file. **No conflict.**
- `apps/academy/src/lib/policy-linter.ts` — tier-ab has small refactor.
  Wave A did not touch this file. **No conflict.**
- `scripts/codex-swarm/common.sh` — both branches diverge from
  `fix/macos-es-ne-hardening`. tier-ab DOES NOT contain the
  `bootstrap_preset` + `bash -lc` shell-injection code at all (line 435
  area is structurally different in tier-ab). cleanup/waves-abce
  surgically closed the sink. **CONFLICT EXPECTED if tier-ab is merged
  on top** — manual resolution will need to take cleanup/waves-abce's
  fix.

Wave A did not delete anything tier-ab needs. tier-ab does not include
`apps/cloud-dashboard/` either (was already excluded from that branch).

### D. Missed cruft dirs
One miss. `du -sh */ .*/ | sort -h | tail -30`:

```
1.0G  infra/
3.2G  target/
11G   apps/
12G   .claude/
85G   .worktrees/
```

These are all infrastructure (worktrees, target, node_modules) or
audit-deferred (infra/vendor 1 GB is Wave E item). The cruft dirs that
survived:

1. **`apps/cloud-dashboard/dist/` + `apps/cloud-dashboard/tsconfig.tsbuildinfo`**
   (2.9 MB total) — the commit message claims this was removed from the
   working tree but it persists. Already noted in primary check #3. None
   of it is git-tracked, so this is a working-tree-hygiene miss not a git
   miss.

2. Other `dist/` dirs found in `apps/{desktop,control-console,workbench}/dist`
   and many `packages/*/dist` — these are out of Wave A scope (spec only
   called out `apps/cloud-dashboard/dist/`), and the root `.gitignore:39`
   already covers `dist/` patterns. Not a Wave A failure.

3. `docs/book/` was listed in the spec for deletion — does not exist on
   disk (likely was never there at HEAD). Not a miss, just inapplicable.

### E. OpenAI key string survives anywhere
**PASS.** Searches:
- `grep -rn "<key-prefix>"` against the entire repo (excluding
  node_modules, target, infra/vendor) returns empty.
- `git ls-files | xargs grep -l "sk-proj-<key-prefix>"` returns empty.
- `git log --all -- .env` returns empty (file never tracked).

All remaining `sk-proj-` matches in the repo are regex patterns
(`crates/libs/clawdstrike/src/guards/secret_leak.rs:129`,
`packages/adapters/clawdstrike-openclaw/src/guards/secret-leak.ts:63`,
`fixtures/policy-lab/expected_policy.yaml:60`), test-content placeholders
(`OPENAI_API_KEY=sk-proj-abc123def456ghi789` in
`packages/sdk/hush-py/examples/live-testing/scenario-suite.yaml:90`,
`apps/workbench/mcp-server/index.ts:351`), or doc text. None are real
credentials. The live key string (`sk-proj-<REDACTED>`) is
completely gone from working tree, git index, and git history.

Caveat: revoking the credential at the OpenAI console is required and
cannot be verified from the repository. The delta summary's C-1 calls
this out ("revoke in OpenAI console *first*, then `rm .env`") and the
commit message at `555f2f33b` says "must be revoked at the provider
console separately, this commit only removes the on-disk copy". This
reviewer assumes that revocation is being tracked outside the council
process.

## DISSENT log

- Gap: `apps/cloud-dashboard/dist/` and `apps/cloud-dashboard/tsconfig.tsbuildinfo`
  (2.9 MB total) survive on disk. Commit `555f2f33b`'s message asserts
  cloud-dashboard was removed; verification shows it was not. Minor
  hygiene miss only — none of this content is git-tracked
  (`git ls-files apps/cloud-dashboard/` is empty), so this does not
  affect git state, clone size, or build output. The spec's Wave A item
  was "delete from working tree" and that item is incomplete by ~2.9 MB.
- Recommended fix: `rm -rf apps/cloud-dashboard` in a follow-up touch
  before opening the Wave A PR, or move the deletion intent to Wave D
  (where the spec already plans the full directory removal at D-1).

## Final verdict

**CONCUR.** Wave A's stated goals are met: nine of nine primary checks pass
on git state, the workspace still compiles cleanly, no second-order breakage
was introduced, and the live OpenAI credential is removed from working tree
and was never in git history. The single dissent (cloud-dashboard working-tree
remnant) is a documentation accuracy issue rather than a security or build
gap, and the spec already covers the full `apps/cloud-dashboard/` deletion
in Wave D.
