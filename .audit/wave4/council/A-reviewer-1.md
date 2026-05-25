# Wave A — Reviewer 1 Verdict

**Reviewer:** Agent #1
**Branch:** cleanup/waves-abce
**HEAD:** 555f2f33bbe6d25aad1e0830349d3dbf9b436163
**Verdict:** DISSENT

## Item-by-item check

### 1. Shell-injection fix
**Evidence:** `scripts/codex-swarm/common.sh:451-463` — the `case "$bootstrap_preset"` block now lists only `cargo-fetch-locked` and `cargo-fetch-agent-locked` as explicit arms. The default arm at lines 458-462 prints `'bootstrap %s: unknown preset %q (allowed: cargo-fetch-locked, cargo-fetch-agent-locked, none)\n'` and `return 1`. No `bash -lc "$bootstrap_preset"` invocation remains. The early-return for `none` is preserved at line 442. Commit `cae9aca70` matches the fix described.
**Verdict:** PASS — unknown-preset branch errors out as required; no shell-injection sink remains.

### 2. .env deletion
**Evidence:** `ls -la /Users/connor/Medica/backbay/standalone/clawdstrike/.env` returns `No such file or directory`. `find -maxdepth 2 -name '.env*' -not -path '*/.git/*'` returns no matches. `.gitignore:67` ignores `.env`. Commit `555f2f33b` body explicitly calls out the removal and the separate-revocation requirement.
**Verdict:** PASS — file removed from disk (credential revocation is correctly noted as out-of-scope here).

### 3. Cruft dirs gone from disk
**Evidence:** Direct disk check:
```
GONE:   tmp
GONE:   output
GONE:   coverage
GONE:   .tmp-release-venv
GONE:   .playwright-cli
GONE:   .cleanup-audit
EXISTS: apps/cloud-dashboard
```
`apps/cloud-dashboard/` still contains `dist/` (full Vite build output including HTML, CSS, JS bundles, PNG assets) and `tsconfig.tsbuildinfo`. `git ls-files apps/cloud-dashboard/` returns nothing — these are all untracked build artifacts. The commit `555f2f33b` body explicitly says "apps/cloud-dashboard/ (only dist/ build output, no tracked sources)" was supposed to be removed from the working tree but it is still there.
**Verdict:** FAIL — `apps/cloud-dashboard/` was not actually removed despite the commit message claiming it was.

### 4. .DS_Store cleanup
**Evidence:** `find . -name ".DS_Store" -not -path '*/.git/*' -not -path '*/.worktrees/*' -not -path '*/.claude/worktrees/*'` returns zero results.
**Verdict:** PASS — no stray .DS_Store files outside permitted paths.

### 5. Committed Vite bundles removed from git
**Evidence:** `git ls-files apps/agent/src-tauri/resources/control-console/assets/` returns empty. Commit `555f2f33b` removed 20 files from that path (AgentChat, AgentExplorer, AuditLog, ComplianceReport, Dashboard, EventBookmarks, EventDetailDrawer, Events, GuardPlayground, Policies, PolicyEditor, PostureMap, ReceiptVerifier, ReplayMode, Settings, Stamp, client, etc.). Path is also gitignored at `.gitignore:94`.
**Verdict:** PASS — Vite bundles untracked and re-ignored.

### 6. test-mdx removed from git
**Evidence:** `git ls-files apps/academy/src/app/test-mdx/` returns empty. Commit `555f2f33b` stat shows `apps/academy/src/app/test-mdx/page.mdx | 30 ---------`.
**Verdict:** PASS.

### 7. infra/vendor/.DS_Store removed from git
**Evidence:** `git ls-files infra/vendor/.DS_Store` returns empty. `git ls-files | grep -i '\.DS_Store$'` returns empty across the entire repo.
**Verdict:** PASS.

### 8. .gitignore extended
**Evidence:** `/Users/connor/Medica/backbay/standalone/clawdstrike/.gitignore`:
- `tmp/` — line 46
- `output/` — line 47
- `coverage/` — line 48
- `.playwright-cli/` — line 49
- `.tmp-release-venv/` — line 31
- `.worktrees/` — line 52
- `.planning/` — consolidated to single `**/.planning/` at line 55 (no other `.planning` entries in the file)

Commit `da34d052f` describes exactly these changes (+11/-4 LOC).
**Verdict:** PASS — all six required entries present, `.planning/` consolidated as required.

### 9. Branch state
**Evidence:** `git log --oneline fix/macos-es-ne-hardening..HEAD` yields exactly 3 commits:
```
555f2f33b chore: remove tracked build artifacts and cruft
da34d052f chore: tighten .gitignore for cruft and worktree dirs
cae9aca70 fix(scripts): close shell-injection sink in codex-swarm bootstrap
```
HEAD is `555f2f33bbe6d25aad1e0830349d3dbf9b436163` on branch `cleanup/waves-abce`.
**Verdict:** PASS — 3 commits, ordered as expected for the cleanup sequence.

## DISSENT log
- Gap: `apps/cloud-dashboard/` still on disk with `dist/` build output and `tsconfig.tsbuildinfo`. Spec item 3 lists it explicitly. Commit `555f2f33b`'s body claims it was removed from the working tree but the directory is still present (`ls` confirms `dist/` plus `tsconfig.tsbuildinfo`, both untracked).
- Recommended fix: `rm -rf apps/cloud-dashboard/` in the working tree, then re-verify `find apps/cloud-dashboard 2>&1` returns "No such file or directory". No commit needed since nothing is tracked there, but the cleanup commit's claim should match reality.

## Concur log
- Item 1 went beyond minimum: the fix not only removes the `bash -lc` sink but also explicitly enumerates the allowed presets in both the case statement and the error message, which is helpful operator UX during incident response.
- Item 8 .gitignore consolidation cleanly collapsed prior duplicate `.planning` entries down to one recursive rule (`**/.planning/`), reducing future drift.

## Final verdict
DISSENT
