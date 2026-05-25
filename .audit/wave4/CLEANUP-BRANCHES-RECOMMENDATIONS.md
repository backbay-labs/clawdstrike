# Cleanup Branches: Disposition Recommendations

**Reviewed from:** `cleanup/waves-abce` @ `9584a7e372148863a4d097ec633bba7ead1c6dc6`
**Main HEAD:** `origin/main` @ `5689c70bbdff725736a11de5c9219cfa5ff2bf36`
**Date:** 2026-05-24

`origin/main` has already absorbed the Tier A+B cleanup via PR #313
(`c0ff91ed4`) and PR #316 (`5689c70bb` — long-form README restore).
Several of the branches below are now strictly ancestors of `origin/main`
or were the source branches for those merged PRs, so their disposition
is mostly about pruning, not re-merging.

---

## chore/cleanup-tier-ab

- **HEAD:** `14aff0d5c`
- **Merge-base with `cleanup/waves-abce`:** `b69fb2727` (the previous
  main HEAD that both branches forked from)
- **Divergence:** ahead 77, behind 60
- **Scope:** the source branch for PR #313 plus 17 additional commits.
  Includes:
  - `8015e437f chore(cleanup): prune build artifacts, demo routes, and tighten gitignore` (overlaps Wave A)
  - `aefb71c02 fix(security): default daemons to fail-closed auth` (overlaps Wave B)
  - `255e8a5f4 docs: reconcile schema version to 1.5.0 and consolidate planning docs` (overlaps Wave C Task 1)
  - `4a9a2d061 chore(deps): canonicalize npm and drop bun lockfiles` (overlaps Wave C Task 3)
  - `645c38501 chore(brand): replace default Tauri 'T' icons with ClawdStrike claw sigil` (the Tauri icon item flagged out of Wave C)
  - `87ec54058 docs(readme): rewrite from 1122 → 243 lines` followed by `14aff0d5c Revert "docs(readme): rewrite from 1122 → 243 lines"` (round-trip; final state is the original README)
  - `ea6d5e9bd refactor(ts): TS \`any\` Sprints 0+1 — 91 hits removed` (new work)
  - `ec8f79adc refactor(workbench): fold swarm-engine into workbench` (new structural refactor)
  - `733c69763 chore(ci): harden permissions, concurrency, timeouts; matrix docker; pin trivy` (new CI hardening)
  - 40+ dependabot bumps absorbed via #270, #271, #273, etc.
- **Conflicts with Wave A/B/C:** large overlap. The branch covers the
  same hygiene/security/schema/lockfile work that Waves A-C just did,
  but via a different commit sequence. A direct merge would force git
  to either prefer the older versions of those changes (regression)
  or surface dozens of textual conflicts on the same files.
- **Recommendation:** **CLOSE.** The Tier A+B work landed via PR #313
  on `origin/main`. The Tauri icon commit (`645c38501`), the TS-any
  refactors (`ea6d5e9bd`), the swarm-engine fold (`ec8f79adc`), and
  the CI hardening (`733c69763`) are the only genuinely new commits
  not yet on main and not in scope for Waves A-C. Those four should
  be cherry-picked onto a fresh branch off `origin/main` for a small
  follow-up PR. Everything else in this branch is either already on
  main or has been re-done more carefully in `cleanup/waves-abce`.
- **Estimated effort:** 2-3 hours to cherry-pick the four targeted
  commits with conflict resolution against `origin/main`.

---

## chore/ts-sprints-23-deps-latest

- **HEAD:** `ae564c1a2`
- **Merge-base with `cleanup/waves-abce`:** `b69fb2727`
- **Divergence:** ahead 100, behind 60
- **Scope:** rebases `chore/cleanup-tier-ab` and adds another wave of
  TypeScript-`any` removal sprints, zod migration of policy/openclaw
  validators, adapter peer-dependency tightening, Rust patch bumps,
  Python SDK floor bumps, and several runtime fixes:
  - `563d5f7da TS-any Sprint 2 batch B2 — canonical validator + loader to zod (-46 any)`
  - `aabe4d10d TS-any Sprint 2 batch B4 — openclaw legacy validator + loader to zod (-66 any)`
  - `9d0eebb4c TS-any Sprint 2 batch B3 — plugin manifest + loader to zod (-19 any)`
  - `813dc154d Sprint 3 batch B5 — vercel-ai middleware (-51 any)`
  - `c7d5df2ee Sprint 3 batch B6 — vercel-ai react/use-secure-chat (-2 any)`
  - `26bd3a1ce chore(deps): tighten adapter peerDependency ranges`
  - `1019b8618 chore(deps): harmonize TS workspace pins`
  - `1515cd753 chore(deps): minor Rust bumps (tokio 1.52, x509-parser, regorus, dirs, which, tokio-tungstenite dev)`
  - `47bcd90fc chore(deps): bump Python SDK floors`
  - `29bda2c02 fix(policy): keep legacy egress translation fail-closed on mixed-type arrays`
  - `cfa388e74 fix(policy): return fresh DEFAULT_CAPABILITIES/RESOURCES objects per parse`
  - `5ffceb05f refactor: drop remaining noise comments per wave-5 audit`
  - `016343b34 docs: rewrite 11 comments to explain WHY (per wave-5 audit)`
- **Conflicts with Wave A/B/C:** carries the entire Tier A+B history,
  so it conflicts with the same regions as `cleanup-tier-ab`. The new
  zod migrations and Rust/Python bumps are independent and should be
  safe to land separately.
- **Recommendation:** **REBASE FIRST onto `origin/main`, then open a
  fresh PR with only the deltas that aren't already on main.** Once
  rebased, the diff to main reduces to the TS-`any` sprints, the zod
  migrations, the dependency bumps, the two `fix(policy)` correctness
  fixes, and the comment-policy refactors. That's a reviewable
  follow-up. Do **not** auto-merge — the zod migration in particular
  changes validator semantics and deserves a focused review.
- **Estimated effort:** 4-6 hours to rebase, resolve conflicts on
  vendored crates, and produce a clean per-topic PR sequence.

---

## chore/cleanup-purge-and-vendor

- **HEAD:** `1f949c578`
- **Merge-base with `cleanup/waves-abce`:** `b69fb2727`
- **Divergence:** ahead 57, behind 60
- **Scope:** sits on top of merged PR #313 + PR #316 plus six additional
  cleanup commits:
  - `3cd3aa02f chore: remove stale .planning/ directory`
  - `237393a2b chore: remove .audit/ corpus and dangling reference`
  - `11c0e6b7e chore: remove .agents/skills/ and dangling doc references`
  - `85d27029f chore: remove apps/academy and refresh root lockfile`
  - `d12066c32 refactor: relocate hushspec path-dep crate to infra/external/`
  - `1f949c578 chore: scrub stale apps/academy reference from package-lock`
- **Conflicts with Wave A/B/C:** the academy removal collides with
  current main, which kept `apps/academy/` (PR #231 was a feature add).
  The `.audit/` removal directly collides with the current cleanup
  work, which writes back into `.audit/wave4/`. The `.planning/` and
  `.agents/skills/` removals are mostly orthogonal.
- **Recommendation:** **CHERRY-PICK SUBSET.** Take `d12066c32` (the
  hushspec relocation) onto a fresh branch off `origin/main` only if
  the user wants the `infra/external/` layout — that's a real
  architecture decision, not cleanup. **Do not** carry the
  `apps/academy` removal: PR #231 added academy as a deliberate
  feature. **Do not** carry the `.audit/` removal: that's the live
  audit corpus this wave is writing into.
- **Estimated effort:** 1 hour, but only if the hushspec relocation
  is a chosen architectural change.

---

## chore/fix-security-deps

- **HEAD:** `e557e35ad`
- **Merge-base with `cleanup/waves-abce`:** **NONE**
- **Merge-base with `origin/main`:** **NONE**
- **Scope:** an orphaned history from a previous repo lineage. Includes
  PR #136 (proofs-api paged leaf fetch), #132 (post-merge follow-ups),
  #130 (README design principles + local-model context), various
  `chore(deploy): promote dev profile images` commits, and old
  dependency fixes (rollup path traversal, minimatch ReDoS) that
  predate the current repo's `main`. Diff to `cleanup/waves-abce` is
  9562 files / +100k / -3.3M lines — the size signal alone confirms
  these are unrelated histories.
- **Conflicts with Wave A/B/C:** total. No shared ancestor; everything
  is technically a conflict because git has nothing to align against.
- **Recommendation:** **CLOSE.** This branch references PRs (#107,
  #130, #132, #136) that landed in a previous version of this
  repository before the history was reset. Any genuine security
  content here is either already addressed by Waves A-B or by PR
  #313 on the current main.
- **Estimated effort:** 0 hours; safe to delete.

---

## chore/misc-cleanup

- **HEAD:** `8aa59255d`
- **Merge-base with `cleanup/waves-abce`:** **NONE**
- **Merge-base with `origin/main`:** **NONE**
- **Scope:** the same orphan-history situation as `chore/fix-security-deps`.
  Top commit `8aa59255d chore: repo hygiene` matches the title of PR
  #92 (`53a31780c` on `chore/resolve-dependabot-alerts`), so this is a
  pre-rewrite version of work that has since been redone. Includes PRs
  #79 (app icons + Helm README), #80 (enterprise desktop agent), #83
  (hush-ffi C ABI), #86 (Desktop Agent Overhaul), #88 (CUA Gateway),
  #91 (README professionalize) — all from an older repo lineage.
- **Conflicts with Wave A/B/C:** total. No shared ancestor.
- **Recommendation:** **CLOSE.** Orphan history. Any commits that
  still matter were re-landed via the post-reset PR sequence.
- **Estimated effort:** 0 hours; safe to delete.

---

## chore/resolve-dependabot-alerts

- **HEAD:** `c47584ae8`
- **Merge-base with `cleanup/waves-abce`:** **NONE**
- **Merge-base with `origin/main`:** **NONE**
- **Scope:** another orphan history. Tip commits are
  `chore(deps): bump minimatch 10.1.2 → 10.2.2 in root lockfile`,
  `chore(deps): bump minimatch in /packages/adapters/clawdstrike-openclaw (#90)`,
  and `chore(deps): bump the cargo group across 4 directories (#89)`.
  These bumps have been re-landed via the dependabot stream feeding
  `origin/main` (PRs #270-#283+).
- **Conflicts with Wave A/B/C:** total. No shared ancestor.
- **Recommendation:** **CLOSE.** Orphan history. The dependabot
  bumps that mattered are already on `origin/main` via the post-reset
  PR sequence.
- **Estimated effort:** 0 hours; safe to delete.

---

## Summary Table

| Branch | Disposition | Effort | Reason |
| --- | --- | --- | --- |
| `chore/cleanup-tier-ab` | **CLOSE**, cherry-pick 4 commits | 2-3h | Tier A+B already merged via PR #313; only Tauri-icons, TS-any sprints, swarm-engine fold, and CI hardening are net-new |
| `chore/ts-sprints-23-deps-latest` | **REBASE FIRST onto main** | 4-6h | Carries zod migration + Rust/Python bumps that aren't on main; needs focused review, not a blind merge |
| `chore/cleanup-purge-and-vendor` | **CHERRY-PICK** the hushspec relocation only | 1h | Academy removal contradicts PR #231; `.audit/` removal contradicts current wave; only hushspec relocation is a real architecture decision |
| `chore/fix-security-deps` | **CLOSE** | 0h | Orphan history, no merge base with main |
| `chore/misc-cleanup` | **CLOSE** | 0h | Orphan history, no merge base with main |
| `chore/resolve-dependabot-alerts` | **CLOSE** | 0h | Orphan history, no merge base with main; bumps already on main |

---

## Process Note

The three orphan branches (`fix-security-deps`, `misc-cleanup`,
`resolve-dependabot-alerts`) all reference PRs that pre-date the
current repository history. They appear to be holdovers from a
history rewrite. Closing them is the right call regardless of their
contents because git itself cannot relate their commits to the
current `main`. Before deleting locally, confirm with the user that
the corresponding remote branches (`origin/chore/fix-security-deps`,
etc.) are also stale.
