# DELTA D02: CI/CD & Infra
**Refreshed:** 2026-05-24 | **Source:** .audit/02-ci-cd-infra.md (2026-05-23) | **Scope:** .github/, infra/, scripts/, Dockerfiles, .moon/, mise.toml, deny.toml, .cargo/, packs/

## Quick Verdict

- Findings still valid: 18/19 (essentially every original finding still has a real footprint on this branch)
- Findings fixed since 2026-05-23: 0
- Findings partially-fixed: 1 (audit-ignore consolidation: deny.toml + docs/security started, but the 38-entry inline list in `ci.yml` is unchanged)
- Findings wrong/misdiagnosed: 1 (the 18 Python "proof bundle" scripts are NOT fully orphan — they're invoked by `scripts/endpoint-decision-engine-live-qualification.sh`; audit said "none referenced from CI workflows", true narrowly, false broadly)
- Findings numerically drifting: 2 (audit-ignore count was 32, is now 38; Python proof scripts are 15 not 18)
- New issues found: 5
- Net delta: **same to slightly worse**. The CI hardening that DID land (`733c69763 chore(ci): harden permissions, concurrency, timeouts; matrix docker; pin trivy; consolidate audit`) is on the `chore/cleanup-tier-ab` family of branches but NOT on `fix/macos-es-ne-hardening` (current HEAD). The three commits in scope (`d3ecce751`, `1ade43894`, `2eff91532`) added one new shell-injection vector (`scripts/codex-swarm/common.sh:462`), a useful macOS signing keychain block, and a tiny build.rs regex fix. Net: still 7/10 ambition, 5/10 polish, with one new sharp edge.

A note on the audit-vs-HEAD branch state: the audit was written against `fix/macos-es-ne-hardening` (this branch) and the cleanup work that addresses many of these findings exists on a sibling branch. Until that work is merged here, every original finding remains a live defect on this branch — which is what an outside reviewer would see if they cloned today.

---

## STILL VALID

### [V-01] `ci.yml` is a 1,497-line monolith with no concurrency cancellation and 4 timeouts across 33 jobs
**At HEAD:** `wc -l .github/workflows/ci.yml` → **1,497** (byte-identical with audit). Confirmed at HEAD:
- No top-level `concurrency:` block (entire `on:` block at `ci.yml:3-7` is bare push/pull_request, no filters).
- `grep -c "timeout-minutes:" ci.yml` → **4** (lines 17, 36, 358, 396). Verified with `ci.yml:14-17` (security-regressions), `ci.yml:33-36` (policy-torture), `ci.yml:355-358` (sdr-integration-tests), `ci.yml:393-396` (adaptive-control-integration).
- 33 jobs (29 substantive + 4 matrix-fanned: `tauri-rust-check`, `desktop-frontend`, `workbench-frontend`, `control-console`, `sdr-integration-tests`, `adaptive-control-integration`, `msrv`, `offline`, `docs`, `security-audit`, `license-check`, `coverage`, `wasm`, `proptest`, `integration-tests`, `fuzz-check`, `typescript-sdk`, `agent-fail-closed-smoke`, `adapter-core-cross-adapter`, `openclaw-plugin`, `openclaw-plugin-runtime-matrix`, `clawdstrike-policy`, `agent-framework-integrations`, `parity-tests`, `python-sdk`, `python-native-wheel-smoke`, `sdk-conformance`, `terminal-tui`, `check`).
- No `paths:` filter on the `on:` block — every push to main and every PR runs all 33 jobs.

**Aggressive cleanup:** RESTRUCTURE. (a) Add top-level `concurrency: { group: ci-${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: ${{ github.event_name == 'pull_request' }} }`. (b) Add a default `timeout-minutes: 30` at job-template level and reduce per-job overrides to outliers. (c) Split into 5 reusable workflows via `workflow_call`: `_ci-rust-core.yml`, `_ci-ts-sdk.yml`, `_ci-tauri-apps.yml`, `_ci-openclaw-matrix.yml`, `_ci-python-sdk.yml`. (d) Add `paths:` filters per call so docs-only changes don't fan out 33 jobs. Net loss: ~600 lines of YAML.

### [V-02] `docker.yml` is 9 near-identical jobs (still 414 lines, still copy-paste)
**At HEAD:** `wc -l .github/workflows/docker.yml` → **414**. Verified the 9 jobs are still discrete:
- `spine` (`docker.yml:43-87`) — has matrix on `bin`
- `tetragon-bridge` (`docker.yml:88-127`)
- `hubble-bridge` (`docker.yml:128-168`)
- `hushd` (`docker.yml:170-209`)
- `control-api` (`docker.yml:211-250`)
- `registry` (`docker.yml:252-291`)
- `auditd-bridge` (`docker.yml:293-332`)
- `k8s-audit-bridge` (`docker.yml:334-373`)
- `eas-anchor` (`docker.yml:375-414`)

8 of these jobs are byte-identical except for `name`, `file:`, image-name in `tags:`, and `image-ref:` in the Trivy step. The `spine` job alone uses a matrix. Permissions block ADDED at top (`docker.yml:34-36`) and concurrency block ADDED (`docker.yml:38-40`) — those parts of the audit are obsolete (positive). But the per-job duplication is unchanged.

**Aggressive cleanup:** REWRITE as a single matrix-driven job. Define the image list in `strategy.matrix.include:` (image name, dockerfile path, optional `extra-bins`). Pull the login/build/scan steps into `.github/workflows/_build-image.yml` reusable workflow called per image. Drops ~280 lines.

### [V-03] `aquasecurity/trivy-action@master` still pinned in 9 places with `continue-on-error: true`
**At HEAD:** `grep -n trivy-action .github/workflows/docker.yml` returns 9 hits at lines **81, 122, 163, 204, 245, 286, 327, 368, 409** — exact byte match with audit. Every one is preceded by `continue-on-error: true` (`docker.yml:80, 121, 162, 203, 244, 285, 326, 367, 408`). The `exit-code: '1'` setting on each scan is therefore neutralized.

**Aggressive cleanup:** REWRITE. (a) Pin to a SHA — current stable is `aquasecurity/trivy-action@0.28.0` (or `@f3a0b9d` as a commit SHA). (b) Delete every `continue-on-error: true`. (c) Switch `format: 'table'` to `format: 'sarif'` and emit to `github/codeql-action/upload-sarif` so the findings show up in the Security tab instead of being lost in logs. (d) If HIGH/CRITICAL findings should not block merges yet, gate them via a separate "scan-only" job that is non-required — but DO NOT silently swallow errors.

### [V-04] Audit-ignore list still inline in `ci.yml` (now 38 entries, was 32)
**At HEAD:** `ci.yml:486-533` still hosts a hand-maintained bash array. Count via `grep "RUSTSEC-" .github/workflows/ci.yml | grep -- "--ignore"` → **38** distinct IDs (up from 32 at audit time). The aws-lc-rs batch (`RUSTSEC-2026-0044` … `0049`, `0067`, `0068` at `ci.yml:525-532`) is the new addition. Mid-array comments at `ci.yml:518-522` ("SEC-PTY-001") and `ci.yml:523-524` ("aws-lc-rs advisories ... Owner: @deps-maintainers") are still there.

**Partial fix observed:** `deny.toml` has 5 RUSTSEC entries with structured owner+expiry+reason (`deny.toml:32-58`). `docs/security/dependency-advisories.md` has 36 entries with table-format owner/expiry/tracking that `tools/scripts/check-advisory-expiry.sh` enforces. So three sources of truth exist; none is canonical; the inline list in `ci.yml` is still what `cargo audit` actually reads against.

**Aggressive cleanup:** RESTRUCTURE. Make `deny.toml` the single source of truth (it already enforces unmaintained+yanked). Move every RUSTSEC-`--ignore` out of `ci.yml`. Have `check-advisory-expiry.sh` read `deny.toml` directly (parse via `cargo deny check --json` or `tomlq`). Delete the markdown doc OR auto-generate it from `deny.toml` via a script invoked in `docs.yml`. Net loss: ~50 lines from `ci.yml`.

### [V-05] 7 workflows still have no top-level `permissions:` block
**At HEAD:** Verified with `grep '^permissions:' .github/workflows/<f>` for each of: `ci.yml`, `ffi-bindings.yml`, `formal-verification.yml`, `fuzz.yml`, `helm-ci.yml`, `miri.yml`, `sanitizers.yml`. **All 7 still report 0.** Unchanged from audit.

Inverse check (workflows that DO have permissions): `argo-dev-verify.yml:13`, `desktop-release.yml:12`, `docs.yml:21`, `docker.yml:34`, `helm-cluster-smoke.yml:22`, `helm-nightly-resilience.yml:18`, `helm-release.yml:14`, `promote-dev-profile-images.yml:8`, `release.yml:14`.

**Aggressive cleanup:** Add `permissions: { contents: read }` to all 7. Override at job level where any job uploads/publishes/comments. Net add: ~14 lines. Zero risk. 10 minutes.

### [V-06] 12 of 16 workflows missing `concurrency:` block
**At HEAD:** `grep '^concurrency:' .github/workflows/*.yml` returns 4: `docker.yml:38`, `docs.yml:27`, `release.yml:22`, `promote-dev-profile-images.yml:20`. The remaining 12 (`argo-dev-verify`, `ci`, `desktop-release`, `ffi-bindings`, `formal-verification`, `fuzz`, `helm-ci`, `helm-cluster-smoke`, `helm-nightly-resilience`, `helm-release`, `miri`, `sanitizers`) have none. **Unchanged from audit.**

**Aggressive cleanup:** Add `concurrency: { group: <workflow>-${{ github.ref }}, cancel-in-progress: <true for PR jobs, false for release/cron> }` to each. Important: for `helm-cluster-smoke` the group should be the namespace (or the PR number) because two cluster smokes racing in the same EKS namespace is the worst case.

### [V-07] `promote-dev-profile-images.yml` still bot-commits to main with a PAT
**At HEAD:** `promote-dev-profile-images.yml:32-87` confirmed unchanged. Line 35 `token: ${{ secrets.GHCR_PUSH_TOKEN }}` is the PAT. The bot config at `promote-dev-profile-images.yml:79-80` is intact. No GitHub App migration, no Argo Image Updater.

**Aggressive cleanup:** Same recommendation as audit. Replace PAT with a GitHub App token (short-lived, scoped), OR route via an `image-promotions` branch with auto-PR + auto-merge, OR adopt Argo Image Updater. Each is a 4-6 hour task.

### [V-08] Cache key sprawl — 8 keys, no Swatinem/rust-cache
**At HEAD:** Confirmed 8 distinct `cargo-` keys at `ci.yml:77, 242, 373, 700, 756, 785, 1167, 1359` (audit was right on the order). Cache action is `actions/cache@v5` everywhere (`ci.yml:71, 236, 367, 693, 750, 779, 1161, 1353`). `grep Swatinem .github/workflows/*.yml` returns nothing — no rust-cache adoption.

The keys are: `cargo-`, `cargo-tauri-`, `cargo-sdr-`, `cargo-proptest-`, `cargo-integration-`, `cargo-policy-parity-`, `cargo-parity-` (note: `cargo-` and `cargo-parity-` overlap, which means cross-evict — bad).

**Aggressive cleanup:** REWRITE. Replace every cargo-cache block with `Swatinem/rust-cache@v2` and pass `shared-key:` per job-family (e.g. `core`, `tauri`, `wasm`, `python`, `policy-parity`). Loses ~80 lines, improves hit rate, fixes the `cargo-` vs `cargo-parity-` cache poisoning.

### [V-09] `:latest` still published from CI on every push to main (9 images)
**At HEAD:** Every job in `docker.yml` still publishes both `:latest` and `:<sha>` tags (`docker.yml:73-74, 114-115, 154-155, 196-197, 237-238, 277-278, 318-319, 359-360, 400-401`). The promote workflow (`promote-dev-profile-images.yml`) still exists precisely because consumers can't trust `:latest`.

**Aggressive cleanup:** DOCUMENT in `infra/docker/README.md` that `:latest` is auto-generated and that downstream consumers should pin to `:<sha>`. Better: rename `:latest` to `:edge` for tip-of-main, and reserve `:latest` for `release.yml` tag pushes. The change in `docker.yml` is 9 lines, in `release.yml` is ~5 lines. Low risk because the production cluster pins via Argo SHAs.

### [V-10] `scripts/cleanup-legacy-paths.sh` still silently rm -rf's hardcoded paths
**At HEAD:** `scripts/cleanup-legacy-paths.sh:1-31` confirmed. The recent improvement (relative to the audit) is that `REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"` is now at `scripts/cleanup-legacy-paths.sh:4` — so it does `cd "$REPO_ROOT"` before deleting. That partially mitigates the "wrong directory" risk.

What it still lacks: `--dry-run` mode, repo-identity guard (matching `git rev-parse --show-toplevel` against an expected value, e.g. checking for a sentinel file like `Cargo.toml` + `.audit/` exists), `--help` usage. The `LEGACY_PATHS=( ... "vendor" )` line at `scripts/cleanup-legacy-paths.sh:16` is still the loaded gun — if anyone ever runs this from a different repo that has a `vendor/` dir, it rm -rf's their work.

**Aggressive cleanup:** WIPE outright. The legacy paths it's targeting (`apps/cloud-dashboard`, `packages/cloud-dashboard`, `crates/services/cloud-api`, `spine/reticulum`, `spine`, `HomebrewFormula`, `deploy`, `docker`, `vendor`) are old enough that the script is no longer running anything useful. If kept, add `--dry-run` as default, require explicit `--apply`, assert the presence of `Cargo.toml` + `infra/vendor/.cargo-checksum.json` markers before destroying anything.

### [V-11] CODEOWNERS still single-user with stale comment
**At HEAD:** `.github/CODEOWNERS:1-23` unchanged. Lines 1-2: `# Monorepo ownership map (bootstrap)` / `# Replace @connor with org teams as they are formalized.`. Every assignment is `@connor`. No team aliases anywhere.

**Aggressive cleanup:** RESTRUCTURE. Add `@backbay-labs/core-rust` (covers `crates/libs/`, `crates/services/`, `formal/`), `@backbay-labs/sdk-ts` (covers `packages/sdk/hush-ts`, `packages/policy/`, `packages/adapters/`), `@backbay-labs/infra` (covers `.github/`, `infra/`, `scripts/`, `Dockerfile.*`), `@backbay-labs/desktop` (covers `apps/desktop`, `apps/workbench`, `apps/agent`). Even if the teams are 1-2 people each, the structure signals "real org" rather than "hobby project".

### [V-12] Python "proof bundle" scripts — partial drift from audit narrative
**At HEAD:** `ls scripts/*.py | wc -l` → **15** (audit said 18, real count is 15). Combined LOC = **16,887** (audit said ~14k; closer to 17k). The largest are:
- `scripts/endpoint-decision-engine-readiness-audit.py` — 3,814 lines
- `scripts/endpoint-decision-engine-qualification-bundle.py` — 2,538 lines
- `scripts/macos-provider-dogfood-manifest.py` — 1,789 lines
- `scripts/macos-provider-deployment-evidence.py` — 1,035 lines
- `scripts/network-extension-live-dogfood-verify.py` — 963 lines
- `scripts/endpoint-security-live-dogfood-verify.py` — 828 lines
- `scripts/macos-provider-dogfood-gate.py` — 819 lines
- `scripts/endpoint-decision-engine-supplemental-proof-bundle.py` — 733 lines
- `scripts/supply-chain-runtime-guard-proof.py` — 730 lines
- `scripts/privacy-preserving-telemetry-proof.py` — 680 lines
- `scripts/operator-workflows-proof.py` — 665 lines
- `scripts/policy-simulation-impact-proof.py` — 641 lines
- `scripts/cross-platform-sensor-breadth-proof.py` — 590 lines
- `scripts/ai-agent-developer-workstation-proof.py` — 582 lines
- `scripts/endpoint-deception-proof.py` — 480 lines

**Why audit was partially wrong:** `scripts/endpoint-decision-engine-live-qualification.sh` (the dogfood-runner) calls 9 of these scripts directly (`endpoint-decision-engine-live-qualification.sh:190, 210, 231, 250` calls `endpoint-decision-engine-supplemental-proof-bundle.py`, and several more). `scripts/ci-changed.sh:79` references the file-name regex of all of them as a path-change trigger. So they're invoked by a peer shell wrapper that runs on dev machines or as a manual gate — not from `.github/workflows/`.

**Aggressive cleanup:** RESTRUCTURE — move all 15 into `tools/evidence/` (or `scripts/dogfood/`). Update `endpoint-decision-engine-live-qualification.sh` paths. The proof bundles aren't trash, but they're not "scripts you'd commonly run" either — separate them from the everyday `scripts/` like `release-preflight.sh`. Net move: 15 files, 16887 LOC out of the top-level `scripts/` directory.

### [V-13] Shell scripts missing `set -euo pipefail` — confirmed false alarm
**At HEAD:** Reproduced the audit's false-positive. `head -2` doesn't see `set -euo pipefail` at line 3 in files that have a blank line after the shebang (`scripts/codex-swarm/*.sh`, etc.). All codex-swarm shells (`bootstrap-lane.sh`, `common.sh`, `launch-lane.sh`, `launch-wave.sh`, `resume-lane.sh`, `review-lane.sh`, `setup-worktrees.sh`, `status.sh`) and `scripts/e2e-local-test.sh`, `scripts/lib/helm-ci-common.sh` all have `set -euo pipefail` on line 3. Audit was right to disregard.

### [V-14] `Dockerfile.hushd` and `Dockerfile.registry` still at repo root
**At HEAD:** `ls /Dockerfile.*` → `Dockerfile.hushd` (2045 bytes), `Dockerfile.registry` (1758 bytes). `ls infra/docker/Dockerfile.*` → 7 others (auditd-bridge, control-api, eas-anchor, hubble-bridge, k8s-audit-bridge, spine, tetragon-bridge). Mixed placement unchanged. `docker.yml:190` references `Dockerfile.hushd` directly; `docker.yml:272` references `Dockerfile.registry`.

**Aggressive cleanup:** Move to `infra/docker/Dockerfile.hushd` and `infra/docker/Dockerfile.registry`. Update `docker.yml:190, 272` and `infra/docker/docker-compose.services.yaml:123` (`dockerfile: Dockerfile.hushd` reference). 5 min, removes cosmetic inconsistency.

### [V-15] `release.yml:128-152` still hardcodes the 5-crate publish list with apology comments
**At HEAD:** `release.yml:131-135` still says:
```
# The remaining 0.2.7-drifting public crates stay excluded for now:
# - clawdstrike: dry-run fails against crates.io's hushspec/nono surface
# - clawdstrike-policy-event, hunt-scan, hunt-query, hunt-correlate, hush-cli,
#   clawdstrike-logos: blocked transitively on clawdstrike 0.2.7 being unpublished
crates=(logos-ffi clawdstrike-ocsf hush-core hush-proxy hush-spine)
```
The "we cannot publish our main crate" admission still lives in the release workflow.

**Aggressive cleanup:** DOCUMENT the unblock plan in `docs/release-process.md` with target versions/dates. Better: migrate to `cargo-release` or `release-plz` which handle dep-order publishing and dry-run all crates. The underlying blockers (hushspec/nono being path-deps not pulled from crates.io) are real architectural issues, not just CI workflow issues — but the workflow at least shouldn't admit defeat in a code comment.

### [V-16] Homebrew formula generation still heredoc + 4 sed replacements
**At HEAD:** `release.yml:1220-1258` unchanged. The Ruby heredoc with `__VERSION__`, `__SHA_DARWIN_ARM64__`, etc. placeholders + 4 `sed -i` lines is still there.

**Aggressive cleanup:** REWRITE using `dawidd6/action-homebrew-bump-formula@v3` (pinned SHA) or `mislav/bump-homebrew-formula-action`. This action handles SHA computation + formula update + commit + push in one step. ~30 LOC delta. Alternately use `goreleaser` with brew config — but goreleaser is heavier infrastructure.

### [V-17] Helm `Chart.yaml` still at 0.2.0 with no prerelease annotation
**At HEAD:** `infra/deploy/helm/clawdstrike/Chart.yaml:5-6`:
```
version: 0.2.0
appVersion: "0.2.0"
```
`Chart.yaml:20-21` has `annotations: artifacthub.io/license: Apache-2.0` but no `artifacthub.io/prerelease`. Audit was right.

**Aggressive cleanup:** Add `artifacthub.io/prerelease: "true"` annotation until 1.0. Link in the `README.md` to stability/deprecation policy. 5-line edit.

### [V-18] `docker-compose.services.yaml` still ships dev defaults in env vars
**At HEAD:** Confirmed `infra/docker/docker-compose.services.yaml:76, 79-80, 113, 133-135`:
- `JWT_SECRET: ${CONTROL_API_JWT_SECRET:-dev-jwt-secret-local}` (76)
- `STRIPE_SECRET_KEY: ${CONTROL_API_STRIPE_SECRET_KEY:-sk_test_local}` (79)
- `STRIPE_WEBHOOK_SECRET: ${... :-whsec_test_local}` (80)
- `CONTROL_API_BOOTSTRAP_API_KEY: ${... :-cs_local_dev_key}` (113)
- `CLAWDSTRIKE_API_KEY: ${... :-clawdstrike-local-check}` (133)
- `CLAWDSTRIKE_ADMIN_KEY: ${... :-clawdstrike-local-admin}` (134)
- `CLAWDSTRIKE_AUTH_PEPPER: ${... :-clawdstrike-local-pepper}` (135)

Risk: low (the values are obviously local-only), smell: high (a reviewer sees `STRIPE_SECRET_KEY:` and gets startled before reading the `-local` suffix).

**Aggressive cleanup:** Add a banner at the top of the compose file. Or — better — define dev defaults in a `.env.local.example` and require the user to `cp .env.local.example .env.local`. The compose file then has `${...}` with no `:-` fallback, so a missing env explicitly fails with "value required" instead of silently using a dev secret.

### [V-19] `Dockerfile.spine` uses a single `BIN` ARG to build 3 binaries
**At HEAD:** `infra/docker/Dockerfile.spine:1-30` unchanged. Audit said LEAVE. Confirmed — the docs at `Dockerfile.spine:1-9` explain the usage, and the matrix in `docker.yml:46-48` lists `[spine-checkpointer, spine-witness, spine-proofs-api]`.

**Action:** Leave. The only nit is that the entrypoint script (`infra/docker/entrypoint-spine.sh`) and `ENV SPINE_BIN=${BIN}` indirection is unusual; a `target` per binary in a multi-stage file would be cleaner. Not worth touching.

---

## PARTIALLY FIXED (started but incomplete)

### [P-01] Audit-ignore consolidation — `deny.toml` + `docs/security/dependency-advisories.md` started, but `ci.yml` still source of truth
**Status:** Three sources of truth for advisory ignores now exist:
- `deny.toml:32-58` — 5 entries with comments + owner + expiry-via-comment
- `docs/security/dependency-advisories.md` — 36 entries with table-format (owner, expiry, tracking ID), enforced via `tools/scripts/check-advisory-expiry.sh`
- `ci.yml:486-533` — 38 entries inline in bash array, no expiry parsing

**Conflict:** The doc has 36 entries but `ci.yml` has 38; `deny.toml` has 5 but `cargo audit` (run by `ci.yml`) ignores from the inline array. So `cargo deny` and `cargo audit` use DIFFERENT ignore sets. The expiry script only checks the doc — but the doc isn't authoritative for either tool.

**Aggressive cleanup:** RESTRUCTURE — make `deny.toml` the only source. Generate the doc from `deny.toml`. Have `cargo audit` consume the same list via `--ignore-from-file` (cargo-audit supports `.cargo/audit.toml` since 0.18; the inline `--ignore` list in `ci.yml` is unnecessary). Total cleanup: ~70 lines of `ci.yml` deleted, ~40 lines of `deny.toml` added, one `audit.toml` file added in `.cargo/`.

---

## NOW WRONG / MISDIAGNOSED

### [W-01] Python proof bundles aren't fully orphan — they're called from `endpoint-decision-engine-live-qualification.sh`
**Audit said:** "None referenced from CI workflows (verify: only `macos-provider-live-dogfood.sh` is in workflows, and not its `.py` cousins)" — TRUE, but the phrasing implied "abandoned". The correct framing is: these scripts power a dev/dogfood evidence pipeline invoked manually or by `scripts/endpoint-decision-engine-live-qualification.sh` (which itself calls `endpoint-decision-engine-supplemental-proof-bundle.py` at lines 190, 210, 231, 250). `scripts/ci-changed.sh:79` knows about them as a path-change trigger.

So they ARE used — just not from `.github/workflows/`. They have a purpose. The audit's recommendation to move them to `tools/evidence/` is still the right call (separate concern: not everyday scripts), but they shouldn't be characterized as "junk drawer".

### [W-02] Numerical drift on the audit-ignore count
**Audit said:** 32 entries. **At HEAD:** 38 entries. Six were added post-audit by `dcc2aa9ae fix(ci): update security gates` (+5) and `733c69763 chore(ci): ...` (presumably) before being de-duped by `98e4a265a chore(ci): dedupe advisory ignore` (-1). Net: the inline list grew.

### [W-03] Numerical drift on Python script count
**Audit said:** 18 Python "proof bundle" scripts. **At HEAD:** 15. Either some were deleted between audit-snapshot and HEAD, or the audit overcounted. (No commits in scope removed Python scripts from `scripts/`; the audit miscounted.)

---

## NEW ISSUES

### [N-01] `scripts/codex-swarm/common.sh:462` — new shell-injection sink from `1ade43894`
**Where:** `scripts/codex-swarm/common.sh:458-465`
**What:** The recent fix `1ade43894 fix(ci): restore swarm bootstrap and macos signing setup` changed the unknown-preset behavior from `exit 1` (rejection) to:
```bash
*)
  printf 'bootstrap %s: %s\n' "$lane" "$bootstrap_preset"
  (
    cd "$worktree_path"
    bash -lc "$bootstrap_preset"
  )
  return 0
  ;;
```
**Why it matters:** `bootstrap_preset` is read from `swarm_lane_field "$lane" bootstrap "$repo_root"` (`common.sh:340-342`), which reads from `.codex/swarm/lanes.tsv` (an untracked TSV file). Anything in that field becomes arbitrary `bash -lc` execution. Previously, unknown presets were rejected — a typo in the TSV failed loud. Now, a typo or malicious TSV content silently runs as a shell command.

The risk surface is: anyone with write access to the repo (or a contractor running this on their machine with a hostile lane spec) can execute arbitrary commands during `swarm_run_lane_bootstrap`.

**Aggressive cleanup:** REVERT to `exit 1` for unknown presets. If a free-form command is needed, add a `cargo-fetch-custom` preset that takes a structured `cargo-fetch-args` field, OR allowlist a set of safe presets explicitly. Never `bash -lc "$untrusted_input"`.

### [N-02] `infra/vendor/.DS_Store` is tracked despite `.gitignore` line 55 declaring `.DS_Store`
**Where:** `infra/vendor/.DS_Store` (8196 bytes), committed in `4f9c8a7b9 chore: update AGENTS.md and package-lock.json`
**Verification:** `git ls-files | grep DS_Store` → `infra/vendor/.DS_Store`. `grep DS_Store .gitignore` → line 55 (`.DS_Store`).
**Why it matters:** A macOS-only artifact in the vendor dir means: (a) the gitignore is being bypassed (probably via `git add -f` or via `infra/vendor/` having its own scope), (b) anyone re-vendoring on Linux/Windows can't reproduce the diff, (c) it's signal to a reviewer that nobody's running `git status` carefully before committing.

Additional untracked-but-present `.DS_Store` files in working copy: `./.DS_Store`, `./apps/.DS_Store`, `./apps/desktop/.DS_Store`, `./apps/agent/.DS_Store`, `./infra/.DS_Store`, `./apps/agent/src-tauri/.DS_Store`, `./apps/agent/src-tauri/src/.DS_Store`.

**Aggressive cleanup:** `git rm --cached infra/vendor/.DS_Store && git commit`. Then verify with `find . -name .DS_Store -not -path './node_modules/*' | xargs -I{} git ls-files {}` that no others are tracked.

### [N-03] `infra/vendor/` is 1.0 GB / 841 directories committed to the repo
**Where:** `du -sh infra/vendor` → **1.0G**; `ls infra/vendor | wc -l` → **841**. 96 of those are multi-version duplicates (`ark-ff-0.3.0` + `ark-ff-0.4.2`, `hashbrown-0.12.3` + `hashbrown-0.14.5` + `hashbrown-0.15.5` + `hashbrown-0.17.1`, etc.).
**Context:** `.cargo/config.toml` is just `[source.vendored-sources]\ndirectory = "infra/vendor"` — every cargo build (default) reads from the committed vendor tree. The repo clone is 1 GB before any work happens.

**Why it matters:** This is a Bazel/hermetic-build pattern, not an OSS pattern. Most OSS repos rely on `Cargo.lock` and a CI-time `cargo fetch --locked`. The benefits the project claims (offline builds) are real but narrowly applicable. The costs are:
- Every clone is 1 GB.
- Every dependency bump touches dozens of vendor files (see `b59a3c282` and `d3ecce751` — both touched 100+ files in `infra/vendor/`).
- Vulnerability scanning has to handle 841 vendored crates instead of pulling from a registry.
- `infra/vendor/aws-lc-rs/` and `infra/vendor/aws-lc-sys/` exist for a stack the audit-ignore list already lists 7 CVEs against; updates require manual `cargo vendor` runs.
- The `.cargo-checksum.json` in each vendor dir means even whitespace changes in vendored crates can flag a checksum mismatch.

The recent `d3ecce751 fix(ci): align offline vendored dependencies` only touched the workspace Cargo.toml/lock to align registries — it didn't touch the actual vendor tree. So the vendor tree is increasingly out of sync with crates.io.

**Aggressive cleanup:** WIPE `infra/vendor/`. Delete `.cargo/config.toml`'s `[source.vendored-sources]` block. Replace with a CI-only "offline build" job that runs `cargo vendor` against the locked `Cargo.lock` at start, then `cargo build --offline` — keep the offline capability but don't commit 1 GB of vendor to git. This is the single largest cleanup possible in this scope. If the team genuinely needs hermetic vendoring for air-gapped deployments, move it to a separate git LFS-tracked submodule or a release artifact.

### [N-04] 4 unused example workflows in `.github/workflows/examples/`
**Where:** `.github/workflows/examples/` (16 KB)
**What:**
- `clawdstrike-guard-ci.yml`
- `clawdstrike-oidc-publish.yml`
- `clawdstrike-policy-check.yml`
- `clawdstrike-publish.yml`

These are SDK-consumer-facing example workflows that ship in the repo as documentation. They're never used by `.github/workflows/*.yml` proper. GitHub Actions still parses every `.github/workflows/*.yml`, but files under `examples/` are NOT picked up by GitHub (only direct children of `workflows/`), so they're harmless from a CI execution standpoint — but they DO pollute the directory.

**Aggressive cleanup:** Move to `docs/examples/workflows/` (the natural home for SDK consumer examples). Or wipe if `docs/` already covers this. Cosmetic but cleans up the workflow directory listing.

### [N-05] `infra/external/hushspec` path-dep relocated on another branch, not on HEAD
**Where:** Test only — `ls infra/external/` returns "No such file or directory" on this branch.
**Context:** A peer cleanup branch (`chore/cleanup-tier-ab` family) has commit `d12066c32 refactor: relocate hushspec path-dep crate to infra/external/`. That branch moved the hushspec crate from sibling-repo path to in-tree. The audit didn't mention hushspec, but the next CI/infra audit refresh would likely flag this — currently `Cargo.toml` (visible as modified in `git status`) and `crates/libs/clawdstrike/Cargo.toml` were touched by the same `d3ecce751` commit, hinting at hushspec being a path-dep that triggers the inline crate-publish-list comment at `release.yml:131-135`.

**Action:** Track the upstream cleanup-tier-ab branch merge. If/when hushspec moves into the repo, the `release.yml` "cannot publish clawdstrike to crates.io" comment can finally be deleted.

---

## DEFER / OUT OF SCOPE

These were marked "Leave alone" in the audit and remain correct:
- `docs.yml` — best workflow in the repo. Has concurrency, scoped permissions, paths filter, parallel linkcheck job. (`docs.yml:1-103`)
- `argo-dev-verify.yml` — purpose-built diagnostic workflow with OIDC + Argo sync wait. (`argo-dev-verify.yml:1-168`)
- `helm-cluster-smoke.yml` — gate-job pattern with `merge-candidate` label + fork-safe `if:` clauses. (`helm-cluster-smoke.yml:1-168`)
- Dockerfile multi-stage + non-root + tini PID-1 pattern across all 9 Dockerfiles — correct, only collapse duplication.
- OIDC-to-AWS in `argo-dev-verify`, `helm-cluster-smoke`, `helm-nightly-resilience`, `promote-dev-profile-images` — modern, no long-lived AWS keys.
- `formal-verification.yml` — narrow scope, opt-in nightly runs, has timeouts. (`formal-verification.yml:1-474`)
- `release.yml`'s `publish_with_retry()` function at `release.yml:163-202` — handles real crates.io flakiness with exponential backoff and retryable-error pattern matching. Leave.
- Helm chart structure (`infra/deploy/helm/clawdstrike/`) — has `profiles/`, `ci/`, `templates/`, NetworkPolicies, PDBs, HPAs, ServiceMonitor, 689-line values.yaml. Real chart.
- `scripts/codex-swarm/` overall structure (`bootstrap-lane.sh`, `launch-lane.sh`, etc.) — well-written, well-decomposed. EXCEPT the new `bash -lc` injection at `common.sh:462`, which must be reverted (see [N-01]).
- The macOS signing keychain create/import/cleanup pattern added by `1ade43894` (`release.yml:993-1053`) — well-written, proper lifecycle, conditional on secret presence. Good addition.
- `apps/agent/src-tauri/build.rs` placeholder regex fix from `2eff91532` — tiny correctness fix, allows underscore in placeholder names. Fine.

**Infra/vendor structural drift (not code review):** The vendor tree IS out of date relative to `Cargo.lock` for some crates (the recent dependency bumps in `1515cd753 chore(deps): minor Rust bumps` etc. don't all show up in vendor diffs). The recommendation is structural — wipe vendor entirely (see [N-03]) — not "audit vendored code".

---

## AGGRESSIVE EXECUTION PLAN (top-5)

These are the actions an outside reviewer would flag first, ordered by signal-per-hour.

### 1. Add top-level `concurrency:` + `permissions:` + `timeout-minutes:` to all 16 workflows (HIGH, trivial)
- Concurrency on 12 workflows missing it. Permissions on 7. Default timeout in `ci.yml`.
- **Total edit:** ~40 lines added across ~16 files.
- **Impact:** Eliminates duplicate runs on force-push, caps blast radius of compromised dependency, prevents stuck-job runner-hours. Zero risk.
- **Time:** 20 min.

### 2. Pin `aquasecurity/trivy-action@master` → SHA, delete `continue-on-error: true` in all 9 places, emit SARIF (HIGH, trivial)
- `docker.yml:81,122,163,204,245,286,327,368,409` + 9× `continue-on-error: true` deletions.
- Add `format: 'sarif'`, output to `trivy-results.sarif`, upload to `github/codeql-action/upload-sarif@v3`.
- **Total edit:** ~50 lines.
- **Impact:** Trivy results actually become enforceable; security tab gets populated; supply-chain-attack-via-action risk drops from real to nominal.
- **Time:** 30 min.

### 3. Collapse `docker.yml` 9 jobs into a matrix (HIGH, small)
- Replace 9 near-identical jobs with one matrix-driven job. Extract `_build-image.yml` reusable workflow.
- **Total edit:** -280 lines from `docker.yml`, +80 lines in `_build-image.yml`.
- **Impact:** Adding a new image becomes a 5-line matrix entry instead of a 40-line job copy. Security tooling changes (Trivy SBOM, Cosign) get one edit, not 9.
- **Time:** 2-3 hours.

### 4. Move audit-ignore list from `ci.yml` → `deny.toml` + `.cargo/audit.toml` (HIGH, small)
- Delete 38-entry inline `audit_ignores=( ... )` array at `ci.yml:486-533`.
- Add structured entries to `deny.toml [advisories]` block and generate `.cargo/audit.toml`.
- Update `tools/scripts/check-advisory-expiry.sh` to read `deny.toml` via `cargo deny check --json` or `tomlq`.
- Delete or auto-generate `docs/security/dependency-advisories.md` from `deny.toml`.
- **Total edit:** -50 lines `ci.yml`, +40 lines `deny.toml`, new `.cargo/audit.toml`, ~30 lines updated in `check-advisory-expiry.sh`.
- **Impact:** Single source of truth. Local `cargo audit` matches CI. Reviewer-visible improvement.
- **Time:** 1-2 hours.

### 5. WIPE `infra/vendor/` and replace with CI-time `cargo vendor` (HIGH, medium)
- Delete 1.0 GB / 841 directories. Delete `.cargo/config.toml`'s `[source.vendored-sources]` block.
- Add a CI step: `cargo vendor && cargo build --offline` for the offline workflow only.
- **Total edit:** -1 GB from git history (use `git filter-repo` to also purge from history if size matters).
- **Impact:** Clone size drops 100×. Dependency bumps no longer touch 100+ vendor files per change. CVE-tracking moves to crates.io (where the advisories live). This is the single largest cleanup possible in scope.
- **Time:** 1 day (including history-rewrite + downstream CI plumbing if needed).
- **Risk:** If anyone genuinely depends on offline/air-gapped builds, document the alternative (`cargo vendor` invocation in a release-artifact tarball).

### Honorable mention (#6, but earned its place)
**REVERT the `bash -lc "$bootstrap_preset"` change in `scripts/codex-swarm/common.sh:458-465`** (`1ade43894`). 5-line edit. Restores fail-closed unknown-preset behavior. Eliminates a fresh shell-injection sink. 5 minutes. This was a regression introduced after the audit was written and must not survive merge.

---

*Outside reviewer's updated verdict:* The bones are still right. The cleanup-tier-ab work landed on a sibling branch but not on `fix/macos-es-ne-hardening`, so HEAD looks exactly like the audit said. Two days of focused work merged into main and this becomes a portfolio piece. Until then, the audit's "5/10 polish, 7/10 ambition" call holds — with one new sharp edge (`bash -lc` injection) and one fresh load-bearing wart (1 GB vendor tree) that weren't itemized in the original.
