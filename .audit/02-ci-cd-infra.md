# CI/CD & Infrastructure Audit

**Scope:** `.github/`, `infra/` (excl. `infra/vendor/`), `scripts/`, top-level `Dockerfile.*`, `docker-compose*.yaml`.
**Auditor stance:** Would a senior SRE / staff engineer reviewing this for a Series A diligence call (or an OSS launch) be impressed, or quietly close the tab?

## Executive Summary

This is a serious-looking pipeline that has clearly been bolted together by someone competent under deadline pressure, then never refactored. The good parts are real: OIDC-to-AWS instead of long-lived keys, GHCR with cache-from `type=gha`, an EKS smoke-and-verify chain backed by Argo, a real release pipeline that publishes crates / npm / PyPI / Homebrew with retry + idempotency checks, formal-verification jobs wired into the same surface, mdBook deploys via GH Pages with link-checking, Helm chart published to an OCI registry plus Artifact Hub metadata, and macOS notarization scripted end-to-end. None of that is amateur hour.

The problems are equally real and would be the first thing a senior reviewer flags. `ci.yml` is **1,497 lines and 33 jobs** with effectively no concurrency cancellation, only 4/33 timeouts, and a path-trigger-less `on:` block so every job runs on every push to every PR. `docker.yml` is 414 lines of **near-perfect copy-paste**: 9 image build jobs that are byte-for-byte identical except for the image name and Dockerfile path — this should be one matrix or a reusable workflow. `release.yml` (1,266 lines, 19 jobs) hardcodes a 32-entry `cargo audit --ignore` list inline in the workflow with comments mid-array, `aquasecurity/trivy-action@master` is pinned to a moving branch in 9 places, the audit ignore list duplicates work that should live in `deny.toml`, and several Dockerfiles ship `:latest` tags from CI alongside immutable SHA tags (so consumers get rolling deployments by default).

There is also material cruft: 18 Python scripts in `scripts/` totaling **~14,000+ LOC** with names like `endpoint-decision-engine-readiness-audit.py` (3,814 lines), `endpoint-decision-engine-qualification-bundle.py` (2,538 lines), and `endpoint-deception-proof.py` that look like one-shot "evidence bundle" generators that were never deleted. A `cleanup-legacy-paths.sh` script silently `rm -rf`s a hardcoded list (no `--dry-run`, no confirm, no logging beyond echo). The `__pycache__` directories under `scripts/` and `tools/scripts/` are not tracked (good) but are sitting in working copy because contributors are running these as part of normal dev. CODEOWNERS is a single-user file (`* @connor`) with a misleading comment ("Replace @connor with org teams as they are formalized") that has clearly not been replaced.

Net read: 7/10 ambition, 5/10 execution polish. Cleaning this up is mostly mechanical — extract reusable workflows, add concurrency + timeouts globally, pin action versions, kill the proof-bundle scripts, move audit ignores into `deny.toml`/`audit.toml`. Two days of focused work and this is genuinely impressive.

## Scores (1-10)

| Dimension | Score | One-line justification |
|---|---|---|
| CI quality | **5/10** | Strong coverage; killed by 1497-line monolith, no concurrency, missing timeouts, no path filters on PR-blocking jobs |
| Release pipeline | **7/10** | Genuinely thorough (crates+npm+pypi+homebrew+OCI+notarization+OTA manifest) but oversized and hand-rolled where tools exist |
| Security / permissions | **5/10** | OIDC + scoped `permissions:` on most workflows is good; 7 workflows have NO top-level permissions block, trivy pinned to `@master`, 32-entry audit ignore list in YAML |
| Build hygiene (cache, parallelism) | **6/10** | GHA cache used everywhere, matrix builds present, but 8 separate caches with overlapping keys and no shared restore strategy; `cargo install` rebuilds tools per job |
| Infra-as-code quality | **6/10** | Helm chart is real (689-line values.yaml, profiles, CI values, NetworkPolicies, PDBs, HPAs, ServiceMonitor); Dockerfiles are correct but heavily duplicated |
| Script hygiene | **4/10** | Codex-swarm / helm scripts are clean; main `scripts/` dir contains 5-figure-LOC proof bundles, hardcoded `rm -rf` scripts, no usage strings on most |

---

## Workflow Inventory

| Workflow | Trigger | Purpose | Health |
|---|---|---|---|
| `ci.yml` (1497L, 33 jobs) | push/PR to main | Rust + TS + Python + WASM + matrix tests | **Concerning** — monolithic, no concurrency, mostly no timeouts |
| `release.yml` (1266L, 19 jobs) | tag `v*` or dispatch | Publish to crates.io / npm / PyPI / GHCR / Homebrew / GH Releases / OTA manifest | **Concerning** — works, but oversized and embeds audit-ignore list |
| `docker.yml` (414L, 9 jobs) | push to main (path-gated) | Build & push 9 images to GHCR | **Concerning** — 90% copy-paste; should be matrix |
| `formal-verification.yml` (474L) | push/PR/sched/dispatch | Z3 + Lean + Aeneas + diff tests | Good — well-scoped, has timeouts, conditional jobs |
| `docs.yml` (103L) | push (docs/**) | mdBook → GH Pages + link check | **Good** — exemplary: concurrency, scoped permissions, paths filter |
| `helm-ci.yml` (47L) | push/PR (helm/**) | helm lint + template + package | Good |
| `helm-release.yml` (110L) | tag `v*` / dispatch | Push chart to GHCR OCI + Artifact Hub | Good |
| `helm-cluster-smoke.yml` (168L) | PR w/ `merge-candidate` label / dispatch | EKS smoke test via Argo-adjacent path | Good — has gate job, fork-safe |
| `helm-nightly-resilience.yml` (187L) | nightly 02:00 UTC / dispatch | Resilience + security on EKS | Good |
| `argo-dev-verify.yml` (168L) | push main / dispatch | Wait for Argo to sync to commit SHA, collect diagnostics | Good — purpose-built and complete |
| `promote-dev-profile-images.yml` (123L) | workflow_run on `Docker Build & Push` | Auto-bump dev profile image tags, commit back to main, sync Argo | **Concerning** — bot commits to main via `GHCR_PUSH_TOKEN` (PAT) |
| `desktop-release.yml` (91L) | dispatch only | Unsigned macOS desktop build | Good — clearly an escape hatch |
| `ffi-bindings.yml` (78L) | push/PR (ffi paths) | Go + .NET FFI tests, matrix linux/mac | Good |
| `fuzz.yml` (41L) | nightly 03:00 UTC / dispatch | 9 fuzz targets × 120s | Good |
| `miri.yml` (39L) | weekly Mon 05:00 UTC / dispatch | Curated Miri security regression tests | Good |
| `sanitizers.yml` (37L) | nightly 04:00 UTC / dispatch | ASAN smoke on 3 tests | Good — narrow but real |

**Total:** 16 workflows, ~4,843 lines of YAML.

---

## Strengths

1. **OIDC-to-AWS everywhere it matters** (`argo-dev-verify`, `helm-cluster-smoke`, `helm-nightly-resilience`, `promote-dev-profile-images`). No long-lived AWS keys in secrets.
2. **Real release plumbing.** `release.yml` checks crates.io / npm / PyPI for existing versions and skips idempotently; retries publishes with backoff on transient errors (`release.yml:163-202`); generates and signs hushd OTA manifests; builds notarized macOS DMG with proper keychain create/delete lifecycle (`release.yml:996-1053`).
3. **Helm chart isn't fake.** `infra/deploy/helm/clawdstrike/` has 689-line `values.yaml`, separate `profiles/`, separate `ci/` values for smoke + resilience, NetworkPolicy, PDB, HPA, ServiceMonitor, ExternalSecrets, RBAC, ingresses, and a chart-tests dir. This is what a real chart looks like.
4. **Formal verification is wired into CI** (`formal-verification.yml`): Z3 policy verification + Lean spec build + Aeneas regen + differential tests with nightly 100M-case runs. Few projects this size have any of this.
5. **PR gate has gates.** `helm-cluster-smoke.yml` requires a `merge-candidate` label and refuses to run on forks — the right call for a workflow that needs OIDC into a real cluster.
6. **`docs.yml` is exemplary.** Path-scoped trigger, scoped permissions, `concurrency: { group: pages, cancel-in-progress: true }`, parallel linkcheck job. If every workflow looked like this we'd be done.
7. **Dockerfiles all use multi-stage + non-root user + tini PID-1 + cache mounts.** No `apt-get install` without `--no-install-recommends`. No `:latest` base images — `rust:1.93-bookworm` and `debian:bookworm-slim` are pinned.
8. **`.dockerignore` not needed because Dockerfiles selectively `COPY`** specific crates (`infra/docker/Dockerfile.spine:27-28`). Smart approach to keep build context minimal without an ignore file.
9. **`scripts/codex-swarm/` is well-written** — proper `set -euo pipefail`, usage strings, function decomposition, comments.

---

## Findings

### [HIGH] CI hygiene: `ci.yml` is a 1497-line monolith with no concurrency cancellation

- **Where:** `.github/workflows/ci.yml` (entire file)
- **What:** 33 jobs, **no top-level `concurrency:`** block, only 4 of 33 jobs have `timeout-minutes`, `on:` triggers every push/PR to main with no `paths:` filter, so a docs-only change runs Rust + Tauri + WASM + Python + 8-way agent-framework matrix + OpenClaw 3-version matrix.
- **Why it matters:** Force-pushing twice to a PR runs everything twice in parallel. CI cost balloons. PR turnaround sucks. Stuck Tauri jobs hold runners for hours.
- **Recommended action:** **RESTRUCTURE**.
  1. Add top-level `concurrency: { group: ci-${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: ${{ github.event_name == 'pull_request' }} }`.
  2. Add default `timeout-minutes: 30` and override per job.
  3. Split into 3-5 reusable workflows by domain (rust-core / ts-sdk / tauri-apps / openclaw-matrix / agent-frameworks) called from a thin top-level `ci.yml` with path filters per call.
- **Effort:** medium (~1 day to extract + verify each split).

### [HIGH] Copy-paste: `docker.yml` is 9 identical jobs, should be a matrix or reusable workflow

- **Where:** `.github/workflows/docker.yml:43-414`
- **What:** Jobs `spine`, `tetragon-bridge`, `hubble-bridge`, `hushd`, `control-api`, `registry`, `auditd-bridge`, `k8s-audit-bridge`, `eas-anchor` are byte-identical except for `name`, `file:`, image-name in `tags:`, and `image-ref:` in the Trivy step. Plus an inner matrix for `spine`'s 3 binaries.
- **Why it matters:** Editing one Docker behavior (e.g. adding SBOM generation, switching to Cosign, adjusting Trivy severity) means 9 identical edits. Adding a new image means copy-pasting 40 lines. This is the textbook "you have a matrix problem" anti-pattern.
- **Recommended action:** **REWRITE** as a single job with a strategy matrix:
  ```yaml
  strategy:
    matrix:
      include:
        - image: spine
          dockerfile: infra/docker/Dockerfile.spine
          extra-bins: [spine-checkpointer, spine-witness, spine-proofs-api]
        - image: hushd
          dockerfile: Dockerfile.hushd
        # ...
  ```
  Or pull the login+build+scan steps into `.github/workflows/_build-image.yml` reusable workflow called per image. Either drops ~280 lines.
- **Effort:** small (2-3 hrs).

### [HIGH] Pinned action `aquasecurity/trivy-action@master` — moving target across 9 jobs

- **Where:** `.github/workflows/docker.yml:81, 122, 163, 204, 245, 286, 327, 368, 409`
- **What:** Trivy action pinned to `@master`. Combined with `continue-on-error: true` on every scan, this means Trivy failures are silently ignored AND the action itself can change behavior overnight.
- **Why it matters:** Supply-chain risk (compromised action), reproducibility risk (yesterday's CI ≠ today's CI), and the `continue-on-error: true` defeats the whole point of scanning. You're paying for the scan and ignoring the result.
- **Recommended action:** **REWRITE**: pin to a SHA or `@v0.x`, remove `continue-on-error: true`, decide whether HIGH/CRITICAL findings should block (`exit-code: 1`) or be uploaded to GitHub code scanning (`format: sarif` + `github/codeql-action/upload-sarif`).
- **Effort:** trivial (15 min once policy is decided).

### [HIGH] Audit-ignore allowlist (32 entries) embedded inline in `ci.yml`

- **Where:** `.github/workflows/ci.yml:488-533`
- **What:** Hand-maintained `audit_ignores=(...)` bash array with 32 `RUSTSEC-*` ignores, including mid-array comments. Several have no expiry date, no owner, no link to tracking issue. Plus there's a separate `tools/scripts/check-advisory-expiry.sh` that runs first — implying expiry is *supposed* to be tracked, but the actual ignores live in YAML.
- **Why it matters:** Advisory ignores are tech debt that goes stale. Sticking them in workflow YAML hides them from `cargo audit` users running locally and makes drift between local and CI inevitable. The "Temporary: SEC-PTY-001" comment shows the right instinct, but it's the wrong location.
- **Recommended action:** **RESTRUCTURE**. Move to `deny.toml`'s `[advisories]` section (or `audit.toml` if using cargo-audit directly), with one block per ignore including `id`, `reason`, `expiry-date`, `owner`. The `check-advisory-expiry.sh` script already exists — point it at the structured file and delete the bash array.
- **Effort:** small (1-2 hrs).

### [MEDIUM] 7 workflows have no top-level `permissions:` block

- **Where:** `ci.yml`, `ffi-bindings.yml`, `formal-verification.yml`, `fuzz.yml`, `helm-ci.yml`, `miri.yml`, `sanitizers.yml`
- **What:** Without a top-level `permissions:` block, GHA falls back to the repo default — which for many older repos is `write-all`. Even if this repo is set to `read`, defense-in-depth says set it explicitly.
- **Why it matters:** A compromised dependency or step (e.g. malicious npm package in a `npm ci`) gets whatever the default token can do. Setting `permissions: { contents: read }` at the top of every workflow caps blast radius.
- **Recommended action:** **DOCUMENT** the policy in `.github/README.md` and add `permissions: { contents: read }` to all 7 workflows. Override at job level where needed (uploading artifacts doesn't need write; creating releases does).
- **Effort:** trivial (10 min).

### [MEDIUM] Missing `concurrency:` block on 12 of 16 workflows

- **Where:** All except `docs.yml`, `docker.yml`, `release.yml`, `promote-dev-profile-images.yml`.
- **What:** Re-pushing a branch or merge-train ordering causes duplicate runs to pile up.
- **Why it matters:** Wastes runner minutes, slows feedback, can race (e.g. two `helm-cluster-smoke` runs racing on the same EKS namespace).
- **Recommended action:** **RESTRUCTURE** — add `concurrency: { group: <workflow>-${{ github.ref }}, cancel-in-progress: <true for PR jobs, false for release/cron> }` to each.
- **Effort:** trivial (20 min).

### [MEDIUM] `promote-dev-profile-images.yml` bot-commits to `main` with a PAT

- **Where:** `.github/workflows/promote-dev-profile-images.yml:32-87`
- **What:** Workflow checks out main using `secrets.GHCR_PUSH_TOKEN` (a PAT), runs a script that rewrites image tags in a Helm profile, commits as `github-actions[bot]`, and pushes directly to main. Branch protection on main therefore must allow this PAT to bypass it, OR there's no branch protection on main, OR there's a bypass list. None of those are great.
- **Why it matters:** PAT-as-bot-committer is the standard escape hatch but it's a long-lived credential that bypasses code review on main. If the PAT leaks, an attacker can land arbitrary commits on main.
- **Recommended action:** **RESTRUCTURE**. Replace with one of: (a) a GitHub App token (short-lived, scoped, auditable), (b) a separate `image-promotions` branch + auto-PR + auto-merge with required reviews waived for this bot, or (c) Argo Image Updater pulling tags from GHCR directly rather than rewriting YAML.
- **Effort:** medium (4-6 hrs to introduce a GitHub App).

### [MEDIUM] Cache key sprawl: 8 different `cargo-*` cache keys, no shared restore

- **Where:** `ci.yml:71-79, 236-245, 367-376, 693-701, 750-758, 779-788, 1160-1170, 1352-1362` (and others)
- **What:** Every job rolls its own cache key (`cargo-`, `cargo-tauri-`, `cargo-sdr-`, `cargo-proptest-`, `cargo-integration-`, `cargo-policy-parity-`, `cargo-parity-`, `cargo-ffi-`, `cargo-wasm-`...). Each ends up with its own `target/` directory in cache. Cache eviction hits hard.
- **Why it matters:** Cold-cache builds are slow, GHA cache has a 10 GB repo limit, divergent caches mean different jobs constantly rebuild the same deps. Also, **none of the caches use `Swatinem/rust-cache`** which is the standard and handles cache-key fingerprinting + cleanup automatically.
- **Recommended action:** **REWRITE**. Replace all `actions/cache@v5` for Cargo with `Swatinem/rust-cache@v2` and pass `shared-key:` per job-family (e.g. `tauri`, `wasm`, `core`). Drops ~80 lines of YAML and improves cache hit rate.
- **Effort:** small (2 hrs).

### [MEDIUM] Dockerfiles ship `:latest` from CI on every push to main

- **Where:** `docker.yml:73-74, 114-115, 154-155, ...` (all 9 jobs)
- **What:** Every push to main publishes both `<image>:latest` AND `<image>:<sha>`. Consumers pulling `:latest` (including the included `docker-compose.services.yaml` defaults? let's check — actually local compose uses `build:` not `image:`, so OK there) get rolling deploys.
- **Why it matters:** "Best practice" guidance is that `:latest` shouldn't be auto-published to a shared registry on every commit. It's a footgun for downstreams and an antipattern in production deployments (which is why `promote-dev-profile-images.yml` exists — it's working around this by pinning SHAs in a profile).
- **Recommended action:** **DOCUMENT** the policy in `infra/docker/README.md`. Consider publishing `:edge` for tip-of-main and reserving `:latest` for `release.yml` tag pushes. Low priority since the Argo pipeline pins SHAs, but cleaner.
- **Effort:** trivial (15 min).

### [MEDIUM] `cleanup-legacy-paths.sh` silently `rm -rf`s hardcoded paths

- **Where:** `scripts/cleanup-legacy-paths.sh:21-27`
- **What:**
  ```bash
  for path in "${LEGACY_PATHS[@]}"; do
    if [[ -e "$path" ]]; then
      rm -rf "$path"
      echo "[cleanup-legacy-paths] removed: $path"
    fi
  done
  ```
  No `--dry-run`, no usage string, no guard for "are we in the right repo". `LEGACY_PATHS` includes generic-sounding entries like `vendor` and `deploy`. If someone runs this in the wrong directory, it eats their work.
- **Why it matters:** "rm -rf hardcoded list" is the classic CI-script footgun. Combine it with the fact that one of the paths is literally `vendor` (which exists in many repos), and this is a loaded gun in the toolbox.
- **Recommended action:** **REWRITE**. Add `set -euo pipefail` (already there), add a repo-identity guard (assert `git rev-parse --show-toplevel` matches expected), add `--dry-run` default-on with `--apply` to actually delete, add `--help` usage string. Or **WIPE** if the legacy paths are gone for good.
- **Effort:** trivial (30 min).

### [MEDIUM] CODEOWNERS is a single-user file with a stale comment

- **Where:** `.github/CODEOWNERS:1-23`
- **What:** Every owner is `@connor`. The comment says "Replace @connor with org teams as they are formalized" — written months ago, never replaced.
- **Why it matters:** Single human bus factor; PRs can't auto-route to a domain expert; "ownership" is performative. Also looks like a hobby project to an outside reader.
- **Recommended action:** **DOCUMENT** in `GOVERNANCE.md` that this is intentional bootstrap state OR **REWRITE** with at least 2-3 domain teams (`@backbay-labs/core-rust`, `@backbay-labs/sdk-ts`, `@backbay-labs/infra`).
- **Effort:** trivial.

### [LOW] `scripts/` has 18 Python "proof bundle" scripts (~14k LOC) that look one-shot

- **Where:** `scripts/endpoint-decision-engine-readiness-audit.py` (3814 L), `scripts/endpoint-decision-engine-qualification-bundle.py` (2538 L), `scripts/macos-provider-dogfood-manifest.py` (1789 L), `scripts/endpoint-decision-engine-supplemental-proof-bundle.py`, `scripts/operator-workflows-proof.py`, `scripts/privacy-preserving-telemetry-proof.py`, `scripts/policy-simulation-impact-proof.py`, `scripts/supply-chain-runtime-guard-proof.py`, `scripts/ai-agent-developer-workstation-proof.py`, `scripts/endpoint-deception-proof.py`, `scripts/cross-platform-sensor-breadth-proof.py`, ...
- **What:** Multi-thousand-line scripts with names like "qualification-bundle", "readiness-audit", "dogfood-manifest", "evidence", "proof". None referenced from CI workflows (verify: only `macos-provider-live-dogfood.sh` is in workflows, and not its `.py` cousins).
- **Why it matters:** Reads as either deliverables for a customer demo that should live in `docs/evidence/` or a separate `audits/` repo, OR abandoned scaffolding. Either way, having 14k LOC of unreferenced Python in `scripts/` makes the directory feel like a junk drawer.
- **Recommended action:** **DOCUMENT** in `scripts/README.md` (which exists, 20k bytes — worth re-reading) what each is for and when it runs, OR **WIPE** the unreferenced ones, OR **RESTRUCTURE** into `tools/evidence/` or `audits/`.
- **Effort:** small (1 hr to triage).

### [LOW] 4 shell scripts missing `set -euo pipefail` at the very top (false alarm — verify)

- **Where:** `scripts/openclaw-plugin-runtime-common.sh`, `scripts/openclaw-agent-smoke.sh`, `scripts/endpoint-decision-engine-live-qualification.sh`, `scripts/macos-provider-live-dogfood.sh`
- **What:** Grep for `set -euo pipefail` returned them as missing, but spot-check showed they have it (line 2). Likely a grep edge case (extra blank line). Disregard if confirmed.
- **Recommended action:** **LEAVE**, but spot-check during cleanup.
- **Effort:** trivial.

### [LOW] `Dockerfile.hushd` and `Dockerfile.registry` live at repo root, others under `infra/docker/`

- **Where:** `/Dockerfile.hushd`, `/Dockerfile.registry` vs `infra/docker/Dockerfile.*`
- **What:** Inconsistent placement. `docker.yml` references both locations.
- **Why it matters:** Cosmetic but it's the kind of thing a reviewer notices immediately. Implies someone added the first two before the convention was established.
- **Recommended action:** **RESTRUCTURE** — move to `infra/docker/Dockerfile.hushd` and `infra/docker/Dockerfile.registry`, update `docker.yml` paths. Or document why the two daemons live at root.
- **Effort:** trivial.

### [LOW] `release.yml` resolves crate publish order with hardcoded list + comment about excluded crates

- **Where:** `release.yml:128-151`
- **What:**
  ```
  # The remaining 0.2.7-drifting public crates stay excluded for now:
  # - clawdstrike: dry-run fails against crates.io's hushspec/nono surface
  # - clawdstrike-policy-event, hunt-scan, hunt-query, hunt-correlate, hush-cli, ...
  crates=(logos-ffi clawdstrike-ocsf hush-core hush-proxy hush-spine)
  ```
- **Why it matters:** Comments admit the release workflow can't publish the *main* `clawdstrike` crate to crates.io. The publish pipeline is partially aspirational. This is honest documentation, but it makes the "we have a release pipeline" claim weaker than it appears.
- **Recommended action:** **DOCUMENT** the unblock plan in `docs/release-process.md` with target dates, OR **RESTRUCTURE** by using `cargo-release` / `release-plz` which handle dep-order publishing.
- **Effort:** medium (the underlying crates.io issues are real).

### [LOW] `release.yml` hand-rolls Homebrew formula generation via inline heredoc + sed

- **Where:** `release.yml:1220-1264`
- **What:** Heredoc Ruby template + 4 `sed -i` replacements + manual `git clone`/`commit`/`push` to a separate tap repo.
- **Why it matters:** Works, but error-prone (placeholder regex would silently miss a typo). Standard pattern is `Homebrew/actions/setup-homebrew` + `homebrew-bump-formula` action or `goreleaser` with brew config.
- **Recommended action:** **REWRITE** using `dawidd6/action-homebrew-bump-formula` or similar. Or **LEAVE** if low-frequency releases make this not worth the maintenance.
- **Effort:** small.

### [LOW] Helm `Chart.yaml` version `0.2.0` but pre-1.0 chart published to public Artifact Hub

- **Where:** `infra/deploy/helm/clawdstrike/Chart.yaml:5`
- **What:** Pre-1.0 chart with `artifacthub.io/license: Apache-2.0` annotation; gets published to GHCR + Artifact Hub on every tag. No `deprecated:` or maturity signal.
- **Why it matters:** External users may pull a chart that's pre-1.0 and lacks stability guarantees. The README probably says so; the Chart.yaml doesn't.
- **Recommended action:** **DOCUMENT** — add `annotations.artifacthub.io/prerelease: "true"` until 1.0, link to deprecation/stability policy.
- **Effort:** trivial.

### [LOW] `docker-compose.services.yaml` ships dev default secrets in env vars

- **Where:** `infra/docker/docker-compose.services.yaml:76-80, 113, 133-135`
- **What:** `JWT_SECRET: ${... :-dev-jwt-secret-local}`, `STRIPE_SECRET_KEY: ${... :-sk_test_local}`, `CLAWDSTRIKE_ADMIN_KEY: ${... :-clawdstrike-local-admin}`, etc.
- **Why it matters:** These ARE clearly labeled dev defaults (the values say `-local`). The risk is low. The smell is that someone running compose without setting env vars gets a working-but-insecure stack. A senior reviewer will pattern-match on "Stripe secret in YAML" and flinch before reading the default.
- **Recommended action:** **DOCUMENT** at top of file: "All `:-...-local` defaults are local-dev only — never use these values in any environment reachable from outside `localhost`." Or **REWRITE** to require an `.env.local` file with `mandatory: true` semantics.
- **Effort:** trivial.

### [LOW] `Dockerfile.spine` accepts `BIN` ARG but ignores it at runtime

- **Where:** `infra/docker/Dockerfile.spine:11-66`
- **What:** `ARG BIN` declared twice; final entrypoint is `entrypoint-spine.sh` with `ENV SPINE_BIN=${BIN}`. CI workflow passes `BIN=spine-checkpointer` etc. but the same `Dockerfile.spine` is reused for 3 different binaries via build args. Functional but unusual.
- **Recommended action:** **LEAVE** — it works and the build matrix is small. Document in the file header (it already is).

### [LOW] `tools/scripts/` and `scripts/` both exist with overlapping responsibilities

- **Where:** `scripts/` (61 files) vs `tools/scripts/` (5 files)
- **What:** Both contain CI helpers. `tools/scripts/check-advisory-expiry.sh`, `tools/scripts/check-changed-rust-coverage.py`, `tools/scripts/policy-parity.mjs`, `tools/scripts/agent-fail-closed-smoke.mjs`, `tools/scripts/validate-docs`. CI references both paths.
- **Why it matters:** Inconsistency — new contributors won't know where to put a new script.
- **Recommended action:** **DOCUMENT** the distinction or **RESTRUCTURE** by consolidating. `tools/scripts/` looks like the better-organized half; move the rest in there or vice versa.
- **Effort:** small.

### [LOW] No top-level `Makefile` / `justfile` / `Taskfile` — only `mise.toml`

- **Where:** Repo root.
- **What:** Project uses `mise` for tasks. That's a valid choice, but most senior reviewers will first look for a `Makefile` or `justfile`.
- **Recommended action:** **LEAVE** — `mise.toml` is fine. Just make sure `CONTRIBUTING.md` shouts about it.

### [LOW] CI references both `bash scripts/foo.sh` and `scripts/foo.sh` inconsistently

- **Where:** `ci.yml:25-31` runs `cargo test` directly; line 48 `bash rulesets/tests/policy-torture/run.sh`; line 96 `bash scripts/smoke-ts-file-deps.sh`; line 162 `bash scripts/run-sdk-conformance.sh`; etc. — sometimes `bash <script>`, sometimes `<script>` directly. Both work because of shebangs, but inconsistent.
- **Recommended action:** **DOCUMENT** convention in `scripts/README.md` ("invoke via `scripts/x.sh` — shebangs are canonical").
- **Effort:** trivial.

---

## Action Plan (priority order)

1. **Add concurrency + permissions + timeouts to all workflows** (HIGH, trivial). One PR, ~60 lines added across 16 files.
2. **Pin `aquasecurity/trivy-action@master` to SHA, remove `continue-on-error: true`, decide block-or-upload-sarif** (HIGH, trivial).
3. **Collapse `docker.yml` 9 jobs into a matrix** (HIGH, small). Drops ~280 lines.
4. **Move 32-entry `cargo audit --ignore` list from `ci.yml` into `deny.toml`/`audit.toml` with structured `id/reason/expiry/owner`** (HIGH, small).
5. **Replace per-job `actions/cache@v5` with `Swatinem/rust-cache@v2`** (MEDIUM, small). Drops ~80 lines, improves cache hit rate.
6. **Split `ci.yml` (1497L) into reusable workflows by domain** (HIGH, medium). One per: rust-core, ts-sdk, tauri, openclaw-matrix, agent-frameworks, python.
7. **Triage 18 Python proof-bundle scripts in `scripts/`** (LOW, small). Either move to `tools/evidence/` or delete unreferenced ones.
8. **Replace PAT-based bot commit in `promote-dev-profile-images.yml` with GitHub App or Argo Image Updater** (MEDIUM, medium).
9. **Move `Dockerfile.hushd` + `Dockerfile.registry` into `infra/docker/`** (LOW, trivial).
10. **Add `--dry-run` default + repo-root assertion to `cleanup-legacy-paths.sh`** (MEDIUM, trivial).
11. **Update CODEOWNERS or document why it's still single-user** (MEDIUM, trivial).
12. **Add chart-prerelease annotation, document dev-default secrets in compose header** (LOW, trivial).

## Top 5 Quick Wins

1. **Add top-level `concurrency:` to `ci.yml`** — one block, eliminates duplicate runs on force-push, biggest quality-of-life win. (5 min)
2. **Pin `trivy-action` and drop `continue-on-error: true`** — security gain + 30 LOC delta. (15 min)
3. **Add `permissions: { contents: read }` to the 7 workflows missing it** — defense in depth, zero risk. (10 min)
4. **Convert `docker.yml` to matrix** — visible 70% LOC reduction, looks immediately more professional. (2 hrs)
5. **Migrate audit ignores out of YAML into `deny.toml`** — moves a glaring eye-sore out of the most-read CI file. (1 hr)

## Things to Leave Alone

- **`docs.yml`** — best workflow in the repo; do not touch.
- **`argo-dev-verify.yml`** — purpose-built, complete, well-instrumented. Leave.
- **`helm-cluster-smoke.yml` gate-job pattern** — correct fork-handling + label-gating; copy this pattern elsewhere.
- **Dockerfile multi-stage + non-root + tini pattern** — already correct; only collapse duplication.
- **OIDC-to-AWS approach** — modern, correct.
- **Formal verification workflow** — narrowly scoped, opt-in via dispatch for the heavy bits. Leave.
- **The retry logic in `release.yml`'s `publish_with_retry`** — handles real crates.io flakiness. Leave.
- **Helm chart structure** (`infra/deploy/helm/clawdstrike/`) — has profiles, CI values, tests, NetworkPolicies, PDBs, HPAs. This is the right shape.
- **`scripts/codex-swarm/`** — well-written, do not touch.

---

*A senior SRE's verdict: "The bones are right. Spend two days deleting and refactoring, then this is a portfolio piece. Don't ship it as-is."*
