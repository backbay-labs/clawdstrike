# Monorepo Audit (2026-02-10)

## Scope

Audit focus:

1. Path and ownership coherence after Phase 0-5 monorepo restructuring.
2. Build and CI safety for moved crates/packages/infra assets.
3. Gaps that still reduce newcomer clarity or operational reliability.

Validation performed in this branch:

1. `bash scripts/test-platform.sh` (full Rust/TS/Python/docs) after Phase 2.
2. `bash scripts/path-lint.sh`.
3. `cargo metadata --no-deps`.
4. `CARGO_NET_OFFLINE=true scripts/cargo-offline.sh metadata --no-deps`.
5. `docker compose -f infra/docker/docker-compose.services.yaml config`.
6. `CARGO_NET_OFFLINE=true scripts/cargo-offline.sh test -p hush-core --lib`.

## Findings

### Medium

1. **Agent desktop crate has ongoing dead-code warnings**.
   Evidence: `apps/agent/src-tauri/src/main.rs:150`, `apps/agent/src-tauri/src/daemon.rs:72`, `apps/agent/src-tauri/src/events.rs:38` and related methods are currently unused in normal compilation.
   Impact: warning noise makes true regressions harder to spot and slows review confidence.
   Recommendation: split experimental APIs behind feature flags or remove unused surfaces before GA.

2. **Move-lint coverage is intentionally scoped and still allows stale references in non-canonical docs domains**.
   Evidence: `scripts/path-lint.sh` excludes historical/spec domains and compatibility scripts by design.
   Impact: stale legacy paths can reappear in exploratory docs or release helper scripts.
   Recommendation: keep current strict scope for CI signal quality, but add a non-blocking informational scan for `docs/specs/**`, `docs/plans/**`, and `docs/research/**`.

### Low

1. **No active low-severity findings in this audit slice**.
   Notes: previous package-manager ambiguity is now addressed via `docs/src/getting-started/package-manager-policy.md` and linked contributor guidance.

## Improvements Implemented During This Audit Cycle

1. Added CI path-lint guard: `scripts/path-lint.sh` and wired it into `.github/workflows/ci.yml` + `scripts/test-platform.sh`.
2. Completed Phase 2 grouping (`crates/{libs,services,bridges,tests}` and `packages/{sdk,adapters,policy}`).
3. Completed Phase 3 infra consolidation (`infra/deploy`, `infra/docker`, `infra/vendor`).
4. Added `hushd` Docker image build/push/scan to `.github/workflows/docker.yml`.
5. Added CI Docker Compose topology smoke validation in `.github/workflows/ci.yml`.
6. Removed all compatibility stubs from legacy paths in Phase 4 cleanup.
7. Updated operational docs and contributor references to new paths (`docs/REPO_MAP.md`, `CONTRIBUTING.md`, `AGENTS.md`, `SECURITY.md`, `GOVERNANCE.md`).
8. Added changed-path CI decomposition workflow with domain jobs (`ci-rust-libs`, `ci-rust-services`, `ci-rust-bridges`, `ci-apps`, `ci-packages-ts`, `ci-packages-py`, `ci-docs`, `ci-infra`).
9. Added move validation and architecture guardrail checks (`scripts/move-validation.sh`, `scripts/architecture-guardrails.sh`) and wired them into CI/local runs.
10. Added top-level domain READMEs and automated enforcement of README/owner/repo-map consistency.
11. Added explicit npm/Bun split policy docs and contributor/PR template guardrails.

## Recommended Next Execution Slice

1. Add non-blocking stale-path informational report job for historical docs domains.
2. Clean up agent Tauri dead-code warnings or gate unused modules with features.
3. Decide whether to fold legacy broad CI jobs into the new changed-path decomposition or keep both permanently.
