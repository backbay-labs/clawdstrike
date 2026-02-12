# Monorepo Organization Plan (Staff/Principal Engineer Proposal)

Status: In Execution  
Author: Codex (second-pass architecture audit)  
Last updated: 2026-02-10

Execution status: Phase 0 and Phase 1 are committed; Phase 2 is committed; Phase 3 is committed; Phase 4 cleanup and hardening are committed; Phase 5 guardrails/policy follow-through is committed.

## Executive Summary

This plan organizes the repository by **product intent and ownership**, not just by language.

Primary goals:

1. Make onboarding materially faster for new engineers.
2. Make ownership and boundaries obvious by folder layout.
3. Reduce build/test ambiguity across Rust, TS, Python, and Tauri.
4. Preserve release stability with phased, reversible migration steps.

This is an incremental migration, not a big-bang rewrite.

## Current-State Audit Snapshot

As of 2026-02-09:

1. Rust crates at `crates/*`: 15
2. JS/Python packages at `packages/*`: 13
3. Apps at `apps/*`: 2
4. Extra top-level integration runtime at `spine/reticulum`
5. Infra spread across `deploy/`, `docker/`, `HomebrewFormula/`, and `vendor/`
6. No first-party `CODEOWNERS` file
7. Mixed package manager signals (`package-lock.json` + per-package lockfiles + `apps/desktop/bun.lockb`)
8. Public identity mixed across `clawdstrike`, `hush`, `spine`, and `sdr`

## What Does Not Make Sense Yet (Needs Further Development)

1. **Domain boundaries are implicit**. Newcomers must infer what is “deployable service” vs “library” vs “adapter”.
2. **`packages/cloud-dashboard` is an app, not a package**. Its location increases cognitive load.
3. **`spine/reticulum` is outside standard product grouping**. The current path looks like a temporary sidecar but is production-relevant.
4. **Ownership is undocumented**. No explicit directory ownership creates review bottlenecks and unclear escalation paths.
5. **No single docs map for contributors**. Documentation exists, but there is no one-page index explaining where normative vs exploratory content lives.
6. **Tooling surface is scattered** (`scripts/` vs `tools/scripts/` without a strict convention).
7. **Inconsistent lifecycle signaling**. Some modules feel experimental, but this is not encoded by metadata/maturity labels.
8. **License metadata mismatch risk exists in repo UX**. Root README badge text and license file should be made unambiguous.

## Design Principles

1. Organize first by **responsibility**: apps, services, libraries, integrations, infra.
2. Keep **public package names and CLI contracts stable** while paths move.
3. Keep phases small and reversible.
4. Define owner and maturity metadata before structural moves.
5. Make every top-level folder self-describing with a short `README.md`.
6. Avoid cross-domain PRs that mix file moves and behavior changes.

## Target Topology (North-Star)

```text
clawdstrike/
├── apps/                         # user-facing products
│   ├── desktop/
│   ├── agent/
│   └── cloud-dashboard/
├── crates/                       # Rust code by role
│   ├── libs/
│   ├── services/
│   ├── bridges/
│   └── tests/
├── packages/                     # non-Rust SDK and adapters
│   ├── sdk/
│   ├── adapters/
│   └── policy/
├── integrations/                 # external runtimes/transports
│   └── transports/
│       └── reticulum/
├── infra/                        # deployment, containers, packaging, vendoring
│   ├── deploy/
│   ├── docker/
│   ├── packaging/
│   └── vendor/
├── docs/
├── examples/
├── fixtures/
├── rulesets/
├── scripts/                      # operator-focused entrypoints
├── tools/                        # repo-dev tooling and validators
├── Cargo.toml
├── package.json
└── mise.toml
```

## Detailed Folder Structure Proposal

### Rust crates

```text
crates/
├── libs/
│   ├── hush-core/
│   ├── hush-proxy/
│   ├── clawdstrike/
│   ├── hush-certification/
│   ├── hush-multi-agent/
│   ├── hush-wasm/
│   └── spine/                    # protocol library
├── services/
│   ├── hush-cli/
│   ├── hushd/
│   ├── spine-cli/
│   ├── cloud-api/
│   └── eas-anchor/
├── bridges/
│   ├── tetragon-bridge/
│   └── hubble-bridge/
└── tests/
    └── sdr-integration-tests/
```

### Packages

```text
packages/
├── sdk/
│   ├── hush-ts/
│   └── hush-py/
├── adapters/
│   ├── clawdstrike-adapter-core/
│   ├── clawdstrike-claude/
│   ├── clawdstrike-openai/
│   ├── clawdstrike-langchain/
│   ├── clawdstrike-openclaw/
│   ├── clawdstrike-opencode/
│   ├── clawdstrike-vercel-ai/
│   ├── clawdstrike-hush-cli-engine/
│   └── clawdstrike-hushd-engine/
└── policy/
    └── clawdstrike-policy/
```

### Infra

```text
infra/
├── deploy/                       # k8s/systemd/launchd/helm/policies
├── docker/                       # dockerfiles + compose + workspace files
├── packaging/
│   └── HomebrewFormula/
└── vendor/                       # vendored Rust deps for offline builds
```

## Naming and Identity Policy

1. `clawdstrike` is the primary public product name.
2. `hush-*` remains for compatibility where already published or externally consumed.
3. `spine-*` remains protocol-plane naming.
4. `sdr-*` should be clearly documented as separate domain naming if retained.

Practical policy:

1. Keep existing binary names and package IDs through deprecation windows.
2. Add aliases before removals.
3. Track deprecations in changelog with planned removal version.

## Ownership and Governance Model

Add `.github/CODEOWNERS` with domain ownership:

1. `crates/libs/**` -> core/security owners
2. `crates/services/**` -> runtime/service owners
3. `crates/bridges/**` -> telemetry/bridge owners
4. `packages/sdk/**` -> SDK owners
5. `packages/adapters/**` -> integrations owners
6. `apps/**` -> product app owners
7. `integrations/**` -> platform integration owners
8. `infra/**` -> platform/devops owners
9. `docs/**` -> docs owners

Add maturity metadata (`alpha`, `beta`, `ga`) per major component in a single table.

## Documentation Information Architecture

Canonical roles:

1. `docs/src/**`: public user-facing mdBook documentation.
2. `docs/plans/**`: implementation plans and architecture decisions.
3. `docs/specs/**`: accepted and implementation-relevant specs.
4. `docs/research/**`: exploratory/non-normative artifacts.
5. `docs/archive/**`: historical artifacts no longer active.

Required additions:

1. `docs/REPO_MAP.md` as newcomer index.
2. `docs/DOCS_MAP.md` explaining canonical sources and precedence.
3. Link both maps from root `README.md`.

## CI and Build Workflow Target

Split CI by path-scoped domains:

1. `ci-rust-libs`
2. `ci-rust-services`
3. `ci-rust-bridges`
4. `ci-apps`
5. `ci-packages-ts`
6. `ci-packages-py`
7. `ci-docs`
8. `ci-infra`

Local task model (`mise` remains top-level orchestrator):

1. `mise run test:rust`
2. `mise run test:apps`
3. `mise run test:packages:ts`
4. `mise run test:packages:py`
5. `mise run ci:changed` (path-aware follow-up optimization)

## Quality and Test-Coverage Improvement Plan

1. Add ownership-based coverage goals per domain (not one global percentage).
2. Require smoke tests for each deployable service under `crates/services/*`.
3. Add integration test matrix for critical cross-domain paths:
   - Rust service + TS adapter
   - Rust service + Python SDK
   - Proof/receipt path end-to-end
4. Add path-lint check in CI to detect stale file paths in manifests/workflows/docs after moves.
5. Enforce “every top-level domain folder has README + owner + maturity”.

## Phased Migration Plan

### Phase 0 (No directory moves; governance first)

Deliverables:

1. Add `.github/CODEOWNERS`.
2. Add `docs/REPO_MAP.md` and `docs/DOCS_MAP.md`.
3. Add component maturity table.
4. Resolve metadata inconsistencies (including license/badge consistency checks).

Exit criteria:

1. New engineer can identify owner + maturity + docs source in under 10 minutes.
2. CI remains fully green.

### Phase 1 (Low-risk semantic moves)

Moves:

1. `packages/cloud-dashboard` -> `apps/cloud-dashboard`
2. `spine/reticulum` -> `integrations/transports/reticulum`
3. `HomebrewFormula` -> `infra/packaging/HomebrewFormula`

Actions:

1. Keep redirect `README.md` stubs in old paths for one release cycle.
2. Update workspace globs, scripts, and workflows.
3. Run docs link validation in same PR.

Exit criteria:

1. No broken workflow paths.
2. No broken docs links.
3. No runtime behavior changes.

### Phase 2 (Workspace grouping)

Moves:

1. Group Rust crates into `crates/libs`, `crates/services`, `crates/bridges`, `crates/tests`.
2. Group JS/Python packages into `packages/sdk`, `packages/adapters`, `packages/policy`.

Actions:

1. Update root `Cargo.toml` members and internal path dependencies.
2. Update root `package.json` workspaces and package CI matrix.
3. Add path-lint and move-validation scripts.

Exit criteria:

1. `cargo build --workspace` and `cargo test --workspace` pass.
2. All package tests and typechecks pass.
3. Release workflows produce identical artifacts.

### Phase 3 (Infra consolidation)

Moves:

1. `deploy` -> `infra/deploy`
2. `docker` -> `infra/docker`
3. `vendor` -> `infra/vendor`

Actions:

1. Validate offline workflows (`scripts/cargo-offline.sh`) unchanged.
2. Validate Docker and Helm release workflows unchanged.
3. Validate security/license scanning paths.

Exit criteria:

1. Offline builds still pass.
2. Container builds and deploy templates still pass.

### Phase 4 (Cleanup and hardening)

1. Remove compatibility stubs.
2. Lock path conventions with CI checks.
3. Add architecture guardrails to contributor docs and PR template.

## Proposed Current -> Target Mapping

| Current path | Target path | Phase |
| --- | --- | --- |
| `packages/cloud-dashboard` | `apps/cloud-dashboard` | 1 |
| `spine/reticulum` | `integrations/transports/reticulum` | 1 |
| `HomebrewFormula` | `infra/packaging/HomebrewFormula` | 1 |
| `crates/hush-core` | `crates/libs/hush-core` | 2 |
| `crates/hush-proxy` | `crates/libs/hush-proxy` | 2 |
| `crates/clawdstrike` | `crates/libs/clawdstrike` | 2 |
| `crates/hush-certification` | `crates/libs/hush-certification` | 2 |
| `crates/hush-multi-agent` | `crates/libs/hush-multi-agent` | 2 |
| `crates/hush-wasm` | `crates/libs/hush-wasm` | 2 |
| `crates/spine` | `crates/libs/spine` | 2 |
| `crates/hush-cli` | `crates/services/hush-cli` | 2 |
| `crates/hushd` | `crates/services/hushd` | 2 |
| `crates/spine-cli` | `crates/services/spine-cli` | 2 |
| `crates/cloud-api` | `crates/services/cloud-api` | 2 |
| `crates/eas-anchor` | `crates/services/eas-anchor` | 2 |
| `crates/tetragon-bridge` | `crates/bridges/tetragon-bridge` | 2 |
| `crates/hubble-bridge` | `crates/bridges/hubble-bridge` | 2 |
| `crates/sdr-integration-tests` | `crates/tests/sdr-integration-tests` | 2 |
| `packages/hush-ts` | `packages/sdk/hush-ts` | 2 |
| `packages/hush-py` | `packages/sdk/hush-py` | 2 |
| `packages/clawdstrike-policy` | `packages/policy/clawdstrike-policy` | 2 |
| `packages/clawdstrike-adapter-core` | `packages/adapters/clawdstrike-adapter-core` | 2 |
| `packages/clawdstrike-claude` | `packages/adapters/clawdstrike-claude` | 2 |
| `packages/clawdstrike-openai` | `packages/adapters/clawdstrike-openai` | 2 |
| `packages/clawdstrike-langchain` | `packages/adapters/clawdstrike-langchain` | 2 |
| `packages/clawdstrike-openclaw` | `packages/adapters/clawdstrike-openclaw` | 2 |
| `packages/clawdstrike-opencode` | `packages/adapters/clawdstrike-opencode` | 2 |
| `packages/clawdstrike-vercel-ai` | `packages/adapters/clawdstrike-vercel-ai` | 2 |
| `packages/clawdstrike-hush-cli-engine` | `packages/adapters/clawdstrike-hush-cli-engine` | 2 |
| `packages/clawdstrike-hushd-engine` | `packages/adapters/clawdstrike-hushd-engine` | 2 |
| `deploy` | `infra/deploy` | 3 |
| `docker` | `infra/docker` | 3 |
| `vendor` | `infra/vendor` | 3 |

## Risks and Rollback Strategy

| Risk | Impact | Control | Rollback |
| --- | --- | --- | --- |
| Path dependency breakage | Build/test failures | Move in small domain PRs + path-lint | Revert single move PR |
| Workflow path drift | CI/release failure | Update and validate workflows in same PR | Restore previous workflow path refs |
| Broken docs links | Onboarding regressions | Run docs link checker in PR | Restore legacy links via redirect READMEs |
| Contributor confusion during transition | Slower reviews | Add repo map + migration notes + stubs | Extend compatibility window |
| Hidden automation dependencies | Release issues | Dry-run release and deploy workflows each phase | Revert moved directory only |

## Implementation Backlog (First 6 PRs)

1. **PR-1 (Governance)**: add `CODEOWNERS`, add `docs/REPO_MAP.md`, add `docs/DOCS_MAP.md`.
2. **PR-2 (Metadata hygiene)**: normalize license/badge metadata, add maturity table, add top-level folder READMEs where missing.
3. **PR-3 (Low-risk move A)**: move `packages/cloud-dashboard` -> `apps/cloud-dashboard`.
4. **PR-4 (Low-risk move B)**: move `spine/reticulum` -> `integrations/transports/reticulum`.
5. **PR-5 (Low-risk move C)**: move `HomebrewFormula` -> `infra/packaging/HomebrewFormula`.
6. **PR-6 (CI hardening)**: add path-lint + changed-path pipeline decomposition.

## Decisions and Follow-Ups

1. Package manager policy is now explicitly documented as npm-default with a Bun exception for `apps/desktop` (`docs/src/getting-started/package-manager-policy.md`).
2. Branding strategy for `hush` naming in user-facing docs remains an open follow-up.
3. `cloud-api` and `cloud-dashboard` product-domain framing in docs/navigation remains an open follow-up.

## Recommendation

Default recommendation: start with **Phase 0 and Phase 1** only.  
Do not begin Phase 2 (major workspace path moves) until one full release cycle is green and stable after Phase 1, unless explicitly approved by maintainers.
