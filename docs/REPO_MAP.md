# Repository Map

Last updated: 2026-02-10

This document is the newcomer index for the monorepo layout.

## Top-Level Layout

| Path | Purpose |
| --- | --- |
| `apps/` | User-facing products (desktop, agent, cloud dashboard). |
| `crates/` | Rust libraries, services, and runtime components. |
| `packages/` | TypeScript and Python SDKs/adapters/policy packages. |
| `integrations/` | External transport/runtime integrations (for example Reticulum). |
| `infra/` | Packaging and infrastructure assets (for example Homebrew formula). |
| `infra/deploy/` | Deployment manifests and policy assets. |
| `infra/docker/` | Container build assets. |
| `infra/vendor/` | Vendored Rust dependencies for offline builds. |
| `docs/` | Public docs, plans, specs, and research. |
| `examples/` | End-to-end and SDK examples. |
| `fixtures/` | Golden fixtures and test vectors. |
| `rulesets/` | Preconfigured policy rulesets. |
| `scripts/` | Operator-facing scripts. |
| `tools/` | Repo tooling and validators. |
| `fuzz/` | Rust fuzzing harnesses and targets. |

## Component Maturity

| Component | Path | Maturity | Notes |
| --- | --- | --- | --- |
| Core runtime libraries | `crates/libs/hush-core`, `crates/libs/hush-proxy`, `crates/libs/clawdstrike` | alpha | APIs may still evolve. |
| CLI + daemon | `crates/services/hush-cli`, `crates/services/hushd` | alpha | Primary local/runtime entrypoints. |
| Spine protocol services | `crates/libs/spine`, `crates/services/spine-cli` | alpha | Active protocol iteration and performance work. |
| Cloud API | `crates/services/cloud-api` | alpha | Early-stage service surface. |
| EAS anchoring | `crates/services/eas-anchor` | alpha | Functional but still under active hardening. |
| Bridge services | `crates/bridges/tetragon-bridge`, `crates/bridges/hubble-bridge` | alpha | Integration-focused components. |
| Desktop app | `apps/desktop` | alpha | Product UX and architecture still moving. |
| Agent app | `apps/agent` | alpha | Product UX and runtime still moving. |
| Cloud dashboard | `apps/cloud-dashboard` | alpha | Recently moved from `packages/cloud-dashboard`. |
| TS SDK | `packages/sdk/hush-ts` | alpha | Public SDK APIs may evolve. |
| Python SDK | `packages/sdk/hush-py` | alpha | Public SDK APIs may evolve. |
| TS adapters | `packages/adapters/clawdstrike-*` | alpha | Adapter contracts still being refined. |
| Reticulum transport | `integrations/transports/reticulum` | experimental | Recently moved from `spine/reticulum`. |

## Ownership

Ownership is codified in `.github/CODEOWNERS`.

Short-term bootstrap owner for all domains is `@connor`; this should be replaced by dedicated org teams as domains mature.

Guardrail enforcement is automated by `scripts/architecture-guardrails.sh` in CI.

## Historical Path Moves

1. `packages/cloud-dashboard` -> `apps/cloud-dashboard`
2. `spine/reticulum` -> `integrations/transports/reticulum`
3. `HomebrewFormula` -> `infra/packaging/HomebrewFormula`
4. `deploy` -> `infra/deploy`
5. `docker` -> `infra/docker`
6. `vendor` -> `infra/vendor`

Compatibility stubs for these paths were removed in Phase 4 cleanup.
