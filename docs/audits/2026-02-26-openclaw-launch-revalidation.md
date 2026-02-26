# OpenClaw Launch Revalidation (2026-02-26)

## Scope

This document is the current branch-status update for `feat/clawdstrike-sdks-launch` as of **2026-02-26**.  
It supersedes point-in-time "Open" statuses in 2026-02-25 launch-readiness audit docs.

## Finding Status

| ID | Finding | Status | What was completed and validated |
| --- | --- | --- | --- |
| 1 | `test:cross-adapter` did not run tests | Closed | Added `packages/adapters/clawdstrike-adapter-core/vitest.cross-adapter.config.ts` and updated script to `vitest run --config vitest.cross-adapter.config.ts`. Validation: `npm --prefix packages/adapters/clawdstrike-adapter-core run test:cross-adapter` now runs and passes **57/57** tests across 4 files. |
| 2 | Rulesets used over-broad `fd*` | Closed | Updated `ai-agent.yaml` and `ai-agent-minimal.yaml` deny lists to `fd00:*` and `fd[0-9a-f][0-9a-f]:*`, matching guard defaults. |
| 3 | Launch/readiness docs stale vs branch | Closed | Added historical banners to 2026-02-25 audit/report docs and this current-status document. Updated current test baseline: OpenClaw adapter suite is now **26 files / 455 tests**; adapter-core cross-adapter suite now runs (**57 tests**). |
| 4 | S4/S5 runtime compatibility not closed with runtime evidence | Closed | Implemented runtime-compatible named hook registration in `src/plugin.ts` with fallback for older runtimes; added modern `before_tool_call` return-based blocking support in `tool-preflight` and `cua-bridge` handlers while preserving `preventDefault`. Added tests for both paths. Runtime validation report: `docs/reports/2026-02-26-openclaw-runtime-compatibility-validation.md`. |
| 5 | PR summary overstated receipt signing maturity | Closed | PR #101 summary was corrected to state receipts are currently unsigned stub attestations (`signature: null`) pending hush-wasm bridge integration. |

## Validation Commands

- `npm --prefix packages/adapters/clawdstrike-adapter-core run test:cross-adapter`
- `npm --prefix packages/adapters/clawdstrike-adapter-core test`
- `npm --prefix packages/adapters/clawdstrike-openclaw test`
- `bash scripts/openclaw-plugin-runtime-smoke.sh`
- `bash scripts/openclaw-plugin-blocked-call-e2e.sh`
- Runtime checks documented in `docs/reports/2026-02-26-openclaw-runtime-compatibility-validation.md`

## Remaining Gaps

- No launch-blocking runtime gaps remain for PR #101.  
  Runtime CI now includes hook-name registration checks plus an end-to-end blocked destructive call smoke test.
