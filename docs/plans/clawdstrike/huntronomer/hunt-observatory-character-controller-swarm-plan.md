# Hunt Observatory Character Controller Swarm Plan

## Summary

The program is scoped to `hunt-observatory-character-controller`.

The goal is to add one controllable observatory player with:

- real rigid-body physics
- authored movement and jump
- front/back flip actions
- stable observatory-world integration
- browser/native dogfood proof

## Shared Ownership

The orchestrator owns the high-conflict seams:

- `apps/desktop/package.json`
- `apps/desktop/vite.config.ts`
- `apps/desktop/tsconfig.json`
- `apps/desktop/src/features/hunt-observatory/index.ts`
- `apps/desktop/src/features/hunt-observatory/world/ObservatoryWorldCanvas.tsx`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-character-controller-plan.md`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-character-controller-swarm-plan.md`
- `docs/plans/clawdstrike/huntronomer/README.md`

Worker lanes must not edit those files.

## Lanes

| Lane | Focus | Owned Paths | Goal | Verification |
| --- | --- | --- | --- | --- |
| `ORCH` | Shared deps, integration seams, docs, merge sequencing | shared files above | seed deps/contracts, integrate controller into observatory canvas, own final merge | `npm --prefix apps/desktop run typecheck` |
| `CHAR1` | Physics/controller core | `apps/desktop/src/features/hunt-observatory/character/controller/**`, `apps/desktop/src/features/hunt-observatory/character/input/**`, `apps/desktop/src/features/hunt-observatory/character/physics/**`, `apps/desktop/src/features/hunt-observatory/character/types.ts` | build input, rigid-body runtime, spawn/collider contracts, movement/jump state | focused controller tests + `typecheck` |
| `CHAR2` | Avatar and authored move-set | `apps/desktop/src/features/hunt-observatory/character/avatar/**`, `apps/desktop/src/features/hunt-observatory/character/animation/**`, `apps/desktop/src/features/hunt-observatory/character/index.ts` | build visible avatar layer, action clips, flip behavior, fallback shell body | focused animation/avatar tests + `typecheck` |
| `CHAR3` | Verification and dogfood | `apps/desktop/src/features/hunt-observatory/**/*.test.ts*`, `apps/desktop/docs/huntronomer-dogfooding.md`, `scripts/huntronomer-playwright-smoke.sh` | add controller smoke checks, dogfood instructions, browser proof | full focused desktop verification + smoke |

## Waves

| Wave | Lanes | Goal |
| --- | --- | --- |
| `wave0` | `orch` | Seed the plan, deps decision, shared seams, and worker contracts |
| `wave1` | `char1`, `char2` | Build controller core and visible avatar/move-set in parallel |
| `wave2` | `char3` | Verify, smoke, dogfood, and close usability gaps after integration |

## Merge Order

1. `ORCH` seeds deps, contracts, and observatory integration seam.
2. Merge `CHAR1` before integrating `CHAR2`, because avatar/action state depends on controller state.
3. Merge `CHAR2` after the controller contract is stable.
4. Merge `CHAR3` last after the live character is integrated.

## Guardrails

- `CHAR1` must not make the observatory canvas itself the controller brain.
- `CHAR2` must support a fallback visible body if production avatar assets are not available.
- `CHAR3` must prove the loop live, not just pass unit tests.
- No worker should revert or rewrite existing observatory-world systems to make the controller fit.
- The player should complement station navigation, not replace it.

## Acceptance Gate

The swarm is complete only when:

- the player spawns and moves reliably in the observatory world
- jump and flip actions are live and readable
- station focus and room travel still function
- browser smoke and dogfood capture the avatar loop end-to-end
