# Hunt Spirits Swarm Plan

## Summary

The program is scoped to `hunt-identity-plus-workspace-presence`.

The goal is not only to add better hunt icons.
It is to make hunt spirits real in:

- state and persistence
- the bind/create flow
- dock and sidebar identity
- anticipation bias
- Forensics and Nexus scene presence

## Shared Ownership

The orchestrator owns the shared contract and registration layer:

- `apps/desktop/src/shell/workbench/huntTypes.ts`
- `apps/desktop/src/shell/workbench/huntReducer.ts`
- `apps/desktop/src/shell/workbench/workbenchState.ts`
- `apps/desktop/src/shell/workbench/WorkbenchStateProvider.tsx`
- `apps/desktop/src/shell/workbench/tabRegistry.ts`
- `apps/desktop/src/shell/workbench/TabBar.tsx`
- `apps/desktop/package.json`
- `docs/plans/clawdstrike/huntronomer/hunt-spirits-roadmap.md`
- `docs/plans/clawdstrike/huntronomer/hunt-spirits-swarm-plan.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

Worker lanes must not edit those files.

## Lanes

| Lane | Focus | Owned Paths | Key Tickets | Verification |
| --- | --- | --- | --- | --- |
| `ORCH` | Shared contracts, integrations, docs, metadata, merge sequencing | shared files above | `HS-P0-01`, `HS-P0-02`, `HS-P0-03`, shared integration for later phases | `npm --prefix apps/desktop run typecheck` |
| `HS1` | Spirit domain and inference spine | `apps/desktop/src/shell/workbench/spirit/**` | `HS-P0-01`, `HS-P3-01` | `npm --prefix apps/desktop run typecheck` + spirit-domain tests |
| `HS2` | Bind Spirit flow and previews | `apps/desktop/src/shell/workbench/spirit-bind/**`, supporting new preview components | `HS-P1-01`, `HS-P1-02`, `HS-P1-03`, `HS-P1-04` | `npm --prefix apps/desktop run typecheck` + bind-flow component tests |
| `HS3` | Dock, smart bucket, and local hunt identity surfaces | `apps/desktop/src/shell/workbench/HuntDock.tsx`, `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`, new spirit UI components outside ORCH-owned paths | `HS-P2-01`, `HS-P2-02`, `HS-P2-03` | `npm --prefix apps/desktop run typecheck` + focused workbench tests |
| `HS4` | Anticipation and sidebar spirit bias | `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts`, `apps/desktop/src/shell/workbench/anticipation/useSidebarDirector.ts`, `apps/desktop/src/shell/workbench/anticipation/useSidebarWakeController.ts`, other spirit-bias hooks under `anticipation/**` except ORCH-owned docs/metadata | `HS-P3-02`, `HS-P3-03` | `npm --prefix apps/desktop run typecheck` + focused anticipation tests |
| `HS5` | Forensics spirit actor and 3D bind behavior | `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`, `apps/desktop/src/features/forensics/components/hunt-spirit/**`, spirit motion adapters outside ORCH-owned files | `HS-P4-01`, `HS-P4-02`, `HS-P4-03` | `npm --prefix apps/desktop run typecheck` + focused forensics tests |
| `HS6` | Nexus and station spirit embodiment | `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`, `apps/desktop/src/features/cyber-nexus/scene/spirits/**`, related station files under `apps/desktop/src/features/cyber-nexus/**` except ORCH-owned files | `HS-P5-01`, `HS-P5-02`, `HS-P5-03` | `npm --prefix apps/desktop run typecheck` + focused nexus tests |
| `HS7` | Verification, smoke, dogfood, performance, accessibility | spirit-related tests, smoke scripts, dogfood notes, verification docs | `HS-P6-01`, `HS-P6-02`, `HS-P6-03` | full desktop suite + build + live dogfood gate |

## Waves

| Wave | Lanes | Goal |
| --- | --- | --- |
| `wave0` | `orch` | Publish the roadmap, swarm plan, shared contract scaffolding, and fresh swarm metadata |
| `wave1` | `hs1,hs2` | Land the spirit domain and the bind-flow shell in parallel |
| `wave2` | `hs3,hs5` | Make spirit visible in dock/sidebar and Forensics |
| `wave3` | `hs4,hs6` | Make anticipation spirit-aware and land Nexus/station embodiment |
| `wave4` | `hs7` | Close verification, smoke, dogfood, and polish gaps |

The orchestrator remains active across all waves and integrates shared-file changes between merges.

## Merge Order

1. `ORCH` seeds contracts and metadata.
2. Merge `HS1` before integrating `HS2`, `HS3`, `HS5`, or `HS4` into shared files.
3. Merge `HS2` before final `HUNT_CREATE -> Bind Spirit` shared wiring.
4. Merge `HS3` and `HS5` before `HS4` and `HS6` so anticipation and Nexus target real spirit surfaces.
5. Merge `HS7` last after all feature lanes are integrated.

## Lane Guardrails

- `HS1` must not edit existing reducer/state registration files owned by `ORCH`.
- `HS2` must keep the flow non-blocking and must not turn spirit binding into a mandatory wizard.
- `HS3` must preserve the compactness of the dock and avoid decorative overload.
- `HS4` must treat spirit as additive bias, not a second autonomous decision engine.
- `HS5` must keep spirits distinct from agent organisms and receipt objects.
- `HS6` must preserve strikecells as topology and use spirits only as posture-relative actors.
- `HS7` must verify accessibility and interaction safety, not just visual output.

## Verification Matrix

| Lane | Minimum Verification |
| --- | --- |
| `ORCH` | `npm --prefix apps/desktop run typecheck` |
| `HS1` | `npm --prefix apps/desktop run typecheck` plus spirit-domain tests |
| `HS2` | `npm --prefix apps/desktop run typecheck` plus bind-flow tests |
| `HS3` | `npm --prefix apps/desktop run typecheck` plus focused hunt/workbench tests |
| `HS4` | `npm --prefix apps/desktop run typecheck` plus focused anticipation tests |
| `HS5` | `npm --prefix apps/desktop run typecheck` plus focused forensics tests |
| `HS6` | `npm --prefix apps/desktop run typecheck` plus focused nexus tests |
| `HS7` | `npm --prefix apps/desktop run typecheck`, `npm --prefix apps/desktop test`, `npm --prefix apps/desktop run build`, `npm --prefix apps/desktop run tauri:dev` |

## Agent Briefs

### `ORCH`

Own the contracts, shared-file integrations, and merge sequencing.
Do not let workers edit reducer/state/package metadata files directly.

### `HS1`

Build the spirit domain as reusable code, not ad hoc fields.
Leave the shared-file integration to `ORCH`.

### `HS2`

Make `Bind Spirit` feel like a short operational ceremony.
Prioritize preview, rationale, and one-click acceptance.

### `HS3`

Make the hunt visibly feel different once spirit exists.
Keep surfaces compact, legible, and non-ornamental.

### `HS4`

Teach the anticipation system to read spirit stance and mood.
Never let spirit override explicit user intent.

### `HS5`

Make the active hunt feel present in Forensics as a first-class scene actor.
Do not turn it into a collectible or pet.

### `HS6`

Make spirit a posture-relative companion in Nexus and stations.
Keep topology and station identity intact.

### `HS7`

Prove the whole program works from a clean run.
Find regressions, performance hits, and accessibility breakage before merge.

## Acceptance Gate

The swarm is complete only when all of the following are true:

- `HUNT_CREATE` stays instant, and `Bind Spirit` is non-blocking
- a bound spirit is visible and coherent in dock, smart bucket, anticipation copy, and 3D scenes
- Forensics and Nexus both have an active-hunt spirit with readable stance changes
- spirit-aware anticipation remains explainable and confidence-gated
- the desktop verification commands pass from one clean run
