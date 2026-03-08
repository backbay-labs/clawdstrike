# Sidebar Intelligence Swarm Plan

## Summary

The program is scoped to `sidebar-plus-adjacent` behavior. The sidebar itself becomes predictive,
and the adjacent surfaces it depends on respond just enough to preserve context and proof flow.

## Shared Ownership

The orchestrator owns the shared integration layer:

- `apps/desktop/src/shell/workbench/LensSidebar.tsx`
- `apps/desktop/src/shell/workbench/WorkbenchShell.tsx`
- `apps/desktop/src/shell/workbench/anticipation/types.ts`
- `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts`
- `apps/desktop/src/shell/workbench/anticipation/useSidebarDirector.ts`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

Worker lanes must not edit those files.

## Lanes

| Lane | Focus | Owned Paths | Verification |
| --- | --- | --- | --- |
| `ORCH` | Contracts, shared wiring, merge sequencing, docs | shared integration files above + initiative docs | `npm --prefix apps/desktop run typecheck` |
| `SB1` | Files lens registry and preferred-view behavior | `apps/desktop/src/shell/workbench/lenses/FilesLens.tsx` | `npm --prefix apps/desktop run typecheck` |
| `SB2` | Remaining monolithic lens conversions | `apps/desktop/src/shell/workbench/lenses/{Scopes,History,Sandboxes,Swarms}Lens.tsx` | `npm --prefix apps/desktop run typecheck` |
| `SB3` | Predictive signal engine | anticipation hooks except ORCH-owned shared files | `npm --prefix apps/desktop run typecheck` + focused anticipation tests |
| `SB4` | Semantic drop execution and adjacent-surface reactions | drag/drop, hunt reducer, bottom panel, inspector, staging/bucket execution files | `npm --prefix apps/desktop run typecheck` + focused reducer tests |
| `SB5` | Verification and dogfood hardening | workbench tests, smoke scripts, dogfood docs, routing mocks | full desktop test/build/smoke gate |

## Waves

| Wave | Lanes | Goal |
| --- | --- | --- |
| `wave0` | `orch` | Publish contracts, section-ID matrix, lane metadata, and worker briefs |
| `wave1` | `sb3,sb1,sb2` | Land the predictive signal engine and all remaining lens registries |
| `wave2` | `sb4` | Make semantic drop behavior and adjacent-surface promotions real |
| `wave3` | `sb5` | Close verification gaps, update smoke coverage, and dogfood the live shell |

The orchestrator remains active across all waves and performs shared-file integration between wave
merges.

## Acceptance Gate

The initiative is done only when all of the following are true:

- the collapsed sidebar rail wakes and peeks open on intent
- every lens is registry-driven and reorderable from the director
- semantic drop roles mutate real hunt/run/case state
- adjacent proof/context surfaces visibly respond to likely intent
- predictive tab opening preserves context instead of replacing it blindly
- the desktop suite, build, and smoke verification pass from one clean run
