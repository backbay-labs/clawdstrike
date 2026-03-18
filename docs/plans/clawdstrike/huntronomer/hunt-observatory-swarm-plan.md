# Hunt Observatory Swarm Plan

## Summary

The program is scoped to `hunt-observatory-unification`.

The goal is not to add another 3D view.
It is to turn the current Hunt Dock, Forensics River, and Nexus scene into one coherent hunt
observatory with shared scene contracts, shared station semantics, and disciplined detail routing.

## Shared Ownership

The orchestrator owns the shared contract, integration, and metadata layer:

- `apps/desktop/src/features/hunt-observatory/**`
- `apps/desktop/src/features/cyber-nexus/types.ts`
- `apps/desktop/src/shell/workbench/workbenchState.ts`
- `apps/desktop/src/shell/workbench/tabRegistry.ts`
- `apps/desktop/src/shell/workbench/WorkbenchShell.tsx`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-spec.md`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-roadmap.md`
- `docs/plans/clawdstrike/huntronomer/hunt-observatory-swarm-plan.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

Worker lanes must not edit those files.

## Lanes

| Lane | Focus | Owned Paths | Key Tickets | Verification |
| --- | --- | --- | --- | --- |
| `ORCH` | Shared contracts, integrations, docs, metadata, merge sequencing | shared files above | `OBS-P0-01`, `OBS-P0-02`, `OBS-P0-03`, shared integration across later phases | `npm --prefix apps/desktop run typecheck` |
| `OBS1` | Shared observatory selectors and actor derivation | observatory selectors/adapters outside ORCH-owned files, spirit/runtime adapters feeding shared actors | `OBS-P1-01` | `npm --prefix apps/desktop run typecheck` + observatory selector tests |
| `OBS2` | Flow mode / Forensics migration | `apps/desktop/src/features/forensics/**` except ORCH-owned shared seams | `OBS-P1-02`, `OBS-P2-01`, `OBS-P2-02`, `OBS-P2-03` | `npm --prefix apps/desktop run typecheck` + focused forensics tests |
| `OBS3` | Atlas mode / Nexus migration | `apps/desktop/src/features/cyber-nexus/**` except ORCH-owned shared seams | `OBS-P1-03`, `OBS-P3-01`, `OBS-P3-02`, `OBS-P3-03` | `npm --prefix apps/desktop run typecheck` + focused nexus tests |
| `OBS4` | Hunt shell integration | `apps/desktop/src/shell/workbench/HuntDock.tsx`, `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`, related compact observatory shell components | `OBS-P4-01`, `OBS-P4-02`, `OBS-P4-03` | `npm --prefix apps/desktop run typecheck` + focused workbench tests |
| `OBS5` | Detail surfaces and workbench integration | right-rail, bottom-panel, tab content/bridge surfaces outside ORCH-owned shared files | `OBS-P5-01`, `OBS-P5-02`, `OBS-P5-03` | `npm --prefix apps/desktop run typecheck` + focused workbench/detail tests |
| `OBS6` | Verification, smoke, dogfood, performance hardening | observatory tests, smoke scripts, verification docs, performance guardrails outside ORCH-owned files | `OBS-P6-01`, `OBS-P6-02`, `OBS-P6-03` | full desktop verification + dogfood gate |

## Waves

| Wave | Lanes | Goal |
| --- | --- | --- |
| `wave0` | `orch` | Seed the observatory contracts, roadmap, swarm plan, and metadata |
| `wave1` | `obs1` | Land shared selector and actor derivation spine |
| `wave2` | `obs2,obs3` | Migrate Forensics and Nexus onto the shared observatory vocabulary in parallel |
| `wave3` | `obs4,obs5` | Simplify shell surfaces and unify detail routing around the room |
| `wave4` | `obs6` | Close verification, performance, smoke, and dogfood gaps |

The orchestrator remains active across all waves and integrates the shared-file changes between
merges.

## Merge Order

1. `ORCH` seeds the contract and metadata layer.
2. Merge `OBS1` before `OBS2`, `OBS3`, `OBS4`, or `OBS5`.
3. Merge `OBS2` and `OBS3` before `OBS4` so shell simplification targets the real unified room.
4. Merge `OBS4` before `OBS5` so detail-surface routing lands against the simplified shell seams.
5. Merge `OBS6` last after all feature lanes are integrated.

## Lane Guardrails

- `OBS1` must not invent a second scene model beside the spec.
- `OBS2` must preserve the strongest existing river behavior and cut HUD rather than add more HUD.
- `OBS3` must preserve topology legibility and avoid decorative graph noise.
- `OBS4` must make dock and bucket quieter, not richer.
- `OBS5` must keep dense detail out of the 3D room by default.
- `OBS6` must verify usability and performance, not only visuals.

## Verification Matrix

| Lane | Minimum Verification |
| --- | --- |
| `ORCH` | `npm --prefix apps/desktop run typecheck` |
| `OBS1` | `npm --prefix apps/desktop run typecheck` plus observatory selector tests |
| `OBS2` | `npm --prefix apps/desktop run typecheck` plus focused Forensics tests |
| `OBS3` | `npm --prefix apps/desktop run typecheck` plus focused Nexus tests |
| `OBS4` | `npm --prefix apps/desktop run typecheck` plus focused workbench shell tests |
| `OBS5` | `npm --prefix apps/desktop run typecheck` plus detail/tab routing tests |
| `OBS6` | `npm --prefix apps/desktop run typecheck`, `npm --prefix apps/desktop test -- --run`, `npm --prefix apps/desktop run build`, browser smoke, native/browser dogfood |

## Agent Briefs

### `ORCH`

Own the station taxonomy, shared contracts, merge sequencing, and observatory docs.
Do not let workers edit shared contract files directly.

### `OBS1`

Build the shared observatory state and actor-derivation spine.
Favor adapters over feature-local rewrites at first.

### `OBS2`

Turn Forensics into observatory `flow`.
Prioritize station meaning, lane usefulness, and reduction of explanatory chrome.

### `OBS3`

Turn Nexus into observatory `atlas`.
Keep the room readable, anchored, and hunt-oriented.

### `OBS4`

Make Hunt Dock and Smart Bucket feed the room quietly.
Do not reintroduce card noise or spirit verbosity.

### `OBS5`

Define what opens in-room versus in tabs, rails, and the bottom surface.
Preserve field continuity whenever detail opens.

### `OBS6`

Prove the observatory survives real operator use.
Catch performance regressions, dead routes, and redundant UI before merge.

## Acceptance Gate

The swarm is complete only when:

- one active hunt is represented by one observatory contract
- Forensics and Nexus consume the same station taxonomy and shared actor families
- the room remains legible while detail opens beside it
- Hunt Dock and Smart Bucket act like observatory seams instead of side dashboards
- browser/native dogfood confirms the room is materially more useful than the pre-observatory state
