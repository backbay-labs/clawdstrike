# Spirit Ritual Swarm Plan

## Summary

This swarm rewrites hunt spirit creation into a Baia-inspired artistic ritual.

The goal is not a prettier config sheet.
The goal is to replace the current spirit-configuration flow with:

- a chamber
- multimodal creation
- manifestation
- release
- continuity into dock, sidebar, and 3D

## Shared Ownership

The orchestrator owns:

- `apps/desktop/src/shell/workbench/huntTypes.ts`
- `apps/desktop/src/shell/workbench/huntReducer.ts`
- `apps/desktop/src/shell/workbench/workbenchState.ts`
- `apps/desktop/src/shell/workbench/WorkbenchStateProvider.tsx`
- `apps/desktop/package.json`
- `docs/plans/clawdstrike/huntronomer/spirit-ritual/**`
- `docs/plans/clawdstrike/huntronomer/README.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

Worker lanes must not edit those files.

## Lanes

| Lane | Focus | Owned Paths | Tickets | Verification |
| --- | --- | --- | --- | --- |
| `ORCH` | shared contracts, docs, merge sequencing, metadata | shared files above | `SR-P0-01`, `SR-P0-02`, final integrations | `npm --prefix apps/desktop run typecheck` |
| `SR1` | ritual chamber shell and control vocabulary | `apps/desktop/src/shell/workbench/spirit-ritual/SpiritCreationChamber.tsx`, `apps/desktop/src/shell/workbench/spirit-ritual/controls/**`, `apps/desktop/src/shell/workbench/spirit-bind/index.ts` | `SR-P1-01`, `SR-P1-02` | `npm --prefix apps/desktop run typecheck` + chamber component tests |
| `SR2` | multimodal creation engine | `apps/desktop/src/shell/workbench/spirit-ritual/state/**`, `apps/desktop/src/shell/workbench/spirit-ritual/modes/**`, `apps/desktop/src/shell/workbench/spirit-ritual/draw/**`, `apps/desktop/src/shell/workbench/spirit-ritual/upload/**`, `apps/desktop/src/shell/workbench/spirit-ritual/IntentionSuggestions.tsx` | `SR-P2-01`, `SR-P2-02`, `SR-P2-03`, `SR-P2-04` | `npm --prefix apps/desktop run typecheck` + ritual-mode tests |
| `SR3` | manifestation, atmosphere, and release choreography | `apps/desktop/src/shell/workbench/spirit-ritual/canvas/**`, `apps/desktop/src/shell/workbench/spirit-ritual/atmosphere/**`, `apps/desktop/src/shell/workbench/spirit-ritual/release/**`, `apps/desktop/src/shell/workbench/spirit-bind/preview.ts` | `SR-P3-01`, `SR-P3-02`, `SR-P3-03` | `npm --prefix apps/desktop run typecheck` + release visual tests |
| `SR4` | dock/sidebar adoption and chamber re-entry | `apps/desktop/src/shell/workbench/HuntDock.tsx`, `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`, `apps/desktop/src/shell/workbench/spirit/components/**` | `SR-P4-01`, `SR-P4-02` | `npm --prefix apps/desktop run typecheck` + workbench spirit tests |
| `SR5` | 3D receive in Forensics and Nexus | `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`, `apps/desktop/src/features/forensics/components/hunt-spirit/**`, `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`, `apps/desktop/src/features/cyber-nexus/scene/spirits/**` | `SR-P5-01`, `SR-P5-02` | `npm --prefix apps/desktop run typecheck` + focused scene tests |
| `SR6` | verification, smoke, dogfood, accessibility, performance | ritual-related tests, smoke scripts, dogfood notes, verification docs | `SR-P6-01`, `SR-P6-02` | full desktop suite + build + live dogfood gate |

## Waves

| Wave | Lanes | Goal |
| --- | --- | --- |
| `wave0` | `orch` | publish ritual initiative docs, shared guardrails, and fresh swarm metadata |
| `wave1` | `sr1,sr2,sr3` | land the new chamber shell, multimodal draft engine, and release visuals in parallel |
| `wave2` | `sr4,sr5` | integrate the ritual into dock/sidebar and 3D receive surfaces |
| `wave3` | `sr6` | verification, dogfood, smoke, accessibility, and performance closure |

The orchestrator remains active through every wave and owns final shared-file integration.

## Merge Order

1. `ORCH` publishes the initiative, lane ownership, and metadata.
2. Merge `SR1` before integrating any launch wiring into shared files.
3. Merge `SR2` and `SR3` before `SR4` so surface lanes target the final chamber and release outputs.
4. Merge `SR4` and `SR5` before `SR6`.
5. Merge `SR6` last after one integrated dogfood pass.

## Lane Guardrails

- `SR1` must not reintroduce a plain settings-sheet mental model.
- `SR2` must keep one shared draft state across all modes.
- `SR3` must keep atmospheric layers click-through and restrained.
- `SR4` must make retune feel like chamber re-entry, not local button state.
- `SR5` must keep scene receive legible and non-ornamental.
- `SR6` must verify keyboard and pointer safety, not just visuals.

## Acceptance Gate

The swarm is complete only when:

- creating or retuning a spirit opens a real ritual chamber
- the chamber supports intention, draw, upload/anchor, and hybrid creation
- release into the workspace is visible and materially better than the old sheet
- dock/sidebar/3D all reflect the released spirit coherently
- tests, build, and live dogfood pass from one integrated run

