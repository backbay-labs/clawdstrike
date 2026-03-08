# Huntronomer V1 Roadmap

> **Status:** Draft | **Date:** 2026-03-07
> **Scope:** Desktop refactor path for `apps/desktop`

Execution topology, lane ownership, and merge waves are defined in `./swarm-plan.md`.

## Delivery Principle

Do not attempt a single giant rewrite. Preserve the working shell, re-home the strongest existing
surfaces, and introduce the new domain model before broad UI replacement.

## Phase 0: Docs and Refactor Frame

Deliverables:

- docs index
- current-state review
- target architecture
- surface map
- formal event model spec

Exit criteria:

- agreed IA and product vocabulary
- agreed v1 object model
- explicit keep/refactor/remove list

## Phase 1: Shell and Information Architecture Reset

Primary code areas:

- `apps/desktop/src/shell/plugins/registry.tsx`
- `apps/desktop/src/shell/components/NavRail.tsx`
- `apps/desktop/src/shell/ShellLayout.tsx`
- `apps/desktop/src/styles.css`

Deliverables:

- route the app to `Wire` by default
- collapse the plugin gallery into Huntronomer primary surfaces
- update rail labels, command palette nouns, and shell chrome
- establish final theme tokens and density rules

Exit criteria:

- app opens into Signal Wire shell
- legacy top-level plugins are either removed, hidden, or demoted
- keyboard navigation still works across the shell

## Phase 2: Domain Model and Mock Wire

Primary code areas:

- `apps/desktop/src/domain/huntronomer/**`
- `apps/desktop/src/features/wire/**`

Deliverables:

- normalized object and envelope model from Spec 16
- mock or fixture-backed Wire rows for `Signal`, `Hunt`, `Receipt`, `Brief`
- watchlist model and filter bar
- right context pane and row-selection behavior

Exit criteria:

- Wire renders typed objects without depending on current daemon event shape
- `Fork Hunt` and `Assign Swarm` actions emit structured launch context

## Phase 3: Huntboard Composition

Primary code areas:

- `apps/desktop/src/features/forensics/**`
- `apps/desktop/src/features/huntboard/**`
- `apps/desktop/src/features/openclaw/**`

Deliverables:

- refactor the forensics river into Huntboard subviews
- carry source wire context into Huntboard state
- attach swarm runtime summaries, approvals, and operator controls
- define evidence, entity, and replay tabs without losing lineage

Exit criteria:

- `Wire -> Fork Hunt` opens a contextual Huntboard
- live/runtime data can coexist with mock or persisted hunt records

## Phase 4: Receipt Vault and Replay Lens

Primary code areas:

- `apps/desktop/src/features/events/**`
- `apps/desktop/src/features/vault/**`
- `apps/desktop/src/features/replay/**`
- `apps/desktop/src/services/tauri.ts`

Deliverables:

- receipt-centric browsing surface
- replay entry points from wire and Huntboard
- signer, posture, policy version, and lineage inspection
- compare / diff affordances for receipts or runs

Exit criteria:

- execution-backed claims are drillable into proof
- stale, degraded, and redacted states are explicit

## Phase 5: Case Room, Profile, and Trust Layer

Primary code areas:

- `apps/desktop/src/features/cases/**`
- `apps/desktop/src/features/profile/**`
- `apps/desktop/src/features/watchlists/**`

Deliverables:

- promote Hunt to Case flow
- lightweight profile and reputation surface
- followable scopes and saved watchlists
- authored briefs and citations

Exit criteria:

- the product loop extends from discovery into durable memory
- validation and credibility are visible in the UI model

## Parallel Workstreams

- Design system convergence can run in parallel with Phase 2 once shell tokens are fixed.
- Proof/replay backend adapters can progress during Phase 3 as long as the domain envelope stays
  stable.
- Watchlist ranking and recommendation logic should wait until after the first typed Wire ships.

## Verification Requirements

Every phase should preserve:

- `bun run typecheck`
- `bun run build`
- Tauri desktop launch via `bun run tauri:dev`

Later phases should add:

- fixture-driven surface tests for wire rows and inspectors
- routing tests for the `Wire -> Huntboard -> Vault` path

## Open Questions

1. Which v1 wire sources are local-only, which are team-scoped, and which are public network data?
2. Should v1 `Rules` ship as a first-class rail destination or remain subordinate to Wire and
   Huntboard?
3. How much of the current 3D scene work remains always-on versus only within Huntboard subviews?
