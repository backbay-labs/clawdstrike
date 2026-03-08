# Huntronomer

> **Status:** Draft | **Date:** 2026-03-07
> **Audience:** Product, design, desktop, platform, and hunt/runtime implementers
> **Scope:** Refactor the restored `apps/desktop` product from ClawdStrike SDR into Huntronomer

Huntronomer is the desktop-first "proof-carrying threat network" built on top of the existing
ClawdStrike shell, hunt telemetry, and receipt plumbing. The refactor keeps the strongest parts of
the restored desktop app, especially the shell/session stack and the forensics river, while
changing the product center of gravity from a multi-plugin SDR launcher to:

1. **Signal Wire** as the default home surface
2. **Huntboard** as the operating surface for swarm supervision
3. **Receipt Vault / Replay Lens** as the proof surface
4. **Case Room / Profile** as the durable memory and reputation layer

## Reading Order

1. [Current State Review](./current-state.md)
2. [Target Architecture](./target-architecture.md)
3. [Surface Map](./surface-map.md)
4. [Spec 16: Huntronomer Event Model](../../../specs/16-huntronomer-event-model.md)
5. [Implementation Roadmap](./roadmap.md)
6. [Swarm Execution Plan](./swarm-plan.md)

## Related Initiatives

- [Intent Gravity Implementation](./intent-gravity-implementation.md) - predictive operator-shell
  implementation spine for the anticipation layer, sidebar reshaping, staging shelf, and semantic
  drop routing
- [Hunt Spirits Concept](./hunt-spirits-concept.md) - proposed identity and behavioral layer for
  giving hunts a durable operative posture instead of generic icons
- [Baia Concept Harvest](./baia-concept-harvest.md) - decision filter for what to steal directly,
  what to translate into Huntronomer, and what to leave behind from Baia
- [Hunt Spirit Creation Flow](./hunt-spirit-creation-flow.md) - canonical user-facing flow for
  creating a hunt first, then binding a spirit through thesis, anchors, or quick inference
- [Hunt Spirits Roadmap](./hunt-spirits-roadmap.md) - phase-by-phase implementation roadmap with
  ticket slices, dependencies, and acceptance gates for turning spirit into a real desktop program
- [Hunt Spirits In The 3D Workspace](./hunt-spirits-3d-workspace-concept.md) - proposed spatial
  architecture for making hunt spirits live in Nexus, Forensics River, and station-aware scenes
- [Hunt Spirits Swarm Plan](./hunt-spirits-swarm-plan.md) - orchestrator/worker lane map, wave
  order, verification matrix, and shared-file boundaries for parallel execution
- [Sidebar Intelligence](./sidebar-intelligence/README.md) - completed/continuing initiative for
  turning the sidebar into a native anticipatory surface with adjacent-surface reactions and
  verification
- [Workspace Shell](./workspace-shell/README.md) - native-backed filesystem, editor, search,
  terminal, and git planning set for the desktop app

## Source Material

- Product spec: Huntronomer Product Spec v0.1 (provided in the task thread)
- Canonical docs layout: `docs/DOCS_MAP.md`, `docs/plans/README.md`
- Existing initiative precedent:
  - `docs/plans/clawdstrike/adaptive-sdr-research-brief.md`
  - `docs/plans/clawdstrike/adaptive-sdr-review.md`
  - `docs/plans/clawdstrike/adaptive-sdr-implementation.md`
- Platform architecture:
  - `docs/specs/15-adaptive-sdr-architecture.md`
  - `docs/research/2026-02-25-desktop-openclaw-integration.md`
- Current desktop app:
  - `apps/desktop/README.md`
  - `apps/desktop/src/shell/**`
  - `apps/desktop/src/features/**`

## Initial Thesis

- The current shell, docking, sessions, Tauri bridge, and OpenClaw integration are worth keeping.
- The current default information architecture is not worth preserving; it behaves like a plugin
  gallery instead of a cyber operations product loop.
- The current forensics river is the strongest reusable substrate for the Huntboard's `Atlas`,
  `Flow`, and `Timeline` views.
- The current `Event Stream` should become a proof-oriented Receipt Vault / Replay entry surface,
  not the flagship home screen.
- Huntronomer needs a first-class typed object model before large UI refactors start. Without that,
  the app will stay trapped in ad hoc event and demo-view wiring.

## Code Touchpoints

| Area | Current Files | Direction |
| --- | --- | --- |
| Shell / navigation / docking | `apps/desktop/src/shell/**` | Keep and simplify around four flagship surfaces |
| Default app registry | `apps/desktop/src/shell/plugins/registry.tsx` | Replace plugin-gallery IA with Huntronomer surface IA |
| Forensics river / 3D execution view | `apps/desktop/src/features/forensics/ForensicsRiverView.tsx` | Refactor into Huntboard center canvas |
| Event stream / receipt preview | `apps/desktop/src/features/events/**` | Recast as Receipt Vault / Replay Lens |
| OpenClaw swarm supervision | `apps/desktop/src/features/openclaw/**`, `apps/desktop/src/context/OpenClaw*` | Keep as live swarm runtime control plane |
| Tauri / local proof plumbing | `apps/desktop/src/services/tauri.ts`, `apps/desktop/src-tauri/**` | Preserve; extend into proof/replay links |

## Deliverables In This Set

- A grounded review of the restored desktop app
- A target architecture for the Huntronomer desktop refactor
- A surface-by-surface design map for the flagship UX
- A formal spec for Huntronomer's typed event and object model
- A phased v1 roadmap tied to real code paths
