# Hunt Spirits Roadmap

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, anticipation, and 3D-scene implementers
> **Scope:** Turn hunt spirits from concept into an executable desktop program with phased delivery and ticketable work

## Why This Exists

The hunt-spirit concept is now mature enough that the missing artifact is not more ideation.

The missing artifact is an execution roadmap tied to:

- the current hunt/workbench code
- the creation-flow decisions already documented
- the 3D workspace direction in Nexus and Forensics
- a real multi-agent implementation topology

This doc is the delivery roadmap for that program.

## Current-State Read

The current desktop app has the right substrate but not the right identity model yet.

### What exists

- Hunts are persisted in `apps/desktop/src/shell/workbench/huntTypes.ts` and reduced in
  `apps/desktop/src/shell/workbench/huntReducer.ts`.
- Hunt creation is instant and thin via `HUNT_CREATE`, which currently stores only title, status,
  color, icon, artifact IDs, run IDs, and semantic assignments.
- The dock already gives hunts a compact identity token in
  `apps/desktop/src/shell/workbench/HuntDock.tsx`.
- The smart bucket and anticipation layer already exist in
  `apps/desktop/src/shell/workbench/anticipation/**`.
- The workbench has phase-aware anticipation and predictive open/lens behavior in
  `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts` and
  `apps/desktop/src/shell/workbench/anticipation/useSidebarDirector.ts`.
- The 3D workspace already has strong scene substrates in
  `apps/desktop/src/features/forensics/ForensicsRiverView.tsx` and
  `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`.

### What is missing

- The `Hunt` model has no first-class spirit payload.
- `HUNT_CREATE` cannot attach a default spirit, thesis, anchors, bind reason, or pinned spirit state.
- Spirit configuration does not exist as a user flow.
- The dock and smart bucket still render hunts as generic icon/color containers.
- Anticipation does not yet consume spirit as a biasing signal.
- Forensics and Nexus have no hunt-spirit actor in scene.
- `apps/desktop/src/features/forensics/hooks/useAgentCognitionState.ts` imports
  `@backbay/glia-agent/cognition`, but `apps/desktop/package.json` does not currently declare
  `@backbay/glia-agent`, which is a dependency hygiene risk before deeper spirit work starts.

## Program Principles

- Keep `HUNT_CREATE` instant. Every new hunt gets a default spirit immediately, and spirit configuration layers on top of that; it does not block creation.
- Steal Baia's lifecycle, not its fantasy layer.
- Make spirit real in state before making it loud in the UI.
- Land 3D embodiment in Forensics first, then Nexus.
- Keep shared state contracts orchestrator-owned.
- End on one coherent cross-surface identity, not disconnected experiments.

## Delivery Phases

| Phase | Goal | Exit Criteria |
| --- | --- | --- |
| `P0` | Contract spine | Spirit types, reducers, dependency hygiene, and shared contracts exist |
| `P1` | Spirit defaulting and configuration | Operators can create a hunt with a default spirit, open `Configure Spirit`, preview, and reconfigure |
| `P2` | 2D propagation | Dock, smart bucket, and related hunt surfaces reflect spirit identity |
| `P3` | Anticipation bias | Sidebar and anticipation logic respond to spirit stance and live mood |
| `P4` | Forensics embodiment | Active hunt spirit exists as a first-class actor in Forensics |
| `P5` | Nexus and station embodiment | Spirits bias strikecells, station emphasis, and transit in Nexus |
| `P6` | Hardening | Tests, smoke flows, performance, accessibility, and dogfood proof are green |

## Ticket Breakdown

## Phase P0: Contract Spine

### `HS-P0-01` Hunt spirit domain contract

- Add a first-class `HuntSpiritState` contract and related enums/selectors under a dedicated
  spirit module.
- Define:
  - `baseSpirit`
  - `liveMood`
  - `thesis`
  - `anchorArtifactIds`
  - `bindSource`
  - `bindReason`
  - `isPinned`
  - `version`
- Keep the domain in a dedicated subtree instead of scattering spirit math across existing files.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit/**` (new)
- `apps/desktop/src/shell/workbench/huntTypes.ts`

Dependencies:

- none

### `HS-P0-02` Reducer and hydration support

- Extend hunt actions to support:
  - `HUNT_CONFIGURE_SPIRIT`
  - `HUNT_RECONFIGURE_SPIRIT`
  - `HUNT_PIN_SPIRIT`
- Ensure persisted workbench state hydrates safely when spirit fields are absent.
- Keep `HUNT_CREATE` fast and backward-compatible while ensuring new hunts always receive a default spirit.

Primary paths:

- `apps/desktop/src/shell/workbench/huntReducer.ts`
- `apps/desktop/src/shell/workbench/workbenchState.ts`
- `apps/desktop/src/shell/workbench/WorkbenchStateProvider.tsx`

Dependencies:

- `HS-P0-01`

### `HS-P0-03` Dependency and adapter hygiene

- Decide the explicit bridge between spirit state and `glia-agent`/`glia-three`.
- Add any missing package dependencies deliberately.
- Introduce a hunt-native adapter contract so spirit semantics do not leak agent semantics.

Primary paths:

- `apps/desktop/package.json`
- `apps/desktop/src/features/forensics/hooks/useAgentCognitionState.ts`
- `apps/desktop/src/shell/workbench/spirit/**`

Dependencies:

- `HS-P0-01`

## Phase P1: Spirit Defaulting And Configuration

### `HS-P1-01` Configure Spirit sheet shell

- Create the non-blocking `Configure Spirit` surface that opens after `HUNT_CREATE`.
- Support dismiss, reopen, and lightweight “keep default for now” behavior.
- Keep this anchored to the active hunt instead of making it a separate app.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-bind/**` (new)
- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/WorkbenchShell.tsx`

Dependencies:

- `HS-P0-01`
- `HS-P0-02`

### `HS-P1-02` Quick Configure and Thesis modes

- Implement the first two creation modes:
  - `Quick Configure`
  - `Thesis`
- Show one primary suggestion, alternates, rationale, and predicted focus surfaces.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-bind/**`
- `apps/desktop/src/shell/workbench/spirit/inference/**` (new)

Dependencies:

- `HS-P1-01`

### `HS-P1-03` Anchor Artifacts mode

- Add artifact-anchor selection with up to three seed artifacts.
- Explain suggestions relative to anchors.
- Reuse existing artifact kinds and hunt semantic assignments.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-bind/**`
- `apps/desktop/src/shell/workbench/spirit/inference/**`

Dependencies:

- `HS-P1-02`

### `HS-P1-04` Configure and release behavior

- Finalize `Configure Spirit` as an explicit commit over the already-attached default.
- Trigger immediate updates for dock/sidebar previews.
- Add a restrained settle confirmation motion instead of a generic toast.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-bind/**`
- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`

Dependencies:

- `HS-P1-02`

## Phase P2: 2D Propagation

### `HS-P2-01` Hunt dock spirit pills

- Replace generic hunt icon semantics with spirit tokens.
- Add spirit-aware hover content:
  - spirit name
  - thesis or rationale
  - current bias
- Keep pills compact and operational.

Primary paths:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/spirit/components/**` (new)

Dependencies:

- `HS-P1-04`

### `HS-P2-02` Smart bucket spirit console

- Make the smart bucket show spirit identity and current semantic preference.
- Align semantic drop roles with the spirit’s current stance.

Primary paths:

- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SemanticDropZone.tsx`

Dependencies:

- `HS-P1-04`

### `HS-P2-03` Existing-hunt configure/rebind entrypoints

- Add `Configure spirit`, `Retune spirit`, and `Pin spirit` affordances in the right places.
- Good homes:
  - hunt dock flyout
  - smart bucket
  - hunt-empty state

Primary paths:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
- `apps/desktop/src/shell/workbench/lenses/**`

Dependencies:

- `HS-P1-04`

### `HS-P2-04` Tab and shell identity propagation

- Carry spirit identity into hunt tabs and other compact shell surfaces.
- Avoid one-off icon fallbacks once spirit exists.

Primary paths:

- `apps/desktop/src/shell/workbench/tabRegistry.ts`
- `apps/desktop/src/shell/workbench/TabBar.tsx`
- `apps/desktop/src/shell/workbench/workbenchState.ts`

Dependencies:

- `HS-P2-01`

## Phase P3: Anticipation Bias

### `HS-P3-01` Spirit inference and live mood engine

- Compute base spirit and live mood from:
  - artifact mix
  - semantic assignments
  - current shell/lens
  - phase
  - drag object
  - active run/case
- Keep spirit bias additive to the existing anticipation system.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit/inference/**`
- `apps/desktop/src/shell/workbench/spirit/selectors/**`

Dependencies:

- `HS-P0-01`
- `HS-P0-02`

### `HS-P3-02` Anticipation context integration

- Surface spirit bias inside the master anticipation context.
- Add spirit-aware reasons, copy, and preferred semantic targets.

Primary paths:

- `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts`
- `apps/desktop/src/shell/workbench/anticipation/types.ts`

Dependencies:

- `HS-P3-01`

### `HS-P3-03` Sidebar and wake integration

- Make wake peeks, section promotion, and smart defaults speak with spirit-aware language.
- Bias promoted sections by spirit stance without making the UI twitchy.

Primary paths:

- `apps/desktop/src/shell/workbench/anticipation/useSidebarDirector.ts`
- `apps/desktop/src/shell/workbench/anticipation/useSidebarWakeController.ts`
- `apps/desktop/src/shell/workbench/LensSidebar.tsx`

Dependencies:

- `HS-P3-02`
- `HS-P2-02`

## Phase P4: Forensics Embodiment

### `HS-P4-01` Hunt spirit actor primitives

- Create the first visual/runtime spirit actor primitives for 3D use.
- Define:
  - stable silhouette grammar
  - idle state
  - bind pulse
  - witness / absorb / focus states

Primary paths:

- `apps/desktop/src/features/forensics/components/hunt-spirit/**` (new)
- `apps/desktop/src/shell/workbench/spirit/motion/**` (new)

Dependencies:

- `HS-P0-03`

### `HS-P4-02` Forensics River integration

- Render the active hunt spirit in Forensics as a first-class scene actor.
- Keep it distinct from agent organisms and proof objects.
- Use receipt attach and semantic actions as motion triggers.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/hunt-spirit/**`

Dependencies:

- `HS-P4-01`
- `HS-P3-02`

### `HS-P4-03` Bind/release into 3D

- When a spirit is bound, make the 3D workspace visibly receive it.
- Keep the motion short and legible.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/shell/workbench/spirit-bind/**`

Dependencies:

- `HS-P4-02`

## Phase P5: Nexus And Stations

### `HS-P5-01` Nexus companion actor

- Add the active hunt spirit as a companion object to strikecells.
- Keep strikecells as topology and spirit as posture.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/scene/spirits/**` (new)

Dependencies:

- `HS-P4-01`

### `HS-P5-02` Station affinity and transit

- Allow spirit stance to bias:
  - likely station glow
  - local emphasis
  - transit motion
- Keep station identity intact.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- related station UI files under `apps/desktop/src/features/cyber-nexus/**`

Dependencies:

- `HS-P5-01`
- `HS-P3-02`

### `HS-P5-03` Cross-surface recentering and reselection

- Let reselecting the active spirit recentre its 3D presence and rehearse rationale.
- Make dock/sidebar/scene feel like handles on one object.

Primary paths:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`

Dependencies:

- `HS-P5-01`
- `HS-P2-01`

## Phase P6: Hardening And Proof

### `HS-P6-01` Tests and migration coverage

- Add reducer, selector, and UI coverage for default-spirit creation and spirit configuration.
- Add hydration coverage for existing state without spirit payloads.

Primary paths:

- `apps/desktop/src/shell/workbench/**/*.test.ts*`
- `apps/desktop/src/features/**/*.test.ts*`

Dependencies:

- `HS-P5-03`

### `HS-P6-02` Dogfood and smoke coverage

- Add smoke coverage for:
  - create hunt
  - confirm default spirit
  - reconfigure spirit
  - dock/sidebar propagation
  - Forensics presence
  - Nexus presence

Primary paths:

- desktop smoke scripts
- dogfood docs
- verification notes

Dependencies:

- `HS-P6-01`

### `HS-P6-03` Performance, motion, and accessibility pass

- Verify spirit motion does not degrade scene performance.
- Ensure keyboard and pointer flows remain correct.
- Ensure ambient layers do not steal interaction.

Primary paths:

- spirit-related UI and 3D files touched above

Dependencies:

- `HS-P6-02`

## Recommended Agent Execution Order

- `wave0`: orchestrator seeds contracts, docs, and metadata
- `wave1`: spirit domain plus bind UI shell
- `wave2`: dock/sidebar propagation plus Forensics actor primitives
- `wave3`: anticipation bias plus Nexus/station embodiment
- `wave4`: verification, smoke, dogfood, and polish

See [Hunt Spirits Swarm Plan](./hunt-spirits-swarm-plan.md) for the concrete lane map.

## Acceptance Gate

The program is done only when:

- a new hunt is created with a default spirit immediately and can be reconfigured without blocking hunt creation
- spirit identity is visible and coherent across dock, smart bucket, tabs, and anticipation copy
- spirit stance biases anticipation without overriding explicit operator action
- the active hunt has a readable first-class presence in Forensics and Nexus
- configuration, rebinding, and pinning are all explainable and reversible
- the desktop verification gate passes from one clean run

## Reading Order

- [Hunt Spirits Concept](./hunt-spirits-concept.md)
- [Baia Concept Harvest](./baia-concept-harvest.md)
- [Hunt Spirit Creation Flow](./hunt-spirit-creation-flow.md)
- [Hunt Spirits In The 3D Workspace](./hunt-spirits-3d-workspace-concept.md)
- [Hunt Spirits Swarm Plan](./hunt-spirits-swarm-plan.md)
