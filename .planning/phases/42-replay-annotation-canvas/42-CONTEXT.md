# Phase 42: Replay Annotation Canvas - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Interactive 3D annotation system for the replay timeline: analysts click in 3D space during replay to drop named pins, attach text notes, manage annotations from the Replay drawer, and their work persists across sessions via localStorage v2.

</domain>

<decisions>
## Implementation Decisions

### Pin Visual Design
- Vertical diamond geometry (two cones tip-to-tip) with emissive glow — distinctive from station geometry
- Spirit accent color when bound, fallback cyan (#00d4ff) when unbound
- Always-visible text label above pin via drei `<Text>` — glanceable without interaction
- Fixed 0.8 unit scale — pins are markers, not landmarks

### Annotation Interaction
- Single click on empty 3D space to drop a pin — lowest friction
- DOM overlay input near pin via drei `<Html>` for text editing — glassmorphism styled, reliable keyboard input
- Smooth 0.8s lerp camera jump when clicking pin in drawer — matches station focus convention
- Immediate delete without confirmation — pins are lightweight, undo is re-create

### Drawer Integration
- Separate "Annotations" section below existing timeline scrubber in the Replay drawer panel
- Pin list sorted by replay frame index ascending — matches timeline left-to-right model
- Always-on annotation mode during replay — no explicit toggle needed, click empty space = drop pin, click pin = edit

### Claude's Discretion
- Exact cone geometry dimensions for the diamond marker
- drei Text font size and maxWidth for pin labels
- Html overlay input styling details within glassmorphism constraints
- Raycast configuration for click detection (layers, threshold)
- Camera lerp easing function parameters

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `observatory-store.ts` — annotation pin CRUD actions (addAnnotationPin, removeAnnotationPin, clearAnnotationPins) from Phase 39
- `observatory-replay-persistence.ts` — v2 schema with annotationPins field (Phase 39)
- `types.ts` — ObservatoryAnnotationPin interface (Phase 39)
- `ObservatoryInvalidationController.tsx` — already has annotationDropCount source key (Phase 39)
- `hud/panels/ReplayDrawerPanel.tsx` — existing Replay drawer panel to extend
- `observatory-hud.css` — glassmorphism CSS variables for DOM overlays

### Established Patterns
- Scene layers are prop-driven from ObservatoryTab → ObservatoryWorldCanvas → ObservatoryWorldScene
- drei `<Html>` for DOM overlays in 3D space (used by ProbeDeltaCard)
- drei `<Text>` for in-world text labels
- localStorage v2 persistence with hydrate-on-mount pattern (established in Phase 41 for constellations)
- Replay store slice: enabled, frameIndex, frameMs, bookmarks, annotations

### Integration Points
- `ObservatoryWorldScene.tsx` — mount ReplayAnnotationLayer as new render layer
- `ObservatoryWorldCanvas.tsx` — thread annotation pins + replay state as props
- `ObservatoryTab.tsx` — hydrate pins from localStorage, save on changes
- `hud/panels/ReplayDrawerPanel.tsx` — add Annotations section with pin list

</code_context>

<specifics>
## Specific Ideas

- Raycast on click should use R3F's built-in onPointerDown on a transparent ground plane, not a custom raycaster
- Pin drop should capture current replay frameIndex from the store at drop time
- Camera jump should use the existing orbit controls target + position lerp pattern from station focus
- Drawer Annotations section should show pin icon + truncated note text + frame timestamp

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
