# Phase 29: Status Strip + Panel Registry - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase builds the persistent cockpit footer (glassmorphism status strip) and the Zustand panel registry that enforces mutual exclusion. After this phase, the observatory has a production-quality bottom bar showing live telemetry and analyst preset toggles, plus a store-level mechanism for managing which left-drawer panel is active.

</domain>

<decisions>
## Implementation Decisions

### Status Strip Layout
- Thin glassmorphism bar anchored to bottom of the observatory canvas viewport
- Left section: speed (u/s), heading cardinal (N/NE/E etc.), station count
- Center-right section: analyst preset segments (THREAT, EVIDENCE, RECEIPTS, GHOST) as toggle buttons
- Right section: minimap indicator dot
- All telemetry updates use rAF + getState() pattern — zero React subscriptions in the frame loop
- Uses `--hud-*` CSS custom properties from Phase 28

### Analyst Presets
- Four preset segments as small pill-shaped toggle buttons inside the status strip
- Only one can be active at a time (radio behavior)
- Clicking the active preset deactivates it (toggle off)
- Active preset shows a glow/underline indicator
- Preset activation sets `analystPreset` in observatory-store — downstream consumers read it for overlay emphasis

### Panel Registry
- New Zustand slice in observatory-store (not a separate store)
- State: `activePanel: HudPanelId | null` where HudPanelId = 'explainability' | 'replay' | 'mission' | 'ghost'
- Actions: `openPanel(id)`, `closePanel()`, `togglePanel(id)`
- `openPanel` closes any currently open panel first (mutual exclusion)
- `togglePanel` closes if already open, opens if different/closed
- No visual drawer in this phase — registry only. Phase 30 adds the drawer.

### Visual Treatment
- Status strip uses glassmorphism CSS (backdrop-filter blur, semi-transparent bg)
- Text contrast must be high enough for readability (opacity >= 0.85)
- Spirit accent color (`--hud-accent`) for active preset indicator

### Claude's Discretion
- Exact status strip height (24-32px reasonable range)
- Exact preset segment dimensions and spacing
- Whether heading uses abbreviated (N) or full (North) labels
- Animation timing for preset toggle feedback

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `observatory-hud.css` — 8 CSS custom properties for glassmorphism (Phase 28)
- `observatory-store.ts` — existing Zustand store with flightState slice, actions pattern
- `SpaceFlightHud` — existing 60fps DOM HUD with rAF + getState() pattern (reference implementation)
- `hud-constants.ts` — STATION_COLORS_HEX, HUD_COLORS already defined
- `flight-types.ts` — FlightState type with position, quaternion, speedTier, currentSpeed

### Established Patterns
- rAF + `useObservatoryStore.getState()` for 60fps updates (no useState/useSelector in frame loop)
- DOM ref-mutation: `ref.current.style.X = value` and `ref.current.textContent = value`
- CSS custom properties for theming (`--spirit-accent`, `--hud-*`)

### Integration Points
- Status strip mounts in ObservatoryTab.tsx as a DOM sibling after the Canvas div (same pattern as SpaceFlightHud)
- Panel registry adds to existing observatory-store.ts (co-located with flightState, dockingState, missionState)
- Preset state feeds into downstream consumers via store selectors

</code_context>

<specifics>
## Specific Ideas

User specified: "presets live in the status strip" and "minimal persistent HUD with thin status strip"

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>
