# Phase 30: Left Drawer + Hotkeys + Flight HUD Restyle - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase builds the left-drawer panel container (the sliding glassmorphism slot), wires keyboard hotkeys (E/R/M/G/Escape) to the panel registry, connects station clicks to open Explainability, restyles the flight HUD to match glassmorphism, and adds the drawer slide transition animation. After this phase, pressing a hotkey slides the drawer open (empty placeholder content for now — Phase 31 fills it with real panels).

</domain>

<decisions>
## Implementation Decisions

### Left Drawer
- 300-400px wide glassmorphism panel, slides in from left edge of the observatory canvas
- Uses --hud-* CSS custom properties from Phase 28
- Renders inside the observatory canvas viewport (position: absolute, overlaying the 3D scene)
- Shows a placeholder with the active panel's name until Phase 31 builds real panel content
- Only visible when `observatory-store.activePanel` is non-null (reads from panel registry built in Phase 29)

### Hotkeys
- E = toggle Explainability panel
- R = toggle Replay panel
- M = toggle Mission panel
- G = toggle Ghost Memory panel
- Escape = close any open panel
- Hotkeys use `togglePanel(id)` from the panel registry — pressing the same key closes the panel
- Pressing a different key switches panels (registry handles mutual exclusion)
- Hotkeys only active when the observatory tab is focused (not when typing in other panes)

### Station Click → Explainability
- Clicking a station in the 3D scene opens the Explainability panel for that station
- Uses `openPanel('explainability')` + sets `selectedStationId` in observatory-store
- The mechanism: existing station click handlers call a new action that combines station selection + panel open

### Flight HUD Restyle
- SpaceFlightHud (speed bar, compass, target brackets, off-screen arrows) gets glassmorphism treatment
- Repositioned so it doesn't overlap the new status strip (shift up by HUD_STATUS_STRIP_HEIGHT)
- Uses --hud-* CSS tokens for consistent visual language

### Transition Animation
- Drawer slides in at 200-300ms ease-out
- Content fades in after the drawer reaches open position (slight delay for polish)
- CSS transition on transform: translateX() for the slide

### Claude's Discretion
- Exact drawer width within 300-400px range
- Placeholder content styling for the drawer before Phase 31
- Whether to use CSS transitions or React Spring for the slide animation
- Exact keyboard event binding approach (useEffect on window vs R3F event layer)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `observatory-store.ts` — panel registry with `activePanel`, `openPanel`, `closePanel`, `togglePanel` (Phase 29)
- `observatory-hud.css` — glassmorphism CSS tokens (Phase 28)
- `ObservatoryStatusStrip.tsx` — reference for glassmorphism component styling (Phase 29)
- `SpaceFlightHud.tsx` — the flight HUD to restyle
- `hud-constants.ts` — `HUD_STATUS_STRIP_HEIGHT = 28`

### Established Patterns
- Panel registry uses `useObservatoryStore` Zustand selectors for reactive panel state
- Glassmorphism: `background: var(--hud-bg)`, `backdrop-filter: var(--hud-blur)`, `border: var(--hud-border)`

### Integration Points
- Drawer mounts in ObservatoryTab.tsx (DOM sibling to Canvas and StatusStrip)
- Hotkey listener mounts in ObservatoryTab.tsx (or a dedicated hook)
- Station click wiring in ObservatoryWorldCanvas.tsx (existing station click handlers)
- SpaceFlightHud.tsx needs bottom offset for status strip clearance

</code_context>

<specifics>
## Specific Ideas

User specified: "hotkeys toggle their panel open/closed — pressing the same key closes the active panel" and "Escape closes any open panel"

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>
