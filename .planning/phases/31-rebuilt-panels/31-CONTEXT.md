# Phase 31: Rebuilt Panels - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase rebuilds four analyst panels as production-quality components designed for the left drawer. Each panel replaces the placeholder content in ObservatoryLeftDrawer with real UI sourced from existing observatory-store data. After this phase, pressing E/R/M/G opens a fully functional panel with real content.

</domain>

<decisions>
## Implementation Decisions

### Panel Architecture
- Each panel is a separate component file in `components/hud/panels/`
- ObservatoryLeftDrawer renders the active panel based on `activePanel` from the store
- Panels receive the drawer width as context (360px) and are designed for that constraint
- All panels use glassmorphism styling via --hud-* CSS tokens
- Panels source data from existing observatory-store slices — no new data fetching

### Explainability Panel (E key)
- Shows selected station name and kind
- Ranked pressure causes from observatory-store telemetry data
- Top anomalies list
- "Probe" action button that dispatches `observatory.probe` command
- Station-specific: content changes when selectedStationId changes

### Mission Panel (M key)
- Active mission objective title and description
- Waypoint guidance text (narrative directive)
- Objective completion checkmarks (completed vs pending)
- Sources from observatory-store.mission state (missionLoop data)

### Replay Panel (R key)
- Timeline scrubber (horizontal range input)
- Bookmark list (clickable items)
- Jump-to-spike button
- Compare-now-vs-then toggle
- Sources from observatory-store.replay state

### Ghost Memory Panel (G key)
- Scrollable list of prior findings
- Receipt traces with timestamps
- Case-note text entries
- Sources from observatory-store ghost memory state

### Claude's Discretion
- Exact component decomposition within each panel
- Typography hierarchy within panels (heading sizes, spacing)
- Whether panels use subsections with collapsible headers
- Empty state messages when no data is available
- Exact button styling for action buttons (Probe, Jump-to-spike, etc.)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ObservatoryLeftDrawer.tsx` — renders `children` based on `activePanel`, handles slide animation (Phase 30)
- `observatory-store.ts` — all data sources: stations, mission, replay, ghostMemory, selectedStationId, telemetry
- `observatory-hud.css` — glassmorphism CSS tokens
- `hud-constants.ts` — HUD_LEFT_DRAWER_WIDTH=360, ANALYST_PRESETS, STATION_COLORS_HEX

### Established Patterns
- Glassmorphism: `background: var(--hud-bg)`, `backdrop-filter: var(--hud-blur)`, `border: var(--hud-border)`
- Text: `color: var(--hud-text)` for primary, `var(--hud-text-muted)` for secondary
- Accent: `var(--hud-accent)` for highlights, buttons, active states
- Store access: `useObservatoryStore` selectors for reactive data in panel components (panels change rarely, not 60fps)

### Integration Points
- ObservatoryLeftDrawer.tsx needs to switch on `activePanel` and render the correct panel component
- Each panel reads from observatory-store selectors
- Explainability panel needs `selectedStationId` for station-specific content
- Mission panel needs `mission` state from observatory-store
- Probe action button dispatches via command registry or store action

</code_context>

<specifics>
## Specific Ideas

User specified: these panels should be "beautiful and professional" — production quality, not prototypes.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>
