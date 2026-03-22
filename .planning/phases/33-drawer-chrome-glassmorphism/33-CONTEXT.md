# Phase 33: Drawer Chrome & Glassmorphism - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix the left drawer's visual flatness: (1) make backdrop-filter blur visually perceptible against the 3D scene, (2) add a visible edge treatment (border or glow), (3) add a header bar showing the active panel name, and (4) add a close button for mouse users.

</domain>

<decisions>
## Implementation Decisions

### Glassmorphism Blur (GLS-01)
- Current issue: drawer appears as flat dark rectangle because the 3D scene behind it may be dark/empty, making blur imperceptible
- Fix: ensure `backdrop-filter: var(--hud-blur)` is applied AND the drawer background opacity allows scene content to show through
- May need to reduce background opacity from current value to let more scene bleed through
- The blur should be visible when the starfield/stations are behind the drawer

### Edge Treatment (GLS-02)
- Add a visible right-edge border or glow on the drawer
- Options: `border-right: 1px solid rgba(255, 255, 255, 0.08)` or a subtle box-shadow on the right edge
- Should feel like a glass pane edge, not a hard divider

### Header Bar (DRW-01)
- Top of the drawer content area shows: "EXPLAINABILITY" / "MISSION" / "REPLAY" / "GHOST MEMORY"
- Uppercase monospace, `var(--hud-text-muted)` color
- Thin bottom border separator between header and panel content
- Fixed height (~32-36px), not scrollable with content

### Close Button (DRW-02)
- X icon or similar in the header bar, right-aligned
- onClick calls `useObservatoryStore.getState().actions.closePanel()`
- Must be visible but not dominant — secondary chrome

### Claude's Discretion
- Exact header height
- Close button icon choice (X, chevron-left, etc.)
- Whether header uses same glass bg or slightly different shade
- Exact border/glow values for edge treatment

</decisions>

<code_context>
## Existing Code Insights

### Key Files
- `ObservatoryLeftDrawer.tsx` — the drawer container (Phase 30), 360px wide, glassmorphism
- `observatory-hud.css` — CSS tokens (--hud-bg, --hud-blur, --hud-border, etc.)
- `hud-constants.ts` — HUD_LEFT_DRAWER_WIDTH=360

### Current Drawer Styling
- Background: `var(--hud-bg)` = `rgba(8, 12, 24, 0.75)`
- Blur: `var(--hud-blur)` = `blur(12px)`
- The drawer mounts always (translateX toggle) and renders panel content via `renderPanel()` switch

</code_context>

<specifics>
## Specific Ideas

From dogfooding: "the drawer panel area appears as a flat dark rectangle with no visible backdrop-filter blur effect... no blur, no border glow, no depth"

</specifics>

<deferred>
## Deferred Ideas

None

</deferred>
