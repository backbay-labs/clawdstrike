# Phase 32: Scene & Status Strip Polish - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix two visual issues identified in dogfooding: (1) the 3D scene shows a blank black rectangle during initial load/fly-by — it should render visible content from the first frame, and (2) the status strip needs a visible top border and higher-contrast text. Also relocate the orphaned ATLAS toggle button from the top-right corner into the status strip.

</domain>

<decisions>
## Implementation Decisions

### Scene Rendering (SCN-01)
- The blank screen is likely caused by the fly-by camera starting in empty void, or the Canvas not rendering until after the fly-by animation setup completes
- Fix should ensure stars/starfield are visible from frame 1 — the Star Nest shader background sphere renders behind everything at renderOrder=-1000
- May need to set Canvas `frameloop="always"` during fly-by, or ensure the initial camera position faces visible content
- If WebGL context init is slow, show the scene background color (not black) as fallback

### ATLAS Relocation (SCN-02)
- Move the ATLAS toggle from the orphaned top-right position into the status strip
- Place it as a labeled segment alongside THREAT/EVIDENCE/RECEIPTS/GHOST
- It's a mode toggle (atlas vs flow), not a preset — but visually belongs in the strip

### Status Strip Border (STS-01)
- Add a visible 1px top border: `border-top: 1px solid rgba(255, 255, 255, 0.08)` or similar
- Must be visible enough to separate strip from scene but not harsh

### Status Strip Text (STS-02)
- Ensure speed, heading, station count text is minimum 11px, font-family monospace, opacity >= 0.8
- Check current values and adjust if below these thresholds

### Claude's Discretion
- Exact border color/opacity for STS-01
- Whether to adjust camera initial position or force early render for SCN-01
- ATLAS segment styling within the status strip

</decisions>

<code_context>
## Existing Code Insights

### Key Files
- `ObservatoryWorldCanvas.tsx` — Canvas with gl prop, camera setup, fly-by logic
- `ObservatoryTab.tsx` — mounts Canvas, StatusStrip, has ATLAS button
- `ObservatoryStatusStrip.tsx` — the status strip component (Phase 29)
- `ObservatoryStarfield.tsx` — Star Nest shader sphere (always renders)
- `world-canvas/ObservatoryWorldScene.tsx` — scene composition

### Integration Points
- ATLAS button currently rendered in ObservatoryTab.tsx as a standalone positioned element
- Status strip mounts at ObservatoryTab.tsx line ~908
- Starfield is inside the Canvas tree — should render from first frame if frameloop allows

</code_context>

<specifics>
## Specific Ideas

From dogfooding: "Users see a black rectangle with 'CLAWDSTRIKE WORKBENCH - SECURITY OBSERVATORY - ESC to skip' but no stars, no stations, no scene. This is a bad first impression."

</specifics>

<deferred>
## Deferred Ideas

None

</deferred>
