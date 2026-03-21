# Phase 28: Design Tokens + Panel Audit - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase establishes a clean slate by deleting all 10 legacy observatory panel/overlay components and defining glassmorphism CSS custom properties. After this phase, the observatory shows only the 3D scene and flight HUD — no panels, no overlays.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure phase. The work is:
1. Delete 10 component files
2. Remove their imports and JSX mounts from ObservatoryTab.tsx and ObservatoryWorldCanvas.tsx
3. Define CSS custom properties for the glassmorphism design system
4. Delete associated test files for removed components

</decisions>

<code_context>
## Existing Code Insights

### Components to Delete (10 files, ~1,463 lines)

| Component | File | Lines | Mounted In |
|-----------|------|-------|-----------|
| Explainability Panel | ObservatoryExplainabilityPanel.tsx | 123 | ObservatoryTab.tsx L983-990 |
| Replay HUD | ObservatoryReplayHud.tsx | 200 | ObservatoryTab.tsx L957-970 |
| Replay Compare Panel | ObservatoryReplayComparePanel.tsx | 170 | ObservatoryTab.tsx L973-980 |
| Analyst Preset Bar | ObservatoryAnalystPresetBar.tsx | 40 | ObservatoryTab.tsx L940-944 |
| Cinematic Overlay | ObservatoryCinematicOverlay.tsx | 195 | ObservatoryTab.tsx L1019-1031 |
| Probe HUD | ObservatoryProbeHud.tsx | 168 | ObservatoryTab.tsx L993-1003 |
| Mission HUD | ObservatoryMissionHud.tsx | 114 | ObservatoryTab.tsx L1007 |
| Ghost Layer | ObservatoryGhostLayer.tsx | 108 | ObservatoryWorldCanvas.tsx L4767 |
| Weather Layer | ObservatoryWeatherLayer.tsx | 75 | ObservatoryWorldCanvas.tsx L4760 |
| Mission Overlay | ObservatoryMissionOverlay.tsx | 269 | ObservatoryWorldCanvas.tsx L4808 |

### Mount Points to Clean

**ObservatoryTab.tsx imports (lines 38-45):**
- ObservatoryProbeHud, ObservatoryMissionHud, ObservatoryReplayHud
- ObservatoryReplayComparePanel, ObservatoryExplainabilityPanel
- ObservatoryAnalystPresetBar, ObservatoryCinematicOverlay + StationArrivalCard

**ObservatoryWorldCanvas.tsx imports (lines 79, 84-85):**
- ObservatoryMissionOverlay, ObservatoryGhostLayer, ObservatoryWeatherLayer

### Glassmorphism Design Tokens
Target values (from user discussion):
- `--hud-bg: rgba(8, 12, 24, 0.75)`
- `--hud-border: 1px solid rgba(255, 255, 255, 0.06)`
- `--hud-shadow: 0 8px 32px rgba(0, 0, 0, 0.4)`
- `--hud-text: rgba(255, 255, 255, 0.85)`
- `--hud-text-muted: rgba(255, 255, 255, 0.45)`
- `--hud-accent: var(--spirit-accent, #4af)`
- `--hud-blur: blur(12px)`
- `--hud-radius: 8px`

### What to KEEP
- SpaceFlightHud (speed bar, compass, brackets, arrows) — stays, restyled in Phase 30
- ObservatoryTab.tsx — stays, mount points cleaned
- ObservatoryWorldCanvas.tsx — stays, mount points cleaned

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase. Delete and define.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>
