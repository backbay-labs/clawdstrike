# Phase 40: Threat Heatmap + Probe Delta Cards - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Two new data-reactive visual layers in the observatory world: (1) a ground-plane GLSL heatmap projecting threat pressure as a continuous color gradient, and (2) floating probe delta cards that appear near stations after probe discharge showing what changed and what to do next.

</domain>

<decisions>
## Implementation Decisions

### Heatmap Visual Design
- Flat CircleGeometry disc at y=-2, matching existing floor conventions, zero GPU overhead from vertex displacement
- Linear gradient blend between 6 SOC colors (blue→teal→green→yellow→amber→red) — smooth, industry standard
- Heatmap radius is 1.2x station ring radius — extends slightly beyond stations for context
- Opacity sine wave pulse (0.3→0.7 over 3s) — subtle breathing, matches beacon pulse convention

### Probe Delta Card UX
- DOM rendering via drei `<Html transform>` — supports text formatting, clickable links, matches glassmorphism HUD style
- Float 8 units above station center, billboard-facing camera — visible from any angle
- Fade out opacity over 0.5s then unmount — matches drawer transition convention
- Replace mode — only show latest delta card per station, previous dismissed immediately

### Integration & Performance
- THREAT preset intensifies heatmap by multiplying opacity by 1.5x, clamped at 1.0 — follows existing preset overlay convention
- Gate behind `weatherBudget === "off"` — reuse existing weather budget system, no new performance toggle needed
- Delta card "why it matters" text sourced from `probeConsequences.ts` explanation + `observatory-recommendations.ts` guidance text — both already compute this data

### Claude's Discretion
- GLSL shader implementation details (uniform naming, vertex/fragment split)
- Exact SOC hex color values for the 6-stop ramp
- Html transform distanceFactor and sprite mode configuration
- Heatmap mesh segment count (balance between resolution and GPU cost)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `StationFresnelGlow.tsx` — existing ShaderMaterial pattern with custom uniforms, established GLSL convention
- `ObservatorySpaceLanes.tsx` — another ShaderMaterial example with animated uniforms
- `probeConsequences.ts` — probe action consequence derivation (explanation text)
- `observatory-recommendations.ts` — probe guidance with delta summaries and next-action recommendations
- `observatory-derivations.ts` — `deriveHeatmapDataTexture` utility (Phase 39)
- `observatory-performance.ts` — `ObservatoryRuntimeActivitySources` with `heatmapPulseVersion` field (Phase 39)
- `ObservatoryInvalidationController.tsx` — already extended with `heatmapPulseVersion` source key (Phase 39)

### Established Patterns
- Scene layers are prop-driven components threaded from ObservatoryTab → ObservatoryWorldCanvas → ObservatoryWorldScene
- All visual layers follow GhostTraceLayer pattern — conditional render, prop-driven, no direct store reads
- Performance gating via weatherBudget from observatory-performance.ts
- Glassmorphism HUD tokens for DOM overlay elements

### Integration Points
- `ObservatoryWorldScene.tsx` — mount ThreatTopologyHeatmap and ProbeDeltaLayer as new render layers
- `ObservatoryWorldCanvas.tsx` / `ObservatoryTab.tsx` — derive and thread heatmap + delta card props
- `analystPresetId` prop — heatmap responds to THREAT preset

</code_context>

<specifics>
## Specific Ideas

- Follow the exact ShaderMaterial uniform pattern from StationFresnelGlow.tsx
- Heatmap should use 6 station pressure values as uniforms (one per station), updated in-place via ref mutation
- Delta card glassmorphism styling should use --hud-bg, --hud-border, --hud-text CSS vars
- Card content: pressure shift arrow (↑/↓/→), explanation sentence, clickable action button

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
