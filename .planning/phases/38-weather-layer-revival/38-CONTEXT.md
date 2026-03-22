# Phase 38: Weather Layer Revival - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Mount the existing weather system into the 3D scene. The weather logic (`observatory-weather.ts`, 931 LOC) is fully implemented but was unmounted during Phase 28 cleanup. Re-add it with proper performance profile gating.
</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- The weather system code already exists — this is a re-mounting and integration task
- `observatory-weather.ts` derives weather state from hunt telemetry pressure
- Need to create or restore a weather layer component that renders fog, particles, lighting based on weatherState
- Mount in ObservatoryWorldCanvas, conditional on performance profile (disabled on low quality)
- weatherState is already computed in ObservatoryTab and passed to ObservatoryWorldCanvas
- Previous `ObservatoryWeatherLayer.tsx` was deleted in Phase 28 — rebuild it using the existing weather data contract
</decisions>

<code_context>
## Existing Code Insights

- `observatory-weather.ts` — full weather derivation logic (style, density, tint, budget, phaseOffset, etc.)
- `ObservatoryWeatherState` type — already defined with all fields needed
- `ObservatoryTab.tsx` — already computes `weatherState` and passes it to `ObservatoryWorldCanvas`
- `ObservatoryWorldCanvas.tsx` — accepts `weatherState` prop (type already in props interface)
- Performance profiles — `ObservatoryPerformanceProfile` has quality tiers that can gate weather
- Phase 28 deleted the old `ObservatoryWeatherLayer.tsx` — needs fresh rebuild
</code_context>

<specifics>No specific requirements</specifics>
<deferred>None</deferred>
