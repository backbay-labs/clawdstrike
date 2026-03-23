---
phase: 40-threat-heatmap-probe-delta-cards
verified: 2026-03-23T01:59:15Z
status: passed
score: 9/9 must-haves verified
re_verification: false
---

# Phase 40: Threat Heatmap + Probe Delta Cards Verification Report

**Phase Goal:** The observatory world has two new data-reactive visual layers — a ground-plane heatmap projects threat pressure as a continuous color gradient across the station ring, and floating delta cards appear near stations after probes fire, showing what changed and what to do next
**Verified:** 2026-03-23T01:59:15Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #  | Truth                                                                                                               | Status     | Evidence                                                                                                              |
|----|---------------------------------------------------------------------------------------------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------|
| 1  | Ground-plane CircleGeometry disc at y=-2 renders below station ring with SOC 6-stop color ramp driven by per-station pressure | ✓ VERIFIED | `ThreatTopologyHeatmap.tsx` L207-211: `position={[0, -2, 0]}`, `circleGeometry args={[WORLD_RADIUS * 1.2, 128]}`; GLSL fragment shader has IDW blending across 6 stations mapped to `socColorRamp()` |
| 2  | Heatmap color ramp blends smoothly from blue through teal, green, yellow, amber to red matching SOC conventions     | ✓ VERIFIED | `HEATMAP_SOC_COLORS` L25-32: exactly 6 entries `#1a5fb4` (blue) → `#26a269` (teal) → `#33d17a` (green) → `#f5c211` (yellow) → `#e66100` (amber) → `#c01c28` (red); piecewise `mix()` in fragment shader |
| 3  | Heatmap pulses with sine-wave opacity oscillation (0.3 to 0.7 over 3s)                                             | ✓ VERIFIED | `ThreatTopologyHeatmap.tsx` L188-189: `Math.sin(clock.elapsedTime * ((2 * Math.PI) / 3)) * 0.5 + 0.5`; GLSL L108: `mix(0.3, 0.7, uPulse) * uOpacityMultiplier` |
| 4  | After probe fires, floating glassmorphism card appears 8 units above target station                                 | ✓ VERIFIED | `ProbeDeltaLayer.tsx` L31 `CARD_Y_OFFSET = 8`; L165: `position={[stationX, stationY + CARD_Y_OFFSET, stationZ]}`; `<Html transform distanceFactor={80} sprite>` |
| 5  | Delta card shows pressure shift direction arrow, explanation sentence, and clickable recommended action button      | ✓ VERIFIED | `ProbeDeltaCard.tsx`: `getShiftArrow()` maps delta kinds to ↑/→/—; renders `guidance.delta.summary`, `guidance.whyItMatters`, and action `<button>` with `data-testid="probe-delta-action"` |
| 6  | Delta card auto-dismisses after 8 seconds or on analyst click/keypress                                              | ✓ VERIFIED | `ProbeDeltaLayer.tsx` L25-27: `AUTO_DISMISS_DELAY_MS = 7500` / `AUTO_DISMISS_TOTAL_MS = 8000`; `window.addEventListener("keydown", handleKeyDown)` L140; `onDismiss` on outer div click |
| 7  | Only latest delta card per station is shown (replace mode) — previous dismissed immediately                         | ✓ VERIFIED | `ProbeDeltaLayer.tsx` L94-102: `setActiveCard` functional update clears timers and replaces guidance on change; test confirms single card at a time |
| 8  | Heatmap gated by weatherBudget — when "off", no mesh renders                                                        | ✓ VERIFIED | `ObservatoryWorldCanvas.tsx` L4302: `const heatmapVisible = performanceProfile.weatherBudget !== "off"`; `ObservatoryWorldScene.tsx` L192: `{heatmapVisible && heatmapPressureData ? <ThreatTopologyHeatmap ... /> : null}` |
| 9  | THREAT analyst preset intensifies heatmap by 1.5x; other presets use 1.0x                                          | ✓ VERIFIED | `ObservatoryWorldCanvas.tsx` L4303: `const heatmapPresetMultiplier = analystPresetIdOuter === "threat" ? 1.5 : 1.0`; threaded to scene and consumed by `uOpacityMultiplier` uniform |

**Score:** 9/9 truths verified

### Required Artifacts

| Artifact                                                                                                    | Expected                                         | Status     | Details                                                                  |
|-------------------------------------------------------------------------------------------------------------|--------------------------------------------------|------------|--------------------------------------------------------------------------|
| `apps/workbench/src/features/observatory/components/world-canvas/ThreatTopologyHeatmap.tsx`                 | GLSL ShaderMaterial heatmap component            | ✓ VERIFIED | 213 lines (min 80). Exports `ThreatTopologyHeatmap`, `ThreatTopologyHeatmapProps`, `HEATMAP_SOC_COLORS`. Full GLSL with 6 station + pressure + color uniforms, pulse, opacity multiplier. |
| `apps/workbench/src/features/observatory/__tests__/threat-topology-heatmap.test.ts`                         | Unit tests for heatmap                           | ✓ VERIFIED | 136 lines (min 30). 4 tests: smoke (zeros), smoke (mixed), SOC colors length, visible=false gate. |
| `apps/workbench/src/features/observatory/components/world-canvas/ProbeDeltaCard.tsx`                        | Single delta card DOM overlay via drei Html      | ✓ VERIFIED | 176 lines (min 40). Exports `ProbeDeltaCard`, `ProbeDeltaCardProps`. Glassmorphism HUD vars, shift arrow, summary, whyItMatters, action button with stopPropagation. |
| `apps/workbench/src/features/observatory/components/world-canvas/ProbeDeltaLayer.tsx`                       | Layer managing delta card lifecycle              | ✓ VERIFIED | 182 lines (min 50). Exports `ProbeDeltaLayer`, `ProbeDeltaLayerProps`. Two-timer auto-dismiss, keydown handler, replace mode. |
| `apps/workbench/src/features/observatory/__tests__/probe-delta-layer.test.ts`                               | Unit tests for delta layer lifecycle             | ✓ VERIFIED | 159 lines (min 30). 5 tests: exports, null guard, show-on-guidance, 8s auto-dismiss (fake timers), replace mode. |
| `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts`          | Extended scene props with heatmap + delta fields | ✓ VERIFIED | Contains `heatmapPressureData?: Float32Array | null`, `heatmapVisible?: boolean`, `heatmapPresetMultiplier?: number`, `probeGuidance?: ObservatoryProbeGuidance | null`, and `ObservatoryProbeGuidance` import. |
| `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx`                 | Renders ThreatTopologyHeatmap and ProbeDeltaLayer | ✓ VERIFIED | Imports both components, renders `<ThreatTopologyHeatmap>` gated by `heatmapVisible && heatmapPressureData`, renders `<ProbeDeltaLayer>` unconditionally, passes `OBSERVATORY_STATION_POSITIONS` to both. |
| `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx`                             | Derives heatmap data and threads props to scene  | ✓ VERIFIED | Imports `deriveHeatmapDataTexture`, derives `heatmapPressureData` via `useMemo` over `world.districts.emphasis`, derives `heatmapVisible` and `heatmapPresetMultiplier`, threads all four props + `probeGuidance` to `ExtractedObservatoryWorldScene`. |

### Key Link Verification

| From                         | To                              | Via                                             | Status     | Details                                                                                      |
|------------------------------|---------------------------------|-------------------------------------------------|------------|----------------------------------------------------------------------------------------------|
| `ThreatTopologyHeatmap.tsx`  | `observatory-derivations.ts`    | `pressureData` prop (Float32Array)              | ✓ WIRED    | Prop consumed via `useFrame` loop updating `uPressure0`-`uPressure5` uniforms from `pressureData[i]` |
| `ThreatTopologyHeatmap.tsx`  | `OBSERVATORY_STATION_POSITIONS` | station positions for shader uniforms           | ✓ WIRED    | `stationPositions` prop consumed in `useMemo` to build `uStation0`-`uStation5` vec2 uniforms |
| `ProbeDeltaLayer.tsx`        | `observatory-recommendations.ts` | `probeGuidance: ObservatoryProbeGuidance`       | ✓ WIRED    | L16: `import type { ObservatoryProbeGuidance }` used in `ProbeDeltaLayerProps.probeGuidance` |
| `ProbeDeltaCard.tsx`         | `observatory-command-actions.ts` | `openObservatoryRecommendationRoute`            | ✓ WIRED    | L22: `import { openObservatoryRecommendationRoute }` — called in action button click handler |
| `ProbeDeltaCard.tsx`         | `observatory-hud.css`           | `--hud-bg`, `--hud-border`, `--hud-blur` vars   | ✓ WIRED    | L79-82: `"var(--hud-bg, ...)"`, `"var(--hud-border, ...)"`, `"var(--hud-blur, ...)"` inline styles with fallbacks |
| `ObservatoryWorldCanvas.tsx` | `observatory-derivations.ts`    | `deriveHeatmapDataTexture` call                 | ✓ WIRED    | L93: import; L4295-4301: `useMemo` calling `deriveHeatmapDataTexture(pressures, HUNT_STATION_ORDER)` returning Float32Array |
| `ObservatoryWorldCanvas.tsx` | `ObservatoryWorldScene.tsx`     | `heatmapPressureData` and `probeGuidance` props | ✓ WIRED    | L4774-4777: all four props threaded to `<ExtractedObservatoryWorldScene>` |
| `ObservatoryWorldScene.tsx`  | `ThreatTopologyHeatmap.tsx`     | conditional render gated by `heatmapVisible`    | ✓ WIRED    | L192-196: `{heatmapVisible && heatmapPressureData ? <ThreatTopologyHeatmap pressureData={heatmapPressureData} stationPositions={OBSERVATORY_STATION_POSITIONS} presetOpacityMultiplier={heatmapPresetMultiplier} /> : null}` |
| `ObservatoryWorldScene.tsx`  | `ProbeDeltaLayer.tsx`           | `probeGuidance` prop                            | ✓ WIRED    | L212-213: `<ProbeDeltaLayer probeGuidance={probeGuidance} stationPositions={OBSERVATORY_STATION_POSITIONS} />` |
| `ObservatoryTab.tsx`         | `ObservatoryWorldCanvas.tsx`    | `probeGuidance` prop                            | ✓ WIRED    | L414: `const probeGuidance = useMemo<ObservatoryProbeGuidance | null>(...)` derived; L895: `probeGuidance={probeGuidance}` passed to `<ObservatoryWorldCanvas>` |

### Requirements Coverage

| Requirement | Source Plan | Description                                                                                     | Status      | Evidence                                                                                                     |
|-------------|-------------|-------------------------------------------------------------------------------------------------|-------------|--------------------------------------------------------------------------------------------------------------|
| HEAT-01     | 40-01       | Ground-plane gradient mesh renders below station ring showing threat pressure as continuous color field | ✓ SATISFIED | `ThreatTopologyHeatmap.tsx` CircleGeometry at y=-2, GLSL IDW blending, full color field output                |
| HEAT-02     | 40-01       | SOC-standard color ramp (blue/teal = calm, amber/red = critical) driven by per-station pressure  | ✓ SATISFIED | `HEATMAP_SOC_COLORS` 6-stop ramp; fragment shader `socColorRamp()` piecewise mix                             |
| HEAT-03     | 40-01       | Heatmap pulses and shifts as telemetry updates arrive, smooth interpolation                      | ✓ SATISFIED | `useFrame` updates `uPressure0-5` each frame from live `pressureData` prop; sine-wave `uPulse` oscillation    |
| HEAT-04     | 40-03       | Heatmap respects performance budget (off/reduced/full) — gated behind `weatherBudget`            | ✓ SATISFIED | `heatmapVisible = performanceProfile.weatherBudget !== "off"` gates `<ThreatTopologyHeatmap>` render          |
| HEAT-05     | 40-03       | THREAT preset intensifies heatmap; other presets dim it                                          | ✓ SATISFIED | `heatmapPresetMultiplier = analystPresetIdOuter === "threat" ? 1.5 : 1.0` threaded to `presetOpacityMultiplier` prop |
| PRBI-01     | 40-02       | Floating delta card appears near target station after probe fires and completes                   | ✓ SATISFIED | `ProbeDeltaLayer` renders `<Html transform sprite>` at `stationY + 8` when `probeGuidance` is non-null        |
| PRBI-02     | 40-02       | Delta card shows what changed (pressure shift direction, transition)                              | ✓ SATISFIED | `ProbeDeltaCard` renders `guidance.delta.summary` and `getShiftArrow(guidance.delta.kind)` shift arrow symbol  |
| PRBI-03     | 40-02       | Delta card shows one-sentence explanation of why the change matters                               | ✓ SATISFIED | `ProbeDeltaCard` renders `guidance.whyItMatters` in muted text block                                          |
| PRBI-04     | 40-02       | Delta card shows clickable recommended next action to open relevant workbench route               | ✓ SATISFIED | `ProbeDeltaCard` renders action `<button>` calling `openObservatoryRecommendationRoute` on click              |
| PRBI-05     | 40-02       | Delta card auto-dismisses after 8 seconds or on analyst click/keypress                           | ✓ SATISFIED | Two-timer pattern: fade at 7500ms, remove at 8000ms; `window.addEventListener("keydown", dismiss)` on mount   |
| PRBI-06     | 40-03       | Delta card triggers invalidation so demand-based frame loop renders it correctly                  | ✓ SATISFIED | `ObservatoryInvalidationController` L22/28 already tracks `probeStatus` and `heatmapPulseVersion` source keys; state transitions from `probeGuidance` prop change trigger React re-renders which invalidate the canvas |

### Anti-Patterns Found

None. No TODO/FIXME/placeholder comments, no empty implementations, no stub returns found in any phase 40 files.

### Human Verification Required

#### 1. Heatmap color gradient visual appearance

**Test:** Open the observatory with a live hunt that has uneven station pressure (e.g., one station at high threat). Observe the ground-plane disc.
**Expected:** Blue/teal regions beneath calm stations, amber/red beneath high-pressure stations, with smooth continuous gradient blending between them. Subtle breathing pulse visible over 3-second period.
**Why human:** Color gradient rendering and visual quality cannot be verified by grep/static analysis — requires live WebGL canvas.

#### 2. THREAT preset heatmap intensity change

**Test:** In the observatory, toggle the THREAT analyst preset on and off while watching the heatmap.
**Expected:** Heatmap visibly brightens (opacity increase) when THREAT preset active; returns to baseline when deactivated or a different preset is chosen.
**Why human:** Requires live UI interaction with the preset selector and visual confirmation of opacity change.

#### 3. Delta card appearance and dismissal flow

**Test:** Fire a probe on a station, wait for it to complete, observe the floating card.
**Expected:** Card appears 8 units above the station with glassmorphism styling, shows pressure direction arrow, summary sentence, and action button. Card fades out around 7.5s and fully vanishes at 8s. Pressing any key or clicking the card dismisses it immediately.
**Why human:** Probe lifecycle, 3D card positioning, and animation timing require live runtime verification.

#### 4. weatherBudget=off completely removes heatmap

**Test:** Set observatory performance to low/minimal (which sets weatherBudget to "off"), then observe the scene.
**Expected:** No heatmap disc is visible anywhere in the scene — complete absence, not just dimmed.
**Why human:** Performance profile switching requires live runtime with confirmed weatherBudget="off" state.

### Gaps Summary

No gaps found. All nine observable truths are verified by codebase evidence:
- `ThreatTopologyHeatmap.tsx` is a complete, substantive GLSL ShaderMaterial component (213 lines) with full inverse-distance-weighted fragment shader, SOC 6-stop color ramp, sine-wave pulse animation, and visibility gate.
- `ProbeDeltaCard.tsx` and `ProbeDeltaLayer.tsx` are complete implementations (176 and 182 lines respectively) with all required behaviors: glassmorphism styling, shift arrows, auto-dismiss lifecycle, keypress handler, replace mode, and drei Html 3D positioning.
- All four wiring artifacts (`observatory-world-scene-types.ts`, `ObservatoryWorldScene.tsx`, `ObservatoryWorldCanvas.tsx`, `ObservatoryTab.tsx`) contain the required derivations and prop threading.
- All 11 requirement IDs (HEAT-01 through HEAT-05, PRBI-01 through PRBI-06) are covered and satisfy their requirement descriptions.

---

_Verified: 2026-03-23T01:59:15Z_
_Verifier: Claude (gsd-verifier)_
