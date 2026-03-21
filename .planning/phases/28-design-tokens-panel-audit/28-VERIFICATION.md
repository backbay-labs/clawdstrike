---
phase: 28-design-tokens-panel-audit
verified: 2026-03-21T00:00:00Z
status: gaps_found
score: 5/6 must-haves verified
re_verification: false
gaps:
  - truth: "The 10 removed component files no longer exist anywhere in apps/workbench/src"
    status: partial
    reason: "All 10 component files are deleted, but observatory-world-canvas.performance.test.tsx still contains a vi.mock of ObservatoryWeatherLayer (lines 96-101) with active assertions at lines 446 and 477 that expect the deleted component's testId to be rendered by ObservatoryWorldCanvas — a test file referencing dead code that will fail at runtime"
    artifacts:
      - path: "apps/workbench/src/features/observatory/__tests__/observatory-world-canvas.performance.test.tsx"
        issue: "vi.mock('@/features/observatory/components/ObservatoryWeatherLayer') on line 96, weatherMock assertions on lines 446 and 477 — mocking a deleted component and asserting testId it would render, both now dead code"
    missing:
      - "Remove the vi.mock block for ObservatoryWeatherLayer (lines 30-33 weatherMock hoisted declaration, lines 96-101 vi.mock factory, line 330 weatherMock.props.length reset)"
      - "Remove or rewrite the test case 'clamps or suppresses weather based on the runtime profile instead of mounting it blindly' (lines 428-478) — it asserts testIds rendered by the deleted WeatherLayer component that ObservatoryWorldCanvas no longer mounts"
human_verification:
  - test: "Open the observatory tab in flow mode and confirm only the 3D scene canvas and SpaceFlightHud are visible"
    expected: "No Hunt Loop panel, Explainability panel, Mission Overlay, Analyst Preset bar, Ghost Layer, Weather Layer, Cinematic Overlay, Probe HUD, or Replay HUD visible on screen"
    why_human: "Visual UI state cannot be verified programmatically — requires running the app and inspecting the rendered DOM"
---

# Phase 28: Design Tokens + Panel Audit — Verification Report

**Phase Goal:** The observatory has a clean slate and a unified visual language — all legacy overlay clutter is gone, the codebase has no dead panel code, and every future HUD surface has shared CSS tokens to draw from
**Verified:** 2026-03-21
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Opening the observatory in flow mode shows only the 3D scene and flight HUD — no legacy overlay components visible | ? UNCERTAIN | Needs human: all legacy JSX removed from ObservatoryTab.tsx and ObservatoryWorldCanvas.tsx, but visual confirmation required |
| 2 | The 10 removed component files no longer exist anywhere in apps/workbench/src | ✗ FAILED | All 10 .tsx component files are deleted, BUT observatory-world-canvas.performance.test.tsx (line 96) mocks ObservatoryWeatherLayer and asserts its testId at lines 446 and 477 — dead mock code for a deleted component remains in the codebase |
| 3 | The 6 associated test files no longer exist | ✓ VERIFIED | All 6 test files confirmed deleted: observatory-explainability-panel.test.tsx, observatory-replay-hud.test.tsx, observatory-replay-compare-panel.test.tsx, observatory-cinematic-overlay.test.tsx, observatory-mission-hud.test.tsx, observatory-ghost-layer.test.tsx |
| 4 | ObservatoryTab.tsx and ObservatoryWorldCanvas.tsx compile without import errors | ✓ VERIFIED | grep for all 10 deleted component names returns NO_MATCHES in both files; both export their functions correctly (ObservatoryTab line 159, ObservatoryWorldCanvas line 4114) |
| 5 | CSS custom properties --hud-bg, --hud-border, --hud-shadow, --hud-text, --hud-text-muted, --hud-accent, --hud-blur, --hud-radius are defined and resolve to glassmorphism values | ✓ VERIFIED | observatory-hud.css exists with all 8 tokens at exact specified values confirmed by direct file read |
| 6 | The --hud-accent token references --spirit-accent with a fallback of #4af | ✓ VERIFIED | Line 24 of observatory-hud.css: `--hud-accent: var(--spirit-accent, #4af);` — confirmed exact match |

**Score:** 5/6 truths verified (1 failed, 1 needs human)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` | Clean render tree — no legacy panel imports or JSX | ✓ VERIFIED | grep for all 10 deleted component names returns zero matches; export function ObservatoryTab present at line 159 |
| `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` | Clean render tree — no GhostLayer, WeatherLayer, or MissionOverlay | ✓ VERIFIED | grep returns zero matches for ObservatoryMissionOverlay, ObservatoryGhostLayer, ObservatoryWeatherLayer; ObservatoryRuntimeMonitors import preserved (lines 80-82) |
| `apps/workbench/src/features/observatory/observatory-hud.css` | Glassmorphism design tokens for all observatory HUD surfaces | ✓ VERIFIED | 8 CSS custom properties in :root with exact specified values; 32 lines |
| `apps/workbench/src/globals.css` | Import of observatory HUD CSS | ✓ VERIFIED | Line 7: `@import "./features/observatory/observatory-hud.css";` — placed after @custom-variant dark, before Theme Tokens block |
| All 10 deleted component files | Non-existent | ✓ VERIFIED | ObservatoryExplainabilityPanel.tsx, ObservatoryReplayHud.tsx, ObservatoryReplayComparePanel.tsx, ObservatoryAnalystPresetBar.tsx, ObservatoryCinematicOverlay.tsx, ObservatoryProbeHud.tsx, ObservatoryMissionHud.tsx, ObservatoryMissionOverlay.tsx, ObservatoryGhostLayer.tsx, ObservatoryWeatherLayer.tsx — all confirmed deleted |
| All 6 deleted test files | Non-existent | ✓ VERIFIED | All 6 confirmed deleted |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| ObservatoryTab.tsx | None of the 10 deleted components | imports removed | ✓ WIRED | grep pattern `Observatory(ExplainabilityPanel\|ReplayHud\|ReplayComparePanel\|AnalystPresetBar\|CinematicOverlay\|ProbeHud\|MissionHud)` returns NO_MATCHES |
| ObservatoryWorldCanvas.tsx | None of the 3 WorldCanvas-mounted deleted components | imports removed | ✓ WIRED | grep pattern `Observatory(MissionOverlay\|GhostLayer\|WeatherLayer)` returns NO_MATCHES |
| globals.css | observatory-hud.css | @import | ✓ WIRED | `@import "./features/observatory/observatory-hud.css";` on line 7, confirmed |
| observatory-world-canvas.performance.test.tsx | ObservatoryWeatherLayer (deleted) | vi.mock | ✗ BROKEN | Lines 96-101 mock a deleted component; lines 446, 477 assert testIds that will never be rendered — dead test code |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| CLN-01 | 28-01-PLAN.md | All existing observatory panel/overlay components removed from render tree | ✓ SATISFIED | All 10 legacy imports and JSX blocks removed from ObservatoryTab.tsx and ObservatoryWorldCanvas.tsx; grep confirms zero matches |
| CLN-03 | 28-01-PLAN.md | Removed panel components deleted from the codebase — dead code eliminated | ✗ BLOCKED | All 10 component files are deleted, but dead code remains in observatory-world-canvas.performance.test.tsx (vi.mock of deleted ObservatoryWeatherLayer + 2 failing assertions); CLN-03 requires dead code eliminated, not just component files deleted |
| VIS-01 | 28-02-PLAN.md | Glassmorphism design tokens defined as CSS custom properties so all HUD surfaces share the same visual language | ✓ SATISFIED | observatory-hud.css defines all 8 tokens at exact values; globals.css imports the file |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `apps/workbench/src/features/observatory/__tests__/observatory-world-canvas.performance.test.tsx` | 30, 96-101 | vi.mock of deleted module `ObservatoryWeatherLayer` + weatherMock hoisted declaration | Blocker | The vi.mock factory provides a component that ObservatoryWorldCanvas no longer imports — the testId `observatory-weather-layer` will never appear in the DOM |
| `apps/workbench/src/features/observatory/__tests__/observatory-world-canvas.performance.test.tsx` | 446-447, 477 | Assertions against testId `observatory-weather-layer` that can never be rendered | Blocker | `findByTestId("observatory-weather-layer")` will throw (element not found); `getAllByTestId("observatory-weather-layer")` will return empty — both assertions fail |

### Human Verification Required

#### 1. Observatory flow mode visual state

**Test:** Open the workbench, navigate to the observatory tab, switch to flow mode
**Expected:** Only the 3D canvas (scene) and SpaceFlightHud (speed bar, compass, target brackets, off-screen arrows) are visible — no Hunt Loop panel, Explainability panel, Mission Overlay, Analyst Preset bar, Ghost Layer, Weather Layer, Cinematic Overlay, Probe HUD, or Replay HUD on screen
**Why human:** Visual UI rendering cannot be verified by grep — requires a running browser instance

### Gaps Summary

The primary gap is in `observatory-world-canvas.performance.test.tsx`. This test file was created in Phase 20 and was not listed in the Phase 28 delete targets. It contains:

1. A `vi.mock` of `@/features/observatory/components/ObservatoryWeatherLayer` (lines 96-101) which provides a fake component returning `<div data-testid="observatory-weather-layer" />`
2. Test assertions at lines 446 and 477 that wait for/assert this testId to be present in the DOM

Since `ObservatoryWorldCanvas.tsx` no longer imports or renders `ObservatoryWeatherLayer`, these assertions will fail at test runtime — the mocked component is never mounted. This constitutes dead test code that directly contradicts CLN-03 ("dead code eliminated").

The fix is targeted: remove the weatherMock hoisted declaration, the vi.mock block for ObservatoryWeatherLayer, the weatherMock.props reset in beforeEach, and rewrite or remove the test case "clamps or suppresses weather based on the runtime profile instead of mounting it blindly" (lines 428-478) since it tests behavior implemented through a now-deleted component.

All other phase deliverables are fully verified — the 10 component files are deleted, the 6 test files are deleted, both mount-point files are clean, observatory-hud.css has all 8 tokens at exact values, and globals.css imports it correctly.

---

_Verified: 2026-03-21_
_Verifier: Claude (gsd-verifier)_
