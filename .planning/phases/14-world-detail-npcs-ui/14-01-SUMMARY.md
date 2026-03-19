---
phase: 14-world-detail-npcs-ui
plan: "01"
subsystem: ui
tags: [react-three-fiber, drei, three.js, procedural, skybox, hdr, environment]

# Dependency graph
requires:
  - phase: 12-particle-effects
    provides: VFX pools and emissive materials already in scene; bloom pipeline active
  - phase: 10-post-processing-foundation
    provides: EffectComposer HDR pipeline; emissiveIntensity > 1 + toneMapped=false bloom targets
provides:
  - mulberry32 seeded RNG for deterministic procedural geometry
  - StationBuilding component — 4-6 seeded RoundedBox buildings per station
  - DistrictGround component — per-zone tinted ground plane with grid texture
  - DistrictEnvProps component — 2 crates + CatmullRomLine cable run per station
  - HDR Environment skybox replacing flat star field (WLD-01)
  - 512x512 dark grid-floor.png texture in public/textures/
affects:
  - 14-world-detail-npcs-ui (subsequent plans build on world detail)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - mulberry32 inline seeded RNG (no npm dep) for deterministic procedural geometry
    - Suspense-wrapped Environment with dark color fallback for HDR load states
    - district.position-derived seeds for per-station uniqueness without explicit IDs

key-files:
  created:
    - apps/workbench/src/features/observatory/world/districtGeometry.tsx
    - apps/workbench/public/textures/grid-floor.png
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx

key-decisions:
  - "Used ReactElement return type instead of JSX.Element (no JSX namespace in this tsconfig)"
  - "Renamed districtGeometry.ts -> .tsx: file contains JSX, .ts extension causes TS1005 parse errors"
  - "Environment wrapped in Suspense + dark #04080f color fallback so scene renders while HDR loads"
  - "District geometry uses group position={district.position} so all child components use local [0,0,0]"
  - "HDR file (space-nebula.hdr) not bundled — user must download CC0 from polyhaven.com at 1K"

patterns-established:
  - "mulberry32(seed): () => number — inline seeded RNG for any deterministic procedural content"
  - "Suspense fallback={null} wraps texture-loading components (DistrictGround) to avoid blocking"
  - "Antenna emissiveIntensity=0.5 + toneMapped=false for bloom pickup without explicit bloom config"

requirements-completed: [WLD-01, WLD-02, WLD-03, WLD-04]

# Metrics
duration: 5min
completed: 2026-03-19
---

# Phase 14 Plan 01: World Detail — HDR Skybox + District Geometry Summary

**HDR Environment skybox (dark fallback + space-nebula.hdr), mulberry32-seeded district buildings, per-zone tinted ground planes, and crate+cable env props mounted per station in R3F**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-19T19:15:29Z
- **Completed:** 2026-03-19T19:20:25Z
- **Tasks:** 2 of 2 auto tasks complete (1 checkpoint pending human verify)
- **Files modified:** 3

## Accomplishments

- Created `districtGeometry.tsx` — pure geometry module with 4 exported symbols: `mulberry32`, `StationBuilding`, `DistrictGround`, `DistrictEnvProps`
- Replaced `<Stars>` with `<Environment files="/textures/space-nebula.hdr" background>` wrapped in Suspense + dark `#04080f` color fallback (WLD-01)
- Mounted district geometry per station: 4-6 seeded buildings + tinted ground plane + 2 crates + cable run (WLD-02/03/04)
- Generated 512x512 dark grid-floor.png via ImageMagick for ground texture

## Task Commits

Each task was committed atomically:

1. **Task 1: Create districtGeometry.tsx** - `df59072bc` (feat)
2. **Task 2: Replace Stars + mount district geometry** - `237b0b7d1` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/world/districtGeometry.tsx` — mulberry32 RNG, StationBuilding, DistrictGround, DistrictEnvProps components
- `apps/workbench/public/textures/grid-floor.png` — 512x512 dark tech grid texture (generated)
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Stars removed, Environment added, district geometry mounted

## Decisions Made

- `ReactElement` return type used instead of `JSX.Element` — no JSX namespace in this tsconfig (isolatedModules + react-jsx)
- File renamed from `.ts` to `.tsx` — JSX in `.ts` files causes TS1005 parse errors
- `Suspense fallback={null}` wraps `DistrictGroundInner` — prevents scene block when grid-floor.png is missing
- Dark `#04080f` color before Environment — ensures scene renders during HDR load (no blank canvas)
- HDR file not bundled — space-nebula.hdr must be downloaded from polyhaven.com (CC0, 1K resolution)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] File extension .ts -> .tsx for JSX content**
- **Found during:** Task 1 (Create districtGeometry.ts)
- **Issue:** Plan specified `.ts` extension, but file contains JSX; TypeScript emits TS1005 errors ("'>' expected") in `.ts` files
- **Fix:** Renamed to `.districtGeometry.tsx` immediately after TypeScript check caught errors
- **Files modified:** apps/workbench/src/features/observatory/world/districtGeometry.tsx
- **Verification:** `npx tsc --noEmit` reports zero errors from districtGeometry.tsx
- **Committed in:** df59072bc (Task 1 commit)

**2. [Rule 1 - Bug] JSX.Element -> ReactElement return type**
- **Found during:** Task 1 (type annotation)
- **Issue:** `JSX.Element` requires the JSX namespace which is not available in this project's tsconfig (no `@types/react` global JSX namespace, `isolatedModules: true`)
- **Fix:** Import and use `ReactElement` from `react` package instead
- **Files modified:** apps/workbench/src/features/observatory/world/districtGeometry.tsx
- **Verification:** TypeScript compiles cleanly
- **Committed in:** df59072bc (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 - bug fixes for file type + return type)
**Impact on plan:** Both fixes necessary for TypeScript correctness. No scope creep.

## Issues Encountered

- `canvas` npm module not available for PNG generation; used system ImageMagick (`magick convert`) to generate 512x512 grid-floor.png — 4162 bytes, dark grid on `#06111d` background with `#0e2540` grid lines.

## User Setup Required

**HDR file must be sourced manually.** Without it, the scene shows the `#04080f` dark blue fallback color. The Environment component fails gracefully (Suspense).

Steps:
1. Visit [polyhaven.com/hdris](https://polyhaven.com/hdris) — filter by "night" or "space" category
2. Download any space/nebula HDR at 1K resolution (.hdr format)
3. Save as `apps/workbench/public/textures/space-nebula.hdr`
4. Restart/reload dev server — the skybox will appear immediately

## Next Phase Readiness

- WLD-01 through WLD-04 complete — world detail geometry foundations in place
- Human verification checkpoint pending — user needs to view Observatory tab and confirm visual correctness
- Remaining plans in phase 14: NPC crews (14-02), UI polish (14-03)

---
*Phase: 14-world-detail-npcs-ui*
*Completed: 2026-03-19*
