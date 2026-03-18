---
phase: 02-r3f-infrastructure-small-embeds
plan: "01"
subsystem: ui
tags: [r3f, three, react-three-fiber, react-three-drei, spirit, tdd, vitest]

# Dependency graph
requires:
  - phase: 01-spirit-observatory-state-foundation
    provides: "spirit-store.ts, types.ts (SpiritKind), useSpiritStore, useRightSidebarStore"
provides:
  - "three@^0.170.0, @react-three/fiber@^9.0.0, @react-three/drei@^10.7.7 installed"
  - "SpiritKind = sentinel | oracle | witness | specter (huntronomer names)"
  - "SPIRIT_ACCENT_MAP with huntronomer hex colors"
  - "5 Wave 0 failing test scaffolds defining Phase 2 component contracts"
affects:
  - 02-02-spirit-orb-icon-activity-bar-integration
  - 02-03-spirit-companion-canvas
  - 02-04-spirit-chamber-tab

# Tech tracking
tech-stack:
  added:
    - "three@^0.170.0 — Three.js 3D library"
    - "@react-three/fiber@^9.0.0 — React renderer for Three.js"
    - "@react-three/drei@^10.7.7 — R3F helpers/abstractions"
    - "@types/three@^0.183.1 — TypeScript types for Three.js"
  patterns:
    - "Wave 0 TDD: create failing tests defining component contracts before implementation"
    - "vi.mock('@react-three/fiber') pattern for jsdom-safe R3F canvas tests"
    - "@ts-expect-error for intentional type violations in Wave 0 scaffolds"

key-files:
  created:
    - "apps/workbench/src/features/spirit/__tests__/spirit-orb-icon.test.tsx"
    - "apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx"
    - "apps/workbench/src/features/spirit/__tests__/spirit-chamber-tab.test.tsx"
    - "apps/workbench/src/features/activity-bar/__tests__/activity-bar-item.test.tsx"
    - "apps/workbench/src/features/right-sidebar/__tests__/right-sidebar-store.test.ts"
  modified:
    - "apps/workbench/package.json — added three/r3f/drei/types-three deps"
    - "apps/workbench/src/features/spirit/types.ts — SpiritKind enum replaced"
    - "apps/workbench/src/features/spirit/stores/spirit-store.ts — SPIRIT_ACCENT_MAP replaced"
    - "bun.lockb — updated lockfile"

key-decisions:
  - "Pinned @react-three/fiber@^9.0.0 (not ^9.5.0) per huntronomer compatibility requirement with React 19.2.4"
  - "Pinned three@^0.170.0 (resolves to 0.170.0) to match huntronomer target; 0.183.2 available but not required"
  - "Used @ts-expect-error in right-sidebar-store Wave 0 test to allow runtime verification of store behavior before type extension"
  - "Wave 0 test scaffolds intentionally produce TypeScript module-not-found errors for spirit-orb-icon/spirit-companion-canvas/spirit-chamber-tab — this is correct RED state"
  - "bun add --ignore-scripts used because @clawdstrike/sdk workspace build fails (pre-existing unrelated issue with @clawdstrike/adapter-core)"

patterns-established:
  - "Wave 0 test pattern: import non-existent components to define contracts before implementation"
  - "vi.mock for WebGL/R3F: mock @react-three/fiber Canvas as plain div for jsdom tests"

requirements-completed: [SPRT-03, SPRT-04, SPRT-05]

# Metrics
duration: 4min
completed: 2026-03-18
---

# Phase 2 Plan 01: R3F Infrastructure + SpiritKind Migration Summary

**R3F packages installed (three/fiber/drei), SpiritKind migrated to sentinel/oracle/witness/specter with huntronomer hex colors, and 5 Wave 0 failing test scaffolds defining all Phase 2 component contracts**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-18T22:20:17Z
- **Completed:** 2026-03-18T22:24:53Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Installed three@^0.170.0, @react-three/fiber@^9.0.0, @react-three/drei@^10.7.7, @types/three@^0.183.1 — R3F is ready for use in Wave 2 components
- Replaced placeholder SpiritKind (ember/tide/verdant/void/neutral) with huntronomer names (sentinel/oracle/witness/specter) and updated SPIRIT_ACCENT_MAP with matching hex colors
- Created 5 Wave 0 test scaffolds that fail for all the right reasons — each failure pinpoints exactly what Wave 2 plans must implement

## Task Commits

Each task was committed atomically:

1. **Task 1: Install R3F packages + migrate SpiritKind** - `650b4fa09` (feat)
2. **Task 2: Create Wave 0 test scaffolds** - `cddfb99d2` (test)

## Files Created/Modified
- `apps/workbench/package.json` — added three/r3f/drei runtime deps, @types/three dev dep
- `apps/workbench/src/features/spirit/types.ts` — SpiritKind replaced: ember/tide/verdant/void/neutral → sentinel/oracle/witness/specter
- `apps/workbench/src/features/spirit/stores/spirit-store.ts` — SPIRIT_ACCENT_MAP: sentinel=#3dbf84, oracle=#7b68ee, witness=#d4a84b, specter=#c45c5c
- `bun.lockb` — updated lockfile
- `apps/workbench/src/features/spirit/__tests__/spirit-orb-icon.test.tsx` — 4 tests: accentColor gradient, aria-hidden, size default/custom
- `apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx` — 3 tests: null-guard, 150x150 wrapper, R3F Canvas render (R3F mocked)
- `apps/workbench/src/features/spirit/__tests__/spirit-chamber-tab.test.tsx` — 5 tests: 4-option selector, bind/unbind, kind display, no-spirit placeholder
- `apps/workbench/src/features/activity-bar/__tests__/activity-bar-item.test.tsx` — 2 tests: orbColor prop renders SpiritOrbIcon vs icon
- `apps/workbench/src/features/right-sidebar/__tests__/right-sidebar-store.test.ts` — 2 tests: "spirit" panel value, panel switching

## Decisions Made
- Pinned `@react-three/fiber@^9.0.0` (not `^9.5.0`) per huntronomer compatibility target; bun resolves to 9.5.0 at install time but the semver range is correctly pinned
- Pinned `three@^0.170.0` to match huntronomer target; bun resolves to 0.170.0
- Used `bun add --ignore-scripts` due to pre-existing `@clawdstrike/sdk` build failure (unrelated to this plan)
- Added `@ts-expect-error` in right-sidebar-store Wave 0 test so runtime can verify Zustand accepts "spirit" as panel value before the TypeScript type is extended

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added @ts-expect-error in right-sidebar-store test**
- **Found during:** Task 2 (Wave 0 test scaffold creation)
- **Issue:** `setActivePanel("spirit")` is a TypeScript error until RightSidebarPanel type includes "spirit". Without @ts-expect-error, the test file fails typecheck AND vitest fails to run it, preventing the runtime behavior from being tested.
- **Fix:** Added `@ts-expect-error` comments on both "spirit" calls so vitest can run the test and verify store runtime behavior is correct
- **Files modified:** right-sidebar-store.test.ts
- **Verification:** Test passes (store accepts any string at runtime); TypeScript suppressed via directive
- **Committed in:** cddfb99d2 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical correctness)
**Impact on plan:** Necessary for test scaffolds to correctly validate store runtime behavior. No scope creep.

## Issues Encountered
- `bun add` without `--ignore-scripts` failed because `@clawdstrike/sdk` workspace package has a build script that errors on `@clawdstrike/adapter-core` missing. Used `--ignore-scripts` flag — this is a pre-existing workspace configuration issue unrelated to this plan. Logged in deferred-items.

## Next Phase Readiness
- R3F dependency foundation complete — all Wave 2 component work can begin
- SpiritKind type is authoritative source of truth; any stale references to old names will fail TypeScript compilation
- 5 test scaffolds define precise contracts for Wave 2 plans 02-02, 02-03, 02-04
- Pre-existing TypeScript errors in `sidebar-icons.tsx` and `tauri-bridge.ts` are out of scope (pre-existing before this plan)

---
*Phase: 02-r3f-infrastructure-small-embeds*
*Completed: 2026-03-18*
