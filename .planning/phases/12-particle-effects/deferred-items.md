# Deferred Items — Phase 12 Particle Effects

## Out-of-Scope Pre-existing Issues

### sidebar-icons.tsx duplicate prop warnings
- **File:** `apps/workbench/src/components/desktop/sidebar-icons.tsx`
- **Lines:** 233-237
- **Errors:** TS2783 — `viewBox`, `fill`, `stroke`, `strokeLinecap`, `strokeLinejoin` specified more than once
- **Last touched:** Phase 05-03 (feat: wire Observatory into activity bar)
- **Reason deferred:** Pre-existing before Phase 12; not caused by current changes
- **Fix:** Deduplicate spread props in SVG component definitions
