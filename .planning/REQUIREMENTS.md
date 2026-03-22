# Requirements: ClawdStrike Workbench v9.0 Observatory 3D World Polish

**Defined:** 2026-03-22
**Core Value:** The observatory world is visually alive — past findings leave traces, missions mark targets, analyst lenses transform the scene, and weather responds to hunt pressure

## Constraints

- **Existing data:** Ghost traces, weather state, mission objectives, and analyst presets already have data pipelines (stores, derivation functions, types). This milestone wires them to 3D rendering.
- **Performance:** New 3D objects must respect the LOD/culling/performance-profile system. Use instanced meshes where possible.
- **Visual consistency:** All new 3D elements use the glassmorphism accent system (spirit colors, --hud-accent) and bloom-compatible materials (toneMapped: false, emissive).

## v9.0 Requirements

### Ghost Trace Markers

- [x] **GHO-01**: Stations with prior findings display translucent holographic marker meshes at the station position — markers are visually distinct from station geometry (spectral glow, not solid)
- [x] **GHO-02**: Ghost markers show the finding type (receipt verdict, probe result, case-note) as a small icon or glyph visible at mid-range (60-180 units)
- [x] **GHO-03**: Ghost markers fade in/out based on the GHOST analyst preset — fully visible when GHOST preset is active, dimmed to 20% opacity when inactive
- [x] **GHO-04**: Ghost markers source their data from `deriveObservatoryGhostMemories()` — no new data fetching, just rendering the existing derived traces

### Mission Objective Beacons

- [x] **MSN-01**: Active mission objective stations display a vertical beacon column (emissive cylinder or line) extending upward from the station — visible from 500+ units through fog
- [x] **MSN-02**: Beacon pulses with a slow breathing animation (opacity oscillation ~2s cycle) when the station is the current objective; dims to static glow for completed objectives
- [x] **MSN-03**: Beacon color matches the station's accent color; completed objective beacons shift to a muted desaturated version
- [x] **MSN-04**: No beacon renders when no mission is active — clean world with no leftover markers

### Analyst Preset Overlays

- [x] **APR-01**: Activating THREAT preset tints active-pressure districts with a red emissive wash and spawns subtle danger particle motes around high-pressure stations
- [x] **APR-02**: Activating EVIDENCE preset highlights stations with receipt data using gold emissive halos (reusing the affinity ring pattern from v3.0)
- [x] **APR-03**: Activating RECEIPTS preset renders small verdict badge markers (ALLOW/DENY/AUDIT icons) floating near stations that have receipt history
- [ ] **APR-04**: Activating GHOST preset dims the world ambient light by 40%, desaturates non-ghost geometry, and reveals ghost trace markers at full opacity (cross-references GHO-03)
- [ ] **APR-05**: Deactivating any preset returns the world to its neutral visual state within one frame — no lingering tint or particles

### Weather Layer

- [x] **WTH-01**: Observatory weather layer renders in the 3D scene — fog density, particle effects, and ambient lighting respond to the `weatherState` from observatory-store
- [x] **WTH-02**: Weather intensity scales with hunt telemetry pressure — calm hunts show clear skies, high-pressure hunts show denser fog and more active particles
- [x] **WTH-03**: Weather effects respect the performance profile — reduced/disabled weather on low-quality settings

## v10.0 Requirements (Deferred)

### Audio
- **AUD-01**: Spatial audio for weather effects (wind, rain particles)
- **AUD-02**: Thruster engine audio with intensity-based pitch

### Multiplayer
- **MP-01**: Other analyst ships visible via NATS presence
- **MP-02**: Shared mission markers

## Out of Scope

| Feature | Reason |
|---------|--------|
| Real-time hunt data integration | This milestone renders existing store data — live telemetry wiring is separate |
| Explainability data pipeline | The hunt → explanation → causes pipeline is a data problem, not a 3D problem |
| Command palette registration | Orthogonal to 3D world rendering — separate milestone |
| Station interior rendering | Outside space stations only |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GHO-01 | Phase 35 | Complete |
| GHO-02 | Phase 35 | Complete |
| GHO-03 | Phase 35 | Complete |
| GHO-04 | Phase 35 | Complete |
| MSN-01 | Phase 36 | Complete |
| MSN-02 | Phase 36 | Complete |
| MSN-03 | Phase 36 | Complete |
| MSN-04 | Phase 36 | Complete |
| APR-01 | Phase 37 | Complete |
| APR-02 | Phase 37 | Complete |
| APR-03 | Phase 37 | Complete |
| APR-04 | Phase 37 | Pending |
| APR-05 | Phase 37 | Pending |
| WTH-01 | Phase 38 | Complete |
| WTH-02 | Phase 38 | Complete |
| WTH-03 | Phase 38 | Complete |

**Coverage:**
- v9.0 requirements: 16 total
- Mapped to phases: 16
- Unmapped: 0

---
*Requirements defined: 2026-03-22*
*Last updated: 2026-03-22 after milestone v9.0 definition*
