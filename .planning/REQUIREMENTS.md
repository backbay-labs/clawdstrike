# Requirements: ClawdStrike Workbench v4.0 — AAA Observatory Experience

**Defined:** 2026-03-19
**Core Value:** Transform the observatory from functional demo to AAA-quality immersive experience with post-processing, particles, cinematic camera, polished character, world detail, and production UI

## v4.0 Requirements

### Post-Processing

- [x] **PP-01**: Observatory scene renders with bloom on all emissive elements (spirit shells, station halos, probe beams)
- [x] **PP-02**: Vignette + SMAA + tone mapping applied as always-on baseline effects
- [x] **PP-03**: Subtle depth-of-field activates when interacting with hero props (Autofocus targeting world position)
- [ ] **PP-04**: Per-spirit-kind color grading via runtime-swappable LUT

### Particles

- [ ] **PFX-01**: Landing dust cloud bursts from ground on character touchdown
- [ ] **PFX-02**: Probe energy discharge — expanding particle shell on probe dispatch
- [ ] **PFX-03**: Station ambient motes — floating particles around hero props
- [ ] **PFX-04**: Spirit companion trail — accent-colored particle trail following the orb
- [ ] **PFX-05**: Thruster exhaust on player avatar backpack during sprint and jump

### Camera

- [ ] **CAM-01**: Spawn fly-by — automated camera sweep with letterbox bars on first observatory open
- [ ] **CAM-02**: Dynamic FOV — widens during sprint (42→52), tightens during probe scan (42→35)
- [ ] **CAM-03**: Screen shake on probe dispatch and character landing
- [ ] **CAM-04**: Focus pull to mission objective station when starting a mission

### Character

- [ ] **CHR-01**: Weight-based locomotion blending — idle/walk/run clips with velocity-driven weights
- [ ] **CHR-02**: Landing squash-stretch — scale Y compression with easeOutBack overshoot
- [ ] **CHR-03**: Idle breathing — subtle torso Y oscillation layered on AnimationMixer
- [ ] **CHR-04**: Sprint lean — body tilts forward proportional to velocity
- [ ] **CHR-05**: Flip easing — two-phase easeInCubic + easeOutBack for settle
- [ ] **CHR-06**: Footstep events — cycle-zero-crossing detection for particle/SFX sync

### World Detail

- [ ] **WLD-01**: HDR skybox via drei Environment replacing flat Stars
- [ ] **WLD-02**: Procedural district geometry — buildings/structures per station zone
- [ ] **WLD-03**: Ground surface variety — tinted materials per district zone
- [ ] **WLD-04**: Environmental storytelling props near stations

### NPCs

- [ ] **NPC-01**: Instanced mesh crew members at stations (4 per station, 24 total)
- [ ] **NPC-02**: Simple patrol paths — waypoint-based lerp within station zones
- [ ] **NPC-03**: Player proximity reaction — look-at + wave gesture

### UI Polish

- [ ] **UIP-01**: 3D waypoint beacons to mission objectives
- [ ] **UIP-02**: Circular probe charge ring replacing text HUD
- [ ] **UIP-03**: Tooltip system for interactable props
- [ ] **UIP-04**: Achievement popups for mission completion

## Out of Scope

| Feature | Reason |
|---------|--------|
| Motion blur | Conflicts with frameloop="demand" |
| Audio/SFX | Separate milestone — needs Web Audio API integration |
| Combat/damage | Observatory is exploration, not combat |
| Ragdoll physics | Squash-stretch is sufficient for landing feel |
| Custom GLSL shaders | Stock materials + postprocessing sufficient |
| Real-time multiplayer | Requires NATS server — deferred to v5.0 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| PP-01 | Phase 10 | Complete |
| PP-02 | Phase 10 | Complete |
| PP-03 | Phase 10 | Complete |
| PP-04 | Phase 10 | Pending |
| CAM-01 | Phase 11 | Pending |
| CAM-02 | Phase 11 | Pending |
| CAM-03 | Phase 11 | Pending |
| CAM-04 | Phase 11 | Pending |
| PFX-01 | Phase 12 | Pending |
| PFX-02 | Phase 12 | Pending |
| PFX-03 | Phase 12 | Pending |
| PFX-04 | Phase 12 | Pending |
| PFX-05 | Phase 12 | Pending |
| CHR-01 | Phase 13 | Pending |
| CHR-02 | Phase 13 | Pending |
| CHR-03 | Phase 13 | Pending |
| CHR-04 | Phase 13 | Pending |
| CHR-05 | Phase 13 | Pending |
| CHR-06 | Phase 13 | Pending |
| WLD-01 | Phase 14 | Pending |
| WLD-02 | Phase 14 | Pending |
| WLD-03 | Phase 14 | Pending |
| WLD-04 | Phase 14 | Pending |
| NPC-01 | Phase 14 | Pending |
| NPC-02 | Phase 14 | Pending |
| NPC-03 | Phase 14 | Pending |
| UIP-01 | Phase 14 | Pending |
| UIP-02 | Phase 14 | Pending |
| UIP-03 | Phase 14 | Pending |
| UIP-04 | Phase 14 | Pending |

**Coverage:**
- v4.0 requirements: 30 total
- Mapped to phases: 30
- Unmapped: 0

---
*Requirements defined: 2026-03-19*
*Traceability updated: 2026-03-19*
