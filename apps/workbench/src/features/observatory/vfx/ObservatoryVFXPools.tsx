import { VFXParticles, RenderMode } from "wawa-vfx";

/**
 * ObservatoryVFXPools
 *
 * Declares all wawa-vfx particle pools used in the observatory scene.
 * Must be mounted inside the observatory Canvas before any VFXEmitter fires.
 * Plan 04 mounts this inside ObservatoryWorldCanvas > Suspense.
 *
 * Pools:
 *   "landing-dust"        — burst on character touchdown (PFX-01)
 *   "thruster-exhaust"    — continuous during sprint/jump (PFX-05)
 *   "ship-thruster-exhaust" — continuous during ship flight (FLT-06)
 *   "lane-particle-stream"  — ambient lane flow particles (SPC-06)
 *   "warp-speed-lines"    — boost speed line streaks (TRN-02)
 *
 * Budget: 1580 particle pool total, 5 draw calls.
 *
 * Note: VFXParticlesSettings provides pool-level settings only (nbParticles,
 * renderMode, gravity, fadeAlpha). Per-particle ranges (lifetime, size, color)
 * are set on the VFXEmitter's settings at emit time.
 */
export function ObservatoryVFXPools() {
  return (
    <>
      {/* PFX-01: Landing dust — billboard quads, downward gravity, warm sand tones */}
      <VFXParticles
        name="landing-dust"
        settings={{
          nbParticles: 200,
          renderMode: RenderMode.Billboard,
          gravity: [0, -4, 0],
          fadeAlpha: [0.0, 0.1],
        }}
      />
      {/* PFX-05: Thruster exhaust — stretchBillboard along velocity, slight upward drift */}
      <VFXParticles
        name="thruster-exhaust"
        settings={{
          nbParticles: 300,
          renderMode: RenderMode.StretchBillboard,
          gravity: [0, 1.5, 0],
          fadeAlpha: [0.0, 0.15],
        }}
      />
      {/* FLT-06: Ship thruster exhaust — stretchBillboard along velocity, slight backward drift */}
      <VFXParticles
        name="ship-thruster-exhaust"
        settings={{
          nbParticles: 400,
          renderMode: RenderMode.StretchBillboard,
          gravity: [0, 0.5, 0],
          fadeAlpha: [0.0, 0.12],
        }}
      />
      {/* SPC-06: Lane particle streams — stretchBillboard along lane curves */}
      <VFXParticles
        name="lane-particle-stream"
        settings={{
          nbParticles: 600,
          renderMode: RenderMode.StretchBillboard,
          gravity: [0, 0, 0],
          fadeAlpha: [0.0, 0.15],
        }}
      />
      {/* TRN-02: Warp speed lines — boost speed streaks from camera (80 = 40 active + 40 buffer) */}
      <VFXParticles
        name="warp-speed-lines"
        settings={{
          nbParticles: 80,
          renderMode: RenderMode.StretchBillboard,
          gravity: [0, 0, 0],
          fadeAlpha: [0.0, 0.15],
        }}
      />
    </>
  );
}
