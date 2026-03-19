import { VFXParticles, RenderMode } from "wawa-vfx";

/**
 * ObservatoryVFXPools
 *
 * Declares all wawa-vfx particle pools used in the observatory scene.
 * Must be mounted inside the observatory Canvas before any VFXEmitter fires.
 * Plan 04 mounts this inside ObservatoryWorldCanvas > Suspense.
 *
 * Pools:
 *   "landing-dust"     — burst on character touchdown (PFX-01)
 *   "thruster-exhaust" — continuous during sprint/jump (PFX-05)
 *
 * Budget: 500 particle pool total, 2 draw calls.
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
    </>
  );
}
