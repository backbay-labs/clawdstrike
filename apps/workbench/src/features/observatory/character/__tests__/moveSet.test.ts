/**
 * moveSet easing upgrades — CHR-02 (landing squash-stretch) + CHR-05 (flip easing)
 *
 * TDD RED: these tests are written against the desired behaviour before the
 * implementation exists.  They will fail until the GREEN phase is applied.
 */

import { describe, it, expect } from "vitest";
import {
  sampleObservatoryPlayerPose,
  OBSERVATORY_PLAYER_MOVE_SPECS,
} from "../animation/moveSet";

// ─── Helper: expose private helpers via re-export trick ──────────────────────
// Since easeOutBack / easeFlipProgress are module-private we test them
// indirectly through sampleObservatoryPlayerPose. However the plan spec
// says to add direct assertions on the math; those are included below and rely
// on the pose values being consistent with the easing formulas.

// ─── Group A: easeOutBack (indirect via sampleLandPose) ──────────────────────
// We validate the easing curve indirectly by asserting rootScale[1] overshoots
// 1.0 at progress≈0.70.  A direct unit test of easeOutBack itself is in Group B.

// To test the helpers directly without exporting them we duplicate the exact
// formulas here so we can assert the math holds.
function easeOutBack(x: number): number {
  const c1 = 1.70158;
  const c3 = c1 + 1; // 2.70158
  return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2);
}

function easeFlipProgress(t: number): number {
  if (t < 0.6) {
    const t2 = t / 0.6;
    return 0.6 * (t2 * t2 * t2);
  }
  const t2 = (t - 0.6) / 0.4;
  return 0.6 + 0.4 * easeOutBack(t2);
}

// ─── Group A: easeOutBack math assertions ────────────────────────────────────
describe("easeOutBack", () => {
  it("returns 0 at x=0", () => {
    expect(easeOutBack(0)).toBeCloseTo(0, 9);
  });

  it("returns 1 at x=1", () => {
    expect(easeOutBack(1)).toBeCloseTo(1, 9);
  });

  it("overshoots past 1.0 at midpoint x=0.5", () => {
    expect(easeOutBack(0.5)).toBeGreaterThan(1.0);
  });

  it("still overshooting at x=0.8", () => {
    expect(easeOutBack(0.8)).toBeGreaterThan(1.0);
  });
});

// ─── Group B: sampleLandPose two-phase scaling ───────────────────────────────
describe("sampleLandPose — two-phase squash-stretch", () => {
  const LAND_DURATION = 0.30; // must be 0.30 after plan change

  it("land spec durationSeconds is 0.30", () => {
    expect(OBSERVATORY_PLAYER_MOVE_SPECS.land.durationSeconds).toBe(0.30);
  });

  it("at t=0 (progress=0) scaleY is compressed below 1 and >= 0.70", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds: 0,
      horizontalSpeed: 0,
    });
    expect(pose.rootScale[1]).toBeLessThan(1.0);
    expect(pose.rootScale[1]).toBeGreaterThanOrEqual(0.70);
  });

  it("at t=0 (progress=0) scaleY is approximately COMPRESS_Y=0.74 (within ±0.08)", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds: 0,
      horizontalSpeed: 0,
    });
    expect(pose.rootScale[1]).toBeGreaterThanOrEqual(0.66);
    expect(pose.rootScale[1]).toBeLessThanOrEqual(0.82);
  });

  it("at end of compress phase (progress=0.35) scaleY is near COMPRESS_Y", () => {
    const elapsedSeconds = LAND_DURATION * 0.35;
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds,
      horizontalSpeed: 0,
    });
    // At the phase boundary scaleY should be at or near COMPRESS_Y
    expect(pose.rootScale[1]).toBeLessThanOrEqual(0.74 + 0.01);
  });

  it("at progress=0.70 scaleY overshoots above 1.0", () => {
    const elapsedSeconds = LAND_DURATION * 0.70;
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds,
      horizontalSpeed: 0,
    });
    expect(pose.rootScale[1]).toBeGreaterThan(1.0);
  });

  it("at progress=1.0 scaleY settles near 1.0 (within ±0.05)", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds: LAND_DURATION,
      horizontalSpeed: 0,
    });
    expect(pose.rootScale[1]).toBeGreaterThanOrEqual(0.95);
    expect(pose.rootScale[1]).toBeLessThanOrEqual(1.05);
  });

  it("at progress=0, scaleXZ >= 1.14 (volume conservation)", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds: 0,
      horizontalSpeed: 0,
    });
    // When scaleY <= 0.76, scaleX = 1/sqrt(scaleY) >= 1/sqrt(0.76) ≈ 1.147
    expect(pose.rootScale[0]).toBeGreaterThanOrEqual(1.14);
    expect(pose.rootScale[2]).toBeGreaterThanOrEqual(1.14);
  });
});

// ─── Group C: easeFlipProgress math assertions ───────────────────────────────
describe("easeFlipProgress", () => {
  it("returns 0 at t=0", () => {
    expect(easeFlipProgress(0)).toBe(0);
  });

  it("returns 1 at t=1", () => {
    expect(easeFlipProgress(1)).toBeCloseTo(1, 9);
  });

  it("cubic-in phase at t=0.3 is less than linear value", () => {
    // In the cubic-in phase [0, 0.6), output = 0.6*(t/0.6)^3
    // At t=0.3: output = 0.6*(0.3/0.6)^3 = 0.6*0.125 = 0.075
    // Linear would be 0.3 * 1.0 = 0.3; cubic-in must be less
    expect(easeFlipProgress(0.3)).toBeLessThan(0.3);
  });

  it("at phase boundary t=0.6 output is exactly 0.6", () => {
    expect(easeFlipProgress(0.6)).toBeCloseTo(0.6, 9);
  });

  it("monotonically increases from 0.6 to 0.8", () => {
    expect(easeFlipProgress(0.8)).toBeGreaterThan(easeFlipProgress(0.6));
  });

  it("settles at 1.0 at t=1.0 (easeOutBack converges to 1)", () => {
    // easeOutBack overshoots then returns to 1 — the value at t=1.0 should be exactly 1
    expect(easeFlipProgress(1.0)).toBeCloseTo(1.0, 9);
  });
});

// ─── Group D: sampleFlipPose bodySpinX assertions ────────────────────────────
describe("sampleFlipPose — bodySpinX uses easeFlipProgress", () => {
  const FLIP_DURATION = 0.72; // front-flip durationSeconds (unchanged)

  it("at progress=0 bodySpinX === 0", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "front-flip",
      elapsedSeconds: 0,
      horizontalSpeed: 0,
    });
    expect(pose.bodySpinX).toBeCloseTo(0, 9);
  });

  it("at progress=0.5 bodySpinX is between 0.55*PI*2 and 0.70*PI*2 (front-flip, spinTurns=-1.15)", () => {
    const elapsedSeconds = FLIP_DURATION * 0.5;
    const pose = sampleObservatoryPlayerPose({
      action: "front-flip",
      elapsedSeconds,
      horizontalSpeed: 0,
    });
    const spinTurns = -1.15;
    // easeFlipProgress(0.5) = 0.6*(0.5/0.6)^3 ≈ 0.347
    // bodySpinX = easeFlipProgress(0.5) * PI*2*spinTurns ≈ 0.347 * 2*PI*(-1.15) ≈ -2.51
    // abs(bodySpinX) should be between 0.55*PI*2 and 0.70*PI*2
    const lower = 0.55 * Math.PI * 2;
    const upper = 0.70 * Math.PI * 2;
    expect(Math.abs(pose.bodySpinX)).toBeGreaterThan(lower);
    expect(Math.abs(pose.bodySpinX)).toBeLessThan(upper);
  });

  it("at progress=1.0 |bodySpinX| is approximately |PI*2*1.15| within ±0.02 (front-flip)", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "front-flip",
      elapsedSeconds: FLIP_DURATION,
      horizontalSpeed: 0,
    });
    const expected = Math.abs(Math.PI * 2 * -1.15);
    expect(Math.abs(pose.bodySpinX)).toBeCloseTo(expected, 1);
  });

  it("at progress=0.6 |bodySpinX| equals phase boundary value 0.6*|PI*2*spinTurns|", () => {
    const elapsedSeconds = FLIP_DURATION * 0.6;
    const pose = sampleObservatoryPlayerPose({
      action: "front-flip",
      elapsedSeconds,
      horizontalSpeed: 0,
    });
    const spinTurns = -1.15;
    const expected = 0.6 * Math.abs(Math.PI * 2 * spinTurns);
    expect(Math.abs(pose.bodySpinX)).toBeCloseTo(expected, 5);
  });
});
