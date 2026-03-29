import { describe, it, expect } from "vitest";

// NOTE: rayRectIntersect will be exported from the component file once created.
// During TDD RED phase, import will fail — that's expected.
import { rayRectIntersect } from "../components/edge-indicators";

describe("rayRectIntersect", () => {
  it("finds intersection on right edge", () => {
    const hit = rayRectIntersect(400, 300, 1200, 300, 0, 0, 800, 600);
    expect(hit).not.toBeNull();
    expect(hit!.x).toBeCloseTo(800, 0);
    expect(hit!.y).toBeCloseTo(300, 0);
  });

  it("finds intersection on left edge", () => {
    const hit = rayRectIntersect(400, 300, -200, 300, 0, 0, 800, 600);
    expect(hit).not.toBeNull();
    expect(hit!.x).toBeCloseTo(0, 0);
    expect(hit!.y).toBeCloseTo(300, 0);
  });

  it("finds intersection on top edge", () => {
    const hit = rayRectIntersect(400, 300, 400, -200, 0, 0, 800, 600);
    expect(hit).not.toBeNull();
    expect(hit!.y).toBeCloseTo(0, 0);
  });

  it("finds intersection on bottom edge", () => {
    const hit = rayRectIntersect(400, 300, 400, 900, 0, 0, 800, 600);
    expect(hit).not.toBeNull();
    expect(hit!.y).toBeCloseTo(600, 0);
  });

  it("returns null when origin equals target (no direction)", () => {
    const hit = rayRectIntersect(400, 300, 400, 300, 0, 0, 800, 600);
    expect(hit).toBeNull();
  });

  it("handles diagonal rays correctly", () => {
    const hit = rayRectIntersect(400, 300, 1000, 0, 0, 0, 800, 600);
    expect(hit).not.toBeNull();
    expect(hit!.x).toBeGreaterThanOrEqual(0);
    expect(hit!.x).toBeLessThanOrEqual(800);
    expect(hit!.y).toBeGreaterThanOrEqual(0);
    expect(hit!.y).toBeLessThanOrEqual(600);
  });
});
