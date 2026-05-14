import { describe, expect, it } from "vitest";
import { OBSERVATORY_WORLD_TEMPLATE } from "@/features/observatory/world/observatory-world-template";

describe("observatory-world template", () => {
  it("keeps the static template data frozen and reusable", () => {
    expect(Object.isFrozen(OBSERVATORY_WORLD_TEMPLATE.heroProps)).toBe(true);
    expect(Object.isFrozen(OBSERVATORY_WORLD_TEMPLATE.environmentByMode)).toBe(true);
    expect(Object.isFrozen(OBSERVATORY_WORLD_TEMPLATE.districtTemplates)).toBe(true);
    expect(OBSERVATORY_WORLD_TEMPLATE.stationPositions.signal).toBe(
      OBSERVATORY_WORLD_TEMPLATE.stationPositions.signal,
    );
    expect(OBSERVATORY_WORLD_TEMPLATE.heroProps[0]?.position).toBe(
      OBSERVATORY_WORLD_TEMPLATE.heroProps[0]?.position,
    );
  });

  it("keeps static geometry arrays shared across modes", () => {
    expect(OBSERVATORY_WORLD_TEMPLATE.coreLinksByMode.atlas).not.toBe(
      OBSERVATORY_WORLD_TEMPLATE.coreLinksByMode.flow,
    );
    expect(OBSERVATORY_WORLD_TEMPLATE.coreLinksByMode.atlas[0]?.points).not.toBe(
      OBSERVATORY_WORLD_TEMPLATE.coreLinksByMode.flow[0]?.points,
    );
    expect(OBSERVATORY_WORLD_TEMPLATE.transitGeometryByMode.atlas["signal-targets"]?.points).toBe(
      OBSERVATORY_WORLD_TEMPLATE.transitGeometryByMode.atlas["signal-targets"]?.points,
    );
  });
});
