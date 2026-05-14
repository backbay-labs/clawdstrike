import { describe, expect, it } from "vitest";
import {
  resolveNearestInteractableHeroProp,
} from "@/features/observatory/components/flow-runtime/observatory-player-interactable";
import { OBSERVATORY_HERO_PROP_ASSETS } from "@/features/observatory/world/propAssets";
import type { ObservatoryHeroPropRecipe } from "@/features/observatory/world/deriveObservatoryWorld";

function makeProp(
  assetId: ObservatoryHeroPropRecipe["assetId"],
  key: string,
  position: [number, number, number],
  stationId: ObservatoryHeroPropRecipe["stationId"],
): ObservatoryHeroPropRecipe {
  const asset = OBSERVATORY_HERO_PROP_ASSETS[assetId];
  return {
    assetId,
    assetUrl: asset.url,
    availability: asset.availability,
    bobAmplitude: 0,
    bobSpeed: 0,
    fallbackKind: asset.fallbackKind,
    glowColor: asset.glowColor,
    importance: 0.5,
    key,
    position,
    rotation: [0, 0, 0],
    scale: 1,
    stationId,
    wakeThreshold: 0.25,
  };
}

describe("resolveNearestInteractableHeroProp", () => {
  it("ignores core props and returns the closest station prop in range", () => {
    const props = [
      makeProp("watchfield-sentinel-beacon", "core-beacon", [0.2, 0, 0.2], "core"),
      makeProp("operations-scan-rig", "near-rig", [1.25, 0, 0], "watch"),
      makeProp("judgment-dais", "far-dais", [3.2, 0, 0], "watch"),
    ];

    const result = resolveNearestInteractableHeroProp(props, [0, 0, 0]);

    expect(result?.key).toBe("near-rig");
    expect(result?.stationId).toBe("watch");
  });

  it("returns null when no prop is close enough to interact", () => {
    const props = [
      makeProp("watchfield-sentinel-beacon", "distant-beacon", [4, 0, 0], "watch"),
      makeProp("operations-scan-rig", "core-rig", [0.5, 0, 0.5], "core"),
    ];

    expect(resolveNearestInteractableHeroProp(props, [0, 0, 0])).toBeNull();
  });
});
