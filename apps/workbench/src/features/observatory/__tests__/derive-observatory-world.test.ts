import { describe, expect, it } from "vitest";
import { deriveObservatoryWorld } from "@/features/observatory/world/deriveObservatoryWorld";
import { OBSERVATORY_WORLD_TEMPLATE } from "@/features/observatory/world/observatory-world-template";
import { HUNT_STATION_LABELS, HUNT_STATION_ORDER } from "@/features/observatory/world/stations";
import type { HuntObservatorySceneState } from "@/features/observatory/world/types";

function createSceneState(
  overrides: Partial<HuntObservatorySceneState> = {},
): HuntObservatorySceneState {
  return {
    huntId: "workbench",
    mode: "atlas",
    stations: HUNT_STATION_ORDER.map((id, index) => ({
      id,
      label: HUNT_STATION_LABELS[id],
      status: "idle",
      affinity: 0,
      emphasis: index === 1 ? 0.9 : 0.2,
      artifactCount: index === 1 ? 2 : 0,
      hasUnread: index === 1,
    })),
    activeSelection: { type: "none" },
    likelyStationId: "targets",
    roomReceiveState: "idle",
    spiritFieldBias: 0.5,
    confidence: 0.72,
    cameraPreset: "overview",
    openedDetailSurface: "none",
    ...overrides,
  };
}

describe("deriveObservatoryWorld", () => {
  it("reuses immutable hero props and cached route geometry across derivations", () => {
    const baseSceneState = createSceneState();
    const baseWorld = deriveObservatoryWorld({
      mode: "atlas",
      sceneState: baseSceneState,
      activeStationId: null,
      spirit: null,
    });
    const focusedWorld = deriveObservatoryWorld({
      mode: "atlas",
      sceneState: createSceneState({
        activeSelection: { type: "station", stationId: "targets" },
      }),
      activeStationId: "targets",
      spirit: null,
    });

    expect(baseWorld.heroProps).toBe(focusedWorld.heroProps);
    expect(baseWorld.heroProps).toBe(OBSERVATORY_WORLD_TEMPLATE.heroProps);
    expect(baseWorld.environment).toBe(OBSERVATORY_WORLD_TEMPLATE.environmentByMode.atlas);
    expect(baseWorld.coreLinks).toBe(focusedWorld.coreLinks);
    expect(baseWorld.coreLinks).toBe(OBSERVATORY_WORLD_TEMPLATE.coreLinksByMode.atlas);
    expect(baseWorld.watchfield.ringPoints).toBe(focusedWorld.watchfield.ringPoints);
    expect(baseWorld.watchfield.ringPoints).toBe(OBSERVATORY_WORLD_TEMPLATE.watchfieldTemplate.ringPoints);
    expect(baseWorld.transitLinks[0]?.points).toBe(focusedWorld.transitLinks[0]?.points);
    expect(baseWorld.transitLinks[0]?.waypointPositions).toBe(
      focusedWorld.transitLinks[0]?.waypointPositions,
    );
  });

  it("keeps district static positions shared while overlays remain dynamic", () => {
    const baseWorld = deriveObservatoryWorld({
      mode: "flow",
      sceneState: createSceneState({ mode: "flow", likelyStationId: null }),
      activeStationId: null,
      spirit: null,
    });
    const focusedWorld = deriveObservatoryWorld({
      mode: "flow",
      sceneState: createSceneState({
        mode: "flow",
        likelyStationId: "run",
        stations: createSceneState({ mode: "flow" }).stations.map((station) => ({
          ...station,
          emphasis: station.id === "run" ? 1 : station.emphasis,
        })),
      }),
      activeStationId: "run",
      spirit: null,
    });

    const baseRunDistrict = baseWorld.districts.find((district) => district.id === "run");
    const focusedRunDistrict = focusedWorld.districts.find((district) => district.id === "run");

    expect(baseRunDistrict?.position).toBe(focusedRunDistrict?.position);
    expect(baseRunDistrict?.growthAnchors[0]?.position).toBe(
      focusedRunDistrict?.growthAnchors[0]?.position,
    );
    expect(baseRunDistrict?.growthAnchors[0]?.opacity).not.toBe(
      focusedRunDistrict?.growthAnchors[0]?.opacity,
    );
  });

  it("keeps dynamic transit activation behavior while reusing cached geometry", () => {
    const idleWorld = deriveObservatoryWorld({
      mode: "flow",
      sceneState: createSceneState({ mode: "flow", likelyStationId: null }),
      activeStationId: null,
      spirit: null,
    });
    const activeWorld = deriveObservatoryWorld({
      mode: "flow",
      sceneState: createSceneState({ mode: "flow", likelyStationId: null }),
      activeStationId: "targets",
      spirit: null,
    });

    const idleRoute = idleWorld.transitLinks.find((route) => route.key === "signal-targets");
    const activeRoute = activeWorld.transitLinks.find((route) => route.key === "signal-targets");

    expect(idleRoute?.active).toBe(false);
    expect(activeRoute?.active).toBe(true);
    expect((activeRoute?.intensity ?? 0)).toBeGreaterThan(idleRoute?.intensity ?? 0);
    expect(idleRoute?.points).toBe(activeRoute?.points);
    expect(idleRoute?.waypointPositions).toBe(activeRoute?.waypointPositions);
  });

  it("keeps core-link caches mode-specific", () => {
    const atlasWorld = deriveObservatoryWorld({
      mode: "atlas",
      sceneState: createSceneState({ mode: "atlas" }),
      activeStationId: null,
      spirit: null,
    });
    const flowWorld = deriveObservatoryWorld({
      mode: "flow",
      sceneState: createSceneState({ mode: "flow" }),
      activeStationId: null,
      spirit: null,
    });

    expect(atlasWorld.coreLinks).not.toBe(flowWorld.coreLinks);
    expect(atlasWorld.coreLinks[0]?.points).not.toBe(flowWorld.coreLinks[0]?.points);
  });
});
