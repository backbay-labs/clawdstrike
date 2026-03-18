import { describe, expect, it } from "vitest";
import { deriveObservatoryWorld } from "./deriveObservatoryWorld";

describe("deriveObservatoryWorld", () => {
  it("derives a stable world model from the observatory scene state", () => {
    const world = deriveObservatoryWorld({
      mode: "atlas",
      activeStationId: "run",
      spirit: {
        kind: "tracker",
        accentColor: "#88d4ff",
        likelyStationId: "run",
        cueKind: "focus",
      },
      sceneState: {
        huntId: "hunt-1",
        mode: "atlas",
        stations: [
          {
            id: "signal",
            label: "Horizon",
            status: "idle",
            affinity: 0.42,
            emphasis: 0.38,
            artifactCount: 1,
            hasUnread: true,
          },
          {
            id: "run",
            label: "Operations",
            status: "active",
            affinity: 0.91,
            emphasis: 1,
            artifactCount: 4,
            hasUnread: false,
          },
          {
            id: "watch",
            label: "Watchfield",
            status: "warming",
            affinity: 0.52,
            emphasis: 0.61,
            artifactCount: 2,
            hasUnread: true,
          },
        ],
        activeSelection: { type: "station", stationId: "run" },
        likelyStationId: "run",
        roomReceiveState: "receiving",
        spiritFieldBias: 0.7,
        confidence: 0.82,
        cameraPreset: "follow-run",
        openedDetailSurface: "none",
      },
    });

    expect(world.districts).toHaveLength(5);
    expect(world.transitLinks).toHaveLength(4);
    expect(world.coreLinks).toHaveLength(5);
    expect(world.watchfield.position).toHaveLength(3);
    expect(Math.abs(world.camera.desiredPosition[0])).toBeGreaterThan(5);
    expect(world.camera.fov).toBeLessThan(42);
    const runDistrict = world.districts.find((district) => district.id === "run");
    expect(runDistrict?.active).toBe(true);
    expect(runDistrict?.growthAnchors).toHaveLength(3);
    expect(runDistrict?.growth.growthLevel).toBeGreaterThan(0.5);
    expect(runDistrict?.growth.structures.length).toBeGreaterThan(4);
    expect(runDistrict?.growth.conduitPaths.length).toBeGreaterThan(2);
    expect(runDistrict?.silhouette.frameLoops.length).toBeGreaterThan(0);
    expect(runDistrict?.silhouette.nodePositions.length).toBeGreaterThan(0);
    expect(runDistrict?.masterplanFeatures.length).toBeGreaterThan(2);
    expect(runDistrict?.traversalSurfaces.length).toBeGreaterThan(6);
    expect(runDistrict?.traversalSurfaces.some((surface) => surface.kind === "jump-pad")).toBe(true);
    expect(runDistrict?.traversalSurfaces.some((surface) => surface.kind === "hanging-platform")).toBe(true);
    expect(runDistrict?.crew.some((crew) => crew.role === "technician")).toBe(true);
    expect(runDistrict?.crew[0]?.waypoints.length).toBeGreaterThan(3);
    expect(runDistrict?.crew[0]?.utilityTarget).toBeTruthy();
    expect(runDistrict?.verticalSpan).toBeGreaterThan(2.5);
    expect(runDistrict?.occupancyNodes.length).toBeGreaterThan(2);
    expect(runDistrict?.timeStrata.length).toBeGreaterThan(1);
    expect(runDistrict?.microInteraction).toBe("engage-machinery");
    expect(runDistrict?.lifecycleState).toBe("saturated");
    expect(runDistrict?.lifecycleProgress).toBeGreaterThan(0.8);
    expect(world.modeProfile.label).toBe("ATLAS");
    expect(world.transitLinks.every((route) => route.corridorRadius > 0.15)).toBe(true);
    expect(world.hypothesisScaffolds[0]?.panels.length).toBeGreaterThan(0);
    expect(world.hypothesisScaffolds[0]?.stage).toBeTruthy();
    expect(world.hypothesisScaffolds[0]?.branchPaths).toBeDefined();
    expect(world.heroProps).toHaveLength(7);
    expect(world.heroProps.every((prop) => prop.availability === "ready")).toBe(true);
    expect(world.heroProps.find((prop) => prop.stationId === "receipts")?.fallbackKind).toBe(
      "vault-rack",
    );
    expect(world.heroProps.find((prop) => prop.stationId === "run")?.availability).toBe("ready");
    expect(world.camera.arrivalDurationMs).toBeGreaterThan(1000);
    expect(world.camera.arrivalLift).toBeGreaterThan(3);
    expect(Math.abs(world.camera.desiredTarget[0])).toBeGreaterThan(1);
    expect(world.core.accentColor).toBe("#88d4ff");
  });
});
