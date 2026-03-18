import { describe, expect, it } from "vitest";
import { buildForensicsFlowRead, resolveForensicsObservatoryStationId } from "./observatory";

describe("resolveForensicsObservatoryStationId", () => {
  it("maps river station ids onto the shared observatory taxonomy", () => {
    expect(resolveForensicsObservatoryStationId("security-overview")).toBe("signal");
    expect(resolveForensicsObservatoryStationId("attack-graph")).toBe("targets");
    expect(resolveForensicsObservatoryStationId("network-map")).toBe("run");
    expect(resolveForensicsObservatoryStationId("threat-radar")).toBe("watch");
  });
});

describe("buildForensicsFlowRead", () => {
  it("prefers the likely observatory station and returns compact strip metadata", () => {
    const read = buildForensicsFlowRead(
      {
        huntId: "hunt-1",
        mode: "flow",
        stations: [
          {
            id: "signal",
            label: "Horizon",
            status: "active",
            affinity: 0.7,
            emphasis: 0.72,
            artifactCount: 2,
            hasUnread: true,
            reason: "Fresh change is arriving at the edge of the hunt world.",
          },
          {
            id: "receipts",
            label: "Evidence",
            status: "warming",
            affinity: 0.8,
            emphasis: 0.84,
            artifactCount: 3,
            hasUnread: true,
            reason: "Evidence and replayable traces are gathering weight.",
          },
        ],
        activeSelection: { type: "station", stationId: "receipts" },
        likelyStationId: "receipts",
        roomReceiveState: "idle",
        spiritFieldBias: 0.6,
        confidence: 0.74,
        cameraPreset: "focus-station",
        openedDetailSurface: "none",
      },
      "signal",
    );

    expect(read.label).toBe("Evidence");
    expect(read.code).toBe("EVD");
    expect(read.coreLabel).toBe("Thesis Core");
    expect(read.stations.find((station) => station.stationId === "signal")?.active).toBe(true);
    expect(read.stations.find((station) => station.stationId === "receipts")?.likely).toBe(true);
  });
});
