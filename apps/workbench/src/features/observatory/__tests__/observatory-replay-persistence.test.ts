import { beforeEach, describe, expect, it } from "vitest";
import {
  OBSERVATORY_REPLAY_PERSISTENCE_KEY,
  OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2,
  loadPersistedObservatoryReplayArtifacts,
  loadPersistedObservatoryReplayArtifactsV2,
  savePersistedObservatoryReplayArtifacts,
  savePersistedObservatoryReplayArtifactsV2,
} from "@/features/observatory/utils/observatory-replay-persistence";
import type {
  ObservatoryAnnotationPin,
} from "@/features/observatory/types";
import type {
  ConstellationRoute,
} from "@/features/observatory/types";

const testPin: ObservatoryAnnotationPin = {
  id: "pin-1",
  frameIndex: 5,
  timestampMs: 5000,
  worldPosition: [1, 2, 3],
  note: "Suspicious pattern",
  districtId: "signal",
};

const testConstellation: ConstellationRoute = {
  id: "const-1",
  name: "Alpha hunt route",
  createdAtMs: 1000,
  stationPath: ["signal", "targets", "run"],
  missionHuntId: "hunt-alpha",
};

describe("observatory replay persistence", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("round-trips authored replay artifacts through localStorage", () => {
    savePersistedObservatoryReplayArtifacts({
      annotations: [
        {
          authorLabel: "Operator",
          body: "Keep this read.",
          districtId: "watch",
          frameIndex: 2,
          id: "annotation-1",
          sourceType: "manual",
          timestampMs: 2000,
        },
      ],
      bookmarks: [
        {
          districtId: "receipts",
          frameIndex: 1,
          id: "bookmark-1",
          label: "Receipt surge",
          timestampMs: 1000,
        },
      ],
    });

    expect(loadPersistedObservatoryReplayArtifacts()).toEqual({
      annotations: [
        expect.objectContaining({
          body: "Keep this read.",
          id: "annotation-1",
        }),
      ],
      bookmarks: [
        expect.objectContaining({
          id: "bookmark-1",
          label: "Receipt surge",
        }),
      ],
    });
  });

  it("falls back cleanly on malformed payloads", () => {
    window.localStorage.setItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY, "{not-valid");

    expect(loadPersistedObservatoryReplayArtifacts()).toEqual({
      annotations: [],
      bookmarks: [],
    });
  });
});

describe("v2 persistence", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("round-trips annotation pins and constellation routes alongside bookmarks and annotations", () => {
    savePersistedObservatoryReplayArtifactsV2({
      annotations: [
        {
          authorLabel: "Analyst",
          body: "Spike detected",
          districtId: "signal",
          frameIndex: 3,
          id: "ann-1",
          sourceType: "manual",
          timestampMs: 3000,
        },
      ],
      bookmarks: [
        {
          districtId: "receipts",
          frameIndex: 1,
          id: "bm-1",
          label: "Bookmark label",
          timestampMs: 1000,
        },
      ],
      annotationPins: [testPin],
      constellations: [testConstellation],
    });

    const result = loadPersistedObservatoryReplayArtifactsV2();
    expect(result.annotationPins).toEqual([testPin]);
    expect(result.constellations).toEqual([testConstellation]);
    expect(result.annotations).toHaveLength(1);
    expect(result.bookmarks).toHaveLength(1);
  });

  it("v1 data migrates to v2 with empty annotationPins and constellations", () => {
    // Write v1 data only
    savePersistedObservatoryReplayArtifacts({
      annotations: [
        {
          authorLabel: "Operator",
          body: "Old annotation",
          districtId: "watch",
          frameIndex: 2,
          id: "ann-old",
          sourceType: "manual",
          timestampMs: 2000,
        },
      ],
      bookmarks: [],
    });

    const result = loadPersistedObservatoryReplayArtifactsV2();
    expect(result.annotationPins).toEqual([]);
    expect(result.constellations).toEqual([]);
    expect(result.annotations).toHaveLength(1);
    expect(result.annotations[0]).toMatchObject({ id: "ann-old", body: "Old annotation" });
  });

  it("prefers v2 data when both v1 and v2 keys are present", () => {
    // Write v1 data
    savePersistedObservatoryReplayArtifacts({ annotations: [], bookmarks: [] });
    // Write v2 data with pins
    savePersistedObservatoryReplayArtifactsV2({
      annotations: [],
      bookmarks: [],
      annotationPins: [testPin],
      constellations: [],
    });

    const result = loadPersistedObservatoryReplayArtifactsV2();
    expect(result.annotationPins).toEqual([testPin]);
  });

  it("falls back to empty arrays for malformed annotationPins and constellations without throwing", () => {
    window.localStorage.setItem(
      OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2,
      JSON.stringify({
        annotations: [],
        bookmarks: [],
        annotationPins: "not-an-array",
        constellations: null,
      }),
    );

    const result = loadPersistedObservatoryReplayArtifactsV2();
    expect(result.annotationPins).toEqual([]);
    expect(result.constellations).toEqual([]);
  });

  it("v2 save writes to v2 key; old v1 key is not updated", () => {
    savePersistedObservatoryReplayArtifactsV2({
      annotations: [],
      bookmarks: [],
      annotationPins: [testPin],
      constellations: [],
    });

    // v1 key should remain absent
    expect(window.localStorage.getItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY)).toBeNull();
    // v2 key should be present
    expect(window.localStorage.getItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2)).not.toBeNull();
  });

  it("asAnnotationPins validator rejects entries missing required fields", () => {
    window.localStorage.setItem(
      OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2,
      JSON.stringify({
        annotations: [],
        bookmarks: [],
        annotationPins: [
          { id: "pin-bad" }, // missing frameIndex, timestampMs, worldPosition, note, districtId
          { id: "pin-partial", frameIndex: 1, timestampMs: 1000 }, // missing worldPosition, note, districtId
          testPin, // valid
        ],
        constellations: [],
      }),
    );

    const result = loadPersistedObservatoryReplayArtifactsV2();
    expect(result.annotationPins).toHaveLength(1);
    expect(result.annotationPins[0]).toEqual(testPin);
  });

  it("asConstellationRoutes validator rejects entries missing required fields", () => {
    window.localStorage.setItem(
      OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2,
      JSON.stringify({
        annotations: [],
        bookmarks: [],
        annotationPins: [],
        constellations: [
          { id: "const-bad" }, // missing name, createdAtMs, stationPath, missionHuntId
          { id: "const-partial", name: "Route" }, // missing createdAtMs, stationPath, missionHuntId
          testConstellation, // valid
        ],
      }),
    );

    const result = loadPersistedObservatoryReplayArtifactsV2();
    expect(result.constellations).toHaveLength(1);
    expect(result.constellations[0]).toEqual(testConstellation);
  });
});
