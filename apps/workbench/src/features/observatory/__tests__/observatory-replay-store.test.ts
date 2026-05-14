import { beforeEach, describe, expect, it } from "vitest";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";

const initialState = useObservatoryStore.getState();

describe("observatory replay store", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      replay: {
        ...initialState.replay,
        annotations: [],
        bookmarks: [],
        enabled: false,
        frameIndex: 0,
        frameMs: null,
        selectedDistrictId: null,
        selectedSpikeTimestampMs: null,
        markers: [],
      },
    });
  });

  it("boots with cleared spike, district, bookmark, and annotation state", () => {
    const { replay } = useObservatoryStore.getState();

    expect(replay.enabled).toBe(false);
    expect(replay.frameIndex).toBe(0);
    expect(replay.frameMs).toBeNull();
    expect(replay.selectedSpikeTimestampMs).toBeNull();
    expect(replay.selectedDistrictId).toBeNull();
    expect(replay.bookmarks).toEqual([]);
    expect(replay.annotations).toEqual([]);
    expect(replay.markers).toEqual([]);
  });

  it("updates replay state through partial merges without discarding frame selection", () => {
    useObservatoryStore.getState().actions.setReplayState({
      enabled: true,
      frameIndex: 4,
      frameMs: 123,
      selectedDistrictId: "receipts",
      selectedSpikeTimestampMs: 456,
    });

    const { replay } = useObservatoryStore.getState();

    expect(replay.enabled).toBe(true);
    expect(replay.frameIndex).toBe(4);
    expect(replay.frameMs).toBe(123);
    expect(replay.selectedDistrictId).toBe("receipts");
    expect(replay.selectedSpikeTimestampMs).toBe(456);
  });

  it("clears transient replay selection when replay is disabled", () => {
    useObservatoryStore.getState().actions.setReplayState({
      enabled: true,
      frameIndex: 2,
      frameMs: 222,
      selectedDistrictId: "watch",
      selectedSpikeTimestampMs: 333,
    });
    useObservatoryStore.getState().actions.addReplayBookmark({
      districtId: "watch",
      frameIndex: 2,
      id: "bookmark-1",
      label: "Watch spike",
      timestampMs: 222,
    });
    useObservatoryStore.getState().actions.upsertReplayAnnotation({
      authorLabel: "Operator",
      body: "Keep this read.",
      districtId: "watch",
      frameIndex: 2,
      id: "annotation-1",
      sourceType: "manual",
      timestampMs: 222,
    });

    useObservatoryStore.getState().actions.setReplayState({
      enabled: false,
    });

    const { replay } = useObservatoryStore.getState();

    expect(replay.enabled).toBe(false);
    expect(replay.frameIndex).toBe(2);
    expect(replay.frameMs).toBe(222);
    expect(replay.selectedDistrictId).toBeNull();
    expect(replay.selectedSpikeTimestampMs).toBeNull();
    expect(replay.bookmarks).toHaveLength(1);
    expect(replay.annotations).toHaveLength(1);
  });

  it("appends bookmarks by id and upserts annotations by id", () => {
    const bookmark = {
      districtId: "receipts" as const,
      frameIndex: 3,
      id: "bookmark-2",
      label: "Receipt surge",
      timestampMs: 333,
    };

    useObservatoryStore.getState().actions.addReplayBookmark(bookmark);
    useObservatoryStore.getState().actions.addReplayBookmark({
      ...bookmark,
      label: "Receipt surge duplicate",
    });

    useObservatoryStore.getState().actions.upsertReplayAnnotation({
      authorLabel: "Operator",
      body: "First note",
      districtId: "receipts",
      frameIndex: 3,
      id: "annotation-2",
      sourceType: "manual",
      timestampMs: 333,
    });
    useObservatoryStore.getState().actions.upsertReplayAnnotation({
      authorLabel: "Operator",
      body: "Updated note",
      districtId: "receipts",
      frameIndex: 4,
      id: "annotation-2",
      sourceType: "manual",
      timestampMs: 444,
    });

    const { replay } = useObservatoryStore.getState();

    expect(replay.bookmarks).toHaveLength(1);
    expect(replay.bookmarks?.[0]).toMatchObject({
      label: "Receipt surge",
      timestampMs: 333,
    });
    expect(replay.annotations).toHaveLength(1);
    expect(replay.annotations?.[0]).toMatchObject({
      body: "Updated note",
      frameIndex: 4,
      timestampMs: 444,
    });
  });

  it("hydrates authored replay artifacts and updates the derived marker feed separately", () => {
    useObservatoryStore.getState().actions.hydrateReplayArtifacts({
      annotations: [
        {
          authorLabel: "Operator",
          body: "Hydrated note",
          districtId: "watch",
          frameIndex: 3,
          id: "annotation-3",
          sourceType: "manual",
          timestampMs: 333,
        },
      ],
      bookmarks: [
        {
          districtId: "watch",
          frameIndex: 2,
          id: "bookmark-3",
          label: "Hydrated bookmark",
          timestampMs: 222,
        },
      ],
    });
    useObservatoryStore.getState().actions.setReplayMarkers([
      {
        districtId: "watch",
        frameIndex: 2,
        id: "marker-1",
        label: "Investigation marker",
        sourceType: "investigation",
        timestampMs: 222,
      },
    ]);

    const { replay } = useObservatoryStore.getState();

    expect(replay.bookmarks).toHaveLength(1);
    expect(replay.annotations).toHaveLength(1);
    expect(replay.markers).toEqual([
      expect.objectContaining({
        id: "marker-1",
        sourceType: "investigation",
      }),
    ]);
  });
});
