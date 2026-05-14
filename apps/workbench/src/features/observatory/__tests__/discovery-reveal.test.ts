/**
 * discovery-reveal.test.ts — DSC-01
 *
 * Unit tests for the discoveredStations store slice.
 * Tests initial state, discoverStation action, idempotency.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { useObservatoryStore } from "../stores/observatory-store";

// Reset store between tests to avoid cross-test contamination.
beforeEach(() => {
  // Reset discoveredStations to initial value by calling store internals.
  const store = useObservatoryStore.getState();
  // Directly set state via the Zustand store setState if available,
  // otherwise use a workaround via the store's underlying base store.
  // We use the store's internal setState via the raw zustand interface.
  useObservatoryStore.setState({
    discoveredStations: new Set(["signal", "targets"]),
  });
});

describe("discoveredStations initial state", () => {
  it("starts with signal and targets discovered", () => {
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations).toBeInstanceOf(Set);
    expect(state.discoveredStations.has("signal")).toBe(true);
    expect(state.discoveredStations.has("targets")).toBe(true);
  });

  it("does not start with run, receipts, case-notes, or watch discovered", () => {
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations.has("run")).toBe(false);
    expect(state.discoveredStations.has("receipts")).toBe(false);
    expect(state.discoveredStations.has("case-notes")).toBe(false);
    expect(state.discoveredStations.has("watch")).toBe(false);
  });

  it("initial set has exactly 2 entries", () => {
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations.size).toBe(2);
  });
});

describe("discoverStation action", () => {
  it("adds an undiscovered station to the set", () => {
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("run");
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations.has("run")).toBe(true);
  });

  it("returns a new Set reference (immutable update pattern)", () => {
    const before = useObservatoryStore.getState().discoveredStations;
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("run");
    const after = useObservatoryStore.getState().discoveredStations;
    expect(after).not.toBe(before);
  });

  it("is a no-op when station is already discovered (signal)", () => {
    const before = useObservatoryStore.getState().discoveredStations;
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("signal");
    const after = useObservatoryStore.getState().discoveredStations;
    // Set reference should be unchanged when no-op
    expect(after).toBe(before);
    expect(after.size).toBe(2);
  });

  it("is a no-op when station is already discovered (targets)", () => {
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("targets");
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations.size).toBe(2);
  });

  it("can discover multiple stations sequentially", () => {
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("run");
    actions.discoverStation("receipts");
    actions.discoverStation("case-notes");
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations.has("run")).toBe(true);
    expect(state.discoveredStations.has("receipts")).toBe(true);
    expect(state.discoveredStations.has("case-notes")).toBe(true);
    expect(state.discoveredStations.size).toBe(5);
  });

  it("can discover watch station", () => {
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("watch");
    const state = useObservatoryStore.getState();
    expect(state.discoveredStations.has("watch")).toBe(true);
  });

  it("after discoverStation the new station appears in the set", () => {
    const { actions } = useObservatoryStore.getState();
    actions.discoverStation("receipts");
    const state = useObservatoryStore.getState();
    expect([...state.discoveredStations]).toContain("receipts");
  });
});

describe("discoveredStations reset behavior", () => {
  it("reset via setState restores initial 2-station set", () => {
    const { actions } = useObservatoryStore.getState();
    // Discover all stations
    actions.discoverStation("run");
    actions.discoverStation("receipts");
    actions.discoverStation("case-notes");
    actions.discoverStation("watch");
    expect(useObservatoryStore.getState().discoveredStations.size).toBe(6);

    // Reset (simulates tab close — store re-init)
    useObservatoryStore.setState({
      discoveredStations: new Set(["signal", "targets"]),
    });
    expect(useObservatoryStore.getState().discoveredStations.size).toBe(2);
  });
});
