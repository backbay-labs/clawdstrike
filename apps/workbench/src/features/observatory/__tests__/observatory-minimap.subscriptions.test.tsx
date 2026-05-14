import { act, render } from "@testing-library/react";
import { Profiler } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ObservatoryMinimapPanel } from "@/features/observatory/panels/observatory-minimap-panel";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";

const initialObservatoryState = useObservatoryStore.getState();

describe("ObservatoryMinimapPanel store subscriptions", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      stations: initialObservatoryState.stations.map((station) => ({ ...station })),
      seamSummary: { ...initialObservatoryState.seamSummary, artifactCount: 0, activeProbes: 0 },
      connected: initialObservatoryState.connected,
      mission: initialObservatoryState.mission,
      actions: initialObservatoryState.actions,
    });
  });

  it("ignores unrelated seamSummary updates but rerenders for active probes and station changes", () => {
    const commits: string[] = [];

    const { container } = render(
      <Profiler
        id="minimap"
        onRender={() => {
          commits.push("commit");
        }}
      >
        <ObservatoryMinimapPanel />
      </Profiler>,
    );

    expect(commits).toHaveLength(1);
    expect(container.textContent).not.toContain("probe active");

    act(() => {
      useObservatoryStore.getState().actions.updateSeamSummary({ stationCount: 99 });
    });
    expect(commits).toHaveLength(1);
    expect(container.textContent).not.toContain("probe active");

    act(() => {
      useObservatoryStore.getState().actions.setActiveProbes(1);
    });
    expect(commits).toHaveLength(2);
    expect(container.textContent).toContain("probe active");

    act(() => {
      useObservatoryStore.getState().actions.setStations(
        initialObservatoryState.stations.map((station, index) => ({
          ...station,
          artifactCount: index === 0 ? 3 : 0,
        })),
      );
    });
    expect(commits).toHaveLength(3);
    expect(container.textContent).toContain("3 artifacts");
  });
});
