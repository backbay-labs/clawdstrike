import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SpiritExperienceTracker } from "../components/spirit-experience-tracker";
import { SpiritMoodReactor } from "../components/spirit-mood-reactor";
import { useSpiritEvolutionStore } from "../stores/spirit-evolution-store";
import { useSpiritStore } from "../stores/spirit-store";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";

vi.mock("@/features/policy/stores/policy-tabs-store", () => ({
  usePolicyTabsStore: (selector: (state: { tabs: [] }) => unknown) =>
    selector({ tabs: [] }),
}));

vi.mock("@/features/policy/stores/policy-edit-store", () => ({
  usePolicyEditStore: (selector: (state: { editStates: Map<string, unknown> }) => unknown) =>
    selector({ editStates: new Map() }),
}));

const initialSpiritState = useSpiritStore.getState();
const initialObservatoryState = useObservatoryStore.getState();
const initialSpiritEvolutionState = useSpiritEvolutionStore.getState();

describe("spirit reactor observatory subscriptions", () => {
  beforeEach(() => {
    vi.useFakeTimers();

    useSpiritStore.setState({
      kind: initialSpiritState.kind,
      mood: initialSpiritState.mood,
      fieldStrength: initialSpiritState.fieldStrength,
      accentColor: initialSpiritState.accentColor,
      actions: initialSpiritState.actions,
    });
    useSpiritEvolutionStore.setState({
      evolution: initialSpiritEvolutionState.evolution,
      actions: initialSpiritEvolutionState.actions,
    });
    useObservatoryStore.setState({
      stations: initialObservatoryState.stations.map((station) => ({ ...station })),
      seamSummary: { ...initialObservatoryState.seamSummary, artifactCount: 0, activeProbes: 0 },
      connected: initialObservatoryState.connected,
      mission: initialObservatoryState.mission,
      actions: initialObservatoryState.actions,
    });
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  it("does not retrigger spirit mood updates for unrelated seamSummary changes, but does for active probe changes", () => {
    const setMood = vi.fn();
    useSpiritStore.setState((state) => ({
      actions: {
        ...state.actions,
        setMood,
      },
    }));
    useSpiritStore.getState().actions.bindSpirit("sentinel");

    render(<SpiritMoodReactor />);

    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(setMood).toHaveBeenCalledTimes(1);
    expect(setMood).toHaveBeenLastCalledWith("idle");

    setMood.mockClear();

    act(() => {
      useObservatoryStore.getState().actions.updateSeamSummary({ artifactCount: 7, stationCount: 99 });
    });
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(setMood).not.toHaveBeenCalled();

    act(() => {
      useObservatoryStore.getState().actions.setActiveProbes(1);
    });
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(setMood).toHaveBeenCalledTimes(1);
    expect(setMood).toHaveBeenLastCalledWith("active");
  });

  it("does not grant probe XP for unrelated seamSummary changes, but does when active probes complete", () => {
    const grantXp = vi.fn();
    useSpiritEvolutionStore.setState((state) => ({
      actions: {
        ...state.actions,
        grantXp,
      },
    }));
    useSpiritStore.getState().actions.bindSpirit("sentinel");

    render(<SpiritExperienceTracker />);

    act(() => {
      useObservatoryStore.getState().actions.updateSeamSummary({ artifactCount: 5, stationCount: 42 });
    });
    expect(grantXp).not.toHaveBeenCalled();

    act(() => {
      useObservatoryStore.getState().actions.setActiveProbes(1);
    });
    expect(grantXp).not.toHaveBeenCalled();

    act(() => {
      useObservatoryStore.getState().actions.setActiveProbes(0);
    });
    expect(grantXp).toHaveBeenCalledTimes(1);
    expect(grantXp).toHaveBeenCalledWith("sentinel", 10);
  });
});
