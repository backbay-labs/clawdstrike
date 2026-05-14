import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useMissions, useMissionStore } from "../mission-store";

const STORAGE_KEY = "clawdstrike_workbench_missions";

function MissionSnapshot() {
  const { activeMission, missions, advanceMission } = useMissions();

  if (!activeMission) {
    return <div data-testid="empty">empty</div>;
  }

  return (
    <>
      <button data-testid="advance" onClick={() => advanceMission(activeMission.id)}>
        advance
      </button>
      <pre data-testid="snapshot">
        {JSON.stringify({
          missionCount: missions.length,
          id: activeMission.id,
          title: activeMission.title,
          status: activeMission.status,
          objective: activeMission.objective,
          driver: activeMission.driver,
          priority: activeMission.priority,
          primarySentinelId: activeMission.primarySentinelId,
          assignedSentinelIds: activeMission.assignedSentinelIds,
          stageStatuses: activeMission.stages.map((stage) => stage.status),
          stageOwners: activeMission.stages.map((stage) => stage.ownerSentinelId),
          signalIds: activeMission.signalIds.length,
          findingIds: activeMission.findingIds.length,
          runtimeEvents: activeMission.runtimeEvents.length,
          evidence: activeMission.evidence.length,
          launchHints: activeMission.launchHints.length,
          updatedAt: activeMission.updatedAt,
        })}
      </pre>
    </>
  );
}

beforeEach(() => {
  // Reset the Zustand store to initial empty state before each test
  useMissionStore.setState({
    missions: [],
    activeMissionId: null,
    loading: false,
  });
});

afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

describe("mission-store", () => {
  it("repairs drifted active missions into an advanceable shape before persisting them", () => {
    vi.useFakeTimers();

    // Seed localStorage with a legacy mission that needs repair
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        missions: [
          {
            id: "msn_legacy",
            title: "Legacy mission",
            status: "active",
          },
        ],
        activeMissionId: "msn_legacy",
      }),
    );

    // Rehydrate the store from localStorage (triggers normalization + repair)
    act(() => {
      useMissionStore.getState().actions._rehydrate();
    });

    render(<MissionSnapshot />);

    const snapshot = JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}");

    expect(snapshot).toMatchObject({
      missionCount: 1,
      id: "msn_legacy",
      title: "Legacy mission",
      status: "active",
      objective: "",
      driver: "claude_code",
      priority: "medium",
      primarySentinelId: "sen_legacy_msn_legacy",
      assignedSentinelIds: ["sen_legacy_msn_legacy"],
      stageStatuses: ["completed", "in_progress", "pending", "pending"],
      stageOwners: [
        "sen_legacy_msn_legacy",
        "sen_legacy_msn_legacy",
        "sen_legacy_msn_legacy",
        "sen_legacy_msn_legacy",
      ],
      signalIds: 0,
      findingIds: 0,
      runtimeEvents: 0,
      evidence: 0,
      launchHints: 0,
    });

    fireEvent.click(screen.getByTestId("advance"));

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      stageStatuses: ["completed", "completed", "in_progress", "pending"],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.activeMissionId).toBe("msn_legacy");
    expect(persisted.missions[0]).toMatchObject({
      id: "msn_legacy",
      primarySentinelId: "sen_legacy_msn_legacy",
      assignedSentinelIds: ["sen_legacy_msn_legacy"],
    });
    expect(persisted.missions[0].stages).toHaveLength(4);
    expect(persisted.missions[0].stages.map((stage: { status: string }) => stage.status)).toEqual([
      "completed",
      "completed",
      "in_progress",
      "pending",
    ]);
    expect(snapshot.updatedAt).toEqual(expect.any(Number));
  });
});
