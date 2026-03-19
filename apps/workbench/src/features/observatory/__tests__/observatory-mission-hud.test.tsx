// apps/workbench/src/features/observatory/__tests__/observatory-mission-hud.test.tsx
// Tests for ObservatoryMissionHud — OBS-11 mission HUD overlay
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";
import { createObservatoryMissionLoopState } from "../world/missionLoop";
import { ObservatoryMissionHud } from "../components/ObservatoryMissionHud";

describe("ObservatoryMissionHud", () => {
  it("renders null when mission prop is null", () => {
    const { container } = render(<ObservatoryMissionHud mission={null} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders null when mission.status === 'completed'", () => {
    // Build a completed mission by forcing the status field
    const mission: ObservatoryMissionLoopState = {
      ...createObservatoryMissionLoopState("test-hunt", 0),
      status: "completed",
      completedAtMs: 100,
    };
    const { container } = render(<ObservatoryMissionHud mission={mission} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders objective title when mission is in-progress with an objective", () => {
    // Fresh mission — first objective is "acknowledge-horizon-ingress"
    const mission = createObservatoryMissionLoopState("test-hunt", 0);
    const { getByTestId } = render(<ObservatoryMissionHud mission={mission} />);
    const titleEl = getByTestId("mission-objective-title");
    expect(titleEl.textContent).toBe("Acknowledge a new Horizon ingress");
  });

  it("renders objective hint text when mission is in-progress", () => {
    const mission = createObservatoryMissionLoopState("test-hunt", 0);
    const { getByTestId } = render(<ObservatoryMissionHud mission={mission} />);
    const hintEl = getByTestId("mission-hint");
    expect(hintEl.textContent).toContain("Horizon");
  });
});
