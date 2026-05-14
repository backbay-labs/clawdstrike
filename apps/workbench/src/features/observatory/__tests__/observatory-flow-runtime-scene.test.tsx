import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import type { RefObject } from "react";
import { ObservatoryFlowRuntimeScene } from "@/features/observatory/components/ObservatoryFlowRuntimeScene";
import type {
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
} from "@/features/observatory/components/ObservatoryFlowRuntimeScene";
import type { DerivedObservatoryWorld } from "@/features/observatory/world/deriveObservatoryWorld";

const controllerMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
}));

vi.mock("@/features/observatory/character/ship/SpaceFlightController", () => ({
  SpaceFlightController: (props: Record<string, unknown>) => {
    controllerMock.props.push(props);
    return <div data-testid="space-flight-controller" />;
  },
}));

const world = {
  core: { accentColor: "#3dbf84" },
  districts: [],
  watchfield: { position: [0, 0, 0] },
} as unknown as DerivedObservatoryWorld;

describe("ObservatoryFlowRuntimeScene", () => {
  beforeEach(() => {
    controllerMock.props.length = 0;
  });

  it("mounts the SpaceFlightController with input enabled", async () => {
    const focusRef = { current: null } as RefObject<ObservatoryPlayerFocusState | null>;

    render(
      <ObservatoryFlowRuntimeScene
        enableCharacterVfx
        heroProps={[]}
        inputEnabled
        onWorldStateChange={(_: ObservatoryPlayerWorldState) => {}}
        playerFocusRef={focusRef}
        preferredStationId="watch"
        world={world}
      />,
    );

    expect(await screen.findByTestId("space-flight-controller")).toBeTruthy();
    expect(controllerMock.props[0]?.inputEnabled).toBe(true);
    expect(controllerMock.props[0]?.playerFocusRef).toBe(focusRef);
  });

  it("mounts the SpaceFlightController with input disabled when not provided", async () => {
    const focusRef = { current: null } as RefObject<ObservatoryPlayerFocusState | null>;

    render(
      <ObservatoryFlowRuntimeScene
        enableCharacterVfx={false}
        heroProps={[]}
        playerFocusRef={focusRef}
        preferredStationId={null}
        world={world}
      />,
    );

    expect(await screen.findByTestId("space-flight-controller")).toBeTruthy();
    expect(controllerMock.props[0]?.inputEnabled).toBe(false);
  });
});
