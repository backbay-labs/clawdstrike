import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import type { ReactNode, RefObject } from "react";
import { ObservatoryFlowPhysicsBootstrap } from "@/features/observatory/components/flow-runtime/ObservatoryFlowPhysicsBootstrap";
import type {
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
} from "@/features/observatory/components/ObservatoryFlowRuntimeScene";
import type { DerivedObservatoryWorld } from "@/features/observatory/world/deriveObservatoryWorld";

const physicsMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
}));

const collidersMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
}));

const playerRuntimeMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
}));

vi.mock("@react-three/rapier", () => ({
  Physics: ({ children, ...props }: { children?: ReactNode }) => {
    physicsMock.props.push(props);
    return <div data-testid="flow-physics">{children}</div>;
  },
}));

vi.mock("@/features/observatory/components/flow-runtime/ObservatoryFlowColliders", () => ({
  ObservatoryFlowColliders: (props: Record<string, unknown>) => {
    collidersMock.props.push(props);
    return <div data-testid="flow-colliders" />;
  },
}));

vi.mock("@/features/observatory/components/flow-runtime/ObservatoryPlayerRuntime", () => ({
  ObservatoryPlayerRuntime: (props: Record<string, unknown>) => {
    playerRuntimeMock.props.push(props);
    return <div data-testid="flow-player-runtime" />;
  },
}));

const world = {
  core: { accentColor: "#3dbf84" },
  districts: [],
  watchfield: { position: [0, 0, 0] },
} as unknown as DerivedObservatoryWorld;

describe("ObservatoryFlowPhysicsBootstrap", () => {
  beforeEach(() => {
    physicsMock.props.length = 0;
    collidersMock.props.length = 0;
    playerRuntimeMock.props.length = 0;
  });

  it("mounts physics and forwards the runtime slices", async () => {
    const focusRef = { current: null } as RefObject<ObservatoryPlayerFocusState | null>;

    render(
      <ObservatoryFlowPhysicsBootstrap
        enableCharacterVfx
        heroProps={[]}
        inputEnabled
        onWorldStateChange={(_: ObservatoryPlayerWorldState) => {}}
        playerFocusRef={focusRef}
        preferredStationId="watch"
        world={world}
      />,
    );

    expect(screen.getByTestId("flow-physics")).toBeTruthy();
    expect(await screen.findByTestId("flow-colliders")).toBeTruthy();
    expect(await screen.findByTestId("flow-player-runtime")).toBeTruthy();
    expect(physicsMock.props[0]?.colliders).toBe(false);
    expect(collidersMock.props[0]?.world).toBe(world);
    expect(playerRuntimeMock.props[0]?.world).toBe(world);
    expect(playerRuntimeMock.props[0]?.enableCharacterVfx).toBe(true);
  });
});
