import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import * as THREE from "three";
import type { ReactNode } from "react";
import { ObservatoryWorldCanvas } from "@/features/observatory/components/ObservatoryWorldCanvas";

const fiberMock = vi.hoisted(() => ({
  canvasProps: [] as Array<Record<string, unknown>>,
  regress: vi.fn(),
}));

const dreiMock = vi.hoisted(() => ({
  performanceMonitorProps: [] as Array<Record<string, unknown>>,
}));

const flowRuntimeMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
  suspend: false,
  suspension: Promise.resolve(),
}));

const sceneMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
}));

const invalidationMock = vi.hoisted(() => ({
  props: [] as Array<Record<string, unknown>>,
}));

vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children, ...props }: { children?: ReactNode }) => {
    fiberMock.canvasProps.push(props);
    return <div data-testid="r3f-canvas">{children}</div>;
  },
  useFrame: vi.fn(),
  useThree: () => ({
    performance: {
      regress: fiberMock.regress,
    },
  }),
}));

vi.mock("@react-three/rapier", () => ({
  Physics: ({ children }: { children?: ReactNode }) => (
    <div data-testid="physics-runtime">{children}</div>
  ),
  RigidBody: ({ children }: { children?: ReactNode }) => <>{children}</>,
  CapsuleCollider: () => null,
  CuboidCollider: () => null,
  CylinderCollider: () => null,
}));

vi.mock("@react-three/drei", () => ({
  Billboard: ({ children }: { children?: ReactNode }) => <>{children}</>,
  CameraShake: () => null,
  Html: ({ children }: { children?: ReactNode }) => <>{children}</>,
  Line: () => null,
  OrbitControls: () => null,
  PerformanceMonitor: ({ children, ...props }: { children?: ReactNode }) => {
    dreiMock.performanceMonitorProps.push(props);
    return <>{children}</>;
  },
  Sparkles: () => null,
  Stars: () => null,
  Text: ({ children }: { children?: ReactNode }) => <>{children}</>,
  useGLTF: Object.assign(
    vi.fn(() => ({
      scene: new THREE.Group(),
    })),
    { preload: vi.fn() },
  ),
}));

vi.mock("@/features/observatory/components/ObservatoryPostFX", () => ({
  ObservatoryPostFX: () => <div data-testid="observatory-postfx" />,
}));

vi.mock("@/features/observatory/components/world-canvas/ObservatoryWorldScene", () => ({
  ObservatoryWorldScene: (props: Record<string, unknown>) => {
    sceneMock.props.push(props);
    return <div data-testid="observatory-world-scene" />;
  },
}));

vi.mock("@/features/observatory/components/world-canvas/ObservatoryInvalidationController", () => ({
  ObservatoryInvalidationController: (props: Record<string, unknown>) => {
    invalidationMock.props.push(props);
    return null;
  },
}));

vi.mock("@/features/observatory/character/ship/SpaceFlightController", () => ({
  SpaceFlightController: (props: Record<string, unknown>) => {
    flowRuntimeMock.props.push(props);
    if (flowRuntimeMock.suspend) {
      throw flowRuntimeMock.suspension;
    }
    return <div data-testid="observatory-flow-physics-bootstrap" />;
  },
}));

vi.mock("@/features/observatory/vfx/ObservatoryVFXPools", () => ({
  ObservatoryVFXPools: () => <div data-testid="observatory-vfx-pools" />,
}));

vi.mock("@/features/observatory/character/avatar/ObservatoryPlayerAvatar", () => ({
  ObservatoryPlayerAvatar: () => null,
}));

vi.mock("@/features/observatory/character/controller/useObservatoryPlayerRuntime", () => ({
  useObservatoryPlayerRuntime: () => ({
    state: {
      activeAction: null,
      facingRadians: 0,
      grounded: true,
      moveMagnitude: 0,
      moveVector: [0, 0] as [number, number],
      position: [0, 0, 0] as [number, number, number],
      sprinting: false,
      stationId: null,
    },
    step: () => ({
      state: {
        activeAction: null,
        facingRadians: 0,
        grounded: true,
        moveMagnitude: 0,
        moveVector: [0, 0] as [number, number],
        position: [0, 0, 0] as [number, number, number],
        sprinting: false,
        stationId: null,
      },
      command: { linearVelocity: [0, 0, 0] as [number, number, number] },
    }),
    reset: vi.fn(),
  }),
}));

vi.mock("@/features/observatory/character/input/useObservatoryPlayerInput", () => ({
  useObservatoryPlayerInput: () => ({
    intent: { flipBack: false, flipFront: false, interact: false, jump: false },
    consumeTransientActions: vi.fn(),
    reset: vi.fn(),
  }),
}));

vi.mock("@/features/observatory/character/physics/colliders", () => ({
  createObservatoryBoundaryColliders: () => [],
  createObservatoryPlayerCapsuleCollider: (spawn: { position: [number, number, number] }) => ({
    friction: 0.5,
    restitution: 0,
    shape: { halfHeight: 0.46, kind: "capsule", radius: 0.34 },
    translation: spawn.position,
  }),
}));

vi.mock("@/features/observatory/world/deriveObservatoryWorld", () => ({
  deriveObservatoryWorld: ({ mode }: { mode: "atlas" | "flow" }) => ({
    camera: {
      arrivalDurationMs: 1000,
      arrivalLift: 1,
      dampingFactor: 0.1,
      desiredPosition: [0, 5, 10],
      desiredTarget: [0, 0, 0],
      fov: 50,
      initialPosition: [0, 5, 10],
      lerpSpeed: 1,
      maxDistance: 20,
      minDistance: 5,
      missionFocusDwellMs: 0,
      settleRadius: 0.5,
    },
    core: {
      accentColor: "#3dbf84",
      haloOpacity: 0.2,
      outerRingOpacity: 0.2,
    },
    coreLinks: [],
    districts: [],
    environment: {
      ambientColor: "#ffffff",
      ambientIntensity: 0.5,
      backgroundColor: "#000000",
      directionalLightColor: "#ffffff",
      directionalLightIntensity: 1,
      directionalLightPosition: [0, 10, 0],
      floorOpacity: 0.2,
      floorRadius: 20,
      fogColor: "#000000",
      fogFar: 100,
      fogNear: 1,
      gridDivisions: 10,
      gridSize: 20,
      pointLightColor: "#ffffff",
      pointLightIntensity: 0.5,
      pointLightPosition: [0, 5, 0],
      starsCount: 10,
      starsDepth: 10,
      starsFactor: 1,
      starsRadius: 10,
    },
    heroProps: [],
    hypothesisScaffolds: [],
    likelyStationId: null,
    modeProfile: {
      label: mode === "flow" ? "FLOW" : "ATLAS",
      routeOpacityScale: 1,
    },
    receiveState: "idle",
    transitLinks: [],
    watchfield: {
      active: false,
      beaconOpacity: 0.2,
      beaconRadius: 1,
      colorHex: "#ffffff",
      emphasis: 0,
      perimeterInnerRadius: 1,
      perimeterOpacity: 0.2,
      perimeterOuterRadius: 2,
      position: [0, 0, 0],
      ringPoints: [],
      secondaryRingInnerRadius: 1,
      secondaryRingOpacity: 0.2,
      secondaryRingOuterRadius: 2,
    },
  }),
}));

vi.mock("@/features/observatory/world/grounding", () => ({
  resolveObservatoryTraversalHalfExtents: () => [1, 1, 1],
  shouldAdhereObservatoryPlayerToGround: () => false,
}));

vi.mock("@/features/observatory/world/missionLoop", () => ({
  OBSERVATORY_MISSION_OBJECTIVES: [],
  getCurrentObservatoryMissionObjective: () => null,
  isObservatoryMissionObjectiveProp: () => false,
  resolveObservatoryMissionProbeTargetStationId: () => null,
}));

vi.mock("@/features/observatory/world/probeRuntime", () => ({
  OBSERVATORY_PROBE_ACTIVE_MS: 1800,
  advanceObservatoryProbeState: <T,>(state: T) => state,
  canDispatchObservatoryProbe: () => false,
  createInitialObservatoryProbeState: () => ({
    activeUntilMs: null,
    cooldownUntilMs: null,
    status: "ready" as const,
    targetStationId: null,
  }),
  dispatchObservatoryProbe: <T,>(state: T) => state,
  getObservatoryProbeCharge: () => 0,
  getObservatoryProbeRemainingMs: () => 0,
}));

vi.mock("@/features/observatory/world/probeConsequences", () => ({
  applyObservatoryProbeConsequences: (world: unknown) => ({
    directive: null,
    world,
  }),
}));

vi.mock("@/features/observatory/vfx/ProbeDischargeVFX", () => ({
  ProbeDischargeVFX: () => null,
}));

vi.mock("@/features/observatory/vfx/CharacterVFX", () => ({
  CharacterVFX: () => null,
}));

vi.mock("@/features/observatory/world/npcCrew", () => ({
  StationNpcCrew: () => null,
}));

vi.mock("@/features/observatory/world/districtGeometry", () => ({
  SpaceStationMesh: () => null,
}));

vi.mock("@/features/observatory/utils/buildSpiritLut", () => ({
  buildSpiritLut: () => null,
}));

const sceneState = {
  activeSelection: { type: "none" as const },
  cameraPreset: "overview" as const,
  confidence: 0.5,
  huntId: "workbench",
  likelyStationId: null,
  mode: "atlas" as const,
  openedDetailSurface: "none" as const,
  roomReceiveState: "idle" as const,
  spiritFieldBias: 0,
  stations: [],
};

const baseProps = {
  activeStationId: null,
  mission: null,
  probeState: {
    activeUntilMs: null,
    cooldownUntilMs: null,
    status: "ready" as const,
    targetStationId: null,
  },
  sceneState,
};

describe("ObservatoryWorldCanvas performance flags", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    // Ensure consistent hardware profile across local (high-core) and CI (low-core) environments
    Object.defineProperty(navigator, "hardwareConcurrency", { configurable: true, value: 8 });
    fiberMock.canvasProps.length = 0;
    fiberMock.regress.mockReset();
    dreiMock.performanceMonitorProps.length = 0;
    flowRuntimeMock.props.length = 0;
    flowRuntimeMock.suspend = false;
    flowRuntimeMock.suspension = Promise.resolve();
    sceneMock.props.length = 0;
    invalidationMock.props.length = 0;
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockReturnValue({
        addEventListener: vi.fn(),
        addListener: vi.fn(),
        dispatchEvent: vi.fn(),
        matches: false,
        media: "(prefers-reduced-motion: reduce)",
        onchange: null,
        removeEventListener: vi.fn(),
        removeListener: vi.fn(),
      }),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps atlas mode on the lighter runtime path", async () => {
    render(<ObservatoryWorldCanvas {...baseProps} mode="atlas" />);

    expect(screen.queryByTestId("observatory-flow-runtime")).toBeNull();
    expect(screen.queryByTestId("observatory-vfx-pools")).toBeNull();
    expect(await screen.findByTestId("observatory-postfx")).toBeTruthy();
    expect(screen.getByTestId("observatory-world-scene")).toBeTruthy();
    expect(fiberMock.canvasProps[fiberMock.canvasProps.length - 1]?.dpr).toEqual([1, 1.2]);
    expect(invalidationMock.props[invalidationMock.props.length - 1]?.sources).toBeDefined();
  });

  it("mounts the flow bootstrap and richer quality settings in flow mode", async () => {
    render(
      <ObservatoryWorldCanvas
        {...baseProps}
        mode="flow"
        playerInputEnabled
        sceneState={{ ...sceneState, mode: "flow" }}
      />,
    );

    expect(await screen.findByTestId("observatory-flow-physics-bootstrap")).toBeTruthy();
    expect(await screen.findByTestId("observatory-postfx")).toBeTruthy();
    expect(await screen.findByTestId("observatory-vfx-pools")).toBeTruthy();
    expect(flowRuntimeMock.props[flowRuntimeMock.props.length - 1]?.inputEnabled).toBe(true);
    expect(fiberMock.canvasProps[fiberMock.canvasProps.length - 1]?.dpr).toEqual([1, 1.5]);
    expect(sceneMock.props[sceneMock.props.length - 1]?.missionTargetStationId).toBeNull();
  });

  it("keeps idle flow on demand while still mounting the scene shell", async () => {
    render(
      <ObservatoryWorldCanvas
        {...baseProps}
        mode="flow"
        playerInputEnabled={false}
        sceneState={{ ...sceneState, mode: "flow" }}
      />,
    );

    expect(await screen.findByTestId("observatory-world-scene")).toBeTruthy();
    expect(fiberMock.canvasProps[fiberMock.canvasProps.length - 1]?.frameloop).toBe("demand");
  });

  it("keeps realtime rendering during fly-by and probe-active windows", async () => {
    render(
      <ObservatoryWorldCanvas
        {...baseProps}
        flyByActive
        mode="atlas"
        probeState={{ ...baseProps.probeState, status: "active", targetStationId: "signal" }}
      />,
    );

    expect(await screen.findByTestId("observatory-world-scene")).toBeTruthy();
    expect(fiberMock.canvasProps[fiberMock.canvasProps.length - 1]?.frameloop).toBe("always");
    const lastInvalidation = invalidationMock.props[invalidationMock.props.length - 1] as {
      sources?: { flyByActive?: boolean };
    };
    expect(lastInvalidation.sources?.flyByActive).toBe(true);
  });

  it("invalidates replay frame changes without forcing the canvas into permanent realtime mode", async () => {
    render(
      <ObservatoryWorldCanvas
        {...baseProps}
        mode="atlas"
        replayFrameIndex={8}
      />,
    );

    expect(await screen.findByTestId("observatory-world-scene")).toBeTruthy();
    expect(fiberMock.canvasProps[fiberMock.canvasProps.length - 1]?.frameloop).toBe("demand");
    const lastInvalidation = invalidationMock.props[invalidationMock.props.length - 1] as {
      sources?: { replayFrameIndex?: number };
    };
    expect(lastInvalidation.sources?.replayFrameIndex).toBe(8);
  });

  it("drops to the low runtime profile after a monitor decline", async () => {
    render(
      <ObservatoryWorldCanvas
        {...baseProps}
        mode="flow"
        playerInputEnabled
        sceneState={{ ...sceneState, mode: "flow" }}
      />,
    );

    expect(await screen.findByTestId("observatory-vfx-pools")).toBeTruthy();

    act(() => {
      const props = dreiMock.performanceMonitorProps[dreiMock.performanceMonitorProps.length - 1] as {
        onDecline?: () => void;
      };
      props.onDecline?.();
    });

    await waitFor(() => {
      expect(fiberMock.canvasProps[fiberMock.canvasProps.length - 1]?.dpr).toEqual([1, 1.1]);
    });
    await waitFor(() => {
      expect(screen.queryByTestId("observatory-vfx-pools")).toBeNull();
    });
    // SpaceFlightController does not receive enableCharacterVfx — flight controller handles its own VFX
    expect(flowRuntimeMock.props[flowRuntimeMock.props.length - 1]?.inputEnabled).toBeDefined();
  });

  it("keeps post fx visible while the flow runtime boundary is still loading", async () => {
    flowRuntimeMock.suspend = true;
    flowRuntimeMock.suspension = new Promise(() => {});

    render(
      <ObservatoryWorldCanvas
        {...baseProps}
        mode="flow"
        playerInputEnabled
        sceneState={{ ...sceneState, mode: "flow" }}
      />,
    );

    expect(await screen.findByTestId("observatory-postfx")).toBeTruthy();
    expect(flowRuntimeMock.props.length).toBeGreaterThan(0);
    expect(screen.queryByTestId("observatory-flow-physics-bootstrap")).toBeNull();
  });
});
