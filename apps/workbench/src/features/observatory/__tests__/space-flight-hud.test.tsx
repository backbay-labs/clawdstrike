/**
 * space-flight-hud.test.tsx — Phase 24 HUD-01, HUD-02, HUD-06
 *
 * Unit tests for the Space Flight HUD components:
 * - SpaceFlightHud shell visibility and structure
 * - SpeedIndicator DOM structure
 * - HeadingCompass DOM structure and content
 *
 * No rAF loop behavior is tested here (jsdom doesn't run real rAF) — just DOM structure.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";

// ---------------------------------------------------------------------------
// Mock @react-three/fiber — jsdom has no WebGL context
// ---------------------------------------------------------------------------

vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({
    camera: {
      projectionMatrix: { copy: vi.fn() },
      matrixWorldInverse: { copy: vi.fn() },
      position: { copy: vi.fn() },
      fov: 60,
      aspect: 1,
    },
    invalidate: vi.fn(),
  }),
}));

// ---------------------------------------------------------------------------
// Mock three — prevent WebGL/canvas errors in jsdom
// ---------------------------------------------------------------------------

vi.mock("three", async () => {
  const actual = await vi.importActual<typeof import("three")>("three");
  return {
    ...actual,
    // Quaternion and Euler are used in HeadingCompass — use the real implementations
    // since they don't need WebGL. Only Matrix4 needs to not crash.
    Matrix4: class {
      copy() { return this; }
      elements = new Float32Array(16);
    },
    Vector3: class {
      x = 0; y = 0; z = 0;
      copy() { return this; }
      set(_x: number, _y: number, _z: number) { return this; }
    },
  };
});

// ---------------------------------------------------------------------------
// Mock useHudProjection — prevents import chain from reaching observatory-world-template
// (which calls CatmullRomCurve3 at module scope with a mocked Vector3)
// ---------------------------------------------------------------------------

vi.mock("@/features/observatory/components/hud/useHudProjection", () => ({
  useHudProjection: () => ({ projectionsRef: { current: [] } }),
}));

// ---------------------------------------------------------------------------
// Mock camera-bridge — so SpaceFlightHud doesn't need R3F for tests
// ---------------------------------------------------------------------------

vi.mock("@/features/observatory/components/hud/camera-bridge", () => ({
  hudCameraRef: {
    current: {
      projectionMatrix: { copy: () => ({ multiply: () => ({}) }), elements: new Float32Array(16) },
      matrixWorldInverse: { elements: new Float32Array(16) },
      fov: 60,
      aspect: 1,
      position: { x: 0, y: 80, z: 200 },
    },
  },
  HudCameraBridge: () => null,
}));

// ---------------------------------------------------------------------------
// Mock observatory store
// ---------------------------------------------------------------------------

const mockFlightState = vi.hoisted(() => ({
  velocity: [0, 0, 0] as [number, number, number],
  quaternion: [0, 0, 0, 1] as [number, number, number, number],
  position: [0, 80, 200] as [number, number, number],
  speedTier: "cruise" as const,
  boostActivatedAtMs: null,
  boostOnCooldown: false,
  pointerLocked: false,
  currentSpeed: 0,
  nearestStationId: null,
}));

vi.mock("@/features/observatory/stores/observatory-store", () => ({
  useObservatoryStore: Object.assign(
    vi.fn((selector?: (state: { flightState: typeof mockFlightState }) => unknown) =>
      selector ? selector({ flightState: mockFlightState }) : { flightState: mockFlightState },
    ),
    {
      getState: vi.fn(() => ({ flightState: mockFlightState })),
      use: {},
    },
  ),
}));

// ---------------------------------------------------------------------------
// Import components under test (after mocks)
// ---------------------------------------------------------------------------

import { SpaceFlightHud } from "@/features/observatory/components/hud/SpaceFlightHud";
import { SpeedIndicator } from "@/features/observatory/components/hud/SpeedIndicator";
import { HeadingCompass } from "@/features/observatory/components/hud/HeadingCompass";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SpaceFlightHud (HUD-06)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders with data-testid markers for SpeedIndicator and HeadingCompass", () => {
    render(<SpaceFlightHud visible={true} />);

    expect(screen.getByTestId("hud-speed-indicator")).toBeDefined();
    expect(screen.getByTestId("hud-heading-compass")).toBeDefined();
  });

  it("sets opacity 0 when visible=false (HUD-06: keep mounted, hide via opacity)", () => {
    const { container } = render(<SpaceFlightHud visible={false} />);

    const root = container.firstChild as HTMLElement;
    expect(root.style.opacity).toBe("0");
  });

  it("sets opacity 1 when visible=true", () => {
    const { container } = render(<SpaceFlightHud visible={true} />);

    const root = container.firstChild as HTMLElement;
    expect(root.style.opacity).toBe("1");
  });

  it("always has pointer-events:none on the root container", () => {
    const { container } = render(<SpaceFlightHud visible={true} />);

    const root = container.firstChild as HTMLElement;
    expect(root.style.pointerEvents).toBe("none");
  });
});

describe("SpeedIndicator (HUD-01)", () => {
  beforeEach(() => {
    // Stub requestAnimationFrame to prevent actual loop in tests
    vi.stubGlobal("requestAnimationFrame", vi.fn(() => 1));
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("renders container with data-testid=hud-speed-indicator", () => {
    render(<SpeedIndicator />);
    expect(screen.getByTestId("hud-speed-indicator")).toBeDefined();
  });

  it("contains fill bar with data-testid=hud-speed-fill", () => {
    render(<SpeedIndicator />);
    expect(screen.getByTestId("hud-speed-fill")).toBeDefined();
  });

  it("contains speed readout with data-testid=hud-speed-readout", () => {
    render(<SpeedIndicator />);
    expect(screen.getByTestId("hud-speed-readout")).toBeDefined();
  });
});

describe("HeadingCompass (HUD-02)", () => {
  beforeEach(() => {
    vi.stubGlobal("requestAnimationFrame", vi.fn(() => 1));
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("renders container with data-testid=hud-heading-compass", () => {
    render(<HeadingCompass />);
    expect(screen.getByTestId("hud-heading-compass")).toBeDefined();
  });

  it("contains all four cardinal direction labels", () => {
    render(<HeadingCompass />);
    // Cardinal markers are rendered 3x (once per strip repeat), getAllByText is fine
    expect(screen.getAllByText("N").length).toBeGreaterThan(0);
    expect(screen.getAllByText("E").length).toBeGreaterThan(0);
    expect(screen.getAllByText("S").length).toBeGreaterThan(0);
    expect(screen.getAllByText("W").length).toBeGreaterThan(0);
  });

  it("contains all six station labels", () => {
    render(<HeadingCompass />);
    // Station labels are also rendered 3x — getAllByText
    expect(screen.getAllByText("Horizon").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Subjects").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Operations").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Evidence").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Judgment").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Watchfield").length).toBeGreaterThan(0);
  });
});
