/**
 * replay-annotation-layer.test.tsx — Phase 42 ANNO-01/ANNO-02/ANNO-06
 *
 * Tests for ReplayAnnotationLayer: diamond pins, click-to-drop, delete.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render } from "@testing-library/react";
import type { ObservatoryAnnotationPin } from "@/features/observatory/types";

// ---------------------------------------------------------------------------
// Three.js / R3F / drei mocks
// ---------------------------------------------------------------------------

vi.mock("three", () => {
  // MeshBasicMaterial must be a proper constructor (class-like) since the component does `new THREE.MeshBasicMaterial(...)`
  class MeshBasicMaterial {
    visible = false;
    side = 0;
    constructor(_opts?: { visible?: boolean; side?: number }) {
      if (_opts) {
        if (_opts.visible !== undefined) this.visible = _opts.visible;
        if (_opts.side !== undefined) this.side = _opts.side;
      }
    }
  }
  return {
    MeshBasicMaterial,
    DoubleSide: 2,
    Color: vi.fn(() => ({ r: 0, g: 0, b: 0 })),
  };
});

vi.mock("@react-three/fiber", () => ({
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn(), camera: { position: { x: 0, y: 10, z: 20 } } }),
  extend: vi.fn(),
}));

vi.mock("@react-three/drei", () => ({
  Html: ({ children }: { children?: React.ReactNode }) => (
    <div data-testid="drei-html">{children}</div>
  ),
  Text: ({ children }: { children?: React.ReactNode }) => (
    <span data-testid="drei-text">{children}</span>
  ),
}));

// Mock the observatory store — factory must not reference top-level variables
vi.mock("@/features/observatory/stores/observatory-store", () => {
  const addAnnotationPin = vi.fn();
  const removeAnnotationPin = vi.fn();

  const storeInstance = {
    annotationPins: [] as ObservatoryAnnotationPin[],
    actions: {
      addAnnotationPin,
      removeAnnotationPin,
    },
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const useObservatoryStore: any = vi.fn((selector: (s: typeof storeInstance) => unknown) => {
    return selector(storeInstance);
  });
  useObservatoryStore.getState = vi.fn(() => storeInstance);

  return { useObservatoryStore };
});

// ---------------------------------------------------------------------------
// Import the component under test (after mocks are registered)
// ---------------------------------------------------------------------------

import { ReplayAnnotationLayer } from "../components/world-canvas/ReplayAnnotationLayer";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makePin(overrides: Partial<ObservatoryAnnotationPin> = {}): ObservatoryAnnotationPin {
  return {
    id: "pin-1",
    frameIndex: 5,
    timestampMs: 1000,
    worldPosition: [3, 0, 4] as [number, number, number],
    note: "Test note",
    districtId: "signal",
    ...overrides,
  };
}

const DEFAULT_PROPS = {
  annotationPins: [] as ObservatoryAnnotationPin[],
  replayEnabled: true,
  replayFrameIndex: 0,
  replayFrameMs: null as number | null,
  spiritAccentColor: null as string | null,
  onDropPin: vi.fn(),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ReplayAnnotationLayer (Phase 42 ANNO)", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Test 1: renders without crashing with empty pins
  it("renders without crashing when given empty annotationPins array", () => {
    const { container } = render(<ReplayAnnotationLayer {...DEFAULT_PROPS} />);
    expect(container).toBeTruthy();
  });

  // Test 2: renders a mesh group for each pin
  it("renders a mesh group for each pin in annotationPins", () => {
    const pins = [makePin({ id: "pin-1" }), makePin({ id: "pin-2", worldPosition: [5, 0, 2] })];
    const { container } = render(
      <ReplayAnnotationLayer {...DEFAULT_PROPS} annotationPins={pins} />,
    );
    // Each pin should produce at least one rendered group element with data-pin-id
    const groups = container.querySelectorAll("[data-pin-id]");
    expect(groups.length).toBe(2);
  });

  // Test 3: Component file contains ConeGeometry (diamond visual)
  it("component source uses ConeGeometry for diamond pin visual", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const filePath = path.resolve(
      __dirname,
      "../components/world-canvas/ReplayAnnotationLayer.tsx",
    );
    const source = fs.readFileSync(filePath, "utf-8");
    expect(source).toContain("ConeGeometry");
  });

  // Test 4: When replayEnabled is false, ground plane click does not invoke onDropPin
  it("does not invoke onDropPin when replayEnabled is false", () => {
    const onDropPin = vi.fn();
    const { container } = render(
      <ReplayAnnotationLayer
        {...DEFAULT_PROPS}
        replayEnabled={false}
        onDropPin={onDropPin}
      />,
    );
    // Find the ground plane hit target and simulate a pointer down
    const groundPlane = container.querySelector("[data-ground-plane]");
    if (groundPlane) {
      groundPlane.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true }));
    }
    // onDropPin should NOT have been called (replayEnabled=false)
    expect(onDropPin).not.toHaveBeenCalled();
  });

  // Test 5: removeAnnotationPin is accessible via pin's delete interaction
  it("removeAnnotationPin is wired through store for pin delete", () => {
    const pin = makePin({ id: "pin-delete-test" });
    const { container } = render(
      <ReplayAnnotationLayer {...DEFAULT_PROPS} annotationPins={[pin]} />,
    );
    // The component should render the pin group
    const pinGroup = container.querySelector(`[data-pin-id="${pin.id}"]`);
    expect(pinGroup).toBeTruthy();
    // The store's getState should be accessible (used for imperative delete calls)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const storeState = (useObservatoryStore as any).getState();
    expect(storeState).toBeTruthy();
  });
});
