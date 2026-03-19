// apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx
// Covers OBS-03 (ObservatoryTab renders at /observatory), OBS-04 (probe state machine), OBS-05 (mode toggle)
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, act, fireEvent } from "@testing-library/react";

// Mock @react-three/fiber Canvas — standard jsdom pattern
vi.mock("@react-three/fiber", () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="r3f-canvas">{children}</div>
  ),
  useFrame: vi.fn(),
  useThree: () => ({ invalidate: vi.fn() }),
}));

// Mock drei so Text and other components don't crash in jsdom
vi.mock("@react-three/drei", () => ({
  Text: vi.fn(() => null),
  Stars: vi.fn(() => null),
  OrbitControls: vi.fn(() => null),
  Line: vi.fn(() => null),
}));

// Mock observatory store
vi.mock("@/features/observatory/stores/observatory-store", () => ({
  useObservatoryStore: {
    use: {
      stations: vi.fn(() => []),
    },
  },
}));

// Mock spirit store
vi.mock("@/features/spirit/stores/spirit-store", () => ({
  useSpiritStore: {
    use: {
      kind: vi.fn(() => null),
      accentColor: vi.fn(() => null),
    },
  },
}));

import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { useSpiritStore } from "@/features/spirit/stores/spirit-store";

// @ts-expect-error — ObservatoryTab does not exist yet (Wave 0 scaffold)
import { ObservatoryTab } from "@/features/observatory/components/ObservatoryTab";

const mockUseStations = useObservatoryStore.use.stations as ReturnType<typeof vi.fn>;
const mockUseKind = useSpiritStore.use.kind as ReturnType<typeof vi.fn>;
const mockUseAccentColor = useSpiritStore.use.accentColor as ReturnType<typeof vi.fn>;

describe("ObservatoryTab (OBS-03, OBS-05)", () => {
  beforeEach(() => {
    mockUseStations.mockReturnValue([]);
    mockUseKind.mockReturnValue(null);
    mockUseAccentColor.mockReturnValue(null);
  });

  it("renders without crash when no stations are in the store", () => {
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders without crash when 3 stations are in the store", () => {
    mockUseStations.mockReturnValue([
      { id: "signal", kind: "hunt", label: "Horizon", route: "/hunt", artifactCount: 2 },
      { id: "targets", kind: "hunt", label: "Subjects", route: "/hunt", artifactCount: 0 },
      { id: "run", kind: "hunt", label: "Operations", route: "/hunt", artifactCount: 1 },
    ]);
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders ObservatoryWorldCanvas (r3f-canvas mock) when there are stations", () => {
    mockUseStations.mockReturnValue([
      { id: "signal", kind: "hunt", label: "Horizon", route: "/hunt", artifactCount: 0 },
    ]);
    const { getByTestId } = render(<ObservatoryTab />);
    expect(getByTestId("r3f-canvas")).toBeDefined();
  });

  it("mode prop defaults to atlas on first render", () => {
    // The ObservatoryWorldCanvas receives mode="atlas" by default.
    // We verify the wrapper renders (mode state exists in component).
    const { container } = render(<ObservatoryTab />);
    expect(container.firstChild).not.toBeNull();
    // Detailed mode assertion deferred until setMode is exposed (OBS-05 Task 3)
  });
});

describe("ObservatoryTab — probe state machine (OBS-04)", () => {
  beforeEach(() => {
    mockUseStations.mockReturnValue([]);
    mockUseKind.mockReturnValue(null);
    mockUseAccentColor.mockReturnValue(null);
    // Reset window event listeners between tests
  });

  afterEach(() => {
    // Clean up any lingering event listeners
    vi.restoreAllMocks();
  });

  it("renders with data-observatory-mode=atlas by default", () => {
    const { container } = render(<ObservatoryTab />);
    // The mode indicator div should be present with atlas as default
    const modeDiv = container.querySelector("[data-observatory-mode]");
    expect(modeDiv).not.toBeNull();
    expect(modeDiv?.getAttribute("data-observatory-mode")).toBe("atlas");
  });

  it("registers observatory:probe window event listener on mount", () => {
    const addEventSpy = vi.spyOn(window, "addEventListener");
    render(<ObservatoryTab />);
    const probeListenerRegistered = addEventSpy.mock.calls.some(
      (call) => call[0] === "observatory:probe",
    );
    expect(probeListenerRegistered).toBe(true);
  });

  it("removes observatory:probe window event listener on unmount", () => {
    const removeEventSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = render(<ObservatoryTab />);
    unmount();
    const probeListenerRemoved = removeEventSpy.mock.calls.some(
      (call) => call[0] === "observatory:probe",
    );
    expect(probeListenerRemoved).toBe(true);
  });

  it("ATLAS/FLOW toggle button is rendered in the tab", () => {
    const { getByRole } = render(<ObservatoryTab />);
    // The mode toggle button should be present
    const buttons = document.querySelectorAll("button");
    const toggleBtn = Array.from(buttons).find(
      (btn) => btn.textContent === "ATLAS" || btn.textContent === "FLOW",
    );
    expect(toggleBtn).toBeDefined();
  });

  it("clicking ATLAS button toggles mode to flow", () => {
    const { container, getByText } = render(<ObservatoryTab />);
    const atlasBtn = getByText("ATLAS");
    expect(atlasBtn).toBeDefined();

    act(() => {
      fireEvent.click(atlasBtn);
    });

    // After clicking, mode should switch to flow — button text becomes FLOW
    const modeDiv = container.querySelector("[data-observatory-mode]");
    expect(modeDiv?.getAttribute("data-observatory-mode")).toBe("flow");
  });
});
