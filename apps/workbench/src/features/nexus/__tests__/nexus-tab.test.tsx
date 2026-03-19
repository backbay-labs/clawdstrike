// Wave 0: NexusTab does not exist yet — tests will fail until 04-02-PLAN.md ships.
// This file establishes the test contract that NexusTab (Plan 02) must satisfy.
//
// NXS-01: NexusTab renders ObservatoryWorldCanvas in atlas mode
// NXS-01: station select calls pane-store.openApp with mapped route

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@testing-library/react";

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
  CameraControls: vi.fn(() => null),
  Line: vi.fn(() => null),
}));

// Mock ObservatoryWorldCanvas to render a div with data-testid and forward onSelectStation
vi.mock(
  "@/features/observatory/components/ObservatoryWorldCanvas",
  () => ({
    ObservatoryWorldCanvas: ({
      mode,
      onSelectStation,
    }: {
      mode?: string;
      onSelectStation?: (stationId: string) => void;
    }) => (
      <div
        data-testid="observatory-world-canvas"
        data-observatory-mode={mode ?? "atlas"}
        onClick={() => onSelectStation?.("signal")}
      />
    ),
  }),
);

// Mock nexus store
vi.mock("@/features/nexus/stores/nexus-store", () => ({
  useNexusStore: {
    use: {
      strikecells: vi.fn(() => []),
    },
  },
}));

// Mock pane store — capture openApp calls
const mockOpenApp = vi.fn();
vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({ openApp: mockOpenApp }),
  },
}));

// @ts-expect-error — NexusTab does not exist yet (Wave 0 scaffold — will be created in 04-02-PLAN.md)
import { NexusTab } from "@/features/nexus/components/NexusTab";

describe("NexusTab (NXS-01 — Wave 0 stubs)", () => {
  beforeEach(() => {
    mockOpenApp.mockClear();
  });

  it("renders ObservatoryWorldCanvas in atlas mode", () => {
    const { getByTestId } = render(<NexusTab />);
    const canvas = getByTestId("observatory-world-canvas");
    expect(canvas).toBeDefined();
    expect(canvas.getAttribute("data-observatory-mode")).toBe("atlas");
  });

  it("station select calls pane-store.openApp with mapped route", () => {
    const { getByTestId } = render(<NexusTab />);
    const canvas = getByTestId("observatory-world-canvas");

    // Clicking the mock canvas fires onSelectStation("signal")
    // signal maps to "security-overview" → STRIKECELL_ROUTE_MAP["security-overview"] = "/home"
    fireEvent.click(canvas);

    expect(mockOpenApp).toHaveBeenCalledWith("/home");
  });
});
