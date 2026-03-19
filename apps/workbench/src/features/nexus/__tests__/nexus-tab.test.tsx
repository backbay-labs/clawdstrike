// NexusTab tests — NXS-01 (atlas view) + NXS-02 (layout toggle)
//
// NXS-01: NexusTab renders ObservatoryWorldCanvas in atlas mode
// NXS-01: station select calls pane-store.openApp with mapped route
// NXS-02: toggle button switches between atlas and force-directed views

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

// Mock NexusForceCanvas
vi.mock("@/features/nexus/components/NexusForceCanvas", () => ({
  NexusForceCanvas: () => <div data-testid="nexus-force-canvas" />,
}));

// Track layoutMode state for tests
let mockLayoutMode = "radial";
const mockSetLayoutMode = vi.fn((mode: string) => {
  mockLayoutMode = mode;
});

// Mock nexus store — includes layoutMode + setLayoutMode
vi.mock("@/features/nexus/stores/nexus-store", () => ({
  useNexusStore: {
    use: {
      strikecells: vi.fn(() => []),
      layoutMode: vi.fn(() => mockLayoutMode),
    },
    getState: () => ({
      actions: { setLayoutMode: mockSetLayoutMode },
    }),
  },
}));

// Mock pane store — capture openApp calls
const mockOpenApp = vi.fn();
vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({ openApp: mockOpenApp }),
  },
}));

import { NexusTab } from "@/features/nexus/components/NexusTab";
import { useNexusStore } from "@/features/nexus/stores/nexus-store";

describe("NexusTab (NXS-01 — atlas mode)", () => {
  beforeEach(() => {
    mockOpenApp.mockClear();
    mockSetLayoutMode.mockClear();
    mockLayoutMode = "radial";
    (useNexusStore.use.layoutMode as ReturnType<typeof vi.fn>).mockReturnValue("radial");
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

describe("NexusTab layout toggle (NXS-02)", () => {
  beforeEach(() => {
    mockOpenApp.mockClear();
    mockSetLayoutMode.mockClear();
    mockLayoutMode = "radial";
    (useNexusStore.use.layoutMode as ReturnType<typeof vi.fn>).mockReturnValue("radial");
  });

  it("renders atlas view (ObservatoryWorldCanvas) by default", () => {
    const { getByTestId, queryByTestId } = render(<NexusTab />);
    expect(getByTestId("observatory-world-canvas")).toBeDefined();
    expect(queryByTestId("nexus-force-canvas")).toBeNull();
  });

  it("toggle button reads 'Force Graph' in atlas mode", () => {
    const { getByTestId } = render(<NexusTab />);
    const btn = getByTestId("nexus-layout-toggle");
    expect(btn.textContent).toBe("Force Graph");
  });

  it("clicking toggle calls setLayoutMode('force-directed')", () => {
    const { getByTestId } = render(<NexusTab />);
    fireEvent.click(getByTestId("nexus-layout-toggle"));
    expect(mockSetLayoutMode).toHaveBeenCalledWith("force-directed");
  });

  it("renders NexusForceCanvas when layoutMode is force-directed", () => {
    mockLayoutMode = "force-directed";
    (useNexusStore.use.layoutMode as ReturnType<typeof vi.fn>).mockReturnValue("force-directed");
    const { getByTestId, queryByTestId } = render(<NexusTab />);
    expect(getByTestId("nexus-force-canvas")).toBeDefined();
    expect(queryByTestId("observatory-world-canvas")).toBeNull();
  });

  it("toggle button reads 'Atlas View' in force-directed mode", () => {
    mockLayoutMode = "force-directed";
    (useNexusStore.use.layoutMode as ReturnType<typeof vi.fn>).mockReturnValue("force-directed");
    const { getByTestId } = render(<NexusTab />);
    expect(getByTestId("nexus-layout-toggle").textContent).toBe("Atlas View");
  });
});
