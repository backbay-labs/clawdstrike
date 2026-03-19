// Observatory minimap panel tests (OBS-10)
// Tests: coordinate math, SVG rendering, artifact badge, empty state.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";

// ---------------------------------------------------------------------------
// Mock observatory store
// ---------------------------------------------------------------------------
vi.mock("@/features/observatory/stores/observatory-store", () => ({
  useObservatoryStore: {
    use: {
      stations: vi.fn(() => []),
      seamSummary: vi.fn(() => ({ stationCount: 0, artifactCount: 0, activeProbes: 0 })),
    },
  },
}));

import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { ObservatoryMinimapPanel, polarToSvg } from "@/features/observatory/panels/observatory-minimap-panel";

const mockStations = useObservatoryStore.use.stations as ReturnType<typeof vi.fn>;
const mockSeamSummary = useObservatoryStore.use.seamSummary as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// Unit tests: coordinate math (polarToSvg)
// ---------------------------------------------------------------------------

describe("polarToSvg — coordinate math", () => {
  it("angleDeg=0, radius=1 → x=170, y=100 (right side of 200x200 viewBox)", () => {
    const { x, y } = polarToSvg(0, 1);
    // cx=100, cy=100, RING_R=70: x = 100 + 1*70*cos(0) = 170, y = 100 + 1*70*sin(0) = 100
    expect(x).toBeCloseTo(170, 1);
    expect(y).toBeCloseTo(100, 1);
  });

  it("angleDeg=-132, radius=1 → approximately x≈53, y≈48", () => {
    const { x, y } = polarToSvg(-132, 1);
    // cos(-132°)*70+100 ≈ cos(2.304)*70+100 ≈ (-0.669)*70+100 ≈ 53.2
    // sin(-132°)*70+100 ≈ sin(2.304)*70+100 ≈ (-0.743)*70+100 ≈ 48.0
    expect(x).toBeCloseTo(53.2, 0);
    expect(y).toBeCloseTo(48.0, 0);
  });

  it("angleDeg=90, radius=1 → x=100, y=170 (bottom)", () => {
    const { x, y } = polarToSvg(90, 1);
    expect(x).toBeCloseTo(100, 1);
    expect(y).toBeCloseTo(170, 1);
  });

  it("angleDeg=180, radius=1.26 → x < 100 (left side, perimeter station watch)", () => {
    const { x, y } = polarToSvg(180, 1.26);
    // cos(180°)*70*1.26 = -70*1.26 ≈ -88.2; x = 100 - 88.2 ≈ 11.8
    expect(x).toBeCloseTo(11.8, 0);
    expect(y).toBeCloseTo(100, 1);
  });
});

// ---------------------------------------------------------------------------
// Rendering tests
// ---------------------------------------------------------------------------

describe("ObservatoryMinimapPanel rendering", () => {
  beforeEach(() => {
    mockStations.mockReturnValue([]);
    mockSeamSummary.mockReturnValue({ stationCount: 0, artifactCount: 0, activeProbes: 0 });
  });

  it("renders without crash when stations array is empty", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders an SVG with viewBox='0 0 200 200'", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg[aria-label='Observatory station map']");
    expect(svg).not.toBeNull();
    expect(svg?.getAttribute("viewBox")).toBe("0 0 200 200");
  });

  it("renders center core circle even with empty stations", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // Should have at least a center core circle
    const circles = svg?.querySelectorAll("circle");
    expect(circles).toBeDefined();
    // Ring guide + core fill + core dot = at least 2 core circles
    expect((circles?.length ?? 0)).toBeGreaterThanOrEqual(2);
  });

  it("renders 6 station dots for 6 HUNT_STATION_PLACEMENTS", () => {
    const { container } = render(<ObservatoryMinimapPanel />);
    const svg = container.querySelector("svg");
    // 6 station g elements should be rendered
    const groups = svg?.querySelectorAll("g");
    expect((groups?.length ?? 0)).toBe(6);
  });

  it("does NOT render artifact badge text when artifactCount is 0 for all stations", () => {
    mockStations.mockReturnValue([
      { id: "signal", kind: "hunt", label: "Horizon", route: "/hunt", artifactCount: 0 },
    ]);
    const { container } = render(<ObservatoryMinimapPanel />);
    // Only label texts should be present, no badge numbers
    const allText = Array.from(container.querySelectorAll("text"));
    // Badge text elements are identified by fontWeight="bold" content being a number
    const badgeTexts = allText.filter(
      (t) => t.getAttribute("font-weight") === "bold" && /^\d+$/.test(t.textContent ?? ""),
    );
    expect(badgeTexts).toHaveLength(0);
  });

  it("renders artifact count badge when artifactCount > 0", () => {
    mockStations.mockReturnValue([
      { id: "signal", kind: "hunt", label: "Horizon", route: "/hunt", artifactCount: 5 },
    ]);
    mockSeamSummary.mockReturnValue({ stationCount: 1, artifactCount: 5, activeProbes: 0 });
    const { container } = render(<ObservatoryMinimapPanel />);
    const allText = Array.from(container.querySelectorAll("text"));
    const badgeTexts = allText.filter(
      (t) => t.getAttribute("font-weight") === "bold" && t.textContent === "5",
    );
    expect(badgeTexts).toHaveLength(1);
  });

  it("renders seam summary footer with artifact count", () => {
    mockSeamSummary.mockReturnValue({ stationCount: 2, artifactCount: 7, activeProbes: 0 });
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.textContent).toContain("7 artifacts");
  });

  it("renders 'probe active' when activeProbes > 0", () => {
    mockSeamSummary.mockReturnValue({ stationCount: 1, artifactCount: 2, activeProbes: 1 });
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.textContent).toContain("probe active");
  });

  it("does NOT render 'probe active' when activeProbes = 0", () => {
    mockSeamSummary.mockReturnValue({ stationCount: 0, artifactCount: 0, activeProbes: 0 });
    const { container } = render(<ObservatoryMinimapPanel />);
    expect(container.textContent).not.toContain("probe active");
  });
});
