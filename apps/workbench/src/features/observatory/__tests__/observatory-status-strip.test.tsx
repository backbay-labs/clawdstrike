/**
 * observatory-status-strip.test.tsx
 *
 * Unit tests for ObservatoryStatusStrip:
 *   - Rendering (data-testids present)
 *   - Four analyst preset buttons visible with correct labels
 *   - Clicking a preset sets analystPresetId in store
 *   - Clicking the active preset deactivates it (radio-toggle)
 *   - Only one preset can be active at a time
 *   - Speed, heading, and station count elements are present
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, fireEvent } from "@testing-library/react";
import { ObservatoryStatusStrip } from "../components/hud/ObservatoryStatusStrip";
import { useObservatoryStore } from "../stores/observatory-store";

// Mock THREE to avoid WebGL in jsdom
vi.mock("three", () => ({
  Quaternion: class {
    set() {}
  },
  Euler: class {
    y = 0;
    setFromQuaternion() {}
  },
}));

// Mock requestAnimationFrame: invoke the callback once synchronously on the first call,
// then return a no-op handle so the loop does not recurse infinitely.
let rafCallCount = 0;
vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
  if (rafCallCount === 0) {
    rafCallCount += 1;
    cb(0);
  }
  return 1;
});
vi.stubGlobal("cancelAnimationFrame", vi.fn());

const initialState = useObservatoryStore.getState();

const defaultProps = {
  mode: "atlas" as const,
  onModeToggle: vi.fn(),
};

describe("ObservatoryStatusStrip", () => {
  beforeEach(() => {
    useObservatoryStore.setState({
      ...initialState,
      analystPresetId: null,
      activePanel: null,
    });
    defaultProps.onModeToggle.mockReset();
  });

  it("renders the status strip with data-testid", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const strip = container.querySelector("[data-testid='observatory-status-strip']");
    expect(strip).not.toBeNull();
  });

  it("shows four analyst preset buttons with correct labels", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    expect(container.querySelector("[data-testid='status-strip-preset-threat']")).not.toBeNull();
    expect(container.querySelector("[data-testid='status-strip-preset-evidence']")).not.toBeNull();
    expect(container.querySelector("[data-testid='status-strip-preset-receipts']")).not.toBeNull();
    expect(container.querySelector("[data-testid='status-strip-preset-ghost']")).not.toBeNull();
    expect(container.textContent).toContain("THREAT");
    expect(container.textContent).toContain("EVIDENCE");
    expect(container.textContent).toContain("RECEIPTS");
    expect(container.textContent).toContain("GHOST");
  });

  it("clicking a preset sets analystPresetId in store", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const threatBtn = container.querySelector("[data-testid='status-strip-preset-threat']");
    expect(threatBtn).not.toBeNull();
    fireEvent.click(threatBtn as HTMLButtonElement);
    expect(useObservatoryStore.getState().analystPresetId).toBe("threat");
  });

  it("clicking the active preset deactivates it (radio-toggle)", () => {
    useObservatoryStore.setState({ ...useObservatoryStore.getState(), analystPresetId: "threat" });
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const threatBtn = container.querySelector("[data-testid='status-strip-preset-threat']");
    expect(threatBtn).not.toBeNull();
    fireEvent.click(threatBtn as HTMLButtonElement);
    expect(useObservatoryStore.getState().analystPresetId).toBeNull();
  });

  it("only one preset can be active at a time", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const threatBtn = container.querySelector("[data-testid='status-strip-preset-threat']");
    const evidenceBtn = container.querySelector("[data-testid='status-strip-preset-evidence']");
    expect(threatBtn).not.toBeNull();
    expect(evidenceBtn).not.toBeNull();
    fireEvent.click(threatBtn as HTMLButtonElement);
    expect(useObservatoryStore.getState().analystPresetId).toBe("threat");
    fireEvent.click(evidenceBtn as HTMLButtonElement);
    expect(useObservatoryStore.getState().analystPresetId).toBe("evidence");
  });

  it("displays speed, heading, and station count elements", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    expect(container.querySelector("[data-testid='status-strip-speed']")).not.toBeNull();
    expect(container.querySelector("[data-testid='status-strip-heading']")).not.toBeNull();
    expect(container.querySelector("[data-testid='status-strip-station-count']")).not.toBeNull();
  });

  it("renders the ATLAS/FLOW mode toggle segment", () => {
    const { container } = render(<ObservatoryStatusStrip mode="atlas" onModeToggle={vi.fn()} />);
    const modeToggle = container.querySelector("[data-testid='status-strip-mode-toggle']");
    expect(modeToggle).not.toBeNull();
    expect(modeToggle?.textContent).toContain("ATLAS");
  });

  it("shows FLOW label when mode is flow", () => {
    const { container } = render(<ObservatoryStatusStrip mode="flow" onModeToggle={vi.fn()} />);
    const modeToggle = container.querySelector("[data-testid='status-strip-mode-toggle']");
    expect(modeToggle).not.toBeNull();
    expect(modeToggle?.textContent).toContain("FLOW");
  });

  it("calls onModeToggle when the mode toggle is clicked", () => {
    const mockFn = vi.fn();
    const { container } = render(<ObservatoryStatusStrip mode="atlas" onModeToggle={mockFn} />);
    const modeToggle = container.querySelector("[data-testid='status-strip-mode-toggle']");
    expect(modeToggle).not.toBeNull();
    fireEvent.click(modeToggle as HTMLButtonElement);
    expect(mockFn).toHaveBeenCalledOnce();
  });

  it("mode toggle and analyst presets coexist in the status strip", () => {
    const { container } = render(<ObservatoryStatusStrip mode="atlas" onModeToggle={vi.fn()} />);
    expect(container.querySelector("[data-testid='status-strip-mode-toggle']")).not.toBeNull();
    expect(container.querySelector("[data-testid='status-strip-preset-threat']")).not.toBeNull();
  });

  it("STS-01: status strip has a visible top border with 0.12 opacity", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const strip = container.querySelector("[data-testid='observatory-status-strip']") as HTMLElement;
    expect(strip).not.toBeNull();
    expect(strip.style.borderTop).toContain("0.12");
    expect(strip.style.borderTop).toContain("solid");
  });

  it("STS-02: telemetry text is at least 11px", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const strip = container.querySelector("[data-testid='observatory-status-strip']") as HTMLElement;
    expect(strip).not.toBeNull();
    // fontSize is set as a numeric 11 in inline styles; jsdom serializes it as "11px"
    const size = parseInt(strip.style.fontSize, 10);
    expect(size).toBeGreaterThanOrEqual(11);
  });

  it("STS-02: telemetry text opacity is at least 0.8", () => {
    const { container } = render(<ObservatoryStatusStrip {...defaultProps} />);
    const speedEl = container.querySelector("[data-testid='status-strip-speed']") as HTMLElement;
    expect(speedEl).not.toBeNull();
    // color is "var(--hud-text, rgba(255, 255, 255, 0.85))" — contains 0.85
    expect(speedEl.style.color).toContain("0.85");
  });
});
