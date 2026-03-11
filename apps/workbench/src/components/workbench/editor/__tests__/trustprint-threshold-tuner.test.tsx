import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TrustprintThresholdTuner } from "../trustprint-threshold-tuner";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function defaultProps(overrides: Partial<React.ComponentProps<typeof TrustprintThresholdTuner>> = {}) {
  return {
    threshold: 0.85,
    ambiguityBand: 0.1,
    onThresholdChange: vi.fn(),
    onAmbiguityBandChange: vi.fn(),
    ...overrides,
  };
}

// SVG getBBox and other geometry methods are not implemented in jsdom.
// Mock ResizeObserver to provide a synthetic width so the component can compute
// pixel positions without a real layout engine.
const resizeCallbacks: ResizeObserverCallback[] = [];

class MockResizeObserver implements ResizeObserver {
  private cb: ResizeObserverCallback;
  constructor(cb: ResizeObserverCallback) {
    this.cb = cb;
    resizeCallbacks.push(cb);
  }
  observe(target: Element) {
    // Fire immediately with a synthetic entry
    this.cb(
      [
        {
          target,
          contentRect: { width: 400, height: 120, x: 0, y: 0, top: 0, left: 0, bottom: 120, right: 400, toJSON: () => ({}) } as DOMRectReadOnly,
          borderBoxSize: [],
          contentBoxSize: [],
          devicePixelContentBoxSize: [],
        },
      ] as ResizeObserverEntry[],
      this,
    );
  }
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  resizeCallbacks.length = 0;
  vi.stubGlobal("ResizeObserver", MockResizeObserver);
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TrustprintThresholdTuner", () => {
  // -----------------------------------------------------------------------
  // Rendering — zone proportions
  // -----------------------------------------------------------------------

  it("renders three zones with correct proportions", () => {
    const props = defaultProps({ threshold: 0.85, ambiguityBand: 0.1 });
    render(<TrustprintThresholdTuner {...props} />);

    const allowZone = screen.getByTestId("zone-allow");
    const ambiguousZone = screen.getByTestId("zone-ambiguous");
    const denyZone = screen.getByTestId("zone-deny");

    expect(allowZone).toBeInTheDocument();
    expect(ambiguousZone).toBeInTheDocument();
    expect(denyZone).toBeInTheDocument();

    // With threshold=0.85 and band=0.10:
    //   lower = 0.75, upper = 0.95
    //   allow width = 0.75 * barWidth
    //   ambiguous width = 0.20 * barWidth
    //   deny width = 0.05 * barWidth
    //
    // barWidth = 400 - 24*2 = 352
    const barWidth = 352;
    const allowW = parseFloat(allowZone.getAttribute("width") ?? "0");
    const ambiguousW = parseFloat(ambiguousZone.getAttribute("width") ?? "0");
    const denyW = parseFloat(denyZone.getAttribute("width") ?? "0");

    expect(allowW).toBeCloseTo(0.75 * barWidth, 0);
    expect(ambiguousW).toBeCloseTo(0.20 * barWidth, 0);
    expect(denyW).toBeCloseTo(0.05 * barWidth, 0);
  });

  it("renders zone labels ALLOW, AMBIGUOUS, DENY", () => {
    const props = defaultProps({ threshold: 0.5, ambiguityBand: 0.15 });
    render(<TrustprintThresholdTuner {...props} />);

    expect(screen.getByTestId("zone-label-allow")).toHaveTextContent("ALLOW");
    expect(screen.getByTestId("zone-label-ambiguous")).toHaveTextContent("AMBIGUOUS");
    expect(screen.getByTestId("zone-label-deny")).toHaveTextContent("DENY");
  });

  it("shows boundary value labels", () => {
    const props = defaultProps({ threshold: 0.85, ambiguityBand: 0.1 });
    render(<TrustprintThresholdTuner {...props} />);

    expect(screen.getByTestId("label-lower")).toHaveTextContent("0.75");
    expect(screen.getByTestId("label-threshold")).toHaveTextContent("0.85");
    expect(screen.getByTestId("label-upper")).toHaveTextContent("0.95");
  });

  // -----------------------------------------------------------------------
  // Preset buttons
  // -----------------------------------------------------------------------

  it("renders preset buttons", () => {
    const props = defaultProps();
    render(<TrustprintThresholdTuner {...props} />);

    expect(screen.getByTestId("preset-permissive")).toBeInTheDocument();
    expect(screen.getByTestId("preset-balanced")).toBeInTheDocument();
    expect(screen.getByTestId("preset-strict")).toBeInTheDocument();
  });

  it("preset buttons update values correctly", async () => {
    const user = userEvent.setup();
    const onThresholdChange = vi.fn();
    const onAmbiguityBandChange = vi.fn();
    render(
      <TrustprintThresholdTuner
        threshold={0.5}
        ambiguityBand={0.05}
        onThresholdChange={onThresholdChange}
        onAmbiguityBandChange={onAmbiguityBandChange}
      />,
    );

    // Click "Permissive" -> threshold 0.70, band 0.15
    await user.click(screen.getByTestId("preset-permissive"));
    expect(onThresholdChange).toHaveBeenCalledWith(0.7);
    expect(onAmbiguityBandChange).toHaveBeenCalledWith(0.15);

    onThresholdChange.mockClear();
    onAmbiguityBandChange.mockClear();

    // Click "Balanced" -> threshold 0.85, band 0.10
    await user.click(screen.getByTestId("preset-balanced"));
    expect(onThresholdChange).toHaveBeenCalledWith(0.85);
    expect(onAmbiguityBandChange).toHaveBeenCalledWith(0.1);

    onThresholdChange.mockClear();
    onAmbiguityBandChange.mockClear();

    // Click "Strict" -> threshold 0.95, band 0.05
    await user.click(screen.getByTestId("preset-strict"));
    expect(onThresholdChange).toHaveBeenCalledWith(0.95);
    expect(onAmbiguityBandChange).toHaveBeenCalledWith(0.05);
  });

  it("highlights the active preset", () => {
    const props = defaultProps({ threshold: 0.85, ambiguityBand: 0.1 });
    render(<TrustprintThresholdTuner {...props} />);

    const balanced = screen.getByTestId("preset-balanced");
    // Active preset has gold background styling
    expect(balanced.className).toContain("bg-[#d4a84b]/15");

    const permissive = screen.getByTestId("preset-permissive");
    // Inactive preset should NOT have gold background
    expect(permissive.className).not.toContain("bg-[#d4a84b]/15");
  });

  it("orders presets from most permissive to most strict", async () => {
    const user = userEvent.setup();
    const seen: Array<{ threshold: number; band: number }> = [];
    render(
      <TrustprintThresholdTuner
        threshold={0.5}
        ambiguityBand={0.05}
        onThresholdChange={(threshold) => {
          const last = seen[seen.length - 1];
          if (last && last.band === 0) {
            last.threshold = threshold;
            return;
          }
          seen.push({ threshold, band: 0 });
        }}
        onAmbiguityBandChange={(band) => {
          const last = seen[seen.length - 1];
          if (last) last.band = band;
        }}
      />,
    );

    await user.click(screen.getByTestId("preset-permissive"));
    await user.click(screen.getByTestId("preset-balanced"));
    await user.click(screen.getByTestId("preset-strict"));

    const permissive = seen[0];
    const balanced = seen[1];
    const strict = seen[2];

    expect(permissive.threshold).toBeLessThan(balanced.threshold);
    expect(balanced.threshold).toBeLessThan(strict.threshold);
    expect(permissive.band).toBeGreaterThan(balanced.band);
    expect(balanced.band).toBeGreaterThan(strict.band);
    expect(permissive.threshold + permissive.band).toBeLessThan(
      balanced.threshold + balanced.band,
    );
    expect(balanced.threshold + balanced.band).toBeLessThan(
      strict.threshold + strict.band,
    );
  });

  // -----------------------------------------------------------------------
  // Boundary clamping
  // -----------------------------------------------------------------------

  it("clamps zone boundaries to valid range", () => {
    // threshold 0.95 + band 0.10 would put upper at 1.05, which must clamp to 1.0
    const props = defaultProps({ threshold: 0.95, ambiguityBand: 0.1 });
    render(<TrustprintThresholdTuner {...props} />);

    const denyZone = screen.getByTestId("zone-deny");
    // Upper bound clamped to 1.0, so deny zone width should be 0
    const denyW = parseFloat(denyZone.getAttribute("width") ?? "0");
    // Band exceeds maxBand(0.95)=0.05, but the component displays based on
    // Math.min(threshold + band, 1.0) = 1.0, so deny width should be ~0
    expect(denyW).toBeLessThanOrEqual(1);
  });

  it("clamps lower boundary to 0 when band exceeds threshold", () => {
    // threshold 0.05 + band 0.10 would put lower at -0.05, clamped to 0.0
    const props = defaultProps({ threshold: 0.05, ambiguityBand: 0.1 });
    render(<TrustprintThresholdTuner {...props} />);

    const allowZone = screen.getByTestId("zone-allow");
    const allowW = parseFloat(allowZone.getAttribute("width") ?? "0");
    // lower bound = max(0.05 - 0.10, 0) = 0.0, so allow zone has 0 width
    expect(allowW).toBeLessThanOrEqual(1);
  });

  // -----------------------------------------------------------------------
  // Compact mode
  // -----------------------------------------------------------------------

  it("compact mode renders smaller SVG", () => {
    const props = defaultProps({ compact: true });
    render(<TrustprintThresholdTuner {...props} />);

    const wrapper = screen.getByTestId("threshold-tuner-compact");
    expect(wrapper).toBeInTheDocument();

    // Should NOT have presets
    expect(screen.queryByTestId("presets")).not.toBeInTheDocument();

    // Should NOT have drag handles
    expect(screen.queryByTestId("handle-threshold")).not.toBeInTheDocument();
    expect(screen.queryByTestId("handle-lower")).not.toBeInTheDocument();
    expect(screen.queryByTestId("handle-upper")).not.toBeInTheDocument();
  });

  it("compact mode still renders three zones", () => {
    const props = defaultProps({ compact: true });
    render(<TrustprintThresholdTuner {...props} />);

    expect(screen.getByTestId("zone-allow")).toBeInTheDocument();
    expect(screen.getByTestId("zone-ambiguous")).toBeInTheDocument();
    expect(screen.getByTestId("zone-deny")).toBeInTheDocument();
  });

  it("compact mode SVG has correct height attribute", () => {
    const props = defaultProps({ compact: true });
    render(<TrustprintThresholdTuner {...props} />);

    const svg = screen.getByTestId("threshold-tuner-compact").querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.getAttribute("height")).toBe("40");
  });

  it("full mode SVG has correct height attribute", () => {
    const props = defaultProps();
    render(<TrustprintThresholdTuner {...props} />);

    const svg = screen.getByTestId("threshold-tuner-full").querySelector("svg");
    expect(svg).toBeInTheDocument();
    expect(svg?.getAttribute("height")).toBe("120");
  });

  // -----------------------------------------------------------------------
  // Highlight score marker
  // -----------------------------------------------------------------------

  it("renders highlight score marker at correct position", () => {
    const props = defaultProps({ highlightScore: 0.6 });
    render(<TrustprintThresholdTuner {...props} />);

    const marker = screen.getByTestId("highlight-marker");
    expect(marker).toBeInTheDocument();

    // The marker should include a label showing the score
    const label = marker.querySelector("text");
    expect(label).toBeInTheDocument();
    expect(label?.textContent).toBe("0.60");
  });

  it("renders highlight score marker in compact mode", () => {
    const props = defaultProps({ compact: true, highlightScore: 0.4 });
    render(<TrustprintThresholdTuner {...props} />);

    const marker = screen.getByTestId("highlight-marker");
    expect(marker).toBeInTheDocument();
  });

  it("does not render highlight marker when highlightScore is not provided", () => {
    const props = defaultProps();
    render(<TrustprintThresholdTuner {...props} />);

    expect(screen.queryByTestId("highlight-marker")).not.toBeInTheDocument();
  });

  // -----------------------------------------------------------------------
  // Pattern scores
  // -----------------------------------------------------------------------

  it("renders pattern score dots when patternScores provided", () => {
    const props = defaultProps({ patternScores: [0.2, 0.5, 0.9] });
    render(<TrustprintThresholdTuner {...props} />);

    const container = screen.getByTestId("pattern-scores");
    expect(container).toBeInTheDocument();

    const circles = container.querySelectorAll("circle");
    expect(circles).toHaveLength(3);
  });

  it("does not render pattern scores group when array is empty", () => {
    const props = defaultProps({ patternScores: [] });
    render(<TrustprintThresholdTuner {...props} />);

    expect(screen.queryByTestId("pattern-scores")).not.toBeInTheDocument();
  });

  // -----------------------------------------------------------------------
  // Keyboard interaction (accessibility)
  // -----------------------------------------------------------------------

  it("supports arrow key navigation on threshold handle", () => {
    const props = defaultProps({ threshold: 0.50, ambiguityBand: 0.10 });
    render(<TrustprintThresholdTuner {...props} />);

    const handle = screen.getByTestId("handle-threshold");
    fireEvent.keyDown(handle, { key: "ArrowRight" });

    expect(props.onThresholdChange).toHaveBeenCalledWith(0.51);
  });

  it("supports shift+arrow for larger step on threshold", () => {
    const props = defaultProps({ threshold: 0.50, ambiguityBand: 0.10 });
    render(<TrustprintThresholdTuner {...props} />);

    const handle = screen.getByTestId("handle-threshold");
    fireEvent.keyDown(handle, { key: "ArrowRight", shiftKey: true });

    expect(props.onThresholdChange).toHaveBeenCalledWith(0.55);
  });

  it("supports arrow key navigation on band handles", () => {
    const props = defaultProps({ threshold: 0.50, ambiguityBand: 0.10 });
    render(<TrustprintThresholdTuner {...props} />);

    const lowerHandle = screen.getByTestId("handle-lower");
    fireEvent.keyDown(lowerHandle, { key: "ArrowRight" });

    // Increasing band by 0.01
    expect(props.onAmbiguityBandChange).toHaveBeenCalledWith(0.11);
  });

  // -----------------------------------------------------------------------
  // Slider ARIA attributes
  // -----------------------------------------------------------------------

  it("renders accessible slider roles", () => {
    const props = defaultProps({ threshold: 0.85, ambiguityBand: 0.10 });
    render(<TrustprintThresholdTuner {...props} />);

    const sliders = screen.getAllByRole("slider");
    expect(sliders).toHaveLength(3); // threshold, lower, upper

    const thresholdSlider = screen.getByLabelText("Similarity threshold");
    expect(thresholdSlider).toBeInTheDocument();

    const lowerSlider = screen.getByLabelText("Ambiguity band lower bound");
    expect(lowerSlider).toBeInTheDocument();

    const upperSlider = screen.getByLabelText("Ambiguity band upper bound");
    expect(upperSlider).toBeInTheDocument();
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  it("handles threshold at 0.0", () => {
    const props = defaultProps({ threshold: 0.0, ambiguityBand: 0.0 });
    render(<TrustprintThresholdTuner {...props} />);

    // All space is deny zone
    const denyZone = screen.getByTestId("zone-deny");
    expect(denyZone).toBeInTheDocument();
    const barWidth = 352;
    const denyW = parseFloat(denyZone.getAttribute("width") ?? "0");
    expect(denyW).toBeCloseTo(barWidth, 0);
  });

  it("handles threshold at 1.0", () => {
    const props = defaultProps({ threshold: 1.0, ambiguityBand: 0.0 });
    render(<TrustprintThresholdTuner {...props} />);

    // All space is allow zone
    const allowZone = screen.getByTestId("zone-allow");
    expect(allowZone).toBeInTheDocument();
    const barWidth = 352;
    const allowW = parseFloat(allowZone.getAttribute("width") ?? "0");
    expect(allowW).toBeCloseTo(barWidth, 0);
  });

  it("displays summary text with current values", () => {
    const props = defaultProps({ threshold: 0.85, ambiguityBand: 0.1 });
    render(<TrustprintThresholdTuner {...props} />);

    // The summary span shows "thresh 0.85 / band 0.10"
    expect(screen.getByText(/thresh 0\.85/)).toBeInTheDocument();
    expect(screen.getByText(/band 0\.10/)).toBeInTheDocument();
  });
});
