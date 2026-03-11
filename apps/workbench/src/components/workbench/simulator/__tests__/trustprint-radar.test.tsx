// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TrustprintRadar, type TrustprintRadarProps } from "../trustprint-radar";

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_PROPS: TrustprintRadarProps = {
  scores: {
    perception: 0.3,
    cognition: 0.2,
    action: 0.5,
    feedback: 0.1,
  },
  threshold: 0.6,
  ambiguityBand: 0.1,
};

function renderRadar(
  overrides: Partial<TrustprintRadarProps> = {},
): { container: HTMLDivElement; root: Root } {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);

  act(() => {
    root.render(<TrustprintRadar {...BASE_PROPS} {...overrides} />);
  });

  return { container, root };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TrustprintRadar", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    if (root) {
      act(() => root.unmount());
    }
    if (container) {
      container.remove();
    }
  });

  // ---- Axis labels ----

  it("renders 4 axis labels", () => {
    ({ container, root } = renderRadar());

    const labels = container.querySelectorAll("[data-testid^='stage-label-']");
    expect(labels.length).toBe(4);

    const texts = Array.from(labels).map((el) => el.textContent);
    expect(texts).toContain("Perception");
    expect(texts).toContain("Action");
    expect(texts).toContain("Feedback");
    expect(texts).toContain("Cognition");
  });

  // ---- Score polygon ----

  it("renders score polygon with correct points", () => {
    ({ container, root } = renderRadar());

    const polygon = container.querySelector(
      "[data-testid='score-polygon']",
    ) as SVGPolygonElement;
    expect(polygon).toBeTruthy();

    const pointsAttr = polygon.getAttribute("points");
    expect(pointsAttr).toBeTruthy();

    // The polygon should have 4 coordinate pairs (one per stage)
    const pairs = pointsAttr!.split(" ");
    expect(pairs.length).toBe(4);

    // Each pair should be "x,y" format
    for (const pair of pairs) {
      const [x, y] = pair.split(",").map(Number);
      expect(Number.isFinite(x)).toBe(true);
      expect(Number.isFinite(y)).toBe(true);
    }
  });

  // ---- Threshold ring ----

  it("renders threshold ring at correct radius", () => {
    const threshold = 0.6;
    ({ container, root } = renderRadar({ threshold }));

    const ring = container.querySelector(
      "[data-testid='threshold-ring']",
    ) as SVGCircleElement;
    expect(ring).toBeTruthy();

    // The ring should have a dashed stroke
    const dashArray = ring.getAttribute("stroke-dasharray");
    expect(dashArray).toBeTruthy();

    // Verify the stroke is gold (#d4a84b)
    const stroke = ring.getAttribute("stroke");
    expect(stroke).toBe("#d4a84b");

    // Verify radius corresponds to threshold * chartRadius
    // For md size (240), chartRadius = 240 * 0.35 = 84
    // threshold radius = 0.6 * 84 = 50.4
    const r = Number(ring.getAttribute("r"));
    expect(r).toBeCloseTo(threshold * (240 * 0.35), 1);
  });

  // ---- Ghost trace ----

  it("renders ghost trace when previousScores provided", () => {
    const previousScores = {
      perception: 0.4,
      cognition: 0.3,
      action: 0.6,
      feedback: 0.2,
    };
    ({ container, root } = renderRadar({ previousScores }));

    const ghost = container.querySelector(
      "[data-testid='ghost-trace']",
    ) as SVGPolygonElement;
    expect(ghost).toBeTruthy();

    // Ghost trace should have dashed stroke
    const dashArray = ghost.getAttribute("stroke-dasharray");
    expect(dashArray).toBeTruthy();

    // Ghost trace should have reduced opacity
    const strokeOpacity = ghost.getAttribute("stroke-opacity");
    expect(Number(strokeOpacity)).toBeLessThanOrEqual(0.3);
  });

  it("does not render ghost trace when previousScores not provided", () => {
    ({ container, root } = renderRadar());

    const ghost = container.querySelector("[data-testid='ghost-trace']");
    expect(ghost).toBeNull();
  });

  // ---- Size variants ----

  it("renders small size variant", () => {
    ({ container, root } = renderRadar({ size: "sm" }));

    const svg = container.querySelector(
      "[data-testid='trustprint-radar']",
    ) as SVGSVGElement;
    expect(svg).toBeTruthy();
    expect(svg.getAttribute("width")).toBe("160");
    expect(svg.getAttribute("height")).toBe("160");
  });

  it("renders medium size variant (default)", () => {
    ({ container, root } = renderRadar());

    const svg = container.querySelector(
      "[data-testid='trustprint-radar']",
    ) as SVGSVGElement;
    expect(svg).toBeTruthy();
    expect(svg.getAttribute("width")).toBe("240");
    expect(svg.getAttribute("height")).toBe("240");
  });

  it("renders large size variant", () => {
    ({ container, root } = renderRadar({ size: "lg" }));

    const svg = container.querySelector(
      "[data-testid='trustprint-radar']",
    ) as SVGSVGElement;
    expect(svg).toBeTruthy();
    expect(svg.getAttribute("width")).toBe("320");
    expect(svg.getAttribute("height")).toBe("320");
  });

  // ---- Color logic ----

  it("uses green fill when all scores are below lower bound", () => {
    // threshold=0.6, band=0.1 -> lower=0.5, upper=0.7
    // All scores below 0.5 -> green
    ({ container, root } = renderRadar({
      scores: {
        perception: 0.1,
        cognition: 0.2,
        action: 0.3,
        feedback: 0.05,
      },
      threshold: 0.6,
      ambiguityBand: 0.1,
    }));

    const polygon = container.querySelector(
      "[data-testid='score-polygon']",
    ) as SVGPolygonElement;
    expect(polygon).toBeTruthy();

    // The stroke should be green (#3dbf84)
    const stroke = polygon.getAttribute("stroke");
    expect(stroke).toBe("#3dbf84");
  });

  it("uses gold fill when a score is in the ambiguity zone", () => {
    // threshold=0.6, band=0.1 -> lower=0.5, upper=0.7
    // Cognition=0.55 is in the ambiguity zone, no red
    ({ container, root } = renderRadar({
      scores: {
        perception: 0.1,
        cognition: 0.55,
        action: 0.3,
        feedback: 0.05,
      },
      threshold: 0.6,
      ambiguityBand: 0.1,
    }));

    const polygon = container.querySelector(
      "[data-testid='score-polygon']",
    ) as SVGPolygonElement;
    expect(polygon).toBeTruthy();

    const stroke = polygon.getAttribute("stroke");
    expect(stroke).toBe("#d4a84b");
  });

  it("uses red fill when any score is above upper bound", () => {
    // threshold=0.6, band=0.1 -> upper=0.7
    // Action=0.85 is above upper bound -> red
    ({ container, root } = renderRadar({
      scores: {
        perception: 0.1,
        cognition: 0.2,
        action: 0.85,
        feedback: 0.05,
      },
      threshold: 0.6,
      ambiguityBand: 0.1,
    }));

    const polygon = container.querySelector(
      "[data-testid='score-polygon']",
    ) as SVGPolygonElement;
    expect(polygon).toBeTruthy();

    const stroke = polygon.getAttribute("stroke");
    expect(stroke).toBe("#c45c5c");
  });

  // ---- Score dots ----

  it("renders score dots for all 4 stages", () => {
    ({ container, root } = renderRadar());

    const dots = container.querySelectorAll("[data-testid^='dot-']");
    expect(dots.length).toBe(4);
  });

  it("colors individual dots by their zone", () => {
    // threshold=0.6, band=0.1 -> lower=0.5, upper=0.7
    // perception=0.1 -> green, action=0.55 -> gold, cognition=0.8 -> red
    ({ container, root } = renderRadar({
      scores: {
        perception: 0.1,
        cognition: 0.8,
        action: 0.55,
        feedback: 0.3,
      },
      threshold: 0.6,
      ambiguityBand: 0.1,
    }));

    const perceptionDot = container.querySelector(
      "[data-testid='dot-perception']",
    ) as SVGCircleElement;
    expect(perceptionDot.getAttribute("fill")).toBe("#3dbf84");

    const cognitionDot = container.querySelector(
      "[data-testid='dot-cognition']",
    ) as SVGCircleElement;
    expect(cognitionDot.getAttribute("fill")).toBe("#c45c5c");

    const actionDot = container.querySelector(
      "[data-testid='dot-action']",
    ) as SVGCircleElement;
    expect(actionDot.getAttribute("fill")).toBe("#d4a84b");
  });

  // ---- Score labels ----

  it("renders score value labels for each stage", () => {
    ({ container, root } = renderRadar({
      scores: {
        perception: 0.82,
        cognition: 0.45,
        action: 0.31,
        feedback: 0.67,
      },
    }));

    const perceptionLabel = container.querySelector(
      "[data-testid='score-label-perception']",
    );
    expect(perceptionLabel?.textContent).toBe("0.82");

    const cognitionLabel = container.querySelector(
      "[data-testid='score-label-cognition']",
    );
    expect(cognitionLabel?.textContent).toBe("0.45");
  });

  // ---- Aria label ----

  it("includes accessible aria-label with score data", () => {
    ({ container, root } = renderRadar({
      scores: {
        perception: 0.3,
        cognition: 0.2,
        action: 0.5,
        feedback: 0.1,
      },
      threshold: 0.6,
      ambiguityBand: 0.1,
    }));

    const svg = container.querySelector(
      "[data-testid='trustprint-radar']",
    ) as SVGSVGElement;
    const label = svg.getAttribute("aria-label");
    expect(label).toContain("Trustprint Radar");
    expect(label).toContain("Perception: 0.30");
    expect(label).toContain("Threshold: 0.60");
  });

  // ---- onStageClick ----

  it("calls onStageClick when a stage label is clicked", () => {
    const onClick = vi.fn();
    ({ container, root } = renderRadar({ onStageClick: onClick }));

    const label = container.querySelector(
      "[data-testid='stage-label-perception']",
    ) as SVGTextElement;
    expect(label).toBeTruthy();

    act(() => {
      label.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    expect(onClick).toHaveBeenCalledWith("perception");
  });

  // ---- Ambiguity zone ----

  it("renders ambiguity zone when band is positive", () => {
    ({ container, root } = renderRadar({ ambiguityBand: 0.1 }));

    const zone = container.querySelector("[data-testid='ambiguity-zone']");
    expect(zone).toBeTruthy();
  });

  it("does not render ambiguity zone when band is zero", () => {
    ({ container, root } = renderRadar({ ambiguityBand: 0 }));

    const zone = container.querySelector("[data-testid='ambiguity-zone']");
    expect(zone).toBeNull();
  });

  // ---- Concentric rings ----

  it("renders 4 concentric grid rings", () => {
    ({ container, root } = renderRadar());

    const rings = container.querySelectorAll("[data-testid^='ring-']");
    expect(rings.length).toBe(4);
  });
});
