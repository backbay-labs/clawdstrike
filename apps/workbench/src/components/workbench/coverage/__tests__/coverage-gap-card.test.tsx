import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { CoverageGapCard } from "../coverage-gap-card";
import type { CoverageGapCandidate } from "@/lib/workbench/detection-workflow/shared-types";

function makeGap(overrides: Partial<CoverageGapCandidate> = {}): CoverageGapCandidate {
  return {
    id: "gap-1",
    sourceKind: "event",
    sourceIds: ["e1", "e2"],
    severity: "medium",
    confidence: 0.75,
    suggestedFormats: ["sigma_rule"],
    techniqueHints: ["T1033", "T1059"],
    dataSourceHints: ["process"],
    rationale: "Technique T1033 observed in 5 events but not covered.",
    ...overrides,
  };
}

describe("CoverageGapCard", () => {
  it("renders severity badge", () => {
    render(<CoverageGapCard gap={makeGap({ severity: "high" })} />);

    const badge = screen.getByTestId("severity-badge");
    expect(badge).toBeDefined();
    expect(badge.textContent).toBe("HIGH");
  });

  it("renders medium severity badge", () => {
    render(<CoverageGapCard gap={makeGap({ severity: "medium" })} />);

    const badge = screen.getByTestId("severity-badge");
    expect(badge.textContent).toBe("MED");
  });

  it("renders low severity badge", () => {
    render(<CoverageGapCard gap={makeGap({ severity: "low" })} />);

    const badge = screen.getByTestId("severity-badge");
    expect(badge.textContent).toBe("LOW");
  });

  it("renders technique hints as tags", () => {
    render(<CoverageGapCard gap={makeGap()} />);

    const tags = screen.getAllByTestId("technique-tag");
    expect(tags.length).toBe(2);
    expect(tags[0].textContent).toBe("T1033");
    expect(tags[1].textContent).toBe("T1059");
  });

  it("renders confidence percentage", () => {
    render(<CoverageGapCard gap={makeGap({ confidence: 0.75 })} />);

    expect(screen.getByText("75% confidence")).toBeDefined();
  });

  it("draft button fires callback", () => {
    const onDraft = vi.fn();
    const gap = makeGap();

    render(<CoverageGapCard gap={gap} onDraft={onDraft} />);

    const draftBtn = screen.getByTestId("draft-button");
    fireEvent.click(draftBtn);

    expect(onDraft).toHaveBeenCalledTimes(1);
    expect(onDraft).toHaveBeenCalledWith(gap);
  });

  it("dismiss button fires callback", () => {
    const onDismiss = vi.fn();
    const gap = makeGap();

    render(<CoverageGapCard gap={gap} onDismiss={onDismiss} />);

    const dismissBtn = screen.getByTestId("dismiss-button");
    fireEvent.click(dismissBtn);

    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledWith("gap-1");
  });

  it("does not render draft button when no callback provided", () => {
    render(<CoverageGapCard gap={makeGap()} />);

    expect(screen.queryByTestId("draft-button")).toBeNull();
  });

  it("does not render dismiss button when no callback provided", () => {
    render(<CoverageGapCard gap={makeGap()} />);

    expect(screen.queryByTestId("dismiss-button")).toBeNull();
  });

  it("renders rationale text in non-compact mode", () => {
    const rationale = "Technique T1033 observed in 5 events but not covered.";
    render(<CoverageGapCard gap={makeGap({ rationale })} />);

    expect(screen.getByText(rationale)).toBeDefined();
  });

  it("ignores unknown suggested formats without crashing", () => {
    render(
      <CoverageGapCard
        gap={makeGap({
          suggestedFormats: ["sigma_rule", "unknown_format"] as unknown as CoverageGapCandidate["suggestedFormats"],
        })}
      />,
    );

    expect(screen.getByText("Sigma")).toBeDefined();
    expect(screen.queryByText("unknown_format")).toBeNull();
  });
});
