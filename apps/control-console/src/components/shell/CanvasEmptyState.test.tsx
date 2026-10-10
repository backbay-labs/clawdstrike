import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CanvasEmptyState } from "./CanvasEmptyState";

describe("CanvasEmptyState", () => {
  it("renders the No window open label", () => {
    render(<CanvasEmptyState onLaunch={() => {}} />);
    expect(screen.getByText("No window open")).toBeTruthy();
  });

  it("renders the Launch Monitor button", () => {
    render(<CanvasEmptyState onLaunch={() => {}} />);
    expect(screen.getByRole("button", { name: /launch monitor/i })).toBeTruthy();
  });

  it("calls onLaunch when the button is clicked", () => {
    const onLaunch = vi.fn();
    render(<CanvasEmptyState onLaunch={onLaunch} />);
    fireEvent.click(screen.getByRole("button", { name: /launch monitor/i }));
    expect(onLaunch).toHaveBeenCalledTimes(1);
  });

  it("button uses gold accent styling", () => {
    render(<CanvasEmptyState onLaunch={() => {}} />);
    const btn = screen.getByRole("button", { name: /launch monitor/i });
    expect(btn.style.color).toBe("var(--gold)");
  });

  it("label uses muted color appropriate for a resting state", () => {
    render(<CanvasEmptyState onLaunch={() => {}} />);
    const label = screen.getByText("No window open");
    // jsdom normalizes rgba spaces: "rgba(154, 167, 181, 0.6)" or without spaces
    expect(label.style.color).toMatch(/rgba\(154,?\s*167,?\s*181,?\s*0\.6\)/);
  });

  it("button text is uppercase (teaches the pattern via branding)", () => {
    render(<CanvasEmptyState onLaunch={() => {}} />);
    const btn = screen.getByRole("button", { name: /launch monitor/i });
    expect(btn.style.textTransform).toBe("uppercase");
  });
});
