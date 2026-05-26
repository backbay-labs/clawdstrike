import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BrandMark } from "./BrandMark";

describe("BrandMark", () => {
  it("renders the SVG glyph container", () => {
    render(<BrandMark />);
    const svg = document.querySelector("svg");
    expect(svg).toBeTruthy();
  });

  it("renders the C arc path in the SVG", () => {
    render(<BrandMark />);
    // The C arc path uses a linearGradient stroke
    const paths = document.querySelectorAll("svg path");
    expect(paths.length).toBeGreaterThanOrEqual(2); // arc + claw accent
  });

  it("renders a linearGradient for the C glyph stroke (graphic element — gradient allowed)", () => {
    render(<BrandMark />);
    const gradient = document.querySelector("linearGradient");
    expect(gradient).toBeTruthy();
  });

  it("renders claw accent using the crimson token", () => {
    render(<BrandMark />);
    const paths = Array.from(document.querySelectorAll("svg path"));
    const clawPath = paths.find((p) => p.getAttribute("stroke") === "var(--crimson)");
    expect(clawPath).toBeTruthy();
  });

  it("does not render the wordmark text when showWordmark is false (default)", () => {
    render(<BrandMark />);
    expect(screen.queryByText("clawdstrike")).toBeNull();
  });

  it("renders the wordmark text when showWordmark=true", () => {
    render(<BrandMark showWordmark />);
    expect(screen.getByText("clawdstrike")).toBeTruthy();
  });

  it("renders the version caption when showWordmark=true", () => {
    render(<BrandMark showWordmark />);
    expect(screen.getByText(/Control Console/)).toBeTruthy();
  });

  it("uses the provided version string in the caption", () => {
    render(<BrandMark showWordmark version="1.0.0" />);
    expect(screen.getByText(/v1\.0\.0/)).toBeTruthy();
  });

  it("defaults version to 0.2.0", () => {
    render(<BrandMark showWordmark />);
    expect(screen.getByText(/v0\.2\.0/)).toBeTruthy();
  });

  it("wordmark text uses solid var(--gold), NOT gradient text (no background-clip on wordmark)", () => {
    render(<BrandMark showWordmark />);
    const wordmark = screen.getByText("clawdstrike");
    // Must NOT use gradient text technique — these CSS properties must be absent or empty
    expect(wordmark.style.backgroundClip).not.toBe("text");
    expect(wordmark.style.webkitTextFillColor).not.toBe("transparent");
    // Must use solid color
    expect(wordmark.style.color).toBe("var(--gold)");
  });

  it("respects a custom size prop", () => {
    render(<BrandMark size={48} />);
    // The tile element should have width and height matching the size
    const tile = document.querySelector("[data-testid='brandmark-tile']") as HTMLElement | null;
    expect(tile).toBeTruthy();
    expect(tile?.style.width).toBe("48px");
    expect(tile?.style.height).toBe("48px");
  });
});
