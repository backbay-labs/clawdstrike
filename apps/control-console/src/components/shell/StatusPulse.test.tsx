import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusPulse } from "./StatusPulse";

describe("StatusPulse", () => {
  describe("card layout (default)", () => {
    it("renders label and value text", () => {
      render(<StatusPulse label="Uptime" value="99.9%" />);
      expect(screen.getByText("Uptime")).toBeTruthy();
      expect(screen.getByText("99.9%")).toBeTruthy();
    });

    it("applies gold tone color by default", () => {
      render(<StatusPulse label="Build" value="0.2.0" />);
      const value = screen.getByText("0.2.0");
      expect(value.style.color).toBe("var(--gold)");
    });

    it("applies teal tone color", () => {
      render(<StatusPulse label="SSE" value="LIVE" tone="teal" />);
      const value = screen.getByText("LIVE");
      expect(value.style.color).toBe("var(--teal)");
    });

    it("applies crimson tone color", () => {
      render(<StatusPulse label="Violations" value="3" tone="crimson" />);
      const value = screen.getByText("3");
      expect(value.style.color).toBe("var(--crimson)");
    });

    it("does not render a pulse dot in card layout", () => {
      render(<StatusPulse label="SSE" value="LIVE" pulse />);
      // In card layout pulse dot is not rendered (chip layout only)
      const dots = document.querySelectorAll("[data-testid='pulse-dot']");
      expect(dots.length).toBe(0);
    });

    it("renders vertically (column direction) by default", () => {
      render(<StatusPulse label="Uptime" value="12d" />);
      const container = screen.getByText("Uptime").closest("div");
      expect(container?.style.flexDirection).toBe("column");
    });

    it("applies tabular number feature settings when mono=true", () => {
      render(<StatusPulse label="Uptime" value="12d 04h" mono />);
      const value = screen.getByText("12d 04h");
      expect(value.style.fontFeatureSettings).toContain("tnum");
    });

    it("does not apply tabular numbers by default", () => {
      render(<StatusPulse label="Uptime" value="12d" />);
      const value = screen.getByText("12d");
      expect(value.style.fontFeatureSettings).toBe("");
    });
  });

  describe("chip layout", () => {
    it("renders label and value in chip layout", () => {
      render(<StatusPulse label="SSE" value="LIVE" layout="chip" />);
      expect(screen.getByText("SSE")).toBeTruthy();
      expect(screen.getByText("LIVE")).toBeTruthy();
    });

    it("renders horizontally (row direction) in chip layout", () => {
      render(<StatusPulse label="SSE" value="LIVE" layout="chip" />);
      const container = screen.getByText("SSE").closest("div");
      expect(container?.style.flexDirection).toBe("row");
    });

    it("renders a pulse dot when pulse=true in chip layout", () => {
      render(<StatusPulse label="SSE" value="LIVE" layout="chip" tone="teal" pulse />);
      const dot = screen.getByTestId("pulse-dot");
      expect(dot).toBeTruthy();
    });

    it("does not render a pulse dot when pulse=false", () => {
      render(<StatusPulse label="SSE" value="LIVE" layout="chip" />);
      expect(document.querySelectorAll("[data-testid='pulse-dot']").length).toBe(0);
    });

    it("pulse dot uses tone color", () => {
      render(<StatusPulse label="SSE" value="LIVE" layout="chip" tone="teal" pulse />);
      const dot = screen.getByTestId("pulse-dot");
      expect(dot.style.background).toBe("var(--teal)");
    });

    it("applies tabular number feature settings when mono=true", () => {
      render(<StatusPulse label="Uptime" value="12d 04h" layout="chip" mono />);
      const value = screen.getByText("12d 04h");
      expect(value.style.fontFeatureSettings).toContain("tnum");
    });

    it("does not apply tabular numbers by default", () => {
      render(<StatusPulse label="Uptime" value="12d" layout="chip" />);
      const value = screen.getByText("12d");
      expect(value.style.fontFeatureSettings).toBe("");
    });
  });
});
