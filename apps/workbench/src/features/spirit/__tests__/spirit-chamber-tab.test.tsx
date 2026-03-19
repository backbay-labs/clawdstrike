// apps/workbench/src/features/spirit/__tests__/spirit-chamber-tab.test.tsx
// Rewritten for Plan 04-03: full creation chamber replacing Phase 2 plain form.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SpiritChamberTab } from "../components/spirit-chamber-tab";
import { useSpiritStore } from "../stores/spirit-store";

// Mock the heavy CSS/SVG components — they contain inline keyframes and complex
// style math that don't affect test logic.
vi.mock("../components/spirit-ritual/canvas/SpiritManifestationCanvas", () => ({
  SpiritManifestationCanvas: ({ model }: { model: { label: string } }) => (
    <div data-testid="spirit-manifestation-canvas" data-kind={model.label} />
  ),
}));

vi.mock("../components/spirit-ritual/atmosphere/SpiritAtmosphereLayer", () => ({
  SpiritAtmosphereLayer: () => <div data-testid="spirit-atmosphere-layer" />,
}));

describe("SpiritChamberTab (creation chamber)", () => {
  beforeEach(() => {
    useSpiritStore.getState().actions.unbindSpirit();
  });

  it("renders SpiritManifestationCanvas", () => {
    render(<SpiritChamberTab />);
    expect(screen.getByTestId("spirit-manifestation-canvas")).toBeDefined();
  });

  it("renders SpiritAtmosphereLayer", () => {
    render(<SpiritChamberTab />);
    expect(screen.getByTestId("spirit-atmosphere-layer")).toBeDefined();
  });

  it("bind button calls bindSpirit with selectedKind", () => {
    render(<SpiritChamberTab />);
    // Click the "oracle" kind pill
    const oraclePill = screen.getByRole("button", { name: /oracle/i });
    fireEvent.click(oraclePill);
    // Click Bind
    const bindBtn = screen.getByRole("button", { name: /^bind$/i });
    fireEvent.click(bindBtn);
    expect(useSpiritStore.getState().kind).toBe("oracle");
  });

  it("unbind button calls unbindSpirit when spirit is bound", () => {
    useSpiritStore.getState().actions.bindSpirit("oracle");
    render(<SpiritChamberTab />);
    const unbindBtn = screen.getByRole("button", { name: /^unbind$/i });
    fireEvent.click(unbindBtn);
    expect(useSpiritStore.getState().kind).toBeNull();
  });

  it("kind pill updates manifestation canvas model kind", () => {
    render(<SpiritChamberTab />);
    // Select "specter" pill
    const specterPill = screen.getByRole("button", { name: /specter/i });
    fireEvent.click(specterPill);
    // Canvas should now show the Specter label (mapped from forge kind → "Specter" label in meta)
    const canvas = screen.getByTestId("spirit-manifestation-canvas");
    expect(canvas.getAttribute("data-kind")).toBe("Specter");
  });
});
