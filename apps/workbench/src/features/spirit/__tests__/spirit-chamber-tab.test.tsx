// apps/workbench/src/features/spirit/__tests__/spirit-chamber-tab.test.tsx
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SpiritChamberTab } from "../components/spirit-chamber-tab";
import { useSpiritStore } from "../stores/spirit-store";

describe("SpiritChamberTab", () => {
  beforeEach(() => {
    useSpiritStore.getState().actions.unbindSpirit();
  });

  it("renders a kind selector with exactly 4 options (sentinel/oracle/witness/specter)", () => {
    render(<SpiritChamberTab />);
    const options = screen.getAllByRole("option");
    const kinds = options.map((o) => o.getAttribute("value") ?? o.textContent?.toLowerCase());
    expect(kinds).toContain("sentinel");
    expect(kinds).toContain("oracle");
    expect(kinds).toContain("witness");
    expect(kinds).toContain("specter");
    // Exactly 4 spirit kinds (placeholder option may make total 5 — allow for it)
    const kindOptions = options.filter((o) => ["sentinel","oracle","witness","specter"].includes(o.getAttribute("value") ?? ""));
    expect(kindOptions).toHaveLength(4);
  });

  it("calls bindSpirit with selected kind when Bind button is clicked", () => {
    render(<SpiritChamberTab />);
    // Select oracle
    const select = screen.getByRole("combobox");
    fireEvent.change(select, { target: { value: "oracle" } });
    const bindBtn = screen.getByRole("button", { name: /bind/i });
    fireEvent.click(bindBtn);
    expect(useSpiritStore.getState().kind).toBe("oracle");
  });

  it("calls unbindSpirit when Unbind button is clicked and spirit is bound", () => {
    useSpiritStore.getState().actions.bindSpirit("witness");
    render(<SpiritChamberTab />);
    const unbindBtn = screen.getByRole("button", { name: /unbind/i });
    fireEvent.click(unbindBtn);
    expect(useSpiritStore.getState().kind).toBeNull();
  });

  it("shows current spirit kind when a spirit is bound", () => {
    useSpiritStore.getState().actions.bindSpirit("specter");
    render(<SpiritChamberTab />);
    expect(screen.getByText(/specter/i)).toBeDefined();
  });

  it("shows no-spirit placeholder text when no spirit is bound", () => {
    render(<SpiritChamberTab />);
    expect(screen.getByText(/no spirit/i)).toBeDefined();
  });
});
