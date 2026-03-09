import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { WorkbenchTopbar } from "../workbench-topbar";
import { renderWithProviders } from "@/test/test-helpers";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

describe("WorkbenchTopbar", () => {
  it("shows the policy name", () => {
    renderWithProviders(<WorkbenchTopbar />);

    // Default policy name is "My Policy"
    expect(screen.getByText("My Policy")).toBeInTheDocument();
  });

  it("shows the policy name as a clickable button for renaming", () => {
    renderWithProviders(<WorkbenchTopbar />);

    const nameButton = screen.getByRole("button", { name: "My Policy" });
    expect(nameButton).toBeInTheDocument();
    expect(nameButton).toHaveAttribute("title", "Click to rename");
  });

  it("shows the schema version badge", () => {
    renderWithProviders(<WorkbenchTopbar />);

    // Default version is "1.2.0"
    expect(screen.getByText("v1.2.0")).toBeInTheDocument();
  });

  it("shows 'Valid' validation status when policy is valid", () => {
    renderWithProviders(<WorkbenchTopbar />);

    expect(screen.getByText("Valid")).toBeInTheDocument();
  });

  it("renders Save button", () => {
    renderWithProviders(<WorkbenchTopbar />);

    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });

  it("renders Export button with format selector", () => {
    renderWithProviders(<WorkbenchTopbar />);

    expect(screen.getByRole("button", { name: "Export" })).toBeInTheDocument();
    // Format selector should be present with YAML as default
    const select = screen.getByTitle("Export format");
    expect(select).toBeInTheDocument();
    expect(select).toHaveValue("yaml");
  });

  it("renders Copy button", () => {
    renderWithProviders(<WorkbenchTopbar />);

    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
  });

  it("enters edit mode when policy name is clicked", async () => {
    const user = userEvent.setup();
    renderWithProviders(<WorkbenchTopbar />);

    const nameButton = screen.getByRole("button", { name: "My Policy" });
    await user.click(nameButton);

    // After clicking, an input should appear with the policy name
    const input = screen.getByDisplayValue("My Policy");
    expect(input).toBeInTheDocument();
    expect(input.tagName).toBe("INPUT");
  });

  it("commits name change on Enter key", async () => {
    const user = userEvent.setup();
    renderWithProviders(<WorkbenchTopbar />);

    // Enter edit mode
    await user.click(screen.getByRole("button", { name: "My Policy" }));
    const input = screen.getByDisplayValue("My Policy");

    // Clear and type new name
    await user.clear(input);
    await user.type(input, "New Policy Name{Enter}");

    // Should exit edit mode and show new name
    expect(screen.getByRole("button", { name: "New Policy Name" })).toBeInTheDocument();
  });

  it("cancels name change on Escape key", async () => {
    const user = userEvent.setup();
    renderWithProviders(<WorkbenchTopbar />);

    // Enter edit mode
    await user.click(screen.getByRole("button", { name: "My Policy" }));
    const input = screen.getByDisplayValue("My Policy");

    // Type something then escape
    await user.clear(input);
    await user.type(input, "Abandoned Name{Escape}");

    // Should revert to original name
    expect(screen.getByRole("button", { name: "My Policy" })).toBeInTheDocument();
    expect(screen.queryByDisplayValue("Abandoned Name")).not.toBeInTheDocument();
  });

  it("reverts to original name on blur with empty input", async () => {
    const user = userEvent.setup();
    renderWithProviders(<WorkbenchTopbar />);

    // Enter edit mode
    await user.click(screen.getByRole("button", { name: "My Policy" }));
    const input = screen.getByDisplayValue("My Policy");

    // Clear the input and blur (tab away)
    await user.clear(input);
    await user.tab();

    // Should revert to "My Policy" since empty names are not accepted
    expect(screen.getByRole("button", { name: "My Policy" })).toBeInTheDocument();
  });

  it("validation status badge has correct styling class for valid state", () => {
    renderWithProviders(<WorkbenchTopbar />);

    const badge = screen.getByText("Valid");
    // Valid state uses green color class
    expect(badge.className).toContain("text-[#3dbf84]");
  });

  it("renders as a header element", () => {
    renderWithProviders(<WorkbenchTopbar />);

    const header = screen.getByRole("banner");
    expect(header).toBeInTheDocument();
  });
});
