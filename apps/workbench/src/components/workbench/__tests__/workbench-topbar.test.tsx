import { describe, it, expect, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { WorkbenchTopbar } from "../workbench-topbar";
import type { TauriExportResponse } from "@/lib/tauri-commands";
import type { OpenFileResult } from "@/lib/tauri-bridge";
import { renderWithProviders } from "@/test/test-helpers";

const tauriBridgeMocks = vi.hoisted(() => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn<() => Promise<void>>(),
  maximizeWindow: vi.fn<() => Promise<void>>(),
  closeWindow: vi.fn<() => Promise<void>>(),
  openPolicyFile: vi.fn<() => Promise<OpenFileResult | null>>(),
  readPolicyFileByPath: vi.fn<(filePath: string) => Promise<OpenFileResult | null>>(),
  pickSavePath: vi.fn<(format?: string) => Promise<string | null>>(),
  savePolicyFile: vi.fn<
    (content: string, filePath?: string | null, format?: string) => Promise<string | null>
  >(),
}));

const tauriCommandMocks = vi.hoisted(() => ({
  exportPolicyFileNative: vi.fn<
    (content: string, path: string, format?: string) => Promise<TauriExportResponse | null>
  >(),
}));

vi.mock("@/lib/tauri-bridge", () => tauriBridgeMocks);
vi.mock("@/lib/tauri-commands", () => tauriCommandMocks);
vi.mock("@/lib/workbench/local-audit", () => ({
  emitAuditEvent: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  tauriBridgeMocks.isDesktop.mockReturnValue(false);
  tauriBridgeMocks.pickSavePath.mockResolvedValue(null);
  tauriBridgeMocks.savePolicyFile.mockResolvedValue(null);
  tauriCommandMocks.exportPolicyFileNative.mockResolvedValue(null);
});

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
    // The shadcn Select renders a <button> trigger (role="combobox"), not a native <select>.
    // The trigger displays the selected item's text; check it contains the default value.
    const trigger = screen.getByTitle("Export format");
    expect(trigger).toBeInTheDocument();
    expect(trigger).toHaveTextContent(/yaml/i);
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

  it("desktop JSON export does not change the active save target", async () => {
    const user = userEvent.setup();
    tauriBridgeMocks.isDesktop.mockReturnValue(true);
    tauriBridgeMocks.pickSavePath.mockResolvedValue("/tmp/exported-policy.json");
    tauriBridgeMocks.savePolicyFile.mockResolvedValue("/tmp/saved-policy.yaml");
    tauriCommandMocks.exportPolicyFileNative.mockResolvedValue({
      success: true,
      path: "/tmp/exported-policy.json",
      message: "Policy exported as JSON successfully",
    });

    renderWithProviders(<WorkbenchTopbar />);

    const saveButton = screen.getByRole("button", { name: "Save" });
    expect(saveButton).toHaveAttribute("title", "Save policy (\u2318S)");

    await user.click(screen.getByTitle("Export format"));
    await user.click(await screen.findByRole("option", { name: "JSON" }));
    await user.click(screen.getByRole("button", { name: "Save As" }));

    await waitFor(() => {
      expect(tauriCommandMocks.exportPolicyFileNative).toHaveBeenCalledWith(
        expect.any(String),
        "/tmp/exported-policy.json",
        "json",
      );
    });

    expect(saveButton).toHaveAttribute("title", "Save policy (\u2318S)");

    await user.click(saveButton);

    await waitFor(() => {
      expect(tauriBridgeMocks.savePolicyFile).toHaveBeenCalledTimes(1);
    });
    expect(tauriBridgeMocks.savePolicyFile.mock.calls[0]).toHaveLength(1);
  });

  it("desktop export does not write through savePolicyFile before native validation", async () => {
    const user = userEvent.setup();
    tauriBridgeMocks.isDesktop.mockReturnValue(true);
    tauriBridgeMocks.pickSavePath.mockResolvedValue("/tmp/existing-policy.json");
    tauriCommandMocks.exportPolicyFileNative.mockResolvedValue({
      success: false,
      path: "/tmp/existing-policy.json",
      message: "Policy validation failed",
    });

    renderWithProviders(<WorkbenchTopbar />);

    await user.click(screen.getByTitle("Export format"));
    await user.click(await screen.findByRole("option", { name: "JSON" }));
    await user.click(screen.getByRole("button", { name: "Save As" }));

    await waitFor(() => {
      expect(tauriCommandMocks.exportPolicyFileNative).toHaveBeenCalledWith(
        expect.any(String),
        "/tmp/existing-policy.json",
        "json",
      );
    });
    expect(tauriBridgeMocks.savePolicyFile).not.toHaveBeenCalled();
  });
});
