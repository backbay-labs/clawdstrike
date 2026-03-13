import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import { StatusBar } from "../status-bar";
import { renderWithProviders } from "@/test/test-helpers";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

describe("StatusBar", () => {
  it("shows 'Valid' status when there are no errors or warnings", () => {
    renderWithProviders(<StatusBar />);

    expect(screen.getByText("Valid")).toBeInTheDocument();
  });

  it("shows the checkmark icon for valid state", () => {
    renderWithProviders(<StatusBar />);

    // Unicode checkmark U+2714
    expect(screen.getByText("\u2714")).toBeInTheDocument();
  });

  it("shows guard count in the format enabled/total", () => {
    renderWithProviders(<StatusBar />);

    const totalGuards = GUARD_REGISTRY.length;
    // Default policy has 3 enabled guards: forbidden_path, egress_allowlist, secret_leak
    expect(screen.getByText(`3/${totalGuards} guards`)).toBeInTheDocument();
  });

  it("shows the schema version from active policy", () => {
    renderWithProviders(<StatusBar />);

    // Default policy version is "1.2.0"
    expect(screen.getByText("v1.2.0")).toBeInTheDocument();
  });

  it("shows 'unsaved' when there is no file path", () => {
    renderWithProviders(<StatusBar />);

    expect(screen.getByText("unsaved")).toBeInTheDocument();
  });

  it("renders as a footer element", () => {
    renderWithProviders(<StatusBar />);

    const footer = screen.getByRole("contentinfo");
    expect(footer).toBeInTheDocument();
    expect(footer.tagName).toBe("FOOTER");
  });
});
