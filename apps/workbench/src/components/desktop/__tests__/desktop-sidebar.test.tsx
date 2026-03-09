import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DesktopSidebar } from "../desktop-sidebar";
import { renderWithProviders } from "@/test/test-helpers";

// Mock tauri-bridge so the module can be imported without Tauri runtime
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

const NAV_ITEMS = [
  { label: "Home", href: "/home" },
  { label: "Editor", href: "/editor" },
  { label: "Threat Lab", href: "/simulator" },
  { label: "Compare", href: "/compare" },
  { label: "Compliance", href: "/compliance" },
  { label: "Receipts", href: "/receipts" },
  { label: "Audit", href: "/audit" },
  { label: "Delegation", href: "/delegation" },
  { label: "Approvals", href: "/approvals" },
  { label: "Hierarchy", href: "/hierarchy" },
  { label: "Fleet", href: "/fleet" },
  { label: "Library", href: "/library" },
] as const;

describe("DesktopSidebar", () => {
  it("renders all navigation items plus settings", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const item of NAV_ITEMS) {
      expect(screen.getByText(item.label)).toBeInTheDocument();
    }
  });

  it("renders each nav item as a link with the correct path (no /workbench prefix)", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const item of NAV_ITEMS) {
      // Use getByText + closest("a") because badge content can affect accessible name
      const label = screen.getByText(item.label);
      const link = label.closest("a");
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute("href", item.href);
    }
  });

  it("highlights the active route with active styling", () => {
    renderWithProviders(<DesktopSidebar />, { route: "/simulator" });

    const activeLink = screen.getByRole("link", { name: "Threat Lab" });
    // Active link gets text-[#ece7dc] and bg-[#131721]
    expect(activeLink.className).toContain("bg-[#131721]");
    expect(activeLink.className).toContain("text-[#ece7dc]");

    // Non-active link gets text-[#6f7f9a]
    const inactiveLink = screen.getByRole("link", { name: "Editor" });
    expect(inactiveLink.className).toContain("text-[#6f7f9a]");
  });

  it("renders a gold accent bar only for the active link", () => {
    renderWithProviders(<DesktopSidebar />, { route: "/editor" });

    const editorLink = screen.getByRole("link", { name: "Editor" });
    // The active link has a child span with the gold accent
    const accentBar = editorLink.querySelector("span.bg-\\[\\#d4a84b\\]");
    expect(accentBar).toBeInTheDocument();

    // Inactive link should not have the accent bar
    const simulatorLink = screen.getByRole("link", { name: "Threat Lab" });
    const noAccent = simulatorLink.querySelector("span.bg-\\[\\#d4a84b\\]");
    expect(noAccent).toBeNull();
  });

  it("each nav item contains an SVG icon", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const item of NAV_ITEMS) {
      const label = screen.getByText(item.label);
      const link = label.closest("a")!;
      const svg = link.querySelector("svg");
      expect(svg).toBeInTheDocument();
    }
  });

  it("renders a collapse button", () => {
    renderWithProviders(<DesktopSidebar />);

    // When expanded, the collapse button shows "Collapse" text
    expect(screen.getByText("Collapse")).toBeInTheDocument();
  });

  it("toggles sidebar collapsed state when collapse button is clicked", async () => {
    const user = userEvent.setup();
    renderWithProviders(<DesktopSidebar />);

    const sidebar = screen.getByRole("complementary"); // <aside> has complementary role
    // Expanded: width class w-[200px]
    expect(sidebar.className).toContain("w-[200px]");

    // Click collapse
    const collapseBtn = screen.getByText("Collapse").closest("button")!;
    await user.click(collapseBtn);

    // After collapse: width class w-[52px], labels hidden
    expect(sidebar.className).toContain("w-[52px]");
    expect(screen.queryByText("Collapse")).not.toBeInTheDocument();
    // Nav labels should also be hidden
    expect(screen.queryByText("Editor")).not.toBeInTheDocument();
  });
});
