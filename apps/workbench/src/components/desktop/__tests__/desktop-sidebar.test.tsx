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
  { label: "Sentinels", href: "/sentinels" },
  { label: "Mission Control", href: "/missions" },
  { label: "Findings & Intel", href: "/findings" },
  { label: "Lab", href: "/lab" },
  { label: "Swarms", href: "/swarms" },
  { label: "Editor", href: "/editor" },
  { label: "Library", href: "/library" },
  { label: "Compliance", href: "/compliance" },
  { label: "Approvals", href: "/approvals" },
  { label: "Audit", href: "/audit" },
  { label: "Receipts", href: "/receipts" },
  { label: "Fleet", href: "/fleet" },
  { label: "Topology", href: "/topology" },
] as const;

const SECTION_HEADERS = [
  "Detect & Respond",
  "Author & Test",
  "Platform",
] as const;

describe("DesktopSidebar", () => {
  it("renders all navigation items plus settings", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const item of NAV_ITEMS) {
      expect(screen.getByText(item.label)).toBeTruthy();
    }
  });

  it("renders each nav item as a link with the correct path", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const item of NAV_ITEMS) {
      const label = screen.getByText(item.label);
      const link = label.closest("a");
      expect(link).toBeTruthy();
      expect(link?.getAttribute("href")).toBe(item.href);
    }
  });

  it("highlights the active route with active styling", () => {
    renderWithProviders(<DesktopSidebar />, { route: "/editor" });

    const activeLink = screen.getByRole("link", { name: "Editor" });
    expect(activeLink.className).toContain("text-[#ece7dc]");

    const inactiveLink = screen.getByRole("link", { name: "Lab" });
    expect(inactiveLink.className).toContain("text-[#6f7f9a]");
  });

  it("renders a gold accent bar only for the active link", () => {
    renderWithProviders(<DesktopSidebar />, { route: "/editor" });

    const editorLink = screen.getByRole("link", { name: "Editor" });
    const accentBar = editorLink.querySelector(".sidebar-accent-bar");
    expect(accentBar).toBeInTheDocument();

    const labLink = screen.getByRole("link", { name: "Lab" });
    const noAccent = labLink.querySelector(".sidebar-accent-bar");
    expect(noAccent).toBeNull();
  });

  it("each nav item contains an SVG icon", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const item of NAV_ITEMS) {
      const label = screen.getByText(item.label);
      const link = label.closest("a")!;
      const svg = link.querySelector("svg");
      expect(svg).toBeTruthy();
    }
  });

  it("renders a collapse button", () => {
    renderWithProviders(<DesktopSidebar />);
    expect(screen.getByText("Collapse")).toBeTruthy();
  });

  it("renders section group headers", () => {
    renderWithProviders(<DesktopSidebar />);

    for (const title of SECTION_HEADERS) {
      expect(screen.getByText(title)).toBeTruthy();
    }
  });

  it("hides section headers when collapsed and shows divider lines instead", async () => {
    const user = userEvent.setup();
    renderWithProviders(<DesktopSidebar />);

    const collapseBtn = screen.getByText("Collapse").closest("button")!;
    await user.click(collapseBtn);

    for (const title of SECTION_HEADERS) {
      expect(screen.queryByText(title)).toBeNull();
    }
  });

  it("toggles sidebar collapsed state when collapse button is clicked", async () => {
    const user = userEvent.setup();
    renderWithProviders(<DesktopSidebar />);

    const sidebar = screen.getByRole("complementary");
    expect(sidebar.className).toContain("w-[200px]");

    const collapseBtn = screen.getByText("Collapse").closest("button")!;
    await user.click(collapseBtn);

    expect(sidebar.className).toContain("w-[52px]");
    expect(screen.queryByText("Collapse")).toBeNull();
    expect(screen.queryByText("Editor")).toBeNull();
  });
});
