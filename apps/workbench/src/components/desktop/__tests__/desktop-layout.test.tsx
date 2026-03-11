import { useEffect } from "react";
import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { DesktopLayout } from "../desktop-layout";
import { MultiPolicyProvider as WorkbenchProvider, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { FleetConnectionProvider } from "@/lib/workbench/use-fleet-connection";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

function DirtyBackgroundTabBootstrap() {
  const { multiDispatch } = useMultiPolicy();

  useEffect(() => {
    multiDispatch({ type: "UPDATE_META", name: "dirty-background-tab" });
    multiDispatch({ type: "NEW_TAB" });
  }, [multiDispatch]);

  return null;
}

function renderLayout(route = "/editor", withDirtyBackgroundTab = false) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <FleetConnectionProvider>
        <WorkbenchProvider>
          {withDirtyBackgroundTab ? <DirtyBackgroundTabBootstrap /> : null}
          <Routes>
            <Route element={<DesktopLayout />}>
              <Route path="editor" element={<div data-testid="editor-page">Editor Page</div>} />
              <Route path="simulator" element={<div data-testid="simulator-page">Simulator Page</div>} />
            </Route>
          </Routes>
        </WorkbenchProvider>
      </FleetConnectionProvider>
    </MemoryRouter>,
  );
}

describe("DesktopLayout", () => {
  it("renders the titlebar", () => {
    renderLayout();

    // The titlebar renders a header with the brand name (split into two spans)
    expect(screen.getByText("Clawdstrike")).toBeInTheDocument();
    expect(screen.getByText("Workbench")).toBeInTheDocument();
  });

  it("renders the sidebar", () => {
    renderLayout();

    // Sidebar renders navigation items
    expect(screen.getByRole("complementary")).toBeInTheDocument();
    expect(screen.getByText("Editor")).toBeInTheDocument();
    expect(screen.getByText("Threat Lab")).toBeInTheDocument();
  });

  it("renders the status bar", () => {
    renderLayout();

    // Status bar renders as a footer
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
  });

  it("renders the routed content via Outlet", () => {
    renderLayout("/editor");

    expect(screen.getByTestId("editor-page")).toBeInTheDocument();
    expect(screen.getByText("Editor Page")).toBeInTheDocument();
  });

  it("renders a different route via Outlet", () => {
    renderLayout("/simulator");

    expect(screen.getByTestId("simulator-page")).toBeInTheDocument();
    expect(screen.getByText("Simulator Page")).toBeInTheDocument();
  });

  it("has a flex column layout structure", () => {
    renderLayout();

    // The root div should have flex flex-col
    const root = screen.getByText("Clawdstrike").closest("div.flex.flex-col");
    expect(root).toBeInTheDocument();
  });

  it("has a flex row section for sidebar + content", () => {
    renderLayout();

    // The sidebar and content area should be in a flex row container
    const sidebar = screen.getByRole("complementary");
    const flexRow = sidebar.parentElement;
    expect(flexRow).toBeInTheDocument();
    expect(flexRow!.className).toContain("flex");
    expect(flexRow!.className).toContain("flex-1");
  });

  it("warns before unload when a background tab is dirty", () => {
    renderLayout("/editor", true);

    const event = new Event("beforeunload", { cancelable: true });
    const preventDefault = vi.spyOn(event, "preventDefault");

    window.dispatchEvent(event);

    expect(preventDefault).toHaveBeenCalled();
  });
});
