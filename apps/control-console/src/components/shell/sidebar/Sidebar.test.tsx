import { fireEvent, render, screen, within } from "@testing-library/react";
import { act } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";

const launch = vi.fn();
const instances = { current: [] as Array<{ windowId: string; processId: string }> };
const focusedId = { current: null as string | null };

vi.mock("@backbay/glia-desktop", () => ({
  useDesktopOS: () => ({
    processes: {
      instances: instances.current,
      launch,
      getDefinition: (processId: string) => ({ description: `desc:${processId}` }),
    },
    windows: { focusedId: focusedId.current },
  }),
}));

import { useShellPreferences } from "../../../state/useShellPreferences";
import { Sidebar } from "./Sidebar";
import { SidebarExpanded } from "./SidebarExpanded";

const STATUS: ConsoleStatus = {
  sseLive: true,
  violations: 0,
  uptime: "01:23:45",
  build: "0.2.0",
};

beforeEach(() => {
  launch.mockClear();
  instances.current = [];
  focusedId.current = null;
  act(() => {
    useShellPreferences.setState({ sidebarVariant: "expanded", sidebarCollapsed: false });
  });
});

describe("SidebarExpanded", () => {
  it("renders all three group labels", () => {
    render(<SidebarExpanded onCmdK={() => {}} onCollapse={() => {}} status={STATUS} />);
    expect(screen.getByText("Operations")).toBeTruthy();
    expect(screen.getByText("Policy + Runtime")).toBeTruthy();
    expect(screen.getByText("Tools")).toBeTruthy();
  });

  it("renders nav rows for apps including Monitor and Policies", () => {
    render(<SidebarExpanded onCmdK={() => {}} onCollapse={() => {}} status={STATUS} />);
    expect(screen.getByRole("button", { name: "Monitor" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Policies" })).toBeTruthy();
  });

  it("launches the process when a nav row is clicked", () => {
    render(<SidebarExpanded onCmdK={() => {}} onCollapse={() => {}} status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: /monitor/i }));
    expect(launch).toHaveBeenCalledWith("monitor");
  });

  it("marks the focused app's row with aria-current=page", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(<SidebarExpanded onCmdK={() => {}} onCollapse={() => {}} status={STATUS} />);
    const monitor = screen.getByRole("button", { name: /monitor/i });
    expect(monitor.getAttribute("aria-current")).toBe("page");
  });

  it("calls onCmdK when the search bar is clicked", () => {
    const onCmdK = vi.fn();
    render(<SidebarExpanded onCmdK={onCmdK} onCollapse={() => {}} status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: /search apps/i }));
    expect(onCmdK).toHaveBeenCalledTimes(1);
  });

  it("calls onCollapse when the collapse chevron is clicked", () => {
    const onCollapse = vi.fn();
    render(<SidebarExpanded onCmdK={() => {}} onCollapse={onCollapse} status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: /collapse sidebar/i }));
    expect(onCollapse).toHaveBeenCalledTimes(1);
  });

  it("renders SSE, Violations, Uptime, and Build pulses in the footer", () => {
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onCollapse={() => {}}
        status={{ sseLive: true, violations: 3, uptime: "02:00:00", build: "9.9.9" }}
      />,
    );
    expect(screen.getByText("SSE")).toBeTruthy();
    expect(screen.getByText("● LIVE")).toBeTruthy();
    expect(screen.getByText("Violations")).toBeTruthy();
    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getByText("Uptime")).toBeTruthy();
    expect(screen.getByText("02:00:00")).toBeTruthy();
    expect(screen.getByText("Build")).toBeTruthy();
    expect(screen.getByText("9.9.9")).toBeTruthy();
  });

  it("shows SSE DOWN in crimson when offline", () => {
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onCollapse={() => {}}
        status={{ sseLive: false, violations: 0, uptime: "00:00:00", build: "0.2.0" }}
      />,
    );
    const sseValue = screen.getByText("◌ DOWN");
    expect(sseValue.style.color).toBe("var(--crimson)");
  });
});

describe("Sidebar orchestrator", () => {
  it("renders the expanded sidebar (248px) for the expanded variant", () => {
    render(<Sidebar onCmdK={() => {}} status={STATUS} />);
    const aside = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(aside.style.width).toBe("248px");
    // Search bar present only in expanded
    expect(screen.getByRole("button", { name: /search apps/i })).toBeTruthy();
  });

  it("renders the rail (64px) when an expanded sidebar is collapsed", () => {
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "expanded", sidebarCollapsed: true });
    });
    render(<Sidebar onCmdK={() => {}} status={STATUS} />);
    const aside = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(aside.style.width).toBe("64px");
    // Rail has no search bar
    expect(screen.queryByRole("button", { name: /search apps/i })).toBeNull();
  });

  it("renders the rail (64px) for the rail variant", () => {
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "rail", sidebarCollapsed: false });
    });
    render(<Sidebar onCmdK={() => {}} status={STATUS} />);
    expect(screen.getByRole("navigation", { name: /primary navigation/i }).style.width).toBe(
      "64px",
    );
  });

  it("clicking the search opens the command palette via onCmdK", () => {
    const onCmdK = vi.fn();
    render(<Sidebar onCmdK={onCmdK} status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: /search apps/i }));
    expect(onCmdK).toHaveBeenCalledTimes(1);
  });

  it("rail variant launches a pinned app on icon click", () => {
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "rail", sidebarCollapsed: false });
    });
    render(<Sidebar onCmdK={() => {}} status={STATUS} />);
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    fireEvent.click(within(nav).getByRole("button", { name: "Monitor" }));
    expect(launch).toHaveBeenCalledWith("monitor");
  });
});
