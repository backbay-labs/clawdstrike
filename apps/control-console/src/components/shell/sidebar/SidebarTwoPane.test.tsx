import { fireEvent, render, screen } from "@testing-library/react";
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

import { SidebarTwoPane } from "./SidebarTwoPane";

const STATUS: ConsoleStatus = {
  sseLive: true,
  violations: 0,
  uptime: "00:00:00",
  build: "0.2.0",
};

beforeEach(() => {
  launch.mockClear();
  instances.current = [];
  focusedId.current = null;
});

describe("SidebarTwoPane", () => {
  it("renders the active group's apps in the column on mount (defaults to core)", () => {
    render(<SidebarTwoPane status={STATUS} />);
    // "core" group apps: Monitor, Agent Explorer, Event Stream, Audit Log, etc.
    expect(screen.getByRole("button", { name: "Monitor" })).toBeTruthy();
  });

  it("switches the listed apps when a different section button is clicked", () => {
    render(<SidebarTwoPane status={STATUS} />);
    // "policy-ops" section button — look for tab with that label
    const policyTab = screen.getByRole("tab", { name: "Policy + Runtime" });
    fireEvent.click(policyTab);
    // "policy-ops" contains "Policies"
    expect(screen.getByRole("button", { name: "Policies" })).toBeTruthy();
    // core-only app should no longer appear in the column
    expect(screen.queryByRole("button", { name: "Monitor" })).toBeNull();
  });

  it("auto-selects the active app's group on mount", () => {
    // monitor is in "core"; focus it
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(<SidebarTwoPane status={STATUS} />);
    // core section button should be aria-selected
    expect(screen.getByRole("tab", { name: "Operations" }).getAttribute("aria-selected")).toBe(
      "true",
    );
    expect(screen.getByRole("button", { name: "Monitor" })).toBeTruthy();
  });

  it("auto-selects the policy-ops group when a policy-ops app is focused", () => {
    instances.current = [{ windowId: "w2", processId: "policy" }];
    focusedId.current = "w2";
    render(<SidebarTwoPane status={STATUS} />);
    expect(
      screen.getByRole("tab", { name: "Policy + Runtime" }).getAttribute("aria-selected"),
    ).toBe("true");
    expect(screen.getByRole("button", { name: "Policies" })).toBeTruthy();
  });

  it("clicking an app row calls processes.launch with the correct processId", () => {
    render(<SidebarTwoPane status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: "Monitor" }));
    expect(launch).toHaveBeenCalledWith("monitor");
  });

  it("marks the focused app's row with aria-current=page", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(<SidebarTwoPane status={STATUS} />);
    expect(screen.getByRole("button", { name: "Monitor" }).getAttribute("aria-current")).toBe(
      "page",
    );
  });

  it("renders the SSE and Violations status pulses in the footer", () => {
    render(
      <SidebarTwoPane
        status={{ sseLive: true, violations: 2, uptime: "00:00:00", build: "0.2.0" }}
      />,
    );
    expect(screen.getByText("SSE")).toBeTruthy();
    expect(screen.getByText("● LIVE")).toBeTruthy();
    expect(screen.getByText("Violations")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
  });

  it("shows SSE as ◌ in crimson when offline", () => {
    render(
      <SidebarTwoPane
        status={{ sseLive: false, violations: 0, uptime: "00:00:00", build: "0.2.0" }}
      />,
    );
    const sseValue = screen.getByText("◌");
    expect(sseValue.style.color).toBe("var(--crimson)");
  });

  it("syncs active group when focused app changes via effect", () => {
    const { rerender } = render(<SidebarTwoPane status={STATUS} />);
    // default: core selected
    expect(screen.getByRole("tab", { name: "Operations" }).getAttribute("aria-selected")).toBe(
      "true",
    );
    // Now simulate a policy-ops app being focused (mutation must happen before rerender)
    instances.current = [{ windowId: "w3", processId: "policy-editor" }];
    focusedId.current = "w3";
    act(() => {
      rerender(<SidebarTwoPane status={STATUS} />);
    });
    expect(
      screen.getByRole("tab", { name: "Policy + Runtime" }).getAttribute("aria-selected"),
    ).toBe("true");
  });
});

describe("SidebarTwoPane — Sidebar orchestrator integration", () => {
  it("Sidebar renders SidebarTwoPane for the twopane variant", async () => {
    const { useShellPreferences } = await import("../../../state/useShellPreferences");
    const { Sidebar } = await import("./Sidebar");
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "twopane", sidebarCollapsed: false });
    });
    render(<Sidebar onCmdK={() => {}} status={STATUS} />);
    // Two-pane nav has no search bar (expanded-only feature)
    expect(screen.queryByRole("button", { name: /search apps/i })).toBeNull();
    // But does have section tabs
    expect(screen.getByRole("tab", { name: "Operations" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Policy + Runtime" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Tools" })).toBeTruthy();
  });
});
