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

import { resolveEffectiveVariant, useShellPreferences } from "../../../state/useShellPreferences";
import { Sidebar } from "./Sidebar";
import { SidebarExpanded } from "./SidebarExpanded";

/** Render the orchestrator with the variant + collapsed resolved from current store state. */
function renderSidebar(props: { onCmdK?: () => void } = {}) {
  const { sidebarVariant, sidebarCollapsed } = useShellPreferences.getState();
  const variant = resolveEffectiveVariant(sidebarVariant, sidebarCollapsed);
  const collapsed = sidebarVariant === "expanded" && sidebarCollapsed;
  return render(
    <Sidebar
      onCmdK={props.onCmdK ?? (() => {})}
      status={STATUS}
      variant={variant}
      collapsed={collapsed}
    />,
  );
}

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
    render(<SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} />);
    expect(screen.getByText("Operations")).toBeTruthy();
    expect(screen.getByText("Policy + Runtime")).toBeTruthy();
    expect(screen.getByText("Tools")).toBeTruthy();
  });

  it("renders nav rows for apps including Monitor and Policies", () => {
    render(<SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} />);
    expect(screen.getByRole("button", { name: "Monitor" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Policies" })).toBeTruthy();
  });

  it("launches the process when a nav row is clicked", () => {
    render(<SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: /monitor/i }));
    expect(launch).toHaveBeenCalledWith("monitor");
  });

  it("marks the focused app's row with aria-current=page", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(<SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} />);
    const monitor = screen.getByRole("button", { name: /monitor/i });
    expect(monitor.getAttribute("aria-current")).toBe("page");
  });

  it("calls onCmdK when the search bar is clicked", () => {
    const onCmdK = vi.fn();
    render(<SidebarExpanded onCmdK={onCmdK} onToggleCollapse={() => {}} status={STATUS} />);
    fireEvent.click(screen.getByRole("button", { name: /search apps/i }));
    expect(onCmdK).toHaveBeenCalledTimes(1);
  });

  it("renders SSE, Violations, Uptime, and Build pulses in the footer when expanded", () => {
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onToggleCollapse={() => {}}
        status={{ sseLive: true, violations: 3, uptime: "02:00:00", build: "9.9.9" }}
      />,
    );
    // Scope to the expanded layer — the (hidden) collapsed layer also carries a
    // violations count, which would otherwise collide on the bare number.
    const layer = within(screen.getByTestId("sidebar-layer-expanded"));
    expect(layer.getByText("SSE")).toBeTruthy();
    expect(layer.getByText("● LIVE")).toBeTruthy();
    expect(layer.getByText("Violations")).toBeTruthy();
    expect(layer.getByText("3")).toBeTruthy();
    expect(layer.getByText("Uptime")).toBeTruthy();
    expect(layer.getByText("02:00:00")).toBeTruthy();
    expect(layer.getByText("Build")).toBeTruthy();
    expect(layer.getByText("9.9.9")).toBeTruthy();
  });

  it("shows SSE DOWN in crimson when offline", () => {
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onToggleCollapse={() => {}}
        status={{ sseLive: false, violations: 0, uptime: "00:00:00", build: "0.2.0" }}
      />,
    );
    const sseValue = screen.getByText("◌ DOWN");
    expect(sseValue.style.color).toBe("var(--crimson)");
  });

  it("morphs to a 64px rail-like width when collapsed", () => {
    render(
      <SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} collapsed />,
    );
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(nav.style.width).toBe("64px");
  });

  it("renders the polished 44x44 NavIconButton rail body when collapsed", () => {
    render(
      <SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} collapsed />,
    );
    // The visible (collapsed) layer must show icon-rail buttons, not folded rows.
    const layer = within(screen.getByTestId("sidebar-layer-collapsed"));
    const monitor = layer.getByRole("button", { name: "Monitor" }) as HTMLButtonElement;
    // NavIconButton geometry: 44×44 rounded icon target (vs labeled NavRowButton).
    expect(monitor.style.width).toBe("44px");
    expect(monitor.style.height).toBe("44px");
  });

  it("shows the gold active treatment on the focused app when collapsed", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(
      <SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} collapsed />,
    );
    const layer = within(screen.getByTestId("sidebar-layer-collapsed"));
    const monitor = layer.getByRole("button", { name: "Monitor" }) as HTMLButtonElement;
    expect(monitor.getAttribute("aria-current")).toBe("page");
    // Active = gold gradient fill + gold icon + gold bloom (the rail treatment).
    expect(monitor.style.background).toContain("linear-gradient");
    expect(monitor.style.color).toBe("var(--gold)");
    expect(monitor.style.boxShadow).toContain("rgba(214,177,90");
  });

  it("launches the app from the collapsed rail icon", () => {
    render(
      <SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} collapsed />,
    );
    const layer = within(screen.getByTestId("sidebar-layer-collapsed"));
    fireEvent.click(layer.getByRole("button", { name: "Monitor" }));
    expect(launch).toHaveBeenCalledWith("monitor");
  });

  it("shows the compact SSE + violations pulse when collapsed", () => {
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onToggleCollapse={() => {}}
        status={{ sseLive: true, violations: 2, uptime: "01:00:00", build: "0.2.0" }}
        collapsed
      />,
    );
    expect(screen.getByTestId("sidebar-collapsed-sse")).toBeTruthy();
    expect(screen.getByTestId("sidebar-collapsed-violations").textContent).toBe("2");
  });

  it("drives the width morph via a CSS transition tagged for reduced-motion", () => {
    // The morph is a pure CSS width transition on a `cs-animated` element, which
    // the global `@media (prefers-reduced-motion: reduce)` rule disables — so
    // the reduced-motion path renders instantly with no JS-driven animation.
    render(<SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} />);
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(nav.classList.contains("cs-animated")).toBe(true);
    expect(nav.style.transition).toContain("width");
  });
});

describe("SidebarExpanded — collapse/expand toggle", () => {
  it("renders a 'Collapse sidebar' toggle with aria-expanded=true when open", () => {
    render(<SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} />);
    const toggle = screen.getByRole("button", { name: /collapse sidebar/i });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
  });

  it("renders an 'Expand sidebar' toggle with aria-expanded=false when collapsed", () => {
    render(
      <SidebarExpanded onCmdK={() => {}} onToggleCollapse={() => {}} status={STATUS} collapsed />,
    );
    const toggle = screen.getByRole("button", { name: /expand sidebar/i });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
  });

  it("calls onToggleCollapse when the toggle is clicked (expanded)", () => {
    const onToggleCollapse = vi.fn();
    render(
      <SidebarExpanded onCmdK={() => {}} onToggleCollapse={onToggleCollapse} status={STATUS} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /collapse sidebar/i }));
    expect(onToggleCollapse).toHaveBeenCalledTimes(1);
  });

  it("calls onToggleCollapse when the toggle is clicked (collapsed → expand)", () => {
    const onToggleCollapse = vi.fn();
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onToggleCollapse={onToggleCollapse}
        status={STATUS}
        collapsed
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /expand sidebar/i }));
    expect(onToggleCollapse).toHaveBeenCalledTimes(1);
  });

  it("surfaces the keyboard shortcut hint in the toggle title", () => {
    render(
      <SidebarExpanded
        onCmdK={() => {}}
        onToggleCollapse={() => {}}
        status={STATUS}
        toggleShortcut="⌘\"
      />,
    );
    const toggle = screen.getByRole("button", { name: /collapse sidebar/i });
    expect(toggle.getAttribute("title")).toContain("⌘\\");
  });
});

describe("Sidebar orchestrator", () => {
  it("renders the expanded sidebar (248px) for the expanded variant", () => {
    renderSidebar();
    const aside = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(aside.style.width).toBe("248px");
    // Search bar present in expanded
    expect(screen.getByRole("button", { name: /search apps/i })).toBeTruthy();
  });

  it("morphs the expanded sidebar to a 64px polished rail when collapsed", () => {
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "expanded", sidebarCollapsed: true });
    });
    renderSidebar();
    const aside = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(aside.style.width).toBe("64px");
    // The persistent expand control must be present so the user can reopen it.
    expect(screen.getByRole("button", { name: /expand sidebar/i })).toBeTruthy();
    // Collapsed rail uses the polished 44×44 NavIconButton (matches SidebarRail),
    // and — like the standalone rail — has NO inline search row.
    const layer = within(screen.getByTestId("sidebar-layer-collapsed"));
    const monitor = layer.getByRole("button", { name: "Monitor" }) as HTMLButtonElement;
    expect(monitor.style.width).toBe("44px");
    expect(screen.queryByRole("button", { name: /search apps/i })).toBeNull();
  });

  it("renders the standalone rail (64px) for the rail variant", () => {
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "rail", sidebarCollapsed: false });
    });
    renderSidebar();
    expect(screen.getByRole("navigation", { name: /primary navigation/i }).style.width).toBe(
      "64px",
    );
    // The user-chosen rail variant must NOT carry a collapse/expand toggle.
    expect(screen.queryByRole("button", { name: /expand sidebar/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /collapse sidebar/i })).toBeNull();
  });

  it("clicking the search opens the command palette via onCmdK", () => {
    const onCmdK = vi.fn();
    renderSidebar({ onCmdK });
    fireEvent.click(screen.getByRole("button", { name: /search apps/i }));
    expect(onCmdK).toHaveBeenCalledTimes(1);
  });

  it("clicking the toggle persists the collapsed flag through the store", () => {
    renderSidebar();
    fireEvent.click(screen.getByRole("button", { name: /collapse sidebar/i }));
    expect(useShellPreferences.getState().sidebarCollapsed).toBe(true);
  });

  it("rail variant launches a pinned app on icon click", () => {
    act(() => {
      useShellPreferences.setState({ sidebarVariant: "rail", sidebarCollapsed: false });
    });
    renderSidebar();
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    fireEvent.click(within(nav).getByRole("button", { name: "Monitor" }));
    expect(launch).toHaveBeenCalledWith("monitor");
  });
});
