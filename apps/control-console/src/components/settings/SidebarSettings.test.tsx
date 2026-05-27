import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Reset store + localStorage between tests to prevent state bleed.
beforeEach(() => {
  localStorage.clear();
  vi.resetModules();
});

afterEach(() => {
  localStorage.clear();
});

async function setup() {
  const { useShellPreferences } = await import("../../state/useShellPreferences");
  const { SidebarSettings } = await import("./SidebarSettings");
  return { useShellPreferences, SidebarSettings };
}

describe("SidebarSettings", () => {
  it("renders three sidebar layout options", async () => {
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    expect(screen.getByRole("radio", { name: /icon rail/i })).toBeTruthy();
    expect(screen.getByRole("radio", { name: /expanded/i })).toBeTruthy();
    expect(screen.getByRole("radio", { name: /two-pane/i })).toBeTruthy();
  });

  it("renders a radiogroup with an accessible label", async () => {
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    expect(screen.getByRole("radiogroup", { name: /sidebar layout/i })).toBeTruthy();
  });

  it("reflects the current store value — default is 'expanded'", async () => {
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    const expanded = screen.getByRole("radio", { name: /expanded/i }) as HTMLInputElement;
    expect(expanded.checked).toBe(true);
  });

  it("reflects a pre-seeded localStorage value — 'rail'", async () => {
    localStorage.setItem("cs_sidebar_variant", "rail");
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    const rail = screen.getByRole("radio", { name: /icon rail/i }) as HTMLInputElement;
    expect(rail.checked).toBe(true);
    const expanded = screen.getByRole("radio", { name: /expanded/i }) as HTMLInputElement;
    expect(expanded.checked).toBe(false);
  });

  it("reflects a pre-seeded localStorage value — 'twopane'", async () => {
    localStorage.setItem("cs_sidebar_variant", "twopane");
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    const twopane = screen.getByRole("radio", { name: /two-pane/i }) as HTMLInputElement;
    expect(twopane.checked).toBe(true);
  });

  it("selecting 'rail' calls setSidebarVariant('rail') and updates the store", async () => {
    const { SidebarSettings, useShellPreferences } = await setup();
    render(<SidebarSettings />);
    fireEvent.click(screen.getByRole("radio", { name: /icon rail/i }));
    expect(useShellPreferences.getState().sidebarVariant).toBe("rail");
  });

  it("selecting 'twopane' calls setSidebarVariant('twopane') and updates the store", async () => {
    const { SidebarSettings, useShellPreferences } = await setup();
    render(<SidebarSettings />);
    fireEvent.click(screen.getByRole("radio", { name: /two-pane/i }));
    expect(useShellPreferences.getState().sidebarVariant).toBe("twopane");
  });

  it("selecting 'expanded' calls setSidebarVariant('expanded') and updates the store", async () => {
    localStorage.setItem("cs_sidebar_variant", "rail");
    const { SidebarSettings, useShellPreferences } = await setup();
    render(<SidebarSettings />);
    fireEvent.click(screen.getByRole("radio", { name: /expanded/i }));
    expect(useShellPreferences.getState().sidebarVariant).toBe("expanded");
  });

  it("persists the selected variant to localStorage", async () => {
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    fireEvent.click(screen.getByRole("radio", { name: /icon rail/i }));
    expect(localStorage.getItem("cs_sidebar_variant")).toBe("rail");
  });

  it("dispatches clawdstrike:shell-prefs-changed on variant change", async () => {
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    const events: Event[] = [];
    window.addEventListener("clawdstrike:shell-prefs-changed", (e) => events.push(e));
    fireEvent.click(screen.getByRole("radio", { name: /two-pane/i }));
    window.removeEventListener("clawdstrike:shell-prefs-changed", events[0] as never);
    expect(events.length).toBeGreaterThan(0);
  });

  it("renders description text for each option", async () => {
    const { SidebarSettings } = await setup();
    render(<SidebarSettings />);
    expect(screen.getByText(/maximum canvas space/i)).toBeTruthy();
    expect(screen.getByText(/balanced density/i)).toBeTruthy();
    expect(screen.getByText(/secondary context drawer/i)).toBeTruthy();
  });
});
