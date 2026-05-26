import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Each test gets a fresh module so zustand state doesn't bleed between tests.
// We achieve isolation by resetting the store between tests.
beforeEach(() => {
  localStorage.clear();
  vi.resetModules();
});

afterEach(() => {
  localStorage.clear();
});

async function getHook() {
  const { useShellPreferences } = await import("./useShellPreferences");
  return useShellPreferences;
}

describe("useShellPreferences", () => {
  it("has correct default values", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    expect(result.current.sidebarVariant).toBe("expanded");
    expect(result.current.sidebarCollapsed).toBe(false);
  });

  it("setSidebarVariant updates state and persists to localStorage", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());

    act(() => result.current.setSidebarVariant("rail"));

    expect(result.current.sidebarVariant).toBe("rail");
    expect(localStorage.getItem("cs_sidebar_variant")).toBe("rail");
  });

  it("setSidebarVariant persists twopane variant", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());

    act(() => result.current.setSidebarVariant("twopane"));

    expect(result.current.sidebarVariant).toBe("twopane");
    expect(localStorage.getItem("cs_sidebar_variant")).toBe("twopane");
  });

  it("setSidebarCollapsed persists to localStorage", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());

    act(() => result.current.setSidebarCollapsed(true));

    expect(result.current.sidebarCollapsed).toBe(true);
    expect(localStorage.getItem("cs_sidebar_collapsed")).toBe("true");
  });

  it("toggleSidebarCollapsed flips the collapsed state", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());

    act(() => result.current.toggleSidebarCollapsed());
    expect(result.current.sidebarCollapsed).toBe(true);

    act(() => result.current.toggleSidebarCollapsed());
    expect(result.current.sidebarCollapsed).toBe(false);
  });

  it("hydrates sidebarVariant from localStorage on init", async () => {
    localStorage.setItem("cs_sidebar_variant", "rail");
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    expect(result.current.sidebarVariant).toBe("rail");
  });

  it("hydrates sidebarCollapsed from localStorage on init", async () => {
    localStorage.setItem("cs_sidebar_collapsed", "true");
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    expect(result.current.sidebarCollapsed).toBe(true);
  });

  it("ignores invalid stored sidebarVariant and falls back to default", async () => {
    localStorage.setItem("cs_sidebar_variant", "not-a-real-variant");
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    expect(result.current.sidebarVariant).toBe("expanded");
  });

  it("ignores invalid stored sidebarCollapsed and falls back to default", async () => {
    localStorage.setItem("cs_sidebar_collapsed", "maybe");
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    expect(result.current.sidebarCollapsed).toBe(false);
  });

  it("dispatches clawdstrike:shell-prefs-changed on setSidebarVariant", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    const events: Event[] = [];
    const handler = (e: Event) => events.push(e);
    window.addEventListener("clawdstrike:shell-prefs-changed", handler);

    act(() => result.current.setSidebarVariant("rail"));

    window.removeEventListener("clawdstrike:shell-prefs-changed", handler);
    expect(events.length).toBeGreaterThan(0);
  });

  it("dispatches clawdstrike:shell-prefs-changed on toggleSidebarCollapsed", async () => {
    const useShellPreferences = await getHook();
    const { result } = renderHook(() => useShellPreferences());
    const events: Event[] = [];
    const handler = (e: Event) => events.push(e);
    window.addEventListener("clawdstrike:shell-prefs-changed", handler);

    act(() => result.current.toggleSidebarCollapsed());

    window.removeEventListener("clawdstrike:shell-prefs-changed", handler);
    expect(events.length).toBeGreaterThan(0);
  });
});
