import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const focusedId = { current: null as string | null };
const instances = { current: [] as Array<{ windowId: string; processId: string }> };

vi.mock("@backbay/glia-desktop", () => ({
  useDesktopOS: () => ({
    processes: {
      instances: instances.current,
      getDefinition: (processId: string) => ({ description: `desc:${processId}` }),
    },
    windows: { focusedId: focusedId.current },
  }),
}));

import { useActiveNavApp, useNavApps } from "./useNavApps";

beforeEach(() => {
  focusedId.current = null;
  instances.current = [];
});

describe("useNavApps", () => {
  it("builds three groups with the correct labels and order", () => {
    const { result } = renderHook(() => useNavApps());
    expect(result.current.map((g) => g.id)).toEqual(["core", "policy-ops", "advanced"]);
    expect(result.current.map((g) => g.label)).toEqual(["Operations", "Policy + Runtime", "Tools"]);
  });

  it("populates each app with description, sigil, and tone", () => {
    const { result } = renderHook(() => useNavApps());
    const monitor = result.current[0].apps.find((a) => a.processId === "monitor");
    expect(monitor).toBeTruthy();
    expect(monitor?.label).toBe("Monitor");
    expect(monitor?.description).toBe("desc:monitor");
    expect(monitor?.tone).toBe("gold");
    expect(monitor?.sigil).toBeTruthy();
    // event-stream is teal in PROCESS_TONE
    const eventStream = result.current[0].apps.find((a) => a.processId === "event-stream");
    expect(eventStream?.tone).toBe("teal");
  });

  it("marks running apps from process instances", () => {
    instances.current = [
      { windowId: "w1", processId: "monitor" },
      { windowId: "w2", processId: "audit" },
    ];
    const { result } = renderHook(() => useNavApps());
    const allApps = result.current.flatMap((g) => g.apps);
    expect(allApps.find((a) => a.processId === "monitor")?.running).toBe(true);
    expect(allApps.find((a) => a.processId === "audit")?.running).toBe(true);
    expect(allApps.find((a) => a.processId === "policy")?.running).toBe(false);
  });

  it("marks the focused window's process as active", () => {
    instances.current = [
      { windowId: "w1", processId: "monitor" },
      { windowId: "w2", processId: "audit" },
    ];
    focusedId.current = "w2";
    const { result } = renderHook(() => useNavApps());
    const allApps = result.current.flatMap((g) => g.apps);
    expect(allApps.find((a) => a.processId === "audit")?.active).toBe(true);
    expect(allApps.find((a) => a.processId === "monitor")?.active).toBe(false);
    // active also implies running
    expect(allApps.find((a) => a.processId === "audit")?.running).toBe(true);
  });

  it("marks no app active when nothing is focused", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    const { result } = renderHook(() => useNavApps());
    const allApps = result.current.flatMap((g) => g.apps);
    expect(allApps.every((a) => a.active === false)).toBe(true);
  });
});

describe("useActiveNavApp", () => {
  it("returns the single active app", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    const { result } = renderHook(() => useActiveNavApp());
    expect(result.current?.processId).toBe("monitor");
  });

  it("returns null when nothing is focused", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    const { result } = renderHook(() => useActiveNavApp());
    expect(result.current).toBeNull();
  });
});
