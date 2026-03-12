import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

const fleetClientMocks = vi.hoisted(() => ({
  fetchAuditEvents: vi.fn(),
}));

vi.mock("@/lib/workbench/fleet-client", async () => {
  const actual = await vi.importActual<typeof import("@/lib/workbench/fleet-client")>(
    "@/lib/workbench/fleet-client",
  );

  return {
    ...actual,
    fetchAuditEvents: fleetClientMocks.fetchAuditEvents,
  };
});

vi.mock("@/lib/workbench/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/lib/workbench/use-fleet-connection")>(
    "@/lib/workbench/use-fleet-connection",
  );

  return {
    ...actual,
    useFleetConnection: () => ({
      connection: {
        connected: true,
        hushdUrl: "http://localhost:9876",
        controlApiUrl: "http://localhost:9877",
        apiKey: "test-api-key",
        controlApiToken: "test-control-token",
        hushdHealth: null,
        agentCount: 0,
      },
      isConnecting: false,
      error: null,
      pollError: null,
      secureStorageWarning: false,
      agents: [],
      remotePolicyInfo: null,
      connect: vi.fn(),
      disconnect: vi.fn(),
      testConnection: vi.fn(),
      refreshAgents: vi.fn(),
      refreshRemotePolicy: vi.fn(),
    }),
  };
});

import { HuntLayout } from "../hunt-layout";

async function flushMicrotasks() {
  await Promise.resolve();
  await Promise.resolve();
}

describe("HuntLayout", () => {
  let intervalCallbacks: Map<number, TimerHandler>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    intervalCallbacks = new Map();
    fleetClientMocks.fetchAuditEvents.mockResolvedValue([]);
    let nextIntervalId = 1;
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((message) => {
      if (String(message).includes("not wrapped in act")) {
        return;
      }
    });

    vi.spyOn(globalThis, "setInterval").mockImplementation(
      ((callback: TimerHandler) => {
        const intervalId = nextIntervalId++;
        intervalCallbacks.set(intervalId, callback);
        return intervalId as unknown as ReturnType<typeof setInterval>;
      }) as unknown as typeof setInterval,
    );

    vi.spyOn(globalThis, "clearInterval").mockImplementation(
      ((intervalId?: ReturnType<typeof setInterval>) => {
        if (typeof intervalId === "number") {
          intervalCallbacks.delete(intervalId);
        }
      }) as unknown as typeof clearInterval,
    );
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it("stops polling while the stream is paused and resumes on live", async () => {
    render(<HuntLayout />);
    await flushMicrotasks();

    expect(fleetClientMocks.fetchAuditEvents).toHaveBeenCalledTimes(1);
    expect(globalThis.setInterval).toHaveBeenCalledTimes(1);
    expect(intervalCallbacks.size).toBe(1);

    const [activeIntervalId, activeIntervalCallback] = Array.from(intervalCallbacks.entries())[0];
    expect(typeof activeIntervalCallback).toBe("function");

    await (activeIntervalCallback as () => void)();
    await flushMicrotasks();
    expect(fleetClientMocks.fetchAuditEvents).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: "LIVE" }));
    await flushMicrotasks();
    expect(screen.getByRole("button", { name: "PAUSED" })).toBeInTheDocument();
    expect(globalThis.clearInterval).toHaveBeenCalledWith(activeIntervalId);
    expect(intervalCallbacks.size).toBe(0);
    expect(globalThis.setInterval).toHaveBeenCalledTimes(1);

    expect(fleetClientMocks.fetchAuditEvents).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: "PAUSED" }));
    await flushMicrotasks();
    expect(fleetClientMocks.fetchAuditEvents).toHaveBeenCalledTimes(3);
    expect(globalThis.setInterval).toHaveBeenCalledTimes(2);
    expect(intervalCallbacks.size).toBe(1);
  });
});
