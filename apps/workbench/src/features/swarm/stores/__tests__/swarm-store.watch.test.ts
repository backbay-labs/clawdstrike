import { cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createElement } from "react";

const {
  readPayloadMock,
  writePayloadMock,
  setSwarmFileWatchScopeMock,
  clearSwarmFileWatchScopeMock,
  subscribeSwarmFileWatchEventsMock,
} = vi.hoisted(() => ({
  readPayloadMock: vi.fn(),
  writePayloadMock: vi.fn(),
  setSwarmFileWatchScopeMock: vi.fn().mockResolvedValue(undefined),
  clearSwarmFileWatchScopeMock: vi.fn().mockResolvedValue(undefined),
  subscribeSwarmFileWatchEventsMock: vi.fn().mockReturnValue(() => {}),
}));

vi.mock("@/lib/tauri-bridge", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-bridge")>(
    "@/lib/tauri-bridge",
  );
  return {
    ...actual,
    isDesktop: () => true,
  };
});

vi.mock("../swarm-persistence", () => ({
  SWARMS_PERSISTENCE_FILE: "swarms-state.v1.json",
  readSwarmPersistencePayload: readPayloadMock,
  writeSwarmPersistencePayload: writePayloadMock,
}));

vi.mock("../swarm-file-watch", () => ({
  setSwarmFileWatchScope: setSwarmFileWatchScopeMock,
  clearSwarmFileWatchScope: clearSwarmFileWatchScopeMock,
  subscribeSwarmFileWatchEvents: subscribeSwarmFileWatchEventsMock,
}));

import { useSwarms } from "../swarm-store";

function WatchHarness() {
  useSwarms();
  return createElement("div", { "data-testid": "watch-harness" }, "mounted");
}

describe("swarm-store file watch scope", () => {
  beforeEach(() => {
    localStorage.clear();
    readPayloadMock.mockReset();
    writePayloadMock.mockReset();
    setSwarmFileWatchScopeMock.mockClear();
    clearSwarmFileWatchScopeMock.mockClear();
    subscribeSwarmFileWatchEventsMock.mockClear();
    subscribeSwarmFileWatchEventsMock.mockReturnValue(() => {});
    readPayloadMock.mockResolvedValue(null);
    writePayloadMock.mockResolvedValue(true);
  });

  afterEach(() => {
    cleanup();
  });

  it("registers file watch scope with SWARMS_PERSISTENCE_FILE on mount", () => {
    render(createElement(WatchHarness));

    expect(setSwarmFileWatchScopeMock).toHaveBeenCalledTimes(1);
    const [scopeId, config] = setSwarmFileWatchScopeMock.mock.calls[0];
    expect(typeof scopeId).toBe("string");
    expect(scopeId).toMatch(/^swarm-store-/);
    expect(config).toEqual({
      persistenceFilenames: ["swarms-state.v1.json"],
    });
  });

  it("clears file watch scope on unmount", () => {
    const { unmount } = render(createElement(WatchHarness));

    const scopeId = setSwarmFileWatchScopeMock.mock.calls[0][0];
    unmount();

    expect(clearSwarmFileWatchScopeMock).toHaveBeenCalledWith(scopeId);
  });

  it("re-hydrates store when persistence event includes swarms-state.v1.json", async () => {
    render(createElement(WatchHarness));

    expect(subscribeSwarmFileWatchEventsMock).toHaveBeenCalledTimes(1);
    const listener = subscribeSwarmFileWatchEventsMock.mock.calls[0][0];

    // Reset readPayloadMock to track re-hydration call
    readPayloadMock.mockReset();
    readPayloadMock.mockResolvedValue({
      swarms: [
        {
          id: "swm_ext",
          name: "External Swarm",
          type: "personal",
          description: "",
          members: [],
          sharedIntel: [],
          sharedDetections: [],
          trustGraph: [],
          policies: {
            minReputationToPublish: null,
            requireSignatures: true,
            autoShareDetections: false,
            compartmentalized: false,
            requiredCapabilities: [],
            maxMembers: null,
          },
          speakeasies: [],
          stats: {
            memberCount: 0,
            sentinelCount: 0,
            operatorCount: 0,
            intelShared: 0,
            activeDetections: 0,
            speakeasyCount: 0,
            avgReputation: 0,
          },
          topicPrefix: "/baychat/v1/swarm/swm_ext/",
          createdAt: 1,
          lastActivityAt: 1,
        },
      ],
      activeSwarmId: "swm_ext",
      invitationTracking: {},
    });

    // Simulate external file watch event
    listener({
      category: "persistence",
      filenames: ["swarms-state.v1.json"],
      paths: ["/tmp/state/swarms-state.v1.json"],
    });

    await waitFor(() => {
      expect(readPayloadMock).toHaveBeenCalledWith("swarms-state.v1.json");
    });
  });
});
