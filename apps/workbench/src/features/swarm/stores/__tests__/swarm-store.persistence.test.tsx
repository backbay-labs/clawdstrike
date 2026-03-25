import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { readPayloadMock, writePayloadMock } = vi.hoisted(() => ({
  readPayloadMock: vi.fn(),
  writePayloadMock: vi.fn(),
}));

vi.mock("@/lib/tauri-bridge", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-bridge")>("@/lib/tauri-bridge");
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

import { useSwarms } from "../swarm-store";

const STORAGE_KEY = "clawdstrike_workbench_swarms";

function PersistenceHarness() {
  const { swarms, activeSwarm, loading } = useSwarms();
  return (
    <div data-testid="swarm-state">
      {JSON.stringify({
        loading,
        swarmCount: swarms.length,
        activeSwarmId: activeSwarm?.id ?? null,
      })}
    </div>
  );
}

function seedLegacySwarm(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      swarms: [
        {
          id: "swm_legacy",
          name: "Legacy Swarm",
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
          topicPrefix: "/baychat/v1/swarm/swm_legacy/",
          createdAt: 1,
          lastActivityAt: 1,
        },
      ],
      activeSwarmId: "swm_legacy",
      invitationTracking: {},
    }),
  );
}

describe("SwarmStore desktop persistence", () => {
  beforeEach(() => {
    localStorage.clear();
    readPayloadMock.mockReset();
    writePayloadMock.mockReset();
  });

  it("hydrates swarms from app-data persistence", async () => {
    readPayloadMock.mockResolvedValueOnce({
      swarms: [
        {
          id: "swm_disk",
          name: "Disk Swarm",
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
          topicPrefix: "/baychat/v1/swarm/swm_disk/",
          createdAt: 1,
          lastActivityAt: 1,
        },
      ],
      activeSwarmId: "swm_disk",
      invitationTracking: {},
    });

    render(<PersistenceHarness />);

    await waitFor(() => {
      expect(screen.getByTestId("swarm-state")).toHaveTextContent("\"swarmCount\":1");
    });

    expect(screen.getByTestId("swarm-state")).toHaveTextContent("\"activeSwarmId\":\"swm_disk\"");
  });

  it("migrates legacy localStorage swarms when no app-data file exists", async () => {
    seedLegacySwarm();
    readPayloadMock.mockResolvedValueOnce(null);
    writePayloadMock.mockResolvedValueOnce(true);

    render(<PersistenceHarness />);

    await waitFor(() => {
      expect(writePayloadMock).toHaveBeenCalledTimes(1);
    });

    expect(writePayloadMock).toHaveBeenCalledWith(
      "swarms-state.v1.json",
      expect.objectContaining({
        activeSwarmId: "swm_legacy",
        swarms: expect.arrayContaining([expect.objectContaining({ id: "swm_legacy" })]),
      }),
    );
  });
});
