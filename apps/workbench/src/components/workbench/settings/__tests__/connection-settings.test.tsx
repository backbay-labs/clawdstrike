import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ConnectionSettings } from "../connection-settings";

const useFleetConnectionMock = vi.hoisted(() => ({
  connect: vi.fn(),
  disconnect: vi.fn(),
  testConnection: vi.fn(),
  refreshAgents: vi.fn(),
  getCredentials: vi.fn(() => ({ apiKey: "", controlApiToken: "" })),
  getAuthenticatedConnection: vi.fn(() => ({
    hushdUrl: "",
    controlApiUrl: "",
    apiKey: "",
    controlApiToken: "",
    connected: false,
    hushdHealth: null,
    agentCount: 0,
  })),
}));

const emitAuditEventMock = vi.hoisted(() => vi.fn());

vi.mock("@/features/fleet/use-fleet-connection", () => ({
  useFleetConnection: () => ({
    connection: {
      connected: false,
      hushdUrl: "",
      controlApiUrl: "",
      hushdHealth: null,
      agentCount: 0,
    },
    isConnecting: false,
    error: null,
    pollError: null,
    secureStorageWarning: false,
    agents: [],
    remotePolicyInfo: null,
    connect: useFleetConnectionMock.connect,
    disconnect: useFleetConnectionMock.disconnect,
    testConnection: useFleetConnectionMock.testConnection,
    refreshAgents: useFleetConnectionMock.refreshAgents,
    getCredentials: useFleetConnectionMock.getCredentials,
    getAuthenticatedConnection: useFleetConnectionMock.getAuthenticatedConnection,
  }),
}));

vi.mock("@/lib/workbench/local-audit", () => ({
  emitAuditEvent: emitAuditEventMock,
}));

describe("ConnectionSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useFleetConnectionMock.connect.mockResolvedValue(true);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("prefills local stack defaults before connecting", async () => {
    const user = userEvent.setup();

    render(<ConnectionSettings />);

    await user.click(screen.getByRole("button", { name: "Use Local Stack" }));
    await user.click(screen.getByRole("button", { name: "Connect to Fleet" }));

    expect(useFleetConnectionMock.connect).toHaveBeenCalledWith(
      "http://localhost:9876",
      "http://localhost:8090",
      "clawdstrike-local-admin",
      "cs_local_dev_key",
    );
    expect(emitAuditEventMock).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: "fleet.connected",
        source: "settings",
        details: expect.objectContaining({
          hushdUrl: "http://localhost:9876",
          controlApiUrl: "http://localhost:8090",
        }),
      }),
    );
  });
});
