import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

vi.mock("@/lib/workbench/secure-store", () => ({
  secureStore: {
    init: vi.fn().mockResolvedValue(undefined),
  },
  migrateCredentialsToStronghold: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/lib/workbench/http-transport", () => ({
  createHttpTransport: vi.fn(() => vi.fn().mockResolvedValue(new Response())),
  httpFetch: vi.fn().mockResolvedValue(new Response()),
}));

describe("App error boundary", () => {
  afterEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    window.location.hash = "";
  });

  it("catches provider initialization errors before the route tree mounts", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    vi.doMock("@/lib/workbench/use-fleet-connection", () => ({
      FleetConnectionProvider: () => {
        throw new Error("fleet init failed");
      },
      useFleetConnection: () => ({
        connection: { connected: false },
        isConnecting: false,
        error: null,
        agents: [],
        remotePolicyInfo: null,
        connect: vi.fn(),
        disconnect: vi.fn(),
        testConnection: vi.fn(),
        refreshAgents: vi.fn(),
        refreshRemotePolicy: vi.fn(),
        getCredentials: () => ({ apiKey: "", controlApiToken: "" }),
        getAuthenticatedConnection: () => ({ connected: false, hushdUrl: "", controlApiUrl: "", apiKey: "", controlApiToken: "", hushdHealth: null, agentCount: 0 }),
      }),
    }));

    try {
      const { App } = await import("../App");
      render(<App />);

      expect(await screen.findByText("Something went wrong")).toBeInTheDocument();
      expect(screen.getByText("fleet init failed")).toBeInTheDocument();
    } finally {
      consoleError.mockRestore();
    }
  });
});
