import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";

import { renderWithProviders } from "@/test/test-helpers";

const fleetClientMocks = vi.hoisted(() => ({
  fetchCatalogTemplates: vi.fn(),
  fetchCatalogCategories: vi.fn(),
  publishCatalogTemplate: vi.fn(),
  forkCatalogTemplate: vi.fn(),
}));

vi.mock("@/features/fleet/fleet-client", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/fleet-client")>(
    "@/features/fleet/fleet-client",
  );
  return {
    ...actual,
    fetchCatalogTemplates: fleetClientMocks.fetchCatalogTemplates,
    fetchCatalogCategories: fleetClientMocks.fetchCatalogCategories,
    publishCatalogTemplate: fleetClientMocks.publishCatalogTemplate,
    forkCatalogTemplate: fleetClientMocks.forkCatalogTemplate,
  };
});

vi.mock("@/features/fleet/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/use-fleet-connection")>(
    "@/features/fleet/use-fleet-connection",
  );
  return {
    ...actual,
    useFleetConnection: () => ({
      connection: {
        connected: true,
        hushdUrl: "http://localhost:9876",
        controlApiUrl: "http://localhost:9877",
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
      getCredentials: () => ({ apiKey: "test-api-key", controlApiToken: "test-control-token" }),
      getAuthenticatedConnection: () => ({ connected: true, hushdUrl: "http://localhost:9876", controlApiUrl: "http://localhost:9877", apiKey: "test-api-key", controlApiToken: "test-control-token", hushdHealth: null, agentCount: 0 }),
    }),
  };
});

import { CatalogBrowser } from "../catalog-browser";

let localStorageState: Record<string, string> = {};

const localStorageMock = {
  getItem: (key: string) => localStorageState[key] ?? null,
  setItem: (key: string, value: string) => {
    localStorageState[key] = value;
  },
  removeItem: (key: string) => {
    delete localStorageState[key];
  },
  clear: () => {
    localStorageState = {};
  },
  key: (index: number) => Object.keys(localStorageState)[index] ?? null,
  get length() {
    return Object.keys(localStorageState).length;
  },
};

describe("CatalogBrowser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorageState = {};
    vi.stubGlobal("localStorage", localStorageMock);
    fleetClientMocks.fetchCatalogTemplates.mockResolvedValue([]);
    fleetClientMocks.fetchCatalogCategories.mockResolvedValue([]);
    fleetClientMocks.publishCatalogTemplate.mockResolvedValue({ success: true, id: "catalog-1" });
    fleetClientMocks.forkCatalogTemplate.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows a degraded live-catalog state when the backend catalog endpoints fail", async () => {
    fleetClientMocks.fetchCatalogTemplates.mockRejectedValue(
      new Error("Catalog endpoints are unavailable on the configured control API"),
    );

    renderWithProviders(<CatalogBrowser />);

    await waitFor(() => {
      expect(screen.getByText("Live catalog unavailable")).toBeInTheDocument();
    });
    expect(screen.getByText("Catalog fetch failed")).toBeInTheDocument();
    expect(screen.queryByText("Live catalog connected")).not.toBeInTheDocument();
  });
});
