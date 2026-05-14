import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks - must be set up before importing the module under test
// ---------------------------------------------------------------------------

const mockDeactivatePlugin = vi.fn().mockResolvedValue(undefined);
const mockLoadPlugin = vi.fn().mockResolvedValue(undefined);

vi.mock("../../plugin-loader", () => ({
  pluginLoader: {
    deactivatePlugin: (...args: unknown[]) => mockDeactivatePlugin(...args),
    loadPlugin: (...args: unknown[]) => mockLoadPlugin(...args),
  },
}));

vi.mock("../../plugin-registry", () => ({
  pluginRegistry: {
    get: vi.fn((pluginId: string) => ({
      manifest: {
        id: pluginId,
        displayName: "Test Plugin",
        main: "/plugins/test/src/index.ts",
      },
    })),
    unregister: vi.fn(),
    register: vi.fn(),
    subscribe: vi.fn(),
  },
}));

// Track calls to storage-snapshot functions
const mockGetSnapshot = vi.fn();
const mockRestoreToApi = vi.fn();
const mockTrackStorageWrite = vi.fn();

vi.mock("../storage-snapshot", () => ({
  getSnapshot: (...args: unknown[]) => mockGetSnapshot(...args),
  restoreToApi: (...args: unknown[]) => mockRestoreToApi(...args),
  trackStorageWrite: (...args: unknown[]) => mockTrackStorageWrite(...args),
}));

import { handlePluginUpdate } from "../hmr-handler";
import type { PluginUpdateEvent } from "../types";
import { pluginRegistry } from "../../plugin-registry";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handlePluginUpdate", () => {
  const baseEvent: PluginUpdateEvent = {
    pluginId: "test-plugin",
    entryPath: "/plugins/test/src/index.ts",
    timestamp: 1234567890,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("storage snapshot lifecycle", () => {
    it("captures storageSnapshot before deactivation", async () => {
      mockGetSnapshot.mockReturnValue(new Map());

      await handlePluginUpdate(baseEvent);

      // getSnapshot should be called with the pluginId
      expect(mockGetSnapshot).toHaveBeenCalledWith("test-plugin");
      // It should be called before deactivatePlugin
      const snapshotOrder = mockGetSnapshot.mock.invocationCallOrder[0];
      const deactivateOrder = mockDeactivatePlugin.mock.invocationCallOrder[0];
      expect(snapshotOrder).toBeLessThan(deactivateOrder);
    });

    it("calls restoreToApi after re-activation when snapshot is non-empty", async () => {
      const snapshot = new Map<string, unknown>([["key1", "value1"]]);
      mockGetSnapshot.mockReturnValue(snapshot);

      await handlePluginUpdate(baseEvent);

      // restoreToApi should be called with the pluginId
      expect(mockRestoreToApi).toHaveBeenCalledWith(
        "test-plugin",
        expect.objectContaining({ set: expect.any(Function) }),
      );
      // restoreToApi should be called after loadPlugin
      const restoreOrder = mockRestoreToApi.mock.invocationCallOrder[0];
      const loadOrder = mockLoadPlugin.mock.invocationCallOrder[0];
      expect(restoreOrder).toBeGreaterThan(loadOrder);
    });

    it("does NOT call restoreToApi when snapshot is empty", async () => {
      mockGetSnapshot.mockReturnValue(new Map());

      await handlePluginUpdate(baseEvent);

      expect(mockRestoreToApi).not.toHaveBeenCalled();
    });
  });

  describe("HMR lifecycle ordering", () => {
    it("deactivates before unregistering", async () => {
      mockGetSnapshot.mockReturnValue(new Map());

      await handlePluginUpdate(baseEvent);

      const deactivateOrder = mockDeactivatePlugin.mock.invocationCallOrder[0];
      const unregisterOrder = vi.mocked(pluginRegistry.unregister).mock.invocationCallOrder[0];
      expect(deactivateOrder).toBeLessThan(unregisterOrder);
    });

    it("re-registers before re-loading", async () => {
      mockGetSnapshot.mockReturnValue(new Map());

      await handlePluginUpdate(baseEvent);

      const registerOrder = vi.mocked(pluginRegistry.register).mock.invocationCallOrder[0];
      const loadOrder = mockLoadPlugin.mock.invocationCallOrder[0];
      expect(registerOrder).toBeLessThan(loadOrder);
    });
  });
});
