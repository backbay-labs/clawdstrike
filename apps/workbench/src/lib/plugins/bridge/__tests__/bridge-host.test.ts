/**
 * PluginBridgeHost Tests
 *
 * Tests for the host-side bridge dispatch: origin validation, method dispatch
 * to workbench registries, error handling for unknown methods and handler
 * exceptions, pushEvent delivery, and destroy cleanup.
 *
 * Mocks the real workbench registries (guard, file-type, status-bar) so host
 * dispatch can be tested in isolation.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type {
  BridgeRequest,
  BridgeResponse,
  BridgeErrorResponse,
  BridgeEvent,
} from "../types";
import type { ReceiptMiddleware } from "../receipt-middleware";

// ---- Registry mocks ----

const mockGuardDispose = vi.fn();
vi.mock("../../../workbench/guard-registry", () => ({
  registerGuard: vi.fn(() => mockGuardDispose),
}));

const mockFileTypeDispose = vi.fn();
vi.mock("../../../workbench/file-type-registry", () => ({
  registerFileType: vi.fn(() => mockFileTypeDispose),
}));

const mockStatusBarDispose = vi.fn();
vi.mock("../../../workbench/status-bar-registry", () => ({
  statusBarRegistry: {
    register: vi.fn(() => mockStatusBarDispose),
  },
}));

const {
  mockCommandRegistryRegister,
  mockCommandRegistryUnregister,
} = vi.hoisted(() => ({
  mockCommandRegistryRegister: vi.fn(),
  mockCommandRegistryUnregister: vi.fn(),
}));
vi.mock("../../../command-registry", () => ({
  commandRegistry: {
    register: mockCommandRegistryRegister,
    unregister: mockCommandRegistryUnregister,
  },
}));

// Import after mocks
import { PluginBridgeHost } from "../bridge-host";
import { registerGuard } from "../../../workbench/guard-registry";
import { registerFileType } from "../../../workbench/file-type-registry";
import { statusBarRegistry } from "../../../workbench/status-bar-registry";
import { commandRegistry } from "../../../command-registry";

// ---- Helpers ----

let currentMessageSource: MessageEventSource | null = null;

function makeRequest(
  method: string,
  params?: unknown,
  id = "req-1",
): BridgeRequest {
  return { id, type: "request", method, params };
}

function makeMessageEvent(
  data: unknown,
  origin = "null",
  source: MessageEventSource | null = currentMessageSource,
): MessageEvent {
  const event = new MessageEvent("message", { data, origin });
  Object.defineProperty(event, "source", {
    configurable: true,
    value: source,
  });
  return event;
}

// ---- Setup ----

describe("PluginBridgeHost", () => {
  let host: PluginBridgeHost;
  let mockTargetWindow: { postMessage: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    vi.clearAllMocks();
    mockTargetWindow = { postMessage: vi.fn() };
    currentMessageSource = mockTargetWindow as unknown as Window;
    host = new PluginBridgeHost({
      pluginId: "test-plugin",
      targetWindow: mockTargetWindow as unknown as Window,
    });
  });

  afterEach(() => {
    host.destroy();
  });

  // ---- guards.register ----

  describe("guards.register", () => {
    it("calls registerGuard and responds with registered: true", () => {
      const guardPayload = {
        id: "custom_guard",
        name: "Custom Guard",
        technicalName: "CustomGuard",
        description: "A custom guard",
        category: "detection",
        defaultVerdict: "deny",
        icon: "IconShield",
        configFields: [],
      };

      host.handleMessage(
        makeMessageEvent(makeRequest("guards.register", guardPayload)),
      );

      expect(registerGuard).toHaveBeenCalledWith(guardPayload);

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply).toMatchObject({
        id: "req-1",
        type: "response",
        result: { registered: true },
      });
    });
  });

  // ---- storage round-trip ----

  describe("storage.set + storage.get", () => {
    it("round-trips a value through the plugin-scoped store", () => {
      host.handleMessage(
        makeMessageEvent(
          makeRequest("storage.set", { key: "theme", value: "dark" }, "s1"),
        ),
      );

      // Verify set response
      const setReply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(setReply).toMatchObject({
        id: "s1",
        type: "response",
      });

      host.handleMessage(
        makeMessageEvent(
          makeRequest("storage.get", { key: "theme" }, "s2"),
        ),
      );

      const getReply = mockTargetWindow.postMessage.mock
        .calls[1][0] as BridgeResponse;
      expect(getReply).toMatchObject({
        id: "s2",
        type: "response",
        result: "dark",
      });
    });
  });

  // ---- unknown method ----

  describe("unknown method", () => {
    it("responds with METHOD_NOT_FOUND error", () => {
      host.handleMessage(
        makeMessageEvent(makeRequest("nonexistent.method", {})),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply).toMatchObject({
        id: "req-1",
        type: "error",
        error: {
          code: "METHOD_NOT_FOUND",
          message: expect.stringContaining("nonexistent.method"),
        },
      });
    });
  });

  // ---- origin validation ----

  describe("origin validation", () => {
    it("silently drops messages with wrong origin", () => {
      host.handleMessage(
        makeMessageEvent(
          makeRequest("storage.get", { key: "x" }),
          "https://evil.com",
        ),
      );

      expect(mockTargetWindow.postMessage).not.toHaveBeenCalled();
    });
  });

  // ---- non-bridge messages ----

  describe("non-bridge message filtering", () => {
    it("silently drops non-BridgeMessage data", () => {
      host.handleMessage(
        makeMessageEvent("just a string"),
      );
      host.handleMessage(
        makeMessageEvent({ foo: "bar" }),
      );
      host.handleMessage(
        makeMessageEvent(null),
      );

      expect(mockTargetWindow.postMessage).not.toHaveBeenCalled();
    });
  });

  // ---- handler error ----

  describe("handler exception", () => {
    it("responds with INTERNAL_ERROR when a handler throws", () => {
      // Make registerGuard throw
      vi.mocked(registerGuard).mockImplementationOnce(() => {
        throw new Error("registry full");
      });

      host.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", { id: "boom" }),
        ),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply).toMatchObject({
        id: "req-1",
        type: "error",
        error: {
          code: "INTERNAL_ERROR",
          message: "registry full",
        },
      });
    });
  });

  // ---- pushEvent ----

  describe("pushEvent", () => {
    it("sends a BridgeEvent to the targetWindow", () => {
      host.pushEvent("policy.changed", { version: "2.0" });

      const sent = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeEvent;
      expect(sent).toMatchObject({
        type: "event",
        method: "policy.changed",
        params: { version: "2.0" },
      });
    });
  });

  // ---- destroy ----

  describe("destroy()", () => {
    it("calls all tracked disposables", () => {
      // Register a guard to create a disposable
      host.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", {
            id: "g1",
            name: "G1",
            technicalName: "G1Guard",
            description: "",
            category: "detection",
            defaultVerdict: "deny",
            icon: "IconShield",
            configFields: [],
          }),
        ),
      );

      host.destroy();

      expect(mockGuardDispose).toHaveBeenCalled();
    });
  });

  // ---- commands.register ----

  describe("commands.register", () => {
    it("registers the command with the host command registry and responds with registered: true", () => {
      host.handleMessage(
        makeMessageEvent(
          makeRequest("commands.register", {
            id: "my.command",
            title: "My Command",
            category: "Sidebar",
            shortcut: "Cmd+Shift+M",
            icon: "plug",
          }),
        ),
      );

      expect(commandRegistry.register).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "my.command",
          title: "My Command",
          category: "Sidebar",
          keybinding: "Cmd+Shift+M",
          icon: "plug",
          execute: expect.any(Function),
        }),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply).toMatchObject({
        id: "req-1",
        type: "response",
        result: { registered: true },
      });
    });

    it("forwards command execution back to the plugin iframe as a bridge event", () => {
      host.handleMessage(
        makeMessageEvent(
          makeRequest("commands.register", {
            id: "my.command",
            title: "My Command",
            category: "InvalidCategory",
          }),
        ),
      );

      const registeredCommand = vi.mocked(commandRegistry.register).mock
        .calls[0][0] as { execute: () => void; category: string };
      expect(registeredCommand.category).toBe("View");

      registeredCommand.execute();

      const event = mockTargetWindow.postMessage.mock
        .calls[1][0] as BridgeEvent;
      expect(event).toMatchObject({
        type: "event",
        method: "command.execute",
        params: { id: "my.command" },
      });
    });
  });

  // ---- fileTypes.register ----

  describe("fileTypes.register", () => {
    it("calls registerFileType and responds with registered: true", () => {
      const fileTypePayload = {
        id: "custom_ft",
        label: "Custom File Type",
        shortLabel: "Custom",
        extensions: [".cft"],
        iconColor: "#ff0000",
        defaultContent: "",
        testable: false,
        convertibleTo: [],
      };

      host.handleMessage(
        makeMessageEvent(
          makeRequest("fileTypes.register", fileTypePayload),
        ),
      );

      expect(registerFileType).toHaveBeenCalledWith(fileTypePayload);

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply).toMatchObject({
        id: "req-1",
        type: "response",
        result: { registered: true },
      });
    });
  });

  // ---- statusBar.register ----

  describe("statusBar.register", () => {
    it("calls statusBarRegistry.register and responds with registered: true", () => {
      const statusBarPayload = {
        id: "custom_sb",
        side: "left" as const,
        priority: 50,
        render: null, // Render function cannot cross iframe boundary; host provides placeholder
      };

      host.handleMessage(
        makeMessageEvent(
          makeRequest("statusBar.register", statusBarPayload),
        ),
      );

      expect(statusBarRegistry.register).toHaveBeenCalled();

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply).toMatchObject({
        id: "req-1",
        type: "response",
        result: { registered: true },
      });
    });
  });

  // ---- Permission Enforcement ----

  describe("permission enforcement", () => {
    let permHost: PluginBridgeHost;

    afterEach(() => {
      permHost?.destroy();
    });

    it("allows guards.register when permissions include guards:register", () => {
      permHost = new PluginBridgeHost({
        pluginId: "perm-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["guards:register"],
      });

      permHost.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", {
            id: "g1",
            name: "G1",
            technicalName: "G1Guard",
            description: "",
            category: "detection",
            defaultVerdict: "deny",
            icon: "IconShield",
            configFields: [],
          }),
        ),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply.type).toBe("response");
      expect(reply.result).toMatchObject({ registered: true });
    });

    it("rejects storage.set with PERMISSION_DENIED when only guards:register is granted", () => {
      permHost = new PluginBridgeHost({
        pluginId: "perm-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["guards:register"],
      });

      permHost.handleMessage(
        makeMessageEvent(
          makeRequest("storage.set", { key: "k", value: "v" }),
        ),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply.type).toBe("error");
      expect(reply.error.code).toBe("PERMISSION_DENIED");
    });

    it("PERMISSION_DENIED error message includes plugin ID, required permission, and method name", () => {
      permHost = new PluginBridgeHost({
        pluginId: "my-locked-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: [],
      });

      permHost.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", { id: "g1" }),
        ),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply.error.code).toBe("PERMISSION_DENIED");
      expect(reply.error.message).toContain("my-locked-plugin");
      expect(reply.error.message).toContain("guards:register");
      expect(reply.error.message).toContain("guards.register");
    });

    it("allows both storage.get and storage.set when both storage permissions are granted", () => {
      permHost = new PluginBridgeHost({
        pluginId: "storage-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["storage:read", "storage:write"],
      });

      permHost.handleMessage(
        makeMessageEvent(
          makeRequest("storage.set", { key: "k", value: "v" }, "s1"),
        ),
      );
      permHost.handleMessage(
        makeMessageEvent(
          makeRequest("storage.get", { key: "k" }, "s2"),
        ),
      );

      const setReply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(setReply.type).toBe("response");

      const getReply = mockTargetWindow.postMessage.mock
        .calls[1][0] as BridgeResponse;
      expect(getReply.type).toBe("response");
    });

    it("rejects all bridge calls with PERMISSION_DENIED when permissions is empty array", () => {
      permHost = new PluginBridgeHost({
        pluginId: "empty-perm-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: [],
      });

      const methods = [
        "guards.register",
        "commands.register",
        "storage.get",
        "storage.set",
        "fileTypes.register",
        "statusBar.register",
        "sidebar.register",
      ];

      for (const method of methods) {
        permHost.handleMessage(
          makeMessageEvent(makeRequest(method, {}, `req-${method}`)),
        );
      }

      for (let i = 0; i < methods.length; i++) {
        const reply = mockTargetWindow.postMessage.mock
          .calls[i][0] as BridgeErrorResponse;
        expect(reply.type).toBe("error");
        expect(reply.error.code).toBe("PERMISSION_DENIED");
      }
    });

    it("backward compat: PluginBridgeHost without permissions option allows all calls", () => {
      // The default 'host' created in beforeEach has no permissions
      host.handleMessage(
        makeMessageEvent(
          makeRequest("storage.set", { key: "x", value: "y" }, "s1"),
        ),
      );
      host.handleMessage(
        makeMessageEvent(
          makeRequest("storage.get", { key: "x" }, "s2"),
        ),
      );

      const setReply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(setReply.type).toBe("response");

      const getReply = mockTargetWindow.postMessage.mock
        .calls[1][0] as BridgeResponse;
      expect(getReply.type).toBe("response");
      expect(getReply.result).toBe("y");
    });

    it("permission check happens BEFORE handler dispatch (handler never called if denied)", () => {
      const customHandler = vi.fn(() => ({ ok: true }));

      permHost = new PluginBridgeHost({
        pluginId: "spy-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["storage:read"], // Does NOT include guards:register
      });

      // Override with spy handler
      permHost.registerHandler("guards.register", customHandler);

      permHost.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", { id: "g1" }),
        ),
      );

      // Handler should NOT have been called -- permission denied first
      expect(customHandler).not.toHaveBeenCalled();

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply.error.code).toBe("PERMISSION_DENIED");
    });
  });

  // ---- Receipt Middleware Integration ----

  describe("receipt middleware integration", () => {
    let receiptHost: PluginBridgeHost;
    let mockRecordAllowed: ReturnType<typeof vi.fn<ReceiptMiddleware["recordAllowed"]>>;
    let mockRecordDenied: ReturnType<typeof vi.fn<ReceiptMiddleware["recordDenied"]>>;
    let mockRecordError: ReturnType<typeof vi.fn<ReceiptMiddleware["recordError"]>>;

    beforeEach(() => {
      mockRecordAllowed = vi.fn<ReceiptMiddleware["recordAllowed"]>().mockResolvedValue(undefined);
      mockRecordDenied = vi.fn<ReceiptMiddleware["recordDenied"]>().mockResolvedValue(undefined);
      mockRecordError = vi.fn<ReceiptMiddleware["recordError"]>().mockResolvedValue(undefined);
    });

    afterEach(() => {
      receiptHost?.destroy();
    });

    it("calls recordAllowed after a successful guards.register dispatch", () => {
      receiptHost = new PluginBridgeHost({
        pluginId: "receipt-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["guards:register"],
        receiptMiddleware: {
          recordAllowed: mockRecordAllowed,
          recordDenied: mockRecordDenied,
          recordError: mockRecordError,
        },
      });

      receiptHost.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", {
            id: "g1",
            name: "G1",
            technicalName: "G1Guard",
            description: "",
            category: "detection",
            defaultVerdict: "deny",
            icon: "IconShield",
            configFields: [],
          }),
        ),
      );

      // Response should have been sent
      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply.type).toBe("response");
      expect(reply.result).toMatchObject({ registered: true });

      // Receipt middleware should have been called with recordAllowed
      expect(mockRecordAllowed).toHaveBeenCalledWith(
        "guards.register",
        expect.anything(),
        expect.any(Number),
      );
    });

    it("calls recordDenied after a permission-denied call", () => {
      receiptHost = new PluginBridgeHost({
        pluginId: "receipt-denied-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: [], // deny all
        receiptMiddleware: {
          recordAllowed: mockRecordAllowed,
          recordDenied: mockRecordDenied,
          recordError: mockRecordError,
        },
      });

      receiptHost.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", { id: "g1" }),
        ),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply.type).toBe("error");
      expect(reply.error.code).toBe("PERMISSION_DENIED");

      // Receipt middleware should have been called with recordDenied
      expect(mockRecordDenied).toHaveBeenCalledWith(
        "guards.register",
        expect.anything(),
        "guards:register",
      );
    });

    it("calls recordAllowed for a successful storage.set dispatch", () => {
      receiptHost = new PluginBridgeHost({
        pluginId: "receipt-storage-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["storage:write"],
        receiptMiddleware: {
          recordAllowed: mockRecordAllowed,
          recordDenied: mockRecordDenied,
          recordError: mockRecordError,
        },
      });

      receiptHost.handleMessage(
        makeMessageEvent(
          makeRequest("storage.set", { key: "k", value: "v" }),
        ),
      );

      expect(mockRecordAllowed).toHaveBeenCalledWith(
        "storage.set",
        expect.anything(),
        expect.any(Number),
      );
    });

    it("calls recordError when a handler throws (sync)", () => {
      vi.mocked(registerGuard).mockImplementationOnce(() => {
        throw new Error("handler boom");
      });

      receiptHost = new PluginBridgeHost({
        pluginId: "receipt-err-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["guards:register"],
        receiptMiddleware: {
          recordAllowed: mockRecordAllowed,
          recordDenied: mockRecordDenied,
          recordError: mockRecordError,
        },
      });

      receiptHost.handleMessage(
        makeMessageEvent(
          makeRequest("guards.register", { id: "g1" }),
        ),
      );

      expect(mockRecordError).toHaveBeenCalledWith(
        "guards.register",
        expect.anything(),
        expect.any(Number),
      );
    });
  });

  // ---- Network fetch handler ----

  describe("network.fetch handler", () => {
    let netHost: PluginBridgeHost;

    afterEach(() => {
      netHost?.destroy();
      vi.restoreAllMocks();
    });

    it("proxies fetch for allowed domain and returns response", async () => {
      const mockHeaders = new Headers({ "content-type": "application/json" });
      const mockResponse = {
        status: 200,
        statusText: "OK",
        headers: mockHeaders,
        text: async () => '{"result": "ok"}',
      };

      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

      netHost = new PluginBridgeHost({
        pluginId: "net-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["network:fetch"],
        networkPermissions: [
          { type: "network:fetch", allowedDomains: ["api.virustotal.com"] },
        ],
      });

      netHost.handleMessage(
        makeMessageEvent(
          makeRequest("network.fetch", {
            url: "https://api.virustotal.com/v3/files",
          }),
        ),
      );

      // Wait for async handler to complete
      await vi.waitFor(() => {
        expect(mockTargetWindow.postMessage).toHaveBeenCalled();
      });

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeResponse;
      expect(reply.type).toBe("response");
      expect(reply.result).toMatchObject({
        status: 200,
        statusText: "OK",
      });
    });

    it("returns PERMISSION_DENIED for domain not in allowed list", async () => {
      netHost = new PluginBridgeHost({
        pluginId: "net-plugin-denied",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["network:fetch"],
        networkPermissions: [
          { type: "network:fetch", allowedDomains: ["api.virustotal.com"] },
        ],
      });

      netHost.handleMessage(
        makeMessageEvent(
          makeRequest("network.fetch", { url: "https://evil.com/steal" }),
        ),
      );

      // Handler is async -- wait for the promise rejection to deliver the error
      await vi.waitFor(() => {
        expect(mockTargetWindow.postMessage).toHaveBeenCalled();
      });

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply.type).toBe("error");
      expect(reply.error.code).toBe("PERMISSION_DENIED");
    });

    it("returns PERMISSION_DENIED when network:fetch permission is not granted", () => {
      netHost = new PluginBridgeHost({
        pluginId: "no-net-plugin",
        targetWindow: mockTargetWindow as unknown as Window,
        permissions: ["guards:register"],
      });

      netHost.handleMessage(
        makeMessageEvent(
          makeRequest("network.fetch", {
            url: "https://api.virustotal.com/v3/files",
          }),
        ),
      );

      const reply = mockTargetWindow.postMessage.mock
        .calls[0][0] as BridgeErrorResponse;
      expect(reply.type).toBe("error");
      expect(reply.error.code).toBe("PERMISSION_DENIED");
    });
  });
});
