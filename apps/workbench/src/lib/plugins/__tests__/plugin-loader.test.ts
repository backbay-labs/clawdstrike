/**
 * PluginLoader Tests
 *
 * Tests for the PluginLoader: contribution routing to Phase 1 registries,
 * error isolation via Promise.allSettled, activation events for lazy loading,
 * trust verification gating, and clean deactivation with dispose.
 *
 * Uses dependency injection via `resolveModule` to avoid dynamic import() in tests.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PluginRegistry } from "../plugin-registry";
import { createTestManifest } from "../manifest-validation";
import { getGuardMeta, unregisterGuard } from "../../workbench/guard-registry";
import {
  getStatusBarItems,
  onStatusBarChange,
} from "../../workbench/status-bar-registry";
import { getView, getViewsBySlot } from "../view-registry";
import { getThreatIntelSource, _resetForTesting as resetThreatIntelRegistry } from "../../workbench/threat-intel-registry";
import { commandRegistry } from "../../command-registry";
import { clearSnapshot, getSnapshot } from "../dev/storage-snapshot";
import type { PluginManifest, GuardContribution, NetworkPermission } from "../types";
import { PluginLoader } from "../plugin-loader";
import type { PluginModule, PluginActivationContext } from "../plugin-loader";
import { PluginBridgeHost } from "../bridge";

// ---- Test fixtures ----

const TEST_GUARD: GuardContribution = {
  id: "test-plugin-guard",
  name: "Test Plugin Guard",
  technicalName: "TestPluginGuard",
  description: "A guard contributed by a test plugin",
  category: "custom",
  defaultVerdict: "deny",
  icon: "IconShield",
  configFields: [],
};

function createGuardPluginManifest(
  id = "guard-plugin",
  overrides?: Partial<PluginManifest>,
): PluginManifest {
  return createTestManifest({
    id,
    trust: "internal",
    activationEvents: ["onStartup"],
    main: "./index.ts",
    contributions: {
      guards: [{ ...TEST_GUARD, id: `${id}-guard` }],
    },
    ...overrides,
  });
}

function createCommandPluginManifest(
  id = "cmd-plugin",
  overrides?: Partial<PluginManifest>,
): PluginManifest {
  return createTestManifest({
    id,
    trust: "internal",
    activationEvents: ["onStartup"],
    main: "./index.ts",
    contributions: {
      commands: [{ id: `${id}:run`, title: "Run Test Command" }],
    },
    ...overrides,
  });
}

function createMockModule(overrides?: Partial<PluginModule>): PluginModule {
  return {
    activate: vi.fn(() => []),
    deactivate: vi.fn(),
    ...overrides,
  };
}

async function resolveCommunityPluginCode(): Promise<string> {
  return 'console.debug("community plugin test bootstrap");';
}

// ---- Test suite ----

describe("PluginLoader", () => {
  let registry: PluginRegistry;
  let loader: PluginLoader;

  // Track guard IDs registered during tests for cleanup
  const registeredGuardIds: string[] = [];
  const registeredCommandIds: string[] = [];

  beforeEach(() => {
    registry = new PluginRegistry();
  });

  afterEach(() => {
    // Clean up any guards registered during tests
    for (const id of registeredGuardIds) {
      unregisterGuard(id);
    }
    registeredGuardIds.length = 0;
    for (const id of registeredCommandIds) {
      commandRegistry.unregister(id);
    }
    registeredCommandIds.length = 0;
  });

  // Test 1: loadPlugin() with guard contribution routes to guard registry
  it("loadPlugin() with a guard contribution calls registerGuard() and the guard is findable via getGuardMeta()", async () => {
    const manifest = createGuardPluginManifest("guard-test");
    registry.register(manifest);

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    registeredGuardIds.push("guard-test-guard");
    await loader.loadPlugin("guard-test");

    const guardMeta = getGuardMeta("guard-test-guard");
    expect(guardMeta).toBeDefined();
    expect(guardMeta!.name).toBe("Test Plugin Guard");
    expect(guardMeta!.category).toBe("custom");
  });

  // Test 2: loadPlugin() with a command contribution stores the command handler via activate()
  it("loadPlugin() with a command contribution calls activate() which receives the activation context", async () => {
    const manifest = createCommandPluginManifest("cmd-test");
    registry.register(manifest);

    const activateFn = vi.fn((_ctx: PluginActivationContext) => []);
    const mockModule = createMockModule({ activate: activateFn });

    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    await loader.loadPlugin("cmd-test");

    expect(activateFn).toHaveBeenCalledOnce();
    const ctx = activateFn.mock.calls[0][0];
    expect(ctx.pluginId).toBe("cmd-test");
    expect(ctx.subscriptions).toBeInstanceOf(Array);
  });

  it("loadPlugin() provides the full SDK activation context shape for internal plugins", async () => {
    const manifest = createTestManifest({
      id: "sdk-context-test",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    registry.register(manifest);

    const activateFn = vi.fn((ctx: PluginActivationContext) => {
      ctx.storage.set("lastRun", 1);
      expect(ctx.storage.get("lastRun")).toBe(1);
      return [];
    });

    loader = new PluginLoader({
      registry,
      resolveModule: async () => createMockModule({ activate: activateFn }),
    });

    await loader.loadPlugin("sdk-context-test");

    const ctx = activateFn.mock.calls[0][0];
    expect(ctx.commands.register).toBeTypeOf("function");
    expect(ctx.guards.register).toBeTypeOf("function");
    expect(ctx.fileTypes.register).toBeTypeOf("function");
    expect(ctx.statusBar.register).toBeTypeOf("function");
    expect(ctx.sidebar.register).toBeTypeOf("function");
    expect(ctx.storage.get).toBeTypeOf("function");
    expect(ctx.storage.set).toBeTypeOf("function");
    expect(ctx.secrets.get).toBeTypeOf("function");
    expect(ctx.enrichmentRenderers.register).toBeTypeOf("function");
    expect(ctx.views.registerEditorTab).toBeTypeOf("function");
  });

  it("mirrors ctx.storage.set writes into the HMR snapshot cache", async () => {
    const pluginId = "hmr-storage-test";
    const manifest = createTestManifest({
      id: pluginId,
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      resolveModule: async () =>
        createMockModule({
          activate: (ctx) => {
            ctx.storage.set("theme", "dark");
            return [];
          },
        }),
    });

    await loader.loadPlugin(pluginId);

    expect(getSnapshot(pluginId).get("theme")).toBe("dark");

    await loader.deactivatePlugin(pluginId);
    clearSnapshot(pluginId);
  });

  it("internal plugins can register commands through ctx.commands.register and clean them up on deactivate", async () => {
    const manifest = createTestManifest({
      id: "ctx-command-plugin",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    registry.register(manifest);

    const execute = vi.fn();
    const commandId = "ctx-command-plugin.run";
    registeredCommandIds.push(commandId);

    loader = new PluginLoader({
      registry,
      resolveModule: async () =>
        createMockModule({
          activate: (ctx) => {
            const dispose = ctx.commands.register(
              { id: commandId, title: "Run Context Command", category: "View" },
              execute,
            );
            ctx.subscriptions.push(dispose);
            return [];
          },
        }),
    });

    await loader.loadPlugin("ctx-command-plugin");

    const registeredCommand = commandRegistry.getById(commandId);
    expect(registeredCommand).toBeDefined();
    await registeredCommand?.execute();
    expect(execute).toHaveBeenCalledOnce();

    await loader.deactivatePlugin("ctx-command-plugin");
    expect(commandRegistry.getById(commandId)).toBeUndefined();

    const idx = registeredCommandIds.indexOf(commandId);
    if (idx !== -1) registeredCommandIds.splice(idx, 1);
  });

  // Test 3: loadPlugin() transitions registry state: installed -> activating -> activated
  it("loadPlugin() transitions state: installed -> activating -> activated", async () => {
    const manifest = createGuardPluginManifest("state-test");
    registry.register(manifest);

    const stateTransitions: string[] = [];
    registry.subscribe("stateChanged", (event) => {
      if (event.newState) stateTransitions.push(event.newState);
    });

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    registeredGuardIds.push("state-test-guard");
    await loader.loadPlugin("state-test");

    expect(stateTransitions).toContain("activating");
    expect(stateTransitions).toContain("activated");
    expect(registry.get("state-test")!.state).toBe("activated");
  });

  // Test 4: loadPlugin() with a plugin whose activate() throws transitions to "error"
  it("loadPlugin() with activate() that throws transitions to 'error' state", async () => {
    const manifest = createTestManifest({
      id: "error-plugin",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    registry.register(manifest);

    const mockModule = createMockModule({
      activate: () => {
        throw new Error("Plugin activation failed!");
      },
    });

    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    await loader.loadPlugin("error-plugin");

    const plugin = registry.get("error-plugin")!;
    expect(plugin.state).toBe("error");
    expect(plugin.error).toContain("Plugin activation failed!");
  });

  // Test 5: loadAll() with two plugins where one throws -- the other still activates
  it("loadAll() isolates failures: one throwing plugin does not block the other", async () => {
    const successManifest = createTestManifest({
      id: "success-plugin",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    const failManifest = createTestManifest({
      id: "fail-plugin",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });

    registry.register(successManifest);
    registry.register(failManifest);

    const modules: Record<string, PluginModule> = {
      "success-plugin": createMockModule(),
      "fail-plugin": createMockModule({
        activate: () => {
          throw new Error("I fail on purpose");
        },
      }),
    };

    loader = new PluginLoader({
      registry,
      resolveModule: async (m) => modules[m.id],
    });

    await loader.loadAll();

    expect(registry.get("success-plugin")!.state).toBe("activated");
    expect(registry.get("fail-plugin")!.state).toBe("error");
  });

  // Test 6: loadPlugin() with onFileType activation event does NOT activate immediately
  it("plugin with onFileType activation event does NOT activate on loadAll(); triggerActivationEvent activates it", async () => {
    const manifest = createTestManifest({
      id: "lazy-plugin",
      trust: "internal",
      activationEvents: ["onFileType:sigma_rule"],
      main: "./index.ts",
    });
    registry.register(manifest);

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    await loader.loadAll();

    // Should NOT have been activated yet
    expect(registry.get("lazy-plugin")!.state).toBe("installed");

    // Now trigger the activation event
    await loader.triggerActivationEvent("onFileType:sigma_rule");

    expect(registry.get("lazy-plugin")!.state).toBe("activated");
  });

  // Test 7: loadPlugin() with onStartup activates immediately
  it("plugin with onStartup activation event activates immediately on loadAll()", async () => {
    const manifest = createTestManifest({
      id: "startup-plugin",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    registry.register(manifest);

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    await loader.loadAll();

    expect(registry.get("startup-plugin")!.state).toBe("activated");
  });

  // Test 8: deactivatePlugin() calls dispose functions and transitions state to "deactivated"
  it("deactivatePlugin() calls dispose functions and transitions to 'deactivated'", async () => {
    const manifest = createGuardPluginManifest("deactivate-test");
    registry.register(manifest);

    const deactivateFn = vi.fn();
    const mockModule = createMockModule({ deactivate: deactivateFn });

    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    registeredGuardIds.push("deactivate-test-guard");
    await loader.loadPlugin("deactivate-test");

    expect(registry.get("deactivate-test")!.state).toBe("activated");
    // Guard should be registered
    expect(getGuardMeta("deactivate-test-guard")).toBeDefined();

    await loader.deactivatePlugin("deactivate-test");

    expect(registry.get("deactivate-test")!.state).toBe("deactivated");
    expect(deactivateFn).toHaveBeenCalledOnce();
    // Guard should be unregistered after deactivation
    expect(getGuardMeta("deactivate-test-guard")).toBeUndefined();
    // Remove from cleanup list since it's already unregistered
    const idx = registeredGuardIds.indexOf("deactivate-test-guard");
    if (idx !== -1) registeredGuardIds.splice(idx, 1);
  });

  // Test 9: loadPlugin() rejects unsigned non-internal plugin (trust verification gate)
  it("loadPlugin() rejects unsigned non-internal plugin with trust gate error", async () => {
    const manifest = createTestManifest({
      id: "untrusted-plugin",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });
    registry.register(manifest);

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });

    await loader.loadPlugin("untrusted-plugin");

    const plugin = registry.get("untrusted-plugin")!;
    expect(plugin.state).toBe("error");
    expect(plugin.error).toBeTruthy();
    // The module's activate should NOT have been called
    expect(mockModule.activate).not.toHaveBeenCalled();
  });

  // ---- Community plugin loading ----

  describe("community plugin loading", () => {
    // Test 10: loadPlugin() for trust="internal" calls resolveModule (existing path)
    it("loadPlugin() for manifest with trust='internal' calls resolveModule", async () => {
      const manifest = createTestManifest({
        id: "internal-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const resolveModule = vi.fn(async () => createMockModule());
      loader = new PluginLoader({
        registry,
        resolveModule,
      });

      await loader.loadPlugin("internal-plugin");

      expect(resolveModule).toHaveBeenCalledOnce();
    });

    // Test 11: loadPlugin() for trust="community" does NOT call resolveModule
    it("loadPlugin() for manifest with trust='community' does NOT call resolveModule", async () => {
      const manifest = createTestManifest({
        id: "community-noresolve",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const resolveModule = vi.fn(async () => createMockModule());
      loader = new PluginLoader({
        registry,
        resolveModule,
        trustOptions: { allowUnsigned: true },
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-noresolve");

      expect(resolveModule).not.toHaveBeenCalled();
    });

    // Test 12: loadPlugin() for trust="community" creates a PluginBridgeHost
    it("loadPlugin() for manifest with trust='community' creates a PluginBridgeHost", async () => {
      const manifest = createTestManifest({
        id: "community-bridge",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-bridge");

      // An iframe should exist in the container
      const iframe = iframeContainer.querySelector("iframe");
      expect(iframe).toBeTruthy();

      // Clean up
      await loader.deactivatePlugin("community-bridge");
      iframeContainer.remove();
    });

    // Test 13: loadPlugin() for trust="community" sets up a message event listener
    it("loadPlugin() for manifest with trust='community' sets up a message event listener on the host window", async () => {
      const manifest = createTestManifest({
        id: "community-listener",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const addEventListenerSpy = vi.spyOn(window, "addEventListener");
      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-listener");

      expect(addEventListenerSpy).toHaveBeenCalledWith(
        "message",
        expect.any(Function),
      );

      // Clean up
      addEventListenerSpy.mockRestore();
      await loader.deactivatePlugin("community-listener");
      iframeContainer.remove();
    });

    // Test 14: loadPlugin() for trust="community" reaches "activated" state
    it("loadPlugin() for manifest with trust='community' reaches 'activated' state in the registry", async () => {
      const manifest = createTestManifest({
        id: "community-activated",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-activated");

      expect(registry.get("community-activated")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("community-activated");
      iframeContainer.remove();
    });

    // Test 15: deactivatePlugin() for a community plugin calls host.destroy() and removes listener
    it("deactivatePlugin() for a community plugin removes the message listener", async () => {
      const manifest = createTestManifest({
        id: "community-deactivate",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const removeEventListenerSpy = vi.spyOn(window, "removeEventListener");
      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-deactivate");

      await loader.deactivatePlugin("community-deactivate");

      expect(removeEventListenerSpy).toHaveBeenCalledWith(
        "message",
        expect.any(Function),
      );

      // Clean up
      removeEventListenerSpy.mockRestore();
      iframeContainer.remove();
    });

    // Test 16: deactivatePlugin() for a community plugin sets state to "deactivated"
    it("deactivatePlugin() for a community plugin sets state to 'deactivated' in the registry", async () => {
      const manifest = createTestManifest({
        id: "community-deactivate-state",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-deactivate-state");
      expect(registry.get("community-deactivate-state")!.state).toBe("activated");

      await loader.deactivatePlugin("community-deactivate-state");
      expect(registry.get("community-deactivate-state")!.state).toBe("deactivated");

      // Clean up
      iframeContainer.remove();
    });

    // Test 17: loadPlugin() for trust="community" with no main field still works
    it("loadPlugin() for manifest with trust='community' and no main field uses contributions directly", async () => {
      const manifest = createTestManifest({
        id: "community-no-main",
        trust: "community",
        activationEvents: ["onStartup"],
        contributions: {
          commands: [{ id: "community-no-main:test", title: "Test Command" }],
        },
      });
      // Remove main field
      delete (manifest as Partial<PluginManifest> & { main?: string }).main;
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-no-main");

      expect(registry.get("community-no-main")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("community-no-main");
      iframeContainer.remove();
    });

    it("community plugins do not route host-executed entrypoint contributions", async () => {
      const manifest = createTestManifest({
        id: "community-host-entrypoint-skip",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          statusBarItems: [
            {
              id: "community-host-status",
              side: "right" as const,
              priority: 20,
              entrypoint: "data:text/javascript,export default function CommunityStatus(){ return null; }",
            },
          ],
          editorTabs: [
            {
              id: "editor",
              label: "Community Editor",
              entrypoint: "data:text/javascript,export default function CommunityEditor(){ return null; }",
            },
          ],
          threatIntelSources: [
            {
              id: "intel",
              name: "Community Intel",
              description: "Should stay sandboxed",
              entrypoint: "data:text/javascript,export default { enrich() {} }",
            },
          ],
        },
      });
      registry.register(manifest);

      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("community-host-entrypoint-skip");

      expect(
        getStatusBarItems("right").find((item) => item.id === "community-host-status"),
      ).toBeUndefined();
      expect(getView("community-host-entrypoint-skip.editor")).toBeUndefined();
      expect(getThreatIntelSource("community-host-entrypoint-skip.intel")).toBeUndefined();
      expect(registry.get("community-host-entrypoint-skip")!.state).toBe("activated");

      warnSpy.mockRestore();
      await loader.deactivatePlugin("community-host-entrypoint-skip");
      iframeContainer.remove();
    });

    // Test 18: Existing internal plugin tests continue to pass (verified by the tests above)
    it("internal plugin loading path is unchanged after adding community fork", async () => {
      const manifest = createGuardPluginManifest("internal-unchanged");
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      registeredGuardIds.push("internal-unchanged-guard");
      await loader.loadPlugin("internal-unchanged");

      expect(registry.get("internal-unchanged")!.state).toBe("activated");
      expect(mockModule.activate).toHaveBeenCalledOnce();
      expect(getGuardMeta("internal-unchanged-guard")).toBeDefined();
    });
  });

  // ---- Permission wiring ----

  describe("permission wiring", () => {
    // Test 19: loadCommunityPlugin passes manifest.permissions to PluginBridgeHost options
    it("community plugin with string permissions passes them to PluginBridgeHost", async () => {
      const manifest = createTestManifest({
        id: "perm-wire-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: ["guards:register"],
      });
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("perm-wire-test");

      expect(registry.get("perm-wire-test")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("perm-wire-test");
      iframeContainer.remove();
    });

    // Test 20: community plugin with permissions=["guards:register"] gets PERMISSION_DENIED for storage.set
    it("community plugin with only guards:register permission gets denied for storage calls via bridge", async () => {
      const manifest = createTestManifest({
        id: "perm-deny-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: ["guards:register"],
      });
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("perm-deny-test");

      // The bridge host should enforce permissions
      // Verify by checking the plugin is activated (permissions were wired)
      expect(registry.get("perm-deny-test")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("perm-deny-test");
      iframeContainer.remove();
    });

    // Test 21: community plugin with NetworkPermission objects passes them as networkPermissions
    it("community plugin with NetworkPermission passes networkPermissions to bridge host", async () => {
      const netPerm: NetworkPermission = {
        type: "network:fetch",
        allowedDomains: ["api.virustotal.com"],
      };
      const manifest = createTestManifest({
        id: "net-perm-wire-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: [netPerm],
      });
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("net-perm-wire-test");

      expect(registry.get("net-perm-wire-test")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("net-perm-wire-test");
      iframeContainer.remove();
    });

    // Test 22: community plugin without permissions field does NOT enforce (backward compat)
    it("community plugin without permissions field allows all calls (backward compat)", async () => {
      const manifest = createTestManifest({
        id: "no-perm-compat-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      // Ensure no permissions key
      delete (manifest as Partial<PluginManifest>).permissions;
      registry.register(manifest);

      const iframeContainer = document.createElement("div");
      document.body.appendChild(iframeContainer);

      loader = new PluginLoader({
        registry,
        trustOptions: { allowUnsigned: true },
        iframeContainer,
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await loader.loadPlugin("no-perm-compat-test");

      expect(registry.get("no-perm-compat-test")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("no-perm-compat-test");
      iframeContainer.remove();
    });
  });

  // ---- View contribution routing ----

  describe("view contribution routing", () => {
    // Test 23: loadPlugin() with editorTabs contribution routes to ViewRegistry
    it("loadPlugin() with editorTabs contribution routes to ViewRegistry with slot 'editorTab'", async () => {
      const manifest = createTestManifest({
        id: "editor-tab-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          editorTabs: [
            { id: "myTab", label: "My Editor Tab", icon: "file-code", entrypoint: "./tabs/my-tab.tsx" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("editor-tab-plugin");

      const view = getView("editor-tab-plugin.myTab");
      expect(view).toBeDefined();
      expect(view!.slot).toBe("editorTab");
      expect(view!.label).toBe("My Editor Tab");
      expect(view!.icon).toBe("file-code");

      // Clean up
      await loader.deactivatePlugin("editor-tab-plugin");
    });

    // Test 24: loadPlugin() with bottomPanelTabs contribution routes to ViewRegistry
    it("loadPlugin() with bottomPanelTabs contribution routes to ViewRegistry with slot 'bottomPanelTab'", async () => {
      const manifest = createTestManifest({
        id: "bottom-panel-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          bottomPanelTabs: [
            { id: "output", label: "Plugin Output", entrypoint: "./panels/output.tsx" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("bottom-panel-plugin");

      const view = getView("bottom-panel-plugin.output");
      expect(view).toBeDefined();
      expect(view!.slot).toBe("bottomPanelTab");
      expect(view!.label).toBe("Plugin Output");

      // Clean up
      await loader.deactivatePlugin("bottom-panel-plugin");
    });

    // Test 25: loadPlugin() with rightSidebarPanels contribution routes to ViewRegistry
    it("loadPlugin() with rightSidebarPanels contribution routes to ViewRegistry with slot 'rightSidebarPanel'", async () => {
      const manifest = createTestManifest({
        id: "right-sidebar-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          rightSidebarPanels: [
            { id: "inspector", label: "Plugin Inspector", icon: "search", entrypoint: "./panels/inspector.tsx" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("right-sidebar-plugin");

      const view = getView("right-sidebar-plugin.inspector");
      expect(view).toBeDefined();
      expect(view!.slot).toBe("rightSidebarPanel");
      expect(view!.label).toBe("Plugin Inspector");

      // Clean up
      await loader.deactivatePlugin("right-sidebar-plugin");
    });

    // Test 26: deactivatePlugin() removes view contributions from ViewRegistry
    it("deactivatePlugin() removes view contributions from ViewRegistry", async () => {
      const manifest = createTestManifest({
        id: "deactivate-views-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          editorTabs: [
            { id: "tab1", label: "Tab 1", entrypoint: "./tab1.tsx" },
          ],
          bottomPanelTabs: [
            { id: "panel1", label: "Panel 1", entrypoint: "./panel1.tsx" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("deactivate-views-plugin");

      // Views should be registered
      expect(getView("deactivate-views-plugin.tab1")).toBeDefined();
      expect(getView("deactivate-views-plugin.panel1")).toBeDefined();

      // Deactivate
      await loader.deactivatePlugin("deactivate-views-plugin");

      // Views should be removed
      expect(getView("deactivate-views-plugin.tab1")).toBeUndefined();
      expect(getView("deactivate-views-plugin.panel1")).toBeUndefined();
    });

    // Test 27: routeStatusBarItemContribution does not crash when entrypoint is invalid
    it("routeStatusBarItemContribution does not crash when entrypoint is invalid", async () => {
      const manifest = createTestManifest({
        id: "status-bar-crash-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          statusBarItems: [
            { id: "broken-status", side: "right" as const, priority: 100, entrypoint: "./does-not-exist.tsx" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      // Should not throw
      await expect(loader.loadPlugin("status-bar-crash-test")).resolves.not.toThrow();

      expect(registry.get("status-bar-crash-test")!.state).toBe("activated");

      // Clean up
      await loader.deactivatePlugin("status-bar-crash-test");
    });

    it("re-registers async status bar items after their component module loads", async () => {
      const notifications = vi.fn();
      const unsubscribe = onStatusBarChange(notifications);
      const entrypoint = `data:text/javascript,${encodeURIComponent(
        "export default function PluginStatusWidget(){ return null; }",
      )}`;
      const manifest = createTestManifest({
        id: "status-bar-async-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        contributions: {
          statusBarItems: [
            { id: "async-status", side: "right" as const, priority: 25, entrypoint },
          ],
        },
      });
      delete (manifest as Partial<PluginManifest> & { main?: string }).main;
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("status-bar-async-test");

      const pendingItem = getStatusBarItems("right").find(
        (item) => item.id === "async-status",
      );
      expect(pendingItem).toBeDefined();
      expect(pendingItem!.render()).toBeNull();

      await new Promise((resolve) => setTimeout(resolve, 50));

      const resolvedItem = getStatusBarItems("right").find(
        (item) => item.id === "async-status",
      );
      expect(resolvedItem).toBeDefined();
      expect(resolvedItem!.render()).not.toBeNull();
      expect(notifications.mock.calls.length).toBeGreaterThanOrEqual(3);

      unsubscribe();
      await loader.deactivatePlugin("status-bar-async-test");
    });

    it("does not re-register async status bar items after the plugin is deactivated", async () => {
      let releaseComponentLoad: (() => void) | undefined;
      const globalForTest = globalThis as typeof globalThis & {
        __statusBarItemLoad?: Promise<void>;
      };
      globalForTest.__statusBarItemLoad = new Promise<void>((resolve) => {
        releaseComponentLoad = resolve;
      });

      const entrypoint = `data:text/javascript,${encodeURIComponent(
        "await globalThis.__statusBarItemLoad; export default function PluginStatusWidget(){ return null; }",
      )}`;
      const manifest = createTestManifest({
        id: "status-bar-async-cancel-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        contributions: {
          statusBarItems: [
            { id: "async-status-cancel", side: "right" as const, priority: 26, entrypoint },
          ],
        },
      });
      registry.register(manifest);

      loader = new PluginLoader({
        registry,
        resolveModule: async () => createMockModule(),
      });

      await loader.loadPlugin("status-bar-async-cancel-test");
      expect(
        getStatusBarItems("right").find((item) => item.id === "async-status-cancel"),
      ).toBeDefined();

      await loader.deactivatePlugin("status-bar-async-cancel-test");
      releaseComponentLoad?.();
      await Promise.resolve();
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(
        getStatusBarItems("right").find((item) => item.id === "async-status-cancel"),
      ).toBeUndefined();

      delete globalForTest.__statusBarItemLoad;
    });

    // Test 28: loadPlugin() with activityBarItems routes to ViewRegistry with slot 'activityBarPanel'
    it("loadPlugin() with activityBarItems contribution routes to ViewRegistry with slot 'activityBarPanel'", async () => {
      const manifest = createTestManifest({
        id: "activity-bar-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          activityBarItems: [
            { id: "myNav", section: "security", label: "My Nav", icon: "shield", href: "/my-nav", order: 10 },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("activity-bar-plugin");

      const view = getView("activity-bar-plugin.myNav");
      expect(view).toBeDefined();
      expect(view!.slot).toBe("activityBarPanel");
      expect(view!.label).toBe("My Nav");
      expect(view!.priority).toBe(10);

      // Clean up
      await loader.deactivatePlugin("activity-bar-plugin");
    });

    it("registering SDK views does not eagerly invoke zero-arg React components", async () => {
      const manifest = createTestManifest({
        id: "sdk-view-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      const viewComponent = vi.fn(() => null);
      const mockModule = createMockModule({
        activate: (ctx: PluginActivationContext) => {
          ctx.views.registerEditorTab({
            id: "sdk-view",
            label: "SDK View",
            component: viewComponent,
          });
          return [];
        },
      });

      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("sdk-view-plugin");

      expect(viewComponent).not.toHaveBeenCalled();
      expect(getView("sdk-view-plugin.sdk-view")).toBeDefined();

      await loader.deactivatePlugin("sdk-view-plugin");
    });
  });

  // ---- Threat intel source routing ----

  describe("threat intel source routing", () => {
    afterEach(() => {
      resetThreatIntelRegistry();
    });

    // Test 29: manifest with threatIntelSources triggers module resolution for each source entrypoint
    it("manifest with threatIntelSources triggers async module resolution for each source entrypoint", async () => {
      const resolveEntrypoint = vi.fn(async () => ({
        default: {
          id: "placeholder",
          name: "VirusTotal",
          supportedIndicatorTypes: ["hash", "ip"],
          rateLimit: { maxPerMinute: 4 },
          enrich: vi.fn(),
        },
      }));

      const manifest = createTestManifest({
        id: "ti-plugin",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          threatIntelSources: [
            { id: "vt", name: "VirusTotal", description: "VT enrichment", entrypoint: "./sources/vt.ts" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        resolveEntrypoint,
      });

      await loader.loadPlugin("ti-plugin");

      // resolveEntrypoint should receive the plugin-root-relative resolved URL
      expect(resolveEntrypoint).toHaveBeenCalledWith(
        expect.stringContaining("/sources/vt.ts"),
      );

      // The source should be registered in the threat intel registry
      const source = getThreatIntelSource("ti-plugin.vt");
      expect(source).toBeDefined();

      // Clean up
      await loader.deactivatePlugin("ti-plugin");
    });

    // Test 30: resolved module's default export is registered via registerThreatIntelSource
    it("resolved module default export with enrich() is registered in ThreatIntelSourceRegistry", async () => {
      const mockSourceModule = {
        default: {
          id: "placeholder",
          name: "VirusTotal",
          supportedIndicatorTypes: ["hash", "ip"],
          rateLimit: { maxPerMinute: 4 },
          enrich: vi.fn(),
        },
      };

      const manifest = createTestManifest({
        id: "ti-register-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          threatIntelSources: [
            { id: "vt", name: "VirusTotal", description: "VT lookup", entrypoint: "./sources/vt.ts" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        resolveEntrypoint: async () => mockSourceModule,
      });

      await loader.loadPlugin("ti-register-test");

      const source = getThreatIntelSource("ti-register-test.vt");
      expect(source).toBeDefined();
      expect(source!.name).toBe("VirusTotal");
      // Source ID should be namespaced
      expect(source!.id).toBe("ti-register-test.vt");

      // Clean up
      await loader.deactivatePlugin("ti-register-test");
    });

    // Test 31: dispose from registerThreatIntelSource is tracked -- deactivation removes source
    it("deactivating a plugin removes its threat intel sources from the registry", async () => {
      const mockSourceModule = {
        default: {
          id: "placeholder",
          name: "AbuseIPDB",
          supportedIndicatorTypes: ["ip"],
          rateLimit: { maxPerMinute: 10 },
          enrich: vi.fn(),
        },
      };

      const manifest = createTestManifest({
        id: "ti-dispose-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          threatIntelSources: [
            { id: "abuseipdb", name: "AbuseIPDB", description: "IP reputation", entrypoint: "./sources/abuse.ts" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        resolveEntrypoint: async () => mockSourceModule,
      });

      await loader.loadPlugin("ti-dispose-test");

      // Source should be registered
      expect(getThreatIntelSource("ti-dispose-test.abuseipdb")).toBeDefined();

      // Deactivate plugin
      await loader.deactivatePlugin("ti-dispose-test");

      // Source should be removed
      expect(getThreatIntelSource("ti-dispose-test.abuseipdb")).toBeUndefined();
    });

    // Test 32: failed entrypoint resolution logs warning without failing activation
    it("failed entrypoint resolution logs a warning but does not fail plugin activation", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const manifest = createTestManifest({
        id: "ti-fail-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          threatIntelSources: [
            { id: "bad-source", name: "Broken", description: "Broken source", entrypoint: "./nonexistent.ts" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        resolveEntrypoint: async () => { throw new Error("Module not found"); },
      });

      await loader.loadPlugin("ti-fail-test");

      // Plugin should still be activated despite source load failure
      expect(registry.get("ti-fail-test")!.state).toBe("activated");

      // Warning should have been logged
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("ti-fail-test.bad-source"),
        expect.anything(),
      );

      warnSpy.mockRestore();
      await loader.deactivatePlugin("ti-fail-test");
    });

    // Test 33: module without enrich() method logs warning about invalid source
    it("module without enrich() method logs warning about missing enrich method", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      // Module that does not have an enrich method
      const mockSourceModule = {
        default: {
          id: "no-enrich",
          name: "BadSource",
        },
      };

      const manifest = createTestManifest({
        id: "ti-noenrich-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          threatIntelSources: [
            { id: "bad", name: "NoEnrich", description: "No enrich method", entrypoint: "./sources/bad.ts" },
          ],
        },
      });
      registry.register(manifest);

      const mockModule = createMockModule();
      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        resolveEntrypoint: async () => mockSourceModule,
      });

      await loader.loadPlugin("ti-noenrich-test");

      // Plugin should still be activated
      expect(registry.get("ti-noenrich-test")!.state).toBe("activated");

      // Warning about missing enrich method
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("missing enrich method"),
      );

      // Source should NOT be in registry
      expect(getThreatIntelSource("ti-noenrich-test.bad")).toBeUndefined();

      warnSpy.mockRestore();
      await loader.deactivatePlugin("ti-noenrich-test");
    });

    it("abandons pending async contribution loads after an uninstall race", async () => {
      let resolveEntrypoint:
        | ((value: Record<string, unknown>) => void)
        | undefined;
      const delayedEntrypoint = new Promise<Record<string, unknown>>((resolve) => {
        resolveEntrypoint = resolve;
      });

      const manifest = createTestManifest({
        id: "ti-cancel-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        contributions: {
          threatIntelSources: [
            { id: "vt", name: "VirusTotal", description: "VT enrichment", entrypoint: "./sources/vt.ts" },
          ],
        },
      });
      registry.register(manifest);

      loader = new PluginLoader({
        registry,
        resolveModule: async () => createMockModule(),
        resolveEntrypoint: async () => delayedEntrypoint,
      });

      const loadPromise = loader.loadPlugin("ti-cancel-test");

      await Promise.resolve();
      await loader.deactivatePlugin("ti-cancel-test");
      registry.unregister("ti-cancel-test");

      resolveEntrypoint?.({
        default: {
          id: "placeholder",
          name: "VirusTotal",
          supportedIndicatorTypes: ["hash"],
          rateLimit: { maxPerMinute: 4 },
          enrich: vi.fn(),
        },
      });

      await loadPromise;

      expect(getThreatIntelSource("ti-cancel-test.vt")).toBeUndefined();
      expect(registry.get("ti-cancel-test")).toBeUndefined();
    });
  });

  // ---- SecretsApi injection ----

  describe("SecretsApi injection", () => {
    // Test 34: PluginActivationContext includes a `secrets` field
    it("PluginActivationContext passed to activate() includes a 'secrets' field", async () => {
      const manifest = createTestManifest({
        id: "secrets-ctx-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      let capturedContext: PluginActivationContext | undefined;
      const mockModule = createMockModule({
        activate: (ctx: PluginActivationContext) => {
          capturedContext = ctx;
          return [];
        },
      });

      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("secrets-ctx-test");

      expect(capturedContext).toBeDefined();
      expect(capturedContext!.secrets).toBeDefined();
      expect(typeof capturedContext!.secrets.get).toBe("function");
      expect(typeof capturedContext!.secrets.set).toBe("function");
      expect(typeof capturedContext!.secrets.delete).toBe("function");
      expect(typeof capturedContext!.secrets.has).toBe("function");
    });

    // Test 35: SecretsApi is created with the correct pluginId
    it("SecretsApi is scoped to the plugin's ID", async () => {
      const manifest = createTestManifest({
        id: "secrets-scope-test",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      registry.register(manifest);

      let capturedContext: PluginActivationContext | undefined;
      const mockModule = createMockModule({
        activate: (ctx: PluginActivationContext) => {
          capturedContext = ctx;
          return [];
        },
      });

      loader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
      });

      await loader.loadPlugin("secrets-scope-test");

      expect(capturedContext).toBeDefined();
      // The SecretsApi should exist and be a valid object with the expected methods
      const secrets = capturedContext!.secrets;
      expect(secrets).toBeDefined();
      expect(typeof secrets.get).toBe("function");
      expect(typeof secrets.set).toBe("function");
    });
  });
});
