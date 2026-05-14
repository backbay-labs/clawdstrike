/**
 * Plugin Installer Tests
 *
 * Tests for the install/uninstall orchestration layer that composes
 * PluginRegistry and PluginLoader to provide a complete lifecycle.
 *
 * Uses fresh PluginRegistry and PluginLoader instances per test (not singletons).
 * Uses mock module resolvers that return no-op activate functions.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PluginRegistry, PluginRegistrationError } from "../plugin-registry";
import { PluginLoader } from "../plugin-loader";
import type { PluginModule } from "../plugin-loader";
import { createTestManifest } from "../manifest-validation";
import { installPlugin, uninstallPlugin } from "../plugin-installer";
import { unregisterGuard } from "../../workbench/guard-registry";
import type { PluginManifest } from "../types";

// ---- Helpers ----

function createMockModule(overrides?: Partial<PluginModule>): PluginModule {
  return {
    activate: vi.fn(() => []),
    deactivate: vi.fn(),
    ...overrides,
  };
}

async function resolveCommunityPluginCode(): Promise<string> {
  return 'console.debug("community installer test bootstrap");';
}

// ---- Tests ----

describe("Plugin Installer", () => {
  let registry: PluginRegistry;
  let loader: PluginLoader;
  let mockModule: PluginModule;

  beforeEach(() => {
    registry = new PluginRegistry();
    mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
    });
  });

  // Test 1: installPlugin registers the manifest and transitions state to "installed" then "activated"
  it("installPlugin registers the manifest and transitions state to installed then activated", async () => {
    const manifest = createTestManifest({
      id: "installer-test-1",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });

    const stateTransitions: string[] = [];
    registry.subscribe("stateChanged", (event) => {
      if (event.newState) stateTransitions.push(event.newState);
    });

    await installPlugin(manifest, { registry, loader });

    // Plugin should be registered
    const plugin = registry.get("installer-test-1");
    expect(plugin).toBeDefined();
    // State should end at "activated"
    expect(plugin!.state).toBe("activated");
    // State transitions should include activating and activated
    expect(stateTransitions).toContain("activating");
    expect(stateTransitions).toContain("activated");
  });

  // Test 2: installPlugin with trust="community" works when loader has allowUnsigned=true
  it("installPlugin with trust=community works when loader has allowUnsigned=true", async () => {
    const manifest = createTestManifest({
      id: "community-install-test",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });

    // Create loader with allowUnsigned=true
    const permissiveLoader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
      trustOptions: { allowUnsigned: true },
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await installPlugin(manifest, { registry, loader: permissiveLoader });

    const plugin = registry.get("community-install-test");
    expect(plugin).toBeDefined();
    expect(plugin!.state).toBe("activated");
  });

  // Test 3: uninstallPlugin calls deactivatePlugin on the loader and then unregister on the registry
  it("uninstallPlugin deactivates the plugin and removes it from the registry", async () => {
    const manifest = createTestManifest({
      id: "uninstall-test",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });

    // First install
    await installPlugin(manifest, { registry, loader });
    expect(registry.get("uninstall-test")).toBeDefined();
    expect(registry.get("uninstall-test")!.state).toBe("activated");

    // Now uninstall
    await uninstallPlugin("uninstall-test", { registry, loader });

    // Plugin should be removed from the registry entirely
    expect(registry.get("uninstall-test")).toBeUndefined();
  });

  // Test 4: installPlugin with a manifest whose id is already registered throws PluginRegistrationError
  it("installPlugin with already-registered id throws PluginRegistrationError", async () => {
    const manifest = createTestManifest({
      id: "duplicate-test",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./index.ts",
    });

    // Install once
    await installPlugin(manifest, { registry, loader });

    // Install again should throw
    await expect(
      installPlugin(manifest, { registry, loader }),
    ).rejects.toThrow(PluginRegistrationError);
  });

  // Test 5: uninstallPlugin with an unknown plugin id is a no-op (does not throw)
  it("uninstallPlugin with unknown id is a no-op", async () => {
    // Should not throw
    await expect(
      uninstallPlugin("nonexistent-plugin", { registry, loader }),
    ).resolves.toBeUndefined();
  });

  // ---- Permission prompt ----

  describe("permission prompt", () => {
    // Test 6: installPlugin for community plugin with permissions calls onPermissionPrompt
    it("installPlugin for community plugin with permissions calls onPermissionPrompt", async () => {
      const manifest = createTestManifest({
        id: "prompt-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: ["guards:register", "storage:read"],
      });

      const permissiveLoader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        trustOptions: { allowUnsigned: true },
        resolvePluginCode: resolveCommunityPluginCode,
      });

      const promptCallback = vi.fn().mockResolvedValue(true);

      await installPlugin(manifest, {
        registry,
        loader: permissiveLoader,
        onPermissionPrompt: promptCallback,
      });

      expect(promptCallback).toHaveBeenCalledOnce();
      expect(promptCallback).toHaveBeenCalledWith(
        manifest,
        manifest.permissions,
      );
      expect(registry.get("prompt-test")!.state).toBe("activated");
    });

    // Test 7: installPlugin proceeds when permission prompt returns true
    it("installPlugin proceeds when permission prompt approves", async () => {
      const manifest = createTestManifest({
        id: "prompt-approve-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: ["guards:register"],
      });

      const permissiveLoader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        trustOptions: { allowUnsigned: true },
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await installPlugin(manifest, {
        registry,
        loader: permissiveLoader,
        onPermissionPrompt: async () => true,
      });

      expect(registry.get("prompt-approve-test")!.state).toBe("activated");
    });

    // Test 8: installPlugin aborts when permission prompt returns false
    it("installPlugin aborts when permission prompt rejects", async () => {
      const manifest = createTestManifest({
        id: "prompt-reject-test",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: ["guards:register"],
      });

      const permissiveLoader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        trustOptions: { allowUnsigned: true },
        resolvePluginCode: resolveCommunityPluginCode,
      });

      await expect(
        installPlugin(manifest, {
          registry,
          loader: permissiveLoader,
          onPermissionPrompt: async () => false,
        }),
      ).rejects.toThrow(/permissions not approved/i);

      // Plugin should not be in registry (or should be cleaned up)
      // The registration happened before the prompt, so it may still be registered
      // but the loader should not have been called
    });

    // Test 9: installPlugin for internal plugin does not call permission prompt
    it("installPlugin for internal plugin does not call permission prompt", async () => {
      const manifest = createTestManifest({
        id: "internal-no-prompt",
        trust: "internal",
        activationEvents: ["onStartup"],
        main: "./index.ts",
        permissions: ["guards:register"],
      });

      const promptCallback = vi.fn().mockResolvedValue(true);

      await installPlugin(manifest, {
        registry,
        loader,
        onPermissionPrompt: promptCallback,
      });

      expect(promptCallback).not.toHaveBeenCalled();
      expect(registry.get("internal-no-prompt")!.state).toBe("activated");
    });

    // Test 10: installPlugin for community plugin with no permissions succeeds without prompt
    it("installPlugin for community plugin with no permissions succeeds without prompt", async () => {
      const manifest = createTestManifest({
        id: "community-no-perms",
        trust: "community",
        activationEvents: ["onStartup"],
        main: "./index.ts",
      });
      // Ensure no permissions key
      delete (manifest as Partial<PluginManifest>).permissions;

      const permissiveLoader = new PluginLoader({
        registry,
        resolveModule: async () => mockModule,
        trustOptions: { allowUnsigned: true },
        resolvePluginCode: resolveCommunityPluginCode,
      });

      const promptCallback = vi.fn().mockResolvedValue(true);

      await installPlugin(manifest, {
        registry,
        loader: permissiveLoader,
        onPermissionPrompt: promptCallback,
      });

      expect(promptCallback).not.toHaveBeenCalled();
      expect(registry.get("community-no-perms")!.state).toBe("activated");
    });
  });
});
