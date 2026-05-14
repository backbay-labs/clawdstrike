/**
 * PluginRegistry Tests
 *
 * Tests for the PluginRegistry singleton: CRUD operations, lifecycle state
 * machine, event emission, contribution-type filtering, and validation
 * rejection.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { PluginRegistry, PluginRegistrationError } from "../plugin-registry";
import type { PluginRegistryEvent } from "../plugin-registry";
import { createTestManifest } from "../manifest-validation";
import type { PluginManifest } from "../types";

// ---- Test fixtures ----

function guardManifest(id = "guard-plugin"): PluginManifest {
  return createTestManifest({
    id,
    contributions: {
      guards: [
        {
          id: "test-guard",
          name: "Test Guard",
          technicalName: "TestGuard",
          description: "A test guard",
          category: "custom",
          defaultVerdict: "deny",
          icon: "IconShield",
          configFields: [],
        },
      ],
    },
  });
}

function commandManifest(id = "cmd-plugin"): PluginManifest {
  return createTestManifest({
    id,
    contributions: {
      commands: [{ id: "test:cmd", title: "Test Command" }],
    },
  });
}

function bothManifest(id = "both-plugin"): PluginManifest {
  return createTestManifest({
    id,
    contributions: {
      guards: [
        {
          id: "both-guard",
          name: "Both Guard",
          technicalName: "BothGuard",
          description: "Guard in both plugin",
          category: "custom",
          defaultVerdict: "deny",
          icon: "IconShield",
          configFields: [],
        },
      ],
      commands: [{ id: "both:cmd", title: "Both Command" }],
    },
  });
}

describe("PluginRegistry", () => {
  let registry: PluginRegistry;

  beforeEach(() => {
    registry = new PluginRegistry();
  });

  // Test 1
  it("register() with a valid manifest stores the plugin with state 'installed'", () => {
    const manifest = createTestManifest({ id: "my-plugin" });
    registry.register(manifest);

    const plugin = registry.get("my-plugin");
    expect(plugin).toBeDefined();
    expect(plugin!.manifest).toBe(manifest);
    expect(plugin!.state).toBe("installed");
    expect(plugin!.installedAt).toBeTypeOf("number");
  });

  // Test 2
  it("register() with a malformed manifest throws PluginRegistrationError with validation details", () => {
    const malformed = { name: "No ID" } as unknown as PluginManifest;
    expect(() => registry.register(malformed)).toThrow(PluginRegistrationError);

    try {
      registry.register(malformed);
    } catch (err) {
      expect(err).toBeInstanceOf(PluginRegistrationError);
      const regErr = err as PluginRegistrationError;
      expect(regErr.validationErrors).toBeDefined();
      expect(regErr.validationErrors!.length).toBeGreaterThan(0);
      // Should mention "id" since it's missing
      expect(regErr.validationErrors!.some((e) => e.field === "id")).toBe(true);
    }
  });

  // Test 3
  it("register() with a duplicate id throws PluginRegistrationError mentioning the id", () => {
    const manifest = createTestManifest({ id: "dup-plugin" });
    registry.register(manifest);

    expect(() => registry.register(manifest)).toThrow(PluginRegistrationError);
    expect(() => registry.register(manifest)).toThrow("dup-plugin");
  });

  // Test 4
  it("get() returns the RegisteredPlugin for a registered id, returns undefined for unknown id", () => {
    const manifest = createTestManifest({ id: "known-plugin" });
    registry.register(manifest);

    expect(registry.get("known-plugin")).toBeDefined();
    expect(registry.get("unknown-plugin")).toBeUndefined();
  });

  // Test 5
  it("getAll() returns all registered plugins as an array", () => {
    registry.register(createTestManifest({ id: "plugin-a" }));
    registry.register(createTestManifest({ id: "plugin-b" }));
    registry.register(createTestManifest({ id: "plugin-c" }));

    const all = registry.getAll();
    expect(all).toHaveLength(3);
    expect(all.map((p) => p.manifest.id).sort()).toEqual([
      "plugin-a",
      "plugin-b",
      "plugin-c",
    ]);
  });

  // Test 6
  it("unregister() removes a plugin; subsequent get() returns undefined", () => {
    registry.register(createTestManifest({ id: "remove-me" }));
    expect(registry.get("remove-me")).toBeDefined();

    registry.unregister("remove-me");
    expect(registry.get("remove-me")).toBeUndefined();
  });

  // Test 7
  it("unregister() with unknown id is a no-op (no throw)", () => {
    expect(() => registry.unregister("nonexistent")).not.toThrow();
  });

  // Test 8
  it('getByContributionType("guards") returns only plugins with guards contributions', () => {
    registry.register(guardManifest());
    registry.register(commandManifest());
    registry.register(bothManifest());

    const guardPlugins = registry.getByContributionType("guards");
    expect(guardPlugins).toHaveLength(2);
    const ids = guardPlugins.map((p) => p.manifest.id).sort();
    expect(ids).toEqual(["both-plugin", "guard-plugin"]);
  });

  // Test 9
  it('getByContributionType("commands") returns only plugins with commands contributions', () => {
    registry.register(guardManifest());
    registry.register(commandManifest());
    registry.register(bothManifest());

    const cmdPlugins = registry.getByContributionType("commands");
    expect(cmdPlugins).toHaveLength(2);
    const ids = cmdPlugins.map((p) => p.manifest.id).sort();
    expect(ids).toEqual(["both-plugin", "cmd-plugin"]);
  });

  // Test 10
  it('getByContributionType("guards") returns empty array when no plugins have guards', () => {
    registry.register(commandManifest());

    const guardPlugins = registry.getByContributionType("guards");
    expect(guardPlugins).toHaveLength(0);
  });

  // Test 11
  it("setState() transitions a plugin to a new lifecycle state", () => {
    registry.register(createTestManifest({ id: "state-test" }));
    expect(registry.get("state-test")!.state).toBe("installed");

    registry.setState("state-test", "activating");
    expect(registry.get("state-test")!.state).toBe("activating");
  });

  // Test 12
  it('setState() to "activated" sets activatedAt timestamp', () => {
    registry.register(createTestManifest({ id: "activate-test" }));
    expect(registry.get("activate-test")!.activatedAt).toBeUndefined();

    registry.setState("activate-test", "activated");
    const plugin = registry.get("activate-test")!;
    expect(plugin.state).toBe("activated");
    expect(plugin.activatedAt).toBeTypeOf("number");
    expect(plugin.activatedAt).toBeGreaterThan(0);
  });

  // Test 13
  it('setState() to "error" with error message stores the error string', () => {
    registry.register(createTestManifest({ id: "error-test" }));

    registry.setState("error-test", "error", "Something went wrong");
    const plugin = registry.get("error-test")!;
    expect(plugin.state).toBe("error");
    expect(plugin.error).toBe("Something went wrong");
  });

  // Test 14
  it('subscribe("registered") fires callback when a plugin is registered', () => {
    const callback = vi.fn();
    registry.subscribe("registered", callback);

    const manifest = createTestManifest({ id: "sub-reg" });
    registry.register(manifest);

    expect(callback).toHaveBeenCalledOnce();
    const event: PluginRegistryEvent = callback.mock.calls[0][0];
    expect(event.type).toBe("registered");
    expect(event.pluginId).toBe("sub-reg");
    expect(event.plugin).toBeDefined();
    expect(event.plugin!.manifest).toBe(manifest);
  });

  // Test 15
  it('subscribe("unregistered") fires callback when a plugin is unregistered', () => {
    registry.register(createTestManifest({ id: "sub-unreg" }));

    const callback = vi.fn();
    registry.subscribe("unregistered", callback);

    registry.unregister("sub-unreg");

    expect(callback).toHaveBeenCalledOnce();
    const event: PluginRegistryEvent = callback.mock.calls[0][0];
    expect(event.type).toBe("unregistered");
    expect(event.pluginId).toBe("sub-unreg");
  });

  // Test 16
  it('subscribe("stateChanged") fires callback with pluginId, oldState, newState when setState is called', () => {
    registry.register(createTestManifest({ id: "sub-state" }));

    const callback = vi.fn();
    registry.subscribe("stateChanged", callback);

    registry.setState("sub-state", "activating");

    expect(callback).toHaveBeenCalledOnce();
    const event: PluginRegistryEvent = callback.mock.calls[0][0];
    expect(event.type).toBe("stateChanged");
    expect(event.pluginId).toBe("sub-state");
    expect(event.oldState).toBe("installed");
    expect(event.newState).toBe("activating");
  });

  // Test 17
  it("subscribe returns a dispose function; after dispose, callback is not called", () => {
    const callback = vi.fn();
    const dispose = registry.subscribe("registered", callback);

    registry.register(createTestManifest({ id: "before-dispose" }));
    expect(callback).toHaveBeenCalledOnce();

    dispose();

    registry.register(createTestManifest({ id: "after-dispose" }));
    expect(callback).toHaveBeenCalledOnce(); // Still 1, not 2
  });

  // Test 18
  it('reset() clears all plugins and fires "unregistered" for each', () => {
    registry.register(createTestManifest({ id: "reset-a" }));
    registry.register(createTestManifest({ id: "reset-b" }));

    const callback = vi.fn();
    registry.subscribe("unregistered", callback);

    registry.reset();

    expect(registry.getAll()).toHaveLength(0);
    expect(callback).toHaveBeenCalledTimes(2);
    const ids = callback.mock.calls.map((call) => {
      const [event] = call as [PluginRegistryEvent];
      return event.pluginId;
    });
    expect(ids.sort()).toEqual(["reset-a", "reset-b"]);
  });
});
