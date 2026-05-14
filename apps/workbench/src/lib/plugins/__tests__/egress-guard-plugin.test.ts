/**
 * EgressAllowlistGuard Plugin Integration Tests
 *
 * Tests for the egress-guard-plugin: manifest structure, guard contribution
 * metadata parity with the built-in egress_allowlist guard, PluginLoader
 * integration (register and deactivate), and activate context handling.
 */

import { describe, it, expect, afterEach } from "vitest";
import { PluginRegistry } from "../plugin-registry";
import { createTestManifest } from "../manifest-validation";
import { getGuardMeta, unregisterGuard, BUILTIN_GUARDS } from "../../workbench/guard-registry";
import { PluginLoader } from "../plugin-loader";
import type { PluginModule, PluginActivationContext } from "../plugin-loader";
import egressGuardPlugin from "../examples/egress-guard-plugin";

// Reference: the built-in egress_allowlist guard metadata
const BUILTIN_EGRESS = BUILTIN_GUARDS.find((g) => g.id === "egress_allowlist")!;

// ---- Cleanup ----

afterEach(() => {
  unregisterGuard("egress_allowlist_plugin");
});

// ---- Tests ----

describe("EgressAllowlistGuard Plugin", () => {
  // Test 1: Plugin module has correct manifest structure
  it("exports a PluginDefinition with manifest id 'clawdstrike.egress-guard-plugin' and a guards contribution", () => {
    expect(egressGuardPlugin).toBeDefined();
    expect(egressGuardPlugin.manifest).toBeDefined();
    expect(egressGuardPlugin.manifest.id).toBe("clawdstrike.egress-guard-plugin");
    expect(egressGuardPlugin.manifest.contributions).toBeDefined();
    expect(egressGuardPlugin.manifest.contributions!.guards).toBeDefined();
    expect(egressGuardPlugin.manifest.contributions!.guards!.length).toBe(1);
    expect(egressGuardPlugin.activate).toBeTypeOf("function");
  });

  // Test 2: Plugin guard contribution metadata matches built-in egress_allowlist
  it("guard contribution has matching id, name, technicalName, description, category, defaultVerdict, icon", () => {
    const guard = egressGuardPlugin.manifest.contributions!.guards![0];
    expect(guard.id).toBe("egress_allowlist_plugin");
    expect(guard.name).toBe(BUILTIN_EGRESS.name); // "Egress Control"
    expect(guard.technicalName).toBe(BUILTIN_EGRESS.technicalName); // "EgressAllowlistGuard"
    expect(guard.description).toBe(BUILTIN_EGRESS.description);
    expect(guard.category).toBe(BUILTIN_EGRESS.category); // "network"
    expect(guard.defaultVerdict).toBe(BUILTIN_EGRESS.defaultVerdict); // "deny"
    expect(guard.icon).toBe(BUILTIN_EGRESS.icon); // "IconNetwork"
  });

  // Test 3: Plugin guard configFields match built-in egress_allowlist exactly
  it("guard contribution configFields match the built-in egress_allowlist guard exactly", () => {
    const guard = egressGuardPlugin.manifest.contributions!.guards![0];
    expect(guard.configFields.length).toBe(4);

    const builtinFields = BUILTIN_EGRESS.configFields;
    expect(guard.configFields.length).toBe(builtinFields.length);

    for (let i = 0; i < builtinFields.length; i++) {
      const expected = builtinFields[i];
      const actual = guard.configFields[i];
      expect(actual.key).toBe(expected.key);
      expect(actual.label).toBe(expected.label);
      expect(actual.type).toBe(expected.type);
      expect(actual.description).toBe(expected.description);
      expect(actual.defaultValue).toEqual(expected.defaultValue);
      expect(actual.options).toEqual(expected.options);
    }
  });

  // Test 4: PluginLoader integration -- loading registers guard in guard registry
  it("loading via PluginLoader registers the guard in the guard registry", async () => {
    const registry = new PluginRegistry();
    const manifest = createTestManifest({
      ...egressGuardPlugin.manifest,
    });
    registry.register(manifest);

    const pluginModule: PluginModule = {
      activate: egressGuardPlugin.activate as (ctx: PluginActivationContext) => void,
      deactivate: egressGuardPlugin.deactivate,
    };

    const loader = new PluginLoader({
      registry,
      resolveModule: async () => pluginModule,
    });

    await loader.loadPlugin(manifest.id);

    const guardMeta = getGuardMeta("egress_allowlist_plugin");
    expect(guardMeta).toBeDefined();
    expect(guardMeta!.name).toBe("Egress Control");
    expect(guardMeta!.technicalName).toBe("EgressAllowlistGuard");
    expect(guardMeta!.category).toBe("network");
    expect(guardMeta!.defaultVerdict).toBe("deny");
    expect(guardMeta!.icon).toBe("IconNetwork");
    expect(guardMeta!.configFields.length).toBe(4);
  });

  // Test 5: PluginLoader deactivation removes guard from registry
  it("deactivating via PluginLoader removes the guard from the guard registry", async () => {
    const registry = new PluginRegistry();
    const manifest = createTestManifest({
      ...egressGuardPlugin.manifest,
    });
    registry.register(manifest);

    const pluginModule: PluginModule = {
      activate: egressGuardPlugin.activate as (ctx: PluginActivationContext) => void,
      deactivate: egressGuardPlugin.deactivate,
    };

    const loader = new PluginLoader({
      registry,
      resolveModule: async () => pluginModule,
    });

    await loader.loadPlugin(manifest.id);
    expect(getGuardMeta("egress_allowlist_plugin")).toBeDefined();

    await loader.deactivatePlugin(manifest.id);
    expect(getGuardMeta("egress_allowlist_plugin")).toBeUndefined();
  });

  // Test 6: activate() receives PluginActivationContext and can use subscriptions
  it("activate() receives context with pluginId and subscriptions", async () => {
    const registry = new PluginRegistry();
    const manifest = createTestManifest({
      ...egressGuardPlugin.manifest,
    });
    registry.register(manifest);

    let capturedContext: PluginActivationContext | undefined;
    const pluginModule: PluginModule = {
      activate: (ctx: PluginActivationContext) => {
        capturedContext = ctx;
        return egressGuardPlugin.activate(ctx as never);
      },
      deactivate: egressGuardPlugin.deactivate,
    };

    const loader = new PluginLoader({
      registry,
      resolveModule: async () => pluginModule,
    });

    await loader.loadPlugin(manifest.id);

    expect(capturedContext).toBeDefined();
    expect(capturedContext!.pluginId).toBe("clawdstrike.egress-guard-plugin");
    expect(capturedContext!.subscriptions).toBeInstanceOf(Array);
  });
});
