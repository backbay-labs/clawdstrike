/**
 * Sandbox Integration Tests
 *
 * Higher-level integration tests proving the full community plugin lifecycle
 * through PluginLoader -> sandboxed iframe -> PluginBridgeHost. Verifies that
 * the trust-tier fork correctly routes community plugins into iframes with
 * proper sandbox attributes and CSP, while internal plugins load in-process.
 *
 * These tests exercise the real PluginLoader, PluginRegistry, and bridge
 * infrastructure together (no mocking of the loader internals), with only
 * the trust verification and registry dispatch mocked for isolation.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PluginRegistry } from "../../plugin-registry";
import { createTestManifest } from "../../manifest-validation";
import { PluginLoader } from "../../plugin-loader";
import type { PluginModule } from "../../plugin-loader";
import { PLUGIN_CSP } from "../srcdoc-builder";

// ---- Helpers ----

function createMockModule(): PluginModule {
  return {
    activate: vi.fn(() => []),
    deactivate: vi.fn(),
  };
}

async function resolveCommunityPluginCode(): Promise<string> {
  return 'console.debug("community plugin test bootstrap");';
}

// ---- Integration test suite ----

describe("Sandbox Integration (PluginLoader + iframe + bridge)", () => {
  let registry: PluginRegistry;
  let loader: PluginLoader;
  let iframeContainer: HTMLDivElement;

  beforeEach(() => {
    registry = new PluginRegistry();
    iframeContainer = document.createElement("div");
    iframeContainer.id = "sandbox-integration-container";
    document.body.appendChild(iframeContainer);
  });

  afterEach(() => {
    iframeContainer.remove();
  });

  // Test 1: Community plugin manifest creates an iframe in the DOM
  it("community plugin loaded via PluginLoader creates an iframe in the DOM", async () => {
    const manifest = createTestManifest({
      id: "community-iframe-test",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./community-plugin.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("community-iframe-test");

    const iframes = iframeContainer.querySelectorAll("iframe");
    expect(iframes.length).toBe(1);

    // Clean up
    await loader.deactivatePlugin("community-iframe-test");
  });

  // Test 2: The created iframe has sandbox="allow-scripts" and srcdoc (not src)
  it("the created iframe has sandbox='allow-scripts' and srcdoc attribute (not src)", async () => {
    const manifest = createTestManifest({
      id: "community-sandbox-attr",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./plugin.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("community-sandbox-attr");

    const iframe = iframeContainer.querySelector("iframe")!;
    expect(iframe).toBeTruthy();
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.hasAttribute("srcdoc")).toBe(true);
    // Must NOT have allow-same-origin
    expect(iframe.getAttribute("sandbox")).not.toContain("allow-same-origin");
    // Must NOT use src attribute
    expect(iframe.hasAttribute("src")).toBe(false);

    // Clean up
    await loader.deactivatePlugin("community-sandbox-attr");
  });

  // Test 3: The iframe's srcdoc contains the CSP meta tag with "connect-src 'none'"
  it("the iframe's srcdoc contains the CSP meta tag with connect-src 'none'", async () => {
    const manifest = createTestManifest({
      id: "community-csp-check",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./plugin.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("community-csp-check");

    const iframe = iframeContainer.querySelector("iframe")!;
    const srcdoc = iframe.getAttribute("srcdoc") ?? "";
    expect(srcdoc).toContain("Content-Security-Policy");
    expect(srcdoc).toContain(PLUGIN_CSP);
    expect(srcdoc).toContain("connect-src 'none'");

    // Clean up
    await loader.deactivatePlugin("community-csp-check");
  });

  // Test 4: After loading, the plugin reaches "activated" state in the registry
  it("after loading, the community plugin reaches 'activated' state in the registry", async () => {
    const manifest = createTestManifest({
      id: "community-activated-check",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./plugin.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("community-activated-check");

    expect(registry.get("community-activated-check")!.state).toBe("activated");

    // Clean up
    await loader.deactivatePlugin("community-activated-check");
  });

  // Test 5: After deactivatePlugin(), the iframe is removed from the DOM
  it("after deactivatePlugin(), the iframe is removed from the DOM", async () => {
    const manifest = createTestManifest({
      id: "community-deactivate-iframe",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./plugin.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("community-deactivate-iframe");

    // Iframe should exist
    expect(iframeContainer.querySelectorAll("iframe").length).toBe(1);

    await loader.deactivatePlugin("community-deactivate-iframe");

    // Iframe should be removed
    expect(iframeContainer.querySelectorAll("iframe").length).toBe(0);
  });

  // Test 6: After deactivatePlugin(), the plugin state is "deactivated"
  it("after deactivatePlugin(), the plugin state is 'deactivated' in the registry", async () => {
    const manifest = createTestManifest({
      id: "community-deactivated-state",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./plugin.ts",
    });
    registry.register(manifest);

    loader = new PluginLoader({
      registry,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("community-deactivated-state");
    expect(registry.get("community-deactivated-state")!.state).toBe("activated");

    await loader.deactivatePlugin("community-deactivated-state");
    expect(registry.get("community-deactivated-state")!.state).toBe("deactivated");
  });

  // Test 7: An internal plugin does NOT create an iframe
  it("an internal plugin with trust='internal' loaded via same PluginLoader does NOT create an iframe", async () => {
    const manifest = createTestManifest({
      id: "internal-no-iframe",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./internal-plugin.ts",
    });
    registry.register(manifest);

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("internal-no-iframe");

    // No iframe should be created for internal plugins
    const iframes = iframeContainer.querySelectorAll("iframe");
    expect(iframes.length).toBe(0);
    expect(registry.get("internal-no-iframe")!.state).toBe("activated");
  });

  // Test 8: Both internal and community plugins can coexist in the same PluginLoader
  it("both internal and community plugins can coexist in the same PluginLoader instance", async () => {
    const internalManifest = createTestManifest({
      id: "coexist-internal",
      trust: "internal",
      activationEvents: ["onStartup"],
      main: "./internal.ts",
    });
    const communityManifest = createTestManifest({
      id: "coexist-community",
      trust: "community",
      activationEvents: ["onStartup"],
      main: "./community.ts",
    });

    registry.register(internalManifest);
    registry.register(communityManifest);

    const mockModule = createMockModule();
    loader = new PluginLoader({
      registry,
      resolveModule: async () => mockModule,
      trustOptions: { allowUnsigned: true },
      iframeContainer,
      resolvePluginCode: resolveCommunityPluginCode,
    });

    await loader.loadPlugin("coexist-internal");
    await loader.loadPlugin("coexist-community");

    // Both should be activated
    expect(registry.get("coexist-internal")!.state).toBe("activated");
    expect(registry.get("coexist-community")!.state).toBe("activated");

    // Only one iframe (community's)
    const iframes = iframeContainer.querySelectorAll("iframe");
    expect(iframes.length).toBe(1);

    // Internal plugin used resolveModule
    expect(mockModule.activate).toHaveBeenCalledOnce();

    // Clean up
    await loader.deactivatePlugin("coexist-internal");
    await loader.deactivatePlugin("coexist-community");
  });
});
