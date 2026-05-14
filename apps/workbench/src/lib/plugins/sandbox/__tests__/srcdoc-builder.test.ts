/**
 * srcdoc-builder Tests
 *
 * Tests for the srcdoc HTML builder that produces locked-down HTML documents
 * for plugin sandboxed iframes. Verifies CSP directives, bridge client
 * bootstrap injection, design system CSS, and HTML structure.
 */

import { describe, it, expect } from "vitest";
import { buildPluginSrcdoc, PLUGIN_CSP } from "../srcdoc-builder";

// ---- PLUGIN_CSP constant ----

describe("PLUGIN_CSP", () => {
  it("contains 'default-src 'none'' directive", () => {
    expect(PLUGIN_CSP).toContain("default-src 'none'");
  });

  it("contains 'connect-src 'none'' directive", () => {
    expect(PLUGIN_CSP).toContain("connect-src 'none'");
  });

  it("contains 'script-src 'unsafe-inline'' directive (needed for srcdoc)", () => {
    expect(PLUGIN_CSP).toContain("script-src 'unsafe-inline'");
  });

  it("contains 'worker-src 'none'' directive", () => {
    expect(PLUGIN_CSP).toContain("worker-src 'none'");
  });

  it("contains 'frame-src 'none'' directive", () => {
    expect(PLUGIN_CSP).toContain("frame-src 'none'");
  });

  it("contains 'form-action 'none'' directive", () => {
    expect(PLUGIN_CSP).toContain("form-action 'none'");
  });

  it("does NOT contain 'unsafe-eval' (no eval/Function allowed)", () => {
    expect(PLUGIN_CSP).not.toContain("unsafe-eval");
  });
});

// ---- buildPluginSrcdoc() ----

describe("buildPluginSrcdoc()", () => {
  const defaultOpts = {
    pluginCode: 'console.log("hello");',
    pluginId: "test-plugin",
  };

  it("returns string containing <meta http-equiv=\"Content-Security-Policy\"", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
  });

  it("output contains the PLUGIN_CSP value in the meta tag content attribute", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain(`content="${PLUGIN_CSP}"`);
  });

  it("output contains a <script> tag with the pluginCode", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain('console.log("hello");');
  });

  it("output contains bridge client bootstrap that creates window.__bridge = new PluginBridgeClient()", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain("window.__bridge");
    expect(html).toContain("PluginBridgeClient");
  });

  it("output injects the SDK bridge runtime for community plugin activation", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain("window.__CLAWDSTRIKE_PLUGIN_SDK__");
    expect(html).toContain("createPluginContext");
    expect(html).toContain("plugin.activate(context)");
  });

  it("output wraps plugin code execution after bridge initialization", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    // Bridge init should come before the plugin code
    const bridgeIndex = html.indexOf("window.__bridge");
    const pluginCodeIndex = html.indexOf('console.log("hello");');
    expect(bridgeIndex).toBeLessThan(pluginCodeIndex);
    expect(bridgeIndex).toBeGreaterThan(-1);
    expect(pluginCodeIndex).toBeGreaterThan(-1);
  });

  it("output contains <style> tag with design system CSS when css option provided", () => {
    const css = "body { background: #1a1a1a; color: white; }";
    const html = buildPluginSrcdoc({ ...defaultOpts, css });
    expect(html).toContain("<style>");
    expect(html).toContain(css);
  });

  it("output is valid HTML (starts with <!DOCTYPE html> or <html>)", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    const trimmed = html.trimStart();
    expect(
      trimmed.startsWith("<!DOCTYPE html>") || trimmed.startsWith("<html"),
    ).toBe(true);
  });

  it("empty plugin code still produces valid HTML with bridge bootstrap", () => {
    const html = buildPluginSrcdoc({ pluginCode: "", pluginId: "empty" });
    expect(html).toContain("window.__bridge");
    expect(html).toContain("PluginBridgeClient");
    expect(html).toContain('<meta http-equiv="Content-Security-Policy"');
    expect(html).toContain("plugin-root");
  });

  // Additional structural tests

  it("output contains <div id=\"plugin-root\"></div> as the plugin render target", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain('<div id="plugin-root"></div>');
  });

  it("does not include <style> tag when no css option is provided", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).not.toContain("<style>");
  });

  it("inlined bridge client includes call() method with timeout", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain("30000"); // BRIDGE_TIMEOUT_MS
    expect(html).toContain("call");
  });

  it("inlined bridge client includes subscribe() method", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain("subscribe");
  });

  it("inlined bridge client includes destroy() method", () => {
    const html = buildPluginSrcdoc(defaultOpts);
    expect(html).toContain("destroy");
  });
});
