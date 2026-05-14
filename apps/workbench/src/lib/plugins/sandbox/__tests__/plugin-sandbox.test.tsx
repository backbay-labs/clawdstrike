/**
 * PluginSandbox Component Tests
 *
 * Tests for the React component that manages the sandboxed iframe lifecycle
 * and bridge wiring. Verifies iframe sandbox attributes, srcdoc content,
 * PluginBridgeHost creation, message listener setup, and cleanup on unmount.
 *
 * Uses @testing-library/react for rendering and vi.mock for the bridge-host module.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, cleanup } from "@testing-library/react";
import React from "react";

// ---- Mock bridge-host module ----
// vi.hoisted() ensures these are available when vi.mock factory runs (hoisted)

const { mockDestroy, mockHandleMessage, mockRegisterHandler, mockPushEvent, MockPluginBridgeHost, constructorCalls } = vi.hoisted(() => {
  const mockDestroy = vi.fn();
  const mockHandleMessage = vi.fn();
  const mockRegisterHandler = vi.fn();
  const mockPushEvent = vi.fn();
  const constructorCalls: unknown[][] = [];

  class MockPluginBridgeHost {
    handleMessage = mockHandleMessage;
    registerHandler = mockRegisterHandler;
    pushEvent = mockPushEvent;
    destroy = mockDestroy;

    constructor(...args: unknown[]) {
      constructorCalls.push(args);
    }
  }

  return { mockDestroy, mockHandleMessage, mockRegisterHandler, mockPushEvent, MockPluginBridgeHost, constructorCalls };
});

vi.mock("../../bridge/bridge-host", () => ({
  PluginBridgeHost: MockPluginBridgeHost,
}));

// Import after mock setup
import { PluginSandbox } from "../plugin-sandbox";
import { PLUGIN_CSP } from "../srcdoc-builder";

// ---- Setup ----

describe("PluginSandbox", () => {
  const defaultProps = {
    pluginId: "test-plugin",
    pluginCode: 'console.log("sandbox test");',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    constructorCalls.length = 0;
  });

  afterEach(() => {
    cleanup();
  });

  // ---- Iframe rendering ----

  it("renders an iframe element", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe");
    expect(iframe).toBeTruthy();
  });

  it('the iframe has sandbox="allow-scripts" attribute (no allow-same-origin)', () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
  });

  it("the iframe does NOT have allow-same-origin in its sandbox attribute", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    const sandbox = iframe.getAttribute("sandbox") ?? "";
    expect(sandbox).not.toContain("allow-same-origin");
  });

  it("the iframe does NOT have allow-top-navigation in its sandbox attribute", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    const sandbox = iframe.getAttribute("sandbox") ?? "";
    expect(sandbox).not.toContain("allow-top-navigation");
  });

  it("the iframe does NOT have allow-popups in its sandbox attribute", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    const sandbox = iframe.getAttribute("sandbox") ?? "";
    expect(sandbox).not.toContain("allow-popups");
  });

  it("the iframe has a srcdoc attribute (not src)", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    expect(iframe.hasAttribute("srcdoc")).toBe(true);
    expect(iframe.hasAttribute("src")).toBe(false);
  });

  it("the iframe's srcdoc contains the CSP meta tag", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    const srcdoc = iframe.getAttribute("srcdoc") ?? "";
    expect(srcdoc).toContain("Content-Security-Policy");
    expect(srcdoc).toContain(PLUGIN_CSP);
  });

  it("the iframe's srcdoc contains the provided plugin code", () => {
    const { container } = render(<PluginSandbox {...defaultProps} />);
    const iframe = container.querySelector("iframe")!;
    const srcdoc = iframe.getAttribute("srcdoc") ?? "";
    expect(srcdoc).toContain('console.log("sandbox test");');
  });

  // ---- Bridge wiring ----

  it("calls onReady with a PluginBridgeHost instance after render", () => {
    const onReady = vi.fn();
    render(<PluginSandbox {...defaultProps} onReady={onReady} />);

    // The host should have been created and onReady called
    expect(constructorCalls.length).toBeGreaterThanOrEqual(1);
    expect(onReady).toHaveBeenCalledOnce();
    // The argument should be the mock host instance
    expect(onReady.mock.calls[0][0]).toHaveProperty("handleMessage");
    expect(onReady.mock.calls[0][0]).toHaveProperty("destroy");
  });

  it("attaches a message event listener on the host window for bridge communication", () => {
    const addSpy = vi.spyOn(window, "addEventListener");
    render(<PluginSandbox {...defaultProps} />);

    const messageCalls = addSpy.mock.calls.filter(
      (call) => call[0] === "message",
    );
    expect(messageCalls.length).toBeGreaterThanOrEqual(1);
    addSpy.mockRestore();
  });

  it("cleans up (removes message listener, calls host.destroy()) on unmount", () => {
    const removeSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = render(<PluginSandbox {...defaultProps} />);

    unmount();

    // Should have removed the message listener
    const removeCalls = removeSpy.mock.calls.filter(
      (call) => call[0] === "message",
    );
    expect(removeCalls.length).toBeGreaterThanOrEqual(1);

    // Should have called destroy on the host
    expect(mockDestroy).toHaveBeenCalled();

    removeSpy.mockRestore();
  });

  it("applies className prop to a wrapper div for layout integration", () => {
    const { container } = render(
      <PluginSandbox {...defaultProps} className="my-sandbox-class" />,
    );
    const wrapper = container.firstElementChild;
    expect(wrapper?.className).toContain("my-sandbox-class");
  });
});
