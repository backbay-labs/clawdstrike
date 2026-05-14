/**
 * Plugin Sandbox Component
 *
 * React component that renders a sandboxed iframe for community plugin
 * isolation. The iframe uses:
 * - `sandbox="allow-scripts"` (NO allow-same-origin, NO allow-popups,
 *   NO allow-top-navigation) to enforce null-origin isolation
 * - `srcdoc` (not `src`) to avoid network requests and ensure the iframe
 *   content is fully controlled by the host
 * - A strict CSP meta tag inside the srcdoc for defense-in-depth
 *
 * The component wires up a PluginBridgeHost to the iframe's contentWindow
 * and attaches a window-level message listener for postMessage RPC. On
 * unmount, the listener is removed and the host is destroyed.
 *
 * Security invariants:
 * - The iframe MUST NOT have allow-same-origin (SANDBOX-02, SANDBOX-06)
 * - The iframe MUST NOT have allow-popups or allow-top-navigation
 * - The host-side message listener is cleaned up on unmount to prevent leaks
 */

import React, { useEffect, useRef } from "react";
import { PluginBridgeHost } from "../bridge/bridge-host";
import { buildPluginSrcdoc } from "./srcdoc-builder";

// ---- Types ----

/**
 * Props for the PluginSandbox component.
 */
export interface PluginSandboxProps {
  /** The plugin's unique identifier. */
  pluginId: string;
  /** The plugin's JavaScript source code to execute in the sandbox. */
  pluginCode: string;
  /** Optional design system CSS to inject into the iframe. */
  css?: string;
  /** Optional CSS class name for the wrapper div. */
  className?: string;
  /** Callback fired when the bridge host is wired up and ready. */
  onReady?: (host: PluginBridgeHost) => void;
  /** Callback fired if the iframe setup fails. */
  onError?: (error: Error) => void;
}

// ---- Component ----

/**
 * Renders a sandboxed iframe for a community plugin with bridge wiring.
 *
 * The iframe runs in a null-origin sandbox with only `allow-scripts`.
 * Communication between the plugin and the host workbench is exclusively
 * via the PluginBridgeHost/Client postMessage protocol.
 */
export function PluginSandbox({
  pluginId,
  pluginCode,
  css,
  className,
  onReady,
  onError,
}: PluginSandboxProps): React.ReactElement {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const hostRef = useRef<PluginBridgeHost | null>(null);

  useEffect(() => {
    const iframe = iframeRef.current;
    if (!iframe) {
      onError?.(new Error("iframe ref is null"));
      return;
    }

    const contentWindow = iframe.contentWindow;
    if (!contentWindow) {
      onError?.(new Error("iframe contentWindow is null"));
      return;
    }

    // Create the bridge host connected to the iframe's contentWindow
    const host = new PluginBridgeHost({
      pluginId,
      targetWindow: contentWindow,
    });
    hostRef.current = host;

    // Create a message handler that forwards messages to the host
    const handler = (event: MessageEvent): void => {
      host.handleMessage(event);
    };

    // Listen for messages from the iframe on the host window
    window.addEventListener("message", handler);

    // Signal readiness
    onReady?.(host);

    // Cleanup on unmount or dep change
    return () => {
      window.removeEventListener("message", handler);
      host.destroy();
      hostRef.current = null;
    };
  }, [pluginId, pluginCode]);

  const srcdoc = buildPluginSrcdoc({ pluginCode, pluginId, css });

  return (
    <div className={className}>
      <iframe
        ref={iframeRef}
        sandbox="allow-scripts"
        srcDoc={srcdoc}
        style={{ width: "100%", height: "100%", border: "none" }}
      />
    </div>
  );
}
