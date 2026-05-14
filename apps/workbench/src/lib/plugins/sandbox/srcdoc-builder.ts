/**
 * Srcdoc Builder
 *
 * Produces a complete HTML document string for use as an iframe's `srcdoc`
 * attribute. The HTML includes:
 * - A strict Content-Security-Policy meta tag blocking network, workers,
 *   frames, forms, eval, and all other resource types
 * - An inlined PluginBridgeClient (self-contained -- no imports possible
 *   inside a srcdoc iframe)
 * - The plugin's code wrapped in an IIFE executed after bridge initialization
 * - Optional design system CSS
 * - A `<div id="plugin-root">` render target
 *
 * Security: The CSP is the second layer of defense (after the iframe sandbox
 * attribute). It ensures that even if allow-same-origin were accidentally
 * added, the CSP would still block network access and eval.
 */

// ---- CSP ----

/**
 * Content-Security-Policy for plugin iframes.
 *
 * Blocks all network (connect-src), workers, frames, forms, objects, and eval.
 * Allows only inline scripts (required for srcdoc execution), inline styles,
 * and data:/blob: images.
 */
export const PLUGIN_CSP =
  "default-src 'none'; script-src 'unsafe-inline' blob:; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src 'none'; child-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";

// ---- Types ----

/**
 * Options for building an iframe srcdoc HTML document.
 */
export interface SrcdocOptions {
  /** The plugin's JavaScript code to execute inside the iframe. */
  pluginCode: string;
  /** The plugin's unique identifier. */
  pluginId: string;
  /** Optional design system CSS to inject into the iframe. */
  css?: string;
}

// ---- Inlined Bridge Client ----

/**
 * Self-contained PluginBridgeClient source code, inlined as a string.
 *
 * This is a stripped-down copy of the bridge-client.ts logic, written as
 * a single script that can execute inside a srcdoc iframe with no module
 * system. It provides call(), subscribe(), and destroy() with the same
 * timeout (30000ms) and message format as the host-side bridge.
 *
 * IMPORTANT: This must stay functionally equivalent to bridge-client.ts.
 * Any protocol changes to bridge-client.ts must be mirrored here.
 */
const INLINED_BRIDGE_CLIENT = `
class PluginBridgeClient {
  constructor(target) {
    this._target = target || window.parent;
    this._pending = new Map();
    this._subscriptions = new Map();
    this._nextId = 0;
    this._listener = this._handleMessage.bind(this);
    window.addEventListener("message", this._listener);
  }

  call(method, params) {
    var id = String(this._nextId++);
    var self = this;
    return new Promise(function(resolve, reject) {
      var timer = setTimeout(function() {
        self._pending.delete(id);
        reject(new Error("Bridge call \\"" + method + "\\" timed out after 30000ms"));
      }, 30000);

      self._pending.set(id, { resolve: resolve, reject: reject, timer: timer });

      var msg = { id: id, type: "request", method: method, params: params };
      self._target.postMessage(msg, "*");
    });
  }

  subscribe(event, handler) {
    var handlers = this._subscriptions.get(event);
    if (!handlers) {
      handlers = new Set();
      this._subscriptions.set(event, handlers);
    }
    handlers.add(handler);

    return function() {
      var h = this._subscriptions.get(event);
      if (h) h.delete(handler);
    }.bind(this);
  }

  destroy() {
    if (this._listener) {
      window.removeEventListener("message", this._listener);
      this._listener = null;
    }
    var self = this;
    this._pending.forEach(function(entry) {
      clearTimeout(entry.timer);
      entry.reject(new Error("Bridge destroyed"));
    });
    this._pending.clear();
    this._subscriptions.clear();
  }

  _handleMessage(event) {
    var data = event.data;
    if (!data || typeof data !== "object" || typeof data.type !== "string") return;

    if (data.type === "response" && this._pending.has(data.id)) {
      var entry = this._pending.get(data.id);
      clearTimeout(entry.timer);
      this._pending.delete(data.id);
      entry.resolve(data.result);
    }

    if (data.type === "error" && this._pending.has(data.id)) {
      var errEntry = this._pending.get(data.id);
      clearTimeout(errEntry.timer);
      this._pending.delete(data.id);
      errEntry.reject(new Error(data.error ? data.error.message : "Unknown bridge error"));
    }

    if (data.type === "event") {
      var handlers = this._subscriptions.get(data.method);
      if (handlers) {
        handlers.forEach(function(handler) {
          handler(data.params);
        });
      }
    }
  }
}
`;

const INLINED_PLUGIN_RUNTIME = `
function createUnsupportedSyncMethod(name) {
  return function() {
    throw new Error(name + " is not supported for sandboxed community plugins");
  };
}

function createUnsupportedAsyncMethod(name) {
  return function() {
    return Promise.reject(new Error(name + " is not supported for sandboxed community plugins"));
  };
}

function createPluginContext(plugin, fallbackPluginId) {
  var bridge = window.__bridge;
  var commandHandlers = new Map();
  var storage = new Map();

  bridge.subscribe("command.execute", function(params) {
    var commandId = params && params.id;
    var handler = commandHandlers.get(commandId);
    if (typeof handler === "function") {
      try {
        handler();
      } catch (error) {
        console.error("[plugin-sandbox] command handler failed", error);
      }
    }
  });

  function sendBridgeCall(method, params) {
    try {
      var result = bridge.call(method, params);
      if (result && typeof result.catch === "function") {
        result.catch(function(error) {
          console.error("[plugin-sandbox] bridge call failed for " + method, error);
        });
      }
    } catch (error) {
      console.error("[plugin-sandbox] bridge call failed for " + method, error);
    }
  }

  function noopDisposable() {
    return function() {};
  }

  return {
    pluginId: plugin && plugin.manifest && plugin.manifest.id ? plugin.manifest.id : fallbackPluginId,
    subscriptions: [],
    commands: {
      register: function(command, handler) {
        if (command && command.id) {
          commandHandlers.set(command.id, handler);
          sendBridgeCall("commands.register", command);
        }
        return function() {
          if (command && command.id) {
            commandHandlers.delete(command.id);
          }
        };
      }
    },
    guards: { register: noopDisposable },
    fileTypes: { register: noopDisposable },
    statusBar: { register: noopDisposable },
    sidebar: { register: noopDisposable },
    storage: {
      get: function(key) {
        return storage.get(key);
      },
      set: function(key, value) {
        storage.set(key, value);
        sendBridgeCall("storage.set", { key: key, value: value });
      }
    },
    secrets: {
      get: createUnsupportedAsyncMethod("secrets.get"),
      set: createUnsupportedAsyncMethod("secrets.set"),
      delete: createUnsupportedAsyncMethod("secrets.delete"),
      has: createUnsupportedAsyncMethod("secrets.has")
    },
    enrichmentRenderers: {
      register: createUnsupportedSyncMethod("enrichmentRenderers.register")
    },
    views: {
      registerEditorTab: createUnsupportedSyncMethod("views.registerEditorTab"),
      registerBottomPanelTab: createUnsupportedSyncMethod("views.registerBottomPanelTab"),
      registerRightSidebarPanel: createUnsupportedSyncMethod("views.registerRightSidebarPanel"),
      registerStatusBarWidget: createUnsupportedSyncMethod("views.registerStatusBarWidget")
    }
  };
}
`;

// ---- Builder ----

/**
 * Build a complete HTML document for use as an iframe srcdoc.
 *
 * The document contains a strict CSP meta tag, optional design system CSS,
 * a plugin render target div, an inlined PluginBridgeClient, and the plugin's
 * code wrapped in an IIFE.
 *
 * @param options - The srcdoc build options
 * @returns A complete HTML document string
 */
export function buildPluginSrcdoc(options: SrcdocOptions): string {
  const { pluginCode, pluginId, css } = options;

  const styleBlock = css ? `<style>${css}</style>` : "";

  return `<!DOCTYPE html>
<html lang="en" data-plugin-id="${pluginId}">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${PLUGIN_CSP}">
${styleBlock}
</head>
<body>
<div id="plugin-root"></div>
<script>
// ---- Inlined PluginBridgeClient ----
${INLINED_BRIDGE_CLIENT}
// ---- Bridge Initialization ----
window.__bridge = new PluginBridgeClient();
window.__CLAWDSTRIKE_PLUGIN__ = undefined;
window.__CLAWDSTRIKE_PLUGIN_SDK__ = {
  createPlugin: function(definition) {
    return definition;
  },
};
${INLINED_PLUGIN_RUNTIME}

// ---- Plugin Code ----
try {
  (function() { ${pluginCode} })();
  var plugin = window.__CLAWDSTRIKE_PLUGIN__;
  if (plugin && typeof plugin.activate === "function") {
    var context = createPluginContext(plugin, ${JSON.stringify(pluginId)});
    var activateResult = plugin.activate(context);
    if (Array.isArray(activateResult)) {
      Array.prototype.push.apply(context.subscriptions, activateResult);
    }
  }
} catch (error) {
  console.error("[plugin-sandbox] plugin bootstrap failed", error);
}
</script>
</body>
</html>`;
}
