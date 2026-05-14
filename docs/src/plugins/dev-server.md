# Dev Server

> **Note:** The dev server requires Phase 3 implementation. Details on this page may change as the `vite-plugin-clawdstrike` package is built out.

The ClawdStrike dev server provides a hot-reload development experience for plugin authors. Changes to plugin source files are detected and reloaded in the running workbench without a full page refresh.

## Installation

The dev server is provided as a Vite plugin:

```typescript,ignore
npm install --save-dev vite-plugin-clawdstrike
```

## Configuration

Add the plugin to your workbench's `vite.config.ts`:

```typescript,ignore
import { defineConfig } from "vite";
import clawdstrike from "vite-plugin-clawdstrike";

export default defineConfig({
  plugins: [
    clawdstrike({
      // Path(s) to plugin directories to watch
      plugins: [
        "../my-guard-plugin",
        "../my-intel-plugin",
      ],
    }),
  ],
});
```

## HMR behavior

When you save a file in a watched plugin directory:

1. The Vite plugin detects the change and identifies which plugin is affected
2. A custom HMR WebSocket event (`clawdstrike:plugin-update`) is sent to the workbench frontend
3. The client-side handler deactivates the old plugin version, unregisters its contributions, and re-imports the updated module
4. The plugin is re-activated and its contributions re-registered

Key properties:

- **Storage state preserved**: Data set via `ctx.storage.set()` before the reload is restored after reactivation
- **Targeted reload**: Only the affected plugin reloads. Other loaded plugins remain untouched
- **Fast iteration**: The reload cycle targets sub-200ms for small plugins

## Dev console

The dev server adds a bottom panel tab showing plugin lifecycle events:

- **Lifecycle events**: Timestamped entries for activation, deactivation, and errors
- **Console output**: Captured `console.log/warn/error` from the dev plugin
- **Contribution changes**: Registration and unregistration of guards, commands, and other contributions
- **Timing**: How long each activation/deactivation cycle took
