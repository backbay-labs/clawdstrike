# Getting Started

This guide walks you through creating, building, testing, and loading your first ClawdStrike plugin.

## Prerequisites

- Node.js 20+ (or Bun 1.x)
- npm (or bun)

## Step 1: Scaffold the project

Use the `create-plugin` scaffolding tool to generate a new plugin project:

```typescript,ignore
npm create @clawdstrike/plugin my-first-plugin --type guard
```

This creates a `my-first-plugin/` directory with a complete project structure.

## Step 2: Project structure

The generated project includes:

```
my-first-plugin/
  package.json          # Dependencies and scripts
  tsconfig.json         # TypeScript strict mode, ESM output
  tsup.config.ts        # Bundle config (ESM + CJS + DTS)
  vitest.config.ts      # Test runner config
  src/
    index.ts            # Plugin entry point with createPlugin()
  tests/
    plugin.test.ts      # Test file using createSpyContext
```

## Step 3: Understand the entry point

Open `src/index.ts`. The generated code uses `createPlugin()` from the SDK to define the plugin with a typed manifest and lifecycle hooks:

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";
import type { PluginContext } from "@clawdstrike/plugin-sdk";

export default createPlugin({
  manifest: {
    id: "example.my-first-plugin",
    name: "my-first-plugin",
    displayName: "My First Plugin",
    description: "A custom guard plugin for ClawdStrike",
    version: "0.1.0",
    publisher: "your-name",
    categories: ["guards"],
    trust: "community",
    activationEvents: ["onStartup"],
    contributions: {
      guards: [
        {
          id: "example.my-guard",
          name: "My Guard",
          technicalName: "my_guard",
          description: "A custom security guard",
          category: "custom",
          defaultVerdict: "warn",
          icon: "shield",
          configFields: [],
        },
      ],
    },
  },

  activate(ctx: PluginContext) {
    // Register the guard declared in contributions
    ctx.subscriptions.push(
      ctx.guards.register({
        id: "example.my-guard",
        name: "My Guard",
        technicalName: "my_guard",
        description: "A custom security guard",
        category: "custom",
        defaultVerdict: "warn",
        icon: "shield",
        configFields: [],
      })
    );
  },
});
```

Key manifest fields:

- **id**: Reverse-domain identifier for your plugin (must be unique).
- **name**: Package name (kebab-case).
- **trust**: Loading strategy. Use `"community"` for third-party plugins.
- **activationEvents**: When the plugin should be activated. `"onStartup"` activates immediately.
- **contributions**: Declares what the plugin contributes (guards, commands, file types, etc.).

## Step 4: Build the plugin

```bash
npm run build
```

This runs `tsup` to produce ESM and CJS bundles with TypeScript declarations in the `dist/` directory.

## Step 5: Run tests

```bash
npm test
```

The generated test file uses `createSpyContext` from `@clawdstrike/plugin-sdk/testing` to verify that the plugin activates correctly and registers the expected contributions. See the [Testing Plugins](testing.md) guide for details on the testing API.

## Step 6: Load in the workbench dev server

To test your plugin in a running workbench, add the `vite-plugin-clawdstrike` plugin to your workbench's Vite config:

```typescript,ignore
// vite.config.ts (in the workbench app)
import { defineConfig } from "vite";
import clawdstrike from "vite-plugin-clawdstrike";

export default defineConfig({
  plugins: [
    clawdstrike({
      plugins: ["../my-first-plugin"],
    }),
  ],
});
```

Start the workbench dev server and your plugin will be loaded automatically. File changes trigger hot reload -- see the [Dev Server](dev-server.md) guide for details.

## Next steps

- [Plugin Manifest](manifest.md) -- Full reference for all manifest fields
- [Contribution Points](contribution-points.md) -- All contribution types your plugin can declare
- [Testing Plugins](testing.md) -- Testing utilities and patterns
- [Publishing](publishing.md) -- How to distribute your plugin
