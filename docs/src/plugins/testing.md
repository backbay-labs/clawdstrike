# Testing Plugins

The `@clawdstrike/plugin-sdk/testing` module provides utilities for unit testing plugins without running the workbench. It exports mock and spy contexts, and assertion helpers for validating manifests and contributions.

## Import

```typescript,ignore
import {
  createMockContext,
  createSpyContext,
  assertContributions,
  assertManifestValid,
} from "@clawdstrike/plugin-sdk/testing";
```

## createMockContext

Creates a fully-stubbed `PluginContext` with no-op implementations for all APIs. Useful when you need a context that satisfies the type checker but does not record calls.

```typescript,ignore
function createMockContext(overrides?: Partial<PluginContext>): PluginContext;
```

**Example:**

```typescript,ignore
import { createMockContext } from "@clawdstrike/plugin-sdk/testing";
import plugin from "../src/index";

test("plugin activates without errors", () => {
  const ctx = createMockContext({ pluginId: "test.my-plugin" });
  // activate() runs against no-op stubs -- no errors expected
  plugin.activate(ctx);
});
```

You can override specific APIs to inject test data:

```typescript,ignore
import { createMockContext } from "@clawdstrike/plugin-sdk/testing";

test("plugin reads from storage on activate", () => {
  const storageData = new Map<string, unknown>([
    ["lastScan", "2026-03-22T10:00:00Z"],
  ]);

  const ctx = createMockContext({
    storage: {
      get: (key: string) => storageData.get(key),
      set: (key: string, value: unknown) => { storageData.set(key, value); },
    },
  });

  plugin.activate(ctx);
  expect(storageData.get("lastScan")).toBeDefined();
});
```

## createSpyContext

Creates a `PluginContext` that records all API calls, exposing spy accessors for assertions. Returns an object `{ ctx, spy }` where `ctx` is the `PluginContext` to pass to `activate()` and `spy` provides recorded call data.

```typescript,ignore
function createSpyContext(
  overrides?: Partial<PluginContext>
): { ctx: PluginContext; spy: SpyPluginContext };
```

The `spy` object exposes:

| Property | Type | Description |
|----------|------|-------------|
| `spy.commands.registered` | `Array<{ contribution, handler }>` | Commands registered via `ctx.commands.register()` |
| `spy.guards.registered` | `GuardContribution[]` | Guards registered via `ctx.guards.register()` |
| `spy.fileTypes.registered` | `FileTypeContribution[]` | File types registered via `ctx.fileTypes.register()` |
| `spy.storage.entries()` | `[string, unknown][]` | All key-value pairs set via `ctx.storage.set()` |
| `spy.subscriptions` | `Disposable[]` | All disposables pushed to `ctx.subscriptions` |

**Example:**

```typescript,ignore
import { createSpyContext } from "@clawdstrike/plugin-sdk/testing";
import plugin from "../src/index";

test("plugin registers expected guards", () => {
  const { ctx, spy } = createSpyContext();
  plugin.activate(ctx);

  expect(spy.guards.registered).toHaveLength(1);
  expect(spy.guards.registered[0].id).toBe("acme.my-guard");
  expect(spy.guards.registered[0].defaultVerdict).toBe("deny");
});

test("plugin registers a command with handler", () => {
  const { ctx, spy } = createSpyContext();
  plugin.activate(ctx);

  expect(spy.commands.registered).toHaveLength(1);
  expect(spy.commands.registered[0].contribution.id).toBe("acme.run-scan");

  // Invoke the handler
  spy.commands.registered[0].handler();
});
```

## assertContributions

Validates that a plugin's manifest declares the expected number of contribution types. Throws a vitest-compatible assertion error on mismatch.

```typescript,ignore
function assertContributions(
  plugin: PluginDefinition,
  expected: { guards?: number; commands?: number; fileTypes?: number }
): void;
```

**Example:**

```typescript,ignore
import { assertContributions } from "@clawdstrike/plugin-sdk/testing";
import plugin from "../src/index";

test("plugin declares correct contributions", () => {
  assertContributions(plugin, {
    guards: 1,
    commands: 2,
    fileTypes: 0,
  });
});
```

If the plugin declares 1 guard but the expected count is 2, the error message will read:
`Expected 2 guards contributions, but manifest declares 1`.

## assertManifestValid

Validates that a `PluginManifest` has all required fields with correct types. Throws a vitest-compatible assertion error with field-level details on invalid manifests.

```typescript,ignore
function assertManifestValid(manifest: PluginManifest): void;
```

**Example:**

```typescript,ignore
import { assertManifestValid } from "@clawdstrike/plugin-sdk/testing";
import plugin from "../src/index";

test("manifest is valid", () => {
  assertManifestValid(plugin.manifest);
});
```

If the manifest is missing the `id` field, the error includes: `"id" is required`.

## Complete test file example

Here is a complete test file using vitest that covers the common testing patterns:

```typescript,ignore
import { describe, test, expect } from "vitest";
import {
  createSpyContext,
  assertContributions,
  assertManifestValid,
} from "@clawdstrike/plugin-sdk/testing";
import plugin from "../src/index";

describe("My Guard Plugin", () => {
  test("manifest is valid", () => {
    assertManifestValid(plugin.manifest);
  });

  test("declares expected contributions", () => {
    assertContributions(plugin, {
      guards: 1,
      commands: 1,
    });
  });

  test("registers guard on activation", () => {
    const { ctx, spy } = createSpyContext();
    plugin.activate(ctx);

    expect(spy.guards.registered).toHaveLength(1);
    expect(spy.guards.registered[0].technicalName).toBe("my_guard");
  });

  test("registers command with working handler", () => {
    const { ctx, spy } = createSpyContext();
    plugin.activate(ctx);

    expect(spy.commands.registered).toHaveLength(1);
    // Handler should not throw
    expect(() => spy.commands.registered[0].handler()).not.toThrow();
  });

  test("pushes disposables to subscriptions", () => {
    const { ctx, spy } = createSpyContext();
    plugin.activate(ctx);

    // Each register() call returns a disposable pushed to subscriptions
    expect(spy.subscriptions.length).toBeGreaterThan(0);
  });
});
```

## Common patterns

### Testing guard registration

```typescript,ignore
test("guard has correct config fields", () => {
  const { ctx, spy } = createSpyContext();
  plugin.activate(ctx);

  const guard = spy.guards.registered[0];
  expect(guard.configFields).toHaveLength(2);
  expect(guard.configFields[0].key).toBe("threshold");
  expect(guard.configFields[0].type).toBe("number_slider");
});
```

### Testing command handlers

```typescript,ignore
test("scan command updates storage", () => {
  const { ctx, spy } = createSpyContext();
  plugin.activate(ctx);

  // Run the command handler
  spy.commands.registered[0].handler();

  // Check storage was updated
  const entries = spy.storage.entries();
  expect(entries).toContainEqual(["lastRun", expect.any(String)]);
});
```

### Testing storage interactions

```typescript,ignore
test("plugin reads initial config from storage", () => {
  const { ctx, spy } = createSpyContext({
    storage: {
      get: (key: string) => key === "config" ? { threshold: 80 } : undefined,
      set: () => {},
    },
  });
  plugin.activate(ctx);

  // Assert behavior based on stored config
  expect(spy.guards.registered[0]).toBeDefined();
});
```
