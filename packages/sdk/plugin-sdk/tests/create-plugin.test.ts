import { describe, it, expect } from "vitest";
import {
  createPlugin,
  type PluginDefinition,
  type PluginContext,
  type PluginManifest,
  type CommandContribution,
  type GuardContribution,
  type FileTypeContribution,
  type StatusBarItemContribution,
  type Disposable,
  type CommandsApi,
  type GuardsApi,
  type FileTypesApi,
  type StatusBarApi,
  type StorageApi,
  type SidebarApi,
  type ViewsApi,
  type ActivityBarItemContribution,
  type PluginContributions,
  type KeybindingContribution,
  type DetectionAdapterContribution,
  type EditorTabContribution,
  type BottomPanelTabContribution,
  type RightSidebarPanelContribution,
  type ThreatIntelSourceContribution,
  type ComplianceFrameworkContribution,
  type InstallationMetadata,
  type ConfigFieldDef,
  type PluginTrustTier,
  type PluginLifecycleState,
  type PluginCategory,
  type ActivationEvent,
  type EditorTabViewContribution,
  type BottomPanelTabViewContribution,
  type RightSidebarPanelViewContribution,
  type StatusBarWidgetViewContribution,
  type ViewProps,
  type EditorTabProps,
  type BottomPanelTabProps,
  type RightSidebarPanelProps,
  type ActivityBarPanelProps,
  type StatusBarWidgetProps,
} from "../src/index";

// ---- Test Helpers ----

function makeManifest(overrides?: Partial<PluginManifest>): PluginManifest {
  return {
    id: "test.plugin",
    name: "test-plugin",
    displayName: "Test Plugin",
    description: "A test plugin",
    version: "1.0.0",
    publisher: "test",
    categories: ["guards"],
    trust: "internal",
    activationEvents: ["onStartup"],
    ...overrides,
  };
}

function makeMockContext(overrides?: Partial<PluginContext>): PluginContext {
  const storage = new Map<string, unknown>();
  return {
    pluginId: "test.plugin",
    subscriptions: [],
    commands: {
      register: (_cmd: CommandContribution, _handler: () => void): Disposable => () => {},
    },
    guards: {
      register: (_guard: GuardContribution): Disposable => () => {},
    },
    fileTypes: {
      register: (_ft: FileTypeContribution): Disposable => () => {},
    },
    statusBar: {
      register: (_item: StatusBarItemContribution): Disposable => () => {},
    },
    sidebar: {
      register: (_item: ActivityBarItemContribution): Disposable => () => {},
    },
    storage: {
      get: (key: string): unknown => storage.get(key),
      set: (key: string, value: unknown): void => { storage.set(key, value); },
    },
    views: {
      registerEditorTab: (_contrib: EditorTabViewContribution): Disposable => () => {},
      registerBottomPanelTab: (_contrib: BottomPanelTabViewContribution): Disposable => () => {},
      registerRightSidebarPanel: (_contrib: RightSidebarPanelViewContribution): Disposable => () => {},
      registerStatusBarWidget: (_contrib: StatusBarWidgetViewContribution): Disposable => () => {},
    },
    ...overrides,
  };
}

// ---- Tests ----

describe("createPlugin", () => {
  it("returns a PluginDefinition with manifest and activate", () => {
    const plugin = createPlugin({
      manifest: makeManifest(),
      activate(_ctx: PluginContext) {
        // no-op
      },
    });

    expect(plugin).toBeDefined();
    expect(plugin.manifest).toBeDefined();
    expect(plugin.manifest.id).toBe("test.plugin");
    expect(plugin.activate).toBeTypeOf("function");
  });

  it("enforces activate receives PluginContext parameter", () => {
    const plugin = createPlugin({
      manifest: makeManifest(),
      activate(ctx: PluginContext) {
        // Type-level check: ctx must have the namespaced APIs
        expect(ctx.commands).toBeDefined();
        expect(ctx.guards).toBeDefined();
        expect(ctx.fileTypes).toBeDefined();
        expect(ctx.statusBar).toBeDefined();
        expect(ctx.storage).toBeDefined();
      },
    });

    const ctx = makeMockContext();
    plugin.activate(ctx);
  });

  it("deactivate is optional (plugin without deactivate compiles and works)", () => {
    const plugin = createPlugin({
      manifest: makeManifest(),
      activate(_ctx: PluginContext) {
        // no-op
      },
      // no deactivate -- should compile fine
    });

    expect(plugin.deactivate).toBeUndefined();
  });

  it("activate can return Disposable[] for cleanup", () => {
    let disposed = false;

    const plugin = createPlugin({
      manifest: makeManifest(),
      activate(_ctx: PluginContext): Disposable[] {
        return [() => { disposed = true; }];
      },
    });

    const ctx = makeMockContext();
    const result = plugin.activate(ctx);
    expect(Array.isArray(result)).toBe(true);

    const disposables = result as Disposable[];
    disposables[0]();
    expect(disposed).toBe(true);
  });

  it("activate can return void", () => {
    const plugin = createPlugin({
      manifest: makeManifest(),
      activate(_ctx: PluginContext): void {
        // returns void
      },
    });

    const ctx = makeMockContext();
    const result = plugin.activate(ctx);
    expect(result).toBeUndefined();
  });
});

describe("PluginContext.commands", () => {
  it("register() accepts a CommandContribution and returns Disposable", () => {
    let registered = false;
    const ctx = makeMockContext({
      commands: {
        register: (cmd: CommandContribution, _handler: () => void): Disposable => {
          registered = true;
          expect(cmd.id).toBe("test.myCommand");
          expect(cmd.title).toBe("My Command");
          return () => {};
        },
      },
    });

    const dispose = ctx.commands.register(
      { id: "test.myCommand", title: "My Command", category: "Test" },
      () => {},
    );

    expect(registered).toBe(true);
    expect(dispose).toBeTypeOf("function");
  });
});

describe("PluginContext.guards", () => {
  it("register() accepts a GuardContribution and returns Disposable", () => {
    let registered = false;
    const ctx = makeMockContext({
      guards: {
        register: (guard: GuardContribution): Disposable => {
          registered = true;
          expect(guard.id).toBe("test.customGuard");
          expect(guard.name).toBe("Custom Guard");
          return () => {};
        },
      },
    });

    const dispose = ctx.guards.register({
      id: "test.customGuard",
      name: "Custom Guard",
      technicalName: "custom_guard",
      description: "A test guard",
      category: "network",
      defaultVerdict: "deny",
      icon: "shield",
      configFields: [],
    });

    expect(registered).toBe(true);
    expect(dispose).toBeTypeOf("function");
  });
});

describe("PluginContext.fileTypes", () => {
  it("register() accepts a FileTypeContribution and returns Disposable", () => {
    let registered = false;
    const ctx = makeMockContext({
      fileTypes: {
        register: (ft: FileTypeContribution): Disposable => {
          registered = true;
          expect(ft.id).toBe("snort_rule");
          return () => {};
        },
      },
    });

    const dispose = ctx.fileTypes.register({
      id: "snort_rule",
      label: "Snort Rule",
      shortLabel: "SNORT",
      extensions: [".rules"],
      iconColor: "#FF6633",
      defaultContent: "alert tcp any any -> any any (msg:\"test\"; sid:1;)",
      testable: true,
    });

    expect(registered).toBe(true);
    expect(dispose).toBeTypeOf("function");
  });
});

describe("PluginContext.statusBar", () => {
  it("register() accepts a StatusBarItemContribution and returns Disposable", () => {
    let registered = false;
    const ctx = makeMockContext({
      statusBar: {
        register: (item: StatusBarItemContribution): Disposable => {
          registered = true;
          expect(item.id).toBe("test.statusItem");
          expect(item.side).toBe("right");
          return () => {};
        },
      },
    });

    const dispose = ctx.statusBar.register({
      id: "test.statusItem",
      side: "right",
      priority: 100,
      entrypoint: "./status.tsx",
    });

    expect(registered).toBe(true);
    expect(dispose).toBeTypeOf("function");
  });
});

describe("PluginContext.storage", () => {
  it("get()/set() provide key-value persistence", () => {
    const ctx = makeMockContext();

    ctx.storage.set("myKey", { count: 42 });
    const value = ctx.storage.get("myKey");
    expect(value).toEqual({ count: 42 });
  });

  it("get() returns undefined for unknown keys", () => {
    const ctx = makeMockContext();
    expect(ctx.storage.get("nonexistent")).toBeUndefined();
  });
});

describe("Type re-exports", () => {
  it("all contribution point interfaces are importable", () => {
    // These are compile-time checks -- if the imports above resolve, this passes.
    // We verify the type names exist at runtime via typeof checks on the objects.
    const _cmd: CommandContribution = { id: "a", title: "b" };
    const _kb: KeybindingContribution = { command: "a", key: "Cmd+K" };
    const _da: DetectionAdapterContribution = { fileType: "sigma", entrypoint: "./detect.ts" };
    const _et: EditorTabContribution = { id: "a", label: "b", entrypoint: "./tab.tsx" };
    const _bp: BottomPanelTabContribution = { id: "a", label: "b", entrypoint: "./panel.tsx" };
    const _rp: RightSidebarPanelContribution = { id: "a", label: "b", entrypoint: "./right.tsx" };
    const _ti: ThreatIntelSourceContribution = { id: "a", name: "b", description: "c", entrypoint: "./intel.ts" };
    const _cf: ComplianceFrameworkContribution = { id: "a", name: "b", description: "c", entrypoint: "./comp.ts" };
    const _im: InstallationMetadata = { downloadUrl: "https://x", size: 100, checksum: "abc", signature: "def" };
    const _cfd: ConfigFieldDef = { key: "k", label: "l", type: "toggle" };

    // Verify trust tier and lifecycle types
    const _trust: PluginTrustTier = "internal";
    const _state: PluginLifecycleState = "activated";
    const _cat: PluginCategory = "guards";
    const _event: ActivationEvent = "onStartup";

    // Verify PluginContributions container
    const _contributions: PluginContributions = {
      guards: [],
      commands: [_cmd],
      keybindings: [_kb],
    };

    // If we got here, all types compile
    expect(true).toBe(true);
  });
});
