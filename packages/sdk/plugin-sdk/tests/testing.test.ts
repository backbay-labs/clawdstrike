import { describe, it, expect } from "vitest";
import {
  MockStorageApi,
  MockSecretsApi,
  createMockContext,
  createSpyContext,
  type SpyContext,
} from "../src/testing";
import type {
  PluginContext,
  CommandContribution,
  GuardContribution,
  FileTypeContribution,
  StatusBarItemContribution,
  ActivityBarItemContribution,
  EditorTabViewContribution,
  BottomPanelTabViewContribution,
  RightSidebarPanelViewContribution,
  StatusBarWidgetViewContribution,
  ComponentType,
} from "../src/index";

// ---- Test Fixtures ----

function makeCommand(id = "test.cmd"): CommandContribution {
  return { id, title: "Test Command", category: "Test" };
}

function makeGuard(id = "test.guard"): GuardContribution {
  return {
    id,
    name: "Test Guard",
    technicalName: "test_guard",
    description: "A test guard",
    category: "network",
    defaultVerdict: "deny",
    icon: "shield",
    configFields: [],
  };
}

function makeFileType(id = "test.filetype"): FileTypeContribution {
  return {
    id,
    label: "Test File Type",
    shortLabel: "TST",
    extensions: [".tst"],
    iconColor: "#FF0000",
    defaultContent: "test content",
    testable: true,
  };
}

function makeStatusBarItem(id = "test.statusbar"): StatusBarItemContribution {
  return { id, side: "right", priority: 100, entrypoint: "./status.tsx" };
}

function makeActivityBarItem(id = "test.sidebar"): ActivityBarItemContribution {
  return {
    id,
    section: "security",
    label: "Test Sidebar",
    icon: "shield",
    href: "/test",
  };
}

const DummyComponent: ComponentType = () => null;

function makeEditorTab(id = "test.tab"): EditorTabViewContribution {
  return { id, label: "Test Tab", component: DummyComponent };
}

function makeBottomPanelTab(id = "test.panel"): BottomPanelTabViewContribution {
  return { id, label: "Test Panel", component: DummyComponent };
}

function makeRightSidebarPanel(id = "test.right"): RightSidebarPanelViewContribution {
  return { id, label: "Test Right", component: DummyComponent };
}

function makeStatusBarWidget(id = "test.widget"): StatusBarWidgetViewContribution {
  return { id, side: "left", priority: 50, component: DummyComponent };
}

// ---- MockStorageApi ----

describe("MockStorageApi", () => {
  it("get() returns undefined when empty", () => {
    const storage = new MockStorageApi();
    expect(storage.get("x")).toBeUndefined();
  });

  it("set() then get() returns the stored value", () => {
    const storage = new MockStorageApi();
    storage.set("x", 42);
    expect(storage.get("x")).toBe(42);
  });

  it("entries() returns all [key, value] pairs", () => {
    const storage = new MockStorageApi();
    storage.set("a", 1);
    storage.set("b", "two");
    const entries = storage.entries();
    expect(entries).toEqual([
      ["a", 1],
      ["b", "two"],
    ]);
  });

  it("clear() resets all stored values", () => {
    const storage = new MockStorageApi();
    storage.set("x", 42);
    storage.clear();
    expect(storage.get("x")).toBeUndefined();
    expect(storage.entries()).toEqual([]);
  });

  it("implements StorageApi interface (get/set)", () => {
    const storage: MockStorageApi = new MockStorageApi();
    // StorageApi has get(key: string): unknown and set(key: string, value: unknown): void
    storage.set("key", { nested: true });
    expect(storage.get("key")).toEqual({ nested: true });
  });
});

// ---- MockSecretsApi ----

describe("MockSecretsApi", () => {
  it("get() resolves null when empty", async () => {
    const secrets = new MockSecretsApi();
    expect(await secrets.get("x")).toBeNull();
  });

  it("set() then get() resolves the stored value", async () => {
    const secrets = new MockSecretsApi();
    await secrets.set("x", "secret-value");
    expect(await secrets.get("x")).toBe("secret-value");
  });

  it("delete() removes a key", async () => {
    const secrets = new MockSecretsApi();
    await secrets.set("x", "v");
    await secrets.delete("x");
    expect(await secrets.get("x")).toBeNull();
  });

  it("has() resolves true when key exists, false when not", async () => {
    const secrets = new MockSecretsApi();
    expect(await secrets.has("x")).toBe(false);
    await secrets.set("x", "v");
    expect(await secrets.has("x")).toBe(true);
  });

  it("all methods return Promises", () => {
    const secrets = new MockSecretsApi();
    expect(secrets.get("x")).toBeInstanceOf(Promise);
    expect(secrets.set("x", "v")).toBeInstanceOf(Promise);
    expect(secrets.delete("x")).toBeInstanceOf(Promise);
    expect(secrets.has("x")).toBeInstanceOf(Promise);
  });
});

// ---- createMockContext ----

describe("createMockContext", () => {
  it("returns a PluginContext with pluginId 'test.plugin'", () => {
    const ctx = createMockContext();
    expect(ctx.pluginId).toBe("test.plugin");
  });

  it("returns empty subscriptions array", () => {
    const ctx = createMockContext();
    expect(ctx.subscriptions).toEqual([]);
    expect(Array.isArray(ctx.subscriptions)).toBe(true);
  });

  it("commands.register returns a Disposable without throwing", () => {
    const ctx = createMockContext();
    const dispose = ctx.commands.register(makeCommand(), () => {});
    expect(dispose).toBeTypeOf("function");
    expect(() => dispose()).not.toThrow();
  });

  it("guards.register returns a Disposable without throwing", () => {
    const ctx = createMockContext();
    const dispose = ctx.guards.register(makeGuard());
    expect(dispose).toBeTypeOf("function");
    expect(() => dispose()).not.toThrow();
  });

  it("fileTypes.register returns a Disposable without throwing", () => {
    const ctx = createMockContext();
    const dispose = ctx.fileTypes.register(makeFileType());
    expect(dispose).toBeTypeOf("function");
  });

  it("statusBar.register returns a Disposable without throwing", () => {
    const ctx = createMockContext();
    const dispose = ctx.statusBar.register(makeStatusBarItem());
    expect(dispose).toBeTypeOf("function");
  });

  it("sidebar.register returns a Disposable without throwing", () => {
    const ctx = createMockContext();
    const dispose = ctx.sidebar.register(makeActivityBarItem());
    expect(dispose).toBeTypeOf("function");
  });

  it("views.registerEditorTab returns a Disposable", () => {
    const ctx = createMockContext();
    const dispose = ctx.views.registerEditorTab(makeEditorTab());
    expect(dispose).toBeTypeOf("function");
  });

  it("views.registerBottomPanelTab returns a Disposable", () => {
    const ctx = createMockContext();
    const dispose = ctx.views.registerBottomPanelTab(makeBottomPanelTab());
    expect(dispose).toBeTypeOf("function");
  });

  it("views.registerRightSidebarPanel returns a Disposable", () => {
    const ctx = createMockContext();
    const dispose = ctx.views.registerRightSidebarPanel(makeRightSidebarPanel());
    expect(dispose).toBeTypeOf("function");
  });

  it("views.registerStatusBarWidget returns a Disposable", () => {
    const ctx = createMockContext();
    const dispose = ctx.views.registerStatusBarWidget(makeStatusBarWidget());
    expect(dispose).toBeTypeOf("function");
  });

  it("enrichmentRenderers.register returns a Disposable", () => {
    const ctx = createMockContext();
    const dispose = ctx.enrichmentRenderers.register("vt", DummyComponent);
    expect(dispose).toBeTypeOf("function");
  });

  it("storage is a MockStorageApi with get/set/entries", () => {
    const ctx = createMockContext();
    ctx.storage.set("key", "value");
    expect(ctx.storage.get("key")).toBe("value");
  });

  it("secrets is a MockSecretsApi with async get/set/delete/has", async () => {
    const ctx = createMockContext();
    await ctx.secrets.set("key", "secret");
    expect(await ctx.secrets.get("key")).toBe("secret");
  });

  it("custom pluginId override", () => {
    const ctx = createMockContext({ pluginId: "custom.id" });
    expect(ctx.pluginId).toBe("custom.id");
  });

  it("custom API override replaces default", () => {
    let called = false;
    const customCommands = {
      register: () => {
        called = true;
        return () => {};
      },
    };
    const ctx = createMockContext({ commands: customCommands });
    ctx.commands.register(makeCommand(), () => {});
    expect(called).toBe(true);
  });
});

// ---- createSpyContext ----

describe("createSpyContext", () => {
  it("spy.commands.registered tracks commands.register() calls", () => {
    const { ctx, spy } = createSpyContext();
    const handler = () => {};
    const cmd = makeCommand();
    ctx.commands.register(cmd, handler);
    expect(spy.commands.registered).toHaveLength(1);
    expect(spy.commands.registered[0].contribution).toBe(cmd);
    expect(spy.commands.registered[0].handler).toBe(handler);
  });

  it("spy.guards.registered tracks guards.register() calls", () => {
    const { ctx, spy } = createSpyContext();
    const guard = makeGuard();
    ctx.guards.register(guard);
    expect(spy.guards.registered).toHaveLength(1);
    expect(spy.guards.registered[0]).toBe(guard);
  });

  it("spy.fileTypes.registered tracks fileTypes.register() calls", () => {
    const { ctx, spy } = createSpyContext();
    const ft = makeFileType();
    ctx.fileTypes.register(ft);
    expect(spy.fileTypes.registered).toHaveLength(1);
    expect(spy.fileTypes.registered[0]).toBe(ft);
  });

  it("spy.statusBar.registered tracks statusBar.register() calls", () => {
    const { ctx, spy } = createSpyContext();
    const item = makeStatusBarItem();
    ctx.statusBar.register(item);
    expect(spy.statusBar.registered).toHaveLength(1);
    expect(spy.statusBar.registered[0]).toBe(item);
  });

  it("spy.sidebar.registered tracks sidebar.register() calls", () => {
    const { ctx, spy } = createSpyContext();
    const item = makeActivityBarItem();
    ctx.sidebar.register(item);
    expect(spy.sidebar.registered).toHaveLength(1);
    expect(spy.sidebar.registered[0]).toBe(item);
  });

  it("spy.views.editorTabs tracks views.registerEditorTab() calls", () => {
    const { ctx, spy } = createSpyContext();
    const tab = makeEditorTab();
    ctx.views.registerEditorTab(tab);
    expect(spy.views.editorTabs).toHaveLength(1);
    expect(spy.views.editorTabs[0]).toBe(tab);
  });

  it("spy.views.bottomPanelTabs tracks views.registerBottomPanelTab() calls", () => {
    const { ctx, spy } = createSpyContext();
    const panel = makeBottomPanelTab();
    ctx.views.registerBottomPanelTab(panel);
    expect(spy.views.bottomPanelTabs).toHaveLength(1);
    expect(spy.views.bottomPanelTabs[0]).toBe(panel);
  });

  it("spy.views.rightSidebarPanels tracks views.registerRightSidebarPanel() calls", () => {
    const { ctx, spy } = createSpyContext();
    const panel = makeRightSidebarPanel();
    ctx.views.registerRightSidebarPanel(panel);
    expect(spy.views.rightSidebarPanels).toHaveLength(1);
    expect(spy.views.rightSidebarPanels[0]).toBe(panel);
  });

  it("spy.views.statusBarWidgets tracks views.registerStatusBarWidget() calls", () => {
    const { ctx, spy } = createSpyContext();
    const widget = makeStatusBarWidget();
    ctx.views.registerStatusBarWidget(widget);
    expect(spy.views.statusBarWidgets).toHaveLength(1);
    expect(spy.views.statusBarWidgets[0]).toBe(widget);
  });

  it("spy.enrichmentRenderers.registered tracks enrichmentRenderers.register() calls", () => {
    const { ctx, spy } = createSpyContext();
    ctx.enrichmentRenderers.register("vt", DummyComponent);
    expect(spy.enrichmentRenderers.registered).toHaveLength(1);
    expect(spy.enrichmentRenderers.registered[0].type).toBe("vt");
    expect(spy.enrichmentRenderers.registered[0].component).toBe(DummyComponent);
  });

  it("spy.storage is the MockStorageApi instance", () => {
    const { ctx, spy } = createSpyContext();
    ctx.storage.set("x", 42);
    expect(spy.storage).toBeInstanceOf(MockStorageApi);
    expect(spy.storage.get("x")).toBe(42);
    expect(spy.storage.entries()).toEqual([["x", 42]]);
  });

  it("spy.secrets is the MockSecretsApi instance", async () => {
    const { ctx, spy } = createSpyContext();
    await ctx.secrets.set("key", "secret");
    expect(spy.secrets).toBeInstanceOf(MockSecretsApi);
    expect(await spy.secrets.get("key")).toBe("secret");
  });

  it("spy.subscriptions is the subscriptions array from the context", () => {
    const { ctx, spy } = createSpyContext();
    const dispose = () => {};
    ctx.subscriptions.push(dispose);
    expect(spy.subscriptions).toBe(ctx.subscriptions);
    expect(spy.subscriptions).toHaveLength(1);
    expect(spy.subscriptions[0]).toBe(dispose);
  });

  it("every register() returns a working Disposable that removes item from tracking", () => {
    const { ctx, spy } = createSpyContext();
    const guard = makeGuard();
    const dispose = ctx.guards.register(guard);
    expect(spy.guards.registered).toHaveLength(1);
    dispose();
    expect(spy.guards.registered).toHaveLength(0);
  });

  it("Disposable from commands.register removes the correct entry", () => {
    const { ctx, spy } = createSpyContext();
    const cmd1 = makeCommand("cmd1");
    const cmd2 = makeCommand("cmd2");
    const dispose1 = ctx.commands.register(cmd1, () => {});
    ctx.commands.register(cmd2, () => {});
    expect(spy.commands.registered).toHaveLength(2);
    dispose1();
    expect(spy.commands.registered).toHaveLength(1);
    expect(spy.commands.registered[0].contribution).toBe(cmd2);
  });

  it("Disposable from views.registerEditorTab removes the tab", () => {
    const { ctx, spy } = createSpyContext();
    const tab = makeEditorTab();
    const dispose = ctx.views.registerEditorTab(tab);
    expect(spy.views.editorTabs).toHaveLength(1);
    dispose();
    expect(spy.views.editorTabs).toHaveLength(0);
  });

  it("Disposable from enrichmentRenderers.register removes the renderer", () => {
    const { ctx, spy } = createSpyContext();
    const dispose = ctx.enrichmentRenderers.register("vt", DummyComponent);
    expect(spy.enrichmentRenderers.registered).toHaveLength(1);
    dispose();
    expect(spy.enrichmentRenderers.registered).toHaveLength(0);
  });

  it("overrides merge on top of spy context", () => {
    let customCalled = false;
    const { ctx } = createSpyContext({
      commands: {
        register: () => {
          customCalled = true;
          return () => {};
        },
      },
    });
    ctx.commands.register(makeCommand(), () => {});
    expect(customCalled).toBe(true);
  });

  it("multiple registrations across different APIs work independently", () => {
    const { ctx, spy } = createSpyContext();
    ctx.commands.register(makeCommand(), () => {});
    ctx.guards.register(makeGuard());
    ctx.fileTypes.register(makeFileType());
    ctx.statusBar.register(makeStatusBarItem());
    ctx.sidebar.register(makeActivityBarItem());

    expect(spy.commands.registered).toHaveLength(1);
    expect(spy.guards.registered).toHaveLength(1);
    expect(spy.fileTypes.registered).toHaveLength(1);
    expect(spy.statusBar.registered).toHaveLength(1);
    expect(spy.sidebar.registered).toHaveLength(1);
  });
});
