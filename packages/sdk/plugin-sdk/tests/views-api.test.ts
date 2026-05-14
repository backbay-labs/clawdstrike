/**
 * ViewsApi Tests
 *
 * Tests for the SDK ViewsApi interface, view prop types, and SDK-side view
 * contribution types. Ensures all types are importable, structurally correct,
 * and that PluginContext includes the views namespace.
 */

import { describe, it, expect } from "vitest";
import type {
  PluginContext,
  ViewsApi,
  ViewProps,
  EditorTabProps,
  BottomPanelTabProps,
  RightSidebarPanelProps,
  ActivityBarPanelProps,
  StatusBarWidgetProps,
  EditorTabViewContribution,
  BottomPanelTabViewContribution,
  RightSidebarPanelViewContribution,
  StatusBarWidgetViewContribution,
  Disposable,
} from "../src/index";

// ---- Tests ----

describe("ViewProps interfaces", () => {
  it("ViewProps has viewId, isActive, and storage", () => {
    const props: ViewProps = {
      viewId: "test.myView",
      isActive: true,
      storage: {
        get: (_key: string): unknown => undefined,
        set: (_key: string, _value: unknown): void => {},
      },
    };
    expect(props.viewId).toBe("test.myView");
    expect(props.isActive).toBe(true);
    expect(props.storage.get).toBeTypeOf("function");
    expect(props.storage.set).toBeTypeOf("function");
  });

  it("EditorTabProps extends ViewProps with setTitle and setDirty", () => {
    let titleSet = "";
    let dirtySet = false;
    const props: EditorTabProps = {
      viewId: "test.editor",
      isActive: true,
      storage: {
        get: () => undefined,
        set: () => {},
      },
      setTitle: (title: string) => { titleSet = title; },
      setDirty: (dirty: boolean) => { dirtySet = dirty; },
    };
    props.setTitle("New Title");
    props.setDirty(true);
    expect(titleSet).toBe("New Title");
    expect(dirtySet).toBe(true);
  });

  it("BottomPanelTabProps extends ViewProps with panelHeight", () => {
    const props: BottomPanelTabProps = {
      viewId: "test.panel",
      isActive: false,
      storage: { get: () => undefined, set: () => {} },
      panelHeight: 300,
    };
    expect(props.panelHeight).toBe(300);
  });

  it("RightSidebarPanelProps extends ViewProps with sidebarWidth", () => {
    const props: RightSidebarPanelProps = {
      viewId: "test.sidebar",
      isActive: true,
      storage: { get: () => undefined, set: () => {} },
      sidebarWidth: 250,
    };
    expect(props.sidebarWidth).toBe(250);
  });

  it("ActivityBarPanelProps extends ViewProps with isCollapsed", () => {
    const props: ActivityBarPanelProps = {
      viewId: "test.activity",
      isActive: true,
      storage: { get: () => undefined, set: () => {} },
      isCollapsed: false,
    };
    expect(props.isCollapsed).toBe(false);
  });

  it("StatusBarWidgetProps has viewId only", () => {
    const props: StatusBarWidgetProps = {
      viewId: "test.status",
    };
    expect(props.viewId).toBe("test.status");
  });
});

describe("SDK View Contribution types", () => {
  it("EditorTabViewContribution accepts a component function", () => {
    const DummyComponent = () => null;
    const contrib: EditorTabViewContribution = {
      id: "myEditor",
      label: "My Editor Tab",
      icon: "file-code",
      component: DummyComponent,
    };
    expect(contrib.id).toBe("myEditor");
    expect(contrib.label).toBe("My Editor Tab");
    expect(contrib.component).toBe(DummyComponent);
  });

  it("EditorTabViewContribution accepts a lazy import factory", () => {
    const DummyComponent = () => null;
    const lazyFactory = async () => ({ default: DummyComponent as any });
    const contrib: EditorTabViewContribution = {
      id: "lazyEditor",
      label: "Lazy Editor Tab",
      component: lazyFactory,
    };
    expect(contrib.component).toBe(lazyFactory);
  });

  it("BottomPanelTabViewContribution has id, label, icon?, component", () => {
    const DummyComponent = () => null;
    const contrib: BottomPanelTabViewContribution = {
      id: "myPanel",
      label: "My Panel",
      component: DummyComponent,
    };
    expect(contrib.id).toBe("myPanel");
    expect(contrib.icon).toBeUndefined();
  });

  it("RightSidebarPanelViewContribution has id, label, icon?, component", () => {
    const DummyComponent = () => null;
    const contrib: RightSidebarPanelViewContribution = {
      id: "mySidebar",
      label: "My Sidebar",
      icon: "panel-right",
      component: DummyComponent,
    };
    expect(contrib.id).toBe("mySidebar");
    expect(contrib.icon).toBe("panel-right");
  });

  it("StatusBarWidgetViewContribution has id, side, priority, component", () => {
    const DummyComponent = () => null;
    const contrib: StatusBarWidgetViewContribution = {
      id: "myStatus",
      side: "right",
      priority: 50,
      component: DummyComponent,
    };
    expect(contrib.side).toBe("right");
    expect(contrib.priority).toBe(50);
  });
});

describe("PluginContext.views namespace", () => {
  it("PluginContext has a views property with ViewsApi methods", () => {
    const mockViews: ViewsApi = {
      registerEditorTab: (_contrib): Disposable => () => {},
      registerBottomPanelTab: (_contrib): Disposable => () => {},
      registerRightSidebarPanel: (_contrib): Disposable => () => {},
      registerStatusBarWidget: (_contrib): Disposable => () => {},
    };

    // Type check: PluginContext should accept views
    const ctx: Pick<PluginContext, "views"> = {
      views: mockViews,
    };

    expect(ctx.views.registerEditorTab).toBeTypeOf("function");
    expect(ctx.views.registerBottomPanelTab).toBeTypeOf("function");
    expect(ctx.views.registerRightSidebarPanel).toBeTypeOf("function");
    expect(ctx.views.registerStatusBarWidget).toBeTypeOf("function");
  });

  it("registerEditorTab returns a Disposable", () => {
    let disposed = false;
    const mockViews: ViewsApi = {
      registerEditorTab: (_contrib) => () => { disposed = true; },
      registerBottomPanelTab: (_contrib) => () => {},
      registerRightSidebarPanel: (_contrib) => () => {},
      registerStatusBarWidget: (_contrib) => () => {},
    };

    const DummyComponent = () => null;
    const dispose = mockViews.registerEditorTab({
      id: "test",
      label: "Test",
      component: DummyComponent,
    });

    dispose();
    expect(disposed).toBe(true);
  });
});
