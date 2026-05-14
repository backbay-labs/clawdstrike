import { describe, it, expect, afterEach, vi } from "vitest";
import {
  registerView,
  getView,
  getViewsBySlot,
  onViewRegistryChange,
} from "../view-registry";
import type { ViewRegistration, ViewSlot } from "../view-registry";
import { createElement } from "react";

function TestComponent() {
  return createElement("div", null, "test");
}

function makeView(
  overrides: Partial<ViewRegistration> & { id: string },
): ViewRegistration {
  return {
    slot: "editorTab" as ViewSlot,
    label: overrides.id,
    component: TestComponent,
    ...overrides,
  };
}

describe("view-registry", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("registers and retrieves a view by id", () => {
    const view = makeView({ id: "p.v" });
    disposers.push(registerView(view));

    const retrieved = getView("p.v");
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe("p.v");
    expect(retrieved?.slot).toBe("editorTab");
    expect(retrieved?.label).toBe("p.v");
    expect(retrieved?.component).toBe(TestComponent);
  });

  it("getViewsBySlot returns only views matching the slot, sorted by priority ascending", () => {
    disposers.push(
      registerView(makeView({ id: "editor-high", slot: "editorTab", priority: 50 })),
    );
    disposers.push(
      registerView(makeView({ id: "editor-low", slot: "editorTab", priority: 10 })),
    );
    disposers.push(
      registerView(makeView({ id: "bottom-panel", slot: "bottomPanelTab" })),
    );

    const editorViews = getViewsBySlot("editorTab");
    expect(editorViews).toHaveLength(2);
    expect(editorViews[0].id).toBe("editor-low");
    expect(editorViews[1].id).toBe("editor-high");

    // bottom panel should not appear in editorTab query
    expect(editorViews.some((v) => v.id === "bottom-panel")).toBe(false);
  });

  it("getViewsBySlot returns empty array when no views registered for that slot", () => {
    const views = getViewsBySlot("bottomPanelTab");
    expect(views).toEqual([]);
  });

  it("registerView returns a dispose function that removes the view", () => {
    const dispose = registerView(makeView({ id: "disposable" }));
    expect(getView("disposable")).toBeDefined();

    dispose();
    expect(getView("disposable")).toBeUndefined();
    expect(getViewsBySlot("editorTab").some((v) => v.id === "disposable")).toBe(false);
  });

  it("throws on duplicate id", () => {
    disposers.push(registerView(makeView({ id: "dup-test" })));
    expect(() => registerView(makeView({ id: "dup-test" }))).toThrow(
      'View "dup-test" already registered',
    );
  });

  it("notifies listeners on register and dispose", () => {
    const listener = vi.fn();
    const unsub = onViewRegistryChange(listener);
    disposers.push(unsub);

    const dispose = registerView(makeView({ id: "notify-test" }));
    expect(listener).toHaveBeenCalledTimes(1);

    dispose();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("unsubscribe stops notifications", () => {
    const listener = vi.fn();
    const unsub = onViewRegistryChange(listener);

    unsub();
    disposers.push(registerView(makeView({ id: "after-unsub" })));
    expect(listener).not.toHaveBeenCalled();
  });

  it("getViewsBySlot returns stable snapshot reference when no changes occur", () => {
    disposers.push(registerView(makeView({ id: "stable-check" })));
    const snap1 = getViewsBySlot("editorTab");
    const snap2 = getViewsBySlot("editorTab");
    expect(snap1).toBe(snap2); // same object identity
  });

  it("uses default priority of 100 when not specified", () => {
    disposers.push(registerView(makeView({ id: "no-pri" })));
    disposers.push(registerView(makeView({ id: "low-pri", priority: 5 })));

    const views = getViewsBySlot("editorTab");
    expect(views[0].id).toBe("low-pri");
    expect(views[1].id).toBe("no-pri");
  });
});
