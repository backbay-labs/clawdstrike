import { describe, it, expect, afterEach, vi } from "vitest";
import {
  registerStatusBarItem,
  unregisterStatusBarItem,
  getStatusBarItems,
  onStatusBarChange,
} from "../status-bar-registry";
import type { StatusBarItem } from "../status-bar-registry";
import { createElement } from "react";

function makeItem(
  overrides: Partial<StatusBarItem> & { id: string },
): StatusBarItem {
  return {
    side: "left",
    priority: 10,
    render: () => createElement("span", null, overrides.id),
    ...overrides,
  };
}

describe("status-bar-registry", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("registers and retrieves items by side", () => {
    disposers.push(registerStatusBarItem(makeItem({ id: "test-left", side: "left" })));
    disposers.push(registerStatusBarItem(makeItem({ id: "test-right", side: "right" })));

    const leftItems = getStatusBarItems("left");
    const rightItems = getStatusBarItems("right");

    expect(leftItems.some((i) => i.id === "test-left")).toBe(true);
    expect(rightItems.some((i) => i.id === "test-right")).toBe(true);
    expect(leftItems.some((i) => i.id === "test-right")).toBe(false);
    expect(rightItems.some((i) => i.id === "test-left")).toBe(false);
  });

  it("sorts items by priority", () => {
    disposers.push(
      registerStatusBarItem(makeItem({ id: "high-pri", side: "left", priority: 30 })),
    );
    disposers.push(
      registerStatusBarItem(makeItem({ id: "low-pri", side: "left", priority: 10 })),
    );
    disposers.push(
      registerStatusBarItem(makeItem({ id: "mid-pri", side: "left", priority: 20 })),
    );

    const items = getStatusBarItems("left");
    const ids = items.filter((i) => i.id.endsWith("-pri")).map((i) => i.id);
    expect(ids).toEqual(["low-pri", "mid-pri", "high-pri"]);
  });

  it("returns dispose function that removes item", () => {
    const dispose = registerStatusBarItem(makeItem({ id: "disposable", side: "left" }));
    expect(getStatusBarItems("left").some((i) => i.id === "disposable")).toBe(true);

    dispose();
    expect(getStatusBarItems("left").some((i) => i.id === "disposable")).toBe(false);
  });

  it("throws on duplicate ID", () => {
    disposers.push(registerStatusBarItem(makeItem({ id: "dup-test" })));
    expect(() => registerStatusBarItem(makeItem({ id: "dup-test" }))).toThrow(
      'Status bar item "dup-test" is already registered',
    );
  });

  it("unregisterStatusBarItem is no-op for unknown ID", () => {
    expect(() => unregisterStatusBarItem("nonexistent")).not.toThrow();
  });

  it("returns a new snapshot reference when the registry changes", () => {
    const before = getStatusBarItems("left");

    disposers.push(registerStatusBarItem(makeItem({ id: "snapshot-change" })));

    const after = getStatusBarItems("left");
    expect(after).not.toBe(before);
  });

  it("refreshes snapshots after a same-size replacement", () => {
    disposers.push(registerStatusBarItem(makeItem({ id: "replace-before" })));
    const before = getStatusBarItems("left");
    expect(before.some((item) => item.id === "replace-before")).toBe(true);

    unregisterStatusBarItem("replace-before");
    disposers.push(registerStatusBarItem(makeItem({ id: "replace-after" })));

    const after = getStatusBarItems("left");
    expect(after).not.toBe(before);
    expect(after.some((item) => item.id === "replace-before")).toBe(false);
    expect(after.some((item) => item.id === "replace-after")).toBe(true);
  });

  it("notifies listeners on register", () => {
    const listener = vi.fn();
    const unsub = onStatusBarChange(listener);
    disposers.push(unsub);

    disposers.push(registerStatusBarItem(makeItem({ id: "notify-reg" })));
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("notifies listeners on unregister", () => {
    disposers.push(registerStatusBarItem(makeItem({ id: "notify-unreg" })));

    const listener = vi.fn();
    const unsub = onStatusBarChange(listener);
    disposers.push(unsub);

    unregisterStatusBarItem("notify-unreg");
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("unsubscribe stops notifications", () => {
    const listener = vi.fn();
    const unsub = onStatusBarChange(listener);

    unsub();
    disposers.push(registerStatusBarItem(makeItem({ id: "after-unsub" })));
    expect(listener).not.toHaveBeenCalled();
  });
});
