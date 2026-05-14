import { describe, it, expect, afterEach, vi } from "vitest";
import {
  registerContextMenuItem,
  getContextMenuItems,
  getContextMenuItemsByMenu,
  onContextMenuChange,
  evaluateWhenClause,
} from "../context-menu-registry";
import type {
  ContextMenuItemRegistration,
  ContextMenuTarget,
} from "../context-menu-registry";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeItem(
  overrides: Partial<ContextMenuItemRegistration> & { id: string },
): ContextMenuItemRegistration {
  return {
    label: overrides.id,
    command: `cmd.${overrides.id}`,
    menu: "editor" as ContextMenuTarget,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

describe("context-menu-registry", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("registration adds item and returns dispose", () => {
    const dispose = registerContextMenuItem(makeItem({ id: "p.item1" }));
    disposers.push(dispose);

    const items = getContextMenuItemsByMenu("editor");
    expect(items).toHaveLength(1);
    expect(items[0].id).toBe("p.item1");
  });

  it("disposal removes item and notifies listeners", () => {
    const listener = vi.fn();
    const unsub = onContextMenuChange(listener);
    disposers.push(unsub);

    const dispose = registerContextMenuItem(makeItem({ id: "p.disposable" }));
    expect(listener).toHaveBeenCalledTimes(1);

    dispose();
    expect(listener).toHaveBeenCalledTimes(2);
    expect(getContextMenuItemsByMenu("editor")).toHaveLength(0);
  });

  it("duplicate id throws Error", () => {
    disposers.push(registerContextMenuItem(makeItem({ id: "p.dup" })));
    expect(() => registerContextMenuItem(makeItem({ id: "p.dup" }))).toThrow(
      'Context menu item "p.dup" already registered',
    );
  });

  it("getContextMenuItemsByMenu returns items for correct menu only", () => {
    disposers.push(
      registerContextMenuItem(makeItem({ id: "p.editor-item", menu: "editor" })),
    );
    disposers.push(
      registerContextMenuItem(makeItem({ id: "p.sidebar-item", menu: "sidebar" })),
    );
    disposers.push(
      registerContextMenuItem(makeItem({ id: "p.tab-item", menu: "tab" })),
    );

    const editorItems = getContextMenuItemsByMenu("editor");
    expect(editorItems).toHaveLength(1);
    expect(editorItems[0].id).toBe("p.editor-item");

    const sidebarItems = getContextMenuItemsByMenu("sidebar");
    expect(sidebarItems).toHaveLength(1);
    expect(sidebarItems[0].id).toBe("p.sidebar-item");
  });

  it("items sorted by priority within a menu", () => {
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.high", menu: "editor", priority: 200 }),
      ),
    );
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.low", menu: "editor", priority: 10 }),
      ),
    );
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.default", menu: "editor" }),
      ),
    );

    const items = getContextMenuItemsByMenu("editor");
    expect(items).toHaveLength(3);
    expect(items[0].id).toBe("p.low"); // priority 10
    expect(items[1].id).toBe("p.default"); // priority 100 (default)
    expect(items[2].id).toBe("p.high"); // priority 200
  });

  it("empty menu returns frozen empty array", () => {
    const items = getContextMenuItemsByMenu("sentinel");
    expect(items).toEqual([]);
    expect(Object.isFrozen(items)).toBe(true);
  });

  it("getContextMenuItems returns all items across all menus", () => {
    disposers.push(
      registerContextMenuItem(makeItem({ id: "p.a", menu: "editor" })),
    );
    disposers.push(
      registerContextMenuItem(makeItem({ id: "p.b", menu: "tab" })),
    );

    const all = getContextMenuItems();
    expect(all).toHaveLength(2);
    const ids = all.map((i) => i.id).sort();
    expect(ids).toEqual(["p.a", "p.b"]);
  });
});

// ---------------------------------------------------------------------------
// When-clause evaluator tests
// ---------------------------------------------------------------------------

describe("evaluateWhenClause", () => {
  it("undefined returns true", () => {
    expect(evaluateWhenClause(undefined, {})).toBe(true);
  });

  it("empty string returns true", () => {
    expect(evaluateWhenClause("", {})).toBe(true);
  });

  it("simple key existence - truthy", () => {
    expect(evaluateWhenClause("editorFocused", { editorFocused: true })).toBe(true);
  });

  it("simple key existence - falsy returns false", () => {
    expect(evaluateWhenClause("editorFocused", { editorFocused: false })).toBe(false);
  });

  it("simple key existence - missing key returns false", () => {
    expect(evaluateWhenClause("editorFocused", {})).toBe(false);
  });

  it("negation - !key with falsy value returns true", () => {
    expect(evaluateWhenClause("!editorReadOnly", { editorReadOnly: false })).toBe(true);
  });

  it("negation - !key with truthy value returns false", () => {
    expect(evaluateWhenClause("!editorReadOnly", { editorReadOnly: true })).toBe(false);
  });

  it("negation - !key with missing key returns true", () => {
    expect(evaluateWhenClause("!editorReadOnly", {})).toBe(true);
  });

  it("equality - matching value returns true", () => {
    expect(
      evaluateWhenClause("fileType == 'policy'", { fileType: "policy" }),
    ).toBe(true);
  });

  it("equality - non-matching value returns false", () => {
    expect(
      evaluateWhenClause("fileType == 'policy'", { fileType: "yara" }),
    ).toBe(false);
  });

  it("equality - double-quoted value", () => {
    expect(
      evaluateWhenClause('fileType == "policy"', { fileType: "policy" }),
    ).toBe(true);
  });

  it("inequality - different value returns true", () => {
    expect(
      evaluateWhenClause("fileType != 'yara'", { fileType: "policy" }),
    ).toBe(true);
  });

  it("inequality - same value returns false", () => {
    expect(
      evaluateWhenClause("fileType != 'yara'", { fileType: "yara" }),
    ).toBe(false);
  });

  it("AND - both clauses true returns true", () => {
    expect(
      evaluateWhenClause("editorFocused && fileType == 'policy'", {
        editorFocused: true,
        fileType: "policy",
      }),
    ).toBe(true);
  });

  it("AND - one clause false returns false", () => {
    expect(
      evaluateWhenClause("editorFocused && fileType == 'policy'", {
        editorFocused: false,
        fileType: "policy",
      }),
    ).toBe(false);
  });

  it("AND - multiple clauses all true", () => {
    expect(
      evaluateWhenClause("editorFocused && !readOnly && fileType == 'policy'", {
        editorFocused: true,
        readOnly: false,
        fileType: "policy",
      }),
    ).toBe(true);
  });
});
