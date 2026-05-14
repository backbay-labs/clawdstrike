import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { createElement } from "react";
import { PluginContextMenuItems } from "../plugin-context-menu";
import {
  registerContextMenuItem,
  type ContextMenuItemRegistration,
  type ContextMenuTarget,
} from "@/lib/plugins/context-menu-registry";

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
// Tests
// ---------------------------------------------------------------------------

describe("PluginContextMenuItems", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("renders nothing when no plugin items registered for the menu", () => {
    const onExecuteCommand = vi.fn();
    const { container } = render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    expect(container.innerHTML).toBe("");
  });

  it("renders plugin items with correct labels", () => {
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.scan", label: "Run Scan", menu: "editor" }),
      ),
    );
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.analyze", label: "Analyze", menu: "editor" }),
      ),
    );

    const onExecuteCommand = vi.fn();
    render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    expect(screen.getByText("Run Scan")).toBeDefined();
    expect(screen.getByText("Analyze")).toBeDefined();
  });

  it("filters items by when-clause (item with failing when-clause hidden)", () => {
    disposers.push(
      registerContextMenuItem(
        makeItem({
          id: "p.visible",
          label: "Visible",
          menu: "editor",
          when: "editorFocused",
        }),
      ),
    );
    disposers.push(
      registerContextMenuItem(
        makeItem({
          id: "p.hidden",
          label: "Hidden",
          menu: "editor",
          when: "readOnlyMode",
        }),
      ),
    );

    const onExecuteCommand = vi.fn();
    render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: { editorFocused: true, readOnlyMode: false },
        onExecuteCommand,
      }),
    );

    expect(screen.getByText("Visible")).toBeDefined();
    expect(screen.queryByText("Hidden")).toBeNull();
  });

  it("clicking an item calls onExecuteCommand with correct command ID", () => {
    disposers.push(
      registerContextMenuItem(
        makeItem({
          id: "p.click-test",
          label: "Click Me",
          command: "test.clickCommand",
          menu: "editor",
        }),
      ),
    );

    const onExecuteCommand = vi.fn();
    render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    fireEvent.click(screen.getByText("Click Me"));
    expect(onExecuteCommand).toHaveBeenCalledWith("test.clickCommand");
    expect(onExecuteCommand).toHaveBeenCalledTimes(1);
  });

  it("renders separator before plugin items", () => {
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.sep-test", label: "Sep Test", menu: "editor" }),
      ),
    );

    const onExecuteCommand = vi.fn();
    render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    const separator = screen.getByRole("separator");
    expect(separator).toBeDefined();
  });

  it("multiple menus: items only appear in their target menu", () => {
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.editor-only", label: "Editor Only", menu: "editor" }),
      ),
    );
    disposers.push(
      registerContextMenuItem(
        makeItem({ id: "p.tab-only", label: "Tab Only", menu: "tab" }),
      ),
    );

    const onExecuteCommand = vi.fn();

    // Render for editor menu
    const { unmount } = render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    expect(screen.getByText("Editor Only")).toBeDefined();
    expect(screen.queryByText("Tab Only")).toBeNull();

    unmount();

    // Render for tab menu
    render(
      createElement(PluginContextMenuItems, {
        menu: "tab",
        context: {},
        onExecuteCommand,
      }),
    );

    expect(screen.getByText("Tab Only")).toBeDefined();
    expect(screen.queryByText("Editor Only")).toBeNull();
  });

  it("disposal removes items from rendered output", () => {
    const dispose = registerContextMenuItem(
      makeItem({ id: "p.disposable", label: "Disposable", menu: "editor" }),
    );

    const onExecuteCommand = vi.fn();
    const { rerender } = render(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    expect(screen.getByText("Disposable")).toBeDefined();

    // Dispose the item
    dispose();

    // Re-render to pick up state change
    rerender(
      createElement(PluginContextMenuItems, {
        menu: "editor",
        context: {},
        onExecuteCommand,
      }),
    );

    expect(screen.queryByText("Disposable")).toBeNull();
  });
});
