// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type ShellShortcutHandlers, useShellShortcuts } from "./useShellShortcuts";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

function ShortcutHarness({ handlers }: { handlers: ShellShortcutHandlers }) {
  useShellShortcuts(handlers);
  return null;
}

describe("useShellShortcuts", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    container.remove();
    vi.restoreAllMocks();
  });

  it("does not intercept workbench-only shortcuts outside workbench mode", async () => {
    const onCloseTab = vi.fn();

    await act(async () => {
      root.render(<ShortcutHarness handlers={{ onCloseTab }} />);
    });

    const event = new KeyboardEvent("keydown", {
      key: "w",
      metaKey: true,
      bubbles: true,
      cancelable: true,
    });

    window.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(false);
    expect(onCloseTab).not.toHaveBeenCalled();
  });

  it("intercepts workbench-only shortcuts when workbench handlers are active", async () => {
    const onCloseTab = vi.fn();

    await act(async () => {
      root.render(<ShortcutHarness handlers={{ isWorkbench: true, onCloseTab }} />);
    });

    const event = new KeyboardEvent("keydown", {
      key: "w",
      metaKey: true,
      bubbles: true,
      cancelable: true,
    });

    window.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(onCloseTab).toHaveBeenCalledTimes(1);
  });
});
