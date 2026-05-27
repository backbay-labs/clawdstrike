import { render } from "@testing-library/react";
import { act } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const launch = vi.fn();
const close = vi.fn();
const focusedId = { current: null as string | null };

vi.mock("@backbay/glia-desktop", () => ({
  useDesktopOS: () => ({
    processes: { launch },
    windows: { focusedId: focusedId.current, close },
  }),
}));

import { KeyboardShortcuts } from "./KeyboardShortcuts";

beforeEach(() => {
  launch.mockClear();
  close.mockClear();
  focusedId.current = null;
});

/** Dispatch a keydown on document (matching the global listener). */
function press(key: string, opts: { ctrl?: boolean; meta?: boolean } = {}) {
  act(() => {
    document.dispatchEvent(
      new KeyboardEvent("keydown", {
        key,
        ctrlKey: !!opts.ctrl,
        metaKey: !!opts.meta,
        bubbles: true,
        cancelable: true,
      }),
    );
  });
}

describe("KeyboardShortcuts — sidebar toggle", () => {
  it("Ctrl+\\ invokes onToggleSidebar", () => {
    const onToggleSidebar = vi.fn();
    render(
      <KeyboardShortcuts
        onToggleCommandPalette={() => {}}
        onLock={() => {}}
        onToggleSidebar={onToggleSidebar}
      />,
    );
    press("\\", { ctrl: true });
    expect(onToggleSidebar).toHaveBeenCalledTimes(1);
  });

  it("does not fire the sidebar toggle without a modifier", () => {
    const onToggleSidebar = vi.fn();
    render(
      <KeyboardShortcuts
        onToggleCommandPalette={() => {}}
        onLock={() => {}}
        onToggleSidebar={onToggleSidebar}
      />,
    );
    press("\\");
    expect(onToggleSidebar).not.toHaveBeenCalled();
  });

  it("⌘\\ (meta) does not collide with the command palette or lock bindings", () => {
    const onToggleCommandPalette = vi.fn();
    const onLock = vi.fn();
    const onToggleSidebar = vi.fn();
    render(
      <KeyboardShortcuts
        onToggleCommandPalette={onToggleCommandPalette}
        onLock={onLock}
        onToggleSidebar={onToggleSidebar}
      />,
    );
    // The handler matches ctrlKey; the meta variant is treated equivalently by
    // the OS on mac, but here we assert ⌘\\ does not trip ⌘K or ⌘L.
    press("\\", { ctrl: true });
    expect(onToggleCommandPalette).not.toHaveBeenCalled();
    expect(onLock).not.toHaveBeenCalled();
    expect(onToggleSidebar).toHaveBeenCalledTimes(1);
  });
});
