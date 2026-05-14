/**
 * observatory-hotkeys.test.ts
 *
 * Unit tests for useObservatoryHotkeys hook.
 *
 * Phase 30 HUD-14/HUD-15: keyboard-driven panel control via E/R/M/G/Escape.
 *
 * Tests:
 *   a. pressing E calls togglePanel('explainability')
 *   b. pressing R calls togglePanel('replay')
 *   c. pressing M calls togglePanel('mission')
 *   d. pressing G calls togglePanel('ghost')
 *   e. pressing Escape calls closePanel()
 *   f. unrelated keys do not trigger any action
 *   g. hotkeys do not fire when enabled=false
 *   h. hotkeys do not fire when target is INPUT element
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useObservatoryHotkeys } from "../components/hud/useObservatoryHotkeys";
import { useObservatoryStore } from "../stores/observatory-store";

// Helper to dispatch a keydown event on window
function pressKey(key: string, target?: EventTarget) {
  const event = new KeyboardEvent("keydown", { key, bubbles: true });
  if (target) {
    Object.defineProperty(event, "target", { value: target, writable: false });
  }
  window.dispatchEvent(event);
}

describe("useObservatoryHotkeys", () => {
  let togglePanel: ReturnType<typeof vi.fn>;
  let closePanel: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    togglePanel = vi.fn();
    closePanel = vi.fn();

    // Patch the store actions used inside the hook
    const currentState = useObservatoryStore.getState();
    useObservatoryStore.setState({
      ...currentState,
      activePanel: null,
      actions: {
        ...currentState.actions,
        togglePanel: togglePanel as unknown as (id: import("../types").HudPanelId) => void,
        closePanel: closePanel as unknown as () => void,
      },
    });
  });

  it("a. pressing E calls togglePanel('explainability')", () => {
    renderHook(() => useObservatoryHotkeys(true));
    pressKey("e");
    expect(togglePanel).toHaveBeenCalledWith("explainability");
    expect(togglePanel).toHaveBeenCalledTimes(1);
  });

  it("b. pressing R calls togglePanel('replay')", () => {
    renderHook(() => useObservatoryHotkeys(true));
    pressKey("r");
    expect(togglePanel).toHaveBeenCalledWith("replay");
    expect(togglePanel).toHaveBeenCalledTimes(1);
  });

  it("c. pressing M calls togglePanel('mission')", () => {
    renderHook(() => useObservatoryHotkeys(true));
    pressKey("m");
    expect(togglePanel).toHaveBeenCalledWith("mission");
    expect(togglePanel).toHaveBeenCalledTimes(1);
  });

  it("d. pressing G calls togglePanel('ghost')", () => {
    renderHook(() => useObservatoryHotkeys(true));
    pressKey("g");
    expect(togglePanel).toHaveBeenCalledWith("ghost");
    expect(togglePanel).toHaveBeenCalledTimes(1);
  });

  it("e. pressing Escape calls closePanel()", () => {
    renderHook(() => useObservatoryHotkeys(true));
    pressKey("Escape");
    expect(closePanel).toHaveBeenCalledTimes(1);
    expect(togglePanel).not.toHaveBeenCalled();
  });

  it("f. unrelated keys do not trigger any action", () => {
    renderHook(() => useObservatoryHotkeys(true));
    pressKey("x");
    pressKey("z");
    pressKey("1");
    expect(togglePanel).not.toHaveBeenCalled();
    expect(closePanel).not.toHaveBeenCalled();
  });

  it("g. hotkeys do not fire when enabled=false", () => {
    renderHook(() => useObservatoryHotkeys(false));
    pressKey("e");
    pressKey("Escape");
    expect(togglePanel).not.toHaveBeenCalled();
    expect(closePanel).not.toHaveBeenCalled();
  });

  it("h. hotkeys do not fire when target is INPUT element", () => {
    renderHook(() => useObservatoryHotkeys(true));

    // Create a real input element so tagName === "INPUT"
    const input = document.createElement("input");
    document.body.appendChild(input);

    const event = new KeyboardEvent("keydown", { key: "e", bubbles: true });
    Object.defineProperty(event, "target", { value: input, writable: false });
    window.dispatchEvent(event);

    expect(togglePanel).not.toHaveBeenCalled();
    expect(closePanel).not.toHaveBeenCalled();

    document.body.removeChild(input);
  });
});
