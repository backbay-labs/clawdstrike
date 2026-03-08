// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createInitialHuntStore } from "../huntTypes";
import { SpiritBindSheet } from "./SpiritBindSheet";
import type { SpiritBindContext } from "./types";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

function buildContext(): SpiritBindContext {
  const store = createInitialHuntStore();
  return {
    hunt: store.hunts.hunt_demo_1,
    artifacts: store.artifacts,
    runs: store.runs,
    currentLens: "files",
    currentShell: "hunt",
    activeStationId: "river",
  };
}

describe("SpiritBindSheet", () => {
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

  it("starts in quick bind and commits a one-click bind", async () => {
    const onBind = vi.fn();

    await act(async () => {
      root.render(
        <SpiritBindSheet
          context={buildContext()}
          isOpen
          onBind={onBind}
          onDismiss={vi.fn()}
          onSkip={vi.fn()}
        />,
      );
    });

    expect(container.querySelector('[data-testid="spirit-bind-quick-panel"]')).toBeTruthy();

    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement).click();
    });

    expect(onBind).toHaveBeenCalledTimes(1);
    expect(onBind.mock.calls[0][0].bindSource).toBe("quick-bind");
    expect(onBind.mock.calls[0][0].anchorArtifactIds.length).toBeGreaterThan(0);
  });

  it("gates thesis mode until the operator provides enough signal", async () => {
    const onBind = vi.fn();

    await act(async () => {
      root.render(
        <SpiritBindSheet
          context={buildContext()}
          isOpen
          onBind={onBind}
          onDismiss={vi.fn()}
          onSkip={vi.fn()}
        />,
      );
    });

    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-mode-thesis"]') as HTMLButtonElement).click();
    });

    const submit = container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement;
    await act(async () => {
      submit.click();
    });
    expect(onBind).not.toHaveBeenCalled();

    const textarea = container.querySelector('[data-testid="spirit-bind-thesis-input"]') as HTMLTextAreaElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      valueSetter.call(textarea, "Trace lateral movement through the sandbox execution chain");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
      textarea.dispatchEvent(new Event("change", { bubbles: true }));
    });

    await act(async () => {
      submit.click();
    });

    expect(onBind).toHaveBeenCalledTimes(1);
    expect(onBind.mock.calls[0][0].bindSource).toBe("thesis");
    expect(onBind.mock.calls[0][0].thesis).toContain("sandbox execution chain");
  });

  it("limits anchor selection to three artifacts in the bind payload", async () => {
    const onBind = vi.fn();

    await act(async () => {
      root.render(
        <SpiritBindSheet
          context={buildContext()}
          isOpen
          onBind={onBind}
          onDismiss={vi.fn()}
          onSkip={vi.fn()}
        />,
      );
    });

    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-mode-anchor-artifacts"]') as HTMLButtonElement).click();
    });

    const buttons = Array.from(container.querySelectorAll('[data-testid^="spirit-bind-anchor-"]')) as HTMLButtonElement[];
    expect(buttons.length).toBeGreaterThan(3);

    await act(async () => {
      buttons[0].click();
    });
    await act(async () => {
      buttons[1].click();
    });
    await act(async () => {
      buttons[2].click();
    });
    await act(async () => {
      buttons[3].click();
    });
    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement).click();
    });

    expect(onBind).toHaveBeenCalledTimes(1);
    expect(onBind.mock.calls[0][0].anchorArtifactIds).toHaveLength(3);
    expect(onBind.mock.calls[0][0].anchorArtifactIds).not.toContain("art_demo_6");
  });

  it("routes skip and dismiss affordances without forcing bind", async () => {
    const onSkip = vi.fn();
    const onDismiss = vi.fn();

    await act(async () => {
      root.render(
        <SpiritBindSheet
          context={buildContext()}
          isOpen
          onBind={vi.fn()}
          onDismiss={onDismiss}
          onSkip={onSkip}
        />,
      );
    });

    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-skip"]') as HTMLButtonElement).click();
      (container.querySelector('[data-testid="spirit-bind-dismiss"]') as HTMLButtonElement).click();
    });

    expect(onSkip).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});
