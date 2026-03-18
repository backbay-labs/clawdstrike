// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createInitialHuntStore } from "../huntTypes";
import type { SpiritBindContext } from "../spirit-bind/types";
vi.mock("./canvas", () => ({
  SpiritManifestationCanvas: () => (
    <div data-testid="spirit-manifestation-canvas" />
  ),
  buildSpiritManifestationModel: () => ({
    accentColor: "#d4a84b",
    fieldPercent: 62,
    release: {
      actionLabel: "Release into the workspace",
      title: "Release",
      subtitle: "Set the field.",
      targetLabel: "dock, sidebar, and river",
      durationMs: 1800,
      tetherStrength: 0.6,
      pulseScale: 1,
    },
  }),
}));
vi.mock("./atmosphere", () => ({
  SpiritAtmosphereLayer: () => <div data-testid="spirit-atmosphere-layer" />,
}));
vi.mock("../spirit-bind/preview", () => ({
  buildSpiritBindPreviewModel: () => ({
    dock: {
      label: "Loom",
      accentColor: "#d4a84b",
      contour: "reticle-vector",
      detail: "Tracks scopes and crossings.",
    },
    sidebar: {
      wakeTitle: "Loom wake",
      wakeReason: "Suggested because this hunt is graph-heavy.",
      biasLine: "Biases Scopes and History.",
    },
    workspace: {
      title: "Loom field",
      stance: "attune",
      fieldStrength: 0.62,
      motionLabel: "Field steadies around the main read.",
    },
  }),
}));
import { SpiritCreationChamber } from "./SpiritCreationChamber";

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

describe("SpiritCreationChamber", () => {
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

  it("preserves quick configure as a one-click bind path", async () => {
    const onBind = vi.fn();

    await act(async () => {
      root.render(
        <SpiritCreationChamber
          context={buildContext()}
          isOpen
          onBind={onBind}
          onDismiss={vi.fn()}
          onSkip={vi.fn()}
        />,
      );
    });

    expect(container.querySelector('[data-testid="spirit-bind-active-control-quick-configure"]')).toBeTruthy();
    expect(container.textContent).toContain("Spirit");
    expect(container.querySelector('[data-testid="spirit-bind-mode-rail"]')).toBeTruthy();
    expect(container.textContent).toContain("Keep current");
    expect(container.textContent).toContain("Close");
    expect(container.textContent).not.toContain("Other readings");

    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement).click();
    });

    expect(onBind).toHaveBeenCalledTimes(1);
    expect(onBind.mock.calls[0][0].bindSource).toBe("quick-configure");
  });

  it("keeps thesis mode thresholded before release", async () => {
    const onBind = vi.fn();

    await act(async () => {
      root.render(
        <SpiritCreationChamber
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

    expect(container.querySelector('[data-testid="spirit-bind-active-control-thesis"]')).toBeTruthy();
    const submit = container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement;
    const textarea = container.querySelector('[data-testid="spirit-bind-thesis-input"]') as HTMLTextAreaElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      valueSetter.call(textarea, "");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
      textarea.dispatchEvent(new Event("change", { bubbles: true }));
    });

    expect(submit.disabled).toBe(true);

    await act(async () => {
      valueSetter.call(textarea, "Trace lateral movement through the sandbox execution chain");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
      textarea.dispatchEvent(new Event("change", { bubbles: true }));
    });

    expect(submit.disabled).toBe(false);

    const firstSuggestionApply = container.querySelector(
      '[data-testid^="ritual-suggestion-apply-"]',
    ) as HTMLButtonElement | null;
    expect(firstSuggestionApply).toBeTruthy();

    await act(async () => {
      firstSuggestionApply?.click();
    });

    expect(textarea.value.length).toBeGreaterThan(
      "Trace lateral movement through the sandbox execution chain".length,
    );

    await act(async () => {
      submit.click();
    });

    expect(onBind).toHaveBeenCalledTimes(1);
    expect(onBind.mock.calls[0][0]).toMatchObject({
      bindSource: "thesis",
    });
    expect(onBind.mock.calls[0][0].thesis).toContain(
      "Trace lateral movement through the sandbox execution chain",
    );
  });

  it("supports keyboard mode switching through the chamber rail", async () => {
    await act(async () => {
      root.render(
        <SpiritCreationChamber
          context={buildContext()}
          isOpen
          onBind={vi.fn()}
          onDismiss={vi.fn()}
          onSkip={vi.fn()}
        />,
      );
    });

    const quick = container.querySelector('[data-testid="spirit-bind-mode-quick-configure"]') as HTMLButtonElement;
    quick.focus();
    expect(document.activeElement).toBe(quick);

    await act(async () => {
      quick.dispatchEvent(
        new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }),
      );
    });

    const thesisPanel = container.querySelector('[data-testid="spirit-bind-active-control-thesis"]');
    expect(thesisPanel).toBeTruthy();
    expect(document.activeElement).toBe(
      container.querySelector('[data-testid="spirit-bind-mode-thesis"]'),
    );
  });

  it("keeps manual reconfiguration and pinning reachable", async () => {
    const onBind = vi.fn();

    await act(async () => {
      root.render(
        <SpiritCreationChamber
          context={buildContext()}
          isOpen
          onBind={onBind}
          onDismiss={vi.fn()}
          onSkip={vi.fn()}
        />,
      );
    });

    await act(async () => {
      (container.querySelector('[data-testid="spirit-bind-mode-manual"]') as HTMLButtonElement).click();
    });

    expect(container.querySelector('[data-testid="spirit-bind-active-control-manual"]')).toBeTruthy();
    const manualLedger = container.querySelector('[data-testid="spirit-bind-manual-ledger"]') as HTMLButtonElement;
    const pinToggle = container.querySelector('[data-testid="spirit-bind-pin-toggle"]') as HTMLButtonElement;
    const submit = container.querySelector('[data-testid="spirit-bind-submit"]') as HTMLButtonElement;

    await act(async () => {
      manualLedger.click();
    });

    await act(async () => {
      pinToggle.click();
    });

    await act(async () => {
      submit.click();
    });

    expect(onBind).toHaveBeenCalledTimes(1);
    expect(onBind.mock.calls[0][0]).toMatchObject({
      bindSource: "manual",
      kind: "ledger",
      isPinned: true,
    });
  });
});
