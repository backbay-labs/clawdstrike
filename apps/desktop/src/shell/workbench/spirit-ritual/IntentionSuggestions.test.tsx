// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IntentionSuggestions } from "./IntentionSuggestions";
import type { SpiritRitualSuggestion } from "./state/types";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

const SUGGESTIONS: SpiritRitualSuggestion[] = [{
  id: "context:prove-the-trail",
  label: "Prove the trail",
  detail: "Bias toward receipts and evidence.",
  promptFragment: "Build proof around the receipt trail",
  focusSurfaces: ["Receipts", "Evidence"],
  keywords: ["proof", "receipt"],
  sourceMode: "context",
  spiritKindHints: { lantern: 1 },
}];

describe("IntentionSuggestions", () => {
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

  it("renders suggestion chips and routes toggle/apply callbacks", async () => {
    const onToggleSuggestion = vi.fn();
    const onApplySuggestion = vi.fn();

    await act(async () => {
      root.render(
        <IntentionSuggestions
          suggestions={SUGGESTIONS}
          selectedSuggestionIds={[]}
          onToggleSuggestion={onToggleSuggestion}
          onApplySuggestion={onApplySuggestion}
        />,
      );
    });

    expect(container.textContent).toContain("Field lines");
    expect(container.textContent).toContain("Prove the trail");
    expect(container.textContent).toContain("Pulls toward Receipts · Evidence");
    expect(container.textContent).toContain("Use");

    await act(async () => {
      (container.querySelector('[data-testid="ritual-suggestion-toggle-context:prove-the-trail"]') as HTMLButtonElement).click();
      (container.querySelector('[data-testid="ritual-suggestion-apply-context:prove-the-trail"]') as HTMLButtonElement).click();
    });

    expect(onToggleSuggestion).toHaveBeenCalledWith("context:prove-the-trail");
    expect(onApplySuggestion).toHaveBeenCalledWith(SUGGESTIONS[0]);
  });
});
