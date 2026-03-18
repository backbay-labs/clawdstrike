// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WorkspaceSearchPanel } from "./WorkspaceSearchPanel";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

async function flushEffects() {
  await act(async () => {
    await Promise.resolve();
  });
}

describe("WorkspaceSearchPanel", () => {
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

  it("searches paths and deep-links matches into the editor", async () => {
    const onOpenResult = vi.fn();

    await act(async () => {
      root.render(
        <WorkspaceSearchPanel
          rootId="root-1"
          onOpenResult={onOpenResult}
          searchPaths={async () => [
            {
              rootId: "root-1",
              relativePath: "briefs/hunt-plan.md",
              name: "hunt-plan.md",
              kind: "file",
            },
          ]}
        />,
      );
    });

    const input = container.querySelector('[data-testid="workspace-search-input"]') as HTMLInputElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing input value setter");

    await act(async () => {
      valueSetter.call(input, "hunt");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await flushEffects();

    expect(container.querySelector('[data-testid="workspace-search-path-results"]')?.textContent).toContain(
      "briefs/hunt-plan.md",
    );

    await act(async () => {
      (container.querySelector('[data-testid="workspace-search-path-results"] button') as HTMLButtonElement).click();
    });

    expect(onOpenResult).toHaveBeenCalledWith({
      relativePath: "briefs/hunt-plan.md",
      mode: "paths",
    });
  });

  it("searches content and preserves line deep-link metadata", async () => {
    const onOpenResult = vi.fn();

    await act(async () => {
      root.render(
        <WorkspaceSearchPanel
          rootId="root-1"
          initialMode="content"
          onOpenResult={onOpenResult}
          searchContent={async () => [
            {
              rootId: "root-1",
              relativePath: "README.md",
              lineNumber: 8,
              column: 4,
              lineText: "workspace summary",
              preview: "README.md:8 workspace summary",
            },
          ]}
        />,
      );
    });

    const input = container.querySelector('[data-testid="workspace-search-input"]') as HTMLInputElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing input value setter");

    await act(async () => {
      valueSetter.call(input, "summary");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await flushEffects();

    expect(container.querySelector('[data-testid="workspace-search-content-results"]')?.textContent).toContain(
      "README.md",
    );

    await act(async () => {
      (container.querySelector('[data-testid="workspace-search-content-results"] button') as HTMLButtonElement).click();
    });

    expect(onOpenResult).toHaveBeenCalledWith({
      relativePath: "README.md",
      lineNumber: 8,
      column: 4,
      mode: "content",
    });
  });
});
