// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WorkspaceGitPanel } from "./WorkspaceGitPanel";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

async function flushEffects() {
  await act(async () => {
    await Promise.resolve();
  });
}

describe("WorkspaceGitPanel", () => {
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

  it("loads git status, switches diff previews, and deep-links changed files", async () => {
    const onOpenPath = vi.fn();
    const loadDiffSummary = vi
      .fn()
      .mockResolvedValueOnce({
        rootId: "root-1",
        relativePath: "briefs/hunt-plan.md",
        fileCount: 1,
        additions: 4,
        deletions: 1,
        previewLines: ["+ new plan line"],
      })
      .mockResolvedValueOnce({
        rootId: "root-1",
        relativePath: "README.md",
        fileCount: 1,
        additions: 2,
        deletions: 0,
        previewLines: ["+ readme update"],
      });

    await act(async () => {
      root.render(
        <WorkspaceGitPanel
          rootId="root-1"
          onOpenPath={onOpenPath}
          loadStatus={async () => ({
            rootId: "root-1",
            branch: "feature/ws6",
            ahead: 1,
            behind: 0,
            stagedCount: 1,
            unstagedCount: 1,
            untrackedCount: 0,
            changedFiles: [
              {
                rootId: "root-1",
                relativePath: "briefs/hunt-plan.md",
                stagedStatus: "M",
                unstagedStatus: " ",
                additions: 4,
                deletions: 1,
              },
              {
                rootId: "root-1",
                relativePath: "README.md",
                stagedStatus: " ",
                unstagedStatus: "M",
                additions: 2,
                deletions: 0,
              },
            ],
          })}
          loadDiffSummary={loadDiffSummary}
        />,
      );
    });

    await flushEffects();

    expect(container.textContent).toContain("feature/ws6");
    expect(container.querySelector('[data-testid="workspace-git-diff-preview"]')?.textContent).toContain(
      "+ new plan line",
    );

    await act(async () => {
      const buttons = container.querySelectorAll('[data-testid="workspace-git-panel"] button');
      (buttons[1] as HTMLButtonElement).click();
    });

    await flushEffects();

    expect(container.querySelector('[data-testid="workspace-git-diff-preview"]')?.textContent).toContain(
      "+ readme update",
    );

    await act(async () => {
      (container.querySelector('button[class*="rounded-full"][type="button"]') as HTMLButtonElement).click();
    });

    expect(onOpenPath).toHaveBeenCalledWith("README.md");
  });
});
