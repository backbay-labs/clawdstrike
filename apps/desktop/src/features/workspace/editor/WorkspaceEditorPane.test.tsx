// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WORKSPACE_SAVE_ACTIVE_FILE_EVENT } from "@/features/workspace/shell/workspaceCommands";
import { WorkspaceEditorPane } from "./WorkspaceEditorPane";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

async function flushEffects() {
  await act(async () => {
    await Promise.resolve();
  });
}

describe("WorkspaceEditorPane", () => {
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

  it("loads a file, tracks dirty state, and saves through the active buffer", async () => {
    const saveFile = vi.fn(async () => ({ modifiedAt: "2026-03-07T12:05:00.000Z" }));
    const onDirtyStateChange = vi.fn();

    await act(async () => {
      root.render(
        <WorkspaceEditorPane
          rootId="root-1"
          activeFilePath="briefs/hunt-plan.md"
          activeTabTitle="hunt-plan.md"
          loadFile={async () => ({
            rootId: "root-1",
            relativePath: "briefs/hunt-plan.md",
            contents: "alpha",
          })}
          saveFile={saveFile}
          onDirtyStateChange={onDirtyStateChange}
        />,
      );
    });

    await flushEffects();

    const textarea = container.querySelector('[data-testid="workspace-editor-textarea"]') as HTMLTextAreaElement;
    expect(textarea.value).toBe("alpha");

    const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      valueSetter.call(textarea, "alpha\nbeta");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    });

    expect(onDirtyStateChange).toHaveBeenLastCalledWith("root-1", "briefs/hunt-plan.md", true);
    expect(container.querySelector('[data-testid="workspace-editor-status"]')?.textContent).toContain("Dirty");

    await act(async () => {
      (container.querySelector('[data-testid="workspace-editor-save"]') as HTMLButtonElement).click();
    });

    expect(saveFile).toHaveBeenCalledWith("root-1", "briefs/hunt-plan.md", "alpha\nbeta");
    expect(onDirtyStateChange).toHaveBeenLastCalledWith("root-1", "briefs/hunt-plan.md", false);
  });

  it("uses the global workspace save event for the active file", async () => {
    const saveFile = vi.fn(async () => ({ modifiedAt: "2026-03-07T12:15:00.000Z" }));

    await act(async () => {
      root.render(
        <WorkspaceEditorPane
          rootId="root-1"
          activeFilePath="README.md"
          activeTabTitle="README.md"
          loadFile={async () => ({
            rootId: "root-1",
            relativePath: "README.md",
            contents: "hello",
          })}
          saveFile={saveFile}
        />,
      );
    });

    await flushEffects();

    const textarea = container.querySelector('[data-testid="workspace-editor-textarea"]') as HTMLTextAreaElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      valueSetter.call(textarea, "hello world");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await act(async () => {
      window.dispatchEvent(new Event(WORKSPACE_SAVE_ACTIVE_FILE_EVENT));
    });

    expect(saveFile).toHaveBeenCalledWith("root-1", "README.md", "hello world");
  });

  it("guards reload when the active buffer is dirty", async () => {
    const loadFile = vi
      .fn<() => Promise<{ rootId: string; relativePath: string; contents: string }>>()
      .mockResolvedValueOnce({
        rootId: "root-1",
        relativePath: "README.md",
        contents: "first",
      })
      .mockResolvedValueOnce({
        rootId: "root-1",
        relativePath: "README.md",
        contents: "second",
      });

    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);

    await act(async () => {
      root.render(
        <WorkspaceEditorPane
          rootId="root-1"
          activeFilePath="README.md"
          activeTabTitle="README.md"
          loadFile={loadFile}
        />,
      );
    });

    await flushEffects();

    const textarea = container.querySelector('[data-testid="workspace-editor-textarea"]') as HTMLTextAreaElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    if (!valueSetter) throw new Error("Missing textarea value setter");

    await act(async () => {
      valueSetter.call(textarea, "locally dirty");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
    });

    await act(async () => {
      (container.querySelector('[data-testid="workspace-editor-reload"]') as HTMLButtonElement).click();
    });

    expect(confirmSpy).toHaveBeenCalledOnce();
    expect(loadFile).toHaveBeenCalledTimes(1);

    confirmSpy.mockReturnValue(true);

    await act(async () => {
      (container.querySelector('[data-testid="workspace-editor-reload"]') as HTMLButtonElement).click();
    });

    await flushEffects();

    expect(loadFile).toHaveBeenCalledTimes(2);
    expect((container.querySelector('[data-testid="workspace-editor-textarea"]') as HTMLTextAreaElement).value).toBe("second");
  });
});
