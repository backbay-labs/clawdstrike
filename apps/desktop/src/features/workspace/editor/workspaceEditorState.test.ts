import { describe, expect, it } from "vitest";
import {
  applyWorkspaceEditorBufferLoad,
  beginWorkspaceEditorBufferSave,
  completeWorkspaceEditorBufferSave,
  createWorkspaceEditorState,
  ensureWorkspaceEditorBuffer,
  getWorkspaceEditorBuffer,
  isWorkspaceEditorBufferDirty,
  updateWorkspaceEditorBufferDraft,
} from "./workspaceEditorState";

describe("workspaceEditorState", () => {
  it("tracks draft changes and save completion for a workspace buffer", () => {
    const hydrated = applyWorkspaceEditorBufferLoad(
      ensureWorkspaceEditorBuffer(createWorkspaceEditorState(), {
        rootId: "root-1",
        relativePath: "briefs/hunt-plan.md",
        title: "hunt-plan.md",
      }),
      {
        rootId: "root-1",
        relativePath: "briefs/hunt-plan.md",
        contents: "alpha",
      },
    );

    const dirty = updateWorkspaceEditorBufferDraft(hydrated, {
      rootId: "root-1",
      relativePath: "briefs/hunt-plan.md",
      contents: "alpha\nbeta",
    });

    const saving = beginWorkspaceEditorBufferSave(dirty, "root-1", "briefs/hunt-plan.md");
    const saved = completeWorkspaceEditorBufferSave(saving, {
      rootId: "root-1",
      relativePath: "briefs/hunt-plan.md",
      contents: "alpha\nbeta",
      modifiedAt: "2026-03-07T12:34:56.000Z",
    });

    const buffer = getWorkspaceEditorBuffer(saved, "root-1", "briefs/hunt-plan.md");
    expect(buffer?.status).toBe("ready");
    expect(buffer?.savedContents).toBe("alpha\nbeta");
    expect(isWorkspaceEditorBufferDirty(buffer)).toBe(false);
  });

  it("updates titles when a preview buffer becomes a real file tab", () => {
    const initial = ensureWorkspaceEditorBuffer(createWorkspaceEditorState(), {
      rootId: "root-1",
      relativePath: "README.md",
      title: "Preview",
    });

    const promoted = ensureWorkspaceEditorBuffer(initial, {
      rootId: "root-1",
      relativePath: "README.md",
      title: "README.md",
    });

    expect(getWorkspaceEditorBuffer(promoted, "root-1", "README.md")?.title).toBe("README.md");
    expect(promoted.order).toHaveLength(1);
  });

  it("preserves edits typed while a save is in flight", () => {
    const hydrated = applyWorkspaceEditorBufferLoad(
      ensureWorkspaceEditorBuffer(createWorkspaceEditorState(), {
        rootId: "root-1",
        relativePath: "briefs/hunt-plan.md",
        title: "hunt-plan.md",
      }),
      {
        rootId: "root-1",
        relativePath: "briefs/hunt-plan.md",
        contents: "alpha",
      },
    );

    const dirty = updateWorkspaceEditorBufferDraft(hydrated, {
      rootId: "root-1",
      relativePath: "briefs/hunt-plan.md",
      contents: "alpha\nbeta",
    });
    const saving = beginWorkspaceEditorBufferSave(dirty, "root-1", "briefs/hunt-plan.md");
    const editedDuringSave = updateWorkspaceEditorBufferDraft(saving, {
      rootId: "root-1",
      relativePath: "briefs/hunt-plan.md",
      contents: "alpha\nbeta\ngamma",
    });
    const saved = completeWorkspaceEditorBufferSave(editedDuringSave, {
      rootId: "root-1",
      relativePath: "briefs/hunt-plan.md",
      contents: "alpha\nbeta",
      modifiedAt: "2026-03-07T12:34:56.000Z",
    });

    const buffer = getWorkspaceEditorBuffer(saved, "root-1", "briefs/hunt-plan.md");
    expect(buffer?.savedContents).toBe("alpha\nbeta");
    expect(buffer?.draftContents).toBe("alpha\nbeta\ngamma");
    expect(isWorkspaceEditorBufferDirty(buffer)).toBe(true);
  });
});
