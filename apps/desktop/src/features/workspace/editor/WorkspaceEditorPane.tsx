import { clsx } from "clsx";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { WORKSPACE_SAVE_ACTIVE_FILE_EVENT } from "@/features/workspace/shell/workspaceCommands";
import type { WorkspaceFile } from "@/services/workspace";
import {
  loadWorkspaceEditorFile,
  saveWorkspaceEditorFile,
  type WorkspaceEditorSaveResult,
} from "./workspaceEditorFileAccess";
import {
  applyWorkspaceEditorBufferLoad,
  beginWorkspaceEditorBufferLoad,
  beginWorkspaceEditorBufferSave,
  completeWorkspaceEditorBufferSave,
  createWorkspaceEditorState,
  ensureWorkspaceEditorBuffer,
  failWorkspaceEditorBufferLoad,
  failWorkspaceEditorBufferSave,
  getWorkspaceEditorBuffer,
  getWorkspaceEditorBufferKey,
  isWorkspaceEditorBufferDirty,
  updateWorkspaceEditorBufferDraft,
} from "./workspaceEditorState";

export interface WorkspaceEditorPaneProps {
  rootId?: string;
  activeFilePath?: string;
  activeTabTitle?: string;
  loadFile?: (rootId: string, relativePath: string) => Promise<WorkspaceFile>;
  saveFile?: (
    rootId: string,
    relativePath: string,
    contents: string,
  ) => Promise<WorkspaceEditorSaveResult>;
  onDirtyStateChange?: (rootId: string, relativePath: string, isDirty: boolean) => void;
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Workspace editor request failed";
}

export function WorkspaceEditorPane({
  rootId,
  activeFilePath,
  activeTabTitle,
  loadFile = loadWorkspaceEditorFile,
  saveFile = saveWorkspaceEditorFile,
  onDirtyStateChange,
}: WorkspaceEditorPaneProps) {
  const [state, setState] = useState(() => createWorkspaceEditorState());
  const dirtyStateRef = useRef<Record<string, boolean>>({});

  const activeBuffer = useMemo(
    () => getWorkspaceEditorBuffer(state, rootId, activeFilePath),
    [activeFilePath, rootId, state],
  );
  const isDirty = isWorkspaceEditorBufferDirty(activeBuffer);

  useEffect(() => {
    if (!rootId || !activeFilePath) {
      return;
    }

    setState((current) =>
      ensureWorkspaceEditorBuffer(current, {
        rootId,
        relativePath: activeFilePath,
        title:
          activeTabTitle ??
          activeFilePath.split("/").filter(Boolean).slice(-1)[0] ??
          activeFilePath,
      }),
    );
  }, [activeFilePath, activeTabTitle, rootId]);

  const loadActiveBuffer = useCallback(async () => {
    if (!rootId || !activeFilePath) {
      return;
    }

    setState((current) => beginWorkspaceEditorBufferLoad(current, rootId, activeFilePath));

    try {
      const file = await loadFile(rootId, activeFilePath);
      setState((current) =>
        applyWorkspaceEditorBufferLoad(current, {
          rootId,
          relativePath: activeFilePath,
          contents: file.contents,
          modifiedAt: file.modifiedAt,
        }),
      );
    } catch (error) {
      setState((current) =>
        failWorkspaceEditorBufferLoad(current, {
          rootId,
          relativePath: activeFilePath,
          errorMessage: toErrorMessage(error),
        }),
      );
    }
  }, [activeFilePath, loadFile, rootId]);

  useEffect(() => {
    if (!rootId || !activeFilePath) {
      return;
    }

    if (activeBuffer?.loaded || activeBuffer?.status === "loading") {
      return;
    }

    void loadActiveBuffer();
  }, [activeBuffer?.loaded, activeBuffer?.status, activeFilePath, loadActiveBuffer, rootId]);

  const saveActiveBuffer = useCallback(async () => {
    if (!rootId || !activeFilePath || !activeBuffer || !isWorkspaceEditorBufferDirty(activeBuffer)) {
      return;
    }

    const draftContents = activeBuffer.draftContents;
    setState((current) => beginWorkspaceEditorBufferSave(current, rootId, activeFilePath));

    try {
      const result = await saveFile(rootId, activeFilePath, draftContents);
      setState((current) =>
        completeWorkspaceEditorBufferSave(current, {
          rootId,
          relativePath: activeFilePath,
          contents: draftContents,
          modifiedAt: result.modifiedAt,
        }),
      );
    } catch (error) {
      setState((current) =>
        failWorkspaceEditorBufferSave(current, {
          rootId,
          relativePath: activeFilePath,
          errorMessage: toErrorMessage(error),
        }),
      );
    }
  }, [activeBuffer, activeFilePath, rootId, saveFile]);

  const reloadActiveBuffer = useCallback(async () => {
    if (!rootId || !activeFilePath || !activeBuffer) {
      return;
    }

    if (isWorkspaceEditorBufferDirty(activeBuffer)) {
      const shouldDiscard = window.confirm("Discard unsaved workspace edits and reload from disk?");
      if (!shouldDiscard) {
        return;
      }
    }

    await loadActiveBuffer();
  }, [activeBuffer, activeFilePath, loadActiveBuffer, rootId]);

  useEffect(() => {
    const handleSaveEvent = () => {
      void saveActiveBuffer();
    };

    window.addEventListener(WORKSPACE_SAVE_ACTIVE_FILE_EVENT, handleSaveEvent);
    return () => {
      window.removeEventListener(WORKSPACE_SAVE_ACTIVE_FILE_EVENT, handleSaveEvent);
    };
  }, [saveActiveBuffer]);

  useEffect(() => {
    if (!onDirtyStateChange) {
      return;
    }

    const nextDirtyState = Object.fromEntries(
      Object.values(state.buffers).map((buffer) => [buffer.key, isWorkspaceEditorBufferDirty(buffer)]),
    );

    for (const buffer of Object.values(state.buffers)) {
      const nextDirty = nextDirtyState[buffer.key] ?? false;
      if (dirtyStateRef.current[buffer.key] !== nextDirty) {
        onDirtyStateChange(buffer.rootId, buffer.relativePath, nextDirty);
      }
    }

    for (const key of Object.keys(dirtyStateRef.current)) {
      if (!(key in nextDirtyState)) {
        const [bufferRootId, ...pathParts] = key.split("::");
        onDirtyStateChange(bufferRootId ?? "", pathParts.join("::"), false);
      }
    }

    dirtyStateRef.current = nextDirtyState;
  }, [onDirtyStateChange, state.buffers]);

  const handleDraftChange = useCallback(
    (nextContents: string) => {
      if (!rootId || !activeFilePath) {
        return;
      }

      setState((current) =>
        updateWorkspaceEditorBufferDraft(current, {
          rootId,
          relativePath: activeFilePath,
          contents: nextContents,
        }),
      );
    },
    [activeFilePath, rootId],
  );

  const handleEditorKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        void saveActiveBuffer();
      }
    },
    [saveActiveBuffer],
  );

  if (!rootId || !activeFilePath) {
    return <WorkspaceEditorPlaceholder title="No file selected" description="Select a file from the trusted workspace tree to start editing." />;
  }

  const bufferKey = getWorkspaceEditorBufferKey(rootId, activeFilePath);
  const statusLabel =
    activeBuffer?.status === "loading"
      ? "Loading"
      : activeBuffer?.status === "saving"
        ? "Saving"
        : activeBuffer?.status === "error"
          ? "Attention"
          : isDirty
            ? "Dirty"
            : "Saved";

  return (
    <div className="flex h-full flex-col gap-3" data-testid="workspace-editor-pane">
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
        <div>
          <div className="font-medium text-sdr-text-primary">{activeBuffer?.title ?? activeTabTitle ?? "Workspace editor"}</div>
          <div className="text-xs text-sdr-text-muted">{activeFilePath}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div
            className={clsx(
              "rounded-full border px-2 py-1 text-[11px] uppercase tracking-[0.12em]",
              activeBuffer?.status === "error"
                ? "border-red-500/40 text-red-200"
                : isDirty
                  ? "border-[color:rgba(213,173,87,0.8)] text-[color:rgba(238,220,166,0.96)]"
                  : "border-sdr-border text-sdr-text-muted",
            )}
            data-testid="workspace-editor-status"
          >
            {statusLabel}
          </div>
          <button
            type="button"
            onClick={() => void reloadActiveBuffer()}
            className="rounded-full border border-sdr-border px-3 py-1.5 text-xs text-sdr-text-muted hover:text-sdr-text-primary"
            data-testid="workspace-editor-reload"
          >
            Reload
          </button>
          <button
            type="button"
            disabled={!isDirty || activeBuffer?.status === "saving"}
            onClick={() => void saveActiveBuffer()}
            className={clsx(
              "rounded-full border px-3 py-1.5 text-xs",
              !isDirty || activeBuffer?.status === "saving"
                ? "border-sdr-border text-sdr-text-muted/60"
                : "border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] text-sdr-text-primary",
            )}
            data-testid="workspace-editor-save"
          >
            Save
          </button>
        </div>
      </div>

      {activeBuffer?.status === "error" ? (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-100" data-testid="workspace-editor-error">
          <div className="font-medium">Workspace editor could not load this file.</div>
          <div className="mt-1 text-xs text-red-100/80">{activeBuffer.errorMessage ?? "Unknown workspace editor failure"}</div>
        </div>
      ) : null}

      <textarea
        key={bufferKey}
        value={activeBuffer?.draftContents ?? ""}
        onChange={(event) => handleDraftChange(event.target.value)}
        onKeyDown={handleEditorKeyDown}
        spellCheck={false}
        className="min-h-0 flex-1 resize-none rounded-xl border border-sdr-border bg-[rgba(4,7,14,0.84)] p-4 font-mono text-xs leading-6 text-[color:rgba(214,224,255,0.92)] outline-none focus:border-[color:rgba(213,173,87,0.8)]"
        data-testid="workspace-editor-textarea"
      />

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-sdr-text-muted">
        <div>{isDirty ? "Unsaved changes are buffered locally for this tab." : "Buffer matches the latest saved workspace contents."}</div>
        <div>{activeBuffer?.modifiedAt ? `Last synced ${activeBuffer.modifiedAt}` : "Awaiting initial file load"}</div>
      </div>
    </div>
  );
}

function WorkspaceEditorPlaceholder({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-sdr-border bg-sdr-bg-primary/20 p-6 text-center">
      <div className="max-w-md space-y-2">
        <div className="text-sm font-medium text-sdr-text-primary">{title}</div>
        <div className="text-xs text-sdr-text-muted">{description}</div>
      </div>
    </div>
  );
}
