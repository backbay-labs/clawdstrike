import { type WorkspaceFile, readWorkspaceFile } from "@/services/workspace";
import { isTauri } from "@/services/tauri";

export interface WorkspaceEditorSaveResult {
  modifiedAt?: string;
}

const mockSavedFiles = new Map<string, { contents: string; modifiedAt: string }>();

function getMockFileKey(rootId: string, relativePath: string): string {
  return `${rootId}::${relativePath}`;
}

export async function loadWorkspaceEditorFile(
  rootId: string,
  relativePath: string,
): Promise<WorkspaceFile> {
  const file = await readWorkspaceFile(rootId, relativePath);
  const override = mockSavedFiles.get(getMockFileKey(rootId, relativePath));

  if (!override) {
    return file;
  }

  return {
    ...file,
    contents: override.contents,
    modifiedAt: override.modifiedAt,
  };
}

export async function saveWorkspaceEditorFile(
  rootId: string,
  relativePath: string,
  contents: string,
): Promise<WorkspaceEditorSaveResult> {
  const modifiedAt = new Date().toISOString();

  if (!isTauri()) {
    mockSavedFiles.set(getMockFileKey(rootId, relativePath), {
      contents,
      modifiedAt,
    });
    return { modifiedAt };
  }

  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("workspace_write_file", { rootId, relativePath, contents });
  return { modifiedAt };
}

export function resetWorkspaceEditorMockFiles(): void {
  mockSavedFiles.clear();
}
