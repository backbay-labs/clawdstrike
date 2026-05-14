import type { FileType } from "@/lib/workbench/file-type-registry";

type Awaitable<T> = T | Promise<T>;

export interface WorkbenchE2EOpenFileResult {
  content: string;
  path: string;
  fileType: FileType;
}

export interface WorkbenchE2EDirEntry {
  name: string;
  isDirectory: boolean;
}

export interface WorkbenchE2EBridge {
  invoke?: <T = unknown>(cmd: string, args?: Record<string, unknown>) => Awaitable<T>;
  openDetectionFile?: () => Awaitable<WorkbenchE2EOpenFileResult | null>;
  readDetectionFileByPath?: (filePath: string) => Awaitable<WorkbenchE2EOpenFileResult | null>;
  readDetectionDir?: (dirPath: string) => Awaitable<WorkbenchE2EDirEntry[]>;
  saveDetectionFile?: (
    content: string,
    fileType: FileType,
    filePath?: string | null,
    suggestedName?: string,
  ) => Awaitable<string | null>;
  createDetectionFile?: (
    dirPath: string,
    fileName: string,
    fileType: FileType,
  ) => Awaitable<string | null>;
  renameDetectionFile?: (oldPath: string, newPath: string) => Awaitable<boolean>;
  deleteDetectionFile?: (filePath: string) => Awaitable<boolean>;
}

declare global {
  interface Window {
    __WORKBENCH_E2E__?: WorkbenchE2EBridge;
  }
}

export function getWorkbenchE2EBridge(): WorkbenchE2EBridge | null {
  if (typeof window === "undefined") {
    return null;
  }

  return window.__WORKBENCH_E2E__ ?? null;
}

export function hasWorkbenchE2EInvoke(): boolean {
  return typeof getWorkbenchE2EBridge()?.invoke === "function";
}
