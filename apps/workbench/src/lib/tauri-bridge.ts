/**
 * Tauri integration utilities for the desktop workbench.
 *
 * All Tauri API calls are lazily imported so the module can be safely
 * imported in non-Tauri contexts (e.g. during tests or SSR) without
 * throwing at module-evaluation time.
 */

import {
  FILE_TYPE_REGISTRY,
  getPrimaryExtension,
  sanitizeFilenameStem,
  type FileType,
} from "@/lib/workbench/file-type-registry";


/** Returns true when running inside a Tauri webview. */
export function isDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Returns true when running on macOS. */
export function isMacOS(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Mac/i.test(navigator.platform);
}


async function getWindow() {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  return getCurrentWindow();
}

/** Minimize the current window. */
export async function minimizeWindow(): Promise<void> {
  if (!isDesktop()) return;
  const win = await getWindow();
  await win.minimize();
}

/** Toggle maximized / restored state. */
export async function maximizeWindow(): Promise<void> {
  if (!isDesktop()) return;
  const win = await getWindow();
  await win.toggleMaximize();
}

/** Close the current window. */
export async function closeWindow(): Promise<void> {
  if (!isDesktop()) return;
  const win = await getWindow();
  await win.close();
}

/** Toggle native fullscreen mode. */
export async function toggleFullscreen(): Promise<void> {
  if (!isDesktop()) return;
  const win = await getWindow();
  const isFullscreen = await win.isFullscreen();
  await win.setFullscreen(!isFullscreen);
}


export interface OpenFileResult {
  /** Raw file content */
  content: string;
  /** Absolute path on disk */
  path: string;
  /** Detected file type */
  fileType: FileType;
}

/**
 * Open a native file dialog filtered for supported detection files.
 * Returns null if the user cancels.
 */
export async function openDetectionFile(): Promise<OpenFileResult | null> {
  if (!isDesktop()) return null;

  const { open } = await import("@tauri-apps/plugin-dialog");

  const selected = await open({
    multiple: false,
    filters: [
      {
        name: "Detection Files",
        extensions: ["yaml", "yml", "yar", "yara", "json"],
      },
    ],
    title: "Open Detection File",
  });

  if (!selected) return null;

  // open() returns string | string[] depending on `multiple`
  const filePath = typeof selected === "string" ? selected : selected[0];
  if (!filePath) return null;

  const { importDetectionFileNative } = await import("./tauri-commands");
  const result = await importDetectionFileNative(filePath);
  if (!result) {
    throw new Error("Native import command unavailable");
  }

  return {
    content: result.content,
    path: filePath,
    fileType: result.file_type as FileType,
  };
}

/**
 * Read a detection file directly by path (no dialog).
 * Returns null if not in desktop mode or if the file cannot be read.
 */
export async function readDetectionFileByPath(filePath: string): Promise<OpenFileResult | null> {
  if (!isDesktop()) return null;

  try {
    const { importDetectionFileNative } = await import("./tauri-commands");
    const result = await importDetectionFileNative(filePath);
    if (!result) return null;
    return {
      content: result.content,
      path: filePath,
      fileType: result.file_type as FileType,
    };
  } catch (err) {
    console.error("[tauri-bridge] Failed to read file:", filePath, err);
    return null;
  }
}

/** File dialog filter configs per workbench file type. */
const FILE_TYPE_FILTERS: Record<FileType, { name: string; extensions: string[] }> = {
  clawdstrike_policy: { name: "ClawdStrike Policy", extensions: ["yaml", "yml"] },
  sigma_rule: { name: "Sigma Rule", extensions: ["yaml", "yml"] },
  yara_rule: { name: "YARA Rule", extensions: ["yar", "yara"] },
  ocsf_event: { name: "OCSF Event", extensions: ["json"] },
};

function resolveLegacySaveType(value: FileType | string): FileType {
  if (value in FILE_TYPE_FILTERS) {
    return value as FileType;
  }

  switch (value) {
    case "json":
      return "ocsf_event";
    case "yara":
    case "yar":
      return "yara_rule";
    case "yaml":
    case "yml":
    default:
      return "clawdstrike_policy";
  }
}

/**
 * Show a native "Save As" dialog and return the chosen path (without writing).
 *
 * @param fileType - File type used to filter extensions.
 * @param suggestedName - File name stem to use in the dialog default.
 * @returns The chosen file path, or null if the user cancelled.
 */
export async function pickSavePath(
  fileType: FileType | string = "clawdstrike_policy",
  suggestedName?: string,
): Promise<string | null> {
  if (!isDesktop()) return null;

  const { save } = await import("@tauri-apps/plugin-dialog");
  const resolvedFileType = resolveLegacySaveType(fileType);
  const filterCfg = FILE_TYPE_FILTERS[resolvedFileType] ?? FILE_TYPE_FILTERS.clawdstrike_policy;
  const defaultExt = getPrimaryExtension(resolvedFileType).replace(/^\./, "");
  const defaultStem = sanitizeFilenameStem(
    suggestedName ?? FILE_TYPE_REGISTRY[resolvedFileType].shortLabel.toLowerCase(),
    FILE_TYPE_REGISTRY[resolvedFileType].shortLabel.toLowerCase(),
  );
  const result = await save({
    filters: [
      {
        name: filterCfg.name,
        extensions: filterCfg.extensions,
      },
    ],
    title: "Save Detection File",
    defaultPath: `${defaultStem}.${defaultExt}`,
  });

  return result ?? null;
}

/**
 * Save detection content to disk via native dialog.
 *
 * @param content  - The serialized source string to write
 * @param fileType - Detection file type used for validation and save dialog filters.
 * @param filePath - If provided, saves directly without prompting a dialog.
 *                   Pass null/undefined to show the "Save As" dialog.
 * @param suggestedName - File name stem to use when prompting a dialog.
 * @returns The path the file was saved to, or null if cancelled.
 */
export async function saveDetectionFile(
  content: string,
  fileType: FileType,
  filePath?: string | null,
  suggestedName?: string,
): Promise<string | null> {
  if (!isDesktop()) return null;

  let targetPath = filePath;

  if (!targetPath) {
    targetPath = await pickSavePath(fileType, suggestedName);
    if (!targetPath) return null;
  }

  const { exportDetectionFileNative } = await import("./tauri-commands");
  const result = await exportDetectionFileNative(content, targetPath, fileType);
  if (!result) {
    throw new Error("Native export command unavailable");
  }
  if (!result.success) {
    throw new Error(result.message);
  }

  return result.path;
}

export async function openPolicyFile(): Promise<OpenFileResult | null> {
  return openDetectionFile();
}

export async function readPolicyFileByPath(filePath: string): Promise<OpenFileResult | null> {
  return readDetectionFileByPath(filePath);
}

export async function savePolicyFile(
  content: string,
  filePath?: string | null,
  _format?: string,
): Promise<string | null> {
  return saveDetectionFile(content, "clawdstrike_policy", filePath, "policy");
}
