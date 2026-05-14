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
import { getWorkbenchE2EBridge } from "@/lib/workbench/e2e-bridge";

const TAURI_FS_SPECIFIER = "@tauri-apps/plugin-fs";
const TAURI_OPENER_SPECIFIER = "@tauri-apps/plugin-opener";

/** Returns true when running inside a Tauri webview. */
export function isDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Returns true when running on macOS. */
export function isMacOS(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Mac/i.test(navigator.platform);
}

async function importTauriFs() {
  return import(/* @vite-ignore */ TAURI_FS_SPECIFIER);
}

async function importTauriOpener() {
  return import(/* @vite-ignore */ TAURI_OPENER_SPECIFIER);
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
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.openDetectionFile) {
    return e2eBridge.openDetectionFile();
  }

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
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.readDetectionFileByPath) {
    return e2eBridge.readDetectionFileByPath(filePath);
  }

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
  swarm_bundle: { name: "Swarm Bundle", extensions: ["swarm"] },
  receipt: { name: "Receipt / Evidence", extensions: ["receipt", "hush"] },
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
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.saveDetectionFile) {
    return e2eBridge.saveDetectionFile(content, fileType, filePath, suggestedName);
  }

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

/**
 * Create a new detection file with default content in the given directory.
 *
 * @param dirPath  - Absolute path to the parent directory.
 * @param fileName - The file name (e.g. "my-policy.yaml").
 * @param fileType - The detection file type to determine default content.
 * @returns The saved file path, or null on failure / non-desktop.
 */
export async function createDetectionFile(
  dirPath: string,
  fileName: string,
  fileType: FileType,
): Promise<string | null> {
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.createDetectionFile) {
    return e2eBridge.createDetectionFile(dirPath, fileName, fileType);
  }

  if (!isDesktop()) return null;

  try {
    const fullPath = `${dirPath}/${fileName}`;
    const defaultContent = FILE_TYPE_REGISTRY[fileType].defaultContent;
    return await saveDetectionFile(defaultContent, fileType, fullPath);
  } catch (err) {
    console.error("[tauri-bridge] Failed to create file:", err);
    return null;
  }
}

/**
 * Rename a file on disk.
 *
 * @param oldPath - Current absolute path.
 * @param newPath - Desired absolute path.
 * @returns true on success, false on failure / non-desktop.
 */
export async function renameDetectionFile(
  oldPath: string,
  newPath: string,
): Promise<boolean> {
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.renameDetectionFile) {
    return e2eBridge.renameDetectionFile(oldPath, newPath);
  }

  if (!isDesktop()) return false;

  try {
    const { rename } = await importTauriFs();
    await rename(oldPath, newPath);
    return true;
  } catch (err) {
    console.error("[tauri-bridge] Failed to rename file:", oldPath, "->", newPath, err);
    return false;
  }
}

/**
 * Delete a file from disk.
 *
 * @param filePath - Absolute path to remove.
 * @returns true on success, false on failure / non-desktop.
 */
export async function deleteDetectionFile(
  filePath: string,
): Promise<boolean> {
  const e2eBridge = getWorkbenchE2EBridge();
  if (e2eBridge?.deleteDetectionFile) {
    return e2eBridge.deleteDetectionFile(filePath);
  }

  if (!isDesktop()) return false;

  try {
    const { remove } = await importTauriFs();
    await remove(filePath);
    return true;
  } catch (err) {
    console.error("[tauri-bridge] Failed to delete file:", filePath, err);
    return false;
  }
}

export async function savePolicyFile(
  content: string,
  filePath?: string | null,
  _format?: string,
): Promise<string | null> {
  return saveDetectionFile(content, "clawdstrike_policy", filePath, "policy");
}

/**
 * Reveal a file or directory in the OS file manager (Finder on macOS).
 * Falls back to opening the parent directory if the path cannot be revealed.
 */
export async function revealInFinder(path: string): Promise<void> {
  if (!isDesktop()) return;
  try {
    const { revealItemInDir } = await importTauriOpener();
    await revealItemInDir(path);
  } catch (err) {
    console.error("[tauri-bridge] Failed to reveal in Finder:", path, err);
  }
}

/**
 * Create a directory on disk (recursive).
 * @returns true on success, false on failure / non-desktop.
 */
export async function createDirectory(dirPath: string): Promise<boolean> {
  if (!isDesktop()) return false;
  try {
    const { mkdir } = await importTauriFs();
    await mkdir(dirPath, { recursive: true });
    return true;
  } catch (err) {
    console.error("[tauri-bridge] Failed to create directory:", dirPath, err);
    return false;
  }
}

// ---------------------------------------------------------------------------
// .swarm bundle helpers
// ---------------------------------------------------------------------------

/**
 * Read a .swarm bundle's manifest.json and board.json files.
 * Returns the parsed data, or null if not found / not desktop.
 */
export async function readSwarmBundle(bundlePath: string): Promise<{
  manifest: Record<string, unknown> | null;
  board: Record<string, unknown> | null;
} | null> {
  if (!isDesktop()) return null;
  try {
    const { readTextFile, exists } = await importTauriFs();
    const manifestPath = `${bundlePath}/manifest.json`;
    const manifest = (await exists(manifestPath))
      ? JSON.parse(await readTextFile(manifestPath))
      : null;
    const boardPath = `${bundlePath}/board.json`;
    const board = (await exists(boardPath))
      ? JSON.parse(await readTextFile(boardPath))
      : null;
    return { manifest, board };
  } catch (err) {
    console.error("[tauri-bridge] readSwarmBundle failed:", bundlePath, err);
    return null;
  }
}

/**
 * Write board.json inside a .swarm bundle directory.
 * Creates the file if it doesn't exist. Returns true on success.
 */
export async function writeSwarmBoardJson(
  bundlePath: string,
  board: Record<string, unknown>,
): Promise<boolean> {
  if (!isDesktop()) return false;
  try {
    const { writeTextFile } = await importTauriFs();
    await writeTextFile(
      `${bundlePath}/board.json`,
      JSON.stringify(board, null, 2),
    );
    return true;
  } catch (err) {
    console.error("[tauri-bridge] writeSwarmBoardJson failed:", bundlePath, err);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Policy-aware .swarm bundle creation
// ---------------------------------------------------------------------------

export interface CreateSwarmFromPolicyOptions {
  parentDir: string;
  policyFileName: string;
  policyFilePath: string;
  sentinels: Array<{ id: string; name: string; mode: string }>;
}

/**
 * Create a .swarm bundle pre-configured for a specific policy file.
 *
 * The manifest includes a `policyRef` pointing to the active policy, and
 * the board is pre-seeded with `agentSession` nodes for each active sentinel.
 * Bundle naming: {policyFileName}-{date}.swarm
 *
 * @returns The absolute bundle path on success, or null on failure.
 */
export async function createSwarmBundleFromPolicy(
  opts: CreateSwarmFromPolicyOptions,
): Promise<string | null> {
  if (!isDesktop()) return null;
  try {
    const { mkdir, writeTextFile } = await importTauriFs();

    // Bundle naming: {policyFileName}-{timestamp}.swarm per user decision
    const timestamp = new Date().toISOString().slice(0, 10);
    const stem = opts.policyFileName.replace(/\.(ya?ml|json)$/i, "");
    const safeName = `${stem}-${timestamp}`.replace(/[<>:"/\\|?*]/g, "_");
    const bundlePath = `${opts.parentDir}/${safeName}.swarm`;
    await mkdir(bundlePath, { recursive: true });

    // Manifest with policyRef (SWARM-03)
    const now = new Date().toISOString();
    const manifest: Record<string, unknown> = {
      version: "1.0.0",
      name: safeName,
      created: now,
      modified: now,
      policyRef: opts.policyFilePath,
      agents: opts.sentinels.map((s) => s.name),
      status: "draft",
    };
    await writeTextFile(
      `${bundlePath}/manifest.json`,
      JSON.stringify(manifest, null, 2),
    );

    // Board with pre-seeded sentinel agent nodes (SWARM-03)
    // Grid layout: 3 columns, 420px horizontal spacing, 320px vertical spacing
    const COL_COUNT = 3;
    const X_START = 80;
    const Y_START = 60;
    const X_GAP = 420;
    const Y_GAP = 320;
    const nodes = opts.sentinels.map((s, i) => ({
      id: `sentinel-${s.id}`,
      type: "agentSession",
      position: {
        x: X_START + (i % COL_COUNT) * X_GAP,
        y: Y_START + Math.floor(i / COL_COUNT) * Y_GAP,
      },
      data: {
        title: s.name,
        status: "idle",
        nodeType: "agentSession",
        createdAt: Date.now(),
        agentModel: s.mode,
        policyMode: "enforce",
      },
      width: 380,
      height: 280,
    }));

    const board = {
      boardId: `board-${Date.now().toString(36)}`,
      repoRoot: opts.parentDir,
      nodes,
      edges: [],
      viewport: { x: 0, y: 0, zoom: 1 },
    };
    await writeTextFile(
      `${bundlePath}/board.json`,
      JSON.stringify(board, null, 2),
    );

    return bundlePath;
  } catch (err) {
    console.error("[tauri-bridge] createSwarmBundleFromPolicy failed:", err);
    return null;
  }
}

/**
 * Create a new .swarm bundle directory with manifest.json and empty board.json.
 * Returns the absolute bundle path on success, or null on failure.
 */
export async function createSwarmBundle(
  parentDir: string,
  name: string,
): Promise<string | null> {
  if (!isDesktop()) return null;
  try {
    const { mkdir, writeTextFile } = await importTauriFs();
    const safeName = name.replace(/[<>:"/\\|?*]/g, "_").replace(/\.swarm$/, "");
    const bundlePath = `${parentDir}/${safeName}.swarm`;
    await mkdir(bundlePath, { recursive: true });

    const now = new Date().toISOString();
    const manifest = {
      version: "1.0.0",
      name: safeName,
      created: now,
      modified: now,
    };
    await writeTextFile(
      `${bundlePath}/manifest.json`,
      JSON.stringify(manifest, null, 2),
    );

    const board = {
      boardId: `board-${Date.now().toString(36)}`,
      repoRoot: "",
      nodes: [],
      edges: [],
      viewport: { x: 0, y: 0, zoom: 1 },
    };
    await writeTextFile(
      `${bundlePath}/board.json`,
      JSON.stringify(board, null, 2),
    );

    return bundlePath;
  } catch (err) {
    console.error("[tauri-bridge] createSwarmBundle failed:", err);
    return null;
  }
}
