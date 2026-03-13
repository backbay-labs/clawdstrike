/**
 * Tauri integration utilities for the desktop workbench.
 *
 * All Tauri API calls are lazily imported so the module can be safely
 * imported in non-Tauri contexts (e.g. during tests or SSR) without
 * throwing at module-evaluation time.
 */

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

/** Returns true when running inside a Tauri webview. */
export function isDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Returns true when running on macOS. */
export function isMacOS(): boolean {
  if (typeof navigator === "undefined") return false;
  return /Mac/i.test(navigator.platform);
}

// ---------------------------------------------------------------------------
// Window controls
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// File dialogs
// ---------------------------------------------------------------------------

export interface OpenFileResult {
  /** Raw YAML string content */
  content: string;
  /** Absolute path on disk */
  path: string;
}

/**
 * Open a native file dialog filtered for YAML policy files.
 * Returns null if the user cancels.
 */
export async function openPolicyFile(): Promise<OpenFileResult | null> {
  if (!isDesktop()) return null;

  const { open } = await import("@tauri-apps/plugin-dialog");

  const selected = await open({
    multiple: false,
    filters: [
      {
        name: "YAML Policy",
        extensions: ["yaml", "yml"],
      },
    ],
    title: "Open Policy File",
  });

  if (!selected) return null;

  // open() returns string | string[] depending on `multiple`
  const filePath = typeof selected === "string" ? selected : selected[0];
  if (!filePath) return null;

  const { importPolicyFileNative } = await import("./tauri-commands");
  const result = await importPolicyFileNative(filePath);
  if (!result) {
    throw new Error("Native import command unavailable");
  }

  return { content: result.yaml, path: filePath };
}

/**
 * Read a policy file directly by path (no dialog).
 * Returns null if not in desktop mode or if the file cannot be read.
 */
export async function readPolicyFileByPath(filePath: string): Promise<OpenFileResult | null> {
  if (!isDesktop()) return null;

  try {
    const { importPolicyFileNative } = await import("./tauri-commands");
    const result = await importPolicyFileNative(filePath);
    if (!result) return null;
    return { content: result.yaml, path: filePath };
  } catch (err) {
    console.error("[tauri-bridge] Failed to read file:", filePath, err);
    return null;
  }
}

/** File dialog filter configs per format. */
const FORMAT_FILTERS: Record<string, { name: string; extensions: string[]; defaultExt: string }> = {
  yaml: { name: "YAML Policy", extensions: ["yaml", "yml"], defaultExt: "yaml" },
  json: { name: "JSON Policy", extensions: ["json"], defaultExt: "json" },
  toml: { name: "TOML Policy", extensions: ["toml"], defaultExt: "toml" },
};

/**
 * Show a native "Save As" dialog and return the chosen path (without writing).
 *
 * @param format - Export format used to filter extensions: "yaml", "json", or "toml".
 * @returns The chosen file path, or null if the user cancelled.
 */
export async function pickSavePath(format: string = "yaml"): Promise<string | null> {
  if (!isDesktop()) return null;

  const { save } = await import("@tauri-apps/plugin-dialog");
  const filterCfg = FORMAT_FILTERS[format] || FORMAT_FILTERS.yaml;
  const result = await save({
    filters: [
      {
        name: filterCfg.name,
        extensions: filterCfg.extensions,
      },
    ],
    title: "Save Policy File",
    defaultPath: `policy.${filterCfg.defaultExt}`,
  });

  return result ?? null;
}

/**
 * Save policy content to disk via native dialog.
 *
 * @param content  - The serialized policy string to write
 * @param filePath - If provided, saves directly without prompting a dialog.
 *                   Pass null/undefined to show the "Save As" dialog.
 * @param format   - Export format: "yaml" (default), "json", or "toml".
 * @returns The path the file was saved to, or null if cancelled.
 */
export async function savePolicyFile(
  content: string,
  filePath?: string | null,
  format: string = "yaml",
): Promise<string | null> {
  if (!isDesktop()) return null;

  let targetPath = filePath;

  if (!targetPath) {
    targetPath = await pickSavePath(format);
    if (!targetPath) return null;
  }

  const { exportPolicyFileNative } = await import("./tauri-commands");
  const result = await exportPolicyFileNative(content, targetPath, format);
  if (!result) {
    throw new Error("Native export command unavailable");
  }
  if (!result.success) {
    throw new Error(result.message);
  }

  return result.path;
}
