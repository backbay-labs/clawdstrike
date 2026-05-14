/**
 * Terminal service — TypeScript bridge for the Rust PTY backend.
 *
 * Wraps Tauri `invoke` calls for terminal session management and git worktree
 * operations. Output streaming uses Tauri's event system; call `onOutput` to
 * subscribe to a session's stdout chunks.
 */

import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ---------------------------------------------------------------------------
// Tauri detection + timeout wrapper
// ---------------------------------------------------------------------------

/** Returns true when running inside a Tauri WebView (IPC bridge available). */
function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const INVOKE_TIMEOUT_MS = 15_000;

/**
 * Wrapper around Tauri's `invoke` that rejects immediately when not running
 * inside a Tauri shell, and adds a generous timeout as a safety net.
 */
function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    return Promise.reject(
      new Error(`Tauri runtime not available (command: ${cmd}). Run the desktop app with "npm run tauri:dev".`),
    );
  }
  let timer: ReturnType<typeof setTimeout>;
  return Promise.race([
    tauriInvoke<T>(cmd, args),
    new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Tauri invoke timed out after ${INVOKE_TIMEOUT_MS / 1000}s: ${cmd}`)),
        INVOKE_TIMEOUT_MS,
      );
    }),
  ]).finally(() => clearTimeout(timer));
}

async function invokeSensitive<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SessionInfo {
  id: string;
  cwd: string;
  branch: string | null;
  created_at: string;
  alive: boolean;
  exit_code: number | null;
  line_count: number;
}

export interface WorktreeInfo {
  path: string;
  branch: string;
  head: string;
}

export interface WorktreeStatus {
  changed_files: string[];
  added_lines: number;
  removed_lines: number;
}

// ---------------------------------------------------------------------------
// Terminal service
// ---------------------------------------------------------------------------

export const terminalService = {
  /**
   * Create a new PTY session in the given working directory.
   *
   * @param cwd      - Working directory for the shell.
   * @param shell    - Shell binary (defaults to a platform-safe backend default).
   * @param env      - Extra environment variables to set.
   * @returns        - Session metadata including the generated session ID.
   */
  create: (
    cwd: string,
    shell?: string,
    env?: Record<string, string>,
  ): Promise<SessionInfo> =>
    invokeSensitive<SessionInfo>("terminal_create", { cwd, shell, env }),

  /**
   * Write data (keystrokes, paste, etc.) to a session's PTY stdin.
   */
  write: (sessionId: string, data: string): Promise<void> =>
    invokeSensitive<void>("terminal_write", { sessionId, data }),

  /**
   * Resize the PTY to new dimensions.
   */
  resize: (sessionId: string, cols: number, rows: number): Promise<void> =>
    invokeSensitive<void>("terminal_resize", { sessionId, cols, rows }),

  /**
   * Kill the session's child process and free resources.
   */
  kill: (sessionId: string): Promise<void> =>
    invokeSensitive<void>("terminal_kill", { sessionId }),

  /**
   * List all active terminal sessions.
   */
  list: (): Promise<SessionInfo[]> => invokeSensitive<SessionInfo[]>("terminal_list"),

  /**
   * Get the last N lines from the session's ring buffer (for tile preview).
   *
   * @param sessionId - The session to query.
   * @param lines     - Number of lines to return (default 6).
   */
  preview: (sessionId: string, lines?: number): Promise<string[]> =>
    invokeSensitive<string[]>("terminal_preview", { sessionId, lines }),

  /**
   * Subscribe to stdout output chunks for a session.
   *
   * Returns an unlisten function — call it when the component unmounts or
   * when you no longer need the subscription.
   *
   * @param sessionId - The session to subscribe to.
   * @param callback  - Called with each output chunk (raw terminal data).
   */
  onOutput: (
    sessionId: string,
    callback: (data: string) => void,
  ): Promise<UnlistenFn> =>
    listen<string>(`terminal:output:${sessionId}`, (event) =>
      callback(event.payload),
    ),

  /**
   * Get the current working directory of the Tauri process.
   *
   * Used to auto-detect a sensible default for repoRoot on first launch.
   */
  getCwd: (): Promise<string> => invokeSensitive<string>("get_cwd"),

  /**
   * Subscribe to session exit events.
   *
   * Fired when the PTY reader detects EOF (child process exited or PTY
   * closed). The payload is the exit code if available, or null.
   *
   * @param sessionId - The session to monitor.
   * @param callback  - Called with the exit code (or null if unavailable).
   */
  onExit: (
    sessionId: string,
    callback: (exitCode: number | null) => void,
  ): Promise<UnlistenFn> =>
    listen<number | null>(`terminal:exit:${sessionId}`, (event) =>
      callback(event.payload),
    ),
};

// ---------------------------------------------------------------------------
// Worktree service
// ---------------------------------------------------------------------------

export const worktreeService = {
  /**
   * Create a new git worktree for the given branch.
   *
   * The worktree is created under `{repoRoot}/.swarm-worktrees/` using a
   * backend-safe directory name derived from the branch.
   * If the branch doesn't exist, it is created from HEAD.
   */
  create: (repoRoot: string, branchName: string): Promise<WorktreeInfo> =>
    invokeSensitive<WorktreeInfo>("worktree_create", { repoRoot, branchName }),

  /**
   * Remove a git worktree and prune the reference.
   */
  remove: (repoRoot: string, worktreePath: string): Promise<void> =>
    invokeSensitive<void>("worktree_remove", { repoRoot, worktreePath }),

  /**
   * List all git worktrees for a repository.
   */
  list: (repoRoot: string): Promise<WorktreeInfo[]> =>
    invokeSensitive<WorktreeInfo[]>("worktree_list", { repoRoot }),

  /**
   * Get the diff status of a worktree (changed files, insertions, deletions).
   */
  status: (repoRoot: string, worktreePath: string): Promise<WorktreeStatus> =>
    invokeSensitive<WorktreeStatus>("worktree_status", { repoRoot, worktreePath }),
};
