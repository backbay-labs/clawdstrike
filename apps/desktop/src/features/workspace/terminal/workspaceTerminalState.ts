export type WorkspaceTerminalSessionKind = "shell" | "task";
export type WorkspaceTerminalSessionStatus = "running" | "exited";

export interface WorkspaceTerminalSession {
  sessionId: string;
  title: string;
  kind: WorkspaceTerminalSessionKind;
  status: WorkspaceTerminalSessionStatus;
  cwd: string;
  cols: number;
  rows: number;
  output: string;
  exitCode?: number;
}

export interface WorkspaceTerminalViewport {
  cols: number;
  rows: number;
}

const DEFAULT_TERMINAL_VIEWPORT: WorkspaceTerminalViewport = {
  cols: 100,
  rows: 24,
};

export function estimateWorkspaceTerminalViewport(
  width?: number,
  height?: number,
): WorkspaceTerminalViewport {
  if (!width || !height) {
    return DEFAULT_TERMINAL_VIEWPORT;
  }

  return {
    cols: Math.max(40, Math.floor(width / 9)),
    rows: Math.max(12, Math.floor(height / 18)),
  };
}

export function selectWorkspaceTerminalSession(
  sessions: WorkspaceTerminalSession[],
  activeSessionId?: string,
) {
  if (!sessions.length) return undefined;
  if (!activeSessionId) return sessions[sessions.length - 1];
  return sessions.find((session) => session.sessionId === activeSessionId) ?? sessions[sessions.length - 1];
}
