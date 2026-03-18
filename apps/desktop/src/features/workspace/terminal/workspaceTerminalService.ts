import type { WorkspaceTerminalSession } from "./workspaceTerminalState";

export type WorkspaceTerminalTaskPreset = "search.paths" | "git.status";

export interface OpenWorkspaceShellRequest {
  rootId: string;
  rootName?: string;
  cwd?: string;
  cols: number;
  rows: number;
}

export interface RunWorkspaceTaskRequest extends OpenWorkspaceShellRequest {
  preset: WorkspaceTerminalTaskPreset;
}

export interface WriteWorkspaceTerminalRequest {
  sessionId: string;
  data: string;
}

export interface ResizeWorkspaceTerminalRequest {
  sessionId: string;
  cols: number;
  rows: number;
}

export interface WorkspaceTerminalService {
  listSessions(): WorkspaceTerminalSession[];
  openShellSession(request: OpenWorkspaceShellRequest): Promise<WorkspaceTerminalSession>;
  runTaskSession(request: RunWorkspaceTaskRequest): Promise<WorkspaceTerminalSession>;
  writeSession(request: WriteWorkspaceTerminalRequest): Promise<void>;
  resizeSession(request: ResizeWorkspaceTerminalRequest): Promise<void>;
  closeSession(sessionId: string): Promise<void>;
  subscribe(listener: () => void): () => void;
}

function timestampId(prefix: string) {
  return `${prefix}-${Math.random().toString(16).slice(2, 10)}`;
}

function getTaskTranscript(preset: WorkspaceTerminalTaskPreset, rootName: string) {
  if (preset === "search.paths") {
    return [`$ rg --files`, `briefs/hunt-plan.md`, `rules/yara/suspicious-loader.yar`, `receipts/${rootName}-receipt.json`].join("\n");
  }

  return [`$ git status --short`, ` M briefs/hunt-plan.md`, `?? evidence/new-sample.txt`].join("\n");
}

export function createMockWorkspaceTerminalService(): WorkspaceTerminalService {
  const sessions = new Map<string, WorkspaceTerminalSession>();
  const listeners = new Set<() => void>();

  const emit = () => {
    for (const listener of listeners) {
      listener();
    }
  };

  const upsertSession = (session: WorkspaceTerminalSession) => {
    sessions.set(session.sessionId, session);
    emit();
    return session;
  };

  return {
    listSessions() {
      return Array.from(sessions.values());
    },
    async openShellSession(request) {
      const session = upsertSession({
        sessionId: timestampId("workspace-shell"),
        title: request.rootName ? `${request.rootName} shell` : "Workspace shell",
        kind: "shell",
        status: "running",
        cwd: request.cwd ?? ".",
        cols: request.cols,
        rows: request.rows,
        output: [`$ cd ${request.cwd ?? "."}`, `shell ready for ${request.rootName ?? request.rootId}`].join("\n"),
      });
      return session;
    },
    async runTaskSession(request) {
      const rootName = request.rootName ?? request.rootId;
      const title = request.preset === "search.paths" ? "rg --files" : "git status --short";
      const session = upsertSession({
        sessionId: timestampId("workspace-task"),
        title,
        kind: "task",
        status: "exited",
        cwd: request.cwd ?? ".",
        cols: request.cols,
        rows: request.rows,
        exitCode: 0,
        output: getTaskTranscript(request.preset, rootName),
      });
      return session;
    },
    async writeSession(request) {
      const session = sessions.get(request.sessionId);
      if (!session) return;

      const command = request.data.trim();
      const nextLines = [session.output, `$ ${command}`];
      if (command === "rg --files") {
        nextLines.push("briefs/hunt-plan.md", "rules/sigma/outbound-spike.yml");
      } else if (command === "git status --short") {
        nextLines.push(" M briefs/hunt-plan.md", "?? evidence/new-sample.txt");
      } else if (command === "exit") {
        session.status = "exited";
        session.exitCode = 0;
        nextLines.push("shell closed");
      } else {
        nextLines.push(`command not mocked: ${command}`);
      }

      upsertSession({
        ...session,
        output: nextLines.filter(Boolean).join("\n"),
      });
    },
    async resizeSession(request) {
      const session = sessions.get(request.sessionId);
      if (!session) return;
      upsertSession({
        ...session,
        cols: request.cols,
        rows: request.rows,
      });
    },
    async closeSession(sessionId) {
      const session = sessions.get(sessionId);
      if (!session) return;
      upsertSession({
        ...session,
        status: "exited",
        exitCode: session.exitCode ?? 130,
        output: `${session.output}\nterminal closed`,
      });
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

export const mockWorkspaceTerminalService = createMockWorkspaceTerminalService();
