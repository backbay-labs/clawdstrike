import { useEffect, useRef, useState } from "react";
import {
  estimateWorkspaceTerminalViewport,
  selectWorkspaceTerminalSession,
  type WorkspaceTerminalSession,
} from "./workspaceTerminalState";
import {
  mockWorkspaceTerminalService,
  type WorkspaceTerminalService,
  type WorkspaceTerminalTaskPreset,
} from "./workspaceTerminalService";

interface WorkspaceTerminalPanelProps {
  rootId?: string;
  rootName?: string;
  initialCwd?: string;
  service?: WorkspaceTerminalService;
}

export function WorkspaceTerminalPanel({
  rootId,
  rootName,
  initialCwd = ".",
  service = mockWorkspaceTerminalService,
}: WorkspaceTerminalPanelProps) {
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const [sessions, setSessions] = useState<WorkspaceTerminalSession[]>(() => service.listSessions());
  const [activeSessionId, setActiveSessionId] = useState<string>();
  const [commandInput, setCommandInput] = useState("");

  useEffect(() => {
    setSessions(service.listSessions());
    return service.subscribe(() => {
      setSessions(service.listSessions());
    });
  }, [service]);

  const activeSession = selectWorkspaceTerminalSession(sessions, activeSessionId);

  useEffect(() => {
    if (!activeSession) return;
    const element = viewportRef.current;
    const viewport = estimateWorkspaceTerminalViewport(element?.clientWidth, element?.clientHeight);
    if (activeSession.cols === viewport.cols && activeSession.rows === viewport.rows) {
      return;
    }
    void service.resizeSession({
      sessionId: activeSession.sessionId,
      cols: viewport.cols,
      rows: viewport.rows,
    });
  }, [activeSession, service]);

  async function openShell() {
    if (!rootId) return;
    const viewport = estimateWorkspaceTerminalViewport(
      viewportRef.current?.clientWidth,
      viewportRef.current?.clientHeight,
    );
    const session = await service.openShellSession({
      rootId,
      rootName,
      cwd: initialCwd,
      cols: viewport.cols,
      rows: viewport.rows,
    });
    setActiveSessionId(session.sessionId);
  }

  async function runTask(preset: WorkspaceTerminalTaskPreset) {
    if (!rootId) return;
    const viewport = estimateWorkspaceTerminalViewport(
      viewportRef.current?.clientWidth,
      viewportRef.current?.clientHeight,
    );
    const session = await service.runTaskSession({
      rootId,
      rootName,
      preset,
      cwd: initialCwd,
      cols: viewport.cols,
      rows: viewport.rows,
    });
    setActiveSessionId(session.sessionId);
  }

  async function submitCommand() {
    if (!activeSession || !commandInput.trim()) return;
    await service.writeSession({
      sessionId: activeSession.sessionId,
      data: commandInput,
    });
    setCommandInput("");
  }

  async function closeActiveSession() {
    if (!activeSession) return;
    await service.closeSession(activeSession.sessionId);
  }

  if (!rootId) {
    return (
      <div className="rounded-xl border border-dashed border-sdr-border p-4 text-sm text-sdr-text-secondary">
        Register a trusted root before opening shell or task sessions.
      </div>
    );
  }

  return (
    <div className="grid h-full min-h-0 grid-rows-[auto_auto_minmax(0,1fr)_auto] gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-sdr-text-primary">Workspace terminal</div>
          <div className="text-xs text-sdr-text-muted">
            Shell sessions stay interactive while search and git run as separate task tabs.
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={openShell}
            className="rounded-full border border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] px-3 py-1.5 text-xs uppercase tracking-[0.12em] text-sdr-text-primary"
          >
            Open shell
          </button>
          <button
            type="button"
            onClick={() => void runTask("search.paths")}
            className="rounded-full border border-sdr-border px-3 py-1.5 text-xs uppercase tracking-[0.12em] text-sdr-text-primary"
          >
            Run `rg --files`
          </button>
          <button
            type="button"
            onClick={() => void runTask("git.status")}
            className="rounded-full border border-sdr-border px-3 py-1.5 text-xs uppercase tracking-[0.12em] text-sdr-text-primary"
          >
            Run `git status`
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2" data-testid="workspace-terminal-tabs">
        {sessions.length ? (
          sessions.map((session) => (
            <button
              key={session.sessionId}
              type="button"
              onClick={() => setActiveSessionId(session.sessionId)}
              className={`rounded-full border px-3 py-1.5 text-xs ${
                activeSession?.sessionId === session.sessionId
                  ? "border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] text-sdr-text-primary"
                  : "border-sdr-border text-sdr-text-muted"
              }`}
            >
              {session.title}
            </button>
          ))
        ) : (
          <div className="rounded-xl border border-dashed border-sdr-border px-3 py-2 text-xs text-sdr-text-muted">
            No sessions yet. Open a shell or run a search/git task.
          </div>
        )}
      </div>

      <div
        ref={viewportRef}
        className="min-h-0 overflow-auto rounded-2xl border border-sdr-border bg-[rgba(7,12,18,0.82)] p-4 font-mono text-xs leading-6 text-[rgba(210,229,255,0.92)]"
        data-testid="workspace-terminal-output"
      >
        {activeSession ? activeSession.output : "No active terminal session"}
      </div>

      <div className="grid gap-3 rounded-2xl border border-sdr-border bg-sdr-bg-primary/20 p-3">
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-sdr-text-muted">
          <span>
            {activeSession
              ? `${activeSession.kind} session · ${activeSession.status} · ${activeSession.cols}x${activeSession.rows}`
              : "No active session"}
          </span>
          <button
            type="button"
            onClick={() => void closeActiveSession()}
            disabled={!activeSession}
            className="rounded-full border border-sdr-border px-3 py-1 text-[11px] uppercase tracking-[0.12em] text-sdr-text-primary disabled:opacity-50"
          >
            Close session
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={commandInput}
            onChange={(event) => setCommandInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                void submitCommand();
              }
            }}
            placeholder="Type a shell command or use the task buttons above"
            disabled={!activeSession || activeSession.status !== "running"}
            className="min-w-[240px] flex-1 rounded-xl border border-sdr-border bg-sdr-bg-primary/40 px-3 py-2 text-sm text-sdr-text-primary placeholder:text-sdr-text-muted disabled:opacity-50"
          />
          <button
            type="button"
            onClick={() => void submitCommand()}
            disabled={!activeSession || activeSession.status !== "running" || !commandInput.trim()}
            className="rounded-xl border border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] px-4 py-2 text-sm text-sdr-text-primary disabled:opacity-50"
          >
            Send
          </button>
        </div>
      </div>
    </div>
  );
}
