import { IconPlus, IconX } from "@tabler/icons-react";
import { useEffect, useRef, useState } from "react";
import { TerminalRenderer } from "@/components/workbench/swarm-board/terminal-renderer";
import { cn } from "@/lib/utils";
import type { TerminalSession } from "./bottom-pane-store";
import { useBottomPaneStore } from "./bottom-pane-store";

function RenameInput({
  sessionId,
  currentName,
  onDone,
}: {
  sessionId: string;
  currentName: string;
  onDone: (id: string, newName: string) => void;
}) {
  const [value, setValue] = useState(currentName);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.select();
  }, []);

  function commit() {
    const trimmed = value.trim();
    onDone(sessionId, trimmed || currentName);
  }

  return (
    <input
      ref={inputRef}
      type="text"
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") commit();
        if (e.key === "Escape") onDone(sessionId, currentName);
      }}
      className="bg-[#0b0d13] border border-[#d4a84b]/40 rounded px-1.5 py-0.5 text-[11px] font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b] w-full max-w-[120px]"
    />
  );
}

function TerminalSessionView({ session }: { session: TerminalSession }) {
  if (session.ptySessionId) {
    return (
      <div className="h-full w-full">
        <TerminalRenderer sessionId={session.ptySessionId} active />
      </div>
    );
  }
  return (
    <div className="flex h-full items-center justify-center px-6 text-center text-[12px] text-[#6f7f9a]">
      {session.error ?? "Terminal unavailable in this environment."}
    </div>
  );
}

export function TerminalPanel() {
  const terminalSessions = useBottomPaneStore((state) => state.terminalSessions);
  const activeTerminalId = useBottomPaneStore((state) => state.activeTerminalId);
  const splitTerminalIds = useBottomPaneStore((state) => state.splitTerminalIds);

  const [renamingId, setRenamingId] = useState<string | null>(null);

  useEffect(() => {
    if (terminalSessions.length === 0) {
      void useBottomPaneStore.getState().newTerminal();
    }
  }, [terminalSessions.length]);

  const activeSession =
    terminalSessions.find((session) => session.id === activeTerminalId)
    ?? terminalSessions[0]
    ?? null;

  const isSplit = splitTerminalIds != null;
  const leftSession = isSplit
    ? terminalSessions.find((s) => s.id === splitTerminalIds[0]) ?? null
    : null;
  const rightSession = isSplit
    ? terminalSessions.find((s) => s.id === splitTerminalIds[1]) ?? null
    : null;

  function isInSplit(id: string): boolean {
    return splitTerminalIds != null &&
      (splitTerminalIds[0] === id || splitTerminalIds[1] === id);
  }

  function handleRenameDone(id: string, newName: string) {
    useBottomPaneStore.getState().renameTerminal(id, newName);
    setRenamingId(null);
  }

  return (
    <div className="flex h-full min-h-0 flex-col" data-shortcut-context="terminal">
      <div className="flex items-center gap-1 border-b border-[#202531] px-2 py-2">
        {terminalSessions.map((session) => (
          <div
            key={session.id}
            className={cn(
              "flex items-center rounded-md text-[11px] transition-colors",
              session.id === activeSession?.id || (isSplit && isInSplit(session.id))
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:bg-[#0f1219] hover:text-[#ece7dc]",
            )}
          >
            {renamingId === session.id ? (
              <div className="px-1.5 py-0.5">
                <RenameInput
                  sessionId={session.id}
                  currentName={session.title}
                  onDone={handleRenameDone}
                />
              </div>
            ) : (
              <button
                type="button"
                className="px-2.5 py-1"
                onClick={() => useBottomPaneStore.getState().setActiveTerminal(session.id)}
                onDoubleClick={() => setRenamingId(session.id)}
              >
                {session.title}
              </button>
            )}
            <button
              type="button"
              className="rounded-r-md px-1.5 py-1 text-[#6f7f9a] transition-colors hover:bg-[#2a1115] hover:text-[#ffb8b8]"
              onClick={() => void useBottomPaneStore.getState().closeTerminal(session.id)}
              aria-label={`Close ${session.title}`}
            >
              <IconX size={11} stroke={1.8} />
            </button>
          </div>
        ))}
        <button
          type="button"
          className="ml-1 rounded-md p-1.5 text-[#6f7f9a] transition-colors hover:bg-[#0f1219] hover:text-[#ece7dc]"
          onClick={() => void useBottomPaneStore.getState().newTerminal()}
          aria-label="New terminal session"
        >
          <IconPlus size={13} stroke={1.8} />
        </button>
      </div>

      <div className="min-h-0 flex-1 bg-[#06080d]">
        {isSplit && leftSession && rightSession ? (
          <div className="flex h-full min-h-0 flex-row">
            <div className="flex-1 min-w-0 min-h-0">
              <TerminalSessionView session={leftSession} />
            </div>
            <div className="w-px bg-[#202531]" />
            <div className="flex-1 min-w-0 min-h-0">
              <TerminalSessionView session={rightSession} />
            </div>
          </div>
        ) : !activeSession ? null : (
          <TerminalSessionView session={activeSession} />
        )}
      </div>
    </div>
  );
}
