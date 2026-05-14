/**
 * SwarmBoardToolbar — dense, vim-statusline-style top bar.
 *
 * Visual hierarchy:
 *   Primary  — "New Claude Session" (gold bg, label visible)
 *   Secondary — "Terminal", "Worktree" (ghost outline, label visible)
 *   Tertiary — Layout/zoom/misc (icon-only, tight group, title tooltip)
 *   Danger   — "Clear" (icon-only, far-right, low prominence)
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useReactFlow } from "@xyflow/react";
import {
  IconTerminal2,
  IconLayoutDistributeHorizontal,
  IconFocusCentered,
  IconPlayerPlay,
  IconZoomIn,
  IconZoomOut,
  IconZoomReset,
  IconTrash,
  IconFolder,
  IconGitBranch,
  IconChevronDown,
  IconRobot,
  IconNote,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { isDesktop } from "@/lib/tauri-bridge";
import {
  useSwarmBoard,
  MAX_ACTIVE_TERMINALS,
  type SpawnSessionOptions,
  type SpawnClaudeSessionOptions,
} from "@/features/swarm/stores/swarm-board-store";
import { useTerminalSessionsFromBoard } from "@/lib/workbench/use-terminal-sessions";

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const TOOLBAR_HEIGHT = 34;
const SESSION_GRID_GAP = 500;
const TASK_GRID_GAP = 350;
const TASK_X_OFFSET = 80;
const TASK_Y = 380;
const EVIDENCE_GRID_GAP = 320;
const EVIDENCE_Y = 550;
const ARTIFACT_X_OFFSET = 100;
const ARTIFACT_Y_GAP = 130;
const NOTE_Y_GAP = 200;
const ERROR_DISMISS_MS = 5000;
const LAYOUT_SETTLE_MS = 50;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SwarmBoardToolbar() {
  const board = useSwarmBoard();
  const { addNode, clearBoard, state, dispatch } = board;
  const {
    spawnSession,
    spawnClaudeSession,
    spawnWorktreeSession,
    activeSessionCount,
    canSpawnMore,
    hasRepoRoot,
  } = useTerminalSessionsFromBoard(board);
  const reactFlow = useReactFlow();
  const [spawning, setSpawning] = useState(false);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [spawnError, setSpawnError] = useState<string | null>(null);
  const [workspaceInput, setWorkspaceInput] = useState(false);
  const [workspaceInputValue, setWorkspaceInputValue] = useState("");
  const optionsRef = useRef<HTMLDivElement>(null);

  const desktop = isDesktop();

  const getDropPosition = useCallback(() => {
    try {
      const viewport = reactFlow.getViewport();
      const centerX = (-viewport.x + window.innerWidth / 2) / viewport.zoom;
      const centerY = (-viewport.y + window.innerHeight / 2) / viewport.zoom;
      return {
        x: centerX + (Math.random() - 0.5) * 100,
        y: centerY + (Math.random() - 0.5) * 100,
      };
    } catch {
      return { x: 200 + Math.random() * 300, y: 200 + Math.random() * 200 };
    }
  }, [reactFlow]);

  useEffect(() => {
    if (!spawnError) return;
    const t = setTimeout(() => setSpawnError(null), ERROR_DISMISS_MS);
    return () => clearTimeout(t);
  }, [spawnError]);

  useEffect(() => {
    if (!optionsOpen) return;
    function handleClick(e: MouseEvent) {
      if (optionsRef.current && !optionsRef.current.contains(e.target as HTMLElement)) {
        setOptionsOpen(false);
      }
    }
    function handleEsc(e: KeyboardEvent) {
      if (e.key === "Escape") setOptionsOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleEsc);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleEsc);
    };
  }, [optionsOpen]);

  // ------- Spawn handlers -------

  const handleNewTerminal = useCallback(async () => {
    if (spawning || !canSpawnMore) return;
    setSpawning(true);
    setSpawnError(null);
    try {
      const cwd = state.repoRoot || "/tmp";
      const node = await spawnSession({
        cwd,
        position: getDropPosition(),
        title: "Terminal",
      });
      dispatch({ type: "SELECT_NODE", nodeId: node.id });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setSpawnError(`Terminal: ${msg}`);
      addNode({
        nodeType: "agentSession",
        title: "Terminal (offline)",
        position: getDropPosition(),
        data: {
          agentModel: "shell",
          status: "idle",
          previewLines: ["~ run npm run tauri:dev for live terminals"],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
        },
      });
    } finally {
      setSpawning(false);
    }
  }, [spawning, canSpawnMore, state.repoRoot, spawnSession, getDropPosition, dispatch, addNode]);

  const handleNewClaudeSession = useCallback(async () => {
    if (spawning || !canSpawnMore) return;
    setSpawning(true);
    setSpawnError(null);
    try {
      const node = await spawnClaudeSession({
        position: getDropPosition(),
        worktree: hasRepoRoot,
      });
      dispatch({ type: "SELECT_NODE", nodeId: node.id });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setSpawnError(`Claude: ${msg}`);
      addNode({
        nodeType: "agentSession",
        title: "Claude (offline)",
        position: getDropPosition(),
        data: {
          agentModel: "claude",
          status: "idle",
          previewLines: ["~ run npm run tauri:dev for live sessions"],
          receiptCount: 0,
          blockedActionCount: 0,
          changedFilesCount: 0,
          risk: "low",
          policyMode: "default",
        },
      });
    } finally {
      setSpawning(false);
    }
  }, [spawning, canSpawnMore, hasRepoRoot, spawnClaudeSession, getDropPosition, dispatch, addNode]);

  const handleNewWorktreeSession = useCallback(async () => {
    if (spawning || !canSpawnMore || !hasRepoRoot) return;
    setSpawning(true);
    setSpawnError(null);
    try {
      const node = await spawnWorktreeSession({
        position: getDropPosition(),
      });
      dispatch({ type: "SELECT_NODE", nodeId: node.id });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setSpawnError(`Worktree: ${msg}`);
    } finally {
      setSpawning(false);
    }
  }, [spawning, canSpawnMore, hasRepoRoot, spawnWorktreeSession, getDropPosition, dispatch]);

  const handleNewNote = useCallback(() => {
    addNode({
      nodeType: "note",
      title: "Note",
      position: getDropPosition(),
      data: { content: "" },
    });
  }, [addNode, getDropPosition]);

  // ------- Layout handlers -------

  const handleAutoLayout = useCallback(() => {
    const nodes = state.nodes;
    if (nodes.length === 0) return;

    const sessions = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "agentSession");
    const tasks = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "terminalTask");
    const receipts = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "receipt");
    const diffs = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "diff");
    const artifacts = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "artifact");
    const notes = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "note");

    const positions = new Map<string, { x: number; y: number }>();

    sessions.forEach((n, i) => {
      positions.set(n.id, { x: i * SESSION_GRID_GAP, y: 0 });
    });

    tasks.forEach((n, i) => {
      positions.set(n.id, { x: i * TASK_GRID_GAP + TASK_X_OFFSET, y: TASK_Y });
    });

    const evidenceNodes = [...receipts, ...diffs];
    evidenceNodes.forEach((n, i) => {
      positions.set(n.id, { x: i * EVIDENCE_GRID_GAP, y: EVIDENCE_Y });
    });

    artifacts.forEach((n, i) => {
      positions.set(n.id, { x: sessions.length * SESSION_GRID_GAP + ARTIFACT_X_OFFSET, y: i * ARTIFACT_Y_GAP });
    });

    notes.forEach((n, i) => {
      positions.set(n.id, {
        x: sessions.length * SESSION_GRID_GAP + ARTIFACT_X_OFFSET,
        y: evidenceNodes.length > 0 ? EVIDENCE_Y + i * NOTE_Y_GAP : i * NOTE_Y_GAP,
      });
    });

    const updated = nodes.map((node) => ({
      ...node,
      position: positions.get(node.id) ?? node.position,
    }));

    dispatch({ type: "SET_NODES", nodes: updated });
    setTimeout(() => {
      reactFlow.fitView({ padding: 0.15, duration: 400 });
    }, LAYOUT_SETTLE_MS);
  }, [state.nodes, dispatch, reactFlow]);

  const handleGather = useCallback(() => {
    reactFlow.fitView({ padding: 0.2, duration: 500 });
  }, [reactFlow]);

  const handleFollowActive = useCallback(() => {
    const nodes = reactFlow.getNodes();
    const runningNode = nodes.find(
      (n) => (n.data as Record<string, unknown>).status === "running",
    );
    if (runningNode) {
      reactFlow.fitView({
        nodes: [runningNode],
        padding: 0.5,
        duration: 400,
      });
    }
  }, [reactFlow]);

  const handleZoomIn = useCallback(() => {
    reactFlow.zoomIn({ duration: 200 });
  }, [reactFlow]);

  const handleZoomOut = useCallback(() => {
    reactFlow.zoomOut({ duration: 200 });
  }, [reactFlow]);

  const handleResetZoom = useCallback(() => {
    reactFlow.fitView({ padding: 0.2, duration: 300 });
  }, [reactFlow]);

  // ------- Workspace picker -------

  const handlePickWorkspace = useCallback(async () => {
    if (!desktop) {
      setWorkspaceInput(true);
      return;
    }
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({ directory: true, title: "Select Workspace Root" });
      if (selected && typeof selected === "string") {
        dispatch({ type: "SET_REPO_ROOT", repoRoot: selected });
      }
    } catch {
      setWorkspaceInput(true);
    }
  }, [desktop, dispatch]);

  const handleWorkspaceInputSubmit = useCallback(() => {
    const val = workspaceInputValue.trim();
    if (val) {
      dispatch({ type: "SET_REPO_ROOT", repoRoot: val });
    }
    setWorkspaceInput(false);
    setWorkspaceInputValue("");
  }, [workspaceInputValue, dispatch]);

  const spawnTooltip = !desktop
    ? "Tauri desktop app required for live sessions"
    : !canSpawnMore
      ? `Session limit reached (${MAX_ACTIVE_TERMINALS})`
      : undefined;

  const spawnDisabled = spawning || !canSpawnMore;

  return (
    <div
      className="flex items-center gap-0.5 px-3 shrink-0 select-none"
      style={{
        height: TOOLBAR_HEIGHT,
        backgroundColor: "#070910",
        borderBottom: "1px solid #0f1119",
      }}
    >
      {/* Board identity / repo root */}
      <div className="flex items-center gap-1.5 mr-2 min-w-0">
        <IconFolder size={11} stroke={1.5} className="text-[#3d4250] shrink-0" />
        {state.repoRoot ? (
          <span className="text-[10px] text-[#3d4250] font-mono truncate max-w-[200px]">
            {state.repoRoot}
          </span>
        ) : !workspaceInput ? (
          <button
            onClick={handlePickWorkspace}
            className="text-[9px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
            title="Set the workspace root directory"
            aria-label="Set workspace root"
          >
            set workspace
          </button>
        ) : null}
        {workspaceInput && (
          <form
            className="flex items-center gap-1"
            onSubmit={(e) => {
              e.preventDefault();
              handleWorkspaceInputSubmit();
            }}
          >
            <input
              type="text"
              value={workspaceInputValue}
              onChange={(e) => setWorkspaceInputValue(e.target.value)}
              placeholder="/path/to/project"
              className="w-[160px] px-1.5 py-0.5 bg-[#05060a] border border-[#1a1f2e] rounded text-[9px] font-mono text-[#ece7dc] placeholder-[#3d4250] focus:border-[#d4a84b40] focus:outline-none"
              autoFocus
              onBlur={() => {
                if (!workspaceInputValue.trim()) {
                  setWorkspaceInput(false);
                }
              }}
            />
            <button
              type="submit"
              className="text-[9px] font-mono text-[#d4a84b] hover:text-[#e8c06a]"
              aria-label="Confirm workspace path"
            >
              OK
            </button>
          </form>
        )}
        {activeSessionCount > 0 && (
          <span className="text-[9px] font-mono text-[#3dbf84] tabular-nums">
            {activeSessionCount} live
          </span>
        )}
      </div>

      {/* Thin separator */}
      <div className="w-px h-3 bg-[#1a1f2e] mx-1" />

      {/* --- Primary: New Claude Session (gold, prominent) --- */}
      <button
        onClick={handleNewClaudeSession}
        disabled={spawnDisabled}
        className={cn(
          "flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono font-medium transition-all",
          spawnDisabled
            ? "opacity-30 cursor-not-allowed text-[#d4a84b60]"
            : "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c06a] active:bg-[#c49a3d]",
        )}
        title={spawnDisabled ? spawnTooltip : "New Claude Session"}
        aria-label="New Claude Session"
      >
        <IconRobot size={12} stroke={1.5} />
        <span className="hidden sm:inline">{spawning ? "..." : "Claude"}</span>
      </button>

      {/* --- Secondary: Terminal, Worktree (ghost outline) --- */}
      <button
        onClick={handleNewTerminal}
        disabled={spawnDisabled}
        className={cn(
          "flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono transition-colors",
          spawnDisabled
            ? "opacity-30 cursor-not-allowed text-[#3d4250]"
            : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#ffffff06]",
        )}
        title={spawnDisabled ? spawnTooltip : "New Terminal"}
        aria-label="New Terminal"
      >
        <IconTerminal2 size={11} stroke={1.5} />
        <span className="hidden sm:inline">Terminal</span>
      </button>

      <button
        onClick={handleNewWorktreeSession}
        disabled={spawnDisabled || !hasRepoRoot}
        className={cn(
          "flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono transition-colors",
          spawnDisabled || !hasRepoRoot
            ? "opacity-30 cursor-not-allowed text-[#3d4250]"
            : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#ffffff06]",
        )}
        title={!hasRepoRoot ? "Set a workspace root first" : (spawnDisabled ? spawnTooltip : "New Worktree Session")}
        aria-label="New Worktree Session"
      >
        <IconGitBranch size={11} stroke={1.5} />
        <span className="hidden sm:inline">Worktree</span>
      </button>

      {/* Session options dropdown chevron */}
      <div className="relative" ref={optionsRef}>
        <button
          onClick={() => setOptionsOpen(!optionsOpen)}
          className="p-1 rounded text-[#3d4250] hover:text-[#6f7f9a] hover:bg-[#ffffff06] transition-colors"
          title="Advanced session options"
          aria-label="Advanced session options"
        >
          <IconChevronDown size={10} stroke={1.5} />
        </button>
        {optionsOpen && (
          <SessionOptionsPopover
            repoRoot={state.repoRoot}
            spawning={spawning}
            canSpawnMore={canSpawnMore}
            onSpawnSession={async (opts) => {
              setSpawning(true);
              setSpawnError(null);
              try {
                const node = await spawnSession(opts);
                dispatch({ type: "SELECT_NODE", nodeId: node.id });
                setOptionsOpen(false);
              } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                setSpawnError(msg);
              } finally {
                setSpawning(false);
              }
            }}
            onSpawnClaudeSession={async (opts) => {
              setSpawning(true);
              setSpawnError(null);
              try {
                const node = await spawnClaudeSession(opts);
                dispatch({ type: "SELECT_NODE", nodeId: node.id });
                setOptionsOpen(false);
              } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                setSpawnError(msg);
              } finally {
                setSpawning(false);
              }
            }}
            getDropPosition={getDropPosition}
          />
        )}
      </div>

      {/* Thin separator */}
      <div className="w-px h-3 bg-[#1a1f2e] mx-1" />

      {/* --- Tertiary: Layout + Note actions (icon-only, tight) --- */}
      <div className="flex items-center gap-0">
        <IconButton icon={IconNote} onClick={handleNewNote} title="Add Note" />
        <IconButton icon={IconLayoutDistributeHorizontal} onClick={handleAutoLayout} title="Auto Layout" />
        <IconButton icon={IconFocusCentered} onClick={handleGather} title="Gather" />
        <IconButton icon={IconPlayerPlay} onClick={handleFollowActive} title="Follow Active" />
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Error toast (inline, minimal) */}
      {spawnError && (
        <span className="text-[9px] font-mono text-[#e74c3c] truncate max-w-[180px] mr-2">
          {spawnError}
          <button
            className="ml-1 text-[#e74c3c60] hover:text-[#e74c3c]"
            onClick={() => setSpawnError(null)}
            aria-label="Dismiss error"
          >
            x
          </button>
        </span>
      )}

      {/* Session limit (text only) */}
      {!canSpawnMore && (
        <span
          className="text-[8px] font-mono text-[#3d4250] mr-2 tabular-nums"
          title={`Maximum of ${MAX_ACTIVE_TERMINALS} concurrent sessions reached`}
        >
          {MAX_ACTIVE_TERMINALS}/{MAX_ACTIVE_TERMINALS}
        </span>
      )}

      {/* Zoom (icon-only, tight group) */}
      <div className="flex items-center gap-0">
        <IconButton icon={IconZoomOut} onClick={handleZoomOut} title="Zoom out" />
        <IconButton icon={IconZoomReset} onClick={handleResetZoom} title="Reset zoom" />
        <IconButton icon={IconZoomIn} onClick={handleZoomIn} title="Zoom in" />
      </div>

      {/* Thin separator */}
      <div className="w-px h-3 bg-[#1a1f2e] mx-1" />

      {/* --- Danger: Clear (icon-only, subdued, far right) --- */}
      <button
        onClick={clearBoard}
        className="p-1 rounded text-[#1e2230] hover:text-[#e74c3c] hover:bg-[#e74c3c08] transition-colors"
        title="Clear board"
        aria-label="Clear board"
      >
        <IconTrash size={11} stroke={1.5} />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Icon-only toolbar button (tertiary actions)
// ---------------------------------------------------------------------------

function IconButton({
  icon: Icon,
  onClick,
  title,
  disabled = false,
}: {
  icon: typeof IconTerminal2;
  onClick: () => void;
  title: string;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "p-1.5 rounded transition-colors",
        disabled
          ? "opacity-20 cursor-not-allowed text-[#3d4250]"
          : "text-[#3d4250] hover:text-[#6f7f9a] hover:bg-[#ffffff06]",
      )}
      title={title}
      aria-label={title}
    >
      <Icon size={12} stroke={1.5} />
    </button>
  );
}

// ---------------------------------------------------------------------------
// Session Options Popover
// ---------------------------------------------------------------------------

function SessionOptionsPopover({
  repoRoot,
  spawning,
  canSpawnMore,
  onSpawnSession,
  onSpawnClaudeSession,
  getDropPosition,
}: {
  repoRoot: string;
  spawning: boolean;
  canSpawnMore: boolean;
  onSpawnSession: (opts: SpawnSessionOptions) => Promise<void>;
  onSpawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<void>;
  getDropPosition: () => { x: number; y: number };
}) {
  const [shell, setShell] = useState("zsh");
  const [cwd, setCwd] = useState(repoRoot || "");
  const [useWorktree, setUseWorktree] = useState(true);
  const [initialCommand, setInitialCommand] = useState("");
  const [branch, setBranch] = useState("");
  const [prompt, setPrompt] = useState("");
  const [mode, setMode] = useState<"terminal" | "claude">("claude");

  const handleSpawn = useCallback(async () => {
    if (spawning || !canSpawnMore) return;
    const position = getDropPosition();

    if (mode === "claude") {
      await onSpawnClaudeSession({
        cwd: cwd || undefined,
        position,
        worktree: useWorktree,
        branch: branch || undefined,
        prompt: prompt || undefined,
      });
    } else {
      await onSpawnSession({
        cwd: cwd || repoRoot || "/tmp",
        position,
        shell: shell === "bash" ? "/bin/bash" : undefined,
        command: initialCommand ? initialCommand + "\n" : undefined,
      });
    }
  }, [
    spawning,
    canSpawnMore,
    mode,
    cwd,
    shell,
    useWorktree,
    branch,
    prompt,
    initialCommand,
    repoRoot,
    getDropPosition,
    onSpawnSession,
    onSpawnClaudeSession,
  ]);

  return (
    <div
      className="absolute top-full left-0 mt-1 z-[100] min-w-[280px] bg-[#0c0e14] border border-[#1a1f2e] rounded-lg shadow-[0_8px_32px_rgba(0,0,0,0.6)] p-3"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="text-[9px] font-mono text-[#3d4250] uppercase tracking-[0.15em] mb-3">
        Session Options
      </div>

      {/* Mode toggle */}
      <div className="flex gap-1 mb-3">
        <button
          className={cn(
            "flex-1 px-2 py-1.5 rounded text-[10px] font-mono font-medium transition-colors",
            mode === "claude"
              ? "bg-[#d4a84b20] text-[#d4a84b] border border-[#d4a84b40]"
              : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
          )}
          onClick={() => setMode("claude")}
          aria-label="Claude mode"
        >
          Claude
        </button>
        <button
          className={cn(
            "flex-1 px-2 py-1.5 rounded text-[10px] font-mono font-medium transition-colors",
            mode === "terminal"
              ? "bg-[#5b8def20] text-[#5b8def] border border-[#5b8def40]"
              : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
          )}
          onClick={() => setMode("terminal")}
          aria-label="Terminal mode"
        >
          Terminal
        </button>
      </div>

      {/* Working directory */}
      <label className="block mb-2">
        <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
          Working Directory
        </span>
        <input
          type="text"
          value={cwd}
          onChange={(e) => setCwd(e.target.value)}
          placeholder={repoRoot || "/path/to/project"}
          className="mt-1 w-full px-2 py-1.5 bg-[#0b0d13] border border-[#2d3240] rounded text-[10px] font-mono text-[#ece7dc] placeholder-[#3d4250] focus:border-[#d4a84b40] focus:outline-none"
        />
      </label>

      {/* Mode-specific options */}
      {mode === "claude" ? (
        <>
          <label className="flex items-center gap-2 mb-2 cursor-pointer">
            <input
              type="checkbox"
              checked={useWorktree}
              onChange={(e) => setUseWorktree(e.target.checked)}
              className="w-3 h-3 rounded border-[#2d3240] bg-[#0b0d13] accent-[#d4a84b]"
            />
            <span className="text-[10px] font-mono text-[#ece7dc]">
              Isolate in worktree
            </span>
          </label>

          {useWorktree && (
            <label className="block mb-2">
              <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
                Branch Name
              </span>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="auto-generated"
                className="mt-1 w-full px-2 py-1.5 bg-[#0b0d13] border border-[#2d3240] rounded text-[10px] font-mono text-[#ece7dc] placeholder-[#3d4250] focus:border-[#d4a84b40] focus:outline-none"
              />
            </label>
          )}

          <label className="block mb-3">
            <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
              Initial Prompt
            </span>
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Optional: what should Claude work on?"
              rows={2}
              className="mt-1 w-full px-2 py-1.5 bg-[#0b0d13] border border-[#2d3240] rounded text-[10px] font-mono text-[#ece7dc] placeholder-[#3d4250] focus:border-[#d4a84b40] focus:outline-none resize-none"
            />
          </label>
        </>
      ) : (
        <>
          <label className="block mb-2">
            <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
              Shell
            </span>
            <div className="flex gap-1 mt-1">
              {(["zsh", "bash"] as const).map((s) => (
                <button
                  key={s}
                  className={cn(
                    "flex-1 px-2 py-1 rounded text-[10px] font-mono transition-colors",
                    shell === s
                      ? "bg-[#5b8def20] text-[#5b8def] border border-[#5b8def40]"
                      : "bg-[#0b0d13] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
                  )}
                  onClick={() => setShell(s)}
                  aria-label={`${s} shell`}
                >
                  {s}
                </button>
              ))}
            </div>
          </label>

          <label className="block mb-3">
            <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
              Initial Command
            </span>
            <input
              type="text"
              value={initialCommand}
              onChange={(e) => setInitialCommand(e.target.value)}
              placeholder="e.g., cargo test --workspace"
              className="mt-1 w-full px-2 py-1.5 bg-[#0b0d13] border border-[#2d3240] rounded text-[10px] font-mono text-[#ece7dc] placeholder-[#3d4250] focus:border-[#d4a84b40] focus:outline-none"
            />
          </label>
        </>
      )}

      {/* Spawn button */}
      <button
        onClick={handleSpawn}
        disabled={spawning || !canSpawnMore}
        className={cn(
          "w-full px-3 py-2 rounded-md text-[11px] font-syne font-semibold uppercase tracking-wider transition-colors",
          spawning || !canSpawnMore
            ? "bg-[#2d3240] text-[#6f7f9a] cursor-not-allowed"
            : mode === "claude"
              ? "bg-[#d4a84b] text-[#0b0d13] hover:bg-[#e8c06a]"
              : "bg-[#5b8def] text-[#0b0d13] hover:bg-[#7ba4f5]",
        )}
        aria-label={mode === "claude" ? "Launch Claude session" : "Launch terminal session"}
      >
        {spawning ? "Spawning..." : mode === "claude" ? "Launch Claude" : "Launch Terminal"}
      </button>
    </div>
  );
}
