/**
 * SwarmBoardToolbar — top bar with session spawning, layout, and zoom controls.
 *
 * Session buttons spawn real PTY sessions via the Tauri backend:
 * - "New Claude Session" (primary, gold accent) — Claude Code in an isolated worktree
 * - "New Terminal" — plain shell at repo root
 * - "Worktree" — shell in a new git worktree
 *
 * The dropdown chevron opens an advanced session options popover for configuring
 * shell type, working directory, worktree isolation, and initial commands.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useReactFlow } from "@xyflow/react";
import {
  IconTerminal2,
  IconNote,
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
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { isDesktop } from "@/lib/tauri-bridge";
import {
  useSwarmBoard,
  MAX_ACTIVE_TERMINALS,
  type SpawnSessionOptions,
  type SpawnClaudeSessionOptions,
} from "@/lib/workbench/swarm-board-store";
import { useTerminalSessions } from "@/lib/workbench/use-terminal-sessions";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SwarmBoardToolbar() {
  const { addNode, clearBoard, state, dispatch } = useSwarmBoard();
  const {
    spawnSession,
    spawnClaudeSession,
    spawnWorktreeSession,
    activeSessionCount,
    canSpawnMore,
    hasRepoRoot,
  } = useTerminalSessions();
  const reactFlow = useReactFlow();
  const [spawning, setSpawning] = useState(false);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [spawnError, setSpawnError] = useState<string | null>(null);
  const [workspaceInput, setWorkspaceInput] = useState(false);
  const [workspaceInputValue, setWorkspaceInputValue] = useState("");
  const optionsRef = useRef<HTMLDivElement>(null);

  // Whether we are running inside Tauri desktop
  const desktop = isDesktop();

  // Get a sensible position for new nodes (center of viewport)
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

  // Clear error after 5 seconds
  useEffect(() => {
    if (!spawnError) return;
    const t = setTimeout(() => setSpawnError(null), 5000);
    return () => clearTimeout(t);
  }, [spawnError]);

  // Close options popover on click-outside or Escape
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
      console.error("[SwarmBoardToolbar] Failed to spawn terminal:", msg);
      setSpawnError(`Terminal: ${msg}`);
      // Fallback mock node for development without Tauri
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
        worktree: hasRepoRoot, // use worktree isolation when repo is configured
      });
      dispatch({ type: "SELECT_NODE", nodeId: node.id });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[SwarmBoardToolbar] Failed to spawn Claude session:", msg);
      setSpawnError(`Claude: ${msg}`);
      // Fallback mock node for development without Tauri
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
      console.error("[SwarmBoardToolbar] Failed to spawn worktree session:", msg);
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

    // Smart grouped layout: spatial zones by node type
    const sessions = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "agentSession");
    const tasks = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "terminalTask");
    const receipts = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "receipt");
    const diffs = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "diff");
    const artifacts = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "artifact");
    const notes = nodes.filter((n) => (n.data as Record<string, unknown>).nodeType === "note");

    const positions = new Map<string, { x: number; y: number }>();

    // Top zone: agent sessions (wide spacing, prominent)
    sessions.forEach((n, i) => {
      positions.set(n.id, { x: i * 500, y: 0 });
    });

    // Middle zone: tasks (narrower spacing, below sessions)
    tasks.forEach((n, i) => {
      positions.set(n.id, { x: i * 350 + 80, y: 380 });
    });

    // Lower zone: receipts and diffs (evidence cluster)
    const evidenceNodes = [...receipts, ...diffs];
    evidenceNodes.forEach((n, i) => {
      positions.set(n.id, { x: i * 320, y: 550 });
    });

    // Right zone: artifacts (small, clustered vertically)
    artifacts.forEach((n, i) => {
      positions.set(n.id, { x: sessions.length * 500 + 100, y: i * 130 });
    });

    // Far right: notes (generous offset)
    notes.forEach((n, i) => {
      positions.set(n.id, {
        x: sessions.length * 500 + 100,
        y: evidenceNodes.length > 0 ? 550 + i * 200 : i * 200,
      });
    });

    const updated = nodes.map((node) => ({
      ...node,
      position: positions.get(node.id) ?? node.position,
    }));

    dispatch({ type: "SET_NODES", nodes: updated });
    setTimeout(() => {
      reactFlow.fitView({ padding: 0.15, duration: 400 });
    }, 50);
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
      // Show text input fallback in browser
      setWorkspaceInput(true);
      return;
    }
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({ directory: true, title: "Select Workspace Root" });
      if (selected && typeof selected === "string") {
        dispatch({ type: "SET_REPO_ROOT", repoRoot: selected });
      }
    } catch (err) {
      console.error("[SwarmBoardToolbar] Folder picker failed:", err);
      // Fall back to text input
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

  // Build tooltip for disabled spawn buttons
  const spawnTooltip = !desktop
    ? "Tauri desktop app required for live sessions"
    : !canSpawnMore
      ? `Session limit reached (${MAX_ACTIVE_TERMINALS})`
      : undefined;

  return (
    <div
      className="flex items-center gap-0.5 px-3 py-1.5 shrink-0 select-none"
      style={{
        backgroundColor: "#090b10",
        borderBottom: "1px solid #1a1f2e",
      }}
    >
      {/* Board title / repo root */}
      <div className="flex items-center gap-2 mr-2 min-w-0">
        <IconFolder size={12} stroke={1.5} className="text-[#d4a84b] shrink-0" />
        <span className="text-[11px] font-syne font-semibold text-[#ece7dc] tracking-wide">
          SwarmBoard
        </span>
        {state.repoRoot ? (
          <span className="text-[9px] text-[#1e2230] font-mono truncate max-w-[180px]">
            {state.repoRoot}
          </span>
        ) : !workspaceInput ? (
          <button
            onClick={handlePickWorkspace}
            className="text-[9px] font-mono text-[#d4a84b] hover:text-[#e8c06a] transition-colors underline underline-offset-2"
            title="Set the workspace root directory"
            aria-label="Set Workspace"
          >
            Set Workspace
          </button>
        ) : null}
        {/* Inline workspace path input (fallback when no native dialog) */}
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
              className="w-[160px] px-1.5 py-0.5 bg-[#0b0d13] border border-[#2d3240] rounded text-[9px] font-mono text-[#ece7dc] placeholder-[#3d4250] focus:border-[#d4a84b40] focus:outline-none"
              autoFocus
              onBlur={() => {
                // Dismiss if empty
                if (!workspaceInputValue.trim()) {
                  setWorkspaceInput(false);
                }
              }}
            />
            <button
              type="submit"
              className="text-[9px] font-mono text-[#d4a84b] hover:text-[#e8c06a]"
            >
              OK
            </button>
          </form>
        )}
        {activeSessionCount > 0 && (
          <span className="flex items-center gap-1 text-[9px] font-mono text-[#3dbf84]">
            <span
              className="w-1 h-1 rounded-full bg-[#3dbf84]"
              style={{ animation: "pulse 2s ease-in-out infinite" }}
            />
            {activeSessionCount}
          </span>
        )}
      </div>

      {/* Separator */}
      <div className="w-px h-4 bg-[#1a1f2e] mx-1.5" />

      {/* Primary action: New Claude Session (gold accent, visually distinct) */}
      <button
        onClick={handleNewClaudeSession}
        disabled={spawning || !canSpawnMore}
        className={cn(
          "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[10px] font-syne font-semibold uppercase tracking-wider transition-all",
          spawning || !canSpawnMore
            ? "opacity-40 cursor-not-allowed text-[#d4a84b60]"
            : "text-[#d4a84b] hover:bg-[#d4a84b12] hover:text-[#e8c06a] active:bg-[#d4a84b18]",
        )}
        title={spawning || !canSpawnMore ? spawnTooltip : "New Claude Session"}
        aria-label="New Claude Session"
      >
        <IconRobot size={14} stroke={1.5} />
        <span className="hidden sm:inline">{spawning ? "Spawning..." : "New Claude Session"}</span>
      </button>

      {/* New Terminal */}
      <ToolbarButton
        icon={IconTerminal2}
        label={spawning ? "Spawning..." : "New Terminal"}
        onClick={handleNewTerminal}
        disabled={spawning || !canSpawnMore}
        tooltip={spawnTooltip}
      />

      {/* New Worktree Session */}
      <ToolbarButton
        icon={IconGitBranch}
        label={spawning ? "Spawning..." : "Worktree"}
        onClick={handleNewWorktreeSession}
        disabled={spawning || !canSpawnMore || !hasRepoRoot}
        tooltip={
          !hasRepoRoot
            ? "Set a workspace root first"
            : spawnTooltip
        }
      />

      {/* Session options dropdown */}
      <div className="relative" ref={optionsRef}>
        <ToolbarButton
          icon={IconChevronDown}
          onClick={() => setOptionsOpen(!optionsOpen)}
        />
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

      {/* Separator */}
      <div className="w-px h-4 bg-[#1a1f2e] mx-1.5" />

      {/* Add Note */}
      <ToolbarButton
        icon={IconNote}
        label="Add Note"
        onClick={handleNewNote}
      />

      {/* Separator */}
      <div className="w-px h-4 bg-[#1a1f2e] mx-1.5" />

      {/* Layout actions */}
      <ToolbarButton
        icon={IconLayoutDistributeHorizontal}
        label="Auto Layout"
        onClick={handleAutoLayout}
      />
      <ToolbarButton
        icon={IconFocusCentered}
        label="Gather"
        onClick={handleGather}
      />
      <ToolbarButton
        icon={IconPlayerPlay}
        label="Follow Active"
        onClick={handleFollowActive}
      />

      {/* Spacer */}
      <div className="flex-1" />

      {/* Error toast */}
      {spawnError && (
        <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#e74c3c08] mr-2">
          <span className="text-[9px] font-mono text-[#e74c3c] truncate max-w-[180px]">
            {spawnError}
          </span>
          <button
            className="text-[#e74c3c60] hover:text-[#e74c3c] text-[10px]"
            onClick={() => setSpawnError(null)}
          >
            x
          </button>
        </div>
      )}

      {/* Session limit badge */}
      {!canSpawnMore && (
        <span
          className="text-[8px] font-mono text-[#d4a84b60] mr-2 uppercase tracking-wider"
          title={`Maximum of ${MAX_ACTIVE_TERMINALS} concurrent sessions reached`}
        >
          max sessions
        </span>
      )}

      {/* Zoom controls */}
      <ToolbarButton icon={IconZoomOut} onClick={handleZoomOut} />
      <ToolbarButton icon={IconZoomReset} onClick={handleResetZoom} />
      <ToolbarButton icon={IconZoomIn} onClick={handleZoomIn} />

      {/* Separator */}
      <div className="w-px h-4 bg-[#1a1f2e] mx-1.5" />

      {/* Clear */}
      <ToolbarButton
        icon={IconTrash}
        label="Clear"
        onClick={clearBoard}
        danger
      />
    </div>
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
          {/* Worktree toggle */}
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

          {/* Branch name (for worktree) */}
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

          {/* Initial prompt */}
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
          {/* Shell selection */}
          <label className="block mb-2">
            <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
              Shell
            </span>
            <div className="flex gap-1 mt-1">
              {["zsh", "bash"].map((s) => (
                <button
                  key={s}
                  className={cn(
                    "flex-1 px-2 py-1 rounded text-[10px] font-mono transition-colors",
                    shell === s
                      ? "bg-[#5b8def20] text-[#5b8def] border border-[#5b8def40]"
                      : "bg-[#0b0d13] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
                  )}
                  onClick={() => setShell(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </label>

          {/* Initial command */}
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
      >
        {spawning ? "Spawning..." : mode === "claude" ? "Launch Claude" : "Launch Terminal"}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reusable toolbar button
// ---------------------------------------------------------------------------

function ToolbarButton({
  icon: Icon,
  label,
  onClick,
  danger = false,
  disabled = false,
  highlight = false,
  tooltip,
}: {
  icon: typeof IconTerminal2;
  label?: string;
  onClick: () => void;
  danger?: boolean;
  disabled?: boolean;
  highlight?: boolean;
  /** Override the native title tooltip (e.g. to explain why the button is disabled). */
  tooltip?: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "flex items-center gap-1.5 px-2 py-1.5 rounded-md text-[10px] font-mono font-medium transition-colors",
        disabled && "opacity-30 cursor-not-allowed",
        danger
          ? "text-[#3d4250] hover:text-[#e74c3c] hover:bg-[#e74c3c08]"
          : highlight
            ? "text-[#d4a84b] hover:text-[#e8c06a] hover:bg-[#d4a84b10]"
            : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#ffffff06]",
      )}
      title={disabled && tooltip ? tooltip : label}
      aria-label={label}
    >
      <Icon size={12} stroke={1.5} />
      {label && <span className="hidden sm:inline">{label}</span>}
    </button>
  );
}
