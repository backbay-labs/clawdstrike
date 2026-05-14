import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { useTerminalSessions } from "../use-terminal-sessions";

const {
  mockSpawnSession,
  mockSpawnClaudeSession,
  mockSpawnWorktreeSession,
  mockKillSession,
  mockSpawnEngineSession,
  mockSpawnEngineClaudeSession,
  mockSpawnEngineWorktreeSession,
  mockUseSwarmBoardStore,
} = vi.hoisted(() => {
  const mockSpawnSession = vi.fn();
  const mockSpawnClaudeSession = vi.fn();
  const mockSpawnWorktreeSession = vi.fn();
  const mockKillSession = vi.fn();
  const mockSpawnEngineSession = vi.fn();
  const mockSpawnEngineClaudeSession = vi.fn();
  const mockSpawnEngineWorktreeSession = vi.fn();

  const mockUseSwarmBoardStore = Object.assign(
    (selector: (state: { actions: { removeNode: ReturnType<typeof vi.fn> } }) => unknown) =>
      selector({ actions: { removeNode: vi.fn() } }),
    {
      use: {
        repoRoot: () => "/repo",
        nodes: () => [],
      },
    },
  );

  return {
    mockSpawnSession,
    mockSpawnClaudeSession,
    mockSpawnWorktreeSession,
    mockKillSession,
    mockSpawnEngineSession,
    mockSpawnEngineClaudeSession,
    mockSpawnEngineWorktreeSession,
    mockUseSwarmBoardStore,
  };
});

vi.mock("../swarm-board-store", () => ({
  MAX_ACTIVE_TERMINALS: 8,
  useSwarmBoardStore: mockUseSwarmBoardStore,
  useSwarmBoardSession: () => ({
    spawnSession: mockSpawnSession,
    spawnClaudeSession: mockSpawnClaudeSession,
    spawnWorktreeSession: mockSpawnWorktreeSession,
    killSession: mockKillSession,
  }),
}));

vi.mock("@/features/swarm/stores/swarm-engine-provider", () => ({
  useOptionalSwarmEngine: () => ({
    mode: "engine",
    spawnEngineSession: mockSpawnEngineSession,
    spawnEngineClaudeSession: mockSpawnEngineClaudeSession,
    spawnEngineWorktreeSession: mockSpawnEngineWorktreeSession,
  }),
}));

describe("useTerminalSessions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("routes terminal session spawns through the engine wrapper when engine mode is enabled", async () => {
    mockSpawnEngineSession.mockResolvedValue({ id: "node_terminal" });

    const { result } = renderHook(() => useTerminalSessions());
    await result.current.spawnSession({ cwd: "/repo", title: "Terminal" });

    expect(mockSpawnEngineSession).toHaveBeenCalledWith(
      mockSpawnSession,
      expect.objectContaining({ cwd: "/repo", title: "Terminal" }),
    );
    expect(mockSpawnSession).not.toHaveBeenCalled();
  });

  it("routes Claude and worktree spawns through the engine wrapper when engine mode is enabled", async () => {
    mockSpawnEngineClaudeSession.mockResolvedValue({ id: "node_claude" });
    mockSpawnEngineWorktreeSession.mockResolvedValue({ id: "node_worktree" });

    const { result } = renderHook(() => useTerminalSessions());
    await result.current.spawnClaudeSession({ prompt: "review" });
    await result.current.spawnWorktreeSession({ branch: "feat/test" });

    expect(mockSpawnEngineClaudeSession).toHaveBeenCalledWith(
      mockSpawnClaudeSession,
      expect.objectContaining({ prompt: "review" }),
    );
    expect(mockSpawnEngineWorktreeSession).toHaveBeenCalledWith(
      mockSpawnWorktreeSession,
      expect.objectContaining({ branch: "feat/test" }),
    );
    expect(mockSpawnClaudeSession).not.toHaveBeenCalled();
    expect(mockSpawnWorktreeSession).not.toHaveBeenCalled();
  });
});
