import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { useTerminalSessions } from "../use-terminal-sessions";

const {
  mockSpawnSession,
  mockSpawnClaudeSession,
  mockSpawnWorktreeSession,
  mockKillSession,
  mockUseSwarmBoard,
} = vi.hoisted(() => {
  const mockSpawnSession = vi.fn();
  const mockSpawnClaudeSession = vi.fn();
  const mockSpawnWorktreeSession = vi.fn();
  const mockKillSession = vi.fn();

  const mockUseSwarmBoard = vi.fn(() => ({
    state: { repoRoot: "/repo", nodes: [] },
    removeNode: vi.fn(),
    spawnSession: mockSpawnSession,
    spawnClaudeSession: mockSpawnClaudeSession,
    spawnWorktreeSession: mockSpawnWorktreeSession,
    killSession: mockKillSession,
  }));

  return {
    mockSpawnSession,
    mockSpawnClaudeSession,
    mockSpawnWorktreeSession,
    mockKillSession,
    mockUseSwarmBoard,
  };
});

vi.mock("../swarm-board-store", () => ({
  MAX_TOTAL_SESSIONS: 64,
  useSwarmBoard: mockUseSwarmBoard,
}));

describe("useTerminalSessions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("delegates terminal spawns through the board session API", async () => {
    mockSpawnSession.mockResolvedValue({ id: "node_terminal" });

    const { result } = renderHook(() => useTerminalSessions());
    await result.current.spawnSession({ cwd: "/repo", title: "Terminal" });

    expect(mockSpawnSession).toHaveBeenCalledWith(
      expect.objectContaining({ cwd: "/repo", title: "Terminal" }),
    );
  });

  it("delegates Claude and worktree spawns through the board session API", async () => {
    mockSpawnClaudeSession.mockResolvedValue({ id: "node_claude" });
    mockSpawnWorktreeSession.mockResolvedValue({ id: "node_worktree" });

    const { result } = renderHook(() => useTerminalSessions());
    await result.current.spawnClaudeSession({ prompt: "review" });
    await result.current.spawnWorktreeSession({ branch: "feat/test" });

    expect(mockSpawnClaudeSession).toHaveBeenCalledWith(
      expect.objectContaining({ prompt: "review" }),
    );
    expect(mockSpawnWorktreeSession).toHaveBeenCalledWith(
      expect.objectContaining({ branch: "feat/test" }),
    );
  });

  it("uses the plain Claude helper without forcing a worktree", async () => {
    mockSpawnClaudeSession.mockResolvedValue({ id: "node_claude" });

    const { result } = renderHook(() => useTerminalSessions());
    await result.current.spawnClaude({ x: 10, y: 20 });

    expect(mockSpawnClaudeSession).toHaveBeenCalledWith({
      position: { x: 10, y: 20 },
    });
  });

  it("keeps worktree isolation behind the explicit Claude worktree helper", async () => {
    mockSpawnClaudeSession.mockResolvedValue({ id: "node_claude_worktree" });

    const { result } = renderHook(() => useTerminalSessions());
    await result.current.spawnClaudeInWorktree({ x: 1, y: 2 }, "feat/worktree", "review");

    expect(mockSpawnClaudeSession).toHaveBeenCalledWith({
      position: { x: 1, y: 2 },
      worktree: true,
      branch: "feat/worktree",
      prompt: "review",
    });
  });
});
