import { describe, expect, it } from "vitest";
import {
  estimateWorkspaceTerminalViewport,
  selectWorkspaceTerminalSession,
} from "./workspaceTerminalState";

describe("workspaceTerminalState", () => {
  it("estimates a bounded viewport from panel size", () => {
    expect(estimateWorkspaceTerminalViewport(900, 360)).toEqual({ cols: 100, rows: 20 });
    expect(estimateWorkspaceTerminalViewport(0, 0)).toEqual({ cols: 100, rows: 24 });
  });

  it("selects the active session and falls back to the newest session", () => {
    const sessions = [
      {
        sessionId: "s1",
        title: "shell",
        kind: "shell" as const,
        status: "running" as const,
        cwd: ".",
        cols: 80,
        rows: 24,
        output: "",
      },
      {
        sessionId: "s2",
        title: "git status",
        kind: "task" as const,
        status: "exited" as const,
        cwd: ".",
        cols: 80,
        rows: 24,
        output: "",
        exitCode: 0,
      },
    ];

    expect(selectWorkspaceTerminalSession(sessions, "s1")?.title).toBe("shell");
    expect(selectWorkspaceTerminalSession(sessions)?.title).toBe("git status");
  });
});
