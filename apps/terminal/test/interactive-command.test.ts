import { describe, expect, test } from "bun:test"
import { buildInteractiveSessionCommand } from "../src/tui/interactive-command"

describe("interactive session command builder", () => {
  test("builds the current Codex interactive CLI command without leaking the prompt in argv", () => {
    expect(
      buildInteractiveSessionCommand("codex", "/tmp/worktree"),
    ).toEqual([
      "codex",
      "-a",
      "never",
      "-s",
      "workspace-write",
      "-C",
      "/tmp/worktree",
    ])
  })

  test("builds the Claude interactive CLI command with bypassed permissions only in isolated sandboxes", () => {
    expect(
      buildInteractiveSessionCommand("claude", "/tmp/worktree", { sandboxMode: "worktree" }),
    ).toEqual([
      "claude",
      "--permission-mode",
      "bypassPermissions",
      "--allowedTools",
      "Read,Glob,Grep,Edit,Write,Bash",
    ])

    expect(
      buildInteractiveSessionCommand("claude", "/tmp/worktree", { sandboxMode: "inplace" }),
    ).toEqual([
      "claude",
      "--allowedTools",
      "Read,Glob,Grep,Edit,Write,Bash",
    ])
  })
})
