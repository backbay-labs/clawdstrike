import { describe, expect, test } from "bun:test"
import { buildInteractiveSessionCommand } from "../src/tui/interactive-command"

describe("interactive session command builder", () => {
  test("builds the current Codex interactive CLI command", () => {
    expect(
      buildInteractiveSessionCommand("codex", "/tmp/worktree", "Reply with exactly OK"),
    ).toEqual([
      "codex",
      "-a",
      "never",
      "-s",
      "workspace-write",
      "-C",
      "/tmp/worktree",
      "Reply with exactly OK",
    ])
  })

  test("builds the Claude interactive CLI command with bypassed permissions", () => {
    expect(
      buildInteractiveSessionCommand("claude", "/tmp/worktree", "Reply with exactly OK"),
    ).toEqual([
      "claude",
      "--permission-mode",
      "bypassPermissions",
      "--allowedTools",
      "Read,Glob,Grep,Edit,Write,Bash",
      "Reply with exactly OK",
    ])
  })
})
