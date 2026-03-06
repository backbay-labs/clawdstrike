import type { Toolchain } from "../types"

const CLAUDE_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Edit", "Write", "Bash"]

export function buildInteractiveSessionCommand(
  toolchain: Toolchain,
  worktreePath: string,
  prompt: string,
): string[] {
  if (toolchain === "codex") {
    return [
      "codex",
      "-a",
      "never",
      "-s",
      "workspace-write",
      "-C",
      worktreePath,
      prompt,
    ]
  }

  if (toolchain === "claude") {
    return [
      "claude",
      "--permission-mode",
      "bypassPermissions",
      "--allowedTools",
      CLAUDE_ALLOWED_TOOLS.join(","),
      prompt,
    ]
  }

  throw new Error(`Interactive session is not available for ${toolchain}`)
}
