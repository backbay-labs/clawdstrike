import type { Toolchain } from "../types"

const CLAUDE_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Edit", "Write", "Bash"]

export interface EmbeddedInteractiveCommandPlan {
  command: string[]
  launchConsumesPrompt: boolean
  stagedTaskEditable: boolean
}

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

export function buildEmbeddedInteractiveSessionCommand(
  toolchain: Toolchain,
  worktreePath: string,
  prompt: string,
): EmbeddedInteractiveCommandPlan {
  if (toolchain === "codex") {
    return {
      command: [
        "codex",
        "--no-alt-screen",
        "-a",
        "never",
        "-s",
        "workspace-write",
        "-C",
        worktreePath,
        prompt,
      ],
      launchConsumesPrompt: true,
      stagedTaskEditable: false,
    }
  }

  if (toolchain === "claude") {
    return {
      command: [
        "claude",
        "--permission-mode",
        "bypassPermissions",
        "--allowedTools",
        CLAUDE_ALLOWED_TOOLS.join(","),
      ],
      launchConsumesPrompt: false,
      stagedTaskEditable: true,
    }
  }

  throw new Error(`Interactive session is not available for ${toolchain}`)
}
