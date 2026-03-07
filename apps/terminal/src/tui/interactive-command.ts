import type { SandboxMode, Toolchain } from "../types"

const CLAUDE_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Edit", "Write", "Bash"]

export interface EmbeddedInteractiveCommandPlan {
  command: string[]
  launchConsumesPrompt: boolean
  stagedTaskEditable: boolean
}

export interface InteractiveCommandOptions {
  sandboxMode?: SandboxMode
}

function canBypassClaudePermissions(sandboxMode?: SandboxMode): boolean {
  return sandboxMode === "worktree" || sandboxMode === "tmpdir"
}

export function buildInteractiveSessionCommand(
  toolchain: Toolchain,
  worktreePath: string,
  options: InteractiveCommandOptions = {},
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
    ]
  }

  if (toolchain === "claude") {
    const args = ["claude"]
    if (canBypassClaudePermissions(options.sandboxMode)) {
      args.push("--permission-mode", "bypassPermissions")
    }
    args.push("--allowedTools", CLAUDE_ALLOWED_TOOLS.join(","))
    return args
  }

  throw new Error(`Interactive session is not available for ${toolchain}`)
}

export function buildEmbeddedInteractiveSessionCommand(
  toolchain: Toolchain,
  worktreePath: string,
  options: InteractiveCommandOptions = {},
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
      ],
      launchConsumesPrompt: false,
      stagedTaskEditable: false,
    }
  }

  if (toolchain === "claude") {
    const command = ["claude"]
    if (canBypassClaudePermissions(options.sandboxMode)) {
      command.push("--permission-mode", "bypassPermissions")
    }
    command.push("--allowedTools", CLAUDE_ALLOWED_TOOLS.join(","))
    return {
      command,
      launchConsumesPrompt: false,
      stagedTaskEditable: true,
    }
  }

  throw new Error(`Interactive session is not available for ${toolchain}`)
}
