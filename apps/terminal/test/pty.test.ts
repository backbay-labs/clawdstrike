import { describe, expect, test } from "bun:test"
import { buildAttachLauncherScript } from "../src/tui/pty"
import { createManagedRun } from "../src/tui/runs"

describe("attach launcher", () => {
  test("renders a Claude-specific handoff banner before exec", () => {
    const run = createManagedRun({
      prompt: "reply with ok",
      action: "dispatch",
      agentId: "claude",
      agentLabel: "Claude",
      mode: "attach",
    })

    const script = buildAttachLauncherScript(
      run,
      "/tmp/workcell",
      ["claude", "--permission-mode", "bypassPermissions", "reply with ok"],
    )

    expect(script).toContain("ClawdStrike interactive attach")
    expect(script).toContain("Agent: Claude")
    expect(script).toContain("Staged task:")
    expect(script).toContain("reply with ok")
    expect(script).toContain("Claude interactive sessions start at a blank prompt")
    expect(script).toContain("printf '\\033[2J\\033[3J\\033[H'")
    expect(script).toContain("exec 'claude' '--permission-mode' 'bypassPermissions' 'reply with ok'")
  })

  test("renders a direct attach handoff for Codex", () => {
    const run = createManagedRun({
      prompt: "Reply with exactly OK",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "attach",
    })

    const script = buildAttachLauncherScript(
      run,
      "/tmp/workcell",
      ["codex", "-a", "never", "-s", "workspace-write", "-C", "/tmp/workcell", "Reply with exactly OK"],
    )

    expect(script).toContain("The agent is attached to this terminal.")
    expect(script).toContain("exec 'codex' '-a' 'never' '-s' 'workspace-write' '-C' '/tmp/workcell' 'Reply with exactly OK'")
  })
})
