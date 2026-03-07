import { describe, expect, test } from "bun:test"
import { sanitizeInteractiveOutput } from "../src/tui/pty-runtime"

describe("embedded PTY sanitizer", () => {
  test("preserves small cursor-forward gaps as spaces", () => {
    const lines = sanitizeInteractiveOutput("\x1b[1CHello\x1b[2CWorld")
    expect(lines).toEqual([" Hello  World"])
  })

  test("strips OSC and ANSI control sequences while keeping plain text", () => {
    const lines = sanitizeInteractiveOutput(
      "\x1b]0;title\x07\x1b[31mClaude\x1b[0m Code\r\n\x1b[?25lready",
    )
    expect(lines).toEqual(["Claude Code", "ready"])
  })
})
