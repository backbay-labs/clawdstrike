import { describe, expect, it } from "vitest";

import {
  appendTerminalPreviewChunk,
  sanitizeTerminalPreviewLines,
} from "../terminal-preview";

describe("terminal-preview", () => {
  it("strips ANSI escape sequences from preview lines", () => {
    expect(
      sanitizeTerminalPreviewLines([
        "\u001b[38;2;136;136;136mClaude Code v2.1.85\u001b[39m",
        "\u001b[1mOpus 4.6\u001b[22m",
      ]),
    ).toEqual(["Claude Code v2.1.85", "Opus 4.6"]);
  });

  it("handles ANSI sequences split across streamed chunks", () => {
    const first = appendTerminalPreviewChunk([], "\u001b[38;2;136");
    expect(first.lines).toEqual([]);
    expect(first.carry).toBe("\u001b[38;2;136");

    const second = appendTerminalPreviewChunk(first.lines, ";136;136mClaude\n", {
      carry: first.carry,
    });
    expect(second.lines).toEqual(["Claude", ""]);
    expect(second.carry).toBe("");
  });

  it("normalizes carriage returns and backspaces for plain text previews", () => {
    const result = appendTerminalPreviewChunk([], "loading\rready\nabc\b!\n");
    expect(result.lines).toEqual(["loading", "ready", "ab!", ""]);
  });
});
