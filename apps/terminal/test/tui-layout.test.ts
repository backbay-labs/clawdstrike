import { describe, expect, test } from "bun:test"
import { centerBlock, centerLine, joinColumns, wrapText } from "../src/tui/components/layout"
import { stripAnsi, visibleLength } from "../src/tui/components/types"
import { THEME } from "../src/tui/theme"

describe("tui layout helpers", () => {
  test("centers colored text using visible width", () => {
    const line = `${THEME.accent}Alert${THEME.reset}`
    const centered = centerLine(line, 11)

    expect(stripAnsi(centered)).toBe("   Alert")
    expect(visibleLength(centered)).toBe(8)
  })

  test("centers a block against its widest visible line", () => {
    const block = centerBlock(
      [
        `${THEME.white}Wide Row${THEME.reset}`,
        `${THEME.muted}Narrow${THEME.reset}`,
      ],
      20,
    )

    expect(stripAnsi(block[0])).toBe("      Wide Row")
    expect(stripAnsi(block[1])).toBe("      Narrow")
  })

  test("joins left and right columns without ANSI drift", () => {
    const joined = joinColumns(
      `${THEME.white}security${THEME.reset}`,
      `${THEME.success}ok${THEME.reset}`,
      18,
    )

    expect(stripAnsi(joined)).toBe("security        ok")
    expect(visibleLength(joined)).toBe(18)
  })

  test("wraps colored text using visible width", () => {
    const wrapped = wrapText(
      `${THEME.warning}long label${THEME.reset} ${THEME.white}still visible${THEME.reset}`,
      14,
    )

    expect(wrapped).toEqual([
      `${THEME.warning}long label${THEME.reset}`,
      `${THEME.white}still visible${THEME.reset}`,
    ])
  })
})
