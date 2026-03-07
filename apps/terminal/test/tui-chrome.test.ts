import { describe, expect, test } from "bun:test"
import { stripAnsi } from "../src/tui/components/types"
import { renderSurfaceHeader } from "../src/tui/components/surface-header"
import { THEME } from "../src/tui/theme"
import { scrollReportViewport, syncReportViewport } from "../src/tui/report-view"

describe("surface header chrome", () => {
  test("shows explicit stage labels in hunt headers", () => {
    const supported = renderSurfaceHeader("hunt-report", "Evidence Report", 80, THEME)
    const experimental = renderSurfaceHeader("hunt-diff", "Scan Diff", 80, THEME)

    expect(stripAnsi(supported[0])).toContain("[beta]")
    expect(stripAnsi(experimental[0])).toContain("[exp]")
  })
})

describe("report viewport helpers", () => {
  test("keeps expanded evidence visible when it fits", () => {
    const viewport = syncReportViewport(
      { offset: 0, selected: 1 },
      1,
      [
        { start: 0, end: 0 },
        { start: 1, end: 4 },
        { start: 5, end: 5 },
      ],
      4,
    )

    expect(viewport.selected).toBe(1)
    expect(viewport.offset).toBe(1)
  })

  test("clamps manual report scrolling to available lines", () => {
    expect(scrollReportViewport(0, -1, 10, 4)).toBe(0)
    expect(scrollReportViewport(0, 3, 10, 4)).toBe(3)
    expect(scrollReportViewport(3, 10, 10, 4)).toBe(6)
  })
})
