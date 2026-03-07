import type { ListViewport } from "./components/scrollable-list"

export interface ReportRowSpan {
  start: number
  end: number
}

export function syncReportViewport(
  viewport: ListViewport,
  selectedIndex: number,
  rowSpans: ReportRowSpan[],
  visibleHeight: number,
): ListViewport {
  if (rowSpans.length === 0 || visibleHeight <= 0) {
    return { offset: 0, selected: 0 }
  }

  const selected = Math.max(0, Math.min(selectedIndex, rowSpans.length - 1))
  const span = rowSpans[selected]
  const spanHeight = span.end - span.start + 1
  const lastLine = rowSpans[rowSpans.length - 1]?.end ?? 0
  const maxOffset = Math.max(0, lastLine - visibleHeight + 1)
  let offset = Math.max(0, Math.min(viewport.offset, maxOffset))

  if (span.start < offset) {
    offset = span.start
  } else if (span.start >= offset + visibleHeight) {
    offset = span.start - visibleHeight + 1
  } else if (span.end >= offset + visibleHeight && spanHeight <= visibleHeight) {
    offset = span.end - visibleHeight + 1
  }

  return {
    selected,
    offset: Math.max(0, Math.min(offset, maxOffset)),
  }
}

export function scrollReportViewport(
  offset: number,
  delta: number,
  totalLines: number,
  visibleHeight: number,
): number {
  if (visibleHeight <= 0) {
    return 0
  }

  const maxOffset = Math.max(0, totalLines - visibleHeight)
  return Math.max(0, Math.min(offset + delta, maxOffset))
}
