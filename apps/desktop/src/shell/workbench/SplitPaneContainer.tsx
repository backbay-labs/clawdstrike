/**
 * SplitPaneContainer - Manages 1-3 vertical split panes, each with its own TabBar + TabContentRenderer.
 *
 * - Single pane: no resize chrome, renders TabBar + TabContentRenderer directly.
 * - Multi-pane: drag handles between panes with 200px min width.
 * - Pane collapses when its last tab closes (via reducer REMOVE_TAB_GROUP).
 * - Focused pane has a subtle gold top border and receives keyboard shortcuts.
 */
import { useCallback, useRef, useState } from "react";
import { useWorkbench, useWorkbenchDispatch } from "./WorkbenchStateProvider";
import { TabBar } from "./TabBar";
import { TabContentRenderer } from "./TabContentRenderer";

const MIN_PANE_WIDTH_PX = 200;

export function SplitPaneContainer() {
  const { state } = useWorkbench();
  const dispatch = useWorkbenchDispatch();
  const { tabGroups } = state;

  const [focusedGroupId, setFocusedGroupId] = useState<string>(
    tabGroups[0]?.id ?? "main",
  );

  // Flex ratios for each pane (local state — too noisy for localStorage)
  const [flexRatios, setFlexRatios] = useState<number[]>(() =>
    tabGroups.map(() => 1),
  );

  // Keep flex ratios in sync with tabGroups length
  const syncedRatios = tabGroups.length === flexRatios.length
    ? flexRatios
    : tabGroups.map((_, i) => flexRatios[i] ?? 1);

  const containerRef = useRef<HTMLDivElement>(null);

  // -- Resize drag handling --
  const handleResizeStart = useCallback(
    (e: React.PointerEvent, handleIndex: number) => {
      e.preventDefault();
      const container = containerRef.current;
      if (!container) return;

      const containerWidth = container.getBoundingClientRect().width;
      // Account for handle widths (4px each)
      const handleCount = tabGroups.length - 1;
      const availableWidth = containerWidth - handleCount * 4;

      const totalRatio = syncedRatios.reduce((a, b) => a + b, 0);
      // Convert ratios to pixel widths
      const paneWidths = syncedRatios.map((r) => (r / totalRatio) * availableWidth);

      const startX = e.clientX;
      const leftWidth = paneWidths[handleIndex];
      const rightWidth = paneWidths[handleIndex + 1];

      const onMove = (me: PointerEvent) => {
        const dx = me.clientX - startX;
        const newLeft = Math.max(MIN_PANE_WIDTH_PX, leftWidth + dx);
        const newRight = Math.max(MIN_PANE_WIDTH_PX, rightWidth - dx);

        // Clamp so neither side goes below min
        const clampedLeft = Math.min(newLeft, leftWidth + rightWidth - MIN_PANE_WIDTH_PX);
        const clampedRight = leftWidth + rightWidth - clampedLeft;

        if (clampedLeft < MIN_PANE_WIDTH_PX || clampedRight < MIN_PANE_WIDTH_PX) return;

        setFlexRatios((prev) => {
          const next = [...(prev.length === tabGroups.length ? prev : syncedRatios)];
          // Convert back to ratios
          next[handleIndex] = clampedLeft / availableWidth * totalRatio;
          next[handleIndex + 1] = clampedRight / availableWidth * totalRatio;
          return next;
        });
      };

      const onUp = () => {
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
        document.body.style.cursor = "";
      };

      document.body.style.cursor = "col-resize";
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    },
    [tabGroups.length, syncedRatios],
  );

  const handlePaneFocus = useCallback((groupId: string) => {
    setFocusedGroupId(groupId);
  }, []);

  // Single pane — no resize chrome
  if (tabGroups.length === 1) {
    const group = tabGroups[0];
    return (
      <div
        className="flex h-full flex-col overflow-hidden"
        onClick={() => handlePaneFocus(group.id)}
      >
        <TabBar groupId={group.id} />
        <TabContentRenderer groupId={group.id} />
      </div>
    );
  }

  // Multi-pane layout
  return (
    <div
      ref={containerRef}
      className="flex h-full flex-row overflow-hidden"
    >
      {tabGroups.map((group, index) => {
        const isFocused = group.id === focusedGroupId;
        const ratio = syncedRatios[index] ?? 1;

        return (
          <div key={group.id} className="contents">
            {/* Pane */}
            <div
              className="flex min-w-0 flex-col overflow-hidden"
              style={{
                flex: ratio,
                minWidth: MIN_PANE_WIDTH_PX,
                borderTop: isFocused ? "2px solid rgba(213,173,87,0.6)" : "2px solid transparent",
              }}
              onClick={() => handlePaneFocus(group.id)}
            >
              <TabBar groupId={group.id} />
              <TabContentRenderer groupId={group.id} />
            </div>

            {/* Resize handle between panes */}
            {index < tabGroups.length - 1 && (
              <div
                className="shrink-0 cursor-col-resize transition-colors hover:bg-[rgba(213,173,87,0.3)] active:bg-[var(--origin-gold-dim,#9f7c3a)]"
                style={{
                  width: 4,
                  background: "var(--color-sdr-border-subtle, #212634)",
                }}
                role="separator"
                aria-label="Resize pane"
                onPointerDown={(e) => handleResizeStart(e, index)}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
