import { useCallback, useRef, useState } from "react";
import { useRightSidebarStore } from "../stores/right-sidebar-store";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// RightSidebarResizeHandle -- 4px-wide drag zone between editor area and
// right sidebar. Mirrors the left SidebarResizeHandle with inverted drag
// direction (dragging left increases width).
// ---------------------------------------------------------------------------

export function RightSidebarResizeHandle() {
  const width = useRightSidebarStore.use.width();
  const actions = useRightSidebarStore.use.actions();
  const [dragging, setDragging] = useState(false);
  const startRef = useRef<{ x: number; width: number } | null>(null);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      startRef.current = { x: e.clientX, width };
      setDragging(true);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";

      const handleMouseMove = (moveEvent: MouseEvent) => {
        if (!startRef.current) return;
        // Inverted: dragging LEFT (negative delta) increases width
        const newWidth =
          startRef.current.width - (moveEvent.clientX - startRef.current.x);
        if (newWidth < 200) {
          actions.hide();
        } else {
          actions.setWidth(newWidth);
        }
      };

      const handleMouseUp = () => {
        document.removeEventListener("mousemove", handleMouseMove);
        document.removeEventListener("mouseup", handleMouseUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        startRef.current = null;
        setDragging(false);
      };

      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    },
    [width, actions],
  );

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-valuenow={width}
      aria-valuemin={200}
      aria-valuemax={480}
      onMouseDown={handleMouseDown}
      className={cn(
        "w-1 shrink-0 cursor-col-resize relative group",
        "transition-colors duration-150 ease-in-out",
      )}
    >
      {/* Visible line */}
      <div
        className={cn(
          "absolute inset-y-0 left-1/2 -translate-x-1/2",
          "transition-all duration-150 ease-in-out",
          dragging
            ? "w-[2px] bg-[#d4a84b]/70"
            : "w-px bg-[#2d3240] group-hover:w-[2px] group-hover:bg-[#d4a84b]/40",
        )}
      />
    </div>
  );
}
