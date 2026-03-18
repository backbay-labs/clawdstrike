import { IconChevronsRight } from "@tabler/icons-react";
import { useRightSidebarStore } from "../stores/right-sidebar-store";
import { SpeakeasyPanel } from "@/components/workbench/speakeasy/speakeasy-panel";
import { SpiritCompanionCanvas } from "@/features/spirit/components/spirit-companion-canvas";
import { cn } from "@/lib/utils";

const PANEL_TABS = [
  { id: "speakeasy" as const, label: "Speakeasy" },
  { id: "spirit" as const, label: "Spirit" },
] satisfies Array<{ id: import("../types").RightSidebarPanel; label: string }>;

export function RightSidebar() {
  const width = useRightSidebarStore.use.width();
  const activePanel = useRightSidebarStore.use.activePanel();
  const actions = useRightSidebarStore.use.actions();

  return (
    <aside
      role="complementary"
      aria-label="Right Sidebar"
      className="shrink-0 flex flex-col bg-[#0b0d13] border-l border-[#1a1d28]/50"
      style={{ width }}
    >
      {/* Panel header with tabs + collapse button */}
      <div className="flex h-8 shrink-0 items-center justify-between border-b border-[#2d3240]/40 px-2">
        <div className="flex items-center gap-1">
          {PANEL_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => actions.setActivePanel(tab.id)}
              className={cn(
                "px-2 py-0.5 text-[12px] font-display font-semibold rounded transition-colors",
                activePanel === tab.id
                  ? "text-[#ece7dc] bg-[#131721]/60"
                  : "text-[#6f7f9a] hover:text-[#ece7dc]/70",
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <button
          type="button"
          aria-label="Collapse right sidebar"
          className="rounded p-0.5 text-[#6f7f9a] transition-colors hover:text-[#ece7dc]"
          onClick={() => actions.hide()}
        >
          <IconChevronsRight size={14} stroke={1.8} />
        </button>
      </div>

      {/* Panel body */}
      {activePanel === "speakeasy" && (
        <SpeakeasyPanel
          inline
          isOpen
          room={null}
          onClose={() => actions.hide()}
        />
      )}
      {activePanel === "spirit" && (
        <div className="flex flex-1 flex-col items-center justify-center gap-3">
          <SpiritCompanionCanvas />
          {/* Shown when no spirit bound (SpiritCompanionCanvas returns null) */}
        </div>
      )}
    </aside>
  );
}
