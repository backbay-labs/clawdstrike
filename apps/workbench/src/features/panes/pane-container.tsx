import { motion } from "motion/react";
import { cn } from "@/lib/utils";
import { getPaneActiveView } from "./pane-tree";
import { usePaneStore } from "./pane-store";
import { PaneRouteRenderer } from "./pane-route-renderer";
import { PaneTabBar } from "./pane-tab-bar";
import type { PaneGroup } from "./pane-types";
import { BreadcrumbBar } from "@/features/navigation/breadcrumb-bar";

export function PaneContainer({
  pane,
  active,
}: {
  pane: PaneGroup;
  active: boolean;
}) {
  const activeView = getPaneActiveView(pane);

  if (!activeView) {
    return null;
  }

  return (
    <section
      className={cn(
        "flex h-full min-h-0 flex-col overflow-hidden border border-[#1a1d27] bg-[#07090f]",
      )}
      onMouseDownCapture={() => {
        if (!active) {
          usePaneStore.getState().setActivePane(pane.id);
        }
      }}
    >
      <PaneTabBar pane={pane} active={active} />
      <BreadcrumbBar route={activeView.route} />

      <motion.div
        key={activeView.route}
        id={`pane-content-${pane.id}`}
        role="tabpanel"
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.15, ease: "easeOut" }}
        className="relative min-h-0 flex-1 flex flex-col overflow-auto"
      >
        <PaneRouteRenderer route={activeView.route} />
      </motion.div>
    </section>
  );
}
