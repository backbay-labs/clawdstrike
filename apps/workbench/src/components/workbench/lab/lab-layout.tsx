import { useSearchParams } from "react-router-dom";
import { lazy, Suspense, useCallback } from "react";
import { IconSearch, IconCrosshair, IconTopologyStar3 } from "@tabler/icons-react";
import { SegmentedControl, type SegmentedTab } from "../shared/segmented-control";
import { HuntLayout } from "../hunt/hunt-layout";
import { SimulatorLayout } from "../simulator/simulator-layout";

const SwarmBoardPage = lazy(() =>
  import("@/components/workbench/swarm-board/swarm-board-page"),
);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type LabTab = "swarm" | "hunt" | "simulate";

function isLabTab(value: string | null): value is LabTab {
  return value === "swarm" || value === "hunt" || value === "simulate";
}

// ---------------------------------------------------------------------------
// Tab definitions
// ---------------------------------------------------------------------------

const tabs: SegmentedTab[] = [
  { id: "swarm", label: "Swarm", icon: IconTopologyStar3 },
  { id: "hunt", label: "Hunt", icon: IconSearch },
  { id: "simulate", label: "Simulate", icon: IconCrosshair },
];

// ---------------------------------------------------------------------------
// Lab Layout
// ---------------------------------------------------------------------------

export function LabLayout() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get("tab");
  const activeTab: LabTab = isLabTab(rawTab) ? rawTab : "swarm";

  const handleTabChange = useCallback(
    (tab: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (tab === "swarm") {
          next.delete("tab");
        } else {
          next.set("tab", tab);
        }
        return next;
      });
    },
    [setSearchParams],
  );

  return (
    <div className="flex flex-col h-full">
      {/* Segmented control for page-level mode switching */}
      <SegmentedControl
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={handleTabChange}
      />

      {/* Active layout — conditional render so inactive layout unmounts */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "swarm" && (
          <Suspense fallback={<div className="flex-1" />}>
            <SwarmBoardPage />
          </Suspense>
        )}
        {activeTab === "hunt" && <HuntLayout />}
        {activeTab === "simulate" && <SimulatorLayout />}
      </div>
    </div>
  );
}
