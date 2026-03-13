import { useSearchParams } from "react-router-dom";
import { useCallback } from "react";
import { IconSearch, IconCrosshair } from "@tabler/icons-react";
import { SegmentedControl, type SegmentedTab } from "../shared/segmented-control";
import { HuntLayout } from "../hunt/hunt-layout";
import { SimulatorLayout } from "../simulator/simulator-layout";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type LabTab = "hunt" | "simulate";

function isLabTab(value: string | null): value is LabTab {
  return value === "hunt" || value === "simulate";
}

// ---------------------------------------------------------------------------
// Tab definitions
// ---------------------------------------------------------------------------

const tabs: SegmentedTab[] = [
  { id: "hunt", label: "Hunt", icon: IconSearch },
  { id: "simulate", label: "Simulate", icon: IconCrosshair },
];

// ---------------------------------------------------------------------------
// Lab Layout
// ---------------------------------------------------------------------------

export function LabLayout() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get("tab");
  const activeTab: LabTab = isLabTab(rawTab) ? rawTab : "hunt";

  const handleTabChange = useCallback(
    (tab: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (tab === "hunt") {
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
        {activeTab === "hunt" && <HuntLayout />}
        {activeTab === "simulate" && <SimulatorLayout />}
      </div>
    </div>
  );
}
