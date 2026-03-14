import { useSearchParams } from "react-router-dom";
import { useCallback } from "react";
import { IconSearch, IconCrosshair } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { HuntLayout } from "../hunt/hunt-layout";
import { SimulatorLayout } from "../simulator/simulator-layout";


type LabTab = "hunt" | "simulate";

function isLabTab(value: string | null): value is LabTab {
  return value === "hunt" || value === "simulate";
}


const tabs: { id: LabTab; label: string; icon: typeof IconSearch }[] = [
  { id: "hunt", label: "Hunt", icon: IconSearch },
  { id: "simulate", label: "Simulate", icon: IconCrosshair },
];


export function LabLayout() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get("tab");
  const activeTab: LabTab = isLabTab(rawTab) ? rawTab : "hunt";

  const handleTabChange = useCallback(
    (tab: LabTab) => {
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
      {/* Lab top-level tab bar */}
      <div className="border-b border-[#2d3240] bg-[#0b0d13] px-5 py-0 flex items-center gap-0 shrink-0">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => handleTabChange(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-2.5 text-xs font-mono font-semibold uppercase tracking-wider transition-all duration-150 border-b-2 -mb-px",
                isActive
                  ? "text-[#ece7dc] border-[#d4a84b]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc]/70 border-transparent",
              )}
            >
              <Icon size={14} stroke={1.5} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Active layout — conditional render so inactive layout unmounts */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "hunt" && <HuntLayout />}
        {activeTab === "simulate" && <SimulatorLayout />}
      </div>
    </div>
  );
}
