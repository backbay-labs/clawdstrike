import { useSearchParams } from "react-router-dom";
import { IconSitemap, IconBinaryTree2 } from "@tabler/icons-react";
import { SegmentedControl, type SegmentedTab } from "../shared/segmented-control";
import { DelegationPage } from "../delegation/delegation-page";
import { HierarchyPage } from "../hierarchy/hierarchy-page";

type TabId = "delegation" | "hierarchy";

const TABS: SegmentedTab[] = [
  { id: "delegation", label: "Delegation", icon: IconSitemap },
  { id: "hierarchy", label: "Hierarchy", icon: IconBinaryTree2 },
];

export function TopologyLayout() {
  const [searchParams, setSearchParams] = useSearchParams();

  const rawTab = searchParams.get("tab");
  const activeTab: TabId =
    rawTab === "hierarchy" ? "hierarchy" : "delegation";

  function selectTab(tab: string) {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (tab === "delegation") {
          next.delete("tab");
        } else {
          next.set("tab", tab);
        }
        return next;
      },
      { replace: true },
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Segmented control for page-level mode switching */}
      <SegmentedControl
        tabs={TABS}
        activeTab={activeTab}
        onTabChange={selectTab}
      />

      {/* Active tab content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "delegation" ? <DelegationPage /> : <HierarchyPage />}
      </div>
    </div>
  );
}
