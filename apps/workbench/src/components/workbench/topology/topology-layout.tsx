import { useSearchParams } from "react-router-dom";
import { IconSitemap, IconBinaryTree2 } from "@tabler/icons-react";
import { DelegationPage } from "../delegation/delegation-page";
import { HierarchyPage } from "../hierarchy/hierarchy-page";

type TabId = "delegation" | "hierarchy";

const TABS: { id: TabId; label: string; icon: typeof IconSitemap }[] = [
  { id: "delegation", label: "Delegation", icon: IconSitemap },
  { id: "hierarchy", label: "Hierarchy", icon: IconBinaryTree2 },
];

export function TopologyLayout() {
  const [searchParams, setSearchParams] = useSearchParams();

  const rawTab = searchParams.get("tab");
  const activeTab: TabId =
    rawTab === "hierarchy" ? "hierarchy" : "delegation";

  function selectTab(tab: TabId) {
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
      {/* Tab bar */}
      <div className="border-b border-[#2d3240] bg-[#0b0d13] px-5 py-0 flex items-center gap-0">
        {TABS.map(({ id, label, icon: Icon }) => {
          const isActive = activeTab === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => selectTab(id)}
              className={`px-4 py-2.5 text-[11px] font-mono uppercase tracking-wider flex items-center gap-1.5 border-b-2 transition-colors ${
                isActive
                  ? "text-[#ece7dc] border-[#d4a84b]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc]/70 border-transparent"
              }`}
            >
              <Icon size={14} stroke={1.5} />
              {label}
            </button>
          );
        })}
      </div>

      {/* Active tab content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "delegation" ? <DelegationPage /> : <HierarchyPage />}
      </div>
    </div>
  );
}
