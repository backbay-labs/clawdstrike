import type { ReactNode } from "react";
import type { IconActivity } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

/** Icon component type accepted by Tabler Icons. */
type TablerIcon = typeof IconActivity;

export interface PageTab {
  id: string;
  label: string;
  icon?: TablerIcon;
}

interface PageTabBarProps {
  tabs: PageTab[];
  activeTab: string;
  onTabChange: (id: string) => void;
  /** Right-side slot for status indicators, badges, etc. */
  children?: ReactNode;
}

export function PageTabBar({ tabs, activeTab, onTabChange, children }: PageTabBarProps) {
  return (
    <div className="flex items-center justify-between px-1 py-0 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
      {/* Tabs */}
      <div className="flex items-center">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-3 font-mono text-[11px] font-medium uppercase tracking-wider transition-all duration-150 border-b-2 -mb-px",
                isActive
                  ? "text-[#ece7dc] border-[#d4a84b]"
                  : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc]/70",
              )}
            >
              {Icon && <Icon size={14} stroke={1.5} />}
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Right-side slot */}
      {children && (
        <div className="flex items-center gap-3 pr-3">
          {children}
        </div>
      )}
    </div>
  );
}
