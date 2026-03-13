/**
 * SubTabBar — Compact subordinate tab navigation.
 *
 * Small LED-dot indicator for the active tab. Visually lighter than
 * SegmentedControl to create clear hierarchy: page-level segmented control
 * sits above, section-level sub-tabs sit below.
 */

import { useId, type ReactNode } from "react";
import { motion } from "motion/react";
import type { IconActivity } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

type TablerIcon = typeof IconActivity;

export interface SubTab {
  id: string;
  label: string;
  icon?: TablerIcon;
  title?: string;
}

interface SubTabBarProps {
  tabs: SubTab[];
  activeTab: string;
  onTabChange: (id: string) => void;
  /** Right-side slot for status indicators, badges, etc. */
  children?: ReactNode;
}

export function SubTabBar({
  tabs,
  activeTab,
  onTabChange,
  children,
}: SubTabBarProps) {
  const layoutId = useId();

  return (
    <div
      className="flex items-center justify-between shrink-0 border-b border-[#2d3240]/40"
      style={{
        background:
          "linear-gradient(180deg, rgba(11,13,19,0.6) 0%, rgba(11,13,19,0) 100%)",
      }}
    >
      {/* Tab row */}
      <div className="flex items-center gap-0.5 pl-2">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              title={tab.title}
              className={cn(
                "relative flex flex-col items-center px-3 pt-2 pb-2.5",
                "text-[10px] font-mono font-medium uppercase tracking-wider",
                "transition-colors duration-150 select-none",
                isActive
                  ? "text-[#ece7dc]/90"
                  : "text-[#6f7f9a]/70 hover:text-[#6f7f9a]",
              )}
            >
              <span className="flex items-center gap-1.5">
                {Icon && (
                  <Icon
                    size={12}
                    stroke={1.5}
                    className={cn(
                      "transition-colors duration-150",
                      isActive ? "text-[#d4a84b]/70" : "",
                    )}
                  />
                )}
                {tab.label}
              </span>

              {/* LED dot indicator */}
              {isActive && (
                <motion.div
                  layoutId={`subtab-dot-${layoutId}`}
                  className="absolute bottom-0 rounded-full"
                  style={{
                    width: 5,
                    height: 2.5,
                    borderRadius: 1,
                    background: "#d4a84b",
                    boxShadow:
                      "0 0 6px rgba(212,168,75,0.5), 0 0 2px rgba(212,168,75,0.8)",
                  }}
                  transition={{
                    type: "spring",
                    bounce: 0.2,
                    duration: 0.3,
                  }}
                />
              )}
            </button>
          );
        })}
      </div>

      {/* Right-side slot */}
      {children && (
        <div className="flex items-center gap-3 pr-3">{children}</div>
      )}
    </div>
  );
}
