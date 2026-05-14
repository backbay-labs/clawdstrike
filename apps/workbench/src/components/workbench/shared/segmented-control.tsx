/**
 * SegmentedControl — Top-level page mode selector.
 *
 * Glass-morphism capsule with a sliding active indicator.
 * Use this for major page-level tab switches (Hunt/Simulate, Findings/Intel,
 * Delegation/Hierarchy). Visually dominant — clearly the primary mode toggle.
 */

import { useId, type ReactNode } from "react";
import { motion } from "motion/react";
import type { IconActivity } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

type TablerIcon = typeof IconActivity;

export interface SegmentedTab {
  id: string;
  label: string;
  icon?: TablerIcon;
}

interface SegmentedControlProps {
  tabs: SegmentedTab[];
  activeTab: string;
  onTabChange: (id: string) => void;
  /** Right-side slot for status indicators, badges, etc. */
  children?: ReactNode;
}

export function SegmentedControl({
  tabs,
  activeTab,
  onTabChange,
  children,
}: SegmentedControlProps) {
  const layoutId = useId();

  return (
    <div className="flex items-center justify-between px-4 py-2.5 shrink-0 bg-[#0b0d13]">
      {/* Capsule container */}
      <div
        className="relative flex items-center gap-0.5 rounded-lg p-[3px]"
        style={{
          background: "#080a10",
          border: "1px solid rgba(45,50,64,0.5)",
          boxShadow:
            "inset 0 1px 4px rgba(0,0,0,0.5), 0 1px 0 rgba(255,255,255,0.02)",
        }}
      >
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "relative z-10 flex items-center gap-1.5 px-4 py-[7px] rounded-md",
                "text-[11px] font-mono font-medium uppercase tracking-wider",
                "transition-colors duration-200 select-none",
                isActive
                  ? "text-[#ece7dc]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc]/50",
              )}
            >
              {/* Sliding active background */}
              {isActive && (
                <motion.div
                  layoutId={`seg-bg-${layoutId}`}
                  className="absolute inset-0 rounded-md"
                  style={{
                    background:
                      "linear-gradient(180deg, #151a25 0%, #111620 100%)",
                    border: "1px solid rgba(212,168,75,0.15)",
                    boxShadow:
                      "0 0 12px rgba(212,168,75,0.05), inset 0 1px 0 rgba(255,255,255,0.03)",
                  }}
                  transition={{
                    type: "spring",
                    bounce: 0.12,
                    duration: 0.4,
                  }}
                />
              )}

              {/* Content */}
              <span className="relative z-10 flex items-center gap-1.5">
                {Icon && (
                  <Icon
                    size={13}
                    stroke={1.5}
                    className={cn(
                      "transition-colors duration-200",
                      isActive ? "text-[#d4a84b]" : "",
                    )}
                    style={
                      isActive
                        ? {
                            filter:
                              "drop-shadow(0 0 3px rgba(212,168,75,0.3))",
                          }
                        : undefined
                    }
                  />
                )}
                {tab.label}
              </span>

              {/* Gold accent line at bottom of active segment */}
              {isActive && (
                <motion.div
                  layoutId={`seg-line-${layoutId}`}
                  className="absolute bottom-0 left-2 right-2 h-[1.5px] rounded-full"
                  style={{
                    background:
                      "linear-gradient(90deg, transparent, #d4a84b, transparent)",
                    opacity: 0.5,
                  }}
                  transition={{
                    type: "spring",
                    bounce: 0.12,
                    duration: 0.4,
                  }}
                />
              )}
            </button>
          );
        })}
      </div>

      {/* Right-side slot */}
      {children && (
        <div className="flex items-center gap-3">{children}</div>
      )}
    </div>
  );
}
