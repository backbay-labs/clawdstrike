/**
 * PageHeader — Standardized page title bar for workbench pages.
 *
 * Provides a consistent icon + title (Syne display font) + subtitle + action
 * slot across all pages. The title has a subtle gold glow on the icon for
 * visual weight. Designed to pair with SegmentedControl and SubTabBar.
 */

import type { ReactNode } from "react";
import type { IconActivity } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

type TablerIcon = typeof IconActivity;

interface PageHeaderProps {
  /** Page title — rendered in Syne display font. */
  title: string;
  /** Optional subtitle below the title. */
  subtitle?: ReactNode;
  /** Tabler icon rendered to the left of the title. */
  icon?: TablerIcon;
  /** Custom icon color (defaults to gold #d4a84b). */
  iconColor?: string;
  /** Right-aligned action slot — buttons, badges, controls. */
  children?: ReactNode;
  /** Extra content below the title row (e.g. inline filters, badges). */
  below?: ReactNode;
  /** Additional className on the outer container. */
  className?: string;
  /** Optional 2px left-border accent color matching the sidebar section group. */
  sectionAccent?: string;
}

export function PageHeader({
  title,
  subtitle,
  icon: Icon,
  iconColor = "#d4a84b",
  children,
  below,
  className,
  sectionAccent,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "shrink-0 px-6 py-3.5",
        className,
      )}
      style={{
        background:
          "linear-gradient(180deg, rgba(11,13,19,0.8) 0%, rgba(5,6,10,0) 100%)",
        borderBottom: "1px solid rgba(45,50,64,0.35)",
        ...(sectionAccent
          ? { borderLeft: `2px solid ${sectionAccent}` }
          : {}),
      }}
    >
      <div className="flex items-center justify-between gap-4">
        {/* Left: icon + title + subtitle */}
        <div className="flex items-center gap-3 min-w-0">
          {Icon && (
            <div
              className="shrink-0 flex items-center justify-center w-8 h-8 rounded-lg"
              style={{
                background: `${iconColor}08`,
                border: `1px solid ${iconColor}15`,
              }}
            >
              <Icon
                size={16}
                stroke={1.5}
                style={{
                  color: iconColor,
                  filter: `drop-shadow(0 0 4px ${iconColor}40)`,
                }}
              />
            </div>
          )}
          <div className="min-w-0">
            <h1 className="font-syne font-semibold text-[15px] text-[#ece7dc] tracking-[-0.02em] truncate">
              {title}
            </h1>
            {subtitle && (
              <p className="text-[11px] text-[#6f7f9a] mt-0.5 truncate">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        {/* Right: action slot */}
        {children && (
          <div className="flex items-center gap-2 shrink-0">{children}</div>
        )}
      </div>

      {/* Below row (filters, badges, etc.) */}
      {below && <div className="mt-3">{below}</div>}
    </div>
  );
}
