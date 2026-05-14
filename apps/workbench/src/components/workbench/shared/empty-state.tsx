/**
 * EmptyState — Consistent empty state with icon, message, and optional CTA.
 */
import type { ReactNode } from "react";
import type { IconActivity } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

type TablerIcon = typeof IconActivity;

interface EmptyStateProps {
  icon: TablerIcon;
  title: string;
  description?: string;
  /** Optional call-to-action button or link. */
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ icon: Icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center py-20 gap-4", className)}>
      <div className="w-14 h-14 rounded-xl bg-[#131721] border border-[#2d3240]/40 flex items-center justify-center">
        <Icon size={24} stroke={1} className="text-[#6f7f9a]/30" />
      </div>
      <div className="text-center max-w-sm">
        <p className="text-[13px] font-medium text-[#ece7dc]/70">{title}</p>
        {description && (
          <p className="mt-1.5 text-[11px] text-[#6f7f9a]/50 leading-relaxed">{description}</p>
        )}
      </div>
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
