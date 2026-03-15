/**
 * SkeletonLoader — Animated placeholder for loading states.
 * Matches the dark cybersecurity aesthetic with a subtle shimmer.
 */
import { cn } from "@/lib/utils";

interface SkeletonProps {
  className?: string;
}

/** Single skeleton bar with shimmer animation. */
export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn(
        "rounded-md bg-[#131721] animate-pulse",
        className,
      )}
    />
  );
}

/** Skeleton for a table row — mimics a row of data cells. */
export function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-6 py-3 border-b border-[#2d3240]/30">
      <Skeleton className="h-3 w-12" />
      <Skeleton className="h-3 w-48" />
      <Skeleton className="h-3 w-20" />
      <Skeleton className="h-3 w-16" />
      <Skeleton className="h-3 w-24 ml-auto" />
    </div>
  );
}

/** Skeleton for a table — multiple rows. */
export function SkeletonTable({ rows = 8 }: { rows?: number }) {
  return (
    <div className="flex flex-col">
      {Array.from({ length: rows }, (_, i) => (
        <SkeletonRow key={i} />
      ))}
    </div>
  );
}

/** Skeleton for a card grid. */
export function SkeletonCardGrid({ cards = 6 }: { cards?: number }) {
  return (
    <div className="grid grid-cols-3 gap-4 p-6">
      {Array.from({ length: cards }, (_, i) => (
        <div key={i} className="rounded-lg border border-[#2d3240]/30 p-4 space-y-3">
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-3 w-1/2" />
        </div>
      ))}
    </div>
  );
}
