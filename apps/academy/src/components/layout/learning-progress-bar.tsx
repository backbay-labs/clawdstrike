'use client';

import { useEffect, useMemo, useState } from 'react';
import type { TrackMeta } from '@/lib/content';
import { useProgressStore } from '@/lib/stores/progress';
import { getAcademyProgressStats } from '@/lib/progress-utils';
import { cn } from '@/lib/utils';

export interface LearningProgressBarProps {
  tracks: TrackMeta[];
  /** Compact for track shell header; roomier on landing. */
  variant?: 'default' | 'compact';
  className?: string;
}

/**
 * Overall academy lesson progress (local persisted completions).
 * Styling follows apps/academy/docs/design/DESIGN.md: subtle inset track, pill fill, warm/neutral type.
 */
export function LearningProgressBar({
  tracks,
  variant = 'default',
  className,
}: LearningProgressBarProps) {
  const completedLessons = useProgressStore((s) => s.completedLessons);
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    setHydrated(true);
  }, []);

  const { total, completed, percent } = useMemo(
    () => getAcademyProgressStats(tracks, completedLessons),
    [tracks, completedLessons],
  );

  const compact = variant === 'compact';

  if (!hydrated) {
    return (
      <div
        className={cn(
          'w-full rounded-full bg-muted/60 shadow-inset-edge',
          compact ? 'h-1.5 max-w-xl' : 'h-2 max-w-md',
          'motion-safe:animate-pulse',
          className,
        )}
        aria-hidden
      />
    );
  }

  return (
    <div className={cn('w-full', compact ? 'max-w-xl' : 'max-w-md', className)}>
      <div
        className={cn(
          'flex items-baseline justify-between gap-3',
          compact ? 'mb-1' : 'mb-2',
        )}
      >
        <span
          className={cn(
            'font-medium tracking-[0.01em] text-muted-foreground',
            compact ? 'text-xs' : 'text-sm',
          )}
        >
          Learning progress
        </span>
        <span
          className={cn(
            'tabular-nums tracking-[0.01em] text-warm-gray',
            compact ? 'text-xs' : 'text-sm',
          )}
        >
          {completed} / {total} lessons
          <span className="sr-only"> ({percent}%)</span>
        </span>
      </div>
      <div
        className={cn(
          'overflow-hidden rounded-full bg-surface-muted shadow-inset-edge',
          compact ? 'h-1.5' : 'h-2',
        )}
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Learning progress, ${completed} of ${total} lessons complete`}
      >
        <div
          className={cn(
            'h-full rounded-full bg-foreground transition-[width] duration-500 ease-out',
            'shadow-[0_0_0_0.5px_rgba(0,0,0,0.06)]',
            'dark:shadow-[0_0_0_0.5px_rgba(255,255,255,0.08)]',
          )}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
