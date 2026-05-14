'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { BookOpen, FileText, ChevronRight, CheckCircle2 } from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import { useProgressStore } from '@/lib/stores/progress';
import type { TrackMeta } from '@/lib/content';

interface SidebarProps {
  tracks: TrackMeta[];
}

export function Sidebar({ tracks }: SidebarProps) {
  const pathname = usePathname();
  const completedLessons = useProgressStore((s) => s.completedLessons);

  // Hydration guard: avoid SSR mismatch by only showing checkmarks after mount
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    setHydrated(true);
  }, []);

  return (
    <ScrollArea className="h-full">
      <nav className="p-4 space-y-2">
        {tracks.map((track) => {
          const isTrackActive = pathname.startsWith(`/tracks/${track.slug}`);

          return (
            <details
              key={track.slug}
              open={isTrackActive || undefined}
              className="group"
            >
              <summary className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium cursor-pointer list-none hover:bg-accent hover:text-accent-foreground transition-colors">
                <ChevronRight className="h-4 w-4 shrink-0 transition-transform group-open:rotate-90" />
                <BookOpen className="h-4 w-4 shrink-0" />
                <span>{track.title}</span>
              </summary>
              <ul className="ml-4 mt-1 space-y-1">
                {track.lessons.map((lesson) => {
                  const isActive = pathname === lesson.path;
                  const lessonSlug = lesson.path.replace(/^\/tracks\//, '');
                  const isComplete =
                    hydrated && (completedLessons.includes(lesson.path) || completedLessons.includes(lessonSlug));

                  return (
                    <li key={lesson.slug}>
                      <Link
                        href={lesson.path}
                        className={cn(
                          'flex items-center gap-2 px-3 py-1.5 rounded-md text-sm transition-colors',
                          isActive
                            ? 'bg-primary/10 text-primary font-medium'
                            : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                        )}
                      >
                        {isComplete ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-green-500" />
                        ) : (
                          <FileText className="h-3.5 w-3.5 shrink-0" />
                        )}
                        <span>{lesson.title}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </details>
          );
        })}
      </nav>
    </ScrollArea>
  );
}
