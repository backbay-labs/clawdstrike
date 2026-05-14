import Link from 'next/link';
import { ArrowLeft, ArrowRight } from 'lucide-react';
import { getLessonNavigation } from '@/lib/content';

interface LessonNavProps {
  trackSlug: string;
  lessonSlug: string;
}

export function LessonNav({ trackSlug, lessonSlug }: LessonNavProps) {
  const { prev, next } = getLessonNavigation(trackSlug, lessonSlug);

  if (!prev && !next) {
    return null;
  }

  return (
    <nav className="not-prose mt-12 flex items-stretch justify-between gap-4 border-t pt-6">
      {prev ? (
        <Link
          href={prev.path}
          className="group flex items-center gap-3 rounded-lg border px-4 py-3 text-sm transition-colors hover:border-primary/50 hover:bg-accent"
        >
          <ArrowLeft className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary transition-colors" />
          <div className="flex flex-col">
            <span className="text-xs text-muted-foreground">Previous</span>
            <span className="font-medium">{prev.title}</span>
          </div>
        </Link>
      ) : (
        <div />
      )}
      {next ? (
        <Link
          href={next.path}
          className="group flex items-center gap-3 rounded-lg border px-4 py-3 text-sm text-right transition-colors hover:border-primary/50 hover:bg-accent"
        >
          <div className="flex flex-col">
            <span className="text-xs text-muted-foreground">Next</span>
            <span className="font-medium">{next.title}</span>
          </div>
          <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary transition-colors" />
        </Link>
      ) : (
        <div />
      )}
    </nav>
  );
}
