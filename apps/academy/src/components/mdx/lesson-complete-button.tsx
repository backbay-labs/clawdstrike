'use client';

import { useState, useEffect } from 'react';
import { CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useProgressStore } from '@/lib/stores/progress';

interface LessonCompleteButtonProps {
  lessonSlug: string;
}

export function LessonCompleteButton({ lessonSlug }: LessonCompleteButtonProps) {
  const markLessonComplete = useProgressStore((s) => s.markLessonComplete);
  const isLessonComplete = useProgressStore((s) => s.isLessonComplete);

  // Hydration guard to avoid SSR mismatch
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    setHydrated(true);
  }, []);

  const completed = hydrated && isLessonComplete(lessonSlug);

  if (completed) {
    return (
      <div className="my-6 flex items-center gap-2 text-green-600 dark:text-green-400">
        <CheckCircle2 className="h-5 w-5" />
        <span className="text-sm font-medium">Completed</span>
      </div>
    );
  }

  return (
    <div className="my-6">
      <Button
        variant="outline"
        onClick={() => markLessonComplete(lessonSlug)}
        className="border-green-500 text-green-600 hover:bg-green-50 hover:text-green-700 dark:border-green-400 dark:text-green-400 dark:hover:bg-green-950 dark:hover:text-green-300"
      >
        Mark as Complete
      </Button>
    </div>
  );
}
