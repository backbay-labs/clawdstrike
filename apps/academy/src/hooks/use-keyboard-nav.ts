import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import type { TrackMeta, LessonMeta } from '@/lib/content';

// ---------------------------------------------------------------------------
// Pure helpers (exported for testing)
// ---------------------------------------------------------------------------

/** Parse a /tracks/:trackSlug/:lessonSlug pathname into its parts. */
export function parseTrackPathname(
  pathname: string,
): { trackSlug: string; lessonSlug: string } | null {
  const match = pathname.match(/^\/tracks\/([^/]+)\/([^/]+)$/);
  if (!match) return null;
  return { trackSlug: match[1], lessonSlug: match[2] };
}

/** Flatten all lessons from all tracks into a single ordered list. */
export function flattenLessons(tracks: TrackMeta[]): LessonMeta[] {
  return tracks.flatMap((track) => track.lessons);
}

/** Find prev/next lessons from a flat lesson list given the current pathname. */
export function findPrevNext(
  lessons: LessonMeta[],
  pathname: string,
): { prev: LessonMeta | null; next: LessonMeta | null } {
  const index = lessons.findIndex((l) => l.path === pathname);
  if (index === -1) return { prev: null, next: null };

  return {
    prev: index > 0 ? lessons[index - 1] : null,
    next: index < lessons.length - 1 ? lessons[index + 1] : null,
  };
}

/**
 * Returns true if the active element is in a context where arrow keys
 * should be handled by the element itself (editors, inputs, etc.).
 */
export function isEditorFocused(activeElement: Element | null): boolean {
  if (!activeElement) return false;

  // Check if focused element is an input, textarea, or contenteditable
  const tagName = activeElement.tagName.toLowerCase();
  if (tagName === 'input' || tagName === 'textarea') return true;
  if (activeElement.getAttribute('contenteditable') === 'true') return true;

  // Check if focused element is inside a CodeMirror editor (.cm-editor)
  if (activeElement.closest('.cm-editor')) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Global keyboard navigation hook for arrow key lesson navigation.
 * Receives the full tracks array (serializable) from the server layout
 * and derives prev/next from the current pathname.
 *
 * Skips navigation when focus is in CodeMirror, textarea, input, or
 * contenteditable elements.
 */
export function useKeyboardNav(tracks: TrackMeta[]) {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    const lessons = flattenLessons(tracks);
    const { prev, next } = findPrevNext(lessons, pathname);

    function onKeyDown(e: KeyboardEvent) {
      // Focus guard: don't intercept arrow keys in editors/inputs
      if (isEditorFocused(document.activeElement)) return;

      if (e.key === 'ArrowLeft' && prev) {
        e.preventDefault();
        router.push(prev.path);
      } else if (e.key === 'ArrowRight' && next) {
        e.preventDefault();
        router.push(next.path);
      }
    }

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [pathname, router, tracks]);
}
