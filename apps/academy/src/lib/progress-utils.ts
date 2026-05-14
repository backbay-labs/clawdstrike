import type { TrackMeta } from '@/lib/content';

/**
 * Normalize lesson completion keys from localStorage (path and/or `track/slug`).
 */
export function isLessonMarkedComplete(
  completedLessons: string[],
  lessonPath: string,
  trackSlug: string,
  lessonSlug: string,
): boolean {
  const keys = new Set([
    lessonPath,
    `${trackSlug}/${lessonSlug}`,
    lessonPath.replace(/^\/tracks\//, ''),
  ]);
  return completedLessons.some((c) => keys.has(c));
}

export function getAcademyProgressStats(
  tracks: TrackMeta[],
  completedLessons: string[],
): { total: number; completed: number; percent: number } {
  let total = 0;
  let completed = 0;
  for (const track of tracks) {
    for (const lesson of track.lessons) {
      total += 1;
      if (isLessonMarkedComplete(completedLessons, lesson.path, track.slug, lesson.slug)) {
        completed += 1;
      }
    }
  }
  const percent = total === 0 ? 0 : Math.round((completed / total) * 100);
  return { total, completed, percent };
}
