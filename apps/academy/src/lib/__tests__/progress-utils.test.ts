import { describe, it, expect } from 'vitest';
import type { TrackMeta } from '@/lib/content';
import { getAcademyProgressStats, isLessonMarkedComplete } from '@/lib/progress-utils';

function makeTracks(
  ...entries: Array<{ track: string; lessons: Array<{ slug: string; path: string }> }>
): TrackMeta[] {
  return entries.map((t) => ({
    slug: t.track,
    title: t.track,
    lessons: t.lessons.map((l) => ({
      title: l.slug,
      order: 1,
      track: t.track,
      slug: l.slug,
      path: l.path,
    })),
  }));
}

describe('isLessonMarkedComplete', () => {
  const path = '/tracks/foo/bar';
  it('matches full lesson path', () => {
    expect(isLessonMarkedComplete([path], path, 'foo', 'bar')).toBe(true);
  });
  it('matches track/slug and path-without-/tracks/ keys', () => {
    expect(isLessonMarkedComplete(['foo/bar'], path, 'foo', 'bar')).toBe(true);
  });
  it('returns false when no key matches', () => {
    expect(isLessonMarkedComplete(['other'], path, 'foo', 'bar')).toBe(false);
  });
});

describe('getAcademyProgressStats', () => {
  it('returns zeros for empty tracks', () => {
    expect(getAcademyProgressStats([], [])).toEqual({
      total: 0,
      completed: 0,
      percent: 0,
    });
  });

  it('counts lessons and completion across keys', () => {
    const tracks = makeTracks({
      track: 'a',
      lessons: [
        { slug: '1', path: '/tracks/a/1' },
        { slug: '2', path: '/tracks/a/2' },
      ],
    });
    expect(
      getAcademyProgressStats(tracks, ['a/1', '/tracks/a/2']),
    ).toEqual({
      total: 2,
      completed: 2,
      percent: 100,
    });
  });

  it('rounds percent to nearest integer', () => {
    const tracks = makeTracks({
      track: 't',
      lessons: [
        { slug: '1', path: '/tracks/t/1' },
        { slug: '2', path: '/tracks/t/2' },
        { slug: '3', path: '/tracks/t/3' },
      ],
    });
    expect(getAcademyProgressStats(tracks, ['t/1']).percent).toBe(33);
  });
});
