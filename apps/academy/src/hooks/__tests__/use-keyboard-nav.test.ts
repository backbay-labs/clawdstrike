import { describe, it, expect } from 'vitest';
import {
  parseTrackPathname,
  flattenLessons,
  findPrevNext,
  isEditorFocused,
} from '../use-keyboard-nav';
import type { TrackMeta, LessonMeta } from '@/lib/content';

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MOCK_TRACKS: TrackMeta[] = [
  {
    slug: 'guard-gallery',
    title: 'Guard Gallery',
    lessons: [
      {
        title: 'Forbidden Path',
        order: 1,
        track: 'guard-gallery',
        slug: '01-forbidden-path',
        path: '/tracks/guard-gallery/01-forbidden-path',
      },
      {
        title: 'Path Allowlist',
        order: 2,
        track: 'guard-gallery',
        slug: '02-path-allowlist',
        path: '/tracks/guard-gallery/02-path-allowlist',
      },
      {
        title: 'Egress Allowlist',
        order: 3,
        track: 'guard-gallery',
        slug: '03-egress-allowlist',
        path: '/tracks/guard-gallery/03-egress-allowlist',
      },
    ],
  },
  {
    slug: 'threat-scenarios',
    title: 'Threat Scenarios',
    lessons: [
      {
        title: 'Introduction',
        order: 1,
        track: 'threat-scenarios',
        slug: '01-introduction',
        path: '/tracks/threat-scenarios/01-introduction',
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// parseTrackPathname
// ---------------------------------------------------------------------------

describe('parseTrackPathname', () => {
  it('parses a valid lesson pathname', () => {
    const result = parseTrackPathname(
      '/tracks/guard-gallery/01-forbidden-path',
    );
    expect(result).toEqual({
      trackSlug: 'guard-gallery',
      lessonSlug: '01-forbidden-path',
    });
  });

  it('returns null for track index pathname (no lesson slug)', () => {
    expect(parseTrackPathname('/tracks/guard-gallery')).toBeNull();
  });

  it('returns null for root pathname', () => {
    expect(parseTrackPathname('/')).toBeNull();
  });

  it('returns null for nested sub-paths beyond lesson', () => {
    expect(
      parseTrackPathname('/tracks/guard-gallery/01-forbidden-path/extra'),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// flattenLessons
// ---------------------------------------------------------------------------

describe('flattenLessons', () => {
  it('flattens all lessons from all tracks into a single array', () => {
    const flat = flattenLessons(MOCK_TRACKS);
    expect(flat).toHaveLength(4);
    expect(flat[0].slug).toBe('01-forbidden-path');
    expect(flat[3].slug).toBe('01-introduction');
  });

  it('returns empty array for no tracks', () => {
    expect(flattenLessons([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// findPrevNext
// ---------------------------------------------------------------------------

describe('findPrevNext', () => {
  const flat = flattenLessons(MOCK_TRACKS);

  it('returns null prev for first lesson, next for second', () => {
    const result = findPrevNext(
      flat,
      '/tracks/guard-gallery/01-forbidden-path',
    );
    expect(result.prev).toBeNull();
    expect(result.next?.slug).toBe('02-path-allowlist');
  });

  it('returns prev and next for middle lesson', () => {
    const result = findPrevNext(
      flat,
      '/tracks/guard-gallery/02-path-allowlist',
    );
    expect(result.prev?.slug).toBe('01-forbidden-path');
    expect(result.next?.slug).toBe('03-egress-allowlist');
  });

  it('returns null next for last lesson', () => {
    const result = findPrevNext(
      flat,
      '/tracks/threat-scenarios/01-introduction',
    );
    expect(result.prev?.slug).toBe('03-egress-allowlist');
    expect(result.next).toBeNull();
  });

  it('navigates across track boundaries', () => {
    // Last lesson in guard-gallery -> first lesson in threat-scenarios
    const result = findPrevNext(
      flat,
      '/tracks/guard-gallery/03-egress-allowlist',
    );
    expect(result.next?.slug).toBe('01-introduction');
    expect(result.next?.track).toBe('threat-scenarios');
  });

  it('returns null for unknown pathname', () => {
    const result = findPrevNext(flat, '/tracks/unknown/99-missing');
    expect(result.prev).toBeNull();
    expect(result.next).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// isEditorFocused
// ---------------------------------------------------------------------------

describe('isEditorFocused', () => {
  it('returns false for null activeElement', () => {
    expect(isEditorFocused(null)).toBe(false);
  });

  it('returns true for textarea', () => {
    const el = document.createElement('textarea');
    expect(isEditorFocused(el)).toBe(true);
  });

  it('returns true for input', () => {
    const el = document.createElement('input');
    expect(isEditorFocused(el)).toBe(true);
  });

  it('returns true for contenteditable element', () => {
    const el = document.createElement('div');
    el.setAttribute('contenteditable', 'true');
    expect(isEditorFocused(el)).toBe(true);
  });

  it('returns true for element inside .cm-editor', () => {
    const container = document.createElement('div');
    container.className = 'cm-editor';
    const child = document.createElement('div');
    container.appendChild(child);
    document.body.appendChild(container);
    try {
      expect(isEditorFocused(child)).toBe(true);
    } finally {
      document.body.removeChild(container);
    }
  });

  it('returns false for regular div', () => {
    const el = document.createElement('div');
    expect(isEditorFocused(el)).toBe(false);
  });

  it('returns false for button', () => {
    const el = document.createElement('button');
    expect(isEditorFocused(el)).toBe(false);
  });
});
