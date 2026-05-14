import { describe, it, expect, beforeEach } from 'vitest';
import { useProgressStore } from '../progress';

describe('useProgressStore', () => {
  beforeEach(() => {
    useProgressStore.setState({
      completedLessons: [],
      completedChallenges: [],
    });
  });

  it('has store name clawdstrike-academy-progress', () => {
    // The persist middleware attaches the name to the store options.
    // We can verify by checking that the persist API exists and the name is correct.
    const persistApi = (useProgressStore as unknown as { persist: { getOptions: () => { name: string } } }).persist;
    expect(persistApi.getOptions().name).toBe('clawdstrike-academy-progress');
  });

  describe('lesson completion', () => {
    it('markLessonComplete adds slug to completedLessons array', () => {
      useProgressStore.getState().markLessonComplete('intro-to-guards');
      expect(useProgressStore.getState().completedLessons).toEqual(['intro-to-guards']);
    });

    it('markLessonComplete is idempotent (calling twice does not duplicate)', () => {
      useProgressStore.getState().markLessonComplete('intro-to-guards');
      useProgressStore.getState().markLessonComplete('intro-to-guards');
      expect(useProgressStore.getState().completedLessons).toEqual(['intro-to-guards']);
    });

    it('isLessonComplete returns true for completed slugs', () => {
      useProgressStore.getState().markLessonComplete('intro-to-guards');
      expect(useProgressStore.getState().isLessonComplete('intro-to-guards')).toBe(true);
    });

    it('isLessonComplete returns false for incomplete slugs', () => {
      expect(useProgressStore.getState().isLessonComplete('advanced-policies')).toBe(false);
    });
  });

  describe('challenge completion', () => {
    it('markChallengeComplete adds id to completedChallenges array', () => {
      useProgressStore.getState().markChallengeComplete('forbidden-path-bypass-01');
      expect(useProgressStore.getState().completedChallenges).toEqual(['forbidden-path-bypass-01']);
    });

    it('markChallengeComplete is idempotent', () => {
      useProgressStore.getState().markChallengeComplete('forbidden-path-bypass-01');
      useProgressStore.getState().markChallengeComplete('forbidden-path-bypass-01');
      expect(useProgressStore.getState().completedChallenges).toEqual(['forbidden-path-bypass-01']);
    });

    it('isChallengeComplete returns true for completed ids', () => {
      useProgressStore.getState().markChallengeComplete('forbidden-path-bypass-01');
      expect(useProgressStore.getState().isChallengeComplete('forbidden-path-bypass-01')).toBe(true);
    });

    it('isChallengeComplete returns false for incomplete ids', () => {
      expect(useProgressStore.getState().isChallengeComplete('unknown-challenge')).toBe(false);
    });
  });

  describe('reset', () => {
    it('clears both arrays', () => {
      useProgressStore.getState().markLessonComplete('lesson-1');
      useProgressStore.getState().markLessonComplete('lesson-2');
      useProgressStore.getState().markChallengeComplete('challenge-1');
      useProgressStore.getState().reset();
      expect(useProgressStore.getState().completedLessons).toEqual([]);
      expect(useProgressStore.getState().completedChallenges).toEqual([]);
    });
  });
});
