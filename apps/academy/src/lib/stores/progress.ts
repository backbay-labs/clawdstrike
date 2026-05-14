import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

interface ProgressState {
  completedLessons: string[];
  completedChallenges: string[];
  markLessonComplete: (slug: string) => void;
  markChallengeComplete: (id: string) => void;
  isLessonComplete: (slug: string) => boolean;
  isChallengeComplete: (id: string) => boolean;
  reset: () => void;
}

/**
 * Browser-safe storage getter for createJSONStorage.
 *
 * Returns a Storage-compatible object. In environments where localStorage
 * methods are not directly accessible (e.g., happy-dom in tests, SSR),
 * returns an in-memory Map-backed fallback.
 */
function getBrowserStorage(): Storage {
  // Check if we're in a browser with a fully functional localStorage
  if (
    typeof window !== 'undefined' &&
    typeof window.localStorage !== 'undefined' &&
    typeof window.localStorage.getItem === 'function'
  ) {
    return window.localStorage;
  }

  // In-memory fallback for SSR and environments with incomplete localStorage
  const mem = new Map<string, string>();
  return {
    get length() { return mem.size; },
    key(index: number) {
      const keys = [...mem.keys()];
      return keys[index] ?? null;
    },
    getItem(name: string) { return mem.get(name) ?? null; },
    setItem(name: string, value: string) { mem.set(name, value); },
    removeItem(name: string) { mem.delete(name); },
    clear() { mem.clear(); },
  };
}

export const useProgressStore = create<ProgressState>()(
  persist(
    (set, get) => ({
      completedLessons: [],
      completedChallenges: [],

      markLessonComplete: (slug: string) => {
        const current = get().completedLessons;
        if (!current.includes(slug)) {
          set({ completedLessons: [...current, slug] });
        }
      },

      markChallengeComplete: (id: string) => {
        const current = get().completedChallenges;
        if (!current.includes(id)) {
          set({ completedChallenges: [...current, id] });
        }
      },

      isLessonComplete: (slug: string) => {
        return get().completedLessons.includes(slug);
      },

      isChallengeComplete: (id: string) => {
        return get().completedChallenges.includes(id);
      },

      reset: () => {
        set({ completedLessons: [], completedChallenges: [] });
      },
    }),
    {
      name: 'clawdstrike-academy-progress',
      version: 1,
      storage: createJSONStorage(() => getBrowserStorage()),
    },
  ),
);
