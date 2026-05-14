import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";

export interface Achievement {
  id: string;
  title: string;
  description: string;
}

interface AchievementState {
  queue: Achievement[];
  actions: {
    pushAchievement: (achievement: Achievement) => void;
    popAchievement: (id: string) => void;
  };
}

const useAchievementStoreBase = create<AchievementState>((set) => ({
  queue: [],
  actions: {
    pushAchievement: (achievement) =>
      set((state) => ({ queue: [...state.queue, achievement] })),
    popAchievement: (id) =>
      set((state) => ({ queue: state.queue.filter((a) => a.id !== id) })),
  },
}));

export const useAchievementStore = createSelectors(useAchievementStoreBase);
