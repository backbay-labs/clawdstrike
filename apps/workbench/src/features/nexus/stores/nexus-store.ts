import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type { Strikecell } from "../types";
import { DEMO_STRIKECELLS } from "../types";

interface NexusState {
  strikecells: Strikecell[];
  actions: {
    setStrikecells: (cells: Strikecell[]) => void;
  };
}

const useNexusStoreBase = create<NexusState>((set) => ({
  strikecells: DEMO_STRIKECELLS,
  actions: {
    setStrikecells: (cells: Strikecell[]) => set({ strikecells: cells }),
  },
}));

export const useNexusStore = createSelectors(useNexusStoreBase);
