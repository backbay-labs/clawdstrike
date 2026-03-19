import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type { Strikecell, StrikecellConnection } from "../types";
import { DEMO_STRIKECELLS, DEMO_CONNECTIONS } from "../types";

interface NexusState {
  strikecells: Strikecell[];
  connections: StrikecellConnection[];
  actions: {
    setStrikecells: (cells: Strikecell[]) => void;
    setConnections: (conns: StrikecellConnection[]) => void;
  };
}

const useNexusStoreBase = create<NexusState>((set) => ({
  strikecells: DEMO_STRIKECELLS,
  connections: DEMO_CONNECTIONS,
  actions: {
    setStrikecells: (cells: Strikecell[]) => set({ strikecells: cells }),
    setConnections: (conns: StrikecellConnection[]) => set({ connections: conns }),
  },
}));

export const useNexusStore = createSelectors(useNexusStoreBase);
