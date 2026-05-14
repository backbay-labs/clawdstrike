import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type { Strikecell, StrikecellConnection, NexusLayoutMode } from "../types";
import { DEMO_STRIKECELLS, DEMO_CONNECTIONS } from "../types";

interface NexusState {
  strikecells: Strikecell[];
  connections: StrikecellConnection[];
  layoutMode: NexusLayoutMode;
  actions: {
    setStrikecells: (cells: Strikecell[]) => void;
    setConnections: (conns: StrikecellConnection[]) => void;
    setLayoutMode: (mode: NexusLayoutMode) => void;
  };
}

const useNexusStoreBase = create<NexusState>((set) => ({
  strikecells: DEMO_STRIKECELLS,
  connections: DEMO_CONNECTIONS,
  layoutMode: "radial",
  actions: {
    setStrikecells: (cells: Strikecell[]) => set({ strikecells: cells }),
    setConnections: (conns: StrikecellConnection[]) => set({ connections: conns }),
    setLayoutMode: (mode: NexusLayoutMode) => set({ layoutMode: mode }),
  },
}));

export const useNexusStore = createSelectors(useNexusStoreBase);
