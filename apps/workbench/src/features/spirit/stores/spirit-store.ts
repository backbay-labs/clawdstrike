import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type { SpiritKind, SpiritMood, SpiritState } from "../types";

const SPIRIT_ACCENT_MAP: Record<SpiritKind, string> = {
  ember: "#e05c3a",
  tide: "#3a8ae0",
  verdant: "#3dbf84",
  void: "#7a3ae0",
  neutral: "#d4a84b",
};

const useSpiritStoreBase = create<SpiritState>((set) => ({
  kind: null,
  mood: "idle",
  fieldStrength: 0,
  accentColor: null,
  actions: {
    bindSpirit: (kind: SpiritKind) =>
      set({ kind, accentColor: SPIRIT_ACCENT_MAP[kind], fieldStrength: 1, mood: "active" }),
    unbindSpirit: () =>
      set({ kind: null, accentColor: null, fieldStrength: 0, mood: "idle" }),
    setMood: (mood: SpiritMood) => set({ mood }),
    setFieldStrength: (fieldStrength: number) =>
      set({ fieldStrength: Math.max(0, Math.min(1, fieldStrength)) }),
  },
}));

export const useSpiritStore = createSelectors(useSpiritStoreBase);
