/**
 * spirit-evolution-store.ts — Per-kind XP and level progression.
 *
 * Persisted to localStorage under "clawdstrike.spirit-evolution".
 * Each SpiritKind accumulates XP independently.
 * Level auto-derives from XP each time grantXp is called.
 *
 * XP event values (set by product decision in CONTEXT.md):
 *   probe finding: 10 XP
 *   lint pass:      5 XP
 *   simulation:    15 XP (fired externally when available)
 *
 * Level thresholds: L1=0, L2=50, L3=150, L4=350, L5=700
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { createSelectors } from "@/lib/create-selectors";
import type { SpiritKind } from "../types";

// ── Constants ───────────────────────────────────────────────────────────────

/** XP required to reach each level. Index = level - 1. */
export const XP_THRESHOLDS = [0, 50, 150, 350, 700] as const;

/** Derive level (1–5) from accumulated XP. */
export function deriveLevel(xp: number): number {
  let level = 1;
  for (let i = 1; i < XP_THRESHOLDS.length; i++) {
    if (xp >= XP_THRESHOLDS[i]) level = i + 1;
    else break;
  }
  return level;
}

// ── State Shape ─────────────────────────────────────────────────────────────

export interface KindEvolution {
  xp: number;
  level: number; // 1–5, derived — stored for quick reads by canvas
}

const KINDS: SpiritKind[] = ["sentinel", "oracle", "witness", "specter"];

const initialEvolution = (): Record<SpiritKind, KindEvolution> =>
  Object.fromEntries(KINDS.map((k) => [k, { xp: 0, level: 1 }])) as Record<
    SpiritKind,
    KindEvolution
  >;

export interface SpiritEvolutionState {
  evolution: Record<SpiritKind, KindEvolution>;
  actions: {
    grantXp: (kind: SpiritKind, amount: number) => void;
    _reset: () => void;
  };
}

// ── Store ────────────────────────────────────────────────────────────────────

const useSpiritEvolutionStoreBase = create<SpiritEvolutionState>()(
  persist(
    (set) => ({
      evolution: initialEvolution(),
      actions: {
        grantXp: (kind: SpiritKind, amount: number) =>
          set((state) => {
            const current = state.evolution[kind];
            const xp = current.xp + amount;
            const level = deriveLevel(xp);
            return {
              evolution: {
                ...state.evolution,
                [kind]: { xp, level },
              },
            };
          }),

        _reset: () => set({ evolution: initialEvolution() }),
      },
    }),
    {
      name: "clawdstrike.spirit-evolution",
      // Persist only the evolution record, not actions
      partialize: (state) => ({ evolution: state.evolution }),
    },
  ),
);

export const useSpiritEvolutionStore = createSelectors(useSpiritEvolutionStoreBase);
