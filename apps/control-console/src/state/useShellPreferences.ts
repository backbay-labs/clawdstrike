import { create } from "zustand";

export type SidebarVariant = "rail" | "expanded" | "twopane";

/** The variant actually rendered after resolving the collapsed flag. */
export type EffectiveSidebarVariant = SidebarVariant;

/**
 * Resolve the rendered sidebar variant. The collapsed flag no longer swaps the
 * component: a collapsed "expanded" sidebar stays "expanded" and animates its
 * own width down to a rail-like 64px (see {@link SidebarExpanded}), so the
 * open/close transition can morph smoothly instead of hot-swapping components.
 * The standalone icon rail is reserved for the user-chosen "rail" variant.
 *
 * Kept as the single source of truth for the variant rule so the shell and the
 * sidebar never drift; the `collapsed` flag is consumed directly where width is
 * computed.
 */
export function resolveEffectiveVariant(
  variant: SidebarVariant,
  _collapsed: boolean,
): EffectiveSidebarVariant {
  return variant;
}

/** Pixel width of the expanded sidebar in its open and collapsed states. */
export const SIDEBAR_EXPANDED_WIDTH = 248;
export const SIDEBAR_COLLAPSED_WIDTH = 64;

const VARIANT_KEY = "cs_sidebar_variant";
const COLLAPSED_KEY = "cs_sidebar_collapsed";

const VALID_VARIANTS: ReadonlySet<string> = new Set(["rail", "expanded", "twopane"]);

function readVariant(): SidebarVariant {
  const stored = localStorage.getItem(VARIANT_KEY);
  return stored && VALID_VARIANTS.has(stored) ? (stored as SidebarVariant) : "expanded";
}

function readCollapsed(): boolean {
  return localStorage.getItem(COLLAPSED_KEY) === "true";
}

function persistVariant(v: SidebarVariant) {
  localStorage.setItem(VARIANT_KEY, v);
}

function persistCollapsed(b: boolean) {
  localStorage.setItem(COLLAPSED_KEY, String(b));
}

interface ShellPreferencesState {
  sidebarVariant: SidebarVariant;
  sidebarCollapsed: boolean;
  setSidebarVariant: (v: SidebarVariant) => void;
  setSidebarCollapsed: (b: boolean) => void;
  toggleSidebarCollapsed: () => void;
}

export const useShellPreferences = create<ShellPreferencesState>((set, get) => ({
  sidebarVariant: readVariant(),
  sidebarCollapsed: readCollapsed(),

  setSidebarVariant(v) {
    set({ sidebarVariant: v });
    persistVariant(v);
  },

  setSidebarCollapsed(b) {
    set({ sidebarCollapsed: b });
    persistCollapsed(b);
  },

  toggleSidebarCollapsed() {
    const next = !get().sidebarCollapsed;
    set({ sidebarCollapsed: next });
    persistCollapsed(next);
  },
}));

// Cross-tab sync: when another tab writes to localStorage, re-hydrate.
if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === VARIANT_KEY || e.key === COLLAPSED_KEY) {
      useShellPreferences.setState({
        sidebarVariant: readVariant(),
        sidebarCollapsed: readCollapsed(),
      });
    }
  });
}
