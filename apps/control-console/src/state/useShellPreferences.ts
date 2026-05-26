import { create } from "zustand";

export type SidebarVariant = "rail" | "expanded" | "twopane";

const SHELL_PREFS_CHANGED_EVENT = "clawdstrike:shell-prefs-changed";

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
  window.dispatchEvent(new CustomEvent(SHELL_PREFS_CHANGED_EVENT));
}

function persistCollapsed(b: boolean) {
  localStorage.setItem(COLLAPSED_KEY, String(b));
  window.dispatchEvent(new CustomEvent(SHELL_PREFS_CHANGED_EVENT));
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
