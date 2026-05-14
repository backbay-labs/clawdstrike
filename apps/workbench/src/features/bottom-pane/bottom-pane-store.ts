import { create } from "zustand";
import { terminalService } from "@/lib/workbench/terminal-service";

export type BottomPaneTab = "terminal" | "problems" | "output" | "audit" | "tape";

export interface OutputEntry {
  id: string;
  timestamp: number;
  level: "info" | "error";
  title: string;
  detail?: string;
  commandId?: string;
}

export interface TerminalSession {
  id: string;
  title: string;
  ptySessionId: string | null;
  cwd: string | null;
  status: "ready" | "error";
  error: string | null;
}

export interface BottomPaneStore {
  isOpen: boolean;
  activeTab: BottomPaneTab;
  size: number;
  terminalSessions: TerminalSession[];
  activeTerminalId: string | null;
  splitTerminalIds: [string, string] | null;
  outputEntries: OutputEntry[];
  toggleTab: (tab: BottomPaneTab) => void;
  setActiveTab: (tab: BottomPaneTab) => void;
  setSize: (size: number) => void;
  newTerminal: () => Promise<void>;
  closeTerminal: (id: string) => Promise<void>;
  setActiveTerminal: (id: string) => void;
  renameTerminal: (id: string, title: string) => void;
  splitTerminal: () => Promise<void>;
  unsplitTerminal: () => void;
  appendOutput: (entry: Omit<OutputEntry, "id" | "timestamp"> & { timestamp?: number }) => void;
  clearOutput: () => void;
  _reset: () => void;
}

const MAX_OUTPUT_ENTRIES = 200;

async function createTerminalSession(
  index: number,
): Promise<TerminalSession> {
  const id = crypto.randomUUID();

  try {
    const cwd = await terminalService.getCwd();
    const session = await terminalService.create(cwd);
    return {
      id,
      title: `Terminal ${index}`,
      ptySessionId: session.id,
      cwd,
      status: "ready",
      error: null,
    };
  } catch (error) {
    return {
      id,
      title: `Terminal ${index}`,
      ptySessionId: null,
      cwd: null,
      status: "error",
      error:
        error instanceof Error
          ? error.message
          : "Terminal session could not be created.",
    };
  }
}

export const useBottomPaneStore = create<BottomPaneStore>((set, get) => ({
  isOpen: false,
  activeTab: "terminal",
  size: 28,
  terminalSessions: [],
  activeTerminalId: null,
  splitTerminalIds: null,
  outputEntries: [],

  toggleTab: (tab) => {
    const state = get();
    if (state.isOpen && state.activeTab === tab) {
      set({ isOpen: false });
      return;
    }
    set({ isOpen: true, activeTab: tab });
  },

  setActiveTab: (tab) => {
    set({ activeTab: tab, isOpen: true });
  },

  setSize: (size) => {
    set({ size: Math.min(45, Math.max(16, size)) });
  },

  newTerminal: async () => {
    set({ isOpen: true, activeTab: "terminal" });
    const nextIndex = get().terminalSessions.length + 1;
    const session = await createTerminalSession(nextIndex);
    set((state) => ({
      terminalSessions: [...state.terminalSessions, session],
      activeTerminalId: session.id,
    }));
    get().appendOutput(
      session.status === "ready"
        ? {
            level: "info",
            title: `Opened ${session.title}`,
            detail: session.cwd ?? undefined,
          }
        : {
            level: "error",
            title: `${session.title} unavailable`,
            detail: session.error ?? undefined,
          },
    );
  },

  closeTerminal: async (id) => {
    const session = get().terminalSessions.find((entry) => entry.id === id);
    if (session?.ptySessionId) {
      try {
        await terminalService.kill(session.ptySessionId);
      } catch {
        // Ignore terminal shutdown failures during local cleanup.
      }
    }

    set((state) => {
      const remaining = state.terminalSessions.filter((entry) => entry.id !== id);
      const exitSplit =
        state.splitTerminalIds != null &&
        (state.splitTerminalIds[0] === id || state.splitTerminalIds[1] === id);
      return {
        terminalSessions: remaining,
        activeTerminalId:
          state.activeTerminalId === id ? (remaining[0]?.id ?? null) : state.activeTerminalId,
        splitTerminalIds: exitSplit ? null : state.splitTerminalIds,
      };
    });
    if (session) {
      get().appendOutput({
        level: "info",
        title: `Closed ${session.title}`,
      });
    }
  },

  setActiveTerminal: (id) => {
    set({ activeTerminalId: id, isOpen: true, activeTab: "terminal" });
  },

  renameTerminal: (id, title) => {
    set((state) => ({
      terminalSessions: state.terminalSessions.map((s) =>
        s.id === id ? { ...s, title } : s,
      ),
    }));
  },

  splitTerminal: async () => {
    const state = get();
    // Toggle off if already split
    if (state.splitTerminalIds != null) {
      set({ splitTerminalIds: null });
      return;
    }

    let sessions = state.terminalSessions;
    let activeId = state.activeTerminalId;

    // Ensure at least 2 sessions exist
    if (sessions.length < 2) {
      await get().newTerminal();
      const updated = get();
      sessions = updated.terminalSessions;
      activeId = updated.activeTerminalId;
    }

    const secondSession = sessions.find((s) => s.id !== activeId);
    if (activeId && secondSession) {
      set({ splitTerminalIds: [activeId, secondSession.id] });
    }
  },

  unsplitTerminal: () => {
    set({ splitTerminalIds: null });
  },

  appendOutput: (entry) => {
    set((state) => ({
      outputEntries: [
        {
          ...entry,
          id: crypto.randomUUID(),
          timestamp: entry.timestamp ?? Date.now(),
        },
        ...state.outputEntries,
      ].slice(0, MAX_OUTPUT_ENTRIES),
    }));
  },

  clearOutput: () => {
    set({ outputEntries: [] });
  },

  _reset: () => {
    set({
      isOpen: false,
      activeTab: "terminal",
      size: 28,
      terminalSessions: [],
      activeTerminalId: null,
      splitTerminalIds: null,
      outputEntries: [],
    });
  },
}));
