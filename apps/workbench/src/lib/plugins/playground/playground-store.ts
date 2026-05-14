/**
 * Playground Store
 *
 * Module-level reactive store for the Plugin Playground state.
 * Uses the Map + listeners + useSyncExternalStore pattern matching
 * status-bar-registry.ts and view-registry.ts.
 */
import { useSyncExternalStore } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Error info from transpilation or runtime evaluation. */
export interface PlaygroundError {
  message: string;
  line?: number;
  column?: number;
  stack?: string;
}

/** A single console output entry captured from the playground plugin. */
export interface ConsoleEntry {
  level: "log" | "warn" | "error" | "info";
  args: unknown[];
  timestamp: number;
}

/** Snapshot of what a playground plugin contributed to the workbench. */
export interface ContributionSnapshot {
  guards: string[];
  commands: string[];
  fileTypes: string[];
  editorTabs: string[];
  bottomPanelTabs: string[];
  rightSidebarPanels: string[];
  statusBarItems: string[];
}

/** Full playground state shape. */
export interface PlaygroundState {
  source: string;
  transpiled: string | null;
  isRunning: boolean;
  runCount: number;
  errors: PlaygroundError[];
  consoleEntries: ConsoleEntry[];
  contributions: ContributionSnapshot | null;
  lastRunTimestamp: number | null;
}

// ---------------------------------------------------------------------------
// Default plugin template
// ---------------------------------------------------------------------------

const DEFAULT_SOURCE = `import { createPlugin } from "@clawdstrike/plugin-sdk";

export default createPlugin({
  manifest: {
    id: "playground.my-plugin",
    name: "my-plugin",
    displayName: "My Plugin",
    description: "A playground plugin experiment",
    version: "0.1.0",
    publisher: "playground",
    categories: ["security"],
    trust: "internal",
    activationEvents: ["onStartup"],
    contributions: {
      guards: [
        {
          id: "my-guard",
          name: "My Guard",
          technicalName: "my_guard",
          description: "A custom guard from the playground",
          category: "custom",
          defaultVerdict: "allow",
        },
      ],
      commands: [
        {
          id: "playground.hello",
          title: "Playground: Hello World",
          category: "Playground",
        },
      ],
    },
  },
  activate(ctx) {
    console.log("[MyPlugin] activated!");
    ctx.commands.register(
      { id: "playground.hello", title: "Playground: Hello World", category: "Playground" },
      () => console.log("Hello from the playground!"),
    );
    return [];
  },
  deactivate() {
    console.log("[MyPlugin] deactivated");
  },
});
`;

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

let state: PlaygroundState = {
  source: DEFAULT_SOURCE,
  transpiled: null,
  isRunning: false,
  runCount: 0,
  errors: [],
  consoleEntries: [],
  contributions: null,
  lastRunTimestamp: null,
};

const listeners = new Set<() => void>();

/** Frozen snapshot for useSyncExternalStore reference stability. */
let snapshot: Readonly<PlaygroundState> = Object.freeze({ ...state });

function notify(): void {
  snapshot = Object.freeze({ ...state });
  for (const listener of listeners) {
    listener();
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export function setSource(s: string): void {
  state = { ...state, source: s };
  notify();
}

export function setTranspiled(js: string | null): void {
  state = { ...state, transpiled: js };
  notify();
}

export function setRunning(b: boolean): void {
  state = { ...state, isRunning: b };
  notify();
}

export function incrementRunCount(): void {
  state = { ...state, runCount: state.runCount + 1 };
  notify();
}

export function addError(e: PlaygroundError): void {
  state = { ...state, errors: [...state.errors, e] };
  notify();
}

export function clearErrors(): void {
  state = { ...state, errors: [] };
  notify();
}

export function addConsoleEntry(e: ConsoleEntry): void {
  state = { ...state, consoleEntries: [...state.consoleEntries, e] };
  notify();
}

export function clearConsole(): void {
  state = { ...state, consoleEntries: [] };
  notify();
}

export function setContributions(c: ContributionSnapshot | null): void {
  state = { ...state, contributions: c };
  notify();
}

export function setLastRunTimestamp(ts: number | null): void {
  state = { ...state, lastRunTimestamp: ts };
  notify();
}

// ---------------------------------------------------------------------------
// Non-hook state accessor (for use outside React components)
// ---------------------------------------------------------------------------

/** Get the current playground state without subscribing to updates. */
export function getPlaygroundState(): Readonly<PlaygroundState> {
  return snapshot;
}

// ---------------------------------------------------------------------------
// React hooks
// ---------------------------------------------------------------------------

/** Hook returning the full playground state snapshot. */
export function usePlaygroundStore(): Readonly<PlaygroundState> {
  return useSyncExternalStore(subscribe, () => snapshot);
}

/** Hook returning just the source code string. */
export function usePlaygroundSource(): string {
  return useSyncExternalStore(subscribe, () => snapshot.source);
}

/** Hook returning the console entries array. */
export function usePlaygroundConsole(): readonly ConsoleEntry[] {
  return useSyncExternalStore(subscribe, () => snapshot.consoleEntries);
}

/** Hook returning the contribution snapshot. */
export function usePlaygroundContributions(): ContributionSnapshot | null {
  return useSyncExternalStore(subscribe, () => snapshot.contributions);
}

/** Hook returning the errors array. */
export function usePlaygroundErrors(): readonly PlaygroundError[] {
  return useSyncExternalStore(subscribe, () => snapshot.errors);
}
