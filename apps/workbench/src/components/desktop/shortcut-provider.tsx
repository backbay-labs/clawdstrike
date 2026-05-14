/**
 * ShortcutProvider — reads all commands with keybindings from the registry
 * and wires them to a single global keydown listener.
 *
 * The SHORTCUT_DEFINITIONS export is preserved (derived from the registry)
 * so that ShortcutHelpDialog continues to work unchanged.
 */
import { useEffect } from "react";
import { useBottomPaneStore } from "@/features/bottom-pane/bottom-pane-store";
import { getActivePaneRoute, usePaneStore } from "@/features/panes/pane-store";
import {
  commandRegistry,
  type Command,
  type CommandContext,
} from "@/lib/command-registry";
import { normalizeWorkbenchRoute } from "./workbench-routes";

// ---- Keybinding parser ----

interface ParsedKeybinding {
  key: string;
  meta: boolean;
  shift: boolean;
  alt: boolean;
}

/**
 * Parse a keybinding string like "Meta+Shift+V" into a matcher object.
 */
function parseKeybinding(binding: string): ParsedKeybinding {
  const parts = binding.split("+");
  const key = parts[parts.length - 1].toLowerCase();
  const meta = parts.some((p) => p === "Meta");
  const shift = parts.some((p) => p === "Shift");
  const alt = parts.some((p) => p === "Alt");
  return { key, meta, shift, alt };
}

const SHIFTED_SYMBOL_KEY_MAP: Record<string, string> = {
  "~": "`",
  "!": "1",
  "@": "2",
  "#": "3",
  "$": "4",
  "%": "5",
  "^": "6",
  "&": "7",
  "*": "8",
  "(": "9",
  ")": "0",
  "_": "-",
  "+": "=",
  "{": "[",
  "}": "]",
  "|": "\\",
  ":": ";",
  "\"": "'",
  "<": ",",
  ">": ".",
  "?": "/",
};

function normalizePressedKey(key: string): string {
  const normalized = key.toLowerCase();
  return SHIFTED_SYMBOL_KEY_MAP[key] ?? SHIFTED_SYMBOL_KEY_MAP[normalized] ?? normalized;
}

function isShiftedSymbolAlias(key: string): boolean {
  return key in SHIFTED_SYMBOL_KEY_MAP;
}

function getShortcutBindings(): Array<{
  cmd: Command & { keybinding: string };
  parsed: ParsedKeybinding;
}> {
  const bindings = commandRegistry
    .getAll()
    .filter((cmd): cmd is Command & { keybinding: string } => !!cmd.keybinding)
    .map((cmd) => ({
      cmd,
      parsed: parseKeybinding(cmd.keybinding),
    }));

  bindings.sort((a, b) => {
    if (a.parsed.key === b.parsed.key) {
      return (b.parsed.shift ? 1 : 0) - (a.parsed.shift ? 1 : 0);
    }
    return 0;
  });

  return bindings;
}

// ---- Shortcut definition type (for help dialog compatibility) ----

export interface ShortcutDefinition {
  key: string;
  meta: boolean;
  shift?: boolean;
  alt?: boolean;
  description: string;
  category: string;
}

function getCommandContexts(command: Command): CommandContext[] {
  if (!command.context) {
    return ["global"];
  }
  return Array.isArray(command.context) ? command.context : [command.context];
}

function resolveActiveShortcutContexts(target: EventTarget | null): Set<CommandContext> {
  const contexts = new Set<CommandContext>(["global"]);
  const element = target instanceof Element ? target : null;

  if (element?.closest('[data-shortcut-context="terminal"]')) {
    contexts.add("terminal");
    return contexts;
  }

  contexts.add("pane");

  const route = normalizeWorkbenchRoute(
    getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
  );
  if (route.startsWith("/editor") || route.startsWith("/file/")) {
    contexts.add("editor");
  }

  if (useBottomPaneStore.getState().isOpen && useBottomPaneStore.getState().activeTab === "terminal") {
    const activeElement = document.activeElement;
    if (activeElement instanceof Element && activeElement.closest('[data-shortcut-context="terminal"]')) {
      contexts.add("terminal");
      contexts.delete("pane");
      contexts.delete("editor");
    }
  }

  return contexts;
}

function commandMatchesShortcutContext(command: Command, target: EventTarget | null): boolean {
  const activeContexts = resolveActiveShortcutContexts(target);
  return getCommandContexts(command).some((context) => activeContexts.has(context));
}

/**
 * Derive SHORTCUT_DEFINITIONS from the current registry snapshot.
 * This is exported so ShortcutHelpDialog can import it.
 *
 * Note: since this is derived dynamically, the help dialog must live inside
 * the ShortcutProvider tree (which it already does via InitCommands).
 */
export function getShortcutDefinitions(): ShortcutDefinition[] {
  return commandRegistry
    .getAll()
    .filter((cmd): cmd is Command & { keybinding: string } => !!cmd.keybinding)
    .map((cmd) => {
      const parsed = parseKeybinding(cmd.keybinding);
      return {
        key: parsed.key,
        meta: parsed.meta,
        shift: parsed.shift || undefined,
        alt: parsed.alt || undefined,
        description: cmd.title,
        category: cmd.category,
      };
    });
}

// SHORTCUT_DEFINITIONS removed — was always empty at module load time
// (registry not populated yet). Use getShortcutDefinitions() for live data.

// ---- Component ----

/**
 * Registers a single global keydown listener that dispatches to command.execute()
 * for any command whose keybinding matches the pressed keys.
 *
 * Renders nothing — visual output (ShortcutHelpDialog) is now handled
 * by InitCommands which manages the dialog open/close state.
 */
export function ShortcutProvider() {
  useEffect(() => {
    function handleKeydown(e: KeyboardEvent) {
      const modifierPressed = e.metaKey || e.ctrlKey;
      const normalizedKey = normalizePressedKey(e.key);
      const bindings = getShortcutBindings();

      for (const { cmd, parsed } of bindings) {
        if (!commandMatchesShortcutContext(cmd, e.target)) {
          continue;
        }

        const keyMatches = normalizedKey === parsed.key;
        const metaMatches = parsed.meta ? modifierPressed : !modifierPressed;
        const shiftMatches = parsed.shift
          ? e.shiftKey
          : !e.shiftKey || (isShiftedSymbolAlias(e.key) && normalizedKey === parsed.key);
        const altMatches = parsed.alt ? e.altKey : !e.altKey;

        if (keyMatches && metaMatches && shiftMatches && altMatches) {
          e.preventDefault();
          e.stopPropagation();
          void commandRegistry.execute(cmd.id);
          return;
        }
      }

    }

    window.addEventListener("keydown", handleKeydown, { capture: true });
    return () => {
      window.removeEventListener("keydown", handleKeydown, { capture: true });
    };
  }, []);

  // ShortcutHelpDialog is now rendered by InitCommands.
  return null;
}
