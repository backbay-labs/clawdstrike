/**
 * CommandPalette — Cmd+K fuzzy search powered by the command registry.
 *
 * Shows recent commands (last 10, from localStorage) when the query is empty,
 * then live-searches the registry as the user types.
 * Results are grouped by category.
 */
import { useState, useCallback, useEffect, useRef, useMemo, useSyncExternalStore } from "react";
import { motion } from "motion/react";
import { IconSearch } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { commandRegistry, type Command, type CommandCategory } from "@/lib/command-registry";

// ---- Recent commands (persisted to localStorage) ----

const RECENT_KEY = "clawdstrike_recent_commands";
const MAX_RECENT = 10;

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as string[]).slice(0, MAX_RECENT) : [];
  } catch {
    return [];
  }
}

function pushRecent(id: string): void {
  const list = loadRecent().filter((x) => x !== id);
  list.unshift(id);
  if (list.length > MAX_RECENT) list.length = MAX_RECENT;
  localStorage.setItem(RECENT_KEY, JSON.stringify(list));
}

// ---- Keybinding display ----

import { formatKeybinding } from "@/lib/format-keybinding";

// ---- Category ordering for grouped display ----

const CATEGORY_ORDER: CommandCategory[] = [
  "Navigate",
  "File",
  "Edit",
  "Policy",
  "Guard",
  "Sentinel",
  "Fleet",
  "Swarm",
  "Hunt",
  "Observatory",
  "Test",
  "Receipt",
  "View",
  "Sidebar",
  "Help",
];

function groupByCategory(commands: Command[]): [CommandCategory, Command[]][] {
  const map = new Map<CommandCategory, Command[]>();
  for (const cmd of commands) {
    let list = map.get(cmd.category);
    if (!list) {
      list = [];
      map.set(cmd.category, list);
    }
    list.push(cmd);
  }
  // Return in canonical order, skip empty groups
  const result: [CommandCategory, Command[]][] = [];
  for (const cat of CATEGORY_ORDER) {
    const list = map.get(cat);
    if (list && list.length > 0) result.push([cat, list]);
  }
  return result;
}

// ---- Component ----

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Subscribe to registry changes so we re-render when commands are added/removed.
  const registryVersion = useSyncExternalStore(
    (cb) => commandRegistry.subscribe(cb),
    () => commandRegistry.getVersion(),
  );

  // Build the result list: recent (no query) or searched
  const results = useMemo(() => {
    if (!query.trim()) {
      // Show recent commands first (if they still exist), then all commands
      const recentIds = loadRecent();
      const all = commandRegistry.getAll();
      const recentCmds: Command[] = [];
      const seen = new Set<string>();

      for (const id of recentIds) {
        const cmd = commandRegistry.getById(id);
        if (cmd) {
          recentCmds.push(cmd);
          seen.add(cmd.id);
        }
      }

      // Append remaining commands not in recent
      for (const cmd of all) {
        if (!seen.has(cmd.id)) {
          recentCmds.push(cmd);
        }
      }
      return recentCmds;
    }
    return commandRegistry.search(query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, registryVersion]);

  const grouped = useMemo(() => groupByCategory(results), [results]);

  // Flatten grouped for keyboard navigation
  const flat = useMemo(() => grouped.flatMap(([, cmds]) => cmds), [grouped]);

  // Cmd+K toggle
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
        setQuery("");
        setSelectedIndex(0);
      }
      if (e.key === "Escape" && open) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open]);

  // Focus input when opened
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 50);
  }, [open]);

  // Clamp selectedIndex when list shrinks
  useEffect(() => {
    setSelectedIndex((i) => (flat.length === 0 ? 0 : Math.min(i, flat.length - 1)));
  }, [flat]);

  const executeCommand = useCallback(
    (cmd: Command) => {
      pushRecent(cmd.id);
      void commandRegistry.execute(cmd.id);
      setOpen(false);
    },
    [],
  );

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, flat.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        const clamped = Math.min(selectedIndex, flat.length - 1);
        const cmd = flat[clamped];
        if (cmd) executeCommand(cmd);
      }
    },
    [flat, selectedIndex, executeCommand],
  );

  if (!open) return null;

  // Track the running index across all groups for highlighting
  let runningIndex = 0;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[20vh]"
      onClick={() => setOpen(false)}
    >
      <div className="fixed inset-0 bg-[#05060a]/60 backdrop-blur-sm" />
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: -10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.15 }}
        className="relative w-full max-w-lg rounded-xl border border-[#2d3240] bg-[#131721] shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[#2d3240]">
          <IconSearch size={16} stroke={1.5} className="text-[#6f7f9a]/50" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Search commands..."
            aria-label="Search commands"
            className="flex-1 bg-transparent text-[13px] text-[#ece7dc] placeholder-[#6f7f9a]/40 outline-none"
          />
          <kbd className="text-[9px] font-mono text-[#6f7f9a]/40 border border-[#2d3240]/60 rounded px-1.5 py-0.5">
            ESC
          </kbd>
        </div>

        {/* Results grouped by category */}
        <div className="max-h-[300px] overflow-y-auto py-2">
          {flat.length === 0 ? (
            <p className="px-4 py-6 text-center text-[12px] text-[#6f7f9a]/40">
              No results
            </p>
          ) : (
            grouped.map(([category, cmds]) => {
              const startIndex = runningIndex;
              runningIndex += cmds.length;
              return (
                <div key={category}>
                  {/* Category header */}
                  <div className="px-4 pt-2 pb-1">
                    <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 font-semibold">
                      {category}
                    </span>
                  </div>
                  {cmds.map((cmd, j) => {
                    const flatIdx = startIndex + j;
                    return (
                      <button
                        key={cmd.id}
                        onClick={() => executeCommand(cmd)}
                        aria-label={`${cmd.category}: ${cmd.title}`}
                        className={cn(
                          "flex items-center justify-between w-full px-4 py-2 text-left transition-colors",
                          flatIdx === selectedIndex
                            ? "bg-[#d4a84b]/10 text-[#ece7dc]"
                            : "text-[#6f7f9a] hover:bg-[#0b0d13]",
                        )}
                      >
                        <span className="text-[12px]">{cmd.title}</span>
                        {cmd.keybinding && (
                          <kbd className="text-[9px] font-mono text-[#6f7f9a]/30">
                            {formatKeybinding(cmd.keybinding)}
                          </kbd>
                        )}
                      </button>
                    );
                  })}
                </div>
              );
            })
          )}
        </div>
      </motion.div>
    </div>
  );
}
