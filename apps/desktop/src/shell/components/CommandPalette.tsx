/**
 * CommandPalette - Quick navigation and command execution
 */
import { useState, useCallback, useEffect, useRef, useMemo } from "react";
import type { KeyboardEvent } from "react";
import { clsx } from "clsx";
import { getPlugins } from "../plugins";
import type { AppId } from "../plugins/types";

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectApp: (appId: AppId) => void;
  extraCommands?: PaletteCommand[];
}

export interface PaletteCommand {
  id: string;
  group?: string;
  title: string;
  description?: string;
  shortcut?: string;
  action: () => void;
}

interface GroupedPaletteCommand {
  key: string;
  index: number;
  command: PaletteCommand;
}

interface PaletteCommandGroup {
  name: string;
  items: GroupedPaletteCommand[];
}

export function CommandPalette({ isOpen, onClose, onSelectApp, extraCommands = [] }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const plugins = getPlugins();

  // Build command list
  const commands = useMemo<PaletteCommand[]>(
    () =>
      plugins.map((plugin, index) => ({
        id: plugin.id,
        group: "Applications",
        title: plugin.name,
        description: plugin.description,
        shortcut: index < 6 ? `Cmd+${index + 1}` : undefined,
        action: () => onSelectApp(plugin.id),
      })),
    [onSelectApp, plugins]
  );
  const fullCommands = useMemo(() => [...extraCommands, ...commands], [commands, extraCommands]);

  // Filter commands
  const filteredCommands = useMemo(
    () =>
      query
        ? fullCommands.filter(
            (cmd) =>
              cmd.title.toLowerCase().includes(query.toLowerCase()) ||
              cmd.description?.toLowerCase().includes(query.toLowerCase())
          )
        : fullCommands,
    [fullCommands, query]
  );

  const groupedCommands = useMemo(() => {
    const map = new Map<string, PaletteCommandGroup>();
    filteredCommands.forEach((command, index) => {
      const groupName = command.group ?? "Commands";
      const existing = map.get(groupName);
      const item: GroupedPaletteCommand = {
        key: `${command.id}:${index}`,
        index,
        command,
      };
      if (existing) {
        existing.items.push(item);
      } else {
        map.set(groupName, { name: groupName, items: [item] });
      }
    });
    return Array.from(map.values());
  }, [filteredCommands]);

  // Reset selection when query changes
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
      setQuery("");
      setSelectedIndex(0);
    }
  }, [isOpen]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (filteredCommands.length === 0) {
        if (e.key === "Escape") {
          e.preventDefault();
          onClose();
        }
        return;
      }

      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIndex((i) => Math.min(i + 1, filteredCommands.length - 1));
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIndex((i) => Math.max(i - 1, 0));
          break;
        case "Enter":
          e.preventDefault();
          if (filteredCommands[selectedIndex]) {
            filteredCommands[selectedIndex].action();
            onClose();
          }
          break;
        case "Escape":
          e.preventDefault();
          onClose();
          break;
      }
    },
    [filteredCommands, selectedIndex, onClose]
  );

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[16vh]">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-[rgba(2,3,7,0.78)] backdrop-blur-md" onClick={onClose} />

      {/* Palette */}
      <div className="premium-panel premium-panel--lens relative w-full max-w-[820px] overflow-hidden rounded-2xl">
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3">
          <span className="origin-glyph-orb origin-glyph-orb--small shrink-0" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <SearchIcon />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search runs, receipts, tools..."
                className="premium-input flex-1 px-3 py-2 text-sm text-sdr-text-primary placeholder:text-sdr-text-muted outline-none"
              />
              <kbd className="premium-chip px-2 py-1 text-[9px] font-mono uppercase tracking-[0.11em] text-sdr-text-secondary">
                Cmd+K
              </kbd>
              <kbd className="premium-chip px-2 py-1 text-[9px] font-mono uppercase tracking-[0.11em] text-sdr-text-secondary">
                Esc
              </kbd>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="origin-label text-[9px] tracking-[0.16em] text-[color:rgba(213,173,87,0.86)]">
                Command Lens
              </span>
              <span className="premium-chip px-1.5 py-0.5 text-[8px] font-mono uppercase text-sdr-text-muted">
                {filteredCommands.length} results
              </span>
              <span className="premium-separator h-px flex-1" />
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="origin-focus-ring premium-chip premium-chip--control px-2.5 py-1 text-[10px] font-mono uppercase tracking-[0.11em] text-sdr-text-secondary"
          >
            Close
          </button>
        </div>
        <div className="premium-separator h-px w-full" />

        {/* Results */}
        <div className="max-h-[460px] overflow-y-auto px-2 py-2">
          {filteredCommands.length === 0 ? (
            <div className="px-4 py-8 text-center text-sdr-text-muted">No results found</div>
          ) : (
            groupedCommands.map((group) => (
              <section key={group.name} className="mb-2 last:mb-0">
                <div className="flex items-center gap-2 px-2 py-1">
                  <span className="origin-label text-[9px] tracking-[0.16em] text-[color:rgba(213,173,87,0.84)]">
                    {group.name}
                  </span>
                  <span className="premium-separator h-px flex-1" />
                </div>
                <ul className="space-y-1 px-1">
                  {group.items.map((item) => {
                    const cmd = item.command;
                    const index = item.index;
                    return (
                      <li key={item.key}>
                        <button
                          onClick={() => {
                            cmd.action();
                            onClose();
                          }}
                          data-selected={index === selectedIndex ? "true" : "false"}
                          className={clsx(
                            "origin-focus-ring premium-result-row flex w-full items-center justify-between px-3 py-2 text-left",
                            index === selectedIndex
                              ? "text-sdr-text-primary"
                              : "text-sdr-text-secondary"
                          )}
                        >
                          <div>
                            <div className="text-sm font-medium">{cmd.title}</div>
                            {cmd.description && (
                              <div className="text-xs text-sdr-text-muted">{cmd.description}</div>
                            )}
                          </div>
                          {cmd.shortcut && (
                            <kbd className="premium-chip px-2 py-1 text-[9px] font-mono uppercase tracking-[0.11em] text-sdr-text-muted">
                              {cmd.shortcut}
                            </kbd>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </section>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function SearchIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-[color:rgba(213,173,87,0.88)]"
    >
      <circle cx="11" cy="11" r="8" />
      <path d="M21 21l-4.35-4.35" />
    </svg>
  );
}
