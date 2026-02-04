/**
 * CommandPalette - Quick navigation and command execution
 */
import { useState, useCallback, useEffect, useRef } from "react";
import { clsx } from "clsx";
import { getPlugins } from "../plugins";
import type { AppId } from "../plugins/types";

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectApp: (appId: AppId) => void;
}

interface Command {
  id: string;
  title: string;
  description?: string;
  shortcut?: string;
  action: () => void;
}

export function CommandPalette({ isOpen, onClose, onSelectApp }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const plugins = getPlugins();

  // Build command list
  const commands: Command[] = plugins.map((plugin, index) => ({
    id: plugin.id,
    title: plugin.name,
    description: plugin.description,
    shortcut: index < 6 ? `Cmd+${index + 1}` : undefined,
    action: () => onSelectApp(plugin.id),
  }));

  // Filter commands
  const filteredCommands = query
    ? commands.filter(
        (cmd) =>
          cmd.title.toLowerCase().includes(query.toLowerCase()) ||
          cmd.description?.toLowerCase().includes(query.toLowerCase())
      )
    : commands;

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
    (e: React.KeyboardEvent) => {
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
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      {/* Palette */}
      <div className="relative w-full max-w-xl bg-sdr-bg-secondary border border-sdr-border rounded-xl shadow-2xl overflow-hidden">
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-sdr-border">
          <SearchIcon />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search views..."
            className="flex-1 bg-transparent text-sdr-text-primary placeholder:text-sdr-text-muted outline-none"
          />
          <kbd className="px-2 py-1 text-xs text-sdr-text-muted bg-sdr-bg-tertiary rounded">Esc</kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto">
          {filteredCommands.length === 0 ? (
            <div className="px-4 py-8 text-center text-sdr-text-muted">No results found</div>
          ) : (
            <ul>
              {filteredCommands.map((cmd, index) => (
                <li key={cmd.id}>
                  <button
                    onClick={() => {
                      cmd.action();
                      onClose();
                    }}
                    className={clsx(
                      "w-full flex items-center justify-between px-4 py-3 text-left transition-colors",
                      index === selectedIndex
                        ? "bg-sdr-accent-blue/20 text-sdr-text-primary"
                        : "text-sdr-text-secondary hover:bg-sdr-bg-tertiary"
                    )}
                  >
                    <div>
                      <div className="font-medium">{cmd.title}</div>
                      {cmd.description && (
                        <div className="text-sm text-sdr-text-muted">{cmd.description}</div>
                      )}
                    </div>
                    {cmd.shortcut && (
                      <kbd className="px-2 py-1 text-xs text-sdr-text-muted bg-sdr-bg-tertiary rounded">
                        {cmd.shortcut}
                      </kbd>
                    )}
                  </button>
                </li>
              ))}
            </ul>
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
      className="text-sdr-text-muted"
    >
      <circle cx="11" cy="11" r="8" />
      <path d="M21 21l-4.35-4.35" />
    </svg>
  );
}
