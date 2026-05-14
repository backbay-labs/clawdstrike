import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "motion/react";
import { FILE_TYPE_REGISTRY, getDescriptor } from "@/lib/workbench/file-type-registry";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { getTranslatableTargets } from "@/lib/workbench/detection-workflow/translations";

// ---- Types ----

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onNewTab: (fileType: FileType) => void;
  onNavigate: (path: string) => void;
  onOpenFile: () => void;
  onValidate: () => void;
  onToggleCoverage: () => void;
  onDraftDetectionFromHunt?: () => void;
  onTranslate?: (targetFileType: FileType) => void;
  currentFileType?: FileType;
}

type CommandCategory = "File" | "Navigate" | "Format" | "Hunt" | "Translate";

interface Command {
  id: string;
  label: string;
  category: CommandCategory;
  shortcut?: string;
  /** Hex color for the format dot (new-file commands). */
  dotColor?: string;
  action: () => void;
}

// ---- Helpers ----

const CATEGORY_ORDER = ["File", "Navigate", "Hunt", "Format", "Translate"] as const;

function buildCommands(
  onNewTab: (ft: FileType) => void,
  onNavigate: (path: string) => void,
  onOpenFile: () => void,
  onValidate: () => void,
  onToggleCoverage: () => void,
  onClose: () => void,
  onDraftDetectionFromHunt?: () => void,
  onTranslate?: (targetFileType: FileType) => void,
  currentFileType?: FileType,
): Command[] {
  const reg = FILE_TYPE_REGISTRY;
  return [
    // File
    {
      id: "new-policy",
      label: "New Policy",
      category: "File",
      shortcut: "\u2318N",
      dotColor: reg.clawdstrike_policy.iconColor,
      action: () => { onNewTab("clawdstrike_policy"); onClose(); },
    },
    {
      id: "new-sigma",
      label: "New Sigma Rule",
      category: "File",
      dotColor: reg.sigma_rule.iconColor,
      action: () => { onNewTab("sigma_rule"); onClose(); },
    },
    {
      id: "new-yara",
      label: "New YARA Rule",
      category: "File",
      dotColor: reg.yara_rule.iconColor,
      action: () => { onNewTab("yara_rule"); onClose(); },
    },
    {
      id: "new-ocsf",
      label: "New OCSF Event",
      category: "File",
      dotColor: reg.ocsf_event.iconColor,
      action: () => { onNewTab("ocsf_event"); onClose(); },
    },
    {
      id: "open-file",
      label: "Open File\u2026",
      category: "File",
      shortcut: "\u2318O",
      action: () => { onOpenFile(); onClose(); },
    },

    // Navigate
    {
      id: "nav-editor",
      label: "Go to Editor",
      category: "Navigate",
      shortcut: "\u23181",
      action: () => { onNavigate("/editor"); onClose(); },
    },
    {
      id: "nav-library",
      label: "Go to Library",
      category: "Navigate",
      shortcut: "\u23186",
      action: () => { onNavigate("/library"); onClose(); },
    },
    {
      id: "nav-lab",
      label: "Go to Lab",
      category: "Navigate",
      shortcut: "\u23182",
      action: () => { onNavigate("/lab"); onClose(); },
    },
    {
      id: "nav-sentinels",
      label: "Go to Sentinels",
      category: "Navigate",
      action: () => { onNavigate("/sentinels"); onClose(); },
    },
    {
      id: "nav-findings",
      label: "Go to Findings",
      category: "Navigate",
      action: () => { onNavigate("/findings"); onClose(); },
    },
    {
      id: "nav-settings",
      label: "Go to Settings",
      category: "Navigate",
      action: () => { onNavigate("/settings"); onClose(); },
    },
    {
      id: "nav-compliance",
      label: "Go to Compliance",
      category: "Navigate",
      shortcut: "\u23184",
      action: () => { onNavigate("/compliance"); onClose(); },
    },

    // Hunt
    ...(onDraftDetectionFromHunt
      ? [
          {
            id: "draft-detection-from-hunt",
            label: "Draft Detection from Hunt",
            category: "Hunt" as const,
            dotColor: "#7c9aef",
            action: () => { onDraftDetectionFromHunt(); onClose(); },
          },
        ]
      : []),

    // Format
    {
      id: "validate",
      label: "Validate Current File",
      category: "Format",
      shortcut: "\u2318\u21a9",
      action: () => { onValidate(); onClose(); },
    },
    {
      id: "attack-coverage",
      label: "Show ATT&CK Coverage",
      category: "Format",
      action: () => { onToggleCoverage(); onClose(); },
    },

    // Translate
    ...(onTranslate && currentFileType
      ? getTranslatableTargets(currentFileType).map((target) => {
          let desc: { label: string; iconColor: string } | undefined;
          try { desc = getDescriptor(target); } catch { /* unknown file type */ }
          return {
            id: `translate-to-${target}`,
            label: `Translate to ${desc?.label ?? target}`,
            category: "Translate" as CommandCategory,
            dotColor: desc?.iconColor,
            action: () => { onTranslate(target); onClose(); },
          };
        })
      : []),
  ];
}

// ---- Component ----

export function CommandPalette({
  open,
  onClose,
  onNewTab,
  onNavigate,
  onOpenFile,
  onValidate,
  onToggleCoverage,
  onDraftDetectionFromHunt,
  onTranslate,
  currentFileType,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const commands = useMemo(
    () => buildCommands(onNewTab, onNavigate, onOpenFile, onValidate, onToggleCoverage, onClose, onDraftDetectionFromHunt, onTranslate, currentFileType),
    [onNewTab, onNavigate, onOpenFile, onValidate, onToggleCoverage, onClose, onDraftDetectionFromHunt, onTranslate, currentFileType],
  );

  // Filter commands by query
  const filtered = useMemo(() => {
    if (!query) return commands;
    const q = query.toLowerCase();
    return commands.filter((c) => c.label.toLowerCase().includes(q));
  }, [commands, query]);

  // Group filtered commands by category, preserving order
  const groups = useMemo(() => {
    const map = new Map<string, Command[]>();
    for (const cat of CATEGORY_ORDER) map.set(cat, []);
    for (const cmd of filtered) {
      const list = map.get(cmd.category);
      if (list) list.push(cmd);
    }
    return CATEGORY_ORDER
      .map((cat) => ({ category: cat, items: map.get(cat) ?? [] }))
      .filter((g) => g.items.length > 0);
  }, [filtered]);

  // Flat list of visible commands for keyboard navigation
  const flatItems = useMemo(() => groups.flatMap((g) => g.items), [groups]);

  // Pre-compute flat index for each command id to avoid mutable counter in render
  const flatIndexMap = useMemo(() => {
    const map = new Map<string, number>();
    let idx = 0;
    for (const group of groups) {
      for (const cmd of group.items) {
        map.set(cmd.id, idx++);
      }
    }
    return map;
  }, [groups]);

  // Reset state when opening
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIndex(0);
      // Defer focus to next tick so the input is mounted
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // Clamp selection when filter results change
  useEffect(() => {
    setSelectedIndex((prev) => Math.min(prev, Math.max(0, flatItems.length - 1)));
  }, [flatItems.length]);

  // Scroll the active item into view
  useEffect(() => {
    if (!listRef.current) return;
    const active = listRef.current.querySelector("[data-active='true']");
    if (active) {
      active.scrollIntoView({ block: "nearest" });
    }
  }, [selectedIndex]);

  const executeSelected = useCallback(() => {
    const cmd = flatItems[selectedIndex];
    if (cmd) cmd.action();
  }, [flatItems, selectedIndex]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIndex((i) => (i + 1) % Math.max(1, flatItems.length));
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIndex((i) => (i - 1 + flatItems.length) % Math.max(1, flatItems.length));
          break;
        case "Enter":
          e.preventDefault();
          executeSelected();
          break;
        case "Escape":
          e.preventDefault();
          onClose();
          break;
        case "Tab":
          e.preventDefault(); // Trap focus inside palette
          break;
      }
    },
    [flatItems.length, executeSelected, onClose],
  );

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.12 }}
            className="fixed inset-0 bg-black/50 z-50"
            onClick={onClose}
          />
          {/* Palette container */}
          <motion.div
            initial={{ opacity: 0, scale: 0.97, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: -8 }}
            transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
            role="dialog"
            aria-modal="true"
            className="fixed top-[15vh] left-1/2 -translate-x-1/2 z-50 w-full max-w-[560px] max-h-[400px] bg-[#0b0d13] border border-[#2d3240] rounded-lg shadow-2xl flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={handleKeyDown}
          >
            {/* Search input */}
            <div className="flex items-center border-b border-[#2d3240]">
              <span className="pl-4 text-[#d4a84b] text-[15px] select-none font-mono" aria-hidden>
                &gt;
              </span>
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setSelectedIndex(0);
                }}
                placeholder="Type a command\u2026"
                className="flex-1 text-[14px] font-mono text-[#ece7dc] bg-transparent w-full px-2 py-3 outline-none caret-[#d4a84b] placeholder:text-[#6f7f9a]/60"
                spellCheck={false}
                autoComplete="off"
              />
            </div>

            {/* Command list */}
            <div ref={listRef} className="overflow-y-auto flex-1" role="listbox">
              {groups.length === 0 && (
                <div className="px-4 py-6 text-center font-mono">
                  <div className="text-[12px] text-[#6f7f9a]">No matching commands</div>
                  <div className="text-[10px] text-[#6f7f9a]/50 mt-1">Try a shorter query, or press Esc to close.</div>
                </div>
              )}

              {groups.map((group) => (
                <div key={group.category}>
                  {/* Category header */}
                  <div className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a] px-4 py-1 mt-1 select-none">
                    {group.category}
                  </div>

                  {group.items.map((cmd) => {
                    const idx = flatIndexMap.get(cmd.id) ?? 0;
                    const isActive = idx === selectedIndex;
                    return (
                      <div
                        key={cmd.id}
                        data-active={isActive}
                        role="option"
                        aria-selected={isActive}
                        className={`flex items-center justify-between py-2 cursor-pointer transition-colors ${
                          isActive
                            ? "bg-[#131721]/60 text-[#ece7dc]"
                            : "text-[#ece7dc] hover:bg-[#131721]/60"
                        }`}
                        style={{ borderLeft: '3px solid transparent', paddingLeft: '13px', paddingRight: '16px', borderLeftColor: isActive ? '#d4a84b' : 'transparent' }}
                        onMouseEnter={() => setSelectedIndex(idx)}
                        onClick={() => cmd.action()}
                      >
                        <span className="flex items-center gap-2 text-[12px] font-mono truncate">
                          {cmd.dotColor && (
                            <span
                              className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                              style={{ backgroundColor: cmd.dotColor }}
                            />
                          )}
                          {cmd.label}
                        </span>

                        {cmd.shortcut && (
                          <kbd className="ml-4 flex-shrink-0 text-[9px] text-[#6f7f9a] bg-[#131721] px-1.5 py-0.5 rounded font-mono">
                            {cmd.shortcut}
                          </kbd>
                        )}
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
