/**
 * CommandPalette — Cmd+K fuzzy search for pages, actions, and entities.
 */
import { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { IconSearch } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface CommandItem {
  id: string;
  label: string;
  section: string;
  href?: string;
  shortcut?: string;
}

const COMMANDS: CommandItem[] = [
  // Navigation
  { id: "home", label: "Home", section: "Navigate", href: "/home", shortcut: "\u23181" },
  { id: "editor", label: "Policy Editor", section: "Navigate", href: "/editor", shortcut: "\u23182" },
  { id: "lab", label: "Lab", section: "Navigate", href: "/lab", shortcut: "\u23183" },
  { id: "sentinels", label: "Sentinels", section: "Navigate", href: "/sentinels" },
  { id: "findings", label: "Findings & Intel", section: "Navigate", href: "/findings" },
  { id: "fleet", label: "Fleet Dashboard", section: "Navigate", href: "/fleet" },
  { id: "approvals", label: "Approvals", section: "Navigate", href: "/approvals" },
  { id: "audit", label: "Audit Log", section: "Navigate", href: "/audit" },
  { id: "compliance", label: "Compliance", section: "Navigate", href: "/compliance" },
  { id: "receipts", label: "Receipts", section: "Navigate", href: "/receipts" },
  { id: "topology", label: "Topology", section: "Navigate", href: "/topology" },
  { id: "swarms", label: "Swarms", section: "Navigate", href: "/swarms" },
  { id: "library", label: "Policy Library", section: "Navigate", href: "/library" },
  { id: "settings", label: "Settings", section: "Navigate", href: "/settings" },
  // Actions
  { id: "new-sentinel", label: "Create Sentinel", section: "Actions", href: "/sentinels/create" },
  { id: "new-policy", label: "New Policy", section: "Actions", href: "/editor" },
  { id: "connect-fleet", label: "Connect to Fleet", section: "Actions", href: "/settings" },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  // Cmd+K toggle
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen(prev => !prev);
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

  // Filtered results
  const filtered = useMemo(() => {
    if (!query.trim()) return COMMANDS;
    const q = query.toLowerCase();
    return COMMANDS.filter(c =>
      c.label.toLowerCase().includes(q) || c.section.toLowerCase().includes(q)
    );
  }, [query]);

  // Reset selectedIndex when filtered results change so we never reference
  // an out-of-bounds index after the list shrinks.
  useEffect(() => {
    setSelectedIndex(i => (filtered.length === 0 ? 0 : Math.min(i, filtered.length - 1)));
  }, [filtered]);

  // Keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      const clamped = Math.min(selectedIndex, filtered.length - 1);
      const item = filtered[clamped];
      if (item?.href) navigate(item.href);
      setOpen(false);
    }
  }, [filtered, selectedIndex, navigate]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[20vh]" onClick={() => setOpen(false)}>
      <div className="fixed inset-0 bg-[#05060a]/60 backdrop-blur-sm" />
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: -10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.15 }}
        className="relative w-full max-w-lg rounded-xl border border-[#2d3240] bg-[#131721] shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[#2d3240]">
          <IconSearch size={16} stroke={1.5} className="text-[#6f7f9a]/50" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setSelectedIndex(0); }}
            onKeyDown={handleKeyDown}
            placeholder="Search pages and actions..."
            aria-label="Search pages and actions"
            className="flex-1 bg-transparent text-[13px] text-[#ece7dc] placeholder-[#6f7f9a]/40 outline-none"
          />
          <kbd className="text-[9px] font-mono text-[#6f7f9a]/40 border border-[#2d3240]/60 rounded px-1.5 py-0.5">ESC</kbd>
        </div>
        {/* Results */}
        <div className="max-h-[300px] overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <p className="px-4 py-6 text-center text-[12px] text-[#6f7f9a]/40">No results</p>
          ) : (
            filtered.map((item, i) => (
              <button
                key={item.id}
                onClick={() => { if (item.href) navigate(item.href); setOpen(false); }}
                aria-label={`${item.section}: ${item.label}`}
                className={cn(
                  "flex items-center justify-between w-full px-4 py-2 text-left transition-colors",
                  i === selectedIndex ? "bg-[#d4a84b]/10 text-[#ece7dc]" : "text-[#6f7f9a] hover:bg-[#0b0d13]",
                )}
              >
                <div className="flex items-center gap-2">
                  <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 w-16">{item.section}</span>
                  <span className="text-[12px]">{item.label}</span>
                </div>
                {item.shortcut && <kbd className="text-[9px] font-mono text-[#6f7f9a]/30">{item.shortcut}</kbd>}
              </button>
            ))
          )}
        </div>
      </motion.div>
    </div>
  );
}
