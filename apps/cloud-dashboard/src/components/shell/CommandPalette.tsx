import { useState, useMemo, useEffect, useRef } from "react";
import { useDesktopOS } from "@backbay/glia-desktop";
import { AnimatePresence, motion } from "framer-motion";
import { processes, PROCESS_ICONS } from "../../state/processRegistry";
import { NoiseGrain } from "../ui";

interface Command {
  id: string;
  name: string;
  description: string;
  icon?: React.ReactNode;
  action: () => void;
}

export function CommandPalette({ open, onClose, onLock }: { open: boolean; onClose: () => void; onLock?: () => void }) {
  const { processes: procManager } = useDesktopOS();
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = useMemo<Command[]>(() => {
    const cmds: Command[] = processes.map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description || "",
      icon: PROCESS_ICONS[p.id],
      action: () => { procManager.launch(p.id); onClose(); },
    }));
    cmds.push({ id: "lock", name: "Lock Screen", description: "Lock the desktop", action: () => { onLock?.(); onClose(); } });
    return cmds;
  }, [procManager, onClose, onLock]);

  const filtered = useMemo(() => {
    if (!query) return commands;
    const q = query.toLowerCase();
    return commands.filter((c) => c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q));
  }, [commands, query]);

  useEffect(() => {
    setSelectedIdx(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    const id = setTimeout(() => inputRef.current?.focus(), 50);
    return () => clearTimeout(id);
  }, [open]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSelectedIdx((i) => Math.min(i + 1, filtered.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSelectedIdx((i) => Math.max(i - 1, 0)); }
    else if (e.key === "Enter" && filtered[selectedIdx]) { filtered[selectedIdx].action(); }
    else if (e.key === "Escape") { onClose(); }
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          onClick={onClose}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "center",
            paddingTop: "15vh",
            background: "rgba(0,0,0,0.5)",
            backdropFilter: "blur(4px)",
          }}
        >
          <motion.div
            initial={{ y: -10, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -10, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
            className="glass-panel"
            style={{ width: "100%", maxWidth: 480, overflow: "hidden" }}
          >
            <NoiseGrain />
            <div style={{ position: "relative", zIndex: 2 }}>
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search commands..."
                className="font-mono"
                style={{
                  width: "100%",
                  padding: "14px 20px",
                  background: "transparent",
                  border: "none",
                  borderBottom: "1px solid var(--slate)",
                  outline: "none",
                  color: "var(--text)",
                  fontSize: 14,
                  letterSpacing: "0.02em",
                }}
              />
              <div style={{ maxHeight: 300, overflowY: "auto", padding: "4px 0" }}>
                {filtered.map((cmd, i) => (
                  <div
                    key={cmd.id}
                    onClick={cmd.action}
                    className="hover-row"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "10px 20px",
                      cursor: "pointer",
                      background: i === selectedIdx ? "var(--gold-bloom)" : "transparent",
                    }}
                  >
                    {cmd.icon && <span style={{ display: "flex", flexShrink: 0 }}>{cmd.icon}</span>}
                    <div>
                      <div className="font-mono" style={{ fontSize: 13, color: "var(--text)" }}>{cmd.name}</div>
                      {cmd.description && (
                        <div className="font-body" style={{ fontSize: 11, color: "var(--muted)", opacity: 0.6 }}>
                          {cmd.description}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                {filtered.length === 0 && (
                  <div className="font-mono" style={{ padding: "16px 20px", fontSize: 12, color: "var(--muted)" }}>
                    No matching commands
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
