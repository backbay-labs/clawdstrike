import { useMemo, useSyncExternalStore } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { commandRegistry, type Command, type CommandCategory } from "@/lib/command-registry";

interface ShortcutHelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

import { formatKeybinding } from "@/lib/format-keybinding";

const CATEGORY_ORDER: CommandCategory[] = [
  "File",
  "Edit",
  "Policy",
  "Navigate",
  "Guard",
  "Sentinel",
  "Fleet",
  "Test",
  "Receipt",
  "View",
  "Help",
];

type CommandWithKeybinding = Command & { keybinding: string };

function groupByCategory(commands: CommandWithKeybinding[]): Map<CommandCategory, CommandWithKeybinding[]> {
  const groups = new Map<CommandCategory, CommandWithKeybinding[]>();
  for (const cat of CATEGORY_ORDER) {
    groups.set(cat, []);
  }
  for (const cmd of commands) {
    const list = groups.get(cmd.category);
    if (list) list.push(cmd);
  }
  return groups;
}

export function ShortcutHelpDialog({ open, onOpenChange }: ShortcutHelpDialogProps) {
  // Subscribe to the registry so the dialog updates when commands change
  const registryVersion = useSyncExternalStore(
    (cb) => commandRegistry.subscribe(cb),
    () => commandRegistry.getVersion(),
  );

  const commandsWithKeybindings = useMemo(
    () =>
      commandRegistry
        .getAll()
        .filter((cmd): cmd is Command & { keybinding: string } => !!cmd.keybinding),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [registryVersion],
  );

  const groups = useMemo(
    () => groupByCategory(commandsWithKeybindings),
    [commandsWithKeybindings],
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="sm:max-w-lg bg-[#0b0d13] border border-[#2d3240] text-[#ece7dc]"
        showCloseButton
      >
        <DialogHeader>
          <DialogTitle className="text-[#d4a84b] text-base font-semibold">
            Keyboard Shortcuts
          </DialogTitle>
          <DialogDescription className="text-[#6f7f9a] text-xs">
            Quick reference for all available shortcuts.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-5 max-h-[60vh] overflow-y-auto pr-1 -mr-1">
          {CATEGORY_ORDER.map((category) => {
            const items = groups.get(category);
            if (!items || items.length === 0) return null;
            return (
              <div key={category}>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#6f7f9a] mb-2">
                  {category}
                </h3>
                <div className="grid gap-1">
                  {items.map((cmd) => (
                    <div
                      key={cmd.id}
                      className="flex items-center justify-between py-1.5 px-2 rounded-md hover:bg-[#131721]/60 transition-colors"
                    >
                      <span className="text-[12px] text-[#ece7dc]/80">
                        {cmd.title}
                      </span>
                      <kbd className="inline-flex items-center gap-0.5 rounded border border-[#2d3240] bg-[#131721] px-2 py-0.5 text-[11px] font-mono text-[#d4a84b]">
                        {formatKeybinding(cmd.keybinding)}
                      </kbd>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </DialogContent>
    </Dialog>
  );
}
