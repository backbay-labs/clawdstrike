import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { SHORTCUT_DEFINITIONS } from "./shortcut-provider";

interface ShortcutHelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Detect macOS for modifier key display. */
const isMac =
  typeof navigator !== "undefined" && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

function formatKeybinding(def: { key: string; meta: boolean; shift?: boolean }): string {
  const parts: string[] = [];
  if (def.meta) parts.push(isMac ? "\u2318" : "Ctrl");
  if (def.shift) parts.push(isMac ? "\u21e7" : "Shift");
  // Prettify special keys
  const displayKey = def.key === "/" ? "?" : def.key.toUpperCase();
  parts.push(displayKey);
  return parts.join(isMac ? "" : "+");
}

const CATEGORY_ORDER = ["File", "Edit", "Policy", "Navigate", "Help"] as const;

type Category = (typeof CATEGORY_ORDER)[number];

function groupByCategory() {
  const groups = new Map<Category, typeof SHORTCUT_DEFINITIONS[number][]>();
  for (const cat of CATEGORY_ORDER) {
    groups.set(cat, []);
  }
  for (const def of SHORTCUT_DEFINITIONS) {
    const list = groups.get(def.category as Category);
    if (list) list.push(def);
  }
  return groups;
}

export function ShortcutHelpDialog({ open, onOpenChange }: ShortcutHelpDialogProps) {
  const groups = groupByCategory();

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
                  {items.map((def) => (
                    <div
                      key={`${def.key}-${def.shift ?? false}`}
                      className="flex items-center justify-between py-1.5 px-2 rounded-md hover:bg-[#131721]/60 transition-colors"
                    >
                      <span className="text-[12px] text-[#ece7dc]/80">
                        {def.description}
                      </span>
                      <kbd className="inline-flex items-center gap-0.5 rounded border border-[#2d3240] bg-[#131721] px-2 py-0.5 text-[11px] font-mono text-[#d4a84b]">
                        {formatKeybinding(def)}
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
