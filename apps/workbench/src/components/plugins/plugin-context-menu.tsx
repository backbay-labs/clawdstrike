/**
 * PluginContextMenuItems - Renders plugin-contributed context menu items.
 *
 * A headless component that returns menu item elements for embedding inside
 * existing context menu rendering. Items are filtered by when-clause evaluation
 * against the provided workbench context. Clicking an item calls onExecuteCommand
 * with the referenced command ID.
 *
 * Also exports usePluginContextMenuItems hook for consumers who want custom rendering.
 */

import {
  useContextMenuItems,
  evaluateWhenClause,
  type ContextMenuTarget,
  type WhenContext,
} from "@/lib/plugins/context-menu-registry";

// ---------------------------------------------------------------------------
// Hook for custom rendering
// ---------------------------------------------------------------------------

/**
 * React hook returning plugin context menu items for a menu target,
 * filtered by when-clause evaluation against the provided context.
 */
export function usePluginContextMenuItems(
  menu: ContextMenuTarget,
  context: WhenContext,
) {
  const items = useContextMenuItems(menu);
  return items.filter((item) => evaluateWhenClause(item.when, context));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface PluginContextMenuItemsProps {
  /** Which context menu is being rendered. */
  menu: ContextMenuTarget;
  /** Current workbench context for evaluating when-clauses. */
  context: WhenContext;
  /** Callback when a plugin menu item is clicked. Receives the command ID. */
  onExecuteCommand: (commandId: string) => void;
  /** Optional className for the separator/group wrapper. */
  className?: string;
}

/**
 * Renders plugin-contributed context menu items for a specific menu target.
 *
 * Includes a separator before plugin items. Returns null when no visible
 * items exist for the menu.
 */
export function PluginContextMenuItems({
  menu,
  context,
  onExecuteCommand,
}: PluginContextMenuItemsProps) {
  const visibleItems = usePluginContextMenuItems(menu, context);

  if (visibleItems.length === 0) return null;

  return (
    <>
      {/* Separator before plugin items */}
      <div className="h-px bg-[#2d3240] my-1" role="separator" />
      {visibleItems.map((item) => (
        <button
          key={item.id}
          className="flex items-center gap-2 w-full px-3 py-1.5 text-left text-[11px] font-mono text-[#ece7dc] hover:bg-[#2d3240] rounded transition-colors"
          onClick={() => onExecuteCommand(item.command)}
        >
          {item.icon && (
            <span className="text-[#6f7f9a] text-xs w-4 text-center shrink-0">
              {item.icon.charAt(0).toUpperCase()}
            </span>
          )}
          <span className="truncate">{item.label}</span>
        </button>
      ))}
    </>
  );
}
