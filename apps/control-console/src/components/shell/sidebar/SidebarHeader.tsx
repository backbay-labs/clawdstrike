import { APP_VERSION } from "../../../hooks/useConsoleStatus";
import { BrandMark } from "../BrandMark";

export interface SidebarHeaderProps {
  collapsed: boolean;
  /**
   * Toggle the collapsed state. When provided (expanded variant only), the
   * engraved "C" mark itself becomes the open/close control — click it to
   * collapse or expand. Rail / two-pane omit it, so their mark stays static.
   */
  onToggle?: () => void;
  /** Keyboard shortcut hint surfaced in the toggle's title (e.g. "⌘\\"). */
  toggleShortcut?: string;
  /** Wordmark caption version; defaults to the live app version. */
  version?: string;
}

/**
 * Brand row at the top of every sidebar variant. The mark sits beside the
 * wordmark when expanded and centers when collapsed (the wordmark fades + clips
 * away during the morph). When `onToggle` is provided the mark doubles as the
 * collapse/expand toggle — there is no separate chevron.
 */
export function SidebarHeader({
  collapsed,
  onToggle,
  toggleShortcut,
  version = APP_VERSION,
}: SidebarHeaderProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: collapsed ? "center" : "flex-start",
        padding: collapsed ? "14px 0 12px" : "14px 14px 10px",
        borderBottom: "1px solid rgba(27,34,48,0.6)",
      }}
    >
      <BrandMark
        size={36}
        showWordmark
        wordmarkHidden={collapsed}
        version={version}
        onToggle={onToggle}
        toggleCollapsed={collapsed}
        toggleShortcut={toggleShortcut}
      />
    </div>
  );
}
