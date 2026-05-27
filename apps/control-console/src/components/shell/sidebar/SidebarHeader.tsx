import { useState } from "react";
import { APP_VERSION } from "../../../hooks/useConsoleStatus";
import { BrandMark } from "../BrandMark";

export interface SidebarHeaderProps {
  collapsed: boolean;
  /**
   * Toggle the collapsed state. When provided, a persistent collapse/expand
   * chevron is rendered in BOTH states so the sidebar can always be reopened
   * without leaving for Settings.
   */
  onToggle?: () => void;
  /** Keyboard shortcut hint surfaced in the toggle tooltip (e.g. "⌘\\"). */
  toggleShortcut?: string;
  /** Wordmark caption version; defaults to the live app version. */
  version?: string;
}

/** Brand row at the top of every sidebar variant, with an optional collapse control. */
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
        flexDirection: collapsed ? "column" : "row",
        alignItems: "center",
        gap: collapsed ? 8 : 10,
        padding: collapsed ? "14px 10px 10px" : "14px 14px 10px",
        justifyContent: collapsed ? "center" : "flex-start",
        borderBottom: "1px solid rgba(27,34,48,0.6)",
        position: "relative",
      }}
    >
      {/*
       * The wordmark is always mounted so its label can fade rather than pop.
       * `BrandMark` lays the wordmark out to the right of the tile; when
       * collapsed we fade + clip it so only the 36px tile reads (rail-like).
       */}
      <BrandMark size={36} showWordmark wordmarkHidden={collapsed} version={version} />
      {onToggle && (
        <CollapseToggle collapsed={collapsed} onToggle={onToggle} shortcut={toggleShortcut} />
      )}
    </div>
  );
}

interface CollapseToggleProps {
  collapsed: boolean;
  onToggle: () => void;
  shortcut?: string;
}

/**
 * Persistent collapse/expand control. Renders a chevron pointing left to
 * collapse and right to expand, anchored consistently in the sidebar header in
 * both states so the affordance never disappears.
 */
function CollapseToggle({ collapsed, onToggle, shortcut }: CollapseToggleProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const highlighted = hover || focused;

  const label = collapsed ? "Expand sidebar" : "Collapse sidebar";
  const tooltipKbd = shortcut ? ` (${shortcut})` : "";

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        // Expanded: pinned to the right of the brand row. Collapsed: a dedicated
        // centered control directly beneath the tile — always visible and never
        // overlapping the mark, so re-opening is obvious without leaving for
        // Settings.
        position: "relative",
        marginLeft: collapsed ? undefined : "auto",
        display: "flex",
        flexShrink: 0,
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        aria-label={label}
        aria-expanded={!collapsed}
        title={`${label}${tooltipKbd}`}
        className="cs-nav-focus"
        style={{
          width: collapsed ? 28 : 24,
          height: collapsed ? 22 : 24,
          borderRadius: 6,
          // Collapsed: a faint resting outline so the expand affordance is
          // discoverable at rest (not hover-only). Expanded: invisible until hover.
          border: collapsed
            ? `1px solid ${highlighted ? "var(--gold-edge)" : "rgba(27,34,48,0.9)"}`
            : "1px solid transparent",
          background: highlighted
            ? "rgba(214,177,90,0.08)"
            : collapsed
              ? "rgba(0,0,0,0.3)"
              : "transparent",
          cursor: "pointer",
          color: highlighted ? "var(--gold)" : "rgba(154,167,181,0.55)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 0,
          transition: "background 0.14s ease, color 0.14s ease, border-color 0.14s ease",
        }}
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 12 12"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          aria-hidden="true"
        >
          {/* "‹" to collapse, "›" to expand */}
          {collapsed ? (
            <path d="M4 3l4 3-4 3" strokeLinecap="round" strokeLinejoin="round" />
          ) : (
            <path d="M8 3L4 6l4 3" strokeLinecap="round" strokeLinejoin="round" />
          )}
        </svg>
      </button>
      {/*
       * Custom hover tooltip only in the collapsed rail, where there is room to
       * the right and discoverability of the expand control matters most. In the
       * expanded state the chevron is self-evident and the native `title`
       * (with the shortcut) still covers it, avoiding a tooltip that would hang
       * past the sidebar edge over the canvas.
       */}
      {collapsed && highlighted && (
        <span
          role="tooltip"
          style={{
            position: "absolute",
            left: "calc(100% + 8px)",
            top: "50%",
            transform: "translateY(-50%)",
            background: "rgba(11,13,16,0.97)",
            border: "1px solid var(--gold-edge)",
            borderRadius: 8,
            padding: "5px 9px",
            whiteSpace: "nowrap",
            pointerEvents: "none",
            fontFamily: "var(--glia-font-mono)",
            fontSize: 10,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--text)",
            boxShadow: "0 6px 24px rgba(0,0,0,0.6), inset 0 1px 0 rgba(214,177,90,0.15)",
            zIndex: 60,
          }}
        >
          {label}
          {shortcut && (
            <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 9.5 }}>{shortcut}</span>
          )}
        </span>
      )}
    </div>
  );
}
