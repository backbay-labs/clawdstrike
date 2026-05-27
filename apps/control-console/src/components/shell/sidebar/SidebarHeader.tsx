import { useRef, useState } from "react";
import { APP_VERSION } from "../../../hooks/useConsoleStatus";
import { BrandMark } from "../BrandMark";
import { Tooltip } from "./NavItem";

export interface SidebarHeaderProps {
  collapsed: boolean;
  /**
   * Toggle the collapsed state. When provided, a collapse/expand chevron is
   * rendered in BOTH states so the sidebar can always be reopened without
   * leaving for Settings.
   */
  onToggle?: () => void;
  /** Keyboard shortcut hint surfaced in the toggle tooltip (e.g. "⌘\\"). */
  toggleShortcut?: string;
  /** Wordmark caption version; defaults to the live app version. */
  version?: string;
}

/**
 * Brand row at the top of every sidebar variant.
 *
 * Expanded: brand tile + wordmark on the left, a quiet collapse chevron pinned
 * right (matches the original handoff). Collapsed: the brand tile centered as
 * the hero, with a borderless, understated expand chevron beneath it — kept
 * subordinate to the mark so the top-left reads intentional, not tacked-on.
 */
export function SidebarHeader({
  collapsed,
  onToggle,
  toggleShortcut,
  version = APP_VERSION,
}: SidebarHeaderProps) {
  if (collapsed) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 10,
          padding: "14px 0 12px",
          borderBottom: "1px solid rgba(27,34,48,0.6)",
        }}
      >
        <BrandMark size={36} showWordmark wordmarkHidden version={version} />
        {onToggle && <ExpandChevron onToggle={onToggle} shortcut={toggleShortcut} />}
      </div>
    );
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "14px 14px 10px",
        borderBottom: "1px solid rgba(27,34,48,0.6)",
      }}
    >
      <BrandMark size={36} showWordmark version={version} />
      {onToggle && <CollapseChevron onToggle={onToggle} shortcut={toggleShortcut} />}
    </div>
  );
}

interface ChevronProps {
  onToggle: () => void;
  shortcut?: string;
}

/**
 * Expanded → collapse control. A quiet 24px chevron pinned to the right of the
 * brand row, invisible until hover (matches the original handoff). The native
 * `title` carries the shortcut.
 */
function CollapseChevron({ onToggle, shortcut }: ChevronProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const highlighted = hover || focused;
  const tooltipKbd = shortcut ? ` (${shortcut})` : "";

  return (
    <button
      type="button"
      onClick={onToggle}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      aria-label="Collapse sidebar"
      aria-expanded={true}
      title={`Collapse sidebar${tooltipKbd}`}
      className="cs-nav-focus"
      style={{
        marginLeft: "auto",
        width: 24,
        height: 24,
        borderRadius: 6,
        border: "1px solid transparent",
        background: highlighted ? "rgba(214,177,90,0.06)" : "transparent",
        cursor: "pointer",
        color: highlighted ? "var(--gold)" : "rgba(154,167,181,0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 0,
        flexShrink: 0,
        transition: "background 0.14s ease, color 0.14s ease",
      }}
    >
      <ChevronGlyph direction="left" />
    </button>
  );
}

/**
 * Collapsed → expand control. A borderless, understated chevron centered below
 * the brand tile: low-opacity at rest so it never competes with the mark, with
 * a soft gold wash on hover/focus. Discoverability is carried by the clip-proof
 * portal tooltip ("Expand sidebar (⌘\\)") and the ⌘\\ shortcut.
 */
function ExpandChevron({ onToggle, shortcut }: ChevronProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const highlighted = hover || focused;
  const tooltipKbd = shortcut ? ` (${shortcut})` : "";

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ position: "relative", display: "flex" }}
    >
      <button
        ref={buttonRef}
        type="button"
        onClick={onToggle}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        aria-label="Expand sidebar"
        aria-expanded={false}
        title={`Expand sidebar${tooltipKbd}`}
        className="cs-nav-focus"
        style={{
          width: 28,
          height: 20,
          borderRadius: 6,
          border: "none",
          background: highlighted ? "rgba(214,177,90,0.08)" : "transparent",
          cursor: "pointer",
          // Quiet at rest, gold on interaction — subordinate to the brand mark.
          color: highlighted ? "var(--gold)" : "rgba(154,167,181,0.4)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 0,
          transition: "background 0.14s ease, color 0.14s ease",
        }}
      >
        <ChevronGlyph direction="right" />
      </button>
      {highlighted && <Tooltip label="Expand sidebar" kbd={shortcut} anchorRef={buttonRef} />}
    </div>
  );
}

/** Shared 12px chevron glyph. "left" = ‹ (collapse), "right" = › (expand). */
function ChevronGlyph({ direction }: { direction: "left" | "right" }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
    >
      {direction === "left" ? (
        <path d="M8 3L4 6l4 3" strokeLinecap="round" strokeLinejoin="round" />
      ) : (
        <path d="M4 3l4 3-4 3" strokeLinecap="round" strokeLinejoin="round" />
      )}
    </svg>
  );
}
