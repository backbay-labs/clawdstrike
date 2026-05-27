import { useRef, useState } from "react";
import { Tooltip } from "./NavItem";

export interface SidebarSearchProps {
  onCmdK: () => void;
  /** Collapse to an icon-only launcher that still opens the command palette. */
  collapsed?: boolean;
}

const MORPH = "cubic-bezier(0.22,1,0.36,1)";

/** Inline launcher that defers to the existing command palette (⌘K). */
export function SidebarSearch({ onCmdK, collapsed = false }: SidebarSearchProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const highlighted = hover || focused;

  return (
    <div style={{ position: "relative", margin: collapsed ? "10px 8px 8px" : "10px 12px 8px" }}>
      <button
        ref={buttonRef}
        type="button"
        onClick={onCmdK}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        aria-label="Search apps, agents, policies"
        className="cs-nav-focus cs-animated"
        style={{
          display: "flex",
          alignItems: "center",
          gap: collapsed ? 0 : 8,
          padding: "7px 10px",
          justifyContent: collapsed ? "center" : "flex-start",
          border: `1px solid ${highlighted ? "var(--gold-edge)" : "rgba(27,34,48,0.85)"}`,
          borderRadius: 8,
          background: "rgba(0,0,0,0.4)",
          cursor: "pointer",
          width: "100%",
          color: highlighted ? "var(--gold)" : "rgba(154,167,181,0.55)",
          overflow: "hidden",
          transition: `border-color 0.14s ease, color 0.14s ease`,
        }}
      >
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          aria-hidden="true"
          style={{ flexShrink: 0 }}
        >
          <circle cx="11" cy="11" r="7" />
          <path d="M21 21l-4.3-4.3" />
        </svg>
        <span
          className="font-mono cs-animated"
          aria-hidden={collapsed || undefined}
          style={{
            fontSize: 11,
            letterSpacing: "0.04em",
            flex: collapsed ? "0 0 0px" : 1,
            width: collapsed ? 0 : undefined,
            textAlign: "left",
            whiteSpace: "nowrap",
            overflow: "hidden",
            opacity: collapsed ? 0 : 1,
            transition: `opacity 0.18s ${MORPH}, flex-basis 0.2s ${MORPH}`,
          }}
        >
          Search apps, agents, policies…
        </span>
        <span
          className="font-mono cs-animated"
          aria-hidden={collapsed || undefined}
          style={{
            fontSize: 9.5,
            letterSpacing: "0.08em",
            padding: collapsed ? "0" : "2px 5px",
            border: collapsed ? "1px solid transparent" : "1px solid rgba(27,34,48,0.9)",
            borderRadius: 4,
            background: collapsed ? "transparent" : "rgba(11,13,16,0.6)",
            color: "rgba(154,167,181,0.5)",
            whiteSpace: "nowrap",
            overflow: "hidden",
            width: collapsed ? 0 : undefined,
            opacity: collapsed ? 0 : 1,
            flexShrink: 0,
            transition: `opacity 0.18s ${MORPH}`,
          }}
        >
          ⌘ K
        </span>
      </button>
      {collapsed && highlighted && <Tooltip label="Search" kbd="⌘K" anchorRef={buttonRef} />}
    </div>
  );
}
