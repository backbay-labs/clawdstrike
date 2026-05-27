import { useState } from "react";

export interface SidebarSearchProps {
  onCmdK: () => void;
}

/** Inline launcher (expanded sidebar only) that defers to the command palette (⌘K). */
export function SidebarSearch({ onCmdK }: SidebarSearchProps) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const highlighted = hover || focused;

  return (
    <button
      type="button"
      onClick={onCmdK}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      aria-label="Search apps, agents, policies"
      className="cs-nav-focus"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        margin: "10px 12px 8px",
        padding: "7px 10px",
        border: `1px solid ${highlighted ? "var(--gold-edge)" : "rgba(27,34,48,0.85)"}`,
        borderRadius: 8,
        background: "rgba(0,0,0,0.4)",
        cursor: "pointer",
        width: "calc(100% - 24px)",
        color: highlighted ? "var(--gold)" : "rgba(154,167,181,0.55)",
        transition: "border-color 0.14s ease, color 0.14s ease",
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
        className="font-mono"
        style={{ fontSize: 11, letterSpacing: "0.04em", flex: 1, textAlign: "left" }}
      >
        Search apps, agents, policies…
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 9.5,
          letterSpacing: "0.08em",
          padding: "2px 5px",
          border: "1px solid rgba(27,34,48,0.9)",
          borderRadius: 4,
          background: "rgba(11,13,16,0.6)",
          color: "rgba(154,167,181,0.5)",
        }}
      >
        ⌘ K
      </span>
    </button>
  );
}
