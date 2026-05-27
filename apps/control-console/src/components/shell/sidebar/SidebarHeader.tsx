import { useState } from "react";
import { APP_VERSION } from "../../../hooks/useConsoleStatus";
import { BrandMark } from "../BrandMark";

export interface SidebarHeaderProps {
  collapsed: boolean;
  onToggle?: () => void;
  /** Wordmark caption version; defaults to the live app version. */
  version?: string;
}

/** Brand row at the top of every sidebar variant, with an optional collapse control. */
export function SidebarHeader({ collapsed, onToggle, version = APP_VERSION }: SidebarHeaderProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: collapsed ? "14px 10px 10px" : "14px 14px 10px",
        justifyContent: collapsed ? "center" : "flex-start",
        borderBottom: "1px solid rgba(27,34,48,0.6)",
      }}
    >
      {collapsed ? <BrandMark size={36} /> : <BrandMark size={36} showWordmark version={version} />}
      {!collapsed && onToggle && <CollapseButton onToggle={onToggle} />}
    </div>
  );
}

function CollapseButton({ onToggle }: { onToggle: () => void }) {
  const [hover, setHover] = useState(false);

  return (
    <button
      type="button"
      onClick={onToggle}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      aria-label="Collapse sidebar"
      title="Collapse sidebar"
      className="cs-nav-focus"
      style={{
        marginLeft: "auto",
        width: 24,
        height: 24,
        borderRadius: 6,
        border: "1px solid transparent",
        background: hover ? "rgba(214,177,90,0.06)" : "transparent",
        cursor: "pointer",
        color: hover ? "var(--gold)" : "rgba(154,167,181,0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 0,
        flexShrink: 0,
        transition: "background 0.14s ease, color 0.14s ease",
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
        <path d="M8 3L4 6l4 3" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </button>
  );
}
