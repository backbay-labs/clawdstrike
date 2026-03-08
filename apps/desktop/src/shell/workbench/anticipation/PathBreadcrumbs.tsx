/**
 * PathBreadcrumbs — renders a single-line pivot trail with an optional
 * suggested next-action link.
 *
 * Shows the last 3 breadcrumbs joined by " -> " separators. If a suggested
 * action exists, it appears as a clickable italic link after the trail.
 */
import type { CSSProperties } from "react";
import type { BreadcrumbHint, SuggestedPathAction } from "./types";

// ── Props ────────────────────────────────────────────────────────

interface PathBreadcrumbsProps {
  breadcrumbs: BreadcrumbHint[];
  suggestedAction: SuggestedPathAction | null;
  onSuggestedAction: () => void;
}

// ── Styles ───────────────────────────────────────────────────────

const CONTAINER_STYLE: CSSProperties = {
  height: 20,
  display: "flex",
  flexDirection: "row",
  alignItems: "center",
  padding: "0 10px",
  overflow: "hidden",
  whiteSpace: "nowrap",
};

const CRUMB_STYLE: CSSProperties = {
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "20px",
  color: "rgba(182,183,193,0.35)",
};

const SEPARATOR_STYLE: CSSProperties = {
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "20px",
  color: "rgba(182,183,193,0.2)",
  margin: "0 4px",
};

const SUGGESTION_STYLE: CSSProperties = {
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "20px",
  fontStyle: "italic",
  color: "rgba(213,173,87,0.6)",
  background: "none",
  border: "none",
  padding: 0,
  marginLeft: 4,
  cursor: "pointer",
  transition: "color 100ms ease",
};

const DOT_SEPARATOR_STYLE: CSSProperties = {
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "20px",
  color: "rgba(182,183,193,0.2)",
  margin: "0 4px",
};

// ── Component ────────────────────────────────────────────────────

export function PathBreadcrumbs({
  breadcrumbs,
  suggestedAction,
  onSuggestedAction,
}: PathBreadcrumbsProps): React.JSX.Element | null {
  if (breadcrumbs.length === 0) return null;

  // Show only the last 3 crumbs
  const visible = breadcrumbs.slice(-3);

  return (
    <div style={CONTAINER_STYLE}>
      {visible.map((crumb, idx) => (
        <span key={crumb.objectId} style={{ display: "inline-flex", alignItems: "center" }}>
          {idx > 0 && <span style={SEPARATOR_STYLE}>{"\u2192"}</span>}
          <span style={CRUMB_STYLE}>{crumb.label}</span>
        </span>
      ))}
      {suggestedAction && (
        <>
          <span style={DOT_SEPARATOR_STYLE}>{"\u00B7"}</span>
          <button
            type="button"
            style={SUGGESTION_STYLE}
            onClick={onSuggestedAction}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.color = "rgba(213,173,87,0.8)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.color = "rgba(213,173,87,0.6)";
            }}
          >
            {suggestedAction.label}
          </button>
        </>
      )}
    </div>
  );
}
