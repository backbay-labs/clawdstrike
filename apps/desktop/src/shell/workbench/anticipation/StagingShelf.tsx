/**
 * StagingShelf — a thin strip above the bottom bar showing temporarily held items.
 *
 * Renders staged item pills (with icon + truncated title) in a horizontal scroll
 * on the left, suggestion chips on the right, and a clear button at the far right.
 * Slides up from the bottom over 150ms when the first item is staged.
 */
import { useCallback, useEffect, useState } from "react";
import type { CSSProperties, HTMLAttributes } from "react";
import type { StagedItem, StagingSuggestion } from "./types";
import { ARTIFACT_KIND_ICONS } from "../lenses/LensIcons";

// ── Props ────────────────────────────────────────────────────────

interface StagingShelfProps {
  items: StagedItem[];
  suggestions: StagingSuggestion[];
  onRemove: (itemId: string) => void;
  onClear: () => void;
  onExecuteSuggestion: (suggestion: StagingSuggestion) => void;
  dropActive?: boolean;
  isDropOver?: boolean;
  dragLabel?: string | null;
  dropTargetProps?: HTMLAttributes<HTMLDivElement>;
}

// ── Styles ───────────────────────────────────────────────────────

const SHELF_STYLE: CSSProperties = {
  height: 32,
  width: "100%",
  display: "flex",
  flexDirection: "row",
  alignItems: "center",
  gap: 6,
  padding: "0 10px",
  background: "rgba(6,8,13,0.85)",
  borderTop: "1px solid rgba(213,173,87,0.1)",
  overflow: "hidden",
  transition: "transform 150ms ease, opacity 150ms ease",
};

const ITEMS_SCROLL_STYLE: CSSProperties = {
  display: "flex",
  flexDirection: "row",
  alignItems: "center",
  gap: 4,
  flex: 1,
  minWidth: 0,
  overflowX: "auto",
  overflowY: "hidden",
  scrollbarWidth: "none",
  msOverflowStyle: "none",
};

const PILL_STYLE: CSSProperties = {
  height: 24,
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
  padding: "0 8px",
  borderRadius: 4,
  background: "rgba(213,173,87,0.06)",
  border: "1px solid rgba(213,173,87,0.1)",
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 11,
  lineHeight: "24px",
  color: "rgba(232,230,222,0.7)",
  whiteSpace: "nowrap",
  flexShrink: 0,
  cursor: "default",
  position: "relative",
};

const PILL_TITLE_STYLE: CSSProperties = {
  maxWidth: 80,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const REMOVE_BTN_STYLE: CSSProperties = {
  display: "none",
  alignItems: "center",
  justifyContent: "center",
  width: 14,
  height: 14,
  marginLeft: 2,
  padding: 0,
  background: "none",
  border: "none",
  color: "rgba(232,230,222,0.4)",
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "14px",
  cursor: "pointer",
};

const SUGGESTION_CHIP_STYLE: CSSProperties = {
  height: 22,
  display: "inline-flex",
  alignItems: "center",
  padding: "0 8px",
  borderRadius: 4,
  background: "rgba(213,173,87,0.08)",
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "22px",
  color: "rgba(213,173,87,0.7)",
  border: "none",
  cursor: "pointer",
  whiteSpace: "nowrap",
  flexShrink: 0,
  transition: "background 100ms ease",
};

const CLEAR_BTN_STYLE: CSSProperties = {
  height: 22,
  display: "inline-flex",
  alignItems: "center",
  padding: "0 6px",
  borderRadius: 4,
  background: "none",
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "22px",
  color: "rgba(182,183,193,0.4)",
  border: "1px solid rgba(182,183,193,0.1)",
  cursor: "pointer",
  whiteSpace: "nowrap",
  flexShrink: 0,
};

const SHELF_BORDER_COLOR = "rgba(213,173,87,0.1)";
const SHELF_BACKGROUND = "rgba(6,8,13,0.85)";

// ── Component ────────────────────────────────────────────────────

export function StagingShelf({
  items,
  suggestions,
  onRemove,
  onClear,
  onExecuteSuggestion,
  dropActive = false,
  isDropOver = false,
  dragLabel = null,
  dropTargetProps,
}: StagingShelfProps): React.JSX.Element | null {
  const [visible, setVisible] = useState(items.length > 0 || dropActive);

  // Animate entrance/exit
  useEffect(() => {
    if (items.length > 0 || dropActive) {
      setVisible(true);
    } else {
      // Let the slide-down animation finish before unmounting
      const timer = setTimeout(() => setVisible(false), 150);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [items.length, dropActive]);

  const handleSuggestionClick = useCallback(
    (suggestion: StagingSuggestion) => (e: React.MouseEvent) => {
      e.stopPropagation();
      onExecuteSuggestion(suggestion);
    },
    [onExecuteSuggestion],
  );

  const handleRemoveClick = useCallback(
    (itemId: string) => (e: React.MouseEvent) => {
      e.stopPropagation();
      onRemove(itemId);
    },
    [onRemove],
  );

  if (!visible) return null;

  const shelfStyle: CSSProperties = {
    ...SHELF_STYLE,
    transform: items.length > 0 || dropActive ? "translateY(0)" : "translateY(100%)",
    opacity: items.length > 0 || dropActive ? 1 : 0,
    borderTopColor: isDropOver
      ? "rgba(213,173,87,0.35)"
      : dropActive
        ? "rgba(213,173,87,0.16)"
        : SHELF_BORDER_COLOR,
    background: isDropOver
      ? "rgba(28,20,6,0.95)"
      : dropActive
        ? "rgba(10,12,18,0.92)"
        : SHELF_BACKGROUND,
  };

  return (
    <div style={shelfStyle} {...dropTargetProps}>
      {/* Staged item pills — scrollable left section */}
      <div
        style={ITEMS_SCROLL_STYLE}
        // Hide WebKit scrollbar
        className="staging-shelf-scroll"
      >
        {items.length === 0 && dropActive ? (
          <div
            className="flex min-w-0 items-center gap-2"
            style={{
              fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
              fontSize: 11,
              color: isDropOver ? "rgba(213,173,87,0.92)" : "rgba(232,230,222,0.64)",
            }}
          >
            <span
              className="inline-flex h-4 items-center rounded-sm border px-1.5 uppercase tracking-[0.12em]"
              style={{
                borderColor: isDropOver ? "rgba(213,173,87,0.35)" : "rgba(213,173,87,0.16)",
                background: isDropOver ? "rgba(213,173,87,0.12)" : "rgba(213,173,87,0.04)",
              }}
            >
              Stage
            </span>
            <span className="truncate">
              {isDropOver
                ? "Release to hold this artifact for later."
                : dragLabel ?? "Drop here to stage artifacts before deciding where they belong."}
            </span>
          </div>
        ) : null}
        {items.map((item) => {
          const IconComponent = ARTIFACT_KIND_ICONS[item.kind];
          return (
            <div
              key={item.id}
              style={PILL_STYLE}
              onMouseEnter={(e) => {
                const removeBtn = e.currentTarget.querySelector<HTMLElement>("[data-remove]");
                if (removeBtn) removeBtn.style.display = "inline-flex";
              }}
              onMouseLeave={(e) => {
                const removeBtn = e.currentTarget.querySelector<HTMLElement>("[data-remove]");
                if (removeBtn) removeBtn.style.display = "none";
              }}
            >
              {IconComponent && <IconComponent />}
              <span style={PILL_TITLE_STYLE}>{item.title}</span>
              <button
                type="button"
                data-remove
                style={REMOVE_BTN_STYLE}
                onClick={handleRemoveClick(item.id)}
                aria-label={`Remove ${item.title}`}
              >
                x
              </button>
            </div>
          );
        })}
      </div>

      {/* Suggestion chips — right section */}
      {suggestions.map((suggestion, idx) => (
        <button
          key={`${suggestion.action}-${idx}`}
          type="button"
          style={SUGGESTION_CHIP_STYLE}
          onClick={handleSuggestionClick(suggestion)}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "rgba(213,173,87,0.14)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "rgba(213,173,87,0.08)";
          }}
        >
          {suggestion.label}
        </button>
      ))}

      {items.length > 0 && dropActive && !isDropOver && (
        <span
          className="shrink-0 font-mono text-[10px]"
          style={{ color: "rgba(182,183,193,0.4)" }}
        >
          Drop to add another staged artifact
        </span>
      )}

      {/* Clear button — far right */}
      {items.length > 1 && (
        <button
          type="button"
          style={CLEAR_BTN_STYLE}
          onClick={onClear}
        >
          Clear
        </button>
      )}
    </div>
  );
}
