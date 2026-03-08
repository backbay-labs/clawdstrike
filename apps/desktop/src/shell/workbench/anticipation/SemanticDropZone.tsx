/**
 * SemanticDropZone — renders semantic drop slot pills inside a target.
 *
 * Each pill corresponds to a DropRole (e.g. "Target", "Evidence", "Cite").
 * The default role gets stronger styling; non-defaults are subtler. On
 * click or drop onto a pill, the associated semantic is emitted via onDrop.
 */
import { useCallback } from "react";
import type { DropRole, DropSemantic } from "./types";

export interface SemanticDropZoneProps {
  roles: DropRole[];
  defaultRole: DropRole | null;
  selectedSemantic?: DropSemantic | null;
  onDrop: (semantic: DropSemantic) => void;
  onPreview?: (semantic: DropSemantic) => void;
  visible: boolean;
}

function DropPill({
  role,
  isDefault,
  isSelected,
  onDrop,
  onPreview,
}: {
  role: DropRole;
  isDefault: boolean;
  isSelected: boolean;
  onDrop: (semantic: DropSemantic) => void;
  onPreview?: (semantic: DropSemantic) => void;
}) {
  const handleClick = useCallback(() => {
    onDrop(role.semantic);
  }, [role.semantic, onDrop]);

  return (
    <button
      type="button"
      onClick={handleClick}
      style={{
        display: "inline-flex",
        alignItems: "center",
        height: 24,
        paddingLeft: 8,
        paddingRight: 8,
        paddingTop: 2,
        paddingBottom: 2,
        borderRadius: 6,
        border: isDefault
          ? "1px solid rgba(213,173,87,0.3)"
          : "1px solid rgba(213,173,87,0.1)",
        background: isSelected
          ? "rgba(213,173,87,0.18)"
          : isDefault
          ? "rgba(213,173,87,0.12)"
          : "rgba(213,173,87,0.04)",
        color: isSelected
          ? "rgba(232,230,222,0.95)"
          : isDefault
          ? "rgba(213,173,87,0.9)"
          : "rgba(232,230,222,0.5)",
        fontFamily: "monospace",
        fontSize: 10,
        lineHeight: 1,
        cursor: "pointer",
        transition: "background 100ms ease, border-color 100ms ease",
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
      onPointerEnter={() => onPreview?.(role.semantic)}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLElement).style.background = "rgba(213,173,87,0.18)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = isSelected
          ? "rgba(213,173,87,0.18)"
          : isDefault
          ? "rgba(213,173,87,0.12)"
          : "rgba(213,173,87,0.04)";
      }}
    >
      {role.label}
    </button>
  );
}

export function SemanticDropZone({
  roles,
  defaultRole,
  selectedSemantic,
  onDrop,
  onPreview,
  visible,
}: SemanticDropZoneProps) {
  if (roles.length === 0) return null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "row",
        alignItems: "center",
        justifyContent: "center",
        gap: 4,
        height: 24,
        opacity: visible ? 1 : 0,
        transition: "opacity 120ms ease",
        pointerEvents: visible ? "auto" : "none",
      }}
    >
      {roles.map((role) => (
        <DropPill
          key={role.id}
          role={role}
          isDefault={defaultRole?.id === role.id}
          isSelected={selectedSemantic === role.semantic}
          onDrop={onDrop}
          onPreview={onPreview}
        />
      ))}
    </div>
  );
}
