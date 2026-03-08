import { motion } from "motion/react";
import type { LensId } from "../workbenchState";
import type { SidebarWakeAnchorKind, SidebarWakePeekVariant } from "./types";

const LENS_LABELS: Record<LensId, string> = {
  scopes: "Scopes",
  history: "History",
  files: "Files",
  sandboxes: "Sandboxes",
  entities: "Entities",
  swarms: "Swarms",
  notes: "Notes",
};

const SOURCE_KIND_LABELS: Record<SidebarWakeAnchorKind, string> = {
  row: "Source Row",
  "hunt-pill": "Hunt Deck",
  "dock-icon": "Dock",
};

interface VariantStyle {
  minHeight: number;
  leftOrigin: number;
  background: string;
  borderColor: string;
  shadow: string;
  accent: string;
  sourceBackground: string;
  sourceColor: string;
}

const VARIANT_STYLES: Record<SidebarWakePeekVariant, VariantStyle> = {
  generic: {
    minHeight: 68,
    leftOrigin: -16,
    background: "rgba(9,12,19,0.94)",
    borderColor: "rgba(213,173,87,0.28)",
    shadow: "0 12px 32px rgba(0,0,0,0.42), 0 0 1px rgba(213,173,87,0.18)",
    accent: "linear-gradient(180deg, rgba(213,173,87,0.9), rgba(213,173,87,0.18))",
    sourceBackground: "rgba(213,173,87,0.08)",
    sourceColor: "rgba(213,173,87,0.84)",
  },
  "row-card": {
    minHeight: 74,
    leftOrigin: -20,
    background: "linear-gradient(135deg, rgba(10,14,23,0.98), rgba(8,11,18,0.92))",
    borderColor: "rgba(114,186,175,0.22)",
    shadow: "0 16px 34px rgba(0,0,0,0.42), 0 0 1px rgba(114,186,175,0.18)",
    accent: "linear-gradient(180deg, rgba(114,186,175,0.92), rgba(114,186,175,0.18))",
    sourceBackground: "rgba(114,186,175,0.1)",
    sourceColor: "rgba(163,223,214,0.9)",
  },
  "hunt-pill-chip": {
    minHeight: 70,
    leftOrigin: -12,
    background: "linear-gradient(135deg, rgba(18,15,9,0.97), rgba(10,11,18,0.94))",
    borderColor: "rgba(213,173,87,0.32)",
    shadow: "0 14px 34px rgba(0,0,0,0.44), 0 0 1px rgba(213,173,87,0.2)",
    accent: "linear-gradient(180deg, rgba(213,173,87,0.95), rgba(213,173,87,0.22))",
    sourceBackground: "rgba(213,173,87,0.12)",
    sourceColor: "rgba(232,211,145,0.92)",
  },
  "dock-icon-chip": {
    minHeight: 68,
    leftOrigin: -14,
    background: "linear-gradient(135deg, rgba(8,11,18,0.97), rgba(7,9,16,0.92))",
    borderColor: "rgba(122,146,212,0.2)",
    shadow: "0 12px 30px rgba(0,0,0,0.4), 0 0 1px rgba(122,146,212,0.16)",
    accent: "linear-gradient(180deg, rgba(122,146,212,0.9), rgba(122,146,212,0.2))",
    sourceBackground: "rgba(122,146,212,0.1)",
    sourceColor: "rgba(176,191,240,0.88)",
  },
};

export interface SidebarGhostPeekProps {
  label: string;
  reason: string | null;
  anchorLens: LensId;
  top: number;
  left: number;
  width: number;
  variant: SidebarWakePeekVariant;
  sourceKind: SidebarWakeAnchorKind | null;
  sourceLabel: string | null;
  sourceObjectType: string | null;
  onCommitOpen: () => void;
}

function titleCase(value: string) {
  return value
    .split(/[\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatSourceLabel(
  sourceKind: SidebarWakeAnchorKind | null,
  sourceObjectType: string | null,
  sourceLabel: string | null,
) {
  if (sourceKind === "row") {
    if (sourceObjectType) return `${titleCase(sourceObjectType)} Row`;
    return SOURCE_KIND_LABELS.row;
  }
  if (sourceKind === "hunt-pill") {
    return sourceLabel ?? SOURCE_KIND_LABELS["hunt-pill"];
  }
  if (sourceKind === "dock-icon") {
    return sourceLabel ?? SOURCE_KIND_LABELS["dock-icon"];
  }
  return sourceLabel ?? "Context Wake";
}

function formatSourceMeta(
  sourceKind: SidebarWakeAnchorKind | null,
  sourceObjectType: string | null,
  sourceLabel: string | null,
) {
  if (sourceKind === "row") {
    return sourceLabel ?? "Current object is steering the next move.";
  }
  if (sourceKind === "hunt-pill") {
    return sourceObjectType
      ? `Live drop surface for ${titleCase(sourceObjectType)}`
      : "Live drop surface";
  }
  if (sourceKind === "dock-icon") {
    return sourceLabel ?? "Dock wake";
  }
  return sourceLabel;
}

export function SidebarGhostPeek({
  label,
  reason,
  anchorLens,
  top,
  left,
  width,
  variant,
  sourceKind,
  sourceLabel,
  sourceObjectType,
  onCommitOpen,
}: SidebarGhostPeekProps) {
  const variantStyle = VARIANT_STYLES[variant];
  const formattedSourceLabel = formatSourceLabel(sourceKind, sourceObjectType, sourceLabel);
  const formattedSourceMeta = formatSourceMeta(sourceKind, sourceObjectType, sourceLabel);
  const showSourceMeta =
    Boolean(formattedSourceMeta)
    && formattedSourceMeta !== label
    && formattedSourceMeta !== reason;

  return (
    <motion.button
      type="button"
      className="origin-focus-ring fixed z-30 flex cursor-pointer items-start gap-2 rounded-[16px] border px-3 py-2 text-left"
      initial={{ opacity: 0, x: variantStyle.leftOrigin, scale: 0.98 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: variantStyle.leftOrigin / 2, scale: 0.985 }}
      transition={{
        opacity: { duration: 0.12, ease: [0.33, 0.01, 0.18, 0.99] },
        x: { duration: 0.18, ease: [0.33, 0.01, 0.18, 0.99] },
        scale: { duration: 0.18, ease: [0.33, 0.01, 0.18, 0.99] },
      }}
      style={{
        left,
        top,
        width,
        minHeight: variantStyle.minHeight,
        background: variantStyle.background,
        borderColor: variantStyle.borderColor,
        boxShadow: variantStyle.shadow,
        backdropFilter: "blur(16px)",
        WebkitBackdropFilter: "blur(16px)",
      }}
      onClick={onCommitOpen}
      aria-label={`${label}. ${reason ?? "Open the anticipatory sidebar."}`}
      title={reason ?? label}
    >
      <span
        className="absolute left-0 top-3 bottom-3 w-[2px] rounded-full"
        style={{
          background: variantStyle.accent,
          boxShadow: `0 0 14px ${variantStyle.sourceBackground}`,
        }}
      />

      {variant === "hunt-pill-chip" && (
        <span
          className="absolute -left-[6px] top-[18px] h-3.5 w-3.5 rounded-full border"
          style={{
            borderColor: "rgba(213,173,87,0.42)",
            background: "radial-gradient(circle at center, rgba(232,211,145,0.9), rgba(213,173,87,0.24))",
            boxShadow: "0 0 12px rgba(213,173,87,0.24)",
          }}
        />
      )}

      {variant === "row-card" && (
        <span
          className="absolute -left-[10px] top-[22px] h-7 w-5 rounded-r-full"
          style={{
            background: "linear-gradient(90deg, rgba(114,186,175,0), rgba(114,186,175,0.22))",
            boxShadow: "0 0 16px rgba(114,186,175,0.14)",
          }}
        />
      )}

      <span className="relative min-w-0 flex-1">
        <span className="flex items-start justify-between gap-3">
          <span
            className="shrink-0 rounded-full px-2 py-[3px] font-mono text-[9px] uppercase tracking-[0.08em]"
            style={{
              background: variantStyle.sourceBackground,
              color: variantStyle.sourceColor,
            }}
          >
            {formattedSourceLabel}
          </span>
          <span
            className="shrink-0 rounded-full px-1.5 py-[2px] font-mono text-[9px] uppercase tracking-[0.08em]"
            style={{
              background: "rgba(232,230,222,0.06)",
              color: "rgba(232,230,222,0.7)",
            }}
          >
            {LENS_LABELS[anchorLens]}
          </span>
        </span>

        {showSourceMeta && (
          <span className="mt-1 block truncate text-[10px] text-[rgba(182,183,193,0.48)]">
            {formattedSourceMeta}
          </span>
        )}

        <span className="mt-1.5 block text-[12px] font-medium leading-[1.25] text-[rgba(232,230,222,0.92)]">
          {label}
        </span>
        <span className="mt-1 line-clamp-2 block text-[10px] text-[rgba(182,183,193,0.6)]">
          {reason ?? "Current context is already pointing at this surface."}
        </span>
      </span>
    </motion.button>
  );
}
