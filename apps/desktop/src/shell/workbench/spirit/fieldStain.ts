import type { CSSProperties } from "react";
import type { SpiritSurfaceReceiveState } from "../spirit-ritual/release";
import type { HuntSpiritKind } from "./types";

type SpiritFieldSurface = "forensics" | "nexus";

interface SpiritFieldStainInput {
  kind: HuntSpiritKind | null;
  accentColor: string;
  receiveState: Exclude<SpiritSurfaceReceiveState, "idle">;
  surface: SpiritFieldSurface;
  focusXPercent: number;
  focusYPercent: number;
  anchorXPercent?: number | null;
  anchorYPercent?: number | null;
}

function clampPercent(value: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, value));
}

function hexToRgb(hex: string): { r: number; g: number; b: number } {
  const normalized = hex.replace("#", "");
  if (normalized.length !== 6) {
    return { r: 212, g: 168, b: 75 };
  }
  return {
    r: Number.parseInt(normalized.slice(0, 2), 16),
    g: Number.parseInt(normalized.slice(2, 4), 16),
    b: Number.parseInt(normalized.slice(4, 6), 16),
  };
}

function rgba(hex: string, alpha: number): string {
  const { r, g, b } = hexToRgb(hex);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function buildAnchorGlow(
  accentColor: string,
  alpha: number,
  anchorXPercent?: number | null,
  anchorYPercent?: number | null,
): string | null {
  if (anchorXPercent == null || anchorYPercent == null) return null;
  return `radial-gradient(circle at ${anchorXPercent}% ${anchorYPercent}%, ${rgba(accentColor, alpha)} 0%, transparent 26%)`;
}

function buildTrackerField(input: SpiritFieldStainInput): string {
  const { accentColor, receiveState, focusXPercent, focusYPercent, anchorXPercent, anchorYPercent } = input;
  const coreAlpha = receiveState === "receiving" ? 0.26 : 0.15;
  const bandAlpha = receiveState === "receiving" ? 0.22 : 0.12;
  const focusX = clampPercent(focusXPercent, 18, 82);
  const focusY = clampPercent(focusYPercent, 18, 82);
  const anchorGlow = buildAnchorGlow(accentColor, receiveState === "receiving" ? 0.12 : 0.08, anchorXPercent, anchorYPercent);

  return [
    `radial-gradient(circle at ${focusX}% ${focusY}%, ${rgba(accentColor, coreAlpha)} 0%, ${rgba(accentColor, coreAlpha * 0.35)} 12%, transparent 34%)`,
    `linear-gradient(90deg, transparent calc(${focusX}% - 15%), ${rgba(accentColor, bandAlpha * 0.4)} calc(${focusX}% - 6%), ${rgba(accentColor, bandAlpha)} ${focusX}%, ${rgba(accentColor, bandAlpha * 0.4)} calc(${focusX}% + 6%), transparent calc(${focusX}% + 15%))`,
    `linear-gradient(180deg, transparent calc(${focusY}% - 18%), ${rgba(accentColor, bandAlpha * 0.4)} calc(${focusY}% - 7%), ${rgba(accentColor, bandAlpha)} ${focusY}%, ${rgba(accentColor, bandAlpha * 0.4)} calc(${focusY}% + 7%), transparent calc(${focusY}% + 18%))`,
    anchorGlow,
  ]
    .filter(Boolean)
    .join(", ");
}

function buildLanternField(input: SpiritFieldStainInput): string {
  const { accentColor, receiveState, focusXPercent, focusYPercent, anchorXPercent, anchorYPercent } = input;
  const bloomAlpha = receiveState === "receiving" ? 0.28 : 0.18;
  const veilAlpha = receiveState === "receiving" ? 0.14 : 0.08;
  const anchorGlow = buildAnchorGlow(accentColor, receiveState === "receiving" ? 0.14 : 0.1, anchorXPercent, anchorYPercent);

  return [
    `radial-gradient(circle at ${focusXPercent}% ${focusYPercent}%, ${rgba(accentColor, bloomAlpha)} 0%, ${rgba(accentColor, bloomAlpha * 0.5)} 16%, ${rgba(accentColor, veilAlpha)} 30%, transparent 54%)`,
    `radial-gradient(circle at ${focusXPercent}% ${clampPercent(focusYPercent + 10, 20, 86)}%, ${rgba("#f7edd0", receiveState === "receiving" ? 0.1 : 0.06)} 0%, transparent 30%)`,
    `linear-gradient(180deg, rgba(4,6,11,0) 0%, ${rgba(accentColor, veilAlpha * 0.5)} 58%, ${rgba(accentColor, veilAlpha)} 100%)`,
    anchorGlow,
  ]
    .filter(Boolean)
    .join(", ");
}

function buildForgeField(input: SpiritFieldStainInput): string {
  const { accentColor, receiveState, focusXPercent, focusYPercent, anchorXPercent, anchorYPercent } = input;
  const emberAlpha = receiveState === "receiving" ? 0.24 : 0.16;
  const streakAlpha = receiveState === "receiving" ? 0.18 : 0.1;
  const anchorGlow = buildAnchorGlow(accentColor, receiveState === "receiving" ? 0.1 : 0.06, anchorXPercent, anchorYPercent);

  return [
    `radial-gradient(circle at ${focusXPercent}% ${focusYPercent}%, ${rgba(accentColor, emberAlpha)} 0%, ${rgba(accentColor, emberAlpha * 0.35)} 14%, transparent 34%)`,
    `linear-gradient(152deg, transparent 34%, ${rgba(accentColor, streakAlpha)} 56%, transparent 74%)`,
    `repeating-linear-gradient(152deg, transparent 0 24px, ${rgba(accentColor, streakAlpha * 0.6)} 24px 26px, transparent 26px 48px)`,
    `linear-gradient(180deg, rgba(4,6,11,0) 0%, ${rgba(accentColor, streakAlpha * 0.45)} 66%, ${rgba(accentColor, streakAlpha)} 100%)`,
    anchorGlow,
  ]
    .filter(Boolean)
    .join(", ");
}

function buildLoomField(input: SpiritFieldStainInput): string {
  const { accentColor, receiveState, focusXPercent, focusYPercent, anchorXPercent, anchorYPercent } = input;
  const threadAlpha = receiveState === "receiving" ? 0.16 : 0.1;
  const anchorGlow = buildAnchorGlow(accentColor, receiveState === "receiving" ? 0.12 : 0.08, anchorXPercent, anchorYPercent);

  return [
    `radial-gradient(circle at ${focusXPercent}% ${focusYPercent}%, ${rgba(accentColor, receiveState === "receiving" ? 0.22 : 0.14)} 0%, ${rgba(accentColor, receiveState === "receiving" ? 0.1 : 0.06)} 18%, transparent 40%)`,
    `repeating-linear-gradient(138deg, ${rgba(accentColor, threadAlpha)} 0 2px, transparent 2px 22px)`,
    `repeating-linear-gradient(-142deg, ${rgba(accentColor, threadAlpha * 0.72)} 0 1.5px, transparent 1.5px 20px)`,
    anchorGlow,
  ]
    .filter(Boolean)
    .join(", ");
}

function buildLedgerField(input: SpiritFieldStainInput): string {
  const { accentColor, receiveState, focusXPercent, focusYPercent, anchorXPercent, anchorYPercent } = input;
  const lineAlpha = receiveState === "receiving" ? 0.18 : 0.11;
  const anchorGlow = buildAnchorGlow(accentColor, receiveState === "receiving" ? 0.1 : 0.06, anchorXPercent, anchorYPercent);

  return [
    `radial-gradient(circle at ${focusXPercent}% ${focusYPercent}%, ${rgba(accentColor, receiveState === "receiving" ? 0.18 : 0.12)} 0%, transparent 34%)`,
    `repeating-linear-gradient(180deg, transparent 0 22px, ${rgba(accentColor, lineAlpha)} 22px 24px, transparent 24px 48px)`,
    `linear-gradient(180deg, rgba(4,6,11,0) 0%, ${rgba(accentColor, lineAlpha * 0.45)} 72%, rgba(4,6,11,0) 100%)`,
    anchorGlow,
  ]
    .filter(Boolean)
    .join(", ");
}

export function buildSpiritFieldStainStyle(input: SpiritFieldStainInput): CSSProperties {
  const { kind, accentColor, receiveState, surface, focusXPercent, focusYPercent, anchorXPercent, anchorYPercent } = input;
  const normalized = {
    ...input,
    focusXPercent: clampPercent(focusXPercent, 16, 84),
    focusYPercent: clampPercent(focusYPercent, 16, 84),
    anchorXPercent: anchorXPercent == null ? null : clampPercent(anchorXPercent, 16, 84),
    anchorYPercent: anchorYPercent == null ? null : clampPercent(anchorYPercent, 16, 84),
  };

  const background = (() => {
    switch (kind) {
      case "tracker":
        return buildTrackerField(normalized);
      case "lantern":
        return buildLanternField(normalized);
      case "forge":
        return buildForgeField(normalized);
      case "loom":
        return buildLoomField(normalized);
      case "ledger":
        return buildLedgerField(normalized);
      default:
        return buildLanternField(normalized);
    }
  })();

  return {
    background,
    opacity:
      receiveState === "receiving"
        ? surface === "nexus"
          ? 0.8
          : 0.86
        : surface === "nexus"
          ? 0.52
          : 0.58,
    transition: "opacity 220ms ease, background 280ms ease",
    mixBlendMode: kind === "ledger" ? "lighten" : "screen",
  };
}
