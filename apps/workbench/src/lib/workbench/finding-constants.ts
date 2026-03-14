import type { FindingStatus } from "@/lib/workbench/finding-engine";
import type { Severity } from "@/lib/workbench/hunt-types";

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#c45c5c",
  high: "#d4784b",
  medium: "#d4a84b",
  low: "#6b9b8b",
  info: "#6f7f9a",
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export const SEVERITY_LABELS_SHORT: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  info: "INFO",
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const STATUS_CONFIG: Record<FindingStatus, { label: string; color: string; bg: string }> = {
  emerging: { label: "Emerging", color: "#d4a84b", bg: "#d4a84b20" },
  confirmed: { label: "Confirmed", color: "#d4784b", bg: "#d4784b20" },
  promoted: { label: "Promoted", color: "#3dbf84", bg: "#3dbf8420" },
  dismissed: { label: "Dismissed", color: "#6f7f9a", bg: "#6f7f9a20" },
  false_positive: { label: "False Positive", color: "#6f7f9a", bg: "#6f7f9a20" },
  archived: { label: "Archived", color: "#6f7f9a", bg: "#6f7f9a15" },
};
