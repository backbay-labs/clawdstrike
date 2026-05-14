/**
 * Shared IOC type color map.
 *
 * Single source of truth for indicator-of-compromise type badge colors
 * used across enrichment-sidebar, enrichment-dashboard-cards,
 * report-threat-dialog, and related-indicators-section.
 */
export const IOC_TYPE_COLORS: Record<string, string> = {
  sha256: "#c45c5c",
  sha1: "#c45c5c",
  md5: "#c45c5c",
  domain: "#6ea8d9",
  ip: "#d4784b",
  url: "#d4a84b",
  email: "#a78bfa",
  filepath: "#6b9b8b",
};
