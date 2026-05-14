/**
 * Shared types for the create-plugin CLI scaffolding tool.
 */

/** The six supported plugin template types. */
export type PluginType =
  | "guard"
  | "detection"
  | "ui"
  | "intel"
  | "compliance"
  | "full";

/** All available contribution point identifiers. */
export type ContributionPoint =
  | "guards"
  | "commands"
  | "fileTypes"
  | "threatIntelSources"
  | "editorTabs"
  | "bottomPanelTabs"
  | "rightSidebarPanels"
  | "statusBarItems"
  | "activityBarItems";

/** Options collected from interactive prompts or CLI flags. */
export interface ScaffoldOptions {
  /** Plugin package name (kebab-case). */
  name: string;
  /** Human-readable display name. */
  displayName: string;
  /** Publisher name or organization. */
  publisher: string;
  /** Plugin template type. */
  type: PluginType;
  /** Selected contribution points to scaffold. */
  contributions: ContributionPoint[];
  /** Package manager for install instructions. */
  packageManager: "npm" | "bun" | "pnpm";
  /** Absolute path to the output directory. */
  outputDir: string;
}

/** All valid PluginType values for validation. */
export const PLUGIN_TYPES: PluginType[] = [
  "guard",
  "detection",
  "ui",
  "intel",
  "compliance",
  "full",
];

/** All valid ContributionPoint values for validation and prompt options. */
export const CONTRIBUTION_POINTS: ContributionPoint[] = [
  "guards",
  "commands",
  "fileTypes",
  "threatIntelSources",
  "editorTabs",
  "bottomPanelTabs",
  "rightSidebarPanels",
  "statusBarItems",
  "activityBarItems",
];

/** Default contribution points for each plugin type. */
export const PLUGIN_TYPE_DEFAULTS: Record<PluginType, ContributionPoint[]> = {
  guard: ["guards", "commands"],
  detection: ["fileTypes", "commands"],
  ui: ["editorTabs", "commands", "activityBarItems"],
  intel: ["threatIntelSources", "commands"],
  compliance: ["commands"],
  full: [
    "guards",
    "commands",
    "fileTypes",
    "threatIntelSources",
    "editorTabs",
    "bottomPanelTabs",
    "rightSidebarPanels",
    "statusBarItems",
    "activityBarItems",
  ],
};

/** Human-readable labels for contribution points (used in prompts). */
export const CONTRIBUTION_LABELS: Record<ContributionPoint, string> = {
  guards: "Guards - Custom security guards",
  commands: "Commands - Command palette entries",
  fileTypes: "File Types - Detection file formats",
  threatIntelSources: "Threat Intel - Threat intelligence sources",
  editorTabs: "Editor Tabs - Custom editor tab views",
  bottomPanelTabs: "Bottom Panel - Bottom panel tabs",
  rightSidebarPanels: "Right Sidebar - Right sidebar panels",
  statusBarItems: "Status Bar - Status bar widgets",
  activityBarItems: "Activity Bar - Activity bar navigation items",
};
