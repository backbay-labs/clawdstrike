/**
 * Plugin SDK Types
 *
 * Re-exports all contribution point interfaces, manifest types, and lifecycle
 * types that plugin authors need. These are standalone copies (not imported from
 * the workbench) so the SDK has zero internal dependencies.
 *
 * Source of truth: apps/workbench/src/lib/plugins/types.ts
 */

// ---- React Compatibility ----
// Standalone type alias to avoid a hard dependency on @types/react.
// Plugin authors will use the real React types; the SDK only needs the shape.

/** A React component type. Mirrors React.ComponentType<P>. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ComponentType<P = any> = ((props: P) => unknown) | (new (props: P) => unknown);

// ---- Disposable ----

/** A dispose function that cleans up a resource. */
export type Disposable = () => void;

// ---- Trust & Lifecycle ----

/**
 * Plugin trust tier determines loading strategy:
 * - "internal": built-in plugins, loaded in-process with full access
 * - "community": third-party plugins, loaded in sandboxed iframe
 * - "mcp": MCP tool plugins, loaded via MCP protocol bridge
 */
export type PluginTrustTier = "internal" | "community" | "mcp";

/**
 * Plugin lifecycle state machine:
 * not-installed -> installing -> installed -> activating -> activated
 *                                         -> deactivated
 *                                         -> error
 */
export type PluginLifecycleState =
  | "not-installed"
  | "installing"
  | "installed"
  | "activating"
  | "activated"
  | "deactivated"
  | "error";

// ---- Categories & Activation ----

/**
 * Plugin category. Open string type for extensibility.
 * Well-known categories: "guards", "detection", "intel", "compliance", "ui", "integration".
 */
export type PluginCategory = string;

/**
 * Activation event string. Determines when the plugin is activated.
 *
 * Known patterns:
 * - `"onStartup"` -- activate immediately on workbench load
 * - `"onFileType:{type}"` -- activate when a file of the given type is opened
 * - `"onCommand:{id}"` -- activate when a specific command is invoked
 * - `"onGuardEvaluate:{id}"` -- activate when a specific guard is evaluated
 */
export type ActivationEvent = string;

// ---- Config Field ----

/**
 * Guard configuration field type.
 * Built-in types: "toggle", "string_list", "pattern_list", "number_slider",
 * "number_input", "select", "secret_pattern_list", "json".
 * Plugins may use "json" as a fallback for arbitrary config schemas.
 */
export type ConfigFieldType = string;

/**
 * Definition of a single configuration field for a guard's config UI.
 * The workbench guard config panel renders these into form controls.
 */
export interface ConfigFieldDef {
  /** Configuration key (maps to the guard's config object). */
  key: string;
  /** Human-readable label for the form control. */
  label: string;
  /** Field type determining which editor widget renders. */
  type: ConfigFieldType;
  /** Optional description shown as help text. */
  description?: string;
  /** Default value when no user override exists. */
  defaultValue?: unknown;
  /** Options for "select" type fields. */
  options?: { value: string; label: string }[];
  /** Minimum value for numeric fields. */
  min?: number;
  /** Maximum value for numeric fields. */
  max?: number;
  /** Step increment for numeric fields. */
  step?: number;
}

// ---- Contribution Point Interfaces ----

/**
 * Guard contribution declares a custom guard to register in the guard pipeline.
 * Fields mirror GuardMeta from the workbench types.
 */
export interface GuardContribution {
  /** Guard ID to register in the guard registry. */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** Technical/snake_case name for policy YAML keys. */
  technicalName: string;
  /** Description of what this guard checks. */
  description: string;
  /** Guard category (e.g. "filesystem", "network", "content"). */
  category: string;
  /** Default verdict when the guard triggers. */
  defaultVerdict: "allow" | "deny" | "warn";
  /** Icon identifier for UI rendering. */
  icon: string;
  /** Configuration field definitions for the guard config UI. */
  configFields: ConfigFieldDef[];
}

/**
 * Command contribution declares a command to register in the command palette.
 */
export interface CommandContribution {
  /** Unique command identifier (e.g. "myPlugin.runScan"). */
  id: string;
  /** Display title in the command palette. */
  title: string;
  /** Optional category for grouping in the palette. */
  category?: string;
  /** Optional default keyboard shortcut (e.g. "Cmd+Shift+S"). */
  shortcut?: string;
  /** Optional contextual visibility expression (for future use). */
  when?: string;
}

/**
 * Keybinding contribution binds a keyboard shortcut to a command.
 */
export interface KeybindingContribution {
  /** Command ID to bind. */
  command: string;
  /** Key combination (e.g. "Cmd+Shift+S", "Ctrl+K"). */
  key: string;
  /** Optional contextual activation expression. */
  when?: string;
}

/**
 * File type contribution declares a new detection engineering file format.
 * Fields mirror FileTypeDescriptor from the workbench file-type-registry.
 */
export interface FileTypeContribution {
  /** Unique file type identifier. */
  id: string;
  /** Human-readable label (e.g. "Splunk SPL Rule"). */
  label: string;
  /** Short label for compact UI (e.g. "SPL"). */
  shortLabel: string;
  /** Associated file extensions (lowercase, with leading dot). */
  extensions: string[];
  /** Hex color for tab dots and explorer icons. */
  iconColor: string;
  /** Template content for new file creation. */
  defaultContent: string;
  /** Whether this format supports the test runner. */
  testable: boolean;
}

/**
 * Detection adapter contribution provides a detection format adapter
 * (e.g., Splunk SPL, KQL, Elastic ESQL).
 */
export interface DetectionAdapterContribution {
  /** File type this adapter handles. */
  fileType: string;
  /** Path to the adapter module within the plugin package. */
  entrypoint: string;
  /** Optional inline file type descriptor metadata for discovery UIs. */
  fileTypeDescriptor?: Omit<FileTypeContribution, "id">;
  /** Whether the adapter exposes a visual panel for this file type. */
  hasVisualPanel?: boolean;
  /** Optional translation routes advertised by the adapter. */
  translations?: Array<{
    from: string;
    to: string;
    lossless: boolean;
    lossDescription?: string;
  }>;
}

/**
 * Activity bar item contribution adds an entry to the left sidebar navigation.
 */
export interface ActivityBarItemContribution {
  /** Unique identifier for this activity bar item. */
  id: string;
  /** Sidebar section name (e.g. "security", "analysis"). */
  section: string;
  /** Display label. */
  label: string;
  /** Icon identifier (Lucide icon name or custom). */
  icon: string;
  /** Route path for navigation. */
  href: string;
  /** Module path for lazy-loaded panel component. Used instead of href for view loading. */
  entrypoint?: string;
  /** Sort order within the section. Lower numbers appear first. */
  order?: number;
}

/**
 * Editor tab contribution declares a custom tab/view that can be opened in the editor pane area.
 */
export interface EditorTabContribution {
  /** Unique identifier for this tab type. */
  id: string;
  /** Display label for the tab. */
  label: string;
  /** Optional icon identifier. */
  icon?: string;
  /** Path to the tab component module within the plugin package. */
  entrypoint: string;
}

/**
 * Bottom panel tab contribution adds a tab to the bottom panel (terminal, output, problems area).
 */
export interface BottomPanelTabContribution {
  /** Unique identifier for this panel tab. */
  id: string;
  /** Display label. */
  label: string;
  /** Optional icon identifier. */
  icon?: string;
  /** Path to the panel component module within the plugin package. */
  entrypoint: string;
}

/**
 * Right sidebar panel contribution adds a panel to the right sidebar.
 */
export interface RightSidebarPanelContribution {
  /** Unique identifier for this panel. */
  id: string;
  /** Display label. */
  label: string;
  /** Optional icon identifier. */
  icon?: string;
  /** Path to the panel component module within the plugin package. */
  entrypoint: string;
}

/**
 * Status bar item contribution adds a segment to the bottom status bar.
 */
export interface StatusBarItemContribution {
  /** Unique identifier for this status bar item. */
  id: string;
  /** Which side of the status bar ("left" or "right"). */
  side: "left" | "right";
  /** Sort order within the side. Lower numbers render first. */
  priority: number;
  /** Path to the render component module within the plugin package. */
  entrypoint: string;
}

/**
 * Threat intel source contribution provides an external threat intelligence feed.
 */
export interface ThreatIntelSourceContribution {
  /** Unique identifier for this intel source. */
  id: string;
  /** Human-readable name (e.g. "VirusTotal", "AbuseIPDB"). */
  name: string;
  /** Description of the intel source. */
  description: string;
  /** Path to the source adapter module within the plugin package. */
  entrypoint: string;
}

/**
 * Compliance framework contribution provides compliance mapping definitions
 * (e.g., HIPAA, SOC 2, PCI-DSS, NIST 800-53).
 */
export interface ComplianceFrameworkContribution {
  /** Unique identifier for this framework. */
  id: string;
  /** Human-readable name (e.g. "NIST 800-53"). */
  name: string;
  /** Description of the compliance framework. */
  description: string;
  /** Path to the framework definition module within the plugin package. */
  entrypoint: string;
}

// ---- Context Menu Contribution ----

/** Context menu item contribution -- adds an item to a right-click context menu. */
export interface ContextMenuContribution {
  /** Unique identifier for this menu item. */
  id: string;
  /** Display label for the menu item. */
  label: string;
  /** Command ID to execute when the item is clicked. */
  command: string;
  /** Optional icon identifier. */
  icon?: string;
  /** Visibility predicate expression. Evaluated against workbench context. */
  when?: string;
  /** Which context menu to add this item to. */
  menu: "editor" | "sidebar" | "tab" | "finding" | "sentinel";
}

// ---- Enrichment Renderer Contribution ----

/**
 * Enrichment renderer contribution declares a custom React renderer
 * for a specific enrichment type in the enrichment sidebar.
 */
export interface EnrichmentRendererContribution {
  /** The enrichment type this renderer handles (e.g. "virustotal", "shodan"). */
  type: string;
  /** Path to the renderer component module within the plugin package. */
  entrypoint: string;
}

// ---- Gutter Decoration Contribution ----

/** Gutter decoration contribution -- provides a CodeMirror Extension factory. */
export interface GutterDecorationContribution {
  /** Unique identifier for this gutter decoration. */
  id: string;
  /** Optional gutter name (defaults to a plugin-namespaced custom gutter). */
  gutter?: string;
  /** Module path exporting a createGutterExtension(config: GutterConfig) => Extension factory. */
  entrypoint: string;
}

/** Configuration passed to a plugin's gutter extension factory. */
export interface GutterConfig {
  /** The plugin's qualified ID. */
  pluginId: string;
  /** The gutter decoration's qualified ID. */
  decorationId: string;
}

// ---- Contributions Container ----

/**
 * All contribution point declarations grouped by type.
 * Each field is optional -- a plugin may contribute to any subset of points.
 */
export interface PluginContributions {
  /** Custom guard definitions for the guard pipeline. */
  guards?: GuardContribution[];
  /** Commands for the command palette. */
  commands?: CommandContribution[];
  /** Keyboard shortcut bindings. */
  keybindings?: KeybindingContribution[];
  /** Custom detection engineering file types. */
  fileTypes?: FileTypeContribution[];
  /** Detection format adapters. */
  detectionAdapters?: DetectionAdapterContribution[];
  /** Left sidebar navigation items. */
  activityBarItems?: ActivityBarItemContribution[];
  /** Custom editor tab/view types. */
  editorTabs?: EditorTabContribution[];
  /** Bottom panel tabs. */
  bottomPanelTabs?: BottomPanelTabContribution[];
  /** Right sidebar panels. */
  rightSidebarPanels?: RightSidebarPanelContribution[];
  /** Status bar segments. */
  statusBarItems?: StatusBarItemContribution[];
  /** Threat intelligence feed sources. */
  threatIntelSources?: ThreatIntelSourceContribution[];
  /** Compliance framework definitions. */
  complianceFrameworks?: ComplianceFrameworkContribution[];
  /** CodeMirror gutter decoration extensions. */
  gutterDecorations?: GutterDecorationContribution[];
  /** Context menu items added to right-click menus. */
  contextMenuItems?: ContextMenuContribution[];
  /** Custom enrichment type renderers for the enrichment sidebar. */
  enrichmentRenderers?: EnrichmentRendererContribution[];
}

// ---- Installation Metadata ----

/**
 * Distribution and installation metadata for a plugin package.
 * Includes integrity fields for secure distribution.
 */
export interface InstallationMetadata {
  /** URL to download the plugin package. */
  downloadUrl: string;
  /** Package size in bytes. */
  size: number;
  /** SHA-256 hex digest of the package contents. */
  checksum: string;
  /** Ed25519 signature of the canonical manifest JSON. */
  signature: string;
  /** Optional Ed25519 public key used to verify the manifest signature. */
  publisherKey?: string;
  /** Minimum compatible workbench version (semver). */
  minWorkbenchVersion?: string;
  /** Maximum compatible workbench version (semver). */
  maxWorkbenchVersion?: string;
}

// ---- Plugin Manifest ----

/**
 * The PluginManifest is the contract that describes what a plugin provides.
 * It declares identity, trust level, contribution points, activation triggers,
 * and distribution metadata. All downstream systems (registry, loader, SDK)
 * depend on this type.
 */
export interface PluginManifest {
  /** Reverse-domain plugin identifier (e.g. "clawdstrike.egress-guard"). */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Display name for UI rendering. */
  displayName: string;
  /** Plugin description. */
  description: string;
  /** Semantic version string (e.g. "1.0.0", "2.1.0-beta.1"). */
  version: string;
  /** Publisher name or organization. */
  publisher: string;
  /** Plugin categories for filtering and discovery. */
  categories: PluginCategory[];
  /** Trust tier determines loading strategy and sandbox level. */
  trust: PluginTrustTier;
  /** Events that trigger plugin activation. */
  activationEvents: ActivationEvent[];
  /** Entry point path for plugin code (relative to plugin root). */
  main?: string;
  /** All contribution point declarations. */
  contributions?: PluginContributions;
  /** Distribution and installation metadata. */
  installation?: InstallationMetadata;
  /**
   * Secrets required by this plugin (e.g., API keys).
   * The workbench renders a generic secret entry form for each declared secret.
   */
  requiredSecrets?: PluginSecretDeclaration[];
}

// ---- Secret Declaration ----

/**
 * Declares a secret that a plugin requires to function.
 * The workbench uses this to render an API key entry form in plugin settings.
 */
export interface PluginSecretDeclaration {
  /** Secret key identifier (e.g., "api_key"). */
  key: string;
  /** Human-readable label (e.g., "Shodan API Key"). */
  label: string;
  /** Description of how to obtain the secret. */
  description: string;
}

// ---- View Prop Interfaces (for plugin component authors) ----

/**
 * Base props passed to every plugin view component by ViewContainer.
 * Mirrors ViewProps from the workbench view-registry.
 */
export interface ViewProps {
  /** Qualified view ID ("{pluginId}.{viewId}"). */
  viewId: string;
  /** Whether this view is currently visible/active. */
  isActive: boolean;
  /** Per-view key/value storage. */
  storage: {
    get(key: string): unknown;
    set(key: string, value: unknown): void;
  };
}

/** Props for plugin editor tab components. */
export interface EditorTabProps extends ViewProps {
  /** Update the tab's display title. */
  setTitle: (title: string) => void;
  /** Mark the tab as having unsaved changes. */
  setDirty: (dirty: boolean) => void;
}

/** Props for plugin bottom panel tab components. */
export interface BottomPanelTabProps extends ViewProps {
  /** Current height of the bottom panel in pixels. */
  panelHeight: number;
}

/** Props for plugin right sidebar panel components. */
export interface RightSidebarPanelProps extends ViewProps {
  /** Current width of the right sidebar in pixels. */
  sidebarWidth: number;
}

/** Props for plugin activity bar panel components. */
export interface ActivityBarPanelProps extends ViewProps {
  /** Whether the sidebar is in collapsed state. */
  isCollapsed: boolean;
}

/** Props for plugin status bar widget components. */
export interface StatusBarWidgetProps {
  /** Qualified view ID for this widget. */
  viewId: string;
}

// ---- SDK View Contributions (used in activate() hook) ----

/**
 * SDK-side editor tab view contribution.
 * Unlike manifest EditorTabContribution (which has an entrypoint string),
 * the SDK version accepts a component directly or a lazy import factory.
 */
export interface EditorTabViewContribution {
  /** Unique identifier for this editor tab view. */
  id: string;
  /** Display label for the tab. */
  label: string;
  /** Optional icon identifier (Lucide name or custom). */
  icon?: string;
  /** React component or lazy import factory. */
  component: ComponentType | (() => Promise<{ default: ComponentType }>);
}

/** SDK-side bottom panel tab view contribution. */
export interface BottomPanelTabViewContribution {
  /** Unique identifier for this panel tab. */
  id: string;
  /** Display label. */
  label: string;
  /** Optional icon identifier. */
  icon?: string;
  /** React component or lazy import factory. */
  component: ComponentType | (() => Promise<{ default: ComponentType }>);
}

/** SDK-side right sidebar panel view contribution. */
export interface RightSidebarPanelViewContribution {
  /** Unique identifier for this panel. */
  id: string;
  /** Display label. */
  label: string;
  /** Optional icon identifier. */
  icon?: string;
  /** React component or lazy import factory. */
  component: ComponentType | (() => Promise<{ default: ComponentType }>);
}

/** SDK-side status bar widget view contribution. */
export interface StatusBarWidgetViewContribution {
  /** Unique identifier for this widget. */
  id: string;
  /** Which side of the status bar ("left" or "right"). */
  side: "left" | "right";
  /** Sort order within the side. Lower numbers render first. */
  priority: number;
  /** React component or lazy import factory. */
  component: ComponentType | (() => Promise<{ default: ComponentType }>);
}
