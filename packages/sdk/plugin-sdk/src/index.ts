/**
 * @clawdstrike/plugin-sdk
 *
 * Public API surface for ClawdStrike plugin authors.
 *
 * Usage:
 * ```typescript
 * import { createPlugin, type PluginContext } from '@clawdstrike/plugin-sdk';
 *
 * export default createPlugin({
 *   manifest: { id: "my.plugin", name: "my-plugin", ... },
 *   activate(ctx) {
 *     ctx.commands.register({ id: "my.command", title: "My Command" }, () => { ... });
 *   },
 * });
 * ```
 */

// ---- Types ----
export type {
  // Disposable
  Disposable,
  // React Compatibility
  ComponentType,
  // Trust & Lifecycle
  PluginTrustTier,
  PluginLifecycleState,
  // Categories & Activation
  PluginCategory,
  ActivationEvent,
  // Config
  ConfigFieldType,
  ConfigFieldDef,
  // Contribution Points (all 13)
  GuardContribution,
  CommandContribution,
  KeybindingContribution,
  FileTypeContribution,
  DetectionAdapterContribution,
  ActivityBarItemContribution,
  EditorTabContribution,
  BottomPanelTabContribution,
  RightSidebarPanelContribution,
  StatusBarItemContribution,
  ThreatIntelSourceContribution,
  ComplianceFrameworkContribution,
  GutterDecorationContribution,
  GutterConfig,
  ContextMenuContribution,
  EnrichmentRendererContribution,
  // Contributions Container
  PluginContributions,
  // Installation & Manifest
  InstallationMetadata,
  PluginManifest,
  PluginSecretDeclaration,
  // View Prop Interfaces (for plugin component authors)
  ViewProps,
  EditorTabProps,
  BottomPanelTabProps,
  RightSidebarPanelProps,
  ActivityBarPanelProps,
  StatusBarWidgetProps,
  // SDK View Contributions (used in activate() hook)
  EditorTabViewContribution,
  BottomPanelTabViewContribution,
  RightSidebarPanelViewContribution,
  StatusBarWidgetViewContribution,
} from "./types";

// ---- Context ----
export type {
  CommandsApi,
  GuardsApi,
  FileTypesApi,
  StatusBarApi,
  SidebarApi,
  StorageApi,
  ViewsApi,
  SecretsApi,
  EnrichmentRenderersApi,
  PluginContext,
} from "./context";

// ---- Threat Intelligence ----
export type {
  IndicatorType,
  Indicator,
  ThreatVerdict,
  EnrichmentResult,
  ThreatIntelSource,
} from "./threat-intel-types";

// ---- Factory ----
export { createPlugin } from "./create-plugin";
export type { PluginDefinition } from "./create-plugin";
