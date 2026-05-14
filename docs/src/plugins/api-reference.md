# API Reference

This page provides a quick reference to the `@clawdstrike/plugin-sdk` public API. The full API documentation is auto-generated from JSDoc comments in the SDK source using TypeDoc.

To regenerate the API docs locally:

```bash
mise run docs:plugin-api
```

[Full API Reference (TypeDoc)](../../api/plugin-sdk/README.md)

## Quick reference

### Factory

| Export | Kind | Description |
|--------|------|-------------|
| `createPlugin()` | Function | Create a type-safe plugin definition with manifest and lifecycle hooks |
| `PluginDefinition` | Interface | A fully-defined plugin with manifest, activate(), and optional deactivate() |

### Context

| Export | Kind | Description |
|--------|------|-------------|
| `PluginContext` | Interface | Context object provided to activate() with namespaced API access |
| `CommandsApi` | Interface | API for registering commands in the command palette |
| `GuardsApi` | Interface | API for registering custom guards in the guard pipeline |
| `FileTypesApi` | Interface | API for registering custom file types |
| `StatusBarApi` | Interface | API for registering status bar items |
| `SidebarApi` | Interface | API for registering activity bar items |
| `StorageApi` | Interface | Plugin-scoped key-value storage API |
| `ViewsApi` | Interface | API for registering views in UI slots (editor tabs, panels, etc.) |
| `SecretsApi` | Interface | Plugin-scoped secret/credential storage API |
| `EnrichmentRenderersApi` | Interface | API for registering custom enrichment type renderers |

### Manifest

| Export | Kind | Description |
|--------|------|-------------|
| `PluginManifest` | Interface | The plugin manifest contract (identity, trust, contributions, activation) |
| `PluginContributions` | Interface | All contribution point declarations grouped by type |
| `PluginTrustTier` | Type | Trust tier: `"internal"`, `"community"`, or `"mcp"` |
| `ActivationEvent` | Type | Activation event string (e.g. `"onStartup"`, `"onCommand:{id}"`) |
| `PluginCategory` | Type | Plugin category string |
| `PluginLifecycleState` | Type | Plugin lifecycle state machine values |
| `InstallationMetadata` | Interface | Distribution metadata (downloadUrl, checksum, signature) |
| `PluginSecretDeclaration` | Interface | Declared secret requirement (key, label, description) |

### Contributions

| Export | Kind | Description |
|--------|------|-------------|
| `GuardContribution` | Interface | Custom guard declaration |
| `CommandContribution` | Interface | Command palette entry |
| `KeybindingContribution` | Interface | Keyboard shortcut binding |
| `FileTypeContribution` | Interface | Custom detection file format |
| `DetectionAdapterContribution` | Interface | Detection format adapter |
| `ActivityBarItemContribution` | Interface | Left sidebar navigation entry |
| `EditorTabContribution` | Interface | Custom editor tab |
| `BottomPanelTabContribution` | Interface | Bottom panel tab |
| `RightSidebarPanelContribution` | Interface | Right sidebar panel |
| `StatusBarItemContribution` | Interface | Status bar segment |
| `ThreatIntelSourceContribution` | Interface | Threat intelligence source |
| `ComplianceFrameworkContribution` | Interface | Compliance framework mapping |
| `GutterDecorationContribution` | Interface | CodeMirror gutter extension |
| `ContextMenuContribution` | Interface | Context menu item |
| `EnrichmentRendererContribution` | Interface | Enrichment type renderer |
| `ConfigFieldDef` | Interface | Guard configuration field definition |

### View Props

| Export | Kind | Description |
|--------|------|-------------|
| `ViewProps` | Interface | Base props for all plugin view components |
| `EditorTabProps` | Interface | Props for editor tab components (extends ViewProps) |
| `BottomPanelTabProps` | Interface | Props for bottom panel components (extends ViewProps) |
| `RightSidebarPanelProps` | Interface | Props for right sidebar components (extends ViewProps) |
| `ActivityBarPanelProps` | Interface | Props for activity bar panel components (extends ViewProps) |
| `StatusBarWidgetProps` | Interface | Props for status bar widget components |

### SDK View Contributions (activate-time)

| Export | Kind | Description |
|--------|------|-------------|
| `EditorTabViewContribution` | Interface | Editor tab with component (used in activate()) |
| `BottomPanelTabViewContribution` | Interface | Bottom panel tab with component |
| `RightSidebarPanelViewContribution` | Interface | Right sidebar panel with component |
| `StatusBarWidgetViewContribution` | Interface | Status bar widget with component |

### Threat Intelligence

| Export | Kind | Description |
|--------|------|-------------|
| `ThreatIntelSource` | Interface | Runtime interface for threat intel source plugins |
| `Indicator` | Interface | An indicator to be enriched (hash, IP, domain, URL, email) |
| `IndicatorType` | Type | Indicator type: `"hash"`, `"ip"`, `"domain"`, `"url"`, `"email"` |
| `EnrichmentResult` | Interface | Result of enriching an indicator against a source |
| `ThreatVerdict` | Interface | Threat classification with confidence score |

### Utility Types

| Export | Kind | Description |
|--------|------|-------------|
| `Disposable` | Type | A dispose function `() => void` for cleanup |
| `ComponentType` | Type | React component type alias |
