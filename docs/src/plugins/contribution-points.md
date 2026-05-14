# Contribution Points

Contribution points are the extension mechanisms that plugins use to add functionality to the workbench. Each contribution type is declared in the plugin manifest's `contributions` field and registered at runtime during `activate()`.

## Available contribution types

| Contribution | Manifest field | Description | Guide |
|-------------|---------------|-------------|-------|
| Guards | `guards` | Custom security guards for the guard pipeline | [Guards](contribution-points/guards.md) |
| Commands | `commands` | Commands for the command palette with optional keybindings | [Commands](contribution-points/commands.md) |
| Keybindings | `keybindings` | Keyboard shortcut bindings for commands | [Commands](contribution-points/commands.md) |
| File Types | `fileTypes` | Custom detection engineering file formats | [File Types](contribution-points/file-types.md) |
| Detection Adapters | `detectionAdapters` | Detection format adapters (SPL, KQL, EQL, etc.) | [File Types](contribution-points/file-types.md) |
| Activity Bar Items | `activityBarItems` | Left sidebar navigation entries | [UI Extensions](contribution-points/ui-extensions.md) |
| Editor Tabs | `editorTabs` | Custom tabs in the editor pane | [UI Extensions](contribution-points/ui-extensions.md) |
| Bottom Panel Tabs | `bottomPanelTabs` | Tabs in the bottom panel (terminal, output area) | [UI Extensions](contribution-points/ui-extensions.md) |
| Right Sidebar Panels | `rightSidebarPanels` | Panels in the right sidebar | [UI Extensions](contribution-points/ui-extensions.md) |
| Status Bar Items | `statusBarItems` | Segments in the bottom status bar | [UI Extensions](contribution-points/ui-extensions.md) |
| Gutter Decorations | `gutterDecorations` | CodeMirror gutter extensions for the editor | [UI Extensions](contribution-points/ui-extensions.md) |
| Context Menu Items | `contextMenuItems` | Items in right-click context menus | [UI Extensions](contribution-points/ui-extensions.md) |
| Enrichment Renderers | `enrichmentRenderers` | Custom renderers for enrichment types in the sidebar | [UI Extensions](contribution-points/ui-extensions.md) |
| Threat Intel Sources | `threatIntelSources` | External threat intelligence feed integrations | [Threat Intel Sources](contribution-points/threat-intel.md) |
| Compliance Frameworks | `complianceFrameworks` | Compliance mapping definitions (HIPAA, SOC 2, etc.) | [Compliance Frameworks](contribution-points/compliance.md) |

## How contributions work

Every contribution follows the same pattern:

1. **Declare** in the manifest -- tells the workbench what the plugin provides before activation.
2. **Register** in `activate()` -- uses the `PluginContext` APIs to register runtime handlers.
3. **Dispose** on deactivation -- push disposables to `ctx.subscriptions` for automatic cleanup.

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";

export default createPlugin({
  manifest: {
    // ... identity fields ...
    contributions: {
      guards: [/* declared here */],
      commands: [/* declared here */],
    },
  },

  activate(ctx) {
    // Register at runtime
    ctx.subscriptions.push(
      ctx.guards.register(/* ... */),
      ctx.commands.register(/* ... */, handler)
    );
  },
});
```

See the individual contribution type pages for detailed interfaces and examples.
