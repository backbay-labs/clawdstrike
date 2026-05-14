# UI Extensions

Plugins can contribute to several UI slots in the workbench: the activity bar, editor tabs, bottom panel, right sidebar, status bar, gutter decorations, context menus, and enrichment renderers.

## Activity bar items

Activity bar items add entries to the left sidebar navigation.

```typescript,ignore
interface ActivityBarItemContribution {
  id: string;       // Unique identifier
  section: string;  // Sidebar section (e.g. "security", "analysis")
  label: string;    // Display label
  icon: string;     // Icon identifier (Lucide name or custom)
  href: string;     // Route path for navigation
  entrypoint?: string; // Module path for lazy-loaded panel component
  order?: number;   // Sort order within the section (lower = first)
}
```

Register activity bar items using `ctx.sidebar.register()`:

```typescript,ignore
activate(ctx) {
  ctx.subscriptions.push(
    ctx.sidebar.register({
      id: "acme.dashboard",
      section: "security",
      label: "Security Dashboard",
      icon: "shield-check",
      href: "/plugins/acme-dashboard",
      order: 10,
    })
  );
}
```

## Editor tabs

Editor tab contributions declare custom views that can be opened in the editor pane area.

```typescript,ignore
interface EditorTabContribution {
  id: string;         // Unique identifier
  label: string;      // Display label for the tab
  icon?: string;      // Optional icon identifier
  entrypoint: string; // Path to the tab component module
}
```

To register an editor tab view at runtime using `ctx.views`, use an `EditorTabViewContribution` which accepts a component directly:

```typescript,ignore
import type { EditorTabViewContribution, EditorTabProps } from "@clawdstrike/plugin-sdk";

const DashboardTab = (props: EditorTabProps) => {
  props.setTitle("Security Dashboard");
  return <div>Dashboard content</div>;
};

activate(ctx) {
  ctx.subscriptions.push(
    ctx.views.registerEditorTab({
      id: "acme.dashboard-tab",
      label: "Dashboard",
      icon: "layout-dashboard",
      component: DashboardTab,
    })
  );
}
```

`EditorTabProps` extends the base `ViewProps` with:

```typescript,ignore
interface EditorTabProps extends ViewProps {
  setTitle: (title: string) => void;  // Update tab display title
  setDirty: (dirty: boolean) => void; // Mark as having unsaved changes
}
```

## Bottom panel tabs

Bottom panel tab contributions add tabs to the bottom panel area (alongside terminal, output, problems).

```typescript,ignore
interface BottomPanelTabContribution {
  id: string;         // Unique identifier
  label: string;      // Display label
  icon?: string;      // Optional icon identifier
  entrypoint: string; // Path to the panel component module
}
```

Register at runtime using `ctx.views.registerBottomPanelTab()`:

```typescript,ignore
import type { BottomPanelTabProps } from "@clawdstrike/plugin-sdk";

const LogPanel = (props: BottomPanelTabProps) => {
  return <div style={{ height: props.panelHeight }}>Log output here</div>;
};

activate(ctx) {
  ctx.subscriptions.push(
    ctx.views.registerBottomPanelTab({
      id: "acme.log-panel",
      label: "Security Log",
      icon: "scroll-text",
      component: LogPanel,
    })
  );
}
```

`BottomPanelTabProps` extends `ViewProps` with `panelHeight: number` (current height in pixels).

## Right sidebar panels

Right sidebar panel contributions add panels to the right sidebar.

```typescript,ignore
interface RightSidebarPanelContribution {
  id: string;         // Unique identifier
  label: string;      // Display label
  icon?: string;      // Optional icon identifier
  entrypoint: string; // Path to the panel component module
}
```

Register at runtime using `ctx.views.registerRightSidebarPanel()`:

```typescript,ignore
import type { RightSidebarPanelProps } from "@clawdstrike/plugin-sdk";

const InspectorPanel = (props: RightSidebarPanelProps) => {
  return <div style={{ width: props.sidebarWidth }}>Inspector content</div>;
};

activate(ctx) {
  ctx.subscriptions.push(
    ctx.views.registerRightSidebarPanel({
      id: "acme.inspector",
      label: "Inspector",
      icon: "search",
      component: InspectorPanel,
    })
  );
}
```

`RightSidebarPanelProps` extends `ViewProps` with `sidebarWidth: number` (current width in pixels).

## Status bar items

Status bar item contributions add segments to the bottom status bar.

```typescript,ignore
interface StatusBarItemContribution {
  id: string;         // Unique identifier
  side: "left" | "right"; // Which side of the status bar
  priority: number;   // Sort order (lower = render first)
  entrypoint: string; // Path to the render component module
}
```

Register at runtime using `ctx.views.registerStatusBarWidget()`:

```typescript,ignore
import type { StatusBarWidgetProps } from "@clawdstrike/plugin-sdk";

const StatusWidget = (props: StatusBarWidgetProps) => {
  return <span>Guard: Active</span>;
};

activate(ctx) {
  ctx.subscriptions.push(
    ctx.views.registerStatusBarWidget({
      id: "acme.guard-status",
      side: "left",
      priority: 100,
      component: StatusWidget,
    })
  );
}
```

`StatusBarWidgetProps` provides `viewId: string`.

## Gutter decorations

Gutter decoration contributions provide CodeMirror Extension factories for the editor gutter.

```typescript,ignore
interface GutterDecorationContribution {
  id: string;         // Unique identifier
  gutter?: string;    // Optional gutter name (defaults to plugin-namespaced)
  entrypoint: string; // Module exporting createGutterExtension(config) => Extension
}
```

The `entrypoint` module must export a `createGutterExtension` function that receives a `GutterConfig`:

```typescript,ignore
interface GutterConfig {
  pluginId: string;    // The plugin's qualified ID
  decorationId: string; // The gutter decoration's qualified ID
}
```

## Context menu items

Context menu contributions add items to right-click menus throughout the workbench.

```typescript,ignore
interface ContextMenuContribution {
  id: string;         // Unique identifier
  label: string;      // Display label
  command: string;    // Command ID to execute on click
  icon?: string;      // Optional icon identifier
  when?: string;      // Visibility predicate expression
  menu: "editor" | "sidebar" | "tab" | "finding" | "sentinel"; // Target menu
}
```

Context menu items are declared in the manifest and reference a command ID. Register the corresponding command handler in `activate()`.

## Enrichment renderers

Enrichment renderer contributions provide custom React components for rendering specific enrichment types in the enrichment sidebar.

```typescript,ignore
interface EnrichmentRendererContribution {
  type: string;       // Enrichment type this renderer handles (e.g. "virustotal")
  entrypoint: string; // Path to the renderer component module
}
```

Register at runtime using `ctx.enrichmentRenderers.register()`:

```typescript,ignore
import type { ComponentType } from "@clawdstrike/plugin-sdk";

const VTRenderer: ComponentType = (props) => {
  return <div>Custom VirusTotal display</div>;
};

activate(ctx) {
  ctx.subscriptions.push(
    ctx.enrichmentRenderers.register("virustotal", VTRenderer)
  );
}
```

## Base ViewProps

All view components receive `ViewProps` as their base props:

```typescript,ignore
interface ViewProps {
  viewId: string;      // Qualified view ID ("{pluginId}.{viewId}")
  isActive: boolean;   // Whether this view is currently visible/active
  storage: {           // Per-view key/value storage
    get(key: string): unknown;
    set(key: string, value: unknown): void;
  };
}
```

Specialized prop types (`EditorTabProps`, `BottomPanelTabProps`, `RightSidebarPanelProps`, `ActivityBarPanelProps`, `StatusBarWidgetProps`) extend or supplement `ViewProps` with slot-specific fields.
